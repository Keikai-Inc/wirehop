//! Session checkpoints: what each persistent session was doing, so it can be
//! started again after the daemon restarts.
//!
//! A checkpoint records, per live session, the Unix user, the working
//! directory and the foreground command (read from the process tree under
//! the session's shell), plus the window title. The daemon writes one every
//! minute and on a clean shutdown; `hop sessions restore` reads it and
//! starts each entry again as a detached session, in the same directory,
//! running the same command. Programs that can pick up where they left off
//! are asked to: `claude` and `pi` come back with `--continue`.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// File name inside the host config dir.
pub const CHECKPOINT_FILE: &str = "sessions-checkpoint.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCheckpoint {
    pub session_id: String,
    /// Node id of the peer that owns the session; restore keeps it so the
    /// same client can attach again and the same sandbox policy applies.
    pub peer_id: String,
    pub username: Option<String>,
    /// Working directory of the foreground process (or the shell).
    pub cwd: Option<String>,
    /// Command line of the foreground process, if the shell was running one.
    pub command: Option<String>,
    /// Pids recorded when the checkpoint was written, used only to detect a
    /// process that outlived a daemon-only restart (see `survivor_pid`). Stale
    /// after a real reboot, which is why the match also checks the command line.
    #[serde(default)]
    pub fg_pid: Option<u32>,
    #[serde(default)]
    pub child_pid: Option<u32>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointFile {
    /// Unix ms when it was written.
    pub saved_ms: u64,
    /// Which daemon process wrote it (its start time, Unix ms).
    #[serde(default)]
    pub daemon_boot: u64,
    pub sessions: Vec<SessionCheckpoint>,
}

impl CheckpointFile {
    pub fn load(config_dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = config_dir.join(CHECKPOINT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(&data)?))
    }

    pub fn save(&self, config_dir: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        crate::config::write_secret_file(&config_dir.join(CHECKPOINT_FILE), &json)
    }
}

/// Snapshot the live sessions from `registry` and write the checkpoint file.
/// Returns how many sessions were recorded.
///
/// A daemon that has just started and has no sessions leaves a previous
/// daemon's non-empty checkpoint alone, so it is still there to restore.
pub async fn write(registry: &super::session_registry::RegistryHandle, config_dir: &Path) -> anyhow::Result<usize> {
    let inputs = registry.checkpoint_inputs().await;
    let sessions = tokio::task::spawn_blocking(move || build(&inputs)).await?;
    let n = sessions.len();
    if n == 0
        && let Some(prev) = CheckpointFile::load(config_dir)?
        && !prev.sessions.is_empty()
        && prev.daemon_boot != *DAEMON_BOOT
    {
        return Ok(0);
    }
    CheckpointFile { saved_ms: super::session_registry::unix_now_ms(), daemon_boot: *DAEMON_BOOT, sessions }.save(config_dir)?;
    Ok(n)
}

/// What the registry knows about a session that a checkpoint needs.
#[derive(Debug, Clone)]
pub struct CheckpointInput {
    pub session_id: String,
    pub peer_id: String,
    pub username: Option<String>,
    /// The shell's pid when this daemon spawned it itself (not under privsep).
    pub child_pid: Option<u32>,
    /// The PTY's foreground process group leader, from `tcgetpgrp` on the master.
    pub fg_pid: Option<u32>,
    pub title: Option<String>,
}

/// Build the checkpoint entries by inspecting each session's process tree.
pub fn build(inputs: &[CheckpointInput]) -> Vec<SessionCheckpoint> {
    inputs
        .iter()
        .map(|i| {
            let (cwd, command) = inspect(i.fg_pid, i.child_pid);
            SessionCheckpoint {
                session_id: i.session_id.clone(),
                peer_id: i.peer_id.clone(),
                username: i.username.clone(),
                cwd,
                command,
                fg_pid: i.fg_pid,
                child_pid: i.child_pid,
                title: i.title.clone(),
            }
        })
        .collect()
}

/// The process group in the foreground of the PTY behind `master`: the job the
/// shell is running, or the shell itself when idle.
pub fn foreground_pid(master: &std::os::fd::OwnedFd) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let pg = unsafe { libc::tcgetpgrp(master.as_raw_fd()) };
    (pg > 0).then_some(pg as u32)
}

/// Working directory and command for a session: from the foreground process
/// group when the terminal reports one, else from the shell's process tree.
/// A shell in the foreground means the session is idle at a prompt: its
/// directory is recorded, no command.
pub fn inspect(fg_pid: Option<u32>, child_pid: Option<u32>) -> (Option<String>, Option<String>) {
    if let Some(fg) = fg_pid {
        let cmdline = process_cmdline(fg);
        // `su`/`login` still in the foreground: the shell has not started yet,
        // so there is nothing to record (a launcher's cwd is not the user's).
        if cmdline.as_deref().is_some_and(is_launcher) {
            return (None, None);
        }
        let cwd = process_cwd(fg);
        let cmd = cmdline.filter(|c| !is_shell(c));
        if cwd.is_some() || cmd.is_some() {
            return (cwd, cmd);
        }
    }
    child_pid.map(inspect_process).unwrap_or((None, None))
}

fn argv0_name(cmdline: &str) -> &str {
    let first = cmdline.split_whitespace().next().unwrap_or("");
    first.trim_start_matches('-').rsplit('/').next().unwrap_or("")
}

/// `-bash`, `/bin/zsh -l`, `fish` …: a login/interactive shell, not a job.
fn is_shell(cmdline: &str) -> bool {
    matches!(argv0_name(cmdline), "sh" | "bash" | "zsh" | "fish" | "dash" | "ksh" | "tcsh" | "csh")
}

/// The program hop starts the session with before the user's shell takes over.
fn is_launcher(cmdline: &str) -> bool {
    matches!(argv0_name(cmdline), "su" | "login" | "sudo" | "doas")
}

/// The working directory and command line of the most recently started child
/// of `pid` (the shell's foreground job), falling back to the shell's own
/// working directory with no command.
pub fn inspect_process(pid: u32) -> (Option<String>, Option<String>) {
    let children = child_pids(pid);
    if let Some(&fg) = children.last() {
        let cwd = process_cwd(fg).or_else(|| process_cwd(pid));
        let cmd = process_cmdline(fg).filter(|c| !c.trim().is_empty() && !is_shell(c));
        return (cwd, cmd);
    }
    (process_cwd(pid), None)
}

#[cfg(target_os = "linux")]
fn process_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok().map(|p| p.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn process_cmdline(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| shell_quote(&String::from_utf8_lossy(p)))
        .collect();
    if parts.is_empty() { None } else { Some(parts.join(" ")) }
}

/// Children of `pid`, oldest first (by pid order, which follows creation
/// order closely enough for "the job the shell is running now").
#[cfg(target_os = "linux")]
fn child_pids(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return out };
    for entry in dir.flatten() {
        let Ok(child) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{child}/stat")) else { continue };
        // "pid (comm) state ppid ..." — comm may contain spaces, so split after ')'.
        let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else { continue };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() > 1 && fields[1].parse::<u32>().ok() == Some(pid) {
            out.push(child);
        }
    }
    out.sort_unstable();
    out
}

#[cfg(target_os = "macos")]
fn process_cwd(pid: u32) -> Option<String> {
    let out = std::process::Command::new("lsof").args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n').map(String::from))
}

#[cfg(target_os = "macos")]
fn process_cmdline(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps").args(["-o", "args=", "-p", &pid.to_string()]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(target_os = "macos")]
fn child_pids(pid: u32) -> Vec<u32> {
    let Ok(out) = std::process::Command::new("pgrep").args(["-P", &pid.to_string()]).output() else { return Vec::new() };
    let mut v: Vec<u32> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect();
    v.sort_unstable();
    v
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_cwd(_pid: u32) -> Option<String> { None }
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_cmdline(_pid: u32) -> Option<String> { None }
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn child_pids(_pid: u32) -> Vec<u32> { Vec::new() }

/// Quote one argv element for a POSIX shell if it needs it.
fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// If the exact process this checkpoint recorded is still alive — same pid AND
/// the same command line — return that pid. After a real host restart the pid
/// is dead (or reused by an unrelated process, whose command line won't match),
/// so this is only true when nothing actually restarted.
fn survivor_pid(cp: &SessionCheckpoint) -> Option<u32> {
    let want = cp.command.as_deref()?;
    let base = |c: &str| c.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
    for pid in [cp.fg_pid, cp.child_pid].into_iter().flatten() {
        if let Some(cur) = process_cmdline(pid)
            && (cur == want || base(&cur) == base(want))
        {
            return Some(pid);
        }
    }
    None
}

/// The command to start on restore. Programs that can resume a conversation
/// are asked to (`claude`, `pi`: `--continue`, unless the line already names
/// a conversation with `--resume`/`--continue`). A bare `--resume` would open
/// a chooser nobody is there to walk, so it becomes `--continue`.
pub fn restore_command(cmd: &str) -> String {
    let mut parts: Vec<&str> = cmd.split_whitespace().collect();
    let Some(first) = parts.first() else { return cmd.to_string() };
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    let mut prog = base(first);
    // `claude` installed through npm shows up as `node …/claude-code/cli.js`.
    if matches!(prog.as_str(), "node" | "bun" | "deno")
        && let Some(script) = parts.get(1)
    {
        if script.ends_with("claude-code/cli.js") {
            prog = "claude".into();
        } else if script.ends_with("/pi") || script.ends_with("pi/cli.js") || base(script) == "pi.js" {
            prog = "pi".into();
        }
    }
    if matches!(prog.as_str(), "claude" | "pi") {
        if let Some(i) = parts.iter().position(|p| *p == "--resume" || *p == "-r") {
            let has_id = parts.get(i + 1).is_some_and(|n| !n.starts_with('-'));
            if !has_id {
                parts[i] = "--continue";
            }
            return parts.join(" ");
        }
        if !parts.iter().any(|p| *p == "--continue" || *p == "-c") {
            parts.push("--continue");
        }
        return parts.join(" ");
    }
    cmd.to_string()
}

/// The line typed into a fresh login shell to bring a checkpoint back.
pub fn restore_line(cp: &SessionCheckpoint) -> Option<String> {
    let cd = cp.cwd.as_deref().map(|d| format!("cd {} && ", shell_quote(d))).unwrap_or_default();
    match cp.command.as_deref() {
        Some(c) => Some(format!("{cd}{}\n", restore_command(c))),
        None if !cd.is_empty() => Some(format!("{}\n", cd.trim_end_matches(" && "))),
        None => None,
    }
}

/// Identifies this daemon process, so a fresh daemon does not overwrite the
/// previous one's checkpoint with an empty list before anyone restores it.
static DAEMON_BOOT: std::sync::LazyLock<u64> = std::sync::LazyLock::new(super::session_registry::unix_now_ms);

/// Start every session in the checkpoint again, detached, owned by the same
/// peer and under that peer's current sandbox policy. Skips sessions that are
/// still running (the daemon did not restart) and peers this host no longer
/// knows. Unless `dry_run`, the checkpoint is rewritten afterwards from the
/// live registry so a second restore does not start everything twice.
pub async fn restore(
    registry: &super::session_registry::RegistryHandle,
    config_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<Vec<crate::proto::RestoreOutcome>> {
    use crate::proto::RestoreOutcome;
    let Some(file) = CheckpointFile::load(config_dir)? else { return Ok(Vec::new()) };
    let peers = crate::config::PeersStore::load(config_dir)?;
    let live: std::collections::HashSet<String> = registry.list().await.into_iter().map(|s| s.session_id).collect();
    let mut out = Vec::with_capacity(file.sessions.len());
    // The checkpoint written back afterwards: restored entries under their new
    // ids (a shell that is still logging in has nothing to inspect yet), the
    // rest unchanged.
    let mut next: Vec<SessionCheckpoint> = Vec::with_capacity(file.sessions.len());
    for cp in &file.sessions {
        let line = restore_line(cp);
        let mut o = RestoreOutcome {
            session_id: cp.session_id.clone(),
            username: cp.username.clone(),
            line: line.clone(),
            new_session_id: None,
            skipped: None,
        };
        // The owning peer, only if this host still knows it (its sandbox applies).
        let known_peer = cp.peer_id.parse::<iroh::PublicKey>().ok()
            .filter(|p| peers.peers.iter().any(|kp| kp.node_id == p.to_string()));
        if live.contains(&cp.session_id) {
            o.skipped = Some("still running".into());
        } else if survivor_pid(cp).is_some() {
            // A daemon-only restart (not a reboot) can leave the previous
            // session's shell running as an orphan; relaunching would double it.
            o.skipped = Some("its process is still running (no restart detected)".into());
        } else if let Some(peer) = known_peer {
            if !dry_run {
                let sandbox = peers.peer_sandbox(&peer);
                match start_detached(registry, config_dir, cp, &sandbox, line.as_deref()).await {
                    Ok(id) => o.new_session_id = Some(id),
                    Err(e) => o.skipped = Some(format!("could not start: {e:#}")),
                }
            }
        } else {
            o.skipped = Some("owner is no longer a peer of this host".into());
        }
        next.push(SessionCheckpoint { session_id: o.new_session_id.clone().unwrap_or_else(|| cp.session_id.clone()), ..cp.clone() });
        out.push(o);
    }
    if !dry_run {
        CheckpointFile { saved_ms: super::session_registry::unix_now_ms(), daemon_boot: *DAEMON_BOOT, sessions: next }.save(config_dir)?;
    }
    Ok(out)
}

/// Spawn a detached PTY for `cp`'s user, register it under `cp`'s owner, and
/// type the restore line into it.
async fn start_detached(
    registry: &super::session_registry::RegistryHandle,
    config_dir: &Path,
    cp: &SessionCheckpoint,
    sandbox: &crate::sandbox::SandboxPolicy,
    line: Option<&str>,
) -> anyhow::Result<String> {
    use super::session_registry::DetachedSession;
    let size = portable_pty::PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 };
    let mut env = std::collections::HashMap::new();
    env.insert("TERM".to_string(), "xterm-256color".to_string());
    let (sid, itx, output_route, rtx, erx, scr, child_pid, reader_cancel, viewers, pty_master) =
        super::spawn_persistent_pty(cp.username.as_deref(), size, &env, sandbox, config_dir, Some(registry.attention_sender()))?;
    let session = DetachedSession {
        session_id: sid.clone(),
        peer_id: cp.peer_id.clone(),
        username: cp.username.clone(),
        child_pid,
        reader_cancel,
        input_tx: itx.clone(),
        output_route,
        resize_tx: rtx,
        exit_rx: erx,
        detached_at: Some(std::time::Instant::now()),
        attached: false,
        started_unix_ms: super::session_registry::unix_now_ms(),
        attach_epoch: 1,
        broker_handle: None,
        viewers,
        pty_master,
        screen: scr,
    };
    registry.insert(session).await;
    #[cfg(target_os = "macos")]
    if sandbox.is_restricted() {
        let handle = crate::sandbox::broker::start_broker(config_dir.to_path_buf(), sid.clone(), sandbox.clone(), cp.username.clone()).await?;
        registry.set_broker_handle(sid.clone(), handle).await;
    }
    crate::audit::record(
        crate::audit::AuditEvent::new(crate::audit::AuditCategory::Session, "session.restore", crate::audit::AuditOutcome::Info)
            .actor(cp.peer_id.clone())
            .user_opt(cp.username.as_deref()),
    );
    if let Some(l) = line {
        // The PTY buffers it until the shell reads its first line.
        let _ = itx.send(l.as_bytes().to_vec());
    }
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_command_resumes_agents_and_leaves_others_alone() {
        assert_eq!(restore_command("claude"), "claude --continue");
        assert_eq!(restore_command("/usr/local/bin/claude --model x"), "/usr/local/bin/claude --model x --continue");
        assert_eq!(restore_command("claude --resume 7f3a"), "claude --resume 7f3a");
        assert_eq!(restore_command("claude --resume"), "claude --continue");
        assert_eq!(restore_command("claude -c"), "claude -c");
        assert_eq!(restore_command("pi"), "pi --continue");
        assert_eq!(restore_command("node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"), "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js --continue");
        assert!(is_shell("-bash") && is_shell("/bin/zsh -l") && !is_shell("bash-runner") && !is_shell("sleep 5"));
        assert!(is_launcher("su - hop") && is_launcher("/usr/bin/login -f hop") && !is_launcher("sudoku"));
        assert_eq!(restore_command("cargo watch -x test"), "cargo watch -x test");
        assert_eq!(restore_command(""), "");
    }

    #[test]
    fn restore_line_changes_directory_first_and_quotes() {
        let cp = SessionCheckpoint { session_id: "s".into(), peer_id: "p".into(), username: None, cwd: Some("/tmp/my proj".into()), command: Some("claude".into()), fg_pid: None, child_pid: None, title: None };
        assert_eq!(restore_line(&cp).unwrap(), "cd '/tmp/my proj' && claude --continue\n");
        let idle = SessionCheckpoint { session_id: "s".into(), peer_id: "p".into(), username: None, cwd: Some("/srv".into()), command: None, fg_pid: None, child_pid: None, title: None };
        assert_eq!(restore_line(&idle).unwrap(), "cd /srv\n");
        let nothing = SessionCheckpoint { session_id: "s".into(), peer_id: "p".into(), username: None, cwd: None, command: None, fg_pid: None, child_pid: None, title: None };
        assert!(restore_line(&nothing).is_none());
    }

    #[test]
    fn checkpoint_file_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let f = CheckpointFile { saved_ms: 5, daemon_boot: 1, sessions: vec![SessionCheckpoint { session_id: "a".into(), peer_id: "p".into(), username: Some("u".into()), cwd: Some("/x".into()), command: Some("vim".into()), fg_pid: Some(9), child_pid: Some(8), title: Some("t".into()) }] };
        f.save(dir.path()).unwrap();
        let back = CheckpointFile::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.saved_ms, 5);
        assert_eq!(back.sessions, f.sessions);
        assert!(CheckpointFile::load(tempfile::tempdir().unwrap().path()).unwrap().is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn survivor_pid_detects_a_live_matching_process() {
        let mut child = std::process::Command::new("sleep").arg("42").spawn().unwrap();
        let pid = child.id();
        let alive = SessionCheckpoint { session_id: "s".into(), peer_id: "p".into(), username: None, cwd: None, command: Some("sleep 42".into()), child_pid: Some(pid), fg_pid: None, title: None };
        // `spawn` returns before the child has finished `exec`ing `sleep`, so the
        // OS may not report its command line for a few ms — poll until it does
        // rather than race it (this is a test artifact, not a production path).
        let mut found = None;
        for _ in 0..100 {
            if let Some(p) = survivor_pid(&alive) {
                found = Some(p);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(found, Some(pid));
        // A pid that is alive but running something else does not match.
        let mismatch = SessionCheckpoint { command: Some("claude".into()), ..alive.clone() };
        assert_eq!(survivor_pid(&mismatch), None);
        let _ = child.kill();
        let _ = child.wait();
        // Dead pid: no match.
        assert_eq!(survivor_pid(&alive), None);
        // No recorded command: nothing to match against.
        let idle = SessionCheckpoint { command: None, child_pid: Some(pid), ..alive };
        assert_eq!(survivor_pid(&idle), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn foreground_pid_reads_the_job_behind_a_pty() {
        use portable_pty::{CommandBuilder, PtySize, native_pty_system};
        use std::os::fd::FromRawFd;
        let pair = native_pty_system().openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 }).unwrap();
        let mut cmd = CommandBuilder::new("sleep");
        cmd.arg("30");
        let mut child = pair.slave.spawn_command(cmd).unwrap();
        let pid = child.process_id().unwrap();
        let raw = pair.master.as_raw_fd().unwrap();
        let master = unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::dup(raw)) };
        std::thread::sleep(std::time::Duration::from_millis(200));
        let fg = foreground_pid(&master);
        let (cwd, job) = inspect(fg, None);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(fg, Some(pid), "tcgetpgrp on the master should name the job");
        assert!(cwd.is_some(), "cwd of the job");
        assert!(job.as_deref().is_some_and(|c| c.contains("sleep")), "{job:?}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn inspect_finds_a_child_and_its_directory() {
        // A `sleep` child of this process, started in a known directory: the
        // inspector must report that directory and the sleep command line.
        let dir = tempfile::tempdir().unwrap();
        let canon = dir.path().canonicalize().unwrap();
        let mut child = std::process::Command::new("sleep").arg("31").current_dir(&canon).spawn().unwrap();
        let pid = child.id();
        let listed = child_pids(std::process::id()).contains(&pid);
        let (cwd, cmd) = (process_cwd(pid), process_cmdline(pid));
        let _ = child.kill();
        let _ = child.wait();
        assert!(listed, "child {pid} not found under this process");
        assert_eq!(cwd.as_deref().map(std::path::Path::new), Some(canon.as_path()));
        assert!(cmd.as_deref().is_some_and(|c| c.contains("sleep") && c.contains("31")), "{cmd:?}");
    }
}
