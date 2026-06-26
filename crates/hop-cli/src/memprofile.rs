//! `hop debug mem-profile` — restart the host daemon in memory-profiling mode and
//! snapshot its live heap, using each platform's native profiler:
//!
//!   - **macOS**: `MallocStackLogging` + `malloc_history`/`leaks`. Works on the
//!     normal release binary (it's an env var, not a build), keeps the daemon
//!     fully functional, and snapshots a *live* process repeatedly without killing
//!     it. `malloc_history` tracks only `malloc`, so mmap'd redb/blob noise is
//!     excluded automatically.
//!   - **Linux**: jemalloc heap profiling. The shipped binary links jemalloc with
//!     `prof` support but inactive (negligible overhead); profiling mode re-execs
//!     with `MALLOC_CONF=prof:true`, and a snapshot triggers `prof.dump`, analyzed
//!     with `jeprof`.
//!
//! Why a daemon restart rather than a flip on the running process: both profilers
//! must be armed before `malloc` initializes, so we re-exec the same binary with
//! the right environment. Profiling mode runs the daemon as a single root process
//! (privsep off) so the privilege-drop can't disable the logging. A self-restoring
//! watchdog guarantees the normal privsep daemon comes back even if `off` is never
//! run, so you can never get stranded on the profiling daemon.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where we record the running profiling daemon so `snapshot`/`off`/the watchdog
/// can find it. World-readable so a non-root `snapshot` can read the pid.
const STATE_FILE: &str = "/tmp/hop-memprofile.json";
/// stdout/stderr of the profiling daemon.
const DAEMON_LOG: &str = "/tmp/hop-memprofile-daemon.log";
/// Deterministic path the Linux daemon dumps its jemalloc heap profile to, so the
/// `snapshot` command knows where to find it without guessing a generated name.
#[cfg(target_os = "linux")]
const LINUX_HEAP: &str = "/tmp/hop-jeprof-latest.heap";
/// Hard deadline after which the watchdog restores the normal daemon no matter
/// what. Long enough to reproduce a slow leak, short enough you're never stuck.
const DEFAULT_WATCHDOG_SECS: u64 = 1800;

/// Actions for `hop debug mem-profile`.
pub enum Action {
    /// Restart the host daemon in profiling mode (full speed; serves traffic).
    On,
    /// Write a sorted, symbolized heap report from the running profiling daemon.
    Snapshot { out: Option<PathBuf> },
    /// Restore the normal (privsep) daemon.
    Off,
    /// Hidden: the detached watchdog body — sleeps, then restores. Not user-run.
    Watchdog { deadline_secs: u64 },
}

pub fn run(action: Action, config_dir: &Path) -> Result<()> {
    match action {
        Action::On => on(config_dir, DEFAULT_WATCHDOG_SECS),
        Action::Off => off(config_dir, true),
        Action::Snapshot { out } => snapshot(out),
        Action::Watchdog { deadline_secs } => watchdog(config_dir, deadline_secs),
    }
}

// ── State ────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct State {
    pid: u32,
    watchdog_pid: Option<u32>,
    started_unix: u64,
    platform: String,
}

impl State {
    fn load() -> Option<State> {
        let bytes = std::fs::read(STATE_FILE).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
    fn save(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(STATE_FILE, json).with_context(|| format!("writing {STATE_FILE}"))?;
        // World-readable so `snapshot` can run without sudo.
        let _ = std::fs::set_permissions(
            STATE_FILE,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644),
        );
        Ok(())
    }
    fn remove() {
        let _ = std::fs::remove_file(STATE_FILE);
    }
}

// ── on ───────────────────────────────────────────────────────────────────────

fn on(config_dir: &Path, watchdog_secs: u64) -> Result<()> {
    require_root("mem-profile on")?;
    if let Some(s) = State::load() {
        if pid_alive(s.pid) {
            bail!(
                "mem-profile is already on (daemon pid {}). Run `hop debug mem-profile off` first.",
                s.pid
            );
        }
        State::remove();
    }
    if !profiler_available() {
        bail!(
            "{}",
            unavailable_msg()
        );
    }

    println!("Stopping the normal {} ...", platform::service_desc());
    platform::stop_service();
    // Give the old daemon a moment to release the redb lock + TUN (the datastore
    // open already retries the hand-off, so this just keeps startup quiet).
    std::thread::sleep(Duration::from_secs(3));

    println!("Starting the profiling daemon (full release speed, privsep off) ...");
    let exe = std::env::current_exe().context("resolving current executable")?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(DAEMON_LOG)
        .with_context(|| format!("opening {DAEMON_LOG}"))?;
    let mut cmd = Command::new(&exe);
    cmd.arg("host")
        .arg("--config")
        .arg(config_dir)
        .arg("--quiet")
        .env("HOP_MEM_PROFILE", "1")
        // Profiling needs a single root process: privsep would drop privileges and
        // disable the malloc logging, and split the heap across two processes.
        .env_remove("HOP_PRIVSEP")
        .env_remove("HOP_PRIVSEP_DROP")
        .env_remove("HOP_PRIVSEP_WORKER")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    platform::profiling_env(&mut cmd);
    detach(&mut cmd);
    let child = cmd.spawn().context("spawning profiling daemon")?;
    let pid = child.id();

    // Verify it actually came up.
    std::thread::sleep(Duration::from_secs(20));
    if !pid_alive(pid) {
        eprintln!("Profiling daemon (pid {pid}) failed to start; see {DAEMON_LOG}. Restoring normal daemon.");
        platform::start_service();
        bail!("profiling daemon did not stay up");
    }

    // Independent watchdog: a detached copy of ourselves that restores the normal
    // daemon after the deadline regardless of what happens to this process.
    let watchdog_pid = spawn_watchdog(config_dir, watchdog_secs).ok();

    State {
        pid,
        watchdog_pid,
        started_unix: now_unix(),
        platform: platform::name().to_string(),
    }
    .save()?;

    println!();
    println!("✅ Profiling daemon is up (pid {pid}). It serves traffic normally.");
    println!("   Reproduce the leak (e.g. your VNC session), then snapshot the heap:");
    println!("     sudo hop debug mem-profile snapshot");
    println!("   (repeatable as the leak grows). When done:");
    println!("     sudo hop debug mem-profile off");
    println!(
        "   Safety: the watchdog auto-restores the normal daemon in {}s no matter what.",
        watchdog_secs
    );
    Ok(())
}

// ── off ──────────────────────────────────────────────────────────────────────

fn off(config_dir: &Path, verbose: bool) -> Result<()> {
    let _ = config_dir;
    require_root("mem-profile off")?;
    if let Some(s) = State::load() {
        if verbose {
            println!("Stopping the profiling daemon (pid {}) ...", s.pid);
        }
        // Clean stop by PID (never a pattern — that was the old script's bug).
        kill(s.pid, libc::SIGTERM);
        for _ in 0..15 {
            if !pid_alive(s.pid) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if pid_alive(s.pid) {
            kill(s.pid, libc::SIGKILL);
        }
        if let Some(wd) = s.watchdog_pid {
            kill(wd, libc::SIGTERM);
        }
        State::remove();
    } else if verbose {
        println!("No profiling daemon recorded; restoring the normal daemon anyway.");
    }

    if verbose {
        println!("Restoring the normal {} ...", platform::service_desc());
    }
    platform::start_service();
    std::thread::sleep(Duration::from_secs(2));
    if verbose {
        if normal_daemon_running() {
            println!("✅ Normal daemon restored.");
        } else {
            println!("⚠️  Normal daemon not detected yet; it may still be starting.");
        }
    }
    Ok(())
}

// ── watchdog ─────────────────────────────────────────────────────────────────

fn watchdog(config_dir: &Path, deadline_secs: u64) -> Result<()> {
    std::thread::sleep(Duration::from_secs(deadline_secs));
    // Only act if a profiling daemon is still recorded (off() clears the state).
    if State::load().is_some() {
        let _ = off(config_dir, false);
    }
    Ok(())
}

fn spawn_watchdog(config_dir: &Path, deadline_secs: u64) -> Result<u32> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.arg("debug")
        .arg("mem-profile")
        .arg("__watchdog")
        .arg("--deadline")
        .arg(deadline_secs.to_string())
        .arg("--config")
        .arg(config_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    detach(&mut cmd);
    Ok(cmd.spawn().context("spawning watchdog")?.id())
}

// ── snapshot ─────────────────────────────────────────────────────────────────

fn snapshot(out: Option<PathBuf>) -> Result<()> {
    let s = State::load().context(
        "mem-profile is not on. Run `sudo hop debug mem-profile on` first, reproduce the leak, then snapshot.",
    )?;
    if !pid_alive(s.pid) {
        bail!(
            "the profiling daemon (pid {}) is not running. Run `hop debug mem-profile on` again.",
            s.pid
        );
    }
    let out = out.unwrap_or_else(|| default_report_path(s.pid));
    platform::snapshot(s.pid, &out)
}

// ── self-snapshot (called by the daemon's SIGUSR2 handler) ────────────────────

/// Write a heap snapshot of THIS process. Called from the host daemon's SIGUSR2
/// handler so `kill -USR2 <pid>` works too. Returns the path of the artifact
/// written (a `.txt` report on macOS, a `.heap` profile on Linux).
pub fn self_snapshot() -> Result<PathBuf> {
    platform::self_snapshot(std::process::id())
}

/// Whether this daemon was started in profiling mode (`mem-profile on`).
pub fn in_profiling_mode() -> bool {
    std::env::var_os("HOP_MEM_PROFILE").is_some()
}

// ── shared helpers ───────────────────────────────────────────────────────────

fn default_report_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/hop-heap-{pid}-{}.txt", now_unix()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn require_root(what: &str) -> Result<()> {
    if !hop_core::unix_user::is_running_as_root() {
        bail!("`hop debug {what}` manages the system daemon — run it with sudo.");
    }
    Ok(())
}

fn pid_alive(pid: u32) -> bool {
    // signal 0: existence/permission check without delivering a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn kill(pid: u32, sig: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
}

/// Put the spawned daemon/watchdog in its own session so it survives this process
/// (and the user's shell) exiting.
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

fn normal_daemon_running() -> bool {
    // The installed daemon runs the binary at this path; the profiling daemon runs
    // current_exe() (the dev/installed binary directly). Good enough as a check.
    pgrep_running("/usr/local/bin/hop host") || pgrep_running("hop host --quiet")
}

fn pgrep_running(pattern: &str) -> bool {
    Command::new("pgrep")
        .arg("-f")
        .arg(pattern)
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run a service-control command; ignore failure (e.g. bootout when not loaded).
fn run_ok(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Capture a command's stdout as a String (for malloc_history / jeprof).
fn capture(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn profiler_available() -> bool {
    platform::profiler_available()
}

fn unavailable_msg() -> String {
    platform::unavailable_msg()
}

// ── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn name() -> &'static str {
        "macos"
    }
    pub fn service_desc() -> &'static str {
        "LaunchDaemon com.hop.daemon"
    }

    pub fn stop_service() {
        run_ok("launchctl", &["bootout", "system/com.hop.daemon"]);
    }
    pub fn start_service() {
        run_ok(
            "launchctl",
            &["bootstrap", "system", "/Library/LaunchDaemons/com.hop.daemon.plist"],
        );
    }

    pub fn profiling_env(cmd: &mut Command) {
        // The macOS-native allocation backtrace recorder. Must be set before the
        // process starts (we re-exec ourselves with it), which is why this is an
        // `on` (restart) rather than a flip on the running daemon.
        cmd.env("MallocStackLogging", "1");
    }

    pub fn profiler_available() -> bool {
        which("malloc_history") && which("leaks")
    }
    pub fn unavailable_msg() -> String {
        "malloc_history/leaks not found (they ship with Xcode / the Command Line Tools). \
         Install with `xcode-select --install`."
            .into()
    }

    pub fn snapshot(pid: u32, out: &Path) -> Result<()> {
        // Live allocations grouped by call stack, sorted by size: the leak is on
        // top. `leaks` adds an unreferenced-blocks view.
        let hist = capture("malloc_history", &[&pid.to_string(), "-allBySize"])
            .context("malloc_history (is MallocStackLogging on? use `mem-profile on`)")?;
        let leaks = capture("leaks", &[&pid.to_string()]).unwrap_or_default();
        write_report(out, pid, &hist, &leaks)?;
        print_head(out, &hist);
        Ok(())
    }

    pub fn self_snapshot(pid: u32) -> Result<PathBuf> {
        // The daemon (root) runs malloc_history against itself.
        let out = default_report_path(pid);
        let hist = capture("malloc_history", &[&pid.to_string(), "-allBySize"])?;
        std::fs::write(&out, hist).with_context(|| format!("writing {}", out.display()))?;
        Ok(out)
    }

    fn which(bin: &str) -> bool {
        Command::new("which")
            .arg(bin)
            .stdout(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn write_report(out: &Path, pid: u32, hist: &str, leaks: &str) -> Result<()> {
        let leaks_tail: String = leaks.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        let body = format!(
            "hop heap snapshot (macOS malloc_history) — pid {pid}, {}\n\
             ============================================================\n\
             # `malloc_history -allBySize` (live allocations by call stack, largest first):\n\n\
             {hist}\n\n\
             ============================================================\n\
             # `leaks` summary (tail):\n\n{leaks_tail}\n",
            now_unix()
        );
        std::fs::write(out, body).with_context(|| format!("writing {}", out.display()))?;
        Ok(())
    }

    fn print_head(out: &Path, hist: &str) {
        println!("Heap snapshot written to {}", out.display());
        println!("Top of `malloc_history -allBySize` (largest live call stacks first):\n");
        for line in hist.lines().take(40) {
            println!("{line}");
        }
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn name() -> &'static str {
        "linux"
    }
    pub fn service_desc() -> String {
        format!("systemd {}", unit())
    }

    fn unit() -> String {
        std::env::var("HOP_SERVICE").unwrap_or_else(|_| "hop".into())
    }

    pub fn stop_service() {
        run_ok("systemctl", &["stop", &unit()]);
    }
    pub fn start_service() {
        run_ok("systemctl", &["start", &unit()]);
    }

    pub fn profiling_env(cmd: &mut Command) {
        // jemalloc: enable profiling collection. lg_prof_sample:19 ≈ one sample per
        // 512 KiB allocated — low overhead, plenty of resolution for a GB leak.
        cmd.env("MALLOC_CONF", "prof:true,prof_active:true,lg_prof_sample:19");
    }

    pub fn profiler_available() -> bool {
        // jemalloc is compiled in; jeprof is only needed to symbolize and we degrade
        // gracefully without it, so profiling is always "available" on Linux.
        true
    }
    pub fn unavailable_msg() -> String {
        String::new()
    }

    pub fn snapshot(pid: u32, out: &Path) -> Result<()> {
        // Ask the daemon to dump a heap profile (its SIGUSR2 handler calls
        // prof.dump → LINUX_HEAP), then symbolize it with jeprof if available.
        super::kill(pid, libc::SIGUSR2);
        std::thread::sleep(Duration::from_secs(2));
        let heap = PathBuf::from(LINUX_HEAP);
        if !heap.exists() {
            bail!(
                "no jemalloc heap dump at {} — is the daemon in profiling mode (`mem-profile on`)?",
                LINUX_HEAP
            );
        }
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("hop"));
        match capture(
            "jeprof",
            &[
                "--text",
                "--show_bytes",
                exe.to_str().unwrap_or("hop"),
                heap.to_str().unwrap_or(""),
            ],
        ) {
            Ok(text) if !text.trim().is_empty() => {
                std::fs::write(out, &text).with_context(|| format!("writing {}", out.display()))?;
                println!("Heap snapshot written to {} (from {})", out.display(), heap.display());
                for line in text.lines().take(40) {
                    println!("{line}");
                }
            }
            _ => {
                println!(
                    "jemalloc heap dump written to {}. Install `jeprof` to symbolize:\n  jeprof --text {} {}",
                    heap.display(),
                    exe.display(),
                    heap.display()
                );
            }
        }
        Ok(())
    }

    pub fn self_snapshot(_pid: u32) -> Result<PathBuf> {
        // Trigger jemalloc's dump to the deterministic LINUX_HEAP path. mallctl
        // `prof.dump` reads `newp` as a `const char *` filename, so we pass the
        // CString's pointer (kept alive across the call).
        let path = std::ffi::CString::new(LINUX_HEAP).expect("static path has no NUL");
        let ptr: *const std::os::raw::c_char = path.as_ptr();
        unsafe {
            tikv_jemalloc_ctl::raw::write(b"prof.dump\0", ptr).map_err(|e| {
                anyhow::anyhow!(
                    "jemalloc prof.dump failed: {e} (profiling not active? start with `mem-profile on`)"
                )
            })?;
        }
        Ok(PathBuf::from(LINUX_HEAP))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_path_is_per_pid() {
        let a = default_report_path(123);
        assert!(a.to_string_lossy().contains("hop-heap-123-"));
        assert!(a.to_string_lossy().ends_with(".txt"));
    }

    #[test]
    fn state_roundtrips() {
        let s = State {
            pid: 4242,
            watchdog_pid: Some(4243),
            started_unix: 1000,
            platform: "macos".into(),
        };
        let json = serde_json::to_vec(&s).unwrap();
        let back: State = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.pid, 4242);
        assert_eq!(back.watchdog_pid, Some(4243));
    }
}
