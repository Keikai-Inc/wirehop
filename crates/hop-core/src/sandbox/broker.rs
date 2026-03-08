//! Sandbox broker: transparently proxy setuid-blocked commands through the hop daemon.
//!
//! On macOS 15+, `sandbox-exec` categorically blocks ALL setuid binaries (`ps`, `top`,
//! `netstat`, etc.) — even with `(allow default)`. This is a kernel-level restriction.
//!
//! The broker pattern lets sandboxed shells transparently run safe read-only commands
//! by proxying them through the unsandboxed hop daemon over a Unix domain socket.
//!
//! ## Architecture
//!
//! ```text
//! User types "ps aux" in sandboxed shell
//!   → Shell finds <broker_dir>/bin/ps (symlink → /usr/local/bin/hop)
//!   → hop detects argv[0]="ps", enters broker client mode
//!   → Connects to <broker_dir>/broker.sock (Unix domain socket)
//!   → Sends BrokerRequest::Exec { command: "ps", args: ["aux"] }
//!   → Daemon validates command against policy + broker-safe list
//!   → Daemon spawns real /bin/ps aux UNSANDBOXED as session user
//!   → Streams stdout/stderr back over socket
//!   → Shim writes output to its stdout, exits with same code
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Commands that are safe to proxy through the broker.
///
/// These are read-only system tools that cannot modify state, write files,
/// or open network connections. They fail under `sandbox-exec` because they
/// are setuid binaries (on macOS), not because they are dangerous.
const BROKER_SAFE_COMMANDS: &[&str] = &[
    "ps",
    "w",
    "who",
    "last",
    "lastlog",
    "uptime",
    "netstat",
    "lsof",
    "iostat",
    "vm_stat",
    "sysctl",
    "sw_vers",
    "system_profiler",
    "diskutil",
    "ifconfig",
    "finger",
];

/// Check if a command name is on the broker-safe list.
pub fn is_broker_safe(name: &str) -> bool {
    BROKER_SAFE_COMMANDS.iter().any(|c| c.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Request from broker client (shim) to broker server (daemon).
#[derive(Debug, Serialize, Deserialize)]
pub enum BrokerRequest {
    Exec { command: String, args: Vec<String> },
}

/// Response from broker server (daemon) to broker client (shim).
#[derive(Debug, Serialize, Deserialize)]
pub enum BrokerResponse {
    /// Chunk of stdout/stderr output.
    Output(Vec<u8>),
    /// Command finished with this exit code.
    Exit(i32),
    /// Command was denied by policy.
    Denied(String),
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Directory for a session's broker files: `<config_dir>/broker/<session_id>/`.
fn broker_dir(config_dir: &Path, session_id: &str) -> PathBuf {
    config_dir.join("broker").join(session_id)
}

/// Path to the broker Unix socket: `<config_dir>/broker/<session_id>/broker.sock`.
pub fn broker_sock_path(config_dir: &Path, session_id: &str) -> PathBuf {
    broker_dir(config_dir, session_id).join("broker.sock")
}

/// Path to the shim bin directory: `<config_dir>/broker/<session_id>/bin/`.
fn shim_bin_dir(config_dir: &Path, session_id: &str) -> PathBuf {
    broker_dir(config_dir, session_id).join("bin")
}

// ---------------------------------------------------------------------------
// Resolve real binary (skip shim symlinks)
// ---------------------------------------------------------------------------

/// Search standard system paths for the real binary, skipping any path that
/// is inside a broker shim directory.
fn resolve_real_binary(command: &str) -> Option<PathBuf> {
    let search_dirs = [
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
    ];
    for dir in &search_dirs {
        let candidate = PathBuf::from(dir).join(command);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Ownership helpers
// ---------------------------------------------------------------------------

/// Change ownership of a path to the given username (best-effort, requires root).
#[cfg(unix)]
fn chown_to_user(path: &Path, username: &str) {
    let Ok(c_name) = std::ffi::CString::new(username) else { return };
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return;
    }
    let uid = unsafe { (*pw).pw_uid };
    let gid = unsafe { (*pw).pw_gid };
    let Ok(c_path) = std::ffi::CString::new(path.to_string_lossy().as_bytes().to_vec()) else {
        return;
    };
    unsafe {
        libc::chown(c_path.as_ptr(), uid, gid);
    }
}

// ---------------------------------------------------------------------------
// Shim setup
// ---------------------------------------------------------------------------

/// Create the shim `bin/` directory with symlinks for each broker-safe command
/// pointing to the hop binary.
///
/// Returns the path to the shim bin directory (to prepend to PATH).
pub fn setup_shim_dir(config_dir: &Path, session_id: &str, username: Option<&str>) -> anyhow::Result<PathBuf> {
    let session_dir = broker_dir(config_dir, session_id);
    let dir = shim_bin_dir(config_dir, session_id);
    std::fs::create_dir_all(&dir)?;

    // Find the hop binary — prefer /usr/local/bin/hop, fall back to current exe
    let hop_bin = if Path::new("/usr/local/bin/hop").exists() {
        PathBuf::from("/usr/local/bin/hop")
    } else {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/hop"))
    };

    for cmd in BROKER_SAFE_COMMANDS {
        let link_path = dir.join(cmd);
        // Remove existing symlink if any (idempotent)
        let _ = std::fs::remove_file(&link_path);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&hop_bin, &link_path)?;
    }

    // chown the broker session dir + bin dir to the session user so the
    // sandboxed shell (which runs as that user, not root) can traverse it.
    #[cfg(unix)]
    if let Some(user) = username {
        // broker/<sid>/
        chown_to_user(&session_dir, user);
        // broker/<sid>/bin/
        chown_to_user(&dir, user);
        // broker/ parent
        if let Some(parent) = session_dir.parent() {
            chown_to_user(parent, user);
        }
    }

    Ok(dir)
}

/// Create a zsh ZDOTDIR that injects broker PATH after login profile scripts.
///
/// On macOS, `zsh -l` sources `/etc/zprofile` which runs `path_helper`,
/// replacing PATH entirely from `/etc/paths` and `/etc/paths.d/`. Any PATH
/// set via `cmd.env()` before the shell starts gets wiped out.
///
/// ZDOTDIR tells zsh to read dotfiles from our directory instead of `$HOME`.
/// Our `.zprofile` runs AFTER `/etc/zprofile`, so we can prepend the shim dir
/// to the already-rebuilt PATH. We also source the user's real dotfiles so
/// their prompt, aliases, etc. still work.
///
/// Returns the zdotdir path to set as the `ZDOTDIR` environment variable.
pub fn setup_zdotdir(config_dir: &Path, session_id: &str, username: Option<&str>) -> anyhow::Result<PathBuf> {
    let zdir = broker_dir(config_dir, session_id).join("zdotdir");
    std::fs::create_dir_all(&zdir)?;

    let shim_dir = shim_bin_dir(config_dir, session_id);
    let sock_path = broker_sock_path(config_dir, session_id);

    // .zshenv — sourced first for ALL zsh invocations.
    // Source the user's real .zshenv from $HOME.
    std::fs::write(
        zdir.join(".zshenv"),
        "[ -f \"$HOME/.zshenv\" ] && . \"$HOME/.zshenv\"\n",
    )?;

    // .zprofile — sourced for login shells AFTER /etc/zprofile (path_helper).
    // This is where we prepend the shim dir to the rebuilt PATH.
    std::fs::write(
        zdir.join(".zprofile"),
        format!(
            concat!(
                "[ -f \"$HOME/.zprofile\" ] && . \"$HOME/.zprofile\"\n",
                "export PATH=\"{}:$PATH\"\n",
                "export HOP_BROKER_SOCK=\"{}\"\n",
            ),
            shim_dir.display(),
            sock_path.display(),
        ),
    )?;

    // .zshrc — sourced for interactive shells.
    // Unset HISTFILE so zsh doesn't try to write history in the read-only sandbox.
    std::fs::write(
        zdir.join(".zshrc"),
        concat!(
            "[ -f \"$HOME/.zshrc\" ] && . \"$HOME/.zshrc\"\n",
            "unset HISTFILE\n",
        ),
    )?;

    // .zlogin — sourced last for login shells.
    std::fs::write(
        zdir.join(".zlogin"),
        "[ -f \"$HOME/.zlogin\" ] && . \"$HOME/.zlogin\"\n",
    )?;

    // chown zdotdir and its files to the session user
    #[cfg(unix)]
    if let Some(user) = username {
        chown_to_user(&zdir, user);
        for entry in std::fs::read_dir(&zdir).into_iter().flatten() {
            if let Ok(e) = entry {
                chown_to_user(&e.path(), user);
            }
        }
    }

    Ok(zdir)
}

// ---------------------------------------------------------------------------
// Broker server (runs in the daemon, unsandboxed)
// ---------------------------------------------------------------------------

/// Start the broker server as a background tokio task.
///
/// Listens on a Unix domain socket and proxies validated commands.
/// Returns a `JoinHandle` that can be aborted to stop the broker.
pub async fn start_broker(
    config_dir: PathBuf,
    session_id: String,
    policy: super::SandboxPolicy,
    username: Option<String>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use tokio::net::UnixListener;

    let sock_path = broker_sock_path(&config_dir, &session_id);

    // Ensure parent directory exists
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale socket
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path)?;

    // Make the socket accessible to the session user.
    // The daemon runs as root so the socket is owned by root:wheel.
    // chown it to the session user; fall back to mode 0666 if no username.
    #[cfg(unix)]
    {
        if let Some(ref user) = username {
            chown_to_user(&sock_path, user);
            // Also chown the parent dirs so the user can traverse
            if let Some(parent) = sock_path.parent() {
                chown_to_user(parent, user);
                if let Some(grandparent) = parent.parent() {
                    chown_to_user(grandparent, user);
                }
            }
        } else {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            let _ = std::fs::set_permissions(&sock_path, perms);
        }
    }

    tracing::debug!("Broker listening on {}", sock_path.display());

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!("Broker accept error: {e}");
                    break;
                }
            };

            let policy = policy.clone();
            let username = username.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_broker_connection(stream, &policy, username.as_deref()).await
                {
                    tracing::debug!("Broker connection error: {e}");
                }
            });
        }
    });

    Ok(handle)
}

/// Handle a single broker client connection.
async fn handle_broker_connection(
    stream: tokio::net::UnixStream,
    policy: &super::SandboxPolicy,
    username: Option<&str>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    let (mut reader, mut writer) = stream.into_split();

    // Read the request (length-prefixed bincode, same as proto::read_message)
    let request: BrokerRequest = read_broker_message(&mut reader).await?;

    match request {
        BrokerRequest::Exec { command, args } => {
            // Validate: must be on broker-safe list
            if !is_broker_safe(&command) {
                let resp = BrokerResponse::Denied(format!(
                    "command '{}' is not on the broker-safe list",
                    command
                ));
                write_broker_message(&mut writer, &resp).await?;
                return Ok(());
            }

            // Validate against sandbox policy (denied_commands, allowed_commands)
            let full_cmd = if args.is_empty() {
                command.clone()
            } else {
                format!("{} {}", command, args.join(" "))
            };
            if let Err(e) = super::validate_command(&full_cmd, policy) {
                let resp = BrokerResponse::Denied(format!("policy denied: {e}"));
                write_broker_message(&mut writer, &resp).await?;
                return Ok(());
            }

            // Resolve the real binary
            let real_bin = match resolve_real_binary(&command) {
                Some(p) => p,
                None => {
                    let resp =
                        BrokerResponse::Denied(format!("command '{}' not found", command));
                    write_broker_message(&mut writer, &resp).await?;
                    return Ok(());
                }
            };

            // Spawn the command unsandboxed as the session user
            let mut cmd = build_broker_command(&real_bin, &args, username);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let resp = BrokerResponse::Denied(format!("spawn failed: {e}"));
                    write_broker_message(&mut writer, &resp).await?;
                    return Ok(());
                }
            };

            // Stream stdout + stderr to the client
            let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

            if let Some(mut stdout) = child.stdout.take() {
                let tx = output_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stdout.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            if let Some(mut stderr) = child.stderr.take() {
                let tx = output_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stderr.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // Drop sender so output_rx closes when both stdout/stderr finish
            drop(output_tx);

            // Forward output chunks
            while let Some(data) = output_rx.recv().await {
                write_broker_message(&mut writer, &BrokerResponse::Output(data)).await?;
            }

            // Wait for exit
            let status = child.wait().await?;
            let code = status.code().unwrap_or(1);
            write_broker_message(&mut writer, &BrokerResponse::Exit(code)).await?;
        }
    }

    Ok(())
}

/// Build a command to run as the session user (unsandboxed).
fn build_broker_command(
    real_bin: &Path,
    args: &[String],
    username: Option<&str>,
) -> tokio::process::Command {
    use std::process::Stdio;

    if let Some(user) = username {
        #[cfg(target_os = "macos")]
        {
            let mut cmd = tokio::process::Command::new("login");
            cmd.args(["-fp", user])
                .arg(real_bin)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            // On Linux: su - user -c 'binary args...'
            let full = std::iter::once(real_bin.to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            let mut cmd = tokio::process::Command::new("su");
            cmd.args(["-", user, "-c", &full])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }
        #[cfg(not(unix))]
        {
            let _ = user;
            let mut cmd = tokio::process::Command::new(real_bin);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        }
    } else {
        let mut cmd = tokio::process::Command::new(real_bin);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
}

// ---------------------------------------------------------------------------
// Broker client (runs inside the sandboxed shell as the shim)
// ---------------------------------------------------------------------------

/// Entry point for broker client mode (called when hop is invoked via symlink).
///
/// Fully synchronous — uses `std::os::unix::net::UnixStream` so it works even
/// when called from inside an existing tokio runtime (e.g. the hop daemon).
/// Returns the exit code.
pub fn broker_client_main(command: &str, args: &[String]) -> i32 {
    let sock = match std::env::var("HOP_BROKER_SOCK") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("hop broker: HOP_BROKER_SOCK not set");
            return 127;
        }
    };

    match broker_client_sync(command, args, &sock) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hop broker: {e}");
            127
        }
    }
}

/// Synchronous broker client logic using std Unix sockets.
fn broker_client_sync(command: &str, args: &[String], sock_path: &str) -> anyhow::Result<i32> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)?;

    // Send the exec request
    let request = BrokerRequest::Exec {
        command: command.to_string(),
        args: args.to_vec(),
    };
    write_broker_message_sync(&mut stream, &request)?;

    // Read responses and write output to stdout
    let mut stdout = std::io::stdout();
    loop {
        let response: BrokerResponse = read_broker_message_sync(&mut stream)?;
        match response {
            BrokerResponse::Output(data) => {
                use std::io::Write;
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            BrokerResponse::Exit(code) => {
                return Ok(code);
            }
            BrokerResponse::Denied(msg) => {
                eprintln!("hop broker: denied: {msg}");
                return Ok(126);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wire format helpers (same length-prefixed bincode as proto::write_message)
// ---------------------------------------------------------------------------

async fn write_broker_message<T: Serialize>(
    stream: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    msg: &T,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let payload = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .context("broker encode failed")?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("broker write length")?;
    stream
        .write_all(&payload)
        .await
        .context("broker write payload")?;
    stream.flush().await.context("broker flush")?;
    Ok(())
}

async fn read_broker_message<T: for<'de> Deserialize<'de>>(
    stream: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> anyhow::Result<T> {
    use anyhow::Context;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("broker read length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        anyhow::bail!("broker frame too large: {len} bytes");
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("broker read payload")?;

    let (msg, _) = bincode::serde::decode_from_slice(&payload, bincode::config::standard())
        .context("broker decode failed")?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Synchronous wire format helpers (for broker client — no tokio dependency)
// ---------------------------------------------------------------------------

fn write_broker_message_sync<T: Serialize>(
    stream: &mut impl std::io::Write,
    msg: &T,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let payload = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .context("broker encode failed")?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).context("broker write length")?;
    stream.write_all(&payload).context("broker write payload")?;
    stream.flush().context("broker flush")?;
    Ok(())
}

fn read_broker_message_sync<T: for<'de> Deserialize<'de>>(
    stream: &mut impl std::io::Read,
) -> anyhow::Result<T> {
    use anyhow::Context;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).context("broker read length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        anyhow::bail!("broker frame too large: {len} bytes");
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).context("broker read payload")?;

    let (msg, _) = bincode::serde::decode_from_slice(&payload, bincode::config::standard())
        .context("broker decode failed")?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Remove the broker socket and shim directory for a session.
pub fn cleanup_broker(config_dir: &Path, session_id: &str) {
    let dir = broker_dir(config_dir, session_id);
    if dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            tracing::debug!("Failed to clean up broker dir {}: {e}", dir.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_safe_list_contains_ps() {
        assert!(is_broker_safe("ps"));
        assert!(is_broker_safe("PS"));
        assert!(is_broker_safe("netstat"));
        assert!(!is_broker_safe("top")); // interactive/ncurses — not brokered
        assert!(!is_broker_safe("rm"));
        assert!(!is_broker_safe("bash"));
    }

    #[test]
    fn resolve_real_binary_finds_ps() {
        // /bin/ps should exist on macOS and most Linux
        let result = resolve_real_binary("ps");
        assert!(result.is_some(), "should find ps binary");
        let path = result.unwrap();
        assert!(path.exists(), "resolved path should exist: {}", path.display());
    }

    #[test]
    fn broker_dir_paths() {
        let config = Path::new("/Library/Application Support/hop");
        let sid = "abc123";
        assert_eq!(
            broker_sock_path(config, sid),
            PathBuf::from("/Library/Application Support/hop/broker/abc123/broker.sock")
        );
        assert_eq!(
            shim_bin_dir(config, sid),
            PathBuf::from("/Library/Application Support/hop/broker/abc123/bin")
        );
    }
}
