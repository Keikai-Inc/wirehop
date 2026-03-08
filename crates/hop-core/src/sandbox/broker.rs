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
    "top",
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
    Exec { command: String, args: Vec<String>, rows: u16, cols: u16 },
    Input(Vec<u8>),
    Resize { rows: u16, cols: u16 },
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
        for e in std::fs::read_dir(&zdir).into_iter().flatten().flatten() {
            chown_to_user(&e.path(), user);
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

/// Commands sent to the PTY control thread.
enum PtyCmd {
    Write(Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Shutdown,
}

/// Handle a single broker client connection using a real PTY.
async fn handle_broker_connection(
    stream: tokio::net::UnixStream,
    policy: &super::SandboxPolicy,
    username: Option<&str>,
) -> anyhow::Result<()> {
    use portable_pty::{native_pty_system, PtySize};
    use std::io::Read as _;

    let (mut reader, mut writer) = stream.into_split();

    // Read the initial Exec request
    let request: BrokerRequest = read_broker_message(&mut reader).await?;

    let (command, args, rows, cols) = match request {
        BrokerRequest::Exec { command, args, rows, cols } => (command, args, rows, cols),
        _ => {
            anyhow::bail!("expected Exec as first message");
        }
    };

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
            let resp = BrokerResponse::Denied(format!("command '{}' not found", command));
            write_broker_message(&mut writer, &resp).await?;
            return Ok(());
        }
    };

    // Open PTY with client's terminal size
    let pty_system = native_pty_system();
    let size = PtySize { rows, cols, pixel_width: 0, pixel_height: 0 };
    let pair = pty_system.openpty(size).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Build command
    let cmd = build_broker_pty_command(&real_bin, &args, username);

    // Spawn on PTY
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            let resp = BrokerResponse::Denied(format!("spawn failed: {e}"));
            write_broker_message(&mut writer, &resp).await?;
            return Ok(());
        }
    };
    drop(pair.slave);

    let pty_reader = pair.master.try_clone_reader().map_err(|e| anyhow::anyhow!("{e}"))?;
    let pty_writer = pair.master.take_writer().map_err(|e| anyhow::anyhow!("{e}"))?;

    // PTY reader thread → tokio channel
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn({
        let mut pty_reader = pty_reader;
        let output_tx = output_tx;
        move || {
            let mut buf = [0u8; 4096];
            loop {
                match pty_reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if output_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    // PTY control thread — owns writer + master (for resize)
    let (pty_cmd_tx, pty_cmd_rx) = std::sync::mpsc::channel::<PtyCmd>();
    std::thread::spawn({
        let mut pty_writer = pty_writer;
        let master = pair.master;
        move || {
            use std::io::Write as _;
            while let Ok(cmd) = pty_cmd_rx.recv() {
                match cmd {
                    PtyCmd::Write(data) => {
                        let _ = pty_writer.write_all(&data);
                        let _ = pty_writer.flush();
                    }
                    PtyCmd::Resize { rows, cols } => {
                        let size = PtySize { rows, cols, pixel_width: 0, pixel_height: 0 };
                        let _ = master.resize(size);
                    }
                    PtyCmd::Shutdown => break,
                }
            }
            // master dropped here → SIGHUP → child exits
        }
    });

    // Child exit watcher
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<i32>();
    std::thread::spawn(move || {
        if let Ok(status) = child.wait() {
            let code: i32 = status.exit_code().try_into().unwrap_or(1);
            let _ = exit_tx.send(code);
        }
    });

    // Bidirectional select loop
    let mut exit_rx = exit_rx;
    let exit_code;

    loop {
        tokio::select! {
            // PTY output → client
            data = output_rx.recv() => {
                match data {
                    Some(d) => {
                        if write_broker_message(&mut writer, &BrokerResponse::Output(d)).await.is_err() {
                            // Client disconnected
                            let _ = pty_cmd_tx.send(PtyCmd::Shutdown);
                            return Ok(());
                        }
                    }
                    None => {
                        // PTY reader closed — child likely exited, wait for exit
                    }
                }
            }
            // Client → PTY (Input, Resize, or new Exec which we ignore)
            msg = read_broker_message::<BrokerRequest>(&mut reader) => {
                match msg {
                    Ok(BrokerRequest::Input(data)) => {
                        let _ = pty_cmd_tx.send(PtyCmd::Write(data));
                    }
                    Ok(BrokerRequest::Resize { rows, cols }) => {
                        let _ = pty_cmd_tx.send(PtyCmd::Resize { rows, cols });
                    }
                    Ok(BrokerRequest::Exec { .. }) => {
                        // Ignore duplicate Exec
                    }
                    Err(_) => {
                        // Client disconnected
                        let _ = pty_cmd_tx.send(PtyCmd::Shutdown);
                        return Ok(());
                    }
                }
            }
            // Child exited
            code = &mut exit_rx => {
                exit_code = code.unwrap_or(1);
                break;
            }
        }
    }

    // Drain remaining output
    while let Ok(data) = output_rx.try_recv() {
        let _ = write_broker_message(&mut writer, &BrokerResponse::Output(data)).await;
    }

    let _ = write_broker_message(&mut writer, &BrokerResponse::Exit(exit_code)).await;
    let _ = pty_cmd_tx.send(PtyCmd::Shutdown);

    Ok(())
}

/// Build a PTY command to run as the session user (unsandboxed).
fn build_broker_pty_command(
    real_bin: &Path,
    args: &[String],
    username: Option<&str>,
) -> portable_pty::CommandBuilder {
    use portable_pty::CommandBuilder;

    let mut cmd = if let Some(user) = username {
        #[cfg(target_os = "macos")]
        {
            let mut cmd = CommandBuilder::new("login");
            cmd.args(["-fp", user]);
            cmd.arg(real_bin.to_string_lossy().as_ref());
            for a in args {
                cmd.arg(a.as_str());
            }
            cmd
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            // On Linux: su - user -c 'binary args...'
            let full = std::iter::once(real_bin.to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            let mut cmd = CommandBuilder::new("su");
            cmd.args(["-", user, "-c", &full]);
            cmd
        }
        #[cfg(not(unix))]
        {
            let _ = user;
            let mut cmd = CommandBuilder::new(real_bin);
            for a in args {
                cmd.arg(a.as_str());
            }
            cmd
        }
    } else {
        let mut cmd = CommandBuilder::new(real_bin);
        for a in args {
            cmd.arg(a.as_str());
        }
        cmd
    };

    cmd.env("TERM", "xterm-256color");
    cmd
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

// ---------------------------------------------------------------------------
// Client-side terminal helpers (libc-based, no extra deps)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}

#[cfg(unix)]
fn get_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        (ws.ws_row, ws.ws_col)
    } else {
        (24, 80)
    }
}

/// RAII guard that restores the terminal to its original state on drop.
#[cfg(unix)]
struct TermGuard {
    original: libc::termios,
}

#[cfg(unix)]
impl TermGuard {
    fn enter_raw() -> Option<Self> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return None;
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { original })
    }
}

#[cfg(unix)]
impl Drop for TermGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

/// Global pipe fd for SIGWINCH self-pipe trick.
#[cfg(unix)]
static SIGWINCH_PIPE_WR: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    let fd = SIGWINCH_PIPE_WR.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            libc::write(fd, b"W".as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Synchronous broker client logic using std Unix sockets.
/// Supports bidirectional PTY I/O with raw mode for interactive commands.
fn broker_client_sync(command: &str, args: &[String], sock_path: &str) -> anyhow::Result<i32> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(sock_path)?;

    let is_tty = stdin_is_tty();
    let (rows, cols) = if is_tty { get_terminal_size() } else { (24, 80) };

    // Send the exec request
    let request = BrokerRequest::Exec {
        command: command.to_string(),
        args: args.to_vec(),
        rows,
        cols,
    };
    write_broker_message_sync(&mut &stream, &request)?;

    // Read first response — if Denied or Exit, return before entering raw mode
    let first: BrokerResponse = read_broker_message_sync(&mut &stream)?;
    match first {
        BrokerResponse::Denied(msg) => {
            eprintln!("hop broker: denied: {msg}");
            return Ok(126);
        }
        BrokerResponse::Exit(code) => {
            return Ok(code);
        }
        BrokerResponse::Output(data) => {
            use std::io::Write;
            let mut stdout = std::io::stdout();
            stdout.write_all(&data)?;
            stdout.flush()?;
        }
    }

    // Non-TTY fallback: simple read loop (no raw mode, no stdin forwarding)
    if !is_tty {
        return broker_client_pipe_loop(&stream);
    }

    // Enter raw mode
    let _term_guard = TermGuard::enter_raw();

    // Set up SIGWINCH self-pipe
    let mut sigwinch_fds = [-1i32; 2];
    unsafe { libc::pipe(sigwinch_fds.as_mut_ptr()) };
    let sigwinch_rd = sigwinch_fds[0];
    let sigwinch_wr = sigwinch_fds[1];
    SIGWINCH_PIPE_WR.store(sigwinch_wr, std::sync::atomic::Ordering::Relaxed);

    // Set read end non-blocking
    unsafe {
        let flags = libc::fcntl(sigwinch_rd, libc::F_GETFL);
        libc::fcntl(sigwinch_rd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Install signal handler
    unsafe {
        libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as libc::sighandler_t);
    }

    // Set stdin and socket non-blocking for poll()
    use std::os::unix::io::AsRawFd;
    let sock_fd = stream.as_raw_fd();
    let stdin_fd = libc::STDIN_FILENO;

    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    unsafe {
        let flags = libc::fcntl(sock_fd, libc::F_GETFL);
        libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let exit_code;
    let mut sock_buf = Vec::new(); // partial message buffer for socket reads

    // poll() loop
    loop {
        let mut pollfds = [
            libc::pollfd { fd: stdin_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sigwinch_rd, events: libc::POLLIN, revents: 0 },
        ];

        let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), 3, -1) };
        if ret < 0 {
            // EINTR is expected (from SIGWINCH), just loop
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            anyhow::bail!("poll failed: {errno}");
        }

        // stdin → send Input to server
        if pollfds[0].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 4096];
            let n = unsafe {
                libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n > 0 {
                let data = buf[..n as usize].to_vec();
                // Temporarily set socket to blocking for the write
                unsafe {
                    let flags = libc::fcntl(sock_fd, libc::F_GETFL);
                    libc::fcntl(sock_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                }
                let _ = write_broker_message_sync(&mut &stream, &BrokerRequest::Input(data));
                unsafe {
                    let flags = libc::fcntl(sock_fd, libc::F_GETFL);
                    libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }

        // socket → read response
        if pollfds[1].revents & libc::POLLIN != 0 {
            // Read available data into sock_buf
            let mut tmp = [0u8; 8192];
            loop {
                let n = unsafe {
                    libc::read(sock_fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len())
                };
                if n > 0 {
                    sock_buf.extend_from_slice(&tmp[..n as usize]);
                } else {
                    break;
                }
            }

            // Try to decode complete messages from sock_buf
            while let Some((msg, consumed)) = try_decode_broker_message::<BrokerResponse>(&sock_buf) {
                sock_buf.drain(..consumed);
                match msg {
                    BrokerResponse::Output(data) => {
                        use std::io::Write;
                        let mut stdout = std::io::stdout();
                        let _ = stdout.write_all(&data);
                        let _ = stdout.flush();
                    }
                    BrokerResponse::Exit(code) => {
                        exit_code = code;
                        // Restore stdin to blocking before returning
                        unsafe {
                            let flags = libc::fcntl(stdin_fd, libc::F_GETFL);
                            libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                        }
                        // Uninstall SIGWINCH handler
                        unsafe { libc::signal(libc::SIGWINCH, libc::SIG_DFL) };
                        SIGWINCH_PIPE_WR.store(-1, std::sync::atomic::Ordering::Relaxed);
                        unsafe {
                            libc::close(sigwinch_rd);
                            libc::close(sigwinch_wr);
                        }
                        // _term_guard drops here, restoring terminal
                        return Ok(exit_code);
                    }
                    BrokerResponse::Denied(msg) => {
                        // Shouldn't happen after first message, but handle it
                        unsafe {
                            let flags = libc::fcntl(stdin_fd, libc::F_GETFL);
                            libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                        }
                        unsafe { libc::signal(libc::SIGWINCH, libc::SIG_DFL) };
                        SIGWINCH_PIPE_WR.store(-1, std::sync::atomic::Ordering::Relaxed);
                        unsafe {
                            libc::close(sigwinch_rd);
                            libc::close(sigwinch_wr);
                        }
                        eprintln!("hop broker: denied: {msg}");
                        return Ok(126);
                    }
                }
            }
        }

        // socket hangup/error
        if pollfds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0
            && pollfds[1].revents & libc::POLLIN == 0
        {
            exit_code = 1;
            break;
        }

        // SIGWINCH → send Resize
        if pollfds[2].revents & libc::POLLIN != 0 {
            // Drain the pipe
            let mut drain = [0u8; 64];
            unsafe {
                libc::read(sigwinch_rd, drain.as_mut_ptr() as *mut libc::c_void, drain.len());
            }
            let (rows, cols) = get_terminal_size();
            // Temporarily set socket to blocking for the write
            unsafe {
                let flags = libc::fcntl(sock_fd, libc::F_GETFL);
                libc::fcntl(sock_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
            let _ = write_broker_message_sync(&mut &stream, &BrokerRequest::Resize { rows, cols });
            unsafe {
                let flags = libc::fcntl(sock_fd, libc::F_GETFL);
                libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
    }

    // Cleanup
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    unsafe { libc::signal(libc::SIGWINCH, libc::SIG_DFL) };
    SIGWINCH_PIPE_WR.store(-1, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        libc::close(sigwinch_rd);
        libc::close(sigwinch_wr);
    }
    // _term_guard drops here, restoring terminal
    Ok(exit_code)
}

/// Simple pipe-mode loop for non-TTY clients (e.g. `echo | ps`).
fn broker_client_pipe_loop(stream: &std::os::unix::net::UnixStream) -> anyhow::Result<i32> {
    let mut stdout = std::io::stdout();
    loop {
        let response: BrokerResponse = read_broker_message_sync(&mut &*stream)?;
        match response {
            BrokerResponse::Output(data) => {
                use std::io::Write;
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            BrokerResponse::Exit(code) => return Ok(code),
            BrokerResponse::Denied(msg) => {
                eprintln!("hop broker: denied: {msg}");
                return Ok(126);
            }
        }
    }
}

/// Try to decode a length-prefixed bincode message from a buffer.
/// Returns `Some((message, bytes_consumed))` or `None` if incomplete.
fn try_decode_broker_message<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Option<(T, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > 16 * 1024 * 1024 {
        return None; // corrupt
    }
    let total = 4 + len;
    if buf.len() < total {
        return None;
    }
    let (msg, _): (T, _) =
        bincode::serde::decode_from_slice(&buf[4..total], bincode::config::standard()).ok()?;
    Some((msg, total))
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
    if dir.exists()
        && let Err(e) = std::fs::remove_dir_all(&dir)
    {
        tracing::debug!("Failed to clean up broker dir {}: {e}", dir.display());
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
        assert!(is_broker_safe("top"));
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
