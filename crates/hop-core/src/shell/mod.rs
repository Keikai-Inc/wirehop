//! PTY and terminal management.

pub mod session_registry;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use tokio::sync::{mpsc, watch};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proto::{self, ClientMessage, HostMessage};
use session_registry::{DetachedSession, RegistryHandle};

/// RAII guard that restores the terminal from raw mode on drop.
///
/// Ensures the terminal is never left in raw mode even if the shell loop
/// panics or returns early via `?`. Public so the client can hold raw mode
/// CONTINUOUSLY across a session → reconnect → session lifecycle: dropping it
/// between phases (as the per-function guards did) leaves the background stdin
/// reader's in-flight read in cooked/line-buffered mode, so keystrokes aren't
/// delivered until Enter — which is why `q` "didn't work" on the reconnect dialog.
pub struct RawModeGuard;

impl RawModeGuard {
    pub fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("Failed to enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Write a HostMessage, using zstd compression when the connection supports it (V3+).
async fn write_host_message(
    stream: &mut (impl AsyncWriteExt + Unpin),
    msg: &HostMessage,
    compress: bool,
) -> Result<()> {
    if compress {
        proto::write_message_compressed(stream, msg).await
    } else {
        proto::write_message(stream, msg).await
    }
}

/// Outcome of a client shell session.
#[derive(Debug)]
pub enum SessionOutcome {
    /// Host sent an Exit message with a status code — clean exit, don't reconnect.
    Exited(i32),
    /// Connection error — the session may be reconnectable.
    Disconnected,
}

/// Opening and closing markers a terminal wraps a paste in when the remote
/// app has enabled bracketed-paste mode (DECSET 2004).
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

/// Find the first occurrence of `needle` in `haystack`, returning its start index.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Tracks bracketed-paste state across a session and carries the one input
/// chunk that can be lost at a disconnect, so the input stream survives a
/// reconnect without corrupting an in-progress paste.
///
/// Why this exists: a reconnect that lands mid-paste used to drop the chunk
/// being sent at that instant. If that chunk held the closing `ESC[201~`, the
/// remote vim/tmux stayed stuck treating every later keystroke as literal
/// paste text. `in_paste` lets the reconnect logic tell "this buffered input
/// is paste content that must be delivered" from "this is free typing during
/// a visible reconnect dialog that should be dropped rather than dumped into
/// the shell".
#[derive(Default)]
pub struct InputReplay {
    /// True if the bytes delivered to the host so far ended inside a paste
    /// (a `PASTE_START` with no matching `PASTE_END` yet).
    in_paste: bool,
    /// Up to `PASTE_END.len() - 1` trailing bytes of the last observed chunk,
    /// carried forward so a marker split across chunk boundaries is still seen.
    tail: Vec<u8>,
    /// The chunk pulled from the input channel but not successfully sent when
    /// the connection dropped. Replayed first on resume so no bytes are lost.
    unsent: Vec<u8>,
}

impl InputReplay {
    /// Update paste state from a chunk that was just delivered to the host.
    /// Only call this for bytes the host actually received (or will receive
    /// via replay) — never for a chunk that was dropped — so `in_paste`
    /// reflects exactly what the remote terminal has seen.
    fn observe(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return; // heartbeat / empty write — no terminal effect
        }
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(chunk);

        // Scan for whichever marker comes last; markers are the same length.
        let mlen = PASTE_START.len();
        let mut i = 0;
        while i + mlen <= buf.len() {
            if &buf[i..i + mlen] == PASTE_START {
                self.in_paste = true;
                i += mlen;
            } else if &buf[i..i + mlen] == PASTE_END {
                self.in_paste = false;
                i += mlen;
            } else {
                i += 1;
            }
        }

        // Carry the trailing bytes that could be the head of a marker split
        // across the next chunk. Keeping fewer than a full marker guarantees a
        // complete marker can't sit entirely in the tail, so it's never
        // double-counted on the next call.
        let keep = buf.len().min(mlen - 1);
        self.tail = buf.split_off(buf.len() - keep);
    }

    /// Whether the host's terminal is currently mid-paste.
    pub fn in_paste(&self) -> bool {
        self.in_paste
    }

    /// Take the un-sent in-flight chunk captured at the last disconnect.
    pub fn take_unsent(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.unsent)
    }

    /// Decide which buffered bytes to replay after a *visible* reconnect.
    ///
    /// If the host was mid-paste, deliver the stream up to and including the
    /// closing `ESC[201~` so the paste completes — and drop anything typed
    /// after it, so a flood of keystrokes banged out during the dialog isn't
    /// dumped into the shell. If the close marker hasn't been buffered yet,
    /// deliver all of it (it's still paste content) and let the resumed loop
    /// carry the eventual close through normally. If not mid-paste, drop
    /// everything — free typing during a visible reconnect is discarded.
    pub fn filter_replay(&self, stream: &[u8]) -> Vec<u8> {
        if !self.in_paste {
            return Vec::new();
        }
        match find_subslice(stream, PASTE_END) {
            Some(i) => stream[..i + PASTE_END.len()].to_vec(),
            None => stream.to_vec(),
        }
    }
}

/// A session PTY master: either locally spawned (the daemon is root, or the
/// session runs as the daemon's own user) or created by the privsep monitor and
/// handed to us as a raw master fd. The two share one I/O surface so the bridge
/// loop is identical; only acquisition differs.
#[cfg(unix)]
enum SessionPty {
    /// Worker spawned the PTY itself (current behavior).
    Local(Box<dyn portable_pty::MasterPty + Send>),
    /// privsep monitor spawned the (setuid) session; we own the master fd. The
    /// monitor owns + reaps the child, so there's no local `Child` to wait — the
    /// session ends when the master reads EOF.
    Passed(std::fs::File),
}

#[cfg(unix)]
impl SessionPty {
    fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        match self {
            SessionPty::Local(m) => m.try_clone_reader().map_err(|e| anyhow::anyhow!("{e}")),
            SessionPty::Passed(f) => Ok(Box::new(f.try_clone().context("clone passed PTY master")?)),
        }
    }
    fn take_writer(&self) -> Result<Box<dyn Write + Send>> {
        match self {
            SessionPty::Local(m) => m.take_writer().map_err(|e| anyhow::anyhow!("{e}")),
            SessionPty::Passed(f) => Ok(Box::new(f.try_clone().context("clone passed PTY master")?)),
        }
    }
    /// The PTY master's raw fd, for the persistent cancellable reader (which
    /// dups it). `None` if the local master can't expose one.
    fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        match self {
            SessionPty::Local(m) => m.as_raw_fd(),
            SessionPty::Passed(f) => Some(f.as_raw_fd()),
        }
    }
    fn resize(&self, size: PtySize) -> Result<()> {
        match self {
            SessionPty::Local(m) => m.resize(size).map_err(|e| anyhow::anyhow!("{e}")),
            SessionPty::Passed(f) => {
                use std::os::fd::AsRawFd;
                let ws = libc::winsize {
                    ws_row: size.rows,
                    ws_col: size.cols,
                    ws_xpixel: size.pixel_width,
                    ws_ypixel: size.pixel_height,
                };
                let rc = unsafe { libc::ioctl(f.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
                anyhow::ensure!(rc == 0, "TIOCSWINSZ: {}", std::io::Error::last_os_error());
                Ok(())
            }
        }
    }
}

/// Resolve the session command and acquire its PTY. Returns the master plus the
/// local `Child` to wait on (`None` when the privsep monitor owns the child).
///
/// The privsep monitor is used exactly when this worker cannot itself switch
/// users — it is unprivileged (`!root`) but a peer is bound to an account, so
/// the `login`/`su` the worker built needs root. In every other case (daemon is
/// root, or session runs as the worker's own user) the worker spawns locally,
/// byte-identically to the pre-privsep path.
#[cfg(unix)]
fn acquire_session_pty(
    sandbox: &crate::sandbox::SandboxPolicy,
    shell: &str,
    username: Option<&str>,
    env_pairs: &[(String, String)],
    size: PtySize,
    broker_config: Option<&std::path::Path>,
) -> Result<(SessionPty, Option<Box<dyn portable_pty::Child + Send + Sync>>)> {
    let (bin, args) = crate::sandbox::sandboxed_shell(sandbox, shell, username, broker_config);

    let via_monitor = username.is_some()
        && !crate::unix_user::is_running_as_root()
        && crate::privsep::is_privsep_worker();

    if via_monitor {
        let mut argv = Vec::with_capacity(1 + args.len());
        argv.push(bin);
        argv.extend(args);
        let fd = crate::privsep::worker_spawn_session(
            &argv,
            env_pairs,
            size.rows,
            size.cols,
            size.pixel_width,
            size.pixel_height,
            username,
        )
        .context("privsep monitor SpawnSession")?;
        return Ok((SessionPty::Passed(std::fs::File::from(fd)), None));
    }

    let pair = native_pty_system().openpty(size).context("Failed to open PTY")?;
    let mut cmd = CommandBuilder::new(&bin);
    cmd.args(args.iter().map(|s| s.as_str()));
    for (k, v) in env_pairs {
        cmd.env(k, v);
    }
    let child = pair
        .slave
        .spawn_command(cmd)
        .context("Failed to spawn shell")?;
    drop(pair.slave);
    Ok((SessionPty::Local(pair.master), Some(child)))
}

/// Build the allowlisted environment for a session PTY from client-supplied
/// vars, defaulting `TERM` for old clients. Shared by the local and monitor
/// spawn paths so both apply the identical security allowlist.
fn session_env_pairs(env_vars: &HashMap<String, String>) -> Vec<(String, String)> {
    const ENV_ALLOWLIST: &[&str] = &[
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_COLLATE",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        "COLORTERM",
    ];
    let mut pairs: Vec<(String, String)> = ENV_ALLOWLIST
        .iter()
        .filter_map(|k| env_vars.get(*k).map(|v| (k.to_string(), v.clone())))
        .collect();
    if !env_vars.contains_key("TERM") {
        pairs.push(("TERM".to_string(), "xterm-256color".to_string()));
    }
    pairs
}

/// Host side: spawn a PTY and bridge I/O over the wire protocol.
///
/// If `username` is `Some`, the shell runs as that Unix user via `login -fp`
/// (macOS) or `su -` (other Unix). This requires the host to run as root.
/// If `None`, the shell runs as the current user (backward compatible).
///
/// If `sandbox` has restrictions, the shell is spawned inside an OS-native
/// sandbox (macOS Seatbelt / Linux Landlock).
pub async fn host_shell_session(
    mut send: SendStream,
    mut recv: RecvStream,
    username: Option<&str>,
    sandbox: &crate::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
    protocol_version: u8,
) -> Result<()> {
    if let Err(e) = check_shell_security(username) {
        let _ = proto::write_message(&mut send, &HostMessage::SessionError(format!("{e:#}"))).await;
        return Err(e);
    }

    // --- Read initial setup messages from the client (WindowSize, SetEnv) ---
    let mut initial_size = PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    };
    let mut env_vars = HashMap::new();
    let mut leftover_msg: Option<ClientMessage> = None;

    for _ in 0..2 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            proto::read_message::<ClientMessage>(&mut recv),
        )
        .await
        {
            Ok(Ok(ClientMessage::WindowSize {
                cols,
                rows,
                pixel_width,
                pixel_height,
            })) => {
                initial_size.cols = cols;
                initial_size.rows = rows;
                initial_size.pixel_width = pixel_width;
                initial_size.pixel_height = pixel_height;
            }
            Ok(Ok(ClientMessage::SetEnv { vars })) => {
                env_vars = vars;
            }
            Ok(Ok(other)) => {
                // Non-setup message — save it and break out
                leftover_msg = Some(other);
                break;
            }
            Ok(Err(_)) | Err(_) => {
                // Read error or timeout — old client or done sending setup
                break;
            }
        }
    }

    // Use the target user's login shell, not the daemon's $SHELL.
    #[cfg(unix)]
    let shell = match username {
        Some(user) => crate::unix_user::user_login_shell(user),
        None => std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
    };
    #[cfg(not(unix))]
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let broker_config = if sandbox.is_restricted() { Some(config_dir) } else { None };
    let env_pairs = session_env_pairs(&env_vars);

    // Acquire the session PTY — locally, or (unprivileged worker + bound user)
    // via the privsep monitor. `child` is the local process to wait on; `None`
    // means the monitor owns + reaps it and we detect exit via master EOF.
    let (session_pty, child) = acquire_session_pty(
        sandbox,
        &shell,
        username,
        &env_pairs,
        initial_size,
        broker_config,
    )?;

    let pty_writer = session_pty.take_writer().context("take PTY writer")?;

    // Wrap the pty_writer in Arc<Mutex<>> for sharing between tasks
    let pty_writer = std::sync::Arc::new(std::sync::Mutex::new(pty_writer));

    // Keep master alive so PTY doesn't close
    let _master = session_pty;

    // Channel for PTY output -> network
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    // Channel for PTY close notification
    let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<i32>();

    // Route the single exit sender to exactly one owner: the local child waiter
    // when we have a child, otherwise the reader task (which fires it on master
    // EOF — the session-end signal when the privsep monitor owns the child).
    let (child_waiter, mut eof_exit_tx) = match child {
        Some(c) => (Some((c, exit_tx)), None),
        None => (None, Some(exit_tx)),
    };

    // Spawn blocking reader for PTY output
    let mut pty_reader2 = _master.try_clone_reader().context("clone PTY reader")?;
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader2.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if output_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Master EOF == session ended; report exit for the monitor-owned case.
        if let Some(tx) = eof_exit_tx.take() {
            let _ = tx.send(0);
        }
    });

    // Spawn blocking waiter for the local child exit (absent when the monitor
    // owns and reaps the child — see the EOF path above).
    if let Some((mut child, exit_tx)) = child_waiter {
        tokio::task::spawn_blocking(move || {
            if let Ok(status) = child.wait() {
                let code = status.exit_code().try_into().unwrap_or(1);
                let _ = exit_tx.send(code);
            }
        });
    }

    // Process any leftover message from the setup phase
    if let Some(msg) = leftover_msg {
        match msg {
            ClientMessage::Input(data) => {
                let writer = pty_writer.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(mut w) = writer.lock() {
                        pty_write_all_blocking(&mut **w, &data);
                    }
                });
            }
            ClientMessage::WindowSize {
                cols,
                rows,
                pixel_width,
                pixel_height,
            } => {
                let _ = _master.resize(PtySize {
                    rows,
                    cols,
                    pixel_width,
                    pixel_height,
                });
                let _ = proto::write_message(&mut send, &HostMessage::WindowSizeAck).await;
            }
            _ => {}
        }
    }

    // Main loop: multiplex between PTY output, client input, and child exit
    let compress = protocol_version >= 3;
    let mut clean_exit = false;
    // Cancellation-safe reader (legacy V0 shell path) — same fix as the persistent
    // loop: a bare `read_message` select! branch loses bytes if `output_rx` cancels
    // it mid-frame under a flood, desyncing the stream.
    let mut framed = proto::FramedReader::new(&mut recv);
    loop {
        tokio::select! {
            // PTY output -> send to client
            Some(data) = output_rx.recv() => {
                if let Err(e) = write_host_message(&mut send, &HostMessage::Output(data), compress).await {
                    tracing::debug!("Failed to send output: {e}");
                    break;
                }
            }
            // Client messages -> write to PTY
            msg = framed.next::<ClientMessage>() => {
                match msg {
                    Ok(ClientMessage::Input(data)) => {
                        let writer = pty_writer.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Ok(mut w) = writer.lock() {
                                let _ = w.write_all(&data);
                                let _ = w.flush();
                            }
                        });
                    }
                    Ok(ClientMessage::WindowSize {
                        cols,
                        rows,
                        pixel_width,
                        pixel_height,
                    }) => {
                        let _ = _master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width,
                            pixel_height,
                        });
                        let _ = proto::write_message(&mut send, &HostMessage::WindowSizeAck).await;
                    }
                    Ok(_) => {
                        tracing::warn!("Unexpected message during shell session");
                    }
                    Err(_) => {
                        tracing::debug!("Client disconnected");
                        break;
                    }
                }
            }
            // Child process exited
            Ok(code) = &mut exit_rx => {
                // Drain remaining output
                while let Ok(data) = output_rx.try_recv() {
                    let _ = write_host_message(&mut send, &HostMessage::Output(data), compress).await;
                }
                let _ = proto::write_message(&mut send, &HostMessage::Exit(code)).await;
                clean_exit = true;
                break;
            }
        }
    }

    // Gracefully close the send stream so the client receives all buffered
    // data (including the Exit message). Without this, dropping the
    // SendStream sends a QUIC RESET which discards undelivered data —
    // causing the client to see a disconnection instead of a clean exit.
    if clean_exit {
        let _ = send.finish();
        // Keep connection alive briefly so QUIC delivers the Exit message
        // before the Connection is dropped. Cap at 200ms to avoid hanging.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            recv.read_to_end(1),
        )
        .await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Persistent session support
// ---------------------------------------------------------------------------

/// Outcome of the attached I/O loop for persistent sessions.
enum AttachOutcome {
    /// The shell exited.
    Exited,
    /// The client disconnected (network error).
    Disconnected,
}

/// Validate that the daemon can safely serve this peer.
/// When running as root, a bound username is required to drop privileges.
/// Used by shell, exec, and transfer sessions.
pub fn check_shell_security(username: Option<&str>) -> Result<()> {
    #[cfg(unix)]
    {
        use crate::unix_user;

        let is_root = unix_user::is_running_as_root();

        if is_root && username.is_none() {
            bail!(
                "hop host is running as root but this peer has no bound username — \
                 refusing to grant a root shell. Re-invite this peer with \
                 `hop invite --user <username>` to bind them to a specific account."
            );
        }

        if let Some(name) = username {
            unix_user::validate_username(name)?;

            // A non-root daemon can't switch users — except the privsep worker,
            // which delegates the setuid spawn to its root monitor (SpawnSession).
            if !is_root && !crate::privsep::is_privsep_worker() {
                bail!(
                    "peer is bound to user '{name}' but hop host is not running as root — \
                     restart with `sudo hop host` to enable per-user shell sessions."
                );
            }
        }
    }
    Ok(())
}

/// Read initial WindowSize and SetEnv setup messages from the client (up to 2s timeout each).
async fn read_setup_messages(
    recv: &mut RecvStream,
) -> (PtySize, HashMap<String, String>, Option<ClientMessage>) {
    let mut initial_size = PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    };
    let mut env_vars = HashMap::new();
    let mut leftover_msg: Option<ClientMessage> = None;

    for _ in 0..2 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            proto::read_message::<ClientMessage>(recv),
        )
        .await
        {
            Ok(Ok(ClientMessage::WindowSize {
                cols,
                rows,
                pixel_width,
                pixel_height,
            })) => {
                initial_size.cols = cols;
                initial_size.rows = rows;
                initial_size.pixel_width = pixel_width;
                initial_size.pixel_height = pixel_height;
            }
            Ok(Ok(ClientMessage::SetEnv { vars })) => {
                env_vars = vars;
            }
            Ok(Ok(other)) => {
                leftover_msg = Some(other);
                break;
            }
            Ok(Err(_)) | Err(_) => {
                break;
            }
        }
    }

    (initial_size, env_vars, leftover_msg)
}

/// Spawn the cancellable PTY-output reader (security: PTY fd-leak hardening).
///
/// Owns a `dup`'d, non-blocking clone of the PTY master `master_fd`, wrapped in
/// an `AsyncFd`, and feeds each chunk into `screen` and (when a client is
/// attached) the route channel. The task ends — dropping the master clone and
/// reclaiming the `/dev/ptmx` — on **either** EOF (the slave fully closed) or a
/// `cancel` notification. Cancellation is what makes fd reclamation independent
/// of the child: the registry fires `cancel` on removal, so the daemon releases
/// its master fd even if a backgrounded/`nohup`'d survivor still holds the slave
/// open and EOF never comes.
///
/// Write every byte of `data` to a PTY master, retrying on `WouldBlock`.
///
/// The master fd is non-blocking: `spawn_cancellable_pty_reader` `dup()`s it for
/// the async reader and sets `O_NONBLOCK`, and `O_NONBLOCK` lives on the shared
/// open file description (dup'd fds share it), so the writer's fd is non-blocking
/// too. A plain `write_all` would then return `WouldBlock` the moment the PTY
/// input buffer fills mid-paste and SILENTLY DROP the unwritten tail — losing a
/// bracketed paste's closing `ESC[201~`, which leaves the remote terminal stuck
/// in paste mode (typed control keys become literal paste content, so e.g. tmux
/// stops catching Ctrl-L). Retrying until every byte lands is the backpressure the
/// input-writer design already assumes (bytes queue in the unbounded channel
/// while this blocks).
fn pty_write_all_blocking<W: std::io::Write + ?Sized>(w: &mut W, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        match w.write(&data[off..]) {
            Ok(0) => return, // slave closed — nothing more we can do
            Ok(n) => off += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                // Buffer full (or signal): wait briefly for the app to drain it.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(_) => return, // real error (e.g. SIGHUP'd slave)
        }
    }
    let _ = w.flush();
}

#[cfg(unix)]
fn spawn_cancellable_pty_reader(
    master_fd: std::os::unix::io::RawFd,
    screen: Arc<std::sync::Mutex<hop_vt::VtScreen>>,
    route_rx: watch::Receiver<Option<mpsc::Sender<Vec<u8>>>>,
    cancel: Arc<tokio::sync::Notify>,
    // Under privsep the monitor owns the child, so there's no local `wait()` to
    // report exit — the reader signals it on master EOF instead. `None` for the
    // local path, where the child-exit watcher owns the exit channel.
    exit_on_eof: Option<watch::Sender<Option<i32>>>,
) -> Result<()> {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    // Dup the master so the reader owns an independent fd it can close on cancel
    // without disturbing the master handle held by the resize task.
    let dup = unsafe { libc::dup(master_fd) };
    if dup < 0 {
        return Err(anyhow::anyhow!("dup PTY master: {}", std::io::Error::last_os_error()));
    }
    // AsyncFd requires the fd be non-blocking.
    unsafe {
        let flags = libc::fcntl(dup, libc::F_GETFL);
        if flags < 0 || libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(dup);
            return Err(anyhow::anyhow!("set PTY master non-blocking: {e}"));
        }
    }
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    let async_fd = tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE)
        .context("register PTY master with reactor")?;

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                biased;
                _ = cancel.notified() => break,
                readable = async_fd.readable() => {
                    let mut guard = match readable {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    let read_res = guard.try_io(|afd| {
                        let raw = afd.get_ref().as_raw_fd();
                        let n = unsafe {
                            libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    });
                    match read_res {
                        Ok(Ok(0)) => break,            // EOF: slave fully closed
                        Ok(Ok(n)) => {
                            let data = buf[..n].to_vec();
                            { screen.lock().unwrap().advance(&data); }
                            // Clone the sender out of the watch borrow *before*
                            // awaiting, so we never hold the Ref across .await.
                            let tx = route_rx.borrow().clone();
                            if let Some(tx) = tx {
                                let _ = tx.send(data).await;
                            }
                        }
                        Ok(Err(_)) => break,           // read error (e.g. EIO on hangup)
                        Err(_would_block) => continue, // readiness cleared; re-poll
                    }
                }
            }
        }
        // Master EOF/hangup == the shell exited. Under privsep (no local child
        // waiter) report it so the attach loop can send Exit and the registry
        // reaps the session.
        if let Some(tx) = exit_on_eof {
            let _ = tx.send(Some(0));
        }
        // async_fd drops here → the dup'd master fd closes.
    });
    Ok(())
}

/// Spawn a new PTY session with all persistent infrastructure.
///
/// The PTY master lives in a background task that handles resize commands
/// and keeps the PTY alive. Dropping the returned channels causes the
/// background tasks to exit and the PTY to close (SIGHUP to the shell).
#[allow(clippy::type_complexity)]
fn spawn_persistent_pty(
    username: Option<&str>,
    size: PtySize,
    env_vars: &HashMap<String, String>,
    sandbox: &crate::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
) -> Result<(
    String,                                                          // session_id
    mpsc::UnboundedSender<Vec<u8>>,                                  // input_tx
    watch::Sender<Option<mpsc::Sender<Vec<u8>>>>,                    // output_route
    watch::Sender<PtySize>,                                          // resize_tx (current size)
    watch::Receiver<Option<i32>>,                                     // exit_rx
    Arc<std::sync::Mutex<hop_vt::VtScreen>>,                          // screen
    Option<u32>,                                                     // child pid (for kill-on-removal)
    Arc<tokio::sync::Notify>,                                        // reader cancel (release master fd on removal)
)> {
    let session_id = session_registry::generate_session_id();

    // Persistent sessions are not yet relocated to the privsep monitor: the
    // detached-session machinery (a resize task that owns the portable-pty
    // master, pid-based registry kill, the cancellable reader) doesn't yet have
    // a monitor-passed-fd variant. Refuse loudly rather than spawn `login`/`su`
    // as the unprivileged worker (which would fail opaquely). One-shot shells,
    // exec, and transfer all work under privsep; persistent is the remaining
    // surface (privsep-node.md §10 Phase 3).

    // Use the target user's login shell, not the daemon's $SHELL.
    // When the daemon runs as root, $SHELL is /bin/sh, but the user's
    // shell is typically /bin/zsh on macOS.
    #[cfg(unix)]
    let shell = match username {
        Some(user) => crate::unix_user::user_login_shell(user),
        None => std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
    };
    #[cfg(not(unix))]
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let broker_config = if sandbox.is_restricted() { Some(config_dir) } else { None };

    // Allowlisted client env + (macOS, restricted) the broker shim vars, so both
    // the local and privsep-monitor spawn paths get an identical environment.
    #[allow(unused_mut)]
    let mut env_pairs = session_env_pairs(env_vars);
    #[cfg(target_os = "macos")]
    if sandbox.is_restricted() {
        let _ = crate::sandbox::broker::setup_shim_dir(config_dir, &session_id, username);
        if let Ok(zdotdir) =
            crate::sandbox::broker::setup_zdotdir(config_dir, &session_id, username)
        {
            env_pairs.push(("ZDOTDIR".to_string(), zdotdir.to_string_lossy().into_owned()));
        }
        let sock_path = crate::sandbox::broker::broker_sock_path(config_dir, &session_id);
        env_pairs.push((
            "HOP_BROKER_SOCK".to_string(),
            sock_path.to_string_lossy().into_owned(),
        ));
    }

    // Acquire the PTY — locally, or via the privsep monitor when we're the
    // unprivileged worker with a bound user. `child` is None on the monitor path
    // (the monitor owns + reaps the child; exit arrives as master EOF).
    let (session_pty, child) =
        acquire_session_pty(sandbox, &shell, username, &env_pairs, size, broker_config)?;

    let pty_writer = session_pty.take_writer().context("take PTY writer")?;
    let pty_writer = Arc::new(std::sync::Mutex::new(pty_writer));

    // Output routing via watch channel
    let (output_route_tx, output_route_rx) =
        watch::channel::<Option<mpsc::Sender<Vec<u8>>>>(None);

    // Off-screen virtual terminal: every PTY output byte runs through a
    // vt parser into an alacritty grid. On reconnect we render the current
    // grid to bytes — escape sequences are present-tense and complete by
    // construction, fixing the corruption the prior raw-byte ring caused.
    let screen = Arc::new(std::sync::Mutex::new(hop_vt::VtScreen::new(
        size.rows,
        size.cols,
    )));

    // Persistent PTY reader — feeds VtScreen, routes to client if attached.
    //
    // The reader is *cancellable* (security: PTY fd-leak hardening): it owns a
    // dup'd, non-blocking clone of the master wrapped in an `AsyncFd` and
    // selects on a `reader_cancel` signal. On session removal the registry
    // fires that signal, so the task drops its master fd **immediately** and
    // the `/dev/ptmx` is reclaimed — even if a survivor process (a backgrounded
    // or `nohup`'d job) still holds the slave open and EOF never arrives.
    // Killing the shell alone isn't enough in that case; this is what makes
    // reclamation independent of what the child or its leftover jobs do.
    let reader_cancel = std::sync::Arc::new(tokio::sync::Notify::new());

    // Exit channel, created here so the reader can own it on the privsep path.
    // Local path: the child-exit watcher below sends the real code. Privsep path
    // (no local child): the reader reports exit on master EOF.
    let (exit_tx, exit_rx) = watch::channel::<Option<i32>>(None);

    let master_fd = session_pty
        .as_raw_fd()
        .context("PTY master exposes no raw fd")?;
    let exit_on_eof = if child.is_none() {
        Some(exit_tx.clone())
    } else {
        None
    };
    spawn_cancellable_pty_reader(
        master_fd,
        screen.clone(),
        output_route_rx.clone(),
        reader_cancel.clone(),
        exit_on_eof,
    )?;

    // Input writer task. Unbounded so the shell select-loop never blocks on
    // send: if the PTY's small kernel input buffer fills mid-paste, bytes
    // queue here instead of stalling the loop (which would starve heartbeats).
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_clone = pty_writer.clone();
    tokio::task::spawn_blocking(move || {
        while let Some(data) = input_rx.blocking_recv() {
            if let Ok(mut w) = writer_clone.lock() {
                pty_write_all_blocking(&mut **w, &data);
            }
        }
    });

    // Current PTY dimensions as a watch channel — single source of truth
    // for the master, the VtScreen feeder, and anyone else who needs to
    // know "how big is this session right now?". Initial value matches the
    // size the PTY was opened with so observers can synchronously borrow()
    // the current dims at startup without waiting for a changed() signal.
    let (resize_tx, mut resize_rx) = watch::channel::<PtySize>(size);

    // PTY-master task: owns the master handle (keeps the PTY alive) and
    // applies resize commands as they land on the watch. Uses
    // Handle::block_on because portable-pty's resize() is a blocking
    // syscall and we're inside spawn_blocking; awaiting changed() directly
    // would require a separate tokio task that can't safely hold the
    // master across .await on a non-Send-bounded API.
    let master = session_pty;
    tokio::task::spawn_blocking(move || {
        let _master = master;
        let handle = tokio::runtime::Handle::current();
        loop {
            if handle.block_on(resize_rx.changed()).is_err() {
                break; // all senders dropped → session ending
            }
            let new_size = *resize_rx.borrow_and_update();
            let _ = _master.resize(new_size);
        }
        // _master drops here → PTY master closes → shell gets SIGHUP. Under
        // privsep the worker holds the only master, so this is the sole closer.
    });

    // VtScreen-resize task: separate watcher for the off-screen grid.
    // Same watch, separate consumer. Without this the screen would render
    // at the size the PTY was opened with even after a SIGWINCH-driven
    // resize, and the repaint we send on reconnect would be encoded for
    // the wrong dimensions.
    let mut screen_size_rx = resize_tx.subscribe();
    let screen_for_resize = screen.clone();
    tokio::spawn(async move {
        while screen_size_rx.changed().await.is_ok() {
            let new_size = *screen_size_rx.borrow_and_update();
            screen_for_resize
                .lock()
                .unwrap()
                .resize(new_size.rows, new_size.cols);
        }
    });

    // Child exit watcher. Local path only: capture the pid so the registry can
    // SIGKILL the shell on removal, and wait() it for the real exit code. On the
    // privsep path the monitor owns + reaps the child — there is no local pid,
    // the reader already reports exit on master EOF, and removal relies on the
    // master-close SIGHUP (the worker holds the only master fd).
    let child_pid = child.as_ref().and_then(|c| c.process_id());
    if let Some(mut child) = child {
        tokio::task::spawn_blocking(move || {
            if let Ok(status) = child.wait() {
                let code: i32 = status.exit_code().try_into().unwrap_or(1);
                let _ = exit_tx.send(Some(code));
            }
        });
    }

    Ok((session_id, input_tx, output_route_tx, resize_tx, exit_rx, screen, child_pid, reader_cancel))
}

/// Run the attached I/O loop: forward PTY output to client, client input to PTY.
///
/// Returns `Exited(code)` if the shell exits, or `Disconnected` if the client
/// disconnects (allowing the session to be preserved for reconnection).
#[allow(clippy::too_many_arguments)]
async fn run_attached_loop(
    send: SendStream,
    recv: &mut RecvStream,
    input_tx: &mpsc::UnboundedSender<Vec<u8>>,
    output_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_tx: &watch::Sender<PtySize>,
    exit_rx: &mut watch::Receiver<Option<i32>>,
    leftover_msg: Option<ClientMessage>,
    protocol_version: u8,
) -> AttachOutcome {
    /// Heartbeat interval: send an empty Output so the client knows we're alive.
    const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
    /// Read deadline: if no message arrives from the client within this time, treat as dead.
    /// Must be above QUIC idle timeout (60s) + margin for lossy-network resilience.
    const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(75);

    let compress = protocol_version >= 3;

    // Dedicated writer task owns the QUIC send stream so a stalled send window
    // (a slow or vanished client on a degraded path) can NEVER park this loop —
    // parking it would stop it reading client Input and freeze the PTY (the
    // symmetric half of the client-side input-freeze bug). All host->client
    // writes funnel through it, preserving the exact wire format: Output is
    // compressed under v3, control messages (WindowSizeAck/Exit) are not. On a
    // clean Exit the channel closes and the writer flushes `finish()`; on any
    // write error it reports back so the loop disconnects promptly.
    let (host_tx, mut host_rx) = mpsc::unbounded_channel::<HostMessage>();
    let (writer_err_tx, mut writer_err_rx) = mpsc::channel::<()>(1);
    let writer = tokio::spawn(async move {
        let mut send = send;
        while let Some(msg) = host_rx.recv().await {
            let res = match &msg {
                HostMessage::Output(_) => write_host_message(&mut send, &msg, compress).await,
                _ => proto::write_message(&mut send, &msg).await,
            };
            if res.is_err() {
                let _ = writer_err_tx.send(()).await;
                return; // stream is dead; nothing to finish
            }
        }
        // Channel closed (clean Exit path) — flush a graceful stream close.
        let _ = send.finish();
    });

    // Process any leftover message from setup phase
    if let Some(msg) = leftover_msg {
        match msg {
            ClientMessage::Input(data) => {
                let _ = input_tx.send(data);
            }
            ClientMessage::WindowSize {
                cols, rows, pixel_width, pixel_height,
            } => {
                let _ = resize_tx.send(PtySize { rows, cols, pixel_width, pixel_height });
                let _ = host_tx.send(HostMessage::WindowSizeAck);
            }
            _ => {}
        }
    }

    // Heartbeat: periodic empty Output to keep the client's read deadline alive
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Read deadline: backstop for cases where QUIC fails to report a dead client
    let read_deadline = tokio::time::sleep(READ_DEADLINE);
    tokio::pin!(read_deadline);

    // Cancellation-safe framed reader — the symmetric half of the client fix. The
    // always-ready `output_rx` branch would otherwise cancel a mid-frame client
    // read during a flood, desyncing the stream and disconnecting the session.
    let mut framed = proto::FramedReader::new(&mut *recv);

    let outcome = loop {
        tokio::select! {
            Some(data) = output_rx.recv() => {
                if host_tx.send(HostMessage::Output(data)).is_err() {
                    break AttachOutcome::Disconnected;
                }
            }
            // Writer task hit a send error — the client is gone.
            Some(()) = writer_err_rx.recv() => {
                tracing::debug!("Host write failed, client disconnected");
                break AttachOutcome::Disconnected;
            }
            msg = framed.next::<ClientMessage>() => {
                // Any message from the client means the connection is alive
                read_deadline.as_mut().reset(tokio::time::Instant::now() + READ_DEADLINE);

                match msg {
                    Ok(ClientMessage::Input(data)) => {
                        let _ = input_tx.send(data);
                    }
                    Ok(ClientMessage::WindowSize {
                        cols, rows, pixel_width, pixel_height,
                    }) => {
                        let _ = resize_tx.send(PtySize { rows, cols, pixel_width, pixel_height });
                        let _ = host_tx.send(HostMessage::WindowSizeAck);
                    }
                    Ok(_) => {
                        tracing::warn!("Unexpected message during shell session");
                    }
                    Err(_) => {
                        tracing::debug!("Client disconnected");
                        break AttachOutcome::Disconnected;
                    }
                }
            }
            // Heartbeat: enqueue empty Output to keep client's read deadline alive
            _ = heartbeat.tick() => {
                let _ = host_tx.send(HostMessage::Output(vec![]));
            }
            // Read deadline: no data from client for too long
            () = &mut read_deadline => {
                tracing::info!("No data from client for {}s, treating as disconnected", READ_DEADLINE.as_secs());
                break AttachOutcome::Disconnected;
            }
            Ok(()) = exit_rx.changed() => {
                let exit_code = { *exit_rx.borrow_and_update() };
                if let Some(code) = exit_code {
                    // Drain remaining output, then Exit. The writer flushes these
                    // and calls finish() once we drop host_tx below.
                    while let Ok(data) = output_rx.try_recv() {
                        let _ = host_tx.send(HostMessage::Output(data));
                    }
                    let _ = host_tx.send(HostMessage::Exit(code));
                    break AttachOutcome::Exited;
                }
            }
        }
    };

    match outcome {
        AttachOutcome::Exited => {
            // Close the channel so the writer drains the queued Output+Exit and
            // calls send.finish(), then wait briefly for that flush to complete.
            drop(host_tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;
        }
        AttachOutcome::Disconnected => {
            // Client is gone; don't wait on a write that may never drain.
            writer.abort();
        }
    }
    outcome
}

/// Host side: persistent shell session that survives client disconnects.
///
/// Uses the session registry to store/retrieve PTY sessions. On disconnect,
/// the PTY stays alive. On reconnect with the same session_id, the client
/// resumes the existing session.
#[allow(clippy::too_many_arguments)]
pub async fn host_shell_session_persistent(
    mut send: SendStream,
    mut recv: RecvStream,
    username: Option<&str>,
    peer_id: &str,
    requested_session_id: Option<String>,
    registry: RegistryHandle,
    sandbox: &crate::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
    protocol_version: u8,
) -> Result<()> {
    if let Err(e) = check_shell_security(username) {
        let _ = proto::write_message(&mut send, &HostMessage::SessionError(format!("{e:#}"))).await;
        return Err(e);
    }
    crate::audit::record(
        crate::audit::AuditEvent::new(
            crate::audit::AuditCategory::Session,
            "session.start",
            crate::audit::AuditOutcome::Info,
        )
        .actor(peer_id.to_string())
        .user_opt(username),
    );

    let (initial_size, env_vars, leftover_msg) = read_setup_messages(&mut recv).await;

    // Channel for receiving routed PTY output during this attachment.
    let (client_output_tx, mut client_output_rx) = mpsc::channel::<Vec<u8>>(64);

    // If the client sent a session_id, try to resume that specific session.
    // Otherwise (new connection), always spawn a new PTY.
    let (session_id, resumed, input_tx, resize_tx, mut exit_rx, attach_epoch, screen) =
        if let Some(ref requested_id) = requested_session_id {
            // Reconnect: try to resume the specific session (peer_id validated inside actor)
            if let Some(result) = registry.attach(requested_id.clone(), peer_id.to_string(), client_output_tx.clone(), initial_size).await {
                (
                    result.session_id,
                    true,
                    result.input_tx,
                    result.resize_tx,
                    result.exit_rx,
                    result.attach_epoch,
                    result.screen,
                )
            } else {
                // Session gone or exited — spawn new
                let (sid, itx, output_route, rtx, erx, scr, child_pid, reader_cancel) =
                    spawn_persistent_pty(username, initial_size, &env_vars, sandbox, config_dir)?;
                let _ = output_route.send(Some(client_output_tx));
                let session = DetachedSession {
                    session_id: sid.clone(),
                    peer_id: peer_id.to_string(),
                    username: username.map(String::from),
                    child_pid,
                    reader_cancel,
                    input_tx: itx.clone(),
                    output_route,
                    resize_tx: rtx.clone(),
                    exit_rx: erx.clone(),
                    detached_at: None,
                    attached: true,
                    attach_epoch: 1,
                    broker_handle: None,
                    screen: scr.clone(),
                };
                registry.insert(session).await;
                (sid, false, itx, rtx, erx, 1u64, scr)
            }
        } else {
            // New connection — always spawn a new PTY
            let (sid, itx, output_route, rtx, erx, scr, child_pid, reader_cancel) =
                spawn_persistent_pty(username, initial_size, &env_vars, sandbox, config_dir)?;
            let _ = output_route.send(Some(client_output_tx));
            let session = DetachedSession {
                session_id: sid.clone(),
                peer_id: peer_id.to_string(),
                username: username.map(String::from),
                child_pid,
                reader_cancel,
                input_tx: itx.clone(),
                output_route,
                resize_tx: rtx.clone(),
                exit_rx: erx.clone(),
                detached_at: None,
                attached: true,
                attach_epoch: 1,
                broker_handle: None,
                screen: scr.clone(),
            };
            registry.insert(session).await;
            (sid, false, itx, rtx, erx, 1u64, scr)
        };

    // Start broker for sandboxed sessions (macOS)
    #[cfg(target_os = "macos")]
    if !resumed && sandbox.is_restricted() {
        match crate::sandbox::broker::start_broker(
            config_dir.to_path_buf(),
            session_id.clone(),
            sandbox.clone(),
            username.map(String::from),
        )
        .await
        {
            Ok(handle) => {
                registry.set_broker_handle(session_id.clone(), handle).await;
            }
            Err(e) => {
                tracing::warn!("Failed to start broker: {e}");
            }
        }
    }

    // Send SessionInfo to client
    proto::write_message(
        &mut send,
        &HostMessage::SessionInfo {
            session_id: session_id.clone(),
            resumed,
        },
    )
    .await?;

    tracing::info!(
        "Shell session {} for peer {} (resumed: {})",
        &session_id[..8],
        peer_id,
        resumed
    );

    // Repaint on resume: render the current grid as bytes so the client
    // sees the present state — not whatever bytes happened to be in a
    // ring at the moment of detach. We deliberately do NOT mutate the
    // screen here: synchronously resizing it to the new client's dims
    // caused alacritty to grow the grid before the captured app had a
    // chance to SIGWINCH-redraw, so the freshly-added rows/cols
    // rendered as blank — manifesting as a missing lower-left quadrant
    // when the left pane's app (Claude, vim, etc.) is slower to repaint
    // than the right pane's. Instead, snapshot the screen as it stands
    // and tell `render` the client's viewport so the bytes are sized for
    // the receiving terminal; the async resize fan-out (PTY-master task
    // and VtScreen-resize task) will catch up afterward via the watch,
    // and the captured app's SIGWINCH-driven redraw will flow through
    // the normal live-forwarding path.
    if resumed {
        let dump_enabled = std::env::var_os("HOP_DEBUG_RESUME_DUMP").is_some();
        let (repaint_bytes, dump_info) = {
            let s = screen.lock().unwrap();
            let bytes = s.render(initial_size.rows, initial_size.cols, hop_vt::Prelude::Initial);
            let info = if dump_enabled {
                Some((s.dims(), s.text_rows()))
            } else {
                None
            };
            (bytes, info)
        };

        if let Some((grid_dims, grid_text)) = dump_info {
            // HOP_DEBUG_RESUME_DUMP=1 emits two files per resume:
            //   /tmp/hop_resume_<id8>.bin   — the exact bytes sent over the wire
            //   /tmp/hop_resume_<id8>.txt   — what the daemon's grid thinks is on
            //                                  screen, as plain text per row
            // Comparing the two answers "is data missing in the bytes, or missing
            // from the grid itself?". Overwrites on every resume — copy off
            // between cycles to capture multiple states.
            let id8 = &session_id[..8];
            let bin_path = format!("/tmp/hop_resume_{id8}.bin");
            let txt_path = format!("/tmp/hop_resume_{id8}.txt");
            let _ = std::fs::write(&bin_path, &repaint_bytes);
            let mut txt = format!(
                "# session={id8} grid_dims=(rows={}, cols={}) client_vp=(rows={}, cols={}) bytes={}\n",
                grid_dims.0,
                grid_dims.1,
                initial_size.rows,
                initial_size.cols,
                repaint_bytes.len(),
            );
            for (i, row) in grid_text.iter().enumerate() {
                txt.push_str(&format!("{:3}: {}\n", i + 1, row));
            }
            let _ = std::fs::write(&txt_path, txt);
            tracing::info!(
                "Resume dump: {} bytes → {}; grid text → {}",
                repaint_bytes.len(),
                bin_path,
                txt_path,
            );
        }

        let compress = protocol_version >= 3;
        tracing::info!(
            "Repainting {} bytes for resumed session {}",
            repaint_bytes.len(),
            &session_id[..8]
        );
        write_host_message(&mut send, &HostMessage::Output(repaint_bytes), compress).await?;

        // The snapshot we just sent reflects the cache at the *instant* of
        // reconnect, which can be a transient mid-tmux-scroll state: tmux
        // may have just used a scroll-region (DECSTBM) to update one pane,
        // which inherently clears all columns of those rows in the grid,
        // and the *other* pane's app hasn't sent the bytes to refill them
        // yet. Nudge the PTY size by +1 row and back to provoke two
        // SIGWINCHes — the captured app redraws fully both times, those
        // bytes flow into the cache and out to the client via normal live
        // forwarding, overwriting any transient blanks within ~100ms.
        // Sleep between sends because the watch coalesces — without a gap
        // the receiver may only ever see the second value.
        let nudge_size = PtySize {
            rows: initial_size.rows.saturating_add(1),
            cols: initial_size.cols,
            pixel_width: initial_size.pixel_width,
            pixel_height: initial_size.pixel_height,
        };
        let _ = resize_tx.send(nudge_size);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = resize_tx.send(initial_size);
    }

    // Run the attached I/O loop. `send` is moved in: the loop's writer task owns
    // it and flushes finish() on a clean exit.
    let outcome = run_attached_loop(
        send,
        &mut recv,
        &input_tx,
        &mut client_output_rx,
        &resize_tx,
        &mut exit_rx,
        leftover_msg,
        protocol_version,
    )
    .await;

    match outcome {
        AttachOutcome::Exited => {
            if let Some(result) = registry.cleanup_exited(session_id.clone(), attach_epoch).await {
                if let Some(handle) = result.broker_handle {
                    handle.abort();
                }
                crate::sandbox::broker::cleanup_broker(config_dir, &result.session_id);
            }
            // `send` was moved into run_attached_loop; its writer task already
            // flushed Exit and called finish(). Just drain recv so the client
            // reads the Exit before the stream tears down.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                recv.read_to_end(1),
            )
            .await;
        }
        AttachOutcome::Disconnected => {
            if registry.detach_if_current(session_id.clone(), attach_epoch).await {
                tracing::info!(
                    "Session {} detached for peer {}",
                    &session_id[..8],
                    peer_id
                );
            }
        }
    }

    Ok(())
}

/// Client side: enter raw terminal mode and bridge I/O over the wire protocol.
///
/// The caller owns the stdin reader and passes its receiver here so the same
/// channel can be reused across reconnections.
pub async fn client_shell_session(
    mut send: SendStream,
    mut recv: RecvStream,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<SessionOutcome> {
    use crossterm::terminal;

    // Send initial window size (with pixel dimensions for sixel/kitty image support)
    let (cols, rows, pixel_width, pixel_height) = match terminal::window_size() {
        Ok(size) => (size.columns, size.rows, size.width, size.height),
        Err(_) => (80, 24, 0, 0),
    };
    proto::write_message(
        &mut send,
        &ClientMessage::WindowSize {
            cols,
            rows,
            pixel_width,
            pixel_height,
        },
    )
    .await?;

    // Collect environment variables to propagate
    let mut vars = HashMap::new();
    for key in &[
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_COLLATE",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        "COLORTERM",
    ] {
        if let Ok(val) = std::env::var(key) {
            vars.insert(key.to_string(), val);
        }
    }
    // Ensure TERM always has a value
    vars.entry("TERM".to_string())
        .or_insert_with(|| "xterm-256color".to_string());
    proto::write_message(&mut send, &ClientMessage::SetEnv { vars }).await?;

    // Enter raw mode
    terminal::enable_raw_mode().context("Failed to enable raw mode")?;

    // v1 has no reconnect, so paste/lost-chunk state is local and discarded.
    let mut replay = InputReplay::default();
    let result = client_shell_loop(send, &mut recv, stdin_rx, &mut replay).await;

    // Always restore terminal
    let _ = terminal::disable_raw_mode();

    result
}

/// Client side: V2 shell session that reads SessionInfo during setup.
///
/// Same as `client_shell_session` but reads the `SessionInfo` response after
/// sending setup messages. Returns `(session_id, outcome)` so the caller can
/// store the session ID for reconnection.
pub async fn client_shell_session_v2(
    mut send: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    replay: &mut InputReplay,
) -> Result<(Option<String>, SessionOutcome)> {
    use crossterm::terminal;

    // Send initial window size
    let (cols, rows, pixel_width, pixel_height) = match terminal::window_size() {
        Ok(size) => (size.columns, size.rows, size.width, size.height),
        Err(_) => (80, 24, 0, 0),
    };
    proto::write_message(
        &mut send,
        &ClientMessage::WindowSize {
            cols,
            rows,
            pixel_width,
            pixel_height,
        },
    )
    .await?;

    // Send environment variables
    let mut vars = HashMap::new();
    for key in &[
        "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
        "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "COLORTERM",
    ] {
        if let Ok(val) = std::env::var(key) {
            vars.insert(key.to_string(), val);
        }
    }
    vars.entry("TERM".to_string())
        .or_insert_with(|| "xterm-256color".to_string());
    proto::write_message(&mut send, &ClientMessage::SetEnv { vars }).await?;

    // Read SessionInfo from host
    let session_id = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        proto::read_message::<HostMessage>(&mut recv),
    )
    .await
    {
        Ok(Ok(HostMessage::SessionInfo { session_id, resumed })) => {
            tracing::debug!(
                "Session {} (resumed: {})",
                &session_id[..8.min(session_id.len())],
                resumed
            );
            Some(session_id)
        }
        Ok(Ok(HostMessage::SessionError(msg))) => {
            anyhow::bail!("Host error: {msg}");
        }
        _ => {
            // Host didn't send SessionInfo — could be old host or error.
            // Continue without a session ID.
            None
        }
    };

    // Raw mode is owned by the caller (cmd_connect) for the whole interactive
    // lifecycle, so it stays enabled continuously across reconnects — see
    // RawModeGuard. Don't toggle it here.
    let result = client_shell_loop(send, &mut recv, stdin_rx, replay).await;

    match result {
        Ok(outcome) => Ok((session_id, outcome)),
        Err(e) => Err(e),
    }
}

/// Client side: enter raw mode and run the I/O loop on a stream that has
/// already completed the full handshake (setup messages + SessionInfo).
///
/// Used on reconnect paths where the reconnect function has already sent
/// WindowSize/SetEnv and consumed the SessionInfo response.
pub async fn client_shell_loop_resumed(
    mut send: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    replay: &mut InputReplay,
    to_send: Vec<u8>,
) -> Result<SessionOutcome> {
    // Raw mode is owned by the caller (cmd_connect) for the whole lifecycle —
    // held continuously across reconnects so the stdin reader never drops to
    // cooked mode. Don't toggle it here.
    // Replay any input the reconnect logic decided to carry across (the lost
    // in-flight chunk, and/or buffered paste content) before resuming live I/O.
    if !to_send.is_empty() {
        let msg = ClientMessage::Input(to_send);
        if proto::write_message(&mut send, &msg).await.is_err() {
            if let ClientMessage::Input(data) = msg {
                replay.unsent = data;
            }
            return Ok(SessionOutcome::Disconnected);
        }
        if let ClientMessage::Input(data) = &msg {
            replay.observe(data);
        }
    }
    client_shell_loop(send, &mut recv, stdin_rx, replay).await
}

/// Detect sleep/wake by observing wall-clock time jumps.
///
/// Sleeps for 3s in a loop; if the elapsed time exceeds 10s, the machine
/// was almost certainly asleep. 10s cleanly separates real sleeps (30s+)
/// from cellular stalls (5-8s) with a 2s safety margin.
async fn detect_sleep_wake() {
    loop {
        let before = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if before.elapsed() > std::time::Duration::from_secs(10) {
            return;
        }
    }
}

async fn client_shell_loop<S>(
    send: S,
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    replay: &mut InputReplay,
) -> Result<SessionOutcome>
where
    S: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crossterm::terminal;

    /// Heartbeat interval: send an empty Input so the host knows we're alive,
    /// and so our write path detects a dead connection quickly.
    const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
    /// Read deadline: if no message arrives from the host within this time, treat
    /// as dead and reconnect. With a 10s heartbeat, this is 3 missed beats — a
    /// genuinely stalled path. Deliberately *below* the 60s QUIC idle timeout so a
    /// dead path surfaces in ~30s instead of freezing the user for 75s: the server
    /// persists the PTY (its own deadline is 75s) so a "premature" reconnect just
    /// re-attaches and repaints rather than losing the session.
    const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

    // Channel for SIGWINCH resize events (Unix only)
    let (resize_tx, mut resize_rx) = mpsc::channel::<()>(1);
    #[cfg(unix)]
    {
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .context("failed to register SIGWINCH handler")?;
        tokio::spawn(async move {
            while sigwinch.recv().await.is_some() {
                let _ = resize_tx.send(()).await;
            }
        });
    }
    #[cfg(not(unix))]
    drop(resize_tx); // silence unused warning; resize_rx will never yield

    // Dedicated stdout writer task. Terminal rendering of paste echo is the
    // slowest stage of the receive path and is synchronous; doing the write
    // inline in the select! body would block heartbeats and host-message
    // reads for as long as the terminal takes to drain, eventually tripping
    // the read deadline and triggering a spurious reconnect mid-paste.
    let (stdout_tx, mut stdout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut stdout = std::io::stdout();
        while let Some(data) = stdout_rx.blocking_recv() {
            if stdout.write_all(&data).is_err() {
                break;
            }
            let _ = stdout.flush();
        }
    });

    // Dedicated SEND writer task. It owns the write half so a stalled QUIC send
    // window can NEVER park this select loop — parking the loop is what froze
    // stdin reading and ctrl handling ("type a couple chars, then nothing").
    // The loop hands it ClientMessages over an unbounded channel and never
    // awaits the network write itself. On write failure the writer reports the
    // unsent Input chunk back so the reconnect path can replay it.
    let (send_tx, mut send_rx) = mpsc::unbounded_channel::<ClientMessage>();
    let (writer_err_tx, mut writer_err_rx) = mpsc::channel::<Vec<u8>>(1);
    let writer = tokio::spawn(async move {
        let mut send = send;
        while let Some(msg) = send_rx.recv().await {
            if proto::write_message(&mut send, &msg).await.is_err() {
                let unsent = match msg {
                    ClientMessage::Input(data) => data,
                    _ => Vec::new(),
                };
                let _ = writer_err_tx.send(unsent).await;
                break;
            }
        }
    });

    let wake_detect = detect_sleep_wake();
    tokio::pin!(wake_detect);

    // Heartbeat: periodic empty Input to probe the connection
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Read deadline: backstop for cases where QUIC fails to report a dead connection
    let read_deadline = tokio::time::sleep(READ_DEADLINE);
    tokio::pin!(read_deadline);

    // Cancellation-safe framed reader: the bare `read_message` future loses
    // already-consumed bytes if the `select!` cancels it mid-frame (which the
    // heartbeat tick guarantees during any multi-second output flood), desyncing
    // the stream into a spurious disconnect. `FramedReader::next` keeps the
    // partial frame in the struct, so racing it here is safe. THIS is what made
    // interactive sessions drop under heavy output (scrolling tmux) while plain
    // exec — a bare read loop — was fine.
    let mut framed = proto::FramedReader::new(&mut *recv);

    let outcome = loop {
        tokio::select! {
            // Stdin -> enqueue for the writer task (never blocks this loop).
            Some(data) = input_rx.recv() => {
                // Observe paste state in enqueue order (== write order). `observe`
                // SETS in_paste (it doesn't toggle), and in_paste is only consumed
                // after a reconnect re-observes, so observing before the write is
                // confirmed is safe and keeps the paste-replay logic intact.
                replay.observe(&data);
                if send_tx.send(ClientMessage::Input(data)).is_err() {
                    break Ok(SessionOutcome::Disconnected);
                }
            }
            // The writer task hit a write error — capture the unsent chunk so the
            // reconnect replays it, then disconnect.
            Some(unsent) = writer_err_rx.recv() => {
                replay.unsent = unsent;
                break Ok(SessionOutcome::Disconnected);
            }
            // Host messages -> write to stdout
            msg = framed.next::<HostMessage>() => {
                // Any message from the host means the connection is alive
                read_deadline.as_mut().reset(tokio::time::Instant::now() + READ_DEADLINE);

                match msg {
                    Ok(HostMessage::Output(data)) => {
                        let _ = stdout_tx.send(data);
                    }
                    Ok(HostMessage::Exit(code)) => {
                        break Ok(SessionOutcome::Exited(code));
                    }
                    Ok(HostMessage::WindowSizeAck) => {}
                    Ok(HostMessage::AuthResult { .. }) | Ok(HostMessage::AuthResultV2 { .. }) => {
                        tracing::warn!("Unexpected auth result during shell session");
                    }
                    Ok(HostMessage::SessionInfo { .. }) => {
                        // Late SessionInfo — ignore
                    }
                    Ok(HostMessage::AdminResponse(_))
                    | Ok(HostMessage::PeerResponse(_))
                    | Ok(HostMessage::NetdocAuthorAck { .. }) => {
                        // Unexpected admin/peer response during shell session — ignore
                    }
                    Ok(HostMessage::SessionError(msg)) => {
                        eprintln!("\r\nHost error: {msg}");
                        break Ok(SessionOutcome::Disconnected);
                    }
                    Err(_) => {
                        break Ok(SessionOutcome::Disconnected);
                    }
                }
            }
            // Terminal resized -> enqueue new window size for the host
            Some(()) = resize_rx.recv() => {
                let (cols, rows, pixel_width, pixel_height) = match terminal::window_size() {
                    Ok(size) => (size.columns, size.rows, size.width, size.height),
                    Err(_) => continue,
                };
                let _ = send_tx.send(ClientMessage::WindowSize {
                    cols,
                    rows,
                    pixel_width,
                    pixel_height,
                });
            }
            // Heartbeat: enqueue empty Input to probe connection liveness. The
            // writer does the actual write; if it fails, writer_err_rx fires.
            _ = heartbeat.tick() => {
                let _ = send_tx.send(ClientMessage::Input(vec![]));
            }
            // Read deadline: no data from host for too long
            () = &mut read_deadline => {
                tracing::info!("No data from host for {}s, treating as disconnected", READ_DEADLINE.as_secs());
                break Ok(SessionOutcome::Disconnected);
            }
            // Sleep/wake detection — instant disconnect on wake
            () = &mut wake_detect => {
                tracing::info!("Sleep/wake detected, treating as disconnected");
                break Ok(SessionOutcome::Disconnected);
            }
        }
    };

    // Tear down the writer task. A stalled write would otherwise keep the task
    // (and the moved write half) alive parked on a dead connection.
    writer.abort();
    outcome
}

/// Where an exec session's exit code comes from: the local child (`wait()`), or
/// — under privsep — the monitor's status pipe, which yields the 4-byte LE code
/// when the monitor reaps the child.
enum ExecExit {
    Child(tokio::process::Child),
    #[cfg(unix)]
    Status(tokio::net::unix::pipe::Receiver),
}

impl ExecExit {
    async fn code(&mut self) -> i32 {
        match self {
            ExecExit::Child(c) => c.wait().await.ok().and_then(|s| s.code()).unwrap_or(1),
            #[cfg(unix)]
            ExecExit::Status(r) => {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4];
                // EOF before 4 bytes (monitor died) → generic failure code.
                match r.read_exact(&mut buf).await {
                    Ok(_) => i32::from_le_bytes(buf),
                    Err(_) => 1,
                }
            }
        }
    }
}

/// Host side: execute a command via pipes (no PTY) and stream output over the wire.
/// Host side of `hop tunnel` (local forward, like `ssh -L`): the stream is now a
/// transparent byte pipe, so dial `127.0.0.1:<port>` and bridge it bidirectionally.
/// One stream per forwarded TCP connection. The caller has already gated
/// authorization (authenticated peer; the session's `no_network` sandbox).
pub async fn host_tunnel_session(
    mut send: SendStream,
    recv: RecvStream,
    port: u16,
    _protocol_version: u8,
) -> Result<()> {
    let target = format!("127.0.0.1:{port}");
    match tokio::net::TcpStream::connect(&target).await {
        Ok(mut tcp) => {
            tracing::info!("tunnel: bridging peer <-> {target}");
            // recv = peer->host bytes (read); send = host->peer bytes (write).
            let mut peer = tokio::io::join(recv, send);
            let _ = tokio::io::copy_bidirectional(&mut peer, &mut tcp).await;
        }
        Err(e) => {
            tracing::warn!("tunnel: cannot reach {target}: {e}");
            let _ = send.finish(); // EOF the peer's forwarded connection
        }
    }
    Ok(())
}

pub async fn host_exec_session(
    mut send: SendStream,
    mut recv: RecvStream,
    command: &str,
    username: Option<&str>,
    sandbox: &crate::sandbox::SandboxPolicy,
    protocol_version: u8,
) -> Result<()> {
    crate::audit::record(
        crate::audit::AuditEvent::new(
            crate::audit::AuditCategory::Exec,
            "exec",
            crate::audit::AuditOutcome::Info,
        )
        .user_opt(username)
        .detail(command.chars().take(200).collect::<String>()),
    );
    // --- Pre-spawn security checks (same as shell) ---
    #[cfg(unix)]
    {
        use crate::unix_user;

        let is_root = unix_user::is_running_as_root();

        if is_root && username.is_none() {
            bail!(
                "hop host is running as root but this peer has no bound username — \
                 refusing to execute command. Re-invite this peer with \
                 `hop invite --user <username>` to bind them to a specific account."
            );
        }

        if let Some(name) = username {
            unix_user::validate_username(name)?;

            // A non-root daemon can't switch users — except the privsep worker,
            // which delegates the setuid exec to its root monitor (SpawnExec).
            if !is_root && !crate::privsep::is_privsep_worker() {
                bail!(
                    "peer is bound to user '{name}' but hop host is not running as root — \
                     restart with `sudo hop host` to enable per-user sessions."
                );
            }
        }
    }

    // Acquire the exec child's I/O — locally, or (unprivileged worker + bound
    // user) via the privsep monitor (`SpawnExec`), which returns the three pipe
    // fds plus a status pipe carrying the exit code. Both paths expose the same
    // boxed async I/O so the bridge below is identical.
    #[cfg(unix)]
    let via_monitor = username.is_some()
        && !crate::unix_user::is_running_as_root()
        && crate::privsep::is_privsep_worker();
    #[cfg(not(unix))]
    let via_monitor = false;

    let child_stdin: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>;
    let child_stdout: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>;
    let child_stderr: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>;
    let mut exit: ExecExit;

    #[cfg(unix)]
    if via_monitor {
        use tokio::net::unix::pipe;
        let fds = crate::privsep::worker_spawn_exec(command, sandbox, username.unwrap())
            .context("privsep monitor SpawnExec")?;
        let mut it = fds.into_iter();
        let stdin = it.next().context("SpawnExec missing stdin fd")?;
        let stdout = it.next().context("SpawnExec missing stdout fd")?;
        let stderr = it.next().context("SpawnExec missing stderr fd")?;
        let status = it.next().context("SpawnExec missing status fd")?;
        child_stdin = Some(Box::new(pipe::Sender::from_owned_fd(stdin)?));
        child_stdout = Some(Box::new(pipe::Receiver::from_owned_fd(stdout)?));
        child_stderr = Some(Box::new(pipe::Receiver::from_owned_fd(stderr)?));
        exit = ExecExit::Status(pipe::Receiver::from_owned_fd(status)?);
    } else {
        let mut child = crate::sandbox::spawn_sandboxed_command(command, sandbox, username)
            .context("Failed to spawn sandboxed command")?;
        child_stdin = child.stdin.take().map(|s| Box::new(s) as _);
        child_stdout = child.stdout.take().map(|s| Box::new(s) as _);
        child_stderr = child.stderr.take().map(|s| Box::new(s) as _);
        exit = ExecExit::Child(child);
    }
    #[cfg(not(unix))]
    {
        let mut child = crate::sandbox::spawn_sandboxed_command(command, sandbox, username)
            .context("Failed to spawn sandboxed command")?;
        child_stdin = child.stdin.take().map(|s| Box::new(s) as _);
        child_stdout = child.stdout.take().map(|s| Box::new(s) as _);
        child_stderr = child.stderr.take().map(|s| Box::new(s) as _);
        exit = ExecExit::Child(child);
    }

    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(64);

    // Read stdout
    if let Some(mut stdout) = child_stdout {
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

    // Read stderr
    if let Some(mut stderr) = child_stderr {
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

    // Drop the sender so output_rx closes when both stdout/stderr tasks finish
    drop(output_tx);

    // Proxy client stdin to child stdin
    if let Some(mut child_in) = child_stdin {
        tokio::spawn(async move {
            while let Ok(ClientMessage::Input(data)) = proto::read_message::<ClientMessage>(&mut recv).await {
                if child_in.write_all(&data).await.is_err() {
                    break;
                }
                let _ = child_in.flush().await;
            }
            // Drop child_in so the child sees EOF
        });
    }

    // Main loop: forward output, then wait for exit
    let compress = protocol_version >= 3;
    let mut clean_exit = false;
    loop {
        match output_rx.recv().await {
            Some(data) => {
                if let Err(e) = write_host_message(&mut send, &HostMessage::Output(data), compress).await {
                    tracing::debug!("Failed to send exec output: {e}");
                    break;
                }
            }
            None => {
                // Both stdout and stderr finished — collect the exit code (from
                // the local child, or the monitor's status pipe under privsep).
                let code = exit.code().await;
                let _ = proto::write_message(&mut send, &HostMessage::Exit(code)).await;
                clean_exit = true;
                break;
            }
        }
    }

    if clean_exit {
        let _ = send.finish();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            send.stopped(),
        )
        .await;
    }

    Ok(())
}

/// Client side: run a remote command, stream I/O, and return the exit code.
///
/// Does NOT enter raw terminal mode or send WindowSize/SetEnv.
/// Like [`client_exec_session`] but **captures** the remote stdout into a string
/// instead of streaming it, and sends no input (the command is non-interactive).
/// Used by `hop fleet grep` to reduce per-node output. Returns
/// `(captured_output, exit_code)`; `exit_code` is `-1` on a dropped connection.
pub async fn client_exec_capture(
    mut recv: impl tokio::io::AsyncRead + Unpin,
) -> Result<(String, i32)> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match proto::read_message::<HostMessage>(&mut recv).await {
            Ok(HostMessage::Output(data)) => buf.extend_from_slice(&data),
            Ok(HostMessage::Exit(code)) => {
                return Ok((String::from_utf8_lossy(&buf).into_owned(), code));
            }
            Ok(_) => {}
            Err(_) => return Ok((String::from_utf8_lossy(&buf).into_owned(), -1)),
        }
    }
}

/// Stream a remote exec's stdout to a callback **one line at a time**, live, as
/// the host produces it (G24 federated log search). Unlike `client_exec_capture`
/// (which batches all output until `Exit`), this splits the incoming `Output`
/// chunks on `\n` and invokes `on_line` per complete line, so the caller can
/// render an aggregated, streaming view (e.g. NDJSON log hits in the TUI).
/// Returns the exit code (`-1` on a dropped connection). A trailing partial line
/// is flushed at the end.
pub async fn client_exec_stream(
    mut recv: impl tokio::io::AsyncRead + Unpin,
    mut on_line: impl FnMut(String),
) -> Result<i32> {
    let mut buf: Vec<u8> = Vec::new();
    let flush_lines = |buf: &mut Vec<u8>, on_line: &mut dyn FnMut(String)| {
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=pos).collect();
            line.pop(); // drop the '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            on_line(String::from_utf8_lossy(&line).into_owned());
        }
    };
    loop {
        match proto::read_message::<HostMessage>(&mut recv).await {
            Ok(HostMessage::Output(data)) => {
                buf.extend_from_slice(&data);
                flush_lines(&mut buf, &mut on_line);
            }
            Ok(HostMessage::Exit(code)) => {
                if !buf.is_empty() {
                    on_line(String::from_utf8_lossy(&buf).into_owned());
                }
                return Ok(code);
            }
            Ok(_) => {}
            Err(_) => {
                if !buf.is_empty() {
                    on_line(String::from_utf8_lossy(&buf).into_owned());
                }
                return Ok(-1);
            }
        }
    }
}

pub async fn client_exec_session(
    mut send: impl tokio::io::AsyncWrite + Unpin,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<SessionOutcome> {
    let mut stdout = std::io::stdout();
    // Cancellation-safe reader: if stdin is active while the host floods output,
    // a bare `read_message` select! branch could be cancelled mid-frame.
    let mut framed = proto::FramedReader::new(&mut recv);

    loop {
        tokio::select! {
            Some(data) = stdin_rx.recv() => {
                if proto::write_message(&mut send, &ClientMessage::Input(data)).await.is_err() {
                    return Ok(SessionOutcome::Disconnected);
                }
            }
            msg = framed.next::<HostMessage>() => {
                match msg {
                    Ok(HostMessage::Output(data)) => {
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Ok(HostMessage::Exit(code)) => {
                        return Ok(SessionOutcome::Exited(code));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        return Ok(SessionOutcome::Disconnected);
                    }
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod reader_tests {
    use super::*;
    use std::time::Duration;

    /// The cancellable PTY reader must stop on `cancel` **without** an EOF —
    /// proving the daemon releases its master fd even when a survivor process
    /// keeps the slave open (a backgrounded/`nohup`'d job). Uses a plain pipe as
    /// a stand-in PTY whose write-end is held open the entire test.
    #[tokio::test]
    async fn cancellable_reader_stops_on_cancel_without_eof() {
        // pipe(): read-end = what the reader consumes, write-end = the "shell".
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe()");
        let read_fd = fds[0];
        let write_fd = fds[1];

        let screen = Arc::new(std::sync::Mutex::new(hop_vt::VtScreen::new(24, 80)));
        let (route_tx, mut route_rx_chan) = mpsc::channel::<Vec<u8>>(16);
        // The reader takes a watch::Receiver<Option<Sender>>; seed it attached.
        let (_route_set, route_get) = watch::channel(Some(route_tx));
        let cancel = Arc::new(tokio::sync::Notify::new());

        spawn_cancellable_pty_reader(read_fd, screen.clone(), route_get, cancel.clone(), None)
            .expect("spawn reader");

        // 1) Data flows through before cancel.
        let n = unsafe { libc::write(write_fd, b"hi".as_ptr() as *const libc::c_void, 2) };
        assert_eq!(n, 2);
        let first = tokio::time::timeout(Duration::from_secs(2), route_rx_chan.recv())
            .await
            .expect("reader should route data")
            .expect("route channel open");
        assert_eq!(first, b"hi");

        // 2) Cancel — the write-end is STILL open, so there is no EOF.
        cancel.notify_one();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 3) A subsequent write must NOT be routed: the reader stopped and
        //    dropped its master fd despite no EOF.
        let n = unsafe { libc::write(write_fd, b"after".as_ptr() as *const libc::c_void, 5) };
        assert_eq!(n, 5);
        let after = tokio::time::timeout(Duration::from_millis(500), route_rx_chan.recv()).await;
        assert!(
            after.is_err(),
            "reader must have stopped after cancel (nothing routed despite no EOF)"
        );

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }
}

#[cfg(test)]
mod pty_write_tests {
    use super::*;
    use std::io::{self, Write};

    /// A writer that returns WouldBlock on every other call and accepts at most
    /// 3 bytes per successful write — modelling a full PTY input buffer that
    /// drains slowly mid-paste. The old `let _ = w.write_all()` would drop the
    /// tail (the closing ESC[201~) the first time it hit WouldBlock.
    struct FlakyWriter {
        out: Vec<u8>,
        call: usize,
    }
    impl Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.call += 1;
            if self.call % 2 == 1 {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer full"));
            }
            let n = buf.len().min(3);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pty_write_all_blocking_loses_nothing_under_wouldblock() {
        let data = b"\x1b[200~hello world this is a pasted block\x1b[201~";
        let mut w = FlakyWriter { out: Vec::new(), call: 0 };
        pty_write_all_blocking(&mut w, data);
        // Every byte lands in order — crucially the closing ESC[201~, whose loss
        // is what left the remote terminal stuck in bracketed-paste mode.
        assert_eq!(w.out, data);
    }
}

#[cfg(test)]
mod input_replay_tests {
    use super::*;

    /// A whole paste observed in one chunk leaves us closed (not mid-paste).
    #[test]
    fn complete_paste_in_one_chunk_is_not_mid_paste() {
        let mut r = InputReplay::default();
        r.observe(b"\x1b[200~hello world\x1b[201~");
        assert!(!r.in_paste());
    }

    /// Seeing only the paste-start leaves us mid-paste.
    #[test]
    fn open_paste_is_mid_paste() {
        let mut r = InputReplay::default();
        r.observe(b"\x1b[200~partial text");
        assert!(r.in_paste());
    }

    /// A marker split across two observed chunks is still detected.
    #[test]
    fn detects_marker_split_across_chunks() {
        let mut r = InputReplay::default();
        // Split the closing ESC[201~ down the middle.
        r.observe(b"\x1b[200~some pasted data\x1b[20");
        assert!(r.in_paste(), "still mid-paste before the close completes");
        r.observe(b"1~");
        assert!(!r.in_paste(), "close marker completed across the boundary");
    }

    /// The start marker can also straddle a boundary.
    #[test]
    fn detects_split_start_marker() {
        let mut r = InputReplay::default();
        r.observe(b"abc\x1b[2");
        assert!(!r.in_paste());
        r.observe(b"00~xyz");
        assert!(r.in_paste());
    }

    /// Mid-paste replay delivers through the close marker and drops what was
    /// typed after it.
    #[test]
    fn filter_replay_delivers_paste_drops_trailing_typing() {
        let mut r = InputReplay::default();
        r.observe(b"\x1b[200~half a paste"); // disconnect mid-paste
        assert!(r.in_paste());

        // Buffered during the dialog: rest of paste, its close, then typing.
        let buffered = b"rest of paste\x1b[201~rm -rf junk\n";
        let replay = r.filter_replay(buffered);
        assert_eq!(replay, b"rest of paste\x1b[201~".to_vec());
    }

    /// If the close marker hasn't been buffered yet, deliver all of it (still
    /// paste content) and stay mid-paste.
    #[test]
    fn filter_replay_delivers_all_when_close_not_yet_seen() {
        let mut r = InputReplay::default();
        r.observe(b"\x1b[200~start");
        let buffered = b"more paste with no close yet";
        assert_eq!(r.filter_replay(buffered), buffered.to_vec());
    }

    /// Not mid-paste: free typing during a visible reconnect is dropped.
    #[test]
    fn filter_replay_drops_free_typing() {
        let mut r = InputReplay::default();
        r.observe(b"ls\n"); // a normal command, fully sent — not mid-paste
        assert!(!r.in_paste());
        let buffered = b"sudo reboot\n";
        assert!(r.filter_replay(buffered).is_empty());
    }

    /// Empty (heartbeat) chunks don't affect paste state.
    #[test]
    fn empty_chunk_is_ignored() {
        let mut r = InputReplay::default();
        r.observe(b"\x1b[200~x");
        r.observe(b"");
        assert!(r.in_paste());
    }
}

