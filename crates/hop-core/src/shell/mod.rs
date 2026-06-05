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
/// panics or returns early via `?`.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
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

    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(initial_size)
        .context("Failed to open PTY")?;

    // Use the target user's login shell, not the daemon's $SHELL.
    #[cfg(unix)]
    let shell = match username {
        Some(user) => crate::unix_user::user_login_shell(user),
        None => std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
    };
    #[cfg(not(unix))]
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let broker_config = if sandbox.is_restricted() { Some(config_dir) } else { None };
    let (bin, args) = crate::sandbox::sandboxed_shell(sandbox, &shell, username, broker_config);
    let mut cmd = CommandBuilder::new(&bin);
    cmd.args(args.iter().map(|s| s.as_str()));
    // Apply environment variables from client through a security allowlist
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
    for key in ENV_ALLOWLIST {
        if let Some(val) = env_vars.get(*key) {
            cmd.env(key, val);
        }
    }
    // Default TERM if not received (old client compat)
    if !env_vars.contains_key("TERM") {
        cmd.env("TERM", "xterm-256color");
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .context("Failed to spawn shell")?;

    // We're done with the slave side
    drop(pair.slave);

    let mut pty_reader = pair.master.try_clone_reader().context("clone PTY reader")?;
    let pty_writer = pair.master.take_writer().context("take PTY writer")?;

    // Wrap the pty_writer in Arc<Mutex<>> for sharing between tasks
    let pty_writer = std::sync::Arc::new(std::sync::Mutex::new(pty_writer));

    // Keep master alive so PTY doesn't close
    let _master = pair.master;

    // Task: read from PTY -> send to client
    let pty_writer_clone = pty_writer.clone();
    let pty_to_client = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut buf = [0u8; 4096];
        let output_buf = match pty_reader.read(&mut buf) {
            Ok(0) => Vec::new(),
            Ok(n) => buf[..n].to_vec(),
            Err(e) => {
                tracing::debug!("PTY read error: {e}");
                Vec::new()
            }
        };
        Ok(output_buf)
    });

    // Actually, let's use a channel-based approach instead
    drop(pty_to_client);
    drop(pty_writer_clone);

    // Channel for PTY output -> network
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    // Channel for PTY close notification
    let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<i32>();

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
    });

    // Spawn blocking waiter for child exit
    tokio::task::spawn_blocking(move || {
        if let Ok(status) = child.wait() {
            let code = status
                .exit_code()
                .try_into()
                .unwrap_or(1);
            let _ = exit_tx.send(code);
        }
    });

    // Process any leftover message from the setup phase
    if let Some(msg) = leftover_msg {
        match msg {
            ClientMessage::Input(data) => {
                let writer = pty_writer.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(mut w) = writer.lock() {
                        let _ = w.write_all(&data);
                        let _ = w.flush();
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
            msg = proto::read_message::<ClientMessage>(&mut recv) => {
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

            if !is_root {
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
)> {
    let session_id = session_registry::generate_session_id();

    let pty_system = native_pty_system();
    let pair = pty_system.openpty(size).context("Failed to open PTY")?;

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
    let (bin, args) = crate::sandbox::sandboxed_shell(sandbox, &shell, username, broker_config);
    let mut cmd = CommandBuilder::new(&bin);
    cmd.args(args.iter().map(|s| s.as_str()));

    const ENV_ALLOWLIST: &[&str] = &[
        "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
        "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "COLORTERM",
    ];
    for key in ENV_ALLOWLIST {
        if let Some(val) = env_vars.get(*key) {
            cmd.env(key, val);
        }
    }
    if !env_vars.contains_key("TERM") {
        cmd.env("TERM", "xterm-256color");
    }

    // On macOS, when sandbox is restricted, set up broker shim directory
    // so the sandboxed shell can proxy setuid-blocked commands through the daemon.
    //
    // We can't use cmd.env("PATH", ...) because login shell profile scripts
    // (path_helper via /etc/zprofile) replace PATH entirely. Instead, we use
    // ZDOTDIR to inject a .zprofile that prepends the shim dir AFTER the
    // system profile scripts have already rebuilt PATH.
    #[cfg(target_os = "macos")]
    if sandbox.is_restricted() {
        let _ = crate::sandbox::broker::setup_shim_dir(config_dir, &session_id, username);
        if let Ok(zdotdir) = crate::sandbox::broker::setup_zdotdir(config_dir, &session_id, username) {
            cmd.env("ZDOTDIR", zdotdir.to_string_lossy().as_ref());
        }
        // Set HOP_BROKER_SOCK as fallback for non-zsh shells
        let sock_path = crate::sandbox::broker::broker_sock_path(config_dir, &session_id);
        cmd.env("HOP_BROKER_SOCK", sock_path.to_string_lossy().as_ref());
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .context("Failed to spawn shell")?;
    drop(pair.slave);

    let pty_writer = pair.master.take_writer().context("take PTY writer")?;
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
    let mut pty_reader = pair.master.try_clone_reader().context("clone PTY reader")?;
    let route_rx = output_route_rx.clone();
    let reader_screen = screen.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    { reader_screen.lock().unwrap().advance(&data); }
                    // Route to client if attached
                    if let Some(tx) = route_rx.borrow().clone() {
                        let _ = tx.blocking_send(data);
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Input writer task. Unbounded so the shell select-loop never blocks on
    // send: if the PTY's small kernel input buffer fills mid-paste, bytes
    // queue here instead of stalling the loop (which would starve heartbeats).
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_clone = pty_writer.clone();
    tokio::task::spawn_blocking(move || {
        while let Some(data) = input_rx.blocking_recv() {
            if let Ok(mut w) = writer_clone.lock() {
                let _ = w.write_all(&data);
                let _ = w.flush();
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
    let master = pair.master;
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
        // _master drops here → PTY closes → shell gets SIGHUP
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

    // Child exit watcher. Capture the pid first so the registry can terminate
    // the shell on removal (the master-drop SIGHUP path doesn't fire — the
    // reader task holds a clone of the master; see session_registry).
    let child_pid = child.process_id();
    let (exit_tx, exit_rx) = watch::channel::<Option<i32>>(None);
    tokio::task::spawn_blocking(move || {
        if let Ok(status) = child.wait() {
            let code: i32 = status.exit_code().try_into().unwrap_or(1);
            let _ = exit_tx.send(Some(code));
        }
    });

    Ok((session_id, input_tx, output_route_tx, resize_tx, exit_rx, screen, child_pid))
}

/// Run the attached I/O loop: forward PTY output to client, client input to PTY.
///
/// Returns `Exited(code)` if the shell exits, or `Disconnected` if the client
/// disconnects (allowing the session to be preserved for reconnection).
#[allow(clippy::too_many_arguments)]
async fn run_attached_loop(
    send: &mut SendStream,
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
                let _ = proto::write_message(send, &HostMessage::WindowSizeAck).await;
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

    loop {
        tokio::select! {
            Some(data) = output_rx.recv() => {
                if let Err(e) = write_host_message(send, &HostMessage::Output(data), compress).await {
                    tracing::debug!("Failed to send output: {e}");
                    return AttachOutcome::Disconnected;
                }
            }
            msg = proto::read_message::<ClientMessage>(recv) => {
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
                        let _ = proto::write_message(send, &HostMessage::WindowSizeAck).await;
                    }
                    Ok(_) => {
                        tracing::warn!("Unexpected message during shell session");
                    }
                    Err(_) => {
                        tracing::debug!("Client disconnected");
                        return AttachOutcome::Disconnected;
                    }
                }
            }
            // Heartbeat: send empty Output to keep client's read deadline alive
            _ = heartbeat.tick() => {
                if write_host_message(send, &HostMessage::Output(vec![]), compress).await.is_err() {
                    tracing::debug!("Heartbeat write failed, client disconnected");
                    return AttachOutcome::Disconnected;
                }
            }
            // Read deadline: no data from client for too long
            () = &mut read_deadline => {
                tracing::info!("No data from client for {}s, treating as disconnected", READ_DEADLINE.as_secs());
                return AttachOutcome::Disconnected;
            }
            Ok(()) = exit_rx.changed() => {
                let exit_code = { *exit_rx.borrow_and_update() };
                if let Some(code) = exit_code {
                    // Drain remaining output
                    while let Ok(data) = output_rx.try_recv() {
                        let _ = write_host_message(send, &HostMessage::Output(data), compress).await;
                    }
                    let _ = proto::write_message(send, &HostMessage::Exit(code)).await;
                    return AttachOutcome::Exited;
                }
            }
        }
    }
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
                let (sid, itx, output_route, rtx, erx, scr, child_pid) =
                    spawn_persistent_pty(username, initial_size, &env_vars, sandbox, config_dir)?;
                let _ = output_route.send(Some(client_output_tx));
                let session = DetachedSession {
                    session_id: sid.clone(),
                    peer_id: peer_id.to_string(),
                    username: username.map(String::from),
                    child_pid,
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
            let (sid, itx, output_route, rtx, erx, scr, child_pid) =
                spawn_persistent_pty(username, initial_size, &env_vars, sandbox, config_dir)?;
            let _ = output_route.send(Some(client_output_tx));
            let session = DetachedSession {
                session_id: sid.clone(),
                peer_id: peer_id.to_string(),
                username: username.map(String::from),
                child_pid,
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

    // Run the attached I/O loop
    let outcome = run_attached_loop(
        &mut send,
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
            let _ = send.finish();
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

    let result = client_shell_loop(&mut send, &mut recv, stdin_rx).await;

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
    mut send: impl tokio::io::AsyncWrite + Unpin,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
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

    let _raw_guard = RawModeGuard::enable()?;
    let result = client_shell_loop(&mut send, &mut recv, stdin_rx).await;
    drop(_raw_guard);

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
    mut send: impl tokio::io::AsyncWrite + Unpin,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<SessionOutcome> {
    let _raw_guard = RawModeGuard::enable()?;
    let result = client_shell_loop(&mut send, &mut recv, stdin_rx).await;
    drop(_raw_guard);
    result
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

async fn client_shell_loop(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<SessionOutcome> {
    use crossterm::terminal;

    /// Heartbeat interval: send an empty Input so the host knows we're alive,
    /// and so our write path detects a dead connection quickly.
    const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
    /// Read deadline: if no message arrives from the host within this time, treat as dead.
    /// Must be above QUIC idle timeout (60s) + margin for lossy-network resilience.
    const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(75);

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

    let wake_detect = detect_sleep_wake();
    tokio::pin!(wake_detect);

    // Heartbeat: periodic empty Input to probe the connection
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Read deadline: backstop for cases where QUIC fails to report a dead connection
    let read_deadline = tokio::time::sleep(READ_DEADLINE);
    tokio::pin!(read_deadline);

    loop {
        tokio::select! {
            // Stdin -> send to host
            Some(data) = input_rx.recv() => {
                if proto::write_message(send, &ClientMessage::Input(data)).await.is_err() {
                    return Ok(SessionOutcome::Disconnected);
                }
            }
            // Host messages -> write to stdout
            msg = proto::read_message::<HostMessage>(recv) => {
                // Any message from the host means the connection is alive
                read_deadline.as_mut().reset(tokio::time::Instant::now() + READ_DEADLINE);

                match msg {
                    Ok(HostMessage::Output(data)) => {
                        let _ = stdout_tx.send(data);
                    }
                    Ok(HostMessage::Exit(code)) => {
                        return Ok(SessionOutcome::Exited(code));
                    }
                    Ok(HostMessage::WindowSizeAck) => {}
                    Ok(HostMessage::AuthResult { .. }) => {
                        tracing::warn!("Unexpected auth result during shell session");
                    }
                    Ok(HostMessage::SessionInfo { .. }) => {
                        // Late SessionInfo — ignore
                    }
                    Ok(HostMessage::AdminResponse(_)) | Ok(HostMessage::PeerResponse(_)) => {
                        // Unexpected admin/peer response during shell session — ignore
                    }
                    Ok(HostMessage::SessionError(msg)) => {
                        eprintln!("\r\nHost error: {msg}");
                        return Ok(SessionOutcome::Disconnected);
                    }
                    Err(_) => {
                        return Ok(SessionOutcome::Disconnected);
                    }
                }
            }
            // Terminal resized -> send new window size to host
            Some(()) = resize_rx.recv() => {
                let (cols, rows, pixel_width, pixel_height) = match terminal::window_size() {
                    Ok(size) => (size.columns, size.rows, size.width, size.height),
                    Err(_) => continue,
                };
                let _ = proto::write_message(
                    send,
                    &ClientMessage::WindowSize {
                        cols,
                        rows,
                        pixel_width,
                        pixel_height,
                    },
                )
                .await;
            }
            // Heartbeat: send empty Input to probe connection liveness
            _ = heartbeat.tick() => {
                if proto::write_message(send, &ClientMessage::Input(vec![])).await.is_err() {
                    return Ok(SessionOutcome::Disconnected);
                }
            }
            // Read deadline: no data from host for too long
            () = &mut read_deadline => {
                tracing::info!("No data from host for {}s, treating as disconnected", READ_DEADLINE.as_secs());
                return Ok(SessionOutcome::Disconnected);
            }
            // Sleep/wake detection — instant disconnect on wake
            () = &mut wake_detect => {
                tracing::info!("Sleep/wake detected, treating as disconnected");
                return Ok(SessionOutcome::Disconnected);
            }
        }
    }
}

/// Host side: execute a command via pipes (no PTY) and stream output over the wire.
pub async fn host_exec_session(
    mut send: SendStream,
    mut recv: RecvStream,
    command: &str,
    username: Option<&str>,
    sandbox: &crate::sandbox::SandboxPolicy,
    protocol_version: u8,
) -> Result<()> {
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

            if !is_root {
                bail!(
                    "peer is bound to user '{name}' but hop host is not running as root — \
                     restart with `sudo hop host` to enable per-user sessions."
                );
            }
        }
    }

    // Build the command with sandbox enforcement
    let mut child = crate::sandbox::spawn_sandboxed_command(command, sandbox, username)
        .context("Failed to spawn sandboxed command")?;

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

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
                // Both stdout and stderr finished — wait for child exit
                let status = child.wait().await.context("Failed to wait for child")?;
                let code = status.code().unwrap_or(1);
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
pub async fn client_exec_session(
    mut send: impl tokio::io::AsyncWrite + Unpin,
    mut recv: impl tokio::io::AsyncRead + Unpin,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<SessionOutcome> {
    let mut stdout = std::io::stdout();

    loop {
        tokio::select! {
            Some(data) = stdin_rx.recv() => {
                if proto::write_message(&mut send, &ClientMessage::Input(data)).await.is_err() {
                    return Ok(SessionOutcome::Disconnected);
                }
            }
            msg = proto::read_message::<HostMessage>(&mut recv) => {
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
