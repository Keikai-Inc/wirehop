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
use session_registry::{DetachedSession, SessionKey, SessionRegistry};

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
) -> Result<()> {
    // --- Pre-spawn security checks ---
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
            // Defense in depth: the user could have been deleted since invite time
            unix_user::validate_username(name)?;

            if !is_root {
                bail!(
                    "peer is bound to user '{name}' but hop host is not running as root — \
                     restart with `sudo hop host` to enable per-user shell sessions."
                );
            }
        }
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
    let mut clean_exit = false;
    loop {
        tokio::select! {
            // PTY output -> send to client
            Some(data) = output_rx.recv() => {
                if let Err(e) = proto::write_message(&mut send, &HostMessage::Output(data)).await {
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
                    let _ = proto::write_message(&mut send, &HostMessage::Output(data)).await;
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

/// Pre-spawn security checks shared by shell and persistent-shell entry points.
fn check_shell_security(username: Option<&str>) -> Result<()> {
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
fn spawn_persistent_pty(
    username: Option<&str>,
    size: PtySize,
    env_vars: &HashMap<String, String>,
    sandbox: &crate::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
) -> Result<(
    String,                                          // session_id
    mpsc::Sender<Vec<u8>>,                           // input_tx
    watch::Sender<Option<mpsc::Sender<Vec<u8>>>>,    // output_route
    mpsc::Sender<PtySize>,                           // resize_tx
    watch::Receiver<Option<i32>>,                     // exit_rx
)> {
    let session_id = session_registry::generate_session_id();

    let pty_system = native_pty_system();
    let pair = pty_system.openpty(size).context("Failed to open PTY")?;

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
    #[cfg(target_os = "macos")]
    if sandbox.is_restricted() {
        if let Ok(shim_bin_dir) = crate::sandbox::broker::setup_shim_dir(config_dir, &session_id) {
            let sock_path = crate::sandbox::broker::broker_sock_path(config_dir, &session_id);
            let current_path = std::env::var("PATH").unwrap_or_default();
            cmd.env("PATH", format!("{}:{}", shim_bin_dir.display(), current_path));
            cmd.env("HOP_BROKER_SOCK", sock_path.to_string_lossy().as_ref());
        }
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

    // Persistent PTY reader — routes output based on the watch channel
    let mut pty_reader = pair.master.try_clone_reader().context("clone PTY reader")?;
    let route_rx = output_route_rx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    if let Some(tx) = route_rx.borrow().clone() {
                        let _ = tx.blocking_send(data);
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Input writer task
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(64);
    let writer_clone = pty_writer.clone();
    tokio::task::spawn_blocking(move || {
        while let Some(data) = input_rx.blocking_recv() {
            if let Ok(mut w) = writer_clone.lock() {
                let _ = w.write_all(&data);
                let _ = w.flush();
            }
        }
    });

    // Resize task — owns the PTY master, keeping it alive
    let (resize_tx, mut resize_rx) = mpsc::channel::<PtySize>(4);
    let master = pair.master;
    tokio::task::spawn_blocking(move || {
        // Keep _master alive. Process resize commands until the channel closes.
        let _master = master;
        while let Some(size) = resize_rx.blocking_recv() {
            let _ = _master.resize(size);
        }
        // _master is dropped here → PTY closes → shell gets SIGHUP
    });

    // Child exit watcher
    let (exit_tx, exit_rx) = watch::channel::<Option<i32>>(None);
    tokio::task::spawn_blocking(move || {
        if let Ok(status) = child.wait() {
            let code: i32 = status.exit_code().try_into().unwrap_or(1);
            let _ = exit_tx.send(Some(code));
        }
    });

    Ok((session_id, input_tx, output_route_tx, resize_tx, exit_rx))
}

/// Run the attached I/O loop: forward PTY output to client, client input to PTY.
///
/// Returns `Exited(code)` if the shell exits, or `Disconnected` if the client
/// disconnects (allowing the session to be preserved for reconnection).
async fn run_attached_loop(
    send: &mut SendStream,
    recv: &mut RecvStream,
    input_tx: &mpsc::Sender<Vec<u8>>,
    output_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_tx: &mpsc::Sender<PtySize>,
    exit_rx: &mut watch::Receiver<Option<i32>>,
    leftover_msg: Option<ClientMessage>,
) -> AttachOutcome {
    // Process any leftover message from setup phase
    if let Some(msg) = leftover_msg {
        match msg {
            ClientMessage::Input(data) => {
                let _ = input_tx.send(data).await;
            }
            ClientMessage::WindowSize {
                cols, rows, pixel_width, pixel_height,
            } => {
                let _ = resize_tx.send(PtySize { rows, cols, pixel_width, pixel_height }).await;
                let _ = proto::write_message(send, &HostMessage::WindowSizeAck).await;
            }
            _ => {}
        }
    }

    loop {
        tokio::select! {
            Some(data) = output_rx.recv() => {
                if let Err(e) = proto::write_message(send, &HostMessage::Output(data)).await {
                    tracing::debug!("Failed to send output: {e}");
                    return AttachOutcome::Disconnected;
                }
            }
            msg = proto::read_message::<ClientMessage>(recv) => {
                match msg {
                    Ok(ClientMessage::Input(data)) => {
                        let _ = input_tx.send(data).await;
                    }
                    Ok(ClientMessage::WindowSize {
                        cols, rows, pixel_width, pixel_height,
                    }) => {
                        let _ = resize_tx.send(PtySize { rows, cols, pixel_width, pixel_height }).await;
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
            Ok(()) = exit_rx.changed() => {
                let exit_code = { *exit_rx.borrow_and_update() };
                if let Some(code) = exit_code {
                    // Drain remaining output
                    while let Ok(data) = output_rx.try_recv() {
                        let _ = proto::write_message(send, &HostMessage::Output(data)).await;
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
pub async fn host_shell_session_persistent(
    mut send: SendStream,
    mut recv: RecvStream,
    username: Option<&str>,
    peer_id: &str,
    _requested_session_id: Option<String>,
    registry: Arc<tokio::sync::Mutex<SessionRegistry>>,
    sandbox: &crate::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
) -> Result<()> {
    check_shell_security(username)?;

    let (initial_size, env_vars, leftover_msg) = read_setup_messages(&mut recv).await;

    let key = SessionKey {
        peer_id: peer_id.to_string(),
        username: username.map(String::from),
    };

    // Channel for receiving routed PTY output during this attachment.
    let (client_output_tx, mut client_output_rx) = mpsc::channel::<Vec<u8>>(64);

    let (session_id, resumed, input_tx, resize_tx, mut exit_rx) = {
        let mut reg = registry.lock().await;

        // Try to resume: if a session exists for this key, is alive, and
        // not currently attached by another connection, take it over.
        // We match on the key alone (not session_id) because there's only
        // one session per (peer_id, username) pair.
        let can_resume = reg
            .lookup(&key)
            .map(|s| !s.has_exited() && !s.attached)
            .unwrap_or(false);

        if can_resume {
            let session = reg.lookup_mut(&key).unwrap();
            session.resize(initial_size);
            session.attach(client_output_tx);

            let sid = session.session_id.clone();
            let itx = session.input_tx.clone();
            let rtx = session.resize_tx.clone();
            let erx = session.exit_rx.clone();
            (sid, true, itx, rtx, erx)
        } else {
            // Remove stale/exited session, but don't evict an attached one —
            // let the other connection's I/O loop detect the disconnect naturally.
            if reg.lookup(&key).map(|s| s.attached).unwrap_or(false) {
                tracing::debug!("Session for {:?} still attached, not evicting", key);
            }
            if !reg.lookup(&key).map(|s| s.attached).unwrap_or(false) {
                reg.remove(&key);
            }

            let (sid, itx, output_route, rtx, erx) =
                spawn_persistent_pty(username, initial_size, &env_vars, sandbox, config_dir)?;

            // Route output to this client
            let _ = output_route.send(Some(client_output_tx));

            let session = DetachedSession {
                session_id: sid.clone(),
                input_tx: itx.clone(),
                output_route,
                resize_tx: rtx.clone(),
                exit_rx: erx.clone(),
                detached_at: None,
                attached: true,
                broker_handle: None,
            };

            // Only insert if no attached session exists (avoid eviction)
            if reg.lookup(&key).is_none() {
                reg.insert(key.clone(), session);
            }
            (sid, false, itx, rtx, erx)
        }
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
                let mut reg = registry.lock().await;
                if let Some(session) = reg.lookup_mut(&key) {
                    session.broker_handle = Some(handle);
                }
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

    // Run the attached I/O loop
    let outcome = run_attached_loop(
        &mut send,
        &mut recv,
        &input_tx,
        &mut client_output_rx,
        &resize_tx,
        &mut exit_rx,
        leftover_msg,
    )
    .await;

    match outcome {
        AttachOutcome::Exited => {
            let mut reg = registry.lock().await;
            if let Some(session) = reg.remove(&key) {
                // Abort broker and clean up shim directory
                if let Some(handle) = session.broker_handle {
                    handle.abort();
                }
                crate::sandbox::broker::cleanup_broker(config_dir, &session.session_id);
            }
            let _ = send.finish();
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                recv.read_to_end(1),
            )
            .await;
        }
        AttachOutcome::Disconnected => {
            let mut reg = registry.lock().await;
            reg.detach(&key);
            tracing::info!(
                "Session {} detached for peer {}",
                &session_id[..8],
                peer_id
            );
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
        _ => {
            // Host didn't send SessionInfo — could be old host or error.
            // Continue without a session ID.
            None
        }
    };

    // Enter raw mode
    terminal::enable_raw_mode().context("Failed to enable raw mode")?;

    let result = client_shell_loop(&mut send, &mut recv, stdin_rx).await;

    let _ = terminal::disable_raw_mode();

    match result {
        Ok(outcome) => Ok((session_id, outcome)),
        Err(e) => Err(e),
    }
}

/// Detect sleep/wake by observing wall-clock time jumps.
///
/// Sleeps for 3s in a loop; if the elapsed time exceeds 7s, the machine
/// was almost certainly asleep. Returns immediately on wake detection.
async fn detect_sleep_wake() {
    loop {
        let before = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if before.elapsed() > std::time::Duration::from_secs(7) {
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

    let mut stdout = std::io::stdout();

    let wake_detect = detect_sleep_wake();
    tokio::pin!(wake_detect);

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
                match msg {
                    Ok(HostMessage::Output(data)) => {
                        stdout.write_all(&data)?;
                        stdout.flush()?;
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
                    Ok(HostMessage::AdminResponse(_)) => {
                        // Unexpected admin response during shell session — ignore
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
            loop {
                match proto::read_message::<ClientMessage>(&mut recv).await {
                    Ok(ClientMessage::Input(data)) => {
                        if child_in.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = child_in.flush().await;
                    }
                    _ => break,
                }
            }
            // Drop child_in so the child sees EOF
        });
    }

    // Main loop: forward output, then wait for exit
    let mut clean_exit = false;
    loop {
        match output_rx.recv().await {
            Some(data) => {
                if let Err(e) = proto::write_message(&mut send, &HostMessage::Output(data)).await {
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
