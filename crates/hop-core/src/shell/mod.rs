//! PTY and terminal management.

use std::collections::HashMap;
use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use tokio::sync::mpsc;

use crate::proto::{self, ClientMessage, HostMessage};

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
pub async fn host_shell_session(
    mut send: SendStream,
    mut recv: RecvStream,
    username: Option<&str>,
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

    let mut cmd = if let Some(user) = username {
        // Spawn a login shell as the specified user.
        // Requires the hop host process to run as root.
        #[cfg(target_os = "macos")]
        {
            let mut c = CommandBuilder::new("login");
            c.args(["-fp", user]);
            c
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let mut c = CommandBuilder::new("su");
            c.args(["-", user]);
            c
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("Per-user shell sessions are only supported on Unix");
        }
    } else {
        // Default: run the host user's own login shell
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = CommandBuilder::new(&shell);
        c.arg("-l");
        c
    };
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
        let mut output_buf = Vec::new();
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    output_buf.extend_from_slice(&buf[..n]);
                    // Flush accumulated output
                    let data = std::mem::take(&mut output_buf);
                    // We'll collect chunks and send them via a channel
                    // For simplicity, return the data and handle in async context
                    // Actually we need a channel approach here
                    output_buf = data; // put it back, we need a different approach
                    break; // exit to restructure
                }
                Err(e) => {
                    // PTY closed
                    tracing::debug!("PTY read error: {e}");
                    break;
                }
            }
        }
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
                break;
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

async fn client_shell_loop(
    send: &mut SendStream,
    recv: &mut RecvStream,
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
        }
    }
}
