//! PTY and terminal management.

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};

use crate::proto::{self, ClientMessage, HostMessage};

/// Host side: spawn a PTY and bridge I/O over the wire protocol.
pub async fn host_shell_session(
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let pty_system = native_pty_system();

    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("Failed to open PTY")?;

    // Get user's default shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut cmd = CommandBuilder::new(&shell);
    cmd.arg("-l"); // login shell

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
                    Ok(ClientMessage::WindowSize { cols, rows }) => {
                        let _ = _master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
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
pub async fn client_shell_session(
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<i32> {
    use crossterm::terminal;

    // Send initial window size
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    proto::write_message(&mut send, &ClientMessage::WindowSize { cols, rows }).await?;

    // Enter raw mode
    terminal::enable_raw_mode().context("Failed to enable raw mode")?;

    let result = client_shell_loop(&mut send, &mut recv).await;

    // Always restore terminal
    let _ = terminal::disable_raw_mode();

    result
}

async fn client_shell_loop(send: &mut SendStream, recv: &mut RecvStream) -> Result<i32> {
    // Channel for stdin input
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn blocking stdin reader
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 1024];
        let stdin = std::io::stdin();
        loop {
            match stdin.lock().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if input_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut stdout = std::io::stdout();

    loop {
        tokio::select! {
            // Stdin -> send to host
            Some(data) = input_rx.recv() => {
                proto::write_message(send, &ClientMessage::Input(data)).await?;
            }
            // Host messages -> write to stdout
            msg = proto::read_message::<HostMessage>(recv) => {
                match msg {
                    Ok(HostMessage::Output(data)) => {
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Ok(HostMessage::Exit(code)) => {
                        return Ok(code);
                    }
                    Ok(HostMessage::WindowSizeAck) => {}
                    Ok(HostMessage::AuthResult { .. }) => {
                        tracing::warn!("Unexpected auth result during shell session");
                    }
                    Err(e) => {
                        tracing::debug!("Connection closed: {e}");
                        return Ok(1);
                    }
                }
            }
        }
    }
}
