//! Connection multiplexer agent process.
//!
//! Owns a single iroh Endpoint and multiplexes all sessions over QUIC bi-streams.
//! Listens on a Unix socket for IPC clients, each of which gets a transparent
//! byte pipe to a host via a dedicated QUIC bi-stream.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::{Endpoint, PublicKey};
use iroh::endpoint::Connection;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use hop_core::config;
use hop_core::net;

use crate::mux::{self, MuxConnect, MuxResult};

/// Idle timeout: shut down the agent after 10 minutes with no active sessions.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Run the agent in foreground mode.
pub async fn run_foreground(config_dir: &Path) -> Result<()> {
    run_agent(config_dir, false).await
}

/// Run the agent in daemon mode (detached, writes PID file).
pub async fn run_daemon(config_dir: &Path) -> Result<()> {
    run_agent(config_dir, true).await
}

/// Stop a running agent by sending it a signal via PID file.
pub fn stop_agent(config_dir: &Path) -> Result<()> {
    let pid_path = mux::agent_pid_path(config_dir);
    if !pid_path.exists() {
        anyhow::bail!("No agent PID file found — agent may not be running");
    }
    let pid_str = std::fs::read_to_string(&pid_path).context("read PID file")?;
    let pid: i32 = pid_str.trim().parse().context("invalid PID")?;

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }

    // Clean up PID file and socket
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(mux::agent_sock_path(config_dir));
    println!("Agent (PID {pid}) stopped.");
    Ok(())
}

/// Print agent status.
pub fn agent_status(config_dir: &Path) -> Result<()> {
    let pid_path = mux::agent_pid_path(config_dir);
    let sock_path = mux::agent_sock_path(config_dir);

    if !pid_path.exists() {
        println!("Agent is not running.");
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_path).context("read PID file")?;
    let pid: i32 = pid_str.trim().parse().context("invalid PID")?;

    // Check if process is actually alive
    #[cfg(unix)]
    let alive = unsafe { libc::kill(pid, 0) == 0 };
    #[cfg(not(unix))]
    let alive = false;

    if alive {
        println!("Agent is running (PID {pid}).");
        if sock_path.exists() {
            println!("  Socket: {}", sock_path.display());
        }
    } else {
        println!("Agent PID file exists but process {pid} is not running.");
        // Clean up stale files
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&sock_path);
    }
    Ok(())
}

struct Agent {
    endpoint: Endpoint,
    connections: Arc<Mutex<HashMap<PublicKey, Connection>>>,
    config_dir: PathBuf,
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
    last_activity: Arc<Mutex<Instant>>,
}

impl Agent {
    async fn new(config_dir: &Path) -> Result<Self> {
        let secret_key = config::load_or_generate_identity(config_dir)?;
        let endpoint = net::create_client_endpoint(secret_key).await?;

        Ok(Agent {
            endpoint,
            connections: Arc::new(Mutex::new(HashMap::new())),
            config_dir: config_dir.to_path_buf(),
            active_sessions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Get an existing connection or create a new one.
    async fn get_or_connect(
        &self,
        host_id: PublicKey,
        relay_url: Option<String>,
    ) -> Result<Connection> {
        let mut conns = self.connections.lock().await;

        // Check for existing live connection
        if let Some(conn) = conns.get(&host_id) {
            // Verify connection is still alive by checking close reason
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            // Dead connection, close explicitly and remove it
            conns.remove(&host_id);
        }

        // Create new connection
        let relay: Option<iroh::RelayUrl> = relay_url
            .as_deref()
            .map(|u| u.parse())
            .transpose()
            .ok()
            .flatten();

        let (conn, _relay_failed) =
            net::connect_to_host(&self.endpoint, host_id, relay.as_ref()).await?;

        conns.insert(host_id, conn.clone());
        Ok(conn)
    }

    /// Handle a single IPC client connection.
    async fn handle_client(&self, mut ipc: UnixStream) -> Result<()> {
        // 1. Read MuxConnect
        let req: MuxConnect = mux::read_ipc_message(&mut ipc).await?;
        let host_id = PublicKey::from_bytes(&req.host_id)
            .context("invalid host_id in MuxConnect")?;

        // 2. Get or create QUIC connection
        let conn = match self.get_or_connect(host_id, req.relay_url).await {
            Ok(conn) => conn,
            Err(e) => {
                let _ = mux::write_ipc_message(
                    &mut ipc,
                    &MuxResult::Error(format!("{e:#}")),
                )
                .await;
                return Err(e);
            }
        };

        // 3. Open new bi-stream on the QUIC connection
        let (quic_send, quic_recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                // Connection may have died; close explicitly and remove from pool
                conn.close(0u32.into(), b"open-bi-failed");
                self.connections.lock().await.remove(&host_id);
                let _ = mux::write_ipc_message(
                    &mut ipc,
                    &MuxResult::Error(format!("failed to open bi-stream: {e:#}")),
                )
                .await;
                anyhow::bail!("open_bi failed: {e:#}");
            }
        };

        // 4. Signal ready
        mux::write_ipc_message(&mut ipc, &MuxResult::Ready).await?;

        // 5. Track active session
        self.active_sessions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self.last_activity.lock().await = Instant::now();

        // 6. Transparent bidirectional proxy
        let (ipc_read, ipc_write) = ipc.into_split();
        let result = proxy_quic(ipc_read, ipc_write, quic_send, quic_recv).await;

        // 7. Session done
        self.active_sessions
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        *self.last_activity.lock().await = Instant::now();

        if let Err(e) = result {
            tracing::debug!("Proxy session ended: {e:#}");
        }
        Ok(())
    }
}

/// Bidirectional proxy between IPC socket and QUIC bi-stream.
///
/// Both directions run as independent tasks. When one completes, it drops its
/// owned resources, which propagates EOF to the other side, causing it to
/// complete naturally. This avoids the old `select!` approach which would
/// immediately cancel the reverse direction, potentially dropping unread data.
async fn proxy_quic(
    mut ipc_read: tokio::net::unix::OwnedReadHalf,
    mut ipc_write: tokio::net::unix::OwnedWriteHalf,
    mut quic_send: iroh::endpoint::SendStream,
    mut quic_recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    // Host→Client: copy QUIC data to IPC.
    // When this finishes, dropping ipc_write signals EOF to the client.
    let h2c = tokio::spawn(async move {
        let r = tokio::io::copy(&mut quic_recv, &mut ipc_write).await;
        if let Err(ref e) = r {
            tracing::debug!("QUIC→IPC ended: {e:#}");
        }
    });

    // Client→Host: copy IPC data to QUIC.
    // When this finishes, quic_send.finish() signals FIN to the host.
    let c2h = tokio::spawn(async move {
        let r = tokio::io::copy(&mut ipc_read, &mut quic_send).await;
        let _ = quic_send.finish();
        if let Err(ref e) = r {
            tracing::debug!("IPC→QUIC ended: {e:#}");
        }
    });

    // Both tasks complete naturally via EOF propagation:
    //   Pull: host finishes → h2c drops ipc_write → client sees EOF → client
    //         drops socket → c2h's ipc_read sees EOF → c2h finishes
    //   Push: client finishes → c2h calls finish() → host sees FIN → host
    //         sends response + finishes → h2c's quic_recv sees EOF → h2c finishes
    // Cap total wait to 30s to avoid hanging on misbehaving peers.
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        let _ = tokio::join!(h2c, c2h);
    })
    .await;

    Ok(())
}

/// Generic bidirectional byte proxy between two async stream pairs.
///
/// Used for testing with mock streams (tokio::io::duplex).
#[cfg(test)]
async fn proxy_streams(
    mut side_a_read: impl tokio::io::AsyncRead + Unpin,
    mut side_a_write: impl tokio::io::AsyncWrite + Unpin,
    mut side_b_read: impl tokio::io::AsyncRead + Unpin,
    mut side_b_write: impl tokio::io::AsyncWrite + Unpin,
) -> Result<()> {
    tokio::select! {
        r = tokio::io::copy(&mut side_a_read, &mut side_b_write) => {
            r.context("A->B copy")?;
        }
        r = tokio::io::copy(&mut side_b_read, &mut side_a_write) => {
            r.context("B->A copy")?;
        }
    }
    Ok(())
}

async fn run_agent(config_dir: &Path, daemon: bool) -> Result<()> {
    let sock_path = mux::agent_sock_path(config_dir);
    let pid_path = mux::agent_pid_path(config_dir);

    // Remove stale socket if present
    if sock_path.exists() {
        let _ = std::fs::remove_file(&sock_path);
    }

    let listener = UnixListener::bind(&sock_path).context("failed to bind agent socket")?;

    // Write PID file
    std::fs::write(&pid_path, std::process::id().to_string())
        .context("failed to write PID file")?;

    if !daemon {
        eprintln!("Agent listening on {}", sock_path.display());
        eprintln!("PID: {}", std::process::id());
    }

    // Set up signal handler for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("failed to register SIGINT handler")?;

    let agent = Agent::new(config_dir).await?;

    // Background task: flush stale connections on sleep/wake
    let wake_conns = agent.connections.clone();
    tokio::spawn(async move {
        loop {
            let before = std::time::Instant::now();
            tokio::time::sleep(Duration::from_secs(3)).await;
            if before.elapsed() > Duration::from_secs(7) {
                tracing::info!("Agent detected sleep/wake, flushing connection pool");
                let mut conns = wake_conns.lock().await;
                for (_, conn) in conns.drain() {
                    conn.close(0u32.into(), b"sleep-flush");
                }
            }
        }
    });

    // Network interface change detector — flushes pooled connections on change
    let _netmon = net::netmon::spawn_interface_watcher(
        agent.endpoint.clone(),
        Some(agent.connections.clone()),
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let agent_conns = agent.connections.clone();
                        let agent_endpoint = agent.endpoint.clone();
                        let agent_config_dir = agent.config_dir.clone();
                        let agent_active = agent.active_sessions.clone();
                        let agent_last = agent.last_activity.clone();

                        // Create a lightweight handle for this client
                        let handler = Agent {
                            endpoint: agent_endpoint,
                            connections: agent_conns,
                            config_dir: agent_config_dir,
                            active_sessions: agent_active,
                            last_activity: agent_last,
                        };

                        tokio::spawn(async move {
                            if let Err(e) = handler.handle_client(stream).await {
                                tracing::debug!("Agent client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Agent accept error: {e}");
                    }
                }
            }
            _ = sigterm.recv() => {
                tracing::info!("Agent received SIGTERM, shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Agent received SIGINT, shutting down");
                break;
            }
            _ = check_idle(&agent.active_sessions, &agent.last_activity) => {
                tracing::info!("Agent idle timeout reached, shutting down");
                break;
            }
        }
    }

    // Cleanup: close all pooled connections, then the endpoint
    {
        let mut conns = agent.connections.lock().await;
        for (_, conn) in conns.drain() {
            conn.close(0u32.into(), b"agent-shutdown");
        }
    }
    agent.endpoint.close().await;
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
}

/// Check idle timeout (public for testing).
async fn check_idle(
    active_sessions: &std::sync::atomic::AtomicUsize,
    last_activity: &Mutex<Instant>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        let active = active_sessions.load(std::sync::atomic::Ordering::Relaxed);
        if active > 0 {
            continue;
        }

        let last = *last_activity.lock().await;
        if last.elapsed() >= IDLE_TIMEOUT {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── Proxy Layer ──

    #[tokio::test]
    async fn proxy_bidirectional_data() {
        let (a1, a2) = tokio::io::duplex(8192);
        let (b1, b2) = tokio::io::duplex(8192);

        let (a1_read, a1_write) = tokio::io::split(a1);
        let (b1_read, b1_write) = tokio::io::split(b1);

        let proxy = tokio::spawn(async move {
            proxy_streams(a1_read, a1_write, b1_read, b1_write).await
        });

        let (mut a2_read, mut a2_write) = tokio::io::split(a2);
        let (mut b2_read, mut b2_write) = tokio::io::split(b2);

        // A -> B (use read_exact so we don't wait for stream close)
        a2_write.write_all(b"hello from A").await.unwrap();
        let mut buf = [0u8; 12];
        b2_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from A");

        // B -> A
        b2_write.write_all(b"hello from B").await.unwrap();
        let mut buf2 = [0u8; 12];
        a2_read.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello from B");

        // Clean up — dropping all ends causes the proxy to exit
        drop(a2_write);
        drop(b2_write);
        drop(a2_read);
        drop(b2_read);
        let _ = proxy.await;
    }

    #[tokio::test]
    async fn proxy_large_transfer() {
        let data: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
        let expected_hash = Sha256::digest(&data);

        let (a1, a2) = tokio::io::duplex(65536);
        let (b1, b2) = tokio::io::duplex(65536);

        let (a1_read, a1_write) = tokio::io::split(a1);
        let (b1_read, b1_write) = tokio::io::split(b1);

        let proxy = tokio::spawn(async move {
            proxy_streams(a1_read, a1_write, b1_read, b1_write).await
        });

        let (_, mut a2_write) = tokio::io::split(a2);
        let (mut b2_read, _) = tokio::io::split(b2);

        let send_data = data.clone();
        let sender = tokio::spawn(async move {
            a2_write.write_all(&send_data).await.unwrap();
            a2_write.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        b2_read.read_to_end(&mut received).await.unwrap();

        assert_eq!(received.len(), 1_048_576);
        let actual_hash = Sha256::digest(&received);
        assert_eq!(expected_hash, actual_hash);

        sender.await.unwrap();
        let _ = proxy.await;
    }

    #[tokio::test]
    async fn proxy_half_close() {
        // Verify that closing one side's write causes the proxy to exit
        // (proxy uses select!, so when one direction's copy completes, the other
        // is cancelled and the proxy returns).
        let (a1, a2) = tokio::io::duplex(8192);
        let (b1, b2) = tokio::io::duplex(8192);

        let (a1_read, a1_write) = tokio::io::split(a1);
        let (b1_read, b1_write) = tokio::io::split(b1);

        let proxy = tokio::spawn(async move {
            proxy_streams(a1_read, a1_write, b1_read, b1_write).await
        });

        let (_a2_read, mut a2_write) = tokio::io::split(a2);
        let (mut b2_read, _b2_write) = tokio::io::split(b2);

        // Send data then close A's write half via shutdown (not drop —
        // drop of a split WriteHalf doesn't propagate EOF to the peer).
        a2_write.write_all(b"from A").await.unwrap();
        let mut buf = [0u8; 6];
        b2_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from A");

        // shutdown() calls poll_shutdown on the DuplexStream, signaling EOF
        a2_write.shutdown().await.unwrap();

        // B should see EOF
        let mut tail = Vec::new();
        b2_read.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());

        // The proxy task should complete without deadlock
        let result = tokio::time::timeout(Duration::from_secs(1), proxy).await;
        assert!(result.is_ok(), "proxy should exit after half-close");
    }

    #[tokio::test]
    async fn proxy_concurrent_sessions() {
        let timeout = tokio::time::timeout(Duration::from_secs(2), async {
            let mut handles = Vec::new();

            for i in 0..100u32 {
                handles.push(tokio::spawn(async move {
                    let (a1, a2) = tokio::io::duplex(8192);
                    let (b1, b2) = tokio::io::duplex(8192);

                    let (a1_read, a1_write) = tokio::io::split(a1);
                    let (b1_read, b1_write) = tokio::io::split(b1);

                    let proxy = tokio::spawn(async move {
                        proxy_streams(a1_read, a1_write, b1_read, b1_write).await
                    });

                    let (_, mut a2_write) = tokio::io::split(a2);
                    let (mut b2_read, _) = tokio::io::split(b2);

                    let unique = format!("session-{i}-payload");
                    a2_write.write_all(unique.as_bytes()).await.unwrap();
                    a2_write.shutdown().await.unwrap();

                    let mut received = Vec::new();
                    b2_read.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, unique.as_bytes());

                    let _ = proxy.await;
                }));
            }

            for h in handles {
                h.await.unwrap();
            }
        });

        timeout.await.expect("proxy_concurrent_sessions timed out after 2s");
    }

    // ── Session Tracking ──

    #[tokio::test]
    async fn session_counter_increment_decrement() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..50 {
            let c = counter.clone();
            handles.push(tokio::spawn(async move {
                c.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
                c.fetch_sub(1, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn idle_timeout_fires_when_no_sessions() {
        let active = Arc::new(AtomicUsize::new(0));
        let last_activity = Arc::new(Mutex::new(
            Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1),
        ));

        // check_idle polls every 30s, so we use tokio::time::pause to advance
        // the clock instantly.
        tokio::time::pause();

        let result = tokio::time::timeout(Duration::from_secs(60), async {
            check_idle(&active, &last_activity).await;
        })
        .await;

        assert!(result.is_ok(), "check_idle should have returned promptly");
    }

    // ── Agent IPC Integration ──

    #[tokio::test]
    async fn agent_ipc_handshake_then_proxy() {
        // Simulate: client <-> (IPC) <-> agent <-> (QUIC mock) <-> "host"
        let (client_ipc, agent_ipc) = tokio::net::UnixStream::pair().unwrap();
        let (mock_quic_agent, mock_quic_host) = tokio::io::duplex(8192);

        // Agent side: read MuxConnect, send MuxResult::Ready, then proxy
        let agent = tokio::spawn(async move {
            let (mut agent_read, mut agent_write) = agent_ipc.into_split();

            let req: MuxConnect = mux::read_ipc_message(&mut agent_read).await.unwrap();
            assert_eq!(req.host_id[0], 42);

            mux::write_ipc_message(&mut agent_write, &MuxResult::Ready)
                .await
                .unwrap();

            let (quic_read, quic_write) = tokio::io::split(mock_quic_agent);
            proxy_streams(agent_read, agent_write, quic_read, quic_write)
                .await
                .ok();
        });

        let (mut client_read, mut client_write) = client_ipc.into_split();

        let connect = MuxConnect {
            host_id: {
                let mut id = [0u8; 32];
                id[0] = 42;
                id
            },
            relay_url: None,
        };
        mux::write_ipc_message(&mut client_write, &connect)
            .await
            .unwrap();

        let result: MuxResult = mux::read_ipc_message(&mut client_read).await.unwrap();
        assert!(matches!(result, MuxResult::Ready));

        let (mut host_read, mut host_write) = tokio::io::split(mock_quic_host);

        // Client sends "ping", host reads it (use read_exact to avoid waiting for EOF)
        client_write.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        host_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Host sends "pong", client reads it
        host_write.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        client_read.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");

        // Cleanup
        drop(client_write);
        drop(client_read);
        drop(host_write);
        drop(host_read);
        let _ = agent.await;
    }

    #[tokio::test]
    async fn agent_concurrent_clients() {
        let timeout = tokio::time::timeout(Duration::from_secs(5), async {
            let mut handles = Vec::new();

            for i in 0..20u32 {
                handles.push(tokio::spawn(async move {
                    let (client_ipc, agent_ipc) = tokio::net::UnixStream::pair().unwrap();
                    let (mock_quic_agent, mock_quic_host) = tokio::io::duplex(8192);

                    let unique_payload = format!("client-{i}-data");
                    let payload_len = unique_payload.len();

                    // Agent side
                    let agent_handle = tokio::spawn(async move {
                        let (mut ar, mut aw) = agent_ipc.into_split();
                        let _req: MuxConnect = mux::read_ipc_message(&mut ar).await.unwrap();
                        mux::write_ipc_message(&mut aw, &MuxResult::Ready).await.unwrap();
                        let (qr, qw) = tokio::io::split(mock_quic_agent);
                        proxy_streams(ar, aw, qr, qw).await.ok();
                    });

                    // Host side: read exact bytes and echo back immediately
                    let host_handle = tokio::spawn(async move {
                        let (mut hr, mut hw) = tokio::io::split(mock_quic_host);
                        let mut buf = vec![0u8; payload_len];
                        hr.read_exact(&mut buf).await.unwrap();
                        hw.write_all(&buf).await.unwrap();
                    });

                    // Client side
                    let (mut cr, mut cw) = client_ipc.into_split();
                    let connect = MuxConnect {
                        host_id: [i as u8; 32],
                        relay_url: None,
                    };
                    mux::write_ipc_message(&mut cw, &connect).await.unwrap();
                    let result: MuxResult = mux::read_ipc_message(&mut cr).await.unwrap();
                    assert!(matches!(result, MuxResult::Ready));

                    cw.write_all(unique_payload.as_bytes()).await.unwrap();

                    let mut echoed = vec![0u8; payload_len];
                    cr.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(String::from_utf8(echoed).unwrap(), unique_payload);

                    // Cleanup
                    drop(cw);
                    drop(cr);
                    let _ = host_handle.await;
                    let _ = agent_handle.await;
                }));
            }

            for h in handles {
                h.await.unwrap();
            }
        });

        timeout.await.expect("agent_concurrent_clients timed out");
    }
}
