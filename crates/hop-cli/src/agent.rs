//! Connection multiplexer agent process.
//!
//! Owns a single iroh Endpoint and multiplexes all sessions over QUIC bi-streams.
//! Listens on a Unix socket for IPC clients, each of which gets a transparent
//! byte pipe to a host via a dedicated QUIC bi-stream.
//!
//! Uses the actor pattern (like session_registry): all mutable connection state
//! is owned by a single actor task, accessed via `AgentHandle` + `AgentCommand`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

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

// ---------------------------------------------------------------------------
// Actor pattern: AgentCommand + AgentHandle + AgentState + actor loop
// ---------------------------------------------------------------------------

/// Commands processed by the agent actor.
enum AgentCommand {
    /// Request a connection + semaphore for a host. If no connection exists,
    /// one is created (or an in-flight connect is joined).
    GetConnection {
        host_id: PublicKey,
        relay_url: Option<String>,
        reply: oneshot::Sender<Result<(Connection, Arc<tokio::sync::Semaphore>)>>,
    },
    /// Self-message from a spawned connect task when the QUIC handshake completes.
    ConnectDone {
        host_id: PublicKey,
        result: Result<Connection>,
    },
    /// Evict a stale connection after an open_bi failure.
    RemoveConnection {
        host_id: PublicKey,
    },
    /// Flush all pooled connections (sleep/wake recovery).
    FlushAll,
    /// Bump last_activity timestamp (session start/end).
    TouchActivity,
    /// Query whether the agent is idle (no sessions, past timeout).
    CheckIdle {
        reply: oneshot::Sender<bool>,
    },
}

/// Cloneable handle to the agent actor.
#[derive(Clone)]
struct AgentHandle {
    tx: mpsc::Sender<AgentCommand>,
}

impl AgentHandle {
    /// Request a connection and per-host semaphore for the given host.
    async fn get_connection(
        &self,
        host_id: PublicKey,
        relay_url: Option<String>,
    ) -> Result<(Connection, Arc<tokio::sync::Semaphore>)> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(AgentCommand::GetConnection {
                host_id,
                relay_url,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("agent actor stopped"))?;
        rx.await.map_err(|_| anyhow::anyhow!("agent actor stopped"))?
    }

    /// Evict a stale connection (fire-and-forget).
    async fn remove_connection(&self, host_id: PublicKey) {
        let _ = self
            .tx
            .send(AgentCommand::RemoveConnection { host_id })
            .await;
    }

    /// Flush all pooled connections (fire-and-forget).
    async fn flush_all(&self) {
        let _ = self.tx.send(AgentCommand::FlushAll).await;
    }

    /// Bump last_activity timestamp (fire-and-forget).
    async fn touch_activity(&self) {
        let _ = self.tx.send(AgentCommand::TouchActivity).await;
    }

    /// Check whether the agent is idle past the timeout.
    async fn check_idle(&self) -> bool {
        let (reply, rx) = oneshot::channel();
        let _ = self.tx.send(AgentCommand::CheckIdle { reply }).await;
        rx.await.unwrap_or(true)
    }
}

/// Reply type for GetConnection: a live connection + per-host semaphore.
type ConnectReply = oneshot::Sender<Result<(Connection, Arc<tokio::sync::Semaphore>)>>;

/// Mutable state owned exclusively by the actor task.
struct AgentState {
    endpoint: Endpoint,
    connections: HashMap<PublicKey, Connection>,
    semaphores: HashMap<PublicKey, Arc<tokio::sync::Semaphore>>,
    /// In-flight connect waiters: queued reply channels for hosts being connected.
    pending: HashMap<PublicKey, Vec<ConnectReply>>,
    /// Self-sender for spawned connect tasks to send ConnectDone back.
    tx: mpsc::Sender<AgentCommand>,
    last_activity: Instant,
}

/// Spawn the agent actor and return a handle.
fn spawn_agent_actor(endpoint: Endpoint) -> AgentHandle {
    let (tx, rx) = mpsc::channel(64);
    let state = AgentState {
        endpoint,
        connections: HashMap::new(),
        semaphores: HashMap::new(),
        pending: HashMap::new(),
        tx: tx.clone(),
        last_activity: Instant::now(),
    };
    tokio::spawn(run_agent_actor(rx, state));
    AgentHandle { tx }
}

/// The actor loop: owns all mutable connection state, processes commands sequentially.
async fn run_agent_actor(mut rx: mpsc::Receiver<AgentCommand>, mut state: AgentState) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            AgentCommand::GetConnection {
                host_id,
                relay_url,
                reply,
            } => {
                // 1. Check cache for a live connection
                if let Some(conn) = state.connections.get(&host_id) {
                    if conn.close_reason().is_none() {
                        let sem = state
                            .semaphores
                            .entry(host_id)
                            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                            .clone();
                        let _ = reply.send(Ok((conn.clone(), sem)));
                        continue;
                    }
                    // Dead connection — remove it
                    state.connections.remove(&host_id);
                }

                // 2. If a connect is already in-flight, queue this waiter
                if let Some(waiters) = state.pending.get_mut(&host_id) {
                    waiters.push(reply);
                    continue;
                }

                // 3. No connection, no in-flight connect — spawn one
                state.pending.insert(host_id, vec![reply]);
                let endpoint = state.endpoint.clone();
                let tx = state.tx.clone();
                tokio::spawn(async move {
                    let result = do_connect(&endpoint, host_id, relay_url).await;
                    let _ = tx
                        .send(AgentCommand::ConnectDone {
                            host_id,
                            result,
                        })
                        .await;
                });
            }

            AgentCommand::ConnectDone { host_id, result } => {
                let waiters = state.pending.remove(&host_id).unwrap_or_default();

                match result {
                    Ok(conn) => {
                        state.connections.insert(host_id, conn.clone());
                        let sem = state
                            .semaphores
                            .entry(host_id)
                            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                            .clone();
                        for reply in waiters {
                            let _ = reply.send(Ok((conn.clone(), sem.clone())));
                        }
                    }
                    Err(e) => {
                        // Fan out the error to all waiters
                        let msg = format!("{e:#}");
                        for reply in waiters {
                            let _ = reply.send(Err(anyhow::anyhow!("{}", msg)));
                        }
                    }
                }
            }

            AgentCommand::RemoveConnection { host_id } => {
                if let Some(conn) = state.connections.remove(&host_id) {
                    conn.close(0u32.into(), b"open-bi-failed");
                }
            }

            AgentCommand::FlushAll => {
                for (_, conn) in state.connections.drain() {
                    conn.close(0u32.into(), b"flush");
                }
            }

            AgentCommand::TouchActivity => {
                state.last_activity = Instant::now();
            }

            AgentCommand::CheckIdle { reply } => {
                let idle = state.last_activity.elapsed() >= IDLE_TIMEOUT;
                let _ = reply.send(idle);
            }
        }
    }
}

/// Connect to a host via QUIC. Tries hop/3 (compressed) first, falls back to hop/2.
/// Runs in a spawned task — never blocks the actor loop.
async fn do_connect(
    endpoint: &Endpoint,
    host_id: PublicKey,
    relay_url: Option<String>,
) -> Result<Connection> {
    let relay: Option<iroh::RelayUrl> = relay_url
        .as_deref()
        .map(|u| u.parse())
        .transpose()
        .ok()
        .flatten();

    match net::connect_to_host_with_alpn(
        endpoint,
        host_id,
        relay.as_ref(),
        hop_core::proto::ALPN_V3,
    )
    .await
    {
        Ok((conn, _)) => Ok(conn),
        Err(_) => {
            tracing::debug!(
                "hop/3 not supported by {}, falling back to hop/2",
                host_id.fmt_short()
            );
            let (conn, _) = net::connect_to_host(endpoint, host_id, relay.as_ref()).await?;
            Ok(conn)
        }
    }
}

// ---------------------------------------------------------------------------
// IPC client handler (free function, takes AgentHandle)
// ---------------------------------------------------------------------------

/// Handle a single IPC client connection.
///
/// Uses a per-host semaphore to serialize the connect+open_bi phase,
/// preventing reconnect stampedes when multiple IPC clients queue up
/// during slow QUIC handshakes. Also monitors IPC liveness so that
/// timed-out clients don't leave orphaned bi-streams.
async fn handle_client(
    mut ipc: UnixStream,
    handle: AgentHandle,
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<()> {
    // 1. Read MuxConnect
    let req: MuxConnect = mux::read_ipc_message(&mut ipc).await?;
    let host_id =
        PublicKey::from_bytes(&req.host_id).context("invalid host_id in MuxConnect")?;

    // 2. Split IPC early so we can monitor liveness during setup
    let (mut ipc_read, mut ipc_write) = ipc.into_split();

    // 3. Get connection + per-host semaphore, abort if IPC client disconnects
    let (conn, sem) = tokio::select! {
        result = handle.get_connection(host_id, req.relay_url) => {
            match result {
                Ok(pair) => pair,
                Err(e) => {
                    let _ = mux::write_ipc_message(
                        &mut ipc_write,
                        &MuxResult::Error(format!("{e:#}")),
                    ).await;
                    return Err(e);
                }
            }
        }
        _ = wait_for_ipc_close(&mut ipc_read) => {
            tracing::debug!("IPC client disconnected during connect ({})", host_id.fmt_short());
            return Ok(());
        }
    };

    // 4. Acquire semaphore, abort if IPC client disconnects while waiting
    let permit = tokio::select! {
        permit = sem.acquire_owned() => {
            permit.map_err(|_| anyhow::anyhow!("host semaphore closed"))?
        }
        _ = wait_for_ipc_close(&mut ipc_read) => {
            tracing::debug!("IPC client disconnected while waiting for host lock ({})", host_id.fmt_short());
            return Ok(());
        }
    };

    // 5. Open bi-stream (fast on live connection)
    let (quic_send, quic_recv) = match conn.open_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            // Connection may have died; evict from pool
            handle.remove_connection(host_id).await;
            let _ = mux::write_ipc_message(
                &mut ipc_write,
                &MuxResult::Error(format!("open_bi failed: {e:#}")),
            )
            .await;
            anyhow::bail!("open_bi failed: {e:#}");
        }
    };

    // 6. Signal ready
    mux::write_ipc_message(&mut ipc_write, &MuxResult::Ready).await?;

    // 7. Drop semaphore permit — unblocks next waiter, doesn't block proxy
    drop(permit);

    // 8. Track active session
    active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    handle.touch_activity().await;

    // 9. Transparent bidirectional proxy
    let result = proxy_quic(ipc_read, ipc_write, quic_send, quic_recv).await;

    // 10. Session done
    active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    handle.touch_activity().await;

    if let Err(e) = result {
        tracing::debug!("Proxy session ended: {e:#}");
    }
    Ok(())
}

/// Detect when an IPC client has disconnected by reading from the socket.
///
/// Cancel-safe: `OwnedReadHalf::read` is cancel-safe per tokio docs.
/// Safe to call during the setup phase — the client sends no data between
/// MuxConnect and MuxResult::Ready, so any read returning 0 or error
/// means the client is gone.
async fn wait_for_ipc_close(ipc_read: &mut tokio::net::unix::OwnedReadHalf) {
    let mut buf = [0u8; 1];
    loop {
        match ipc_read.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
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
    // Host→Client: copy QUIC data to IPC, flushing after each chunk
    // to avoid buffering delays on high-latency links.
    // When this finishes, dropping ipc_write signals EOF to the client.
    let h2c = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => {
                    if ipc_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if ipc_write.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("QUIC→IPC ended: {e:#}");
                    break;
                }
            }
        }
    });

    // Client→Host: copy IPC data to QUIC, flushing after each chunk.
    // When this finishes, quic_send.finish() signals FIN to the host.
    let c2h = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match ipc_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if quic_send.flush().await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("IPC→QUIC ended: {e:#}");
                    break;
                }
            }
        }
        let _ = quic_send.finish();
    });

    // Both tasks complete naturally via EOF propagation:
    //   Pull: host finishes → h2c drops ipc_write → client sees EOF → client
    //         drops socket → c2h's ipc_read sees EOF → c2h finishes
    //   Push: client finishes → c2h calls finish() → host sees FIN → host
    //         sends response + finishes → h2c's quic_recv sees EOF → h2c finishes
    let _ = tokio::join!(h2c, c2h);

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

// ---------------------------------------------------------------------------
// Idle check (actor-based)
// ---------------------------------------------------------------------------

/// Poll the actor for idle status. Returns when the agent is idle.
async fn check_idle_actor(
    active_sessions: &std::sync::atomic::AtomicUsize,
    handle: &AgentHandle,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        let active = active_sessions.load(std::sync::atomic::Ordering::Relaxed);
        if active > 0 {
            continue;
        }

        if handle.check_idle().await {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Main agent entry point
// ---------------------------------------------------------------------------

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

    let secret_key = config::load_or_generate_identity(config_dir)?;
    let endpoint = net::create_client_endpoint(secret_key).await?;
    let handle = spawn_agent_actor(endpoint.clone());
    let active_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Background task: flush stale connections on sleep/wake
    let wake_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            let before = std::time::Instant::now();
            tokio::time::sleep(Duration::from_secs(3)).await;
            if before.elapsed() > Duration::from_secs(15) {
                tracing::info!("Agent detected sleep/wake, flushing connection pool");
                wake_handle.flush_all().await;
            }
        }
    });

    // Network interface change detector — flushes pooled connections on change
    let _netmon = net::netmon::spawn_interface_watcher(endpoint.clone());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let h = handle.clone();
                        let sessions = active_sessions.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, h, sessions).await {
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
            _ = check_idle_actor(&active_sessions, &handle) => {
                tracing::info!("Agent idle timeout reached, shutting down");
                break;
            }
        }
    }

    // Cleanup: flush all pooled connections, then close the endpoint
    handle.flush_all().await;
    drop(handle);
    endpoint.close().await;
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(&pid_path);

    Ok(())
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

        // Spawn a minimal actor with last_activity already past the timeout
        let (tx, mut rx) = mpsc::channel::<AgentCommand>(16);
        let handle = AgentHandle { tx };

        // Actor that only handles CheckIdle, with last_activity in the past
        tokio::spawn(async move {
            let past = Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1);
            while let Some(cmd) = rx.recv().await {
                if let AgentCommand::CheckIdle { reply } = cmd {
                    let _ = reply.send(past.elapsed() >= IDLE_TIMEOUT);
                }
            }
        });

        // check_idle_actor polls every 30s, so we use tokio::time::pause to advance
        // the clock instantly.
        tokio::time::pause();

        let result = tokio::time::timeout(Duration::from_secs(60), async {
            check_idle_actor(&active, &handle).await;
        })
        .await;

        assert!(result.is_ok(), "check_idle_actor should have returned promptly");
    }

    #[tokio::test]
    async fn handle_returns_error_when_actor_dropped() {
        let (tx, rx) = mpsc::channel::<AgentCommand>(1);
        let handle = AgentHandle { tx };

        // Drop the receiver immediately — actor is "stopped"
        drop(rx);

        let host_id = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let result = handle.get_connection(host_id, None).await;
        assert!(result.is_err(), "should return error when actor is stopped");
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
