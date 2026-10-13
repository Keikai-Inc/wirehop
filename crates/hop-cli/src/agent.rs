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

use tracing_subscriber::filter::Targets;

use hop_core::config;
use hop_core::net;

use crate::mux::{self, MuxConnect, MuxResult};

/// Type alias for the reload handle used by the SIGUSR1 debug toggle.
type ReloadHandle = tracing_subscriber::reload::Handle<Targets, tracing_subscriber::Registry>;

/// Idle timeout: shut down the agent after 10 minutes with no active sessions.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Run the agent in foreground mode.
pub async fn run_foreground(config_dir: &Path, reload_handle: ReloadHandle) -> Result<()> {
    run_agent(config_dir, false, reload_handle).await
}

/// Run the agent in daemon mode (detached, writes PID file).
pub async fn run_daemon(config_dir: &Path, reload_handle: ReloadHandle) -> Result<()> {
    run_agent(config_dir, true, reload_handle).await
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
        print_agent_health(config_dir);
    } else {
        println!("Agent PID file exists but process {pid} is not running.");
        // Clean up stale files
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(&sock_path);
    }
    Ok(())
}

/// Per-host connection quality from the running agent's `agent-health.json`.
fn print_agent_health(config_dir: &Path) {
    let Ok(json) = std::fs::read_to_string(agent_health_path(config_dir)) else {
        return; // an agent that predates the probe, or no hop/4 connection yet
    };
    let Ok(h) = serde_json::from_str::<hop_core::health::HealthSnapshot>(&json) else {
        return;
    };
    if h.agent_conns.is_empty() {
        return;
    }
    println!("  Connections (probed every ~{}s):", quality_probe_every().as_secs());
    for (host, c) in &h.agent_conns {
        let rtt = c.last_rtt_ms.map(|v| format!("{v} ms")).unwrap_or_else(|| "no answer".into());
        let base = c.baseline_ms.map(|v| format!("{v} ms")).unwrap_or_else(|| "?".into());
        let path = match c.on_relay {
            Some(true) => "relay",
            Some(false) => "direct",
            None => "?",
        };
        println!(
            "    {host}  rtt {rtt} (baseline {base}), {path}, {}",
            c.last_verdict.as_deref().unwrap_or("?")
        );
        if let Some(ev) = &c.last_event {
            println!("      last action: {ev}");
        }
    }
    if h.agent_replacements > 0 {
        println!("  Degraded connections replaced: {}", h.agent_replacements);
    }
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
        reply: ConnectReply,
    },
    /// Self-message from a spawned connect task when the QUIC handshake completes.
    ConnectDone {
        host_id: PublicKey,
        result: Result<Connection>,
    },
    /// Evict a stale connection after an open_bi failure or reconnect.
    /// Skipped if the host still has live sessions (the conn is in use).
    RemoveConnection {
        host_id: PublicKey,
    },
    /// Evict one specific connection (by `stable_id`) that failed a liveness
    /// check, live sessions or not: a connection that cannot carry stream data
    /// is dead for every session on it, and closing it is what lets those
    /// sessions notice and reconnect instead of waiting out a 75s deadline.
    /// The id guard means a replacement dialed in the meantime is left alone.
    ForceRemoveConnection {
        host_id: PublicKey,
        stable_id: usize,
    },
    /// The quality probe dialed a better connection to replace a degraded one.
    /// Swapped in only if `old_stable_id` is still the pooled connection (else
    /// something already replaced it); the old one is then closed so its
    /// sessions resume on the new one. Replies whether the swap happened.
    ReplaceConnection {
        host_id: PublicKey,
        old_stable_id: usize,
        new: Connection,
        reply: oneshot::Sender<bool>,
    },
    /// A pooled connection answered a `Ping`: refresh its verified timestamp.
    NotePoolVerified {
        host_id: PublicKey,
        stable_id: usize,
    },
    /// A multiplexed proxy session for `host_id` started.
    SessionStarted {
        host_id: PublicKey,
    },
    /// A multiplexed proxy session for `host_id` ended.
    SessionEnded {
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
    /// Request a connection and per-host semaphore for the given host. The
    /// flag says whether the caller must still run the liveness check.
    async fn get_connection(
        &self,
        host_id: PublicKey,
        relay_url: Option<String>,
    ) -> Result<(Connection, Arc<tokio::sync::Semaphore>, bool)> {
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

    /// Evict the connection with this `stable_id` regardless of live sessions
    /// (fire-and-forget). See `AgentCommand::ForceRemoveConnection`.
    async fn force_remove_connection(&self, host_id: PublicKey, stable_id: usize) {
        let _ = self
            .tx
            .send(AgentCommand::ForceRemoveConnection { host_id, stable_id })
            .await;
    }

    /// Swap `new` in for the degraded pooled connection `old_stable_id`.
    async fn replace_connection(&self, host_id: PublicKey, old_stable_id: usize, new: Connection) -> bool {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(AgentCommand::ReplaceConnection { host_id, old_stable_id, new, reply })
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    /// Record that the pooled connection with this `stable_id` answered a ping.
    async fn note_pool_verified(&self, host_id: PublicKey, stable_id: usize) {
        let _ = self
            .tx
            .send(AgentCommand::NotePoolVerified { host_id, stable_id })
            .await;
    }

    /// Register a started proxy session for `host_id` (fire-and-forget).
    async fn session_started(&self, host_id: PublicKey) {
        let _ = self
            .tx
            .send(AgentCommand::SessionStarted { host_id })
            .await;
    }

    /// Register an ended proxy session for `host_id` (fire-and-forget).
    async fn session_ended(&self, host_id: PublicKey) {
        let _ = self.tx.send(AgentCommand::SessionEnded { host_id }).await;
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

/// Reply type for GetConnection: a live connection + per-host semaphore +
/// whether it still needs a liveness check (pooled, and not verified within
/// `POOL_VERIFY_WINDOW`). A freshly dialed connection never does.
type ConnectReply = oneshot::Sender<Result<(Connection, Arc<tokio::sync::Semaphore>, bool)>>;


/// Mutable state owned exclusively by the actor task.
struct AgentState {
    endpoint: Endpoint,
    connections: HashMap<PublicKey, Connection>,
    semaphores: HashMap<PublicKey, Arc<tokio::sync::Semaphore>>,
    /// Live multiplexed sessions per host. The pooled connection is shared across
    /// all sessions to a host, so eviction must never close a connection that
    /// still has a live session on it (see `RemoveConnection`).
    active: HashMap<PublicKey, usize>,
    /// In-flight connect waiters: queued reply channels for hosts being connected.
    pending: HashMap<PublicKey, Vec<ConnectReply>>,
    /// When each host's pooled connection last proved it carries stream data:
    /// the dial itself (a fresh handshake), or a `Ping`/`Pong` round-trip. A
    /// cache hit inside `POOL_VERIFY_WINDOW` of that skips the ping, so a burst
    /// of sessions reconnecting together runs one check, not one each.
    verified: HashMap<PublicKey, Instant>,
    /// When each pooled connection was dialed (or swapped in). A network-change
    /// flush spares connections younger than `FLUSH_SPARES_YOUNGER_THAN`.
    dialed: HashMap<PublicKey, Instant>,
    /// Self-sender for spawned connect tasks to send ConnectDone back.
    tx: mpsc::Sender<AgentCommand>,
    last_activity: Instant,
}

/// Whether a host's pooled connection may be evicted. Eviction closes the
/// shared per-host connection's streams, so it is only safe when no live session
/// is using it — otherwise a concurrent session's reconnect would tear down the
/// streams in use (the mutual-eviction loop). See `AgentCommand::RemoveConnection`.
fn may_evict(active: &HashMap<PublicKey, usize>, host_id: &PublicKey) -> bool {
    active.get(host_id).copied().unwrap_or(0) == 0
}

/// Record that a proxy session for `host_id` started.
fn session_inc(active: &mut HashMap<PublicKey, usize>, host_id: PublicKey) {
    *active.entry(host_id).or_insert(0) += 1;
}

/// Record that a proxy session for `host_id` ended (drops the entry at zero).
fn session_dec(active: &mut HashMap<PublicKey, usize>, host_id: &PublicKey) {
    if let Some(n) = active.get_mut(host_id) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            active.remove(host_id);
        }
    }
}

/// Spawn the agent actor and return a handle.
fn spawn_agent_actor(endpoint: Endpoint) -> AgentHandle {
    let (tx, rx) = mpsc::channel(64);
    let state = AgentState {
        endpoint,
        connections: HashMap::new(),
        semaphores: HashMap::new(),
        active: HashMap::new(),
        pending: HashMap::new(),
        verified: HashMap::new(),
        dialed: HashMap::new(),
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
                        tracing::debug!("actor: cache HIT for {} (pool size: {})", host_id.fmt_short(), state.connections.len());
                        let sem = state
                            .semaphores
                            .entry(host_id)
                            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                            .clone();
                        let needs_check = state
                            .verified
                            .get(&host_id)
                            .map(|t| t.elapsed() >= POOL_VERIFY_WINDOW)
                            .unwrap_or(true);
                        let _ = reply.send(Ok((conn.clone(), sem, needs_check)));
                        continue;
                    }
                    // Dead connection — remove it
                    tracing::debug!("actor: evicting dead connection for {}", host_id.fmt_short());
                    state.connections.remove(&host_id);
                }

                // 2. If a connect is already in-flight, queue this waiter
                if let Some(waiters) = state.pending.get_mut(&host_id) {
                    tracing::debug!("actor: joining in-flight connect for {} ({} waiters)", host_id.fmt_short(), waiters.len() + 1);
                    waiters.push(reply);
                    continue;
                }

                // 3. No connection, no in-flight connect — spawn one
                tracing::debug!("actor: spawning new connect for {} (pool size: {})", host_id.fmt_short(), state.connections.len());
                state.pending.insert(host_id, vec![reply]);
                let endpoint = state.endpoint.clone();
                let tx = state.tx.clone();
                tokio::spawn(async move {
                    let result = do_connect(&endpoint, host_id, relay_url.clone()).await;
                    if let Ok(conn) = &result {
                        spawn_quality_probe(
                            conn.clone(),
                            host_id,
                            relay_url,
                            endpoint.clone(),
                            AgentHandle { tx: tx.clone() },
                        );
                    }
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
                        state.dialed.insert(host_id, Instant::now());
                        // A completed handshake is proof enough for now.
                        state.verified.insert(host_id, Instant::now());
                        tracing::debug!("actor: connect succeeded for {} (alpn: {}, pool size: {}, notifying {} waiters)",
                            host_id.fmt_short(),
                            std::str::from_utf8(conn.alpn()).unwrap_or("?"),
                            state.connections.len(),
                            waiters.len());
                        let sem = state
                            .semaphores
                            .entry(host_id)
                            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                            .clone();
                        for reply in waiters {
                            let _ = reply.send(Ok((conn.clone(), sem.clone(), false)));
                        }
                    }
                    Err(e) => {
                        tracing::debug!("actor: connect failed for {}: {:#}, notifying {} waiters", host_id.fmt_short(), e, waiters.len());
                        // Fan out the error to all waiters
                        let msg = format!("{e:#}");
                        for reply in waiters {
                            let _ = reply.send(Err(anyhow::anyhow!("{}", msg)));
                        }
                    }
                }
            }

            AgentCommand::RemoveConnection { host_id } => {
                // Never close a connection that still has live multiplexed
                // sessions. The pooled connection is shared per-host, so evicting
                // it — e.g. a concurrent session's reconnect dialing with
                // evict_first — would tear down the streams the other sessions are
                // actively using. That is a mutual-eviction reconnect loop between
                // two `hop connect` sessions to the same host: each one's reconnect
                // kills the other's connection, forever. A connection with a live
                // session is provably not half-open, so keep it; only evict an
                // idle (genuinely stale) pooled connection.
                if may_evict(&state.active, &host_id) {
                    if let Some(conn) = state.connections.remove(&host_id) {
                        tracing::debug!("actor: evicting idle connection for {} (pool size: {})", host_id.fmt_short(), state.connections.len());
                        conn.close(0u32.into(), b"evicted-idle");
                    }
                } else {
                    tracing::debug!("actor: skip evicting connection for {} — {} active session(s) still using it", host_id.fmt_short(), state.active.get(&host_id).copied().unwrap_or(0));
                }
            }

            AgentCommand::ReplaceConnection { host_id, old_stable_id, new, reply } => {
                let current = state
                    .connections
                    .get(&host_id)
                    .map(|c| c.stable_id() == old_stable_id)
                    .unwrap_or(false);
                if !current {
                    let _ = reply.send(false);
                    continue;
                }
                if let Some(old) = state.connections.insert(host_id, new) {
                    // Closing errors the old connection's proxied streams, so its
                    // sessions reconnect now — onto the replacement, which is
                    // already pooled — instead of limping on the degraded path.
                    old.close(0u32.into(), b"replaced-degraded");
                }
                state.verified.insert(host_id, Instant::now());
                state.dialed.insert(host_id, Instant::now());
                let _ = reply.send(true);
            }

            AgentCommand::NotePoolVerified { host_id, stable_id } => {
                if state
                    .connections
                    .get(&host_id)
                    .map(|c| c.stable_id() == stable_id)
                    .unwrap_or(false)
                {
                    state.verified.insert(host_id, Instant::now());
                }
            }

            AgentCommand::ForceRemoveConnection { host_id, stable_id } => {
                let matches = state
                    .connections
                    .get(&host_id)
                    .map(|c| c.stable_id() == stable_id)
                    .unwrap_or(false);
                if matches
                    && let Some(conn) = state.connections.remove(&host_id)
                {
                    tracing::info!(
                        "mux: dropping pooled connection to {} that failed its liveness check ({} active session(s) will reconnect)",
                        host_id.fmt_short(),
                        state.active.get(&host_id).copied().unwrap_or(0)
                    );
                    conn.close(0u32.into(), b"failed-liveness-check");
                    state.verified.remove(&host_id);
                }
            }

            AgentCommand::SessionStarted { host_id } => {
                session_inc(&mut state.active, host_id);
            }

            AgentCommand::SessionEnded { host_id } => {
                session_dec(&mut state.active, &host_id);
            }

            AgentCommand::FlushAll => {
                // A connection dialed in the last few seconds was dialed after
                // the change that triggered this flush (netmon debounces ~2 s
                // before signalling), so it is already on the current network.
                // Closing it dropped sessions that had just recovered — 2-3 s
                // after every reconnect, which tripped flap backoff and pushed
                // net_flap recovery to the 30 s read deadline.
                let young: Vec<PublicKey> = state
                    .dialed
                    .iter()
                    .filter(|(_, t)| t.elapsed() < FLUSH_SPARES_YOUNGER_THAN)
                    .map(|(h, _)| *h)
                    .collect();
                tracing::debug!(
                    "actor: flushing connections ({} pooled, sparing {} dialed <{}s ago)",
                    state.connections.len(),
                    young.len(),
                    FLUSH_SPARES_YOUNGER_THAN.as_secs()
                );
                let spared: HashMap<PublicKey, Connection> = state
                    .connections
                    .drain()
                    .filter_map(|(h, conn)| {
                        if young.contains(&h) && conn.close_reason().is_none() {
                            Some((h, conn))
                        } else {
                            conn.close(0u32.into(), b"flush");
                            None
                        }
                    })
                    .collect();
                state.connections = spared;
                state.dialed.retain(|h, _| state.connections.contains_key(h));
                // Per-host semaphores are recreated on demand; a handle_client
                // mid-connect keeps its own Arc. Dropping them here keeps the
                // map from growing with every host ever dialed.
                state.semaphores.clear();
                state.verified.retain(|h, _| state.connections.contains_key(h));
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

/// Dial timeout for mux connects. Deliberately short (session-recovery-parity
/// Phase 2): a dead path must FAIL FAST so the reconnect loop can retry — and
/// because concurrent retry attempts JOIN the in-flight dial as waiters, one
/// slow dial pins every "retry now" the user presses behind it. The old
/// 30s-hop/3 + 30s-hop/2 sequence meant a dead path blocked all reconnect
/// attempts for a full minute. The VPN data plane uses the same fail-fast
/// rationale for its short dial timeout.
const MUX_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// After this long with zero received datagrams, a connection is a zombie.
/// Both ends run hop's transport config (5s keepalives), so a healthy
/// connection receives SOMETHING at least every ~5s even when idle; 15s of
/// silence = 3 missed keepalives. QUIC's own idle timeout is 60s — waiting for
/// it is what made dead sessions sit frozen for a minute before the reconnect
/// machinery even started.
const ZOMBIE_STALL: Duration = Duration::from_secs(15);
const ZOMBIE_POLL: Duration = Duration::from_secs(3);

/// Watch a pooled connection for rx-stall and close it as a zombie. Closing
/// errors the proxied session streams immediately → the client sees EOF →
/// its quick-reconnect tier engages within seconds instead of waiting out
/// QUIC's 60s idle timeout (session-recovery-parity Phase 1).
fn spawn_zombie_watchdog(conn: Connection, host_id: PublicKey) {
    tokio::spawn(async move {
        let mut last_rx = conn.stats().udp_rx.datagrams;
        let mut last_progress = Instant::now();
        loop {
            tokio::time::sleep(ZOMBIE_POLL).await;
            if conn.close_reason().is_some() {
                return; // closed normally — watchdog done
            }
            let rx = conn.stats().udp_rx.datagrams;
            if rx != last_rx {
                last_rx = rx;
                last_progress = Instant::now();
                continue;
            }
            if last_progress.elapsed() >= ZOMBIE_STALL {
                tracing::info!(
                    "mux: connection to {} stalled ({}s without a datagram despite 5s keepalives) — closing zombie",
                    host_id.fmt_short(),
                    last_progress.elapsed().as_secs()
                );
                conn.close(0u32.into(), b"zombie-stall");
                return;
            }
        }
    });
}

/// How often each pooled hop/4 connection is probed (jittered ±20 %), whether
/// or not a session is using it, so a degraded path is found and replaced
/// before the next keystroke rather than by it. `HOP_AGENT_PROBE_SECS` overrides.
const QUALITY_PROBE_EVERY: Duration = Duration::from_secs(15);
/// At most one replacement attempt per connection this often.
const REPLACE_COOLDOWN: Duration = Duration::from_secs(120);

/// Where the client agent publishes its health snapshot for `hop agent status`
/// (set by `run_agent`; the host daemon's mux service leaves it unset and
/// serves the same registry over its daemon socket instead).
static AGENT_HEALTH_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

fn agent_health_path(config_dir: &Path) -> std::path::PathBuf {
    config_dir.join("agent-health.json")
}

fn write_agent_health() {
    if let Some(path) = AGENT_HEALTH_PATH.get() {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, hop_core::health::snapshot_json()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn quality_probe_every() -> Duration {
    let base = std::env::var("HOP_AGENT_PROBE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(QUALITY_PROBE_EVERY);
    // ±20 % jitter from the clock's sub-second noise: a fleet of agents must
    // not line their probes up on the relay.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pct = 80 + (nanos % 41); // 80..=120
    base * pct / 100
}

fn verdict_label(v: &hop_core::conn_quality::Verdict) -> String {
    use hop_core::conn_quality::Verdict;
    match v {
        Verdict::Good => "Good".into(),
        Verdict::Unanswered => "Unanswered".into(),
        Verdict::Slow { rtt, baseline } => {
            format!("Slow ({} ms vs {} ms baseline)", rtt.as_millis(), baseline.as_millis())
        }
        Verdict::StuckOnRelay => "StuckOnRelay".into(),
    }
}

/// Probe one pooled hop/4 connection for as long as it lives, and replace it
/// when it degrades (`docs/technical/self-healing.md`, "Pre-emptive
/// detection"). The 2026-10-12 incident: a pooled connection on a bad path
/// kept its keepalives flowing, so `spawn_zombie_watchdog` never fired, and
/// every session on it crawled until the operator ran `hop agent stop`.
///
/// Replace before tearing down: the replacement is dialed and pinged first and
/// swapped in only if it is clearly better (or the old one stopped answering).
/// If it is no better the path itself is slow, so the old connection is kept
/// and its baseline restarted — no redial loop on a path that is just slow.
fn spawn_quality_probe(
    conn: Connection,
    host_id: PublicKey,
    relay_url: Option<String>,
    endpoint: Endpoint,
    handle: AgentHandle,
) {
    use hop_core::conn_quality::{QualityTracker, replacement_is_better};
    if conn.alpn() != hop_core::proto::ALPN_V4 {
        return; // `Ping` is hop/4-only
    }
    tokio::spawn(async move {
        let host = host_id.fmt_short().to_string();
        let mut conn = conn;
        let mut q = QualityTracker::default();
        let mut last_attempt: Option<Instant> = None;
        let mut last_rx = conn.stats().udp_rx.datagrams;
        loop {
            tokio::time::sleep(quality_probe_every()).await;
            if conn.close_reason().is_some() {
                return;
            }
            // Nothing received since the last probe (5 s keepalives make that
            // impossible on a live path) means the path is blacked out: that is
            // `spawn_zombie_watchdog`'s case. Probing into it only adds lost
            // stream data on top of the keepalives, and with it the probe
            // stretched recovery after a blackout from ~2 s to 24-30 s in 3 of
            // 17 session-resilience zombie_path cycles (0 of 13 without it).
            let rx = conn.stats().udp_rx.datagrams;
            if rx == last_rx {
                continue;
            }
            last_rx = rx;
            let rtt = check_pooled_liveness(&conn).await.ok();
            if conn.close_reason().is_some() {
                return; // evicted or replaced while the probe was in flight
            }
            let on_relay = conn.to_info().selected_path().map(|p| p.is_relay());
            let verdict = q.record(rtt, on_relay).clone();
            hop_core::health::note_agent_conn(
                &host,
                hop_core::health::AgentConnSnapshot {
                    last_rtt_ms: rtt.map(|d| d.as_millis() as u64),
                    baseline_ms: q.baseline().map(|d| d.as_millis() as u64),
                    on_relay,
                    consecutive_bad: q.consecutive_bad(),
                    last_verdict: Some(verdict_label(&verdict)),
                    ..Default::default()
                },
            );
            write_agent_health();

            if !q.degraded() || last_attempt.is_some_and(|t| t.elapsed() < REPLACE_COOLDOWN) {
                continue;
            }
            last_attempt = Some(Instant::now());
            let why = verdict_label(&verdict);
            let fresh = match do_connect(&endpoint, host_id, relay_url.clone()).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("mux: connection to {host} degraded ({why}); replacement dial failed: {e:#}");
                    hop_core::health::note_agent_event(&host, format!("degraded ({why}); replacement dial failed"), false);
                    write_agent_health();
                    continue;
                }
            };
            let fresh_rtt = if fresh.alpn() == hop_core::proto::ALPN_V4 {
                check_pooled_liveness(&fresh).await.ok()
            } else {
                None
            };
            match fresh_rtt {
                Some(new_rtt) if replacement_is_better(q.last_rtt(), new_rtt) => {
                    if !handle.replace_connection(host_id, conn.stable_id(), fresh.clone()).await {
                        // Already replaced or evicted; whatever is pooled now has
                        // its own probe.
                        fresh.close(0u32.into(), b"replacement-superseded");
                        return;
                    }
                    let event = format!(
                        "replaced degraded connection ({why}); new one answered in {} ms",
                        new_rtt.as_millis()
                    );
                    tracing::warn!("mux: {host}: {event}");
                    hop_core::health::note_agent_event(&host, event, true);
                    write_agent_health();
                    conn = fresh;
                    last_rx = conn.stats().udp_rx.datagrams;
                    q = QualityTracker::default();
                    q.record(Some(new_rtt), conn.to_info().selected_path().map(|p| p.is_relay()));
                    last_attempt = None;
                }
                _ => {
                    fresh.close(0u32.into(), b"replacement-no-better");
                    q.rebase();
                    let event = format!(
                        "degraded ({why}) but a fresh connection was no better ({}); keeping it as the new normal",
                        fresh_rtt.map(|d| format!("{} ms", d.as_millis())).unwrap_or_else(|| "no answer".into())
                    );
                    tracing::info!("mux: {host}: {event}");
                    hop_core::health::note_agent_event(&host, event, false);
                    write_agent_health();
                }
            }
        }
    });
}

/// Budget for opening a session stream on a pooled connection.
const OPEN_BI_TIMEOUT: Duration = Duration::from_secs(10);

/// A network-change flush leaves connections dialed more recently than this.
const FLUSH_SPARES_YOUNGER_THAN: Duration = Duration::from_secs(5);

/// Budget for the pooled-connection liveness check. A dead connection never
/// answers, so the only cost of a generous budget is how long the rare zombie
/// case waits before re-dialing; a tight one turns every ordinary stall on a
/// slow path into a teardown of every session on the connection. The first
/// cut was 2s and did exactly that: on a path with multi-second stalls, each
/// reconnect burst had one ping time out, evict the shared connection, drop
/// every other session, and start the next burst.
const POOL_LIVENESS_TIMEOUT: Duration = Duration::from_secs(8);
/// How long a fresh dial or a successful `Ping` vouches for a pooled
/// connection. Sessions reconnecting together (a laptop waking, a network
/// change) arrive within a second of each other; they must share one check
/// rather than each open a ping stream on a connection that is still settling.
/// See `AgentState::verified`.
const POOL_VERIFY_WINDOW: Duration = Duration::from_secs(20);

/// Prove a pooled connection can still carry stream data both ways: open a
/// bi-stream, send `Ping`, expect `Pong` (hop/4+ hosts). `close_reason()` and
/// the rx-stall watchdog only see the transport; on 2026-09-11 a pooled
/// connection kept QUIC keepalives flowing for 20 minutes while no stream
/// data reached the host, and every `hop connect` was handed that connection.
async fn check_pooled_liveness(conn: &Connection) -> Result<Duration> {
    use hop_core::proto::{self, ClientMessage, HostMessage};
    let started = Instant::now();
    let probe = async {
        let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
        proto::write_message(&mut send, &ClientMessage::Ping).await.context("send ping")?;
        let reply: HostMessage = proto::read_message(&mut recv).await.context("read pong")?;
        anyhow::ensure!(matches!(reply, HostMessage::Pong), "unexpected reply to ping: {reply:?}");
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(POOL_LIVENESS_TIMEOUT, probe)
        .await
        .map_err(|_| anyhow::anyhow!("no pong within {}s", POOL_LIVENESS_TIMEOUT.as_secs()))??;
    Ok(started.elapsed())
}

/// True if the dial error was a timeout (dead/stale path) rather than a
/// rejection. Matches the message produced by `connect_to_host_with_alpn_timeout`.
fn is_dial_timeout(e: &anyhow::Error) -> bool {
    format!("{e:#}").to_lowercase().contains("timed out")
}

/// Start another, fresh dial if the previous one has not completed after this.
const DIAL_HEDGE_AFTER: Duration = Duration::from_secs(3);

/// Dial with hedging: if the dial has not completed after `DIAL_HEDGE_AFTER`,
/// start a fresh one alongside it (and another after twice that), and take
/// whichever completes first, all inside `total`. A dial started during an
/// outage sends handshake packets that are lost, and QUIC backs off their
/// retransmission (0.9 s, 1.8 s, 3.6 s, …); when the path returns mid-dial that
/// handshake is still asleep in its backoff and runs to the timeout. A fresh
/// handshake after the path is back completes in well under a second — this
/// took `zombie_path` recovery after a `net_flap` from 21–23 s (3 of 6) down.
async fn hedged_dial(
    endpoint: &Endpoint,
    host_id: PublicKey,
    relay: Option<&iroh::RelayUrl>,
    alpn: &'static [u8],
    total: Duration,
) -> Result<Connection> {
    let started = Instant::now();
    let mut dials = tokio::task::JoinSet::new();
    let mut launched = 0u32;
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        let elapsed = started.elapsed();
        if elapsed >= total {
            break;
        }
        if launched < 3 && elapsed >= DIAL_HEDGE_AFTER * launched {
            let ep = endpoint.clone();
            let relay = relay.cloned();
            let budget = total - elapsed;
            dials.spawn(async move {
                net::connect_to_host_with_alpn_timeout(&ep, host_id, relay.as_ref(), alpn, budget)
                    .await
                    .map(|(c, _)| c)
            });
            launched += 1;
            if launched > 1 {
                tracing::debug!("do_connect: dial to {} not done after {:?}; hedging (dial {launched})", host_id.fmt_short(), elapsed);
            }
        }
        let next_hedge = if launched < 3 {
            (DIAL_HEDGE_AFTER * launched).saturating_sub(started.elapsed())
        } else {
            total.saturating_sub(started.elapsed())
        };
        tokio::select! {
            joined = dials.join_next(), if !dials.is_empty() => match joined {
                Some(Ok(Ok(conn))) => return Ok(conn), // dropping the set aborts the rest
                Some(Ok(Err(e))) => {
                    // A refused ALPN is an answer, not a slow path: no hedging.
                    if is_alpn_rejection(&e) {
                        return Err(e);
                    }
                    last_err = Some(e);
                    if dials.is_empty() && launched >= 3 {
                        break;
                    }
                }
                Some(Err(_)) | None => {}
            },
            _ = tokio::time::sleep(next_hedge) => {}
        }
    }
    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Connection timed out after {}s. The host may be offline, behind a strict firewall, \
             or unable to reach the relay.",
            total.as_secs()
        )
    }))
}

/// True if the host refused the ALPN itself: TLS alert 120
/// (`no_application_protocol`), which noq reports as "the cryptographic
/// handshake failed: error 120" and rustls as "peer doesn't support any known
/// protocol". Only this means "older host, try an older protocol".
fn is_alpn_rejection(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}");
    msg.contains("error 120") || msg.contains("doesn't support any known protocol")
}

/// Connect to a host via QUIC. Tries hop/4 first and steps down ONLY when the
/// host REJECTED the ALPN (an older host). Any other failure — a timeout, a
/// handshake aborted on a flaky path — is returned as is: stepping down on it
/// would pin the pooled connection to an older protocol for its whole life,
/// which also switches off the hop/4-only `Ping` liveness check. Runs in a
/// spawned task — never blocks the actor loop.
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

    tracing::debug!("do_connect: {} relay_hint={:?}", host_id.fmt_short(), relay.as_ref().map(|u| u.to_string()));

    // Newest protocol first; an older host refuses the ALPN and we step down.
    // A dial *timeout* is a dead path, not a version mismatch, so it is not
    // retried on an older ALPN.
    let mut last_err = None;
    for (alpn, label) in [
        (hop_core::proto::ALPN_V4, "hop/4"),
        (hop_core::proto::ALPN_V3, "hop/3"),
        (hop_core::proto::ALPN_V2, "hop/2"),
    ] {
        match hedged_dial(endpoint, host_id, relay.as_ref(), alpn, MUX_DIAL_TIMEOUT).await {
            Ok(conn) => {
                tracing::debug!("do_connect: {label} connected to {}", host_id.fmt_short());
                spawn_zombie_watchdog(conn.clone(), host_id);
                return Ok(conn);
            }
            Err(e) if is_alpn_rejection(&e) => {
                tracing::debug!("{label} not supported by {}, trying an older protocol", host_id.fmt_short());
                last_err = Some(e);
            }
            Err(e) => {
                if is_dial_timeout(&e) {
                    tracing::debug!("do_connect: {label} dial to {} timed out — dead path, NOT falling back", host_id.fmt_short());
                } else {
                    tracing::debug!("do_connect: {label} dial to {} failed ({e:#}) — not an ALPN refusal, NOT falling back", host_id.fmt_short());
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no protocol version accepted by {}", host_id.fmt_short())))
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

    tracing::debug!("handle_client: MuxConnect for {} relay={:?} evict_first={}", host_id.fmt_short(), req.relay_url, req.evict_first);

    // Reconnect requested a fresh dial: drop any pooled (possibly half-open)
    // connection so get_connection re-dials rather than handing back a dead path.
    if req.evict_first {
        handle.remove_connection(host_id).await;
    }

    // 2. Split IPC early so we can monitor liveness during setup
    let (mut ipc_read, mut ipc_write) = ipc.into_split();

    // 3. Get connection + per-host semaphore, abort if IPC client disconnects.
    //    A pooled connection that has not proved itself recently is pinged
    //    before it is handed out (hop/4+): if it can't answer, it is
    //    force-evicted and the loop dials fresh — at most once, since the
    //    second pass returns a freshly dialed (and therefore verified) one.
    tracing::debug!("handle_client: getting connection for {}", host_id.fmt_short());
    let relay_url = req.relay_url;
    let (conn, sem) = loop {
        let (conn, sem, needs_check) = tokio::select! {
            result = handle.get_connection(host_id, relay_url.clone()) => {
                match result {
                    Ok(triple) => {
                        tracing::debug!("handle_client: connection obtained for {}", host_id.fmt_short());
                        triple
                    }
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
        if needs_check && conn.alpn() == hop_core::proto::ALPN_V4 {
            match check_pooled_liveness(&conn).await {
                Ok(rtt) => {
                    tracing::debug!("handle_client: pooled connection to {} answered ping in {} ms", host_id.fmt_short(), rtt.as_millis());
                    handle.note_pool_verified(host_id, conn.stable_id()).await;
                }
                Err(e) => {
                    tracing::info!(
                        "mux: pooled connection to {} failed its liveness check ({e:#}); dialing fresh",
                        host_id.fmt_short()
                    );
                    handle.force_remove_connection(host_id, conn.stable_id()).await;
                    continue;
                }
            }
        }
        break (conn, sem);
    };

    // 4. Acquire semaphore, abort if IPC client disconnects while waiting
    tracing::debug!("handle_client: waiting for host semaphore for {}", host_id.fmt_short());
    let permit = tokio::select! {
        permit = sem.acquire_owned() => {
            tracing::debug!("handle_client: semaphore acquired for {}", host_id.fmt_short());
            permit.map_err(|_| anyhow::anyhow!("host semaphore closed"))?
        }
        _ = wait_for_ipc_close(&mut ipc_read) => {
            tracing::debug!("IPC client disconnected while waiting for host lock ({})", host_id.fmt_short());
            return Ok(());
        }
    };

    // 5. Open bi-stream (fast on live connection). Bounded and raced against
    // the client leaving: it runs while holding the per-host semaphore, so an
    // open that never completes (stream limit on a wedged connection) queued
    // every later reconnect to this host behind it.
    let opened = tokio::select! {
        r = tokio::time::timeout(OPEN_BI_TIMEOUT, conn.open_bi()) => match r {
            Ok(r) => r.map_err(|e| anyhow::anyhow!("{e}")),
            Err(_) => Err(anyhow::anyhow!("open_bi did not complete within {}s", OPEN_BI_TIMEOUT.as_secs())),
        },
        _ = wait_for_ipc_close(&mut ipc_read) => {
            tracing::debug!("IPC client disconnected while opening a stream ({})", host_id.fmt_short());
            return Ok(());
        }
    };
    let (quic_send, quic_recv) = match opened {
        Ok(pair) => {
            tracing::debug!("handle_client: open_bi succeeded for {}", host_id.fmt_short());
            pair
        }
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

    // 8. Track active session. The per-host count guards the shared pooled
    // connection from being evicted out from under this session (see
    // RemoveConnection); the global counter drives idle shutdown.
    let session_start = Instant::now();
    active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    handle.session_started(host_id).await;
    handle.touch_activity().await;
    tracing::debug!("handle_client: session started for {}", host_id.fmt_short());

    // 9. Transparent bidirectional proxy
    let result = proxy_quic(ipc_read, ipc_write, quic_send, quic_recv).await;

    // 10. Session done
    active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    handle.session_ended(host_id).await;
    handle.touch_activity().await;
    tracing::debug!("handle_client: session ended for {} (duration: {:?})", host_id.fmt_short(), session_start.elapsed());

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

/// How a proxy direction finished.
#[derive(PartialEq)]
enum Ended {
    /// Clean EOF — the peer closed gracefully; let the other direction drain.
    Eof,
    /// Transport error — the stream is broken; the other direction must not
    /// keep running, or it silently blackholes data (see `proxy_quic`).
    Errored,
}

/// Bidirectional proxy between IPC socket and QUIC bi-stream.
///
/// Both directions run as independent tasks so a graceful close on one side
/// lets the other drain (a `select!` would cancel the reverse direction and
/// drop unread data).
///
/// But an ERROR is not a graceful close. If client→host dies on a broken QUIC
/// stream while host→client keeps running, the IPC socket stays open and the
/// client goes on writing input that nobody forwards: output still flows, no
/// error is reported, and the session silently accepts keystrokes that never
/// arrive — until the host's 75s read deadline reaps the attachment. That is
/// exactly the "session came back but I couldn't type for a minute" bug.
///
/// So: clean EOF drains the peer; an error aborts it, tearing the whole proxy
/// down so the client sees EOF and its reconnect logic engages immediately.
async fn proxy_quic(
    mut ipc_read: tokio::net::unix::OwnedReadHalf,
    mut ipc_write: tokio::net::unix::OwnedWriteHalf,
    mut quic_send: iroh::endpoint::SendStream,
    mut quic_recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    // Host→Client: copy QUIC data to IPC, flushing after each chunk to avoid
    // buffering delays on high-latency links.
    let mut h2c = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => break Ended::Eof,
                Ok(Some(n)) => {
                    if ipc_write.write_all(&buf[..n]).await.is_err() {
                        break Ended::Errored;
                    }
                    if ipc_write.flush().await.is_err() {
                        break Ended::Errored;
                    }
                }
                Err(e) => {
                    tracing::debug!("QUIC→IPC ended: {e:#}");
                    break Ended::Errored;
                }
            }
        }
    });

    // Client→Host: copy IPC data to QUIC, flushing after each chunk.
    let mut c2h = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let ended = loop {
            match ipc_read.read(&mut buf).await {
                Ok(0) => break Ended::Eof,
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break Ended::Errored;
                    }
                    if quic_send.flush().await.is_err() {
                        break Ended::Errored;
                    }
                }
                Err(e) => {
                    tracing::debug!("IPC→QUIC ended: {e:#}");
                    break Ended::Errored;
                }
            }
        };
        // FIN only on a clean close: after an error the stream is already
        // broken, and finishing it would mask the failure as an orderly EOF.
        if ended == Ended::Eof {
            let _ = quic_send.finish();
        }
        ended
    });

    // Whichever finishes first decides the other's fate.
    tokio::select! {
        r = &mut h2c => {
            if matches!(r, Ok(Ended::Errored)) {
                tracing::debug!("proxy: host→client errored — aborting client→host");
                c2h.abort();
            } else {
                let _ = c2h.await;
            }
        }
        r = &mut c2h => {
            if matches!(r, Ok(Ended::Errored)) {
                // The direction whose silent death caused the "can't type" bug.
                tracing::debug!("proxy: client→host errored — aborting host→client");
                h2c.abort();
            } else {
                let _ = h2c.await;
            }
        }
    }

    Ok(())
}

/// Generic bidirectional byte proxy between two async stream pairs.
///
/// A SIMPLIFIED double, not a mirror of [`proxy_quic`]: it uses `select!`, so
/// either direction completing cancels the other. Several tests below encode
/// that behaviour deliberately. For coverage of `proxy_quic`'s ACTUAL teardown
/// rules — clean EOF drains the peer, an error aborts it — see
/// [`proxy_pair_like_production`] and the tests that use it.
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

/// Faithful mirror of [`proxy_quic`]'s teardown logic over generic streams.
///
/// Kept byte-for-byte equivalent in STRUCTURE to the production function so the
/// rules that matter can be tested: a clean EOF lets the peer drain; a transport
/// ERROR aborts the peer so the whole proxy tears down. The production version
/// can't be tested directly because it takes concrete iroh stream types.
#[cfg(test)]
async fn proxy_pair_like_production(
    mut a_read: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut a_write: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    mut b_read: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut b_write: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
) -> Result<()> {
    async fn pump(
        r: &mut (impl tokio::io::AsyncRead + Unpin),
        w: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Ended {
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => return Ended::Eof,
                Ok(n) => {
                    if w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err() {
                        return Ended::Errored;
                    }
                }
                Err(_) => return Ended::Errored,
            }
        }
    }

    let mut a2b = tokio::spawn(async move { pump(&mut a_read, &mut b_write).await });
    let mut b2a = tokio::spawn(async move { pump(&mut b_read, &mut a_write).await });

    tokio::select! {
        r = &mut a2b => {
            if matches!(r, Ok(Ended::Errored)) { b2a.abort(); } else { let _ = b2a.await; }
        }
        r = &mut b2a => {
            if matches!(r, Ok(Ended::Errored)) { a2b.abort(); } else { let _ = a2b.await; }
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

/// Wire the "network changed → flush the connection pool" machinery for a mux
/// service and hand back the flush channel to give the netmon watchers.
///
/// Every mux host MUST install this — both the standalone agent and the host
/// daemon. A pool that is never flushed hands the next `hop connect` a pooled
/// connection whose path died with the old network; `open_bi` on it then stalls
/// until the QUIC idle timeout instead of re-dialing. That is not hypothetical:
/// the daemon's mux service originally shipped without this wiring, so once
/// client connects moved onto the daemon every dial after a laptop changed
/// networks stalled ~30s. Keeping it in ONE function is the point — the bug was
/// two copies of this setup drifting apart.
fn spawn_pool_flush_watchers(
    endpoint: Endpoint,
    handle: AgentHandle,
) -> tokio::sync::mpsc::Sender<()> {
    let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Sleep/wake: carrying the laptop to a new network is the #1 cause of a
    // stale path. A wake almost always means the old path is dead, so force
    // re-discovery AND flush — flushing alone leaves iroh's endpoint pointed at
    // the old network until its own netwatch catches up.
    let wake_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            let before = std::time::Instant::now();
            tokio::time::sleep(Duration::from_secs(3)).await;
            if before.elapsed() > Duration::from_secs(10) {
                tracing::info!("Detected sleep/wake, forcing re-discovery + flushing pool");
                endpoint.network_change().await;
                wake_handle.flush_all().await;
            }
        }
    });

    tokio::spawn(async move {
        while flush_rx.recv().await.is_some() {
            tracing::info!("Flushing mux connection pool after network change");
            handle.flush_all().await;
        }
    });

    flush_tx
}

/// Bind a mux IPC socket on `sock_path` and serve `MuxConnect` requests using
/// `endpoint`. Used by the host daemon: a machine running `hop host` serves
/// client connects (`hop connect`) through ITS single endpoint instead of
/// letting the client spawn a *second* endpoint under the same node-id, which
/// the relay prunes against the daemon every few seconds (the identity
/// collision). Additive + defensive: a bind failure is returned to the caller
/// (the daemon logs and continues — the mux is a convenience, never
/// load-bearing for the daemon's own VPN/inbound roles).
///
/// Returns the pool-flush channel: the caller MUST hand it to the netmon
/// watchers, or the pool it serves is never flushed on a network change.
pub fn spawn_mux_listener(
    endpoint: Endpoint,
    sock_paths: &[std::path::PathBuf],
) -> Result<tokio::sync::mpsc::Sender<()>> {
    let mut listeners = Vec::new();
    for sock_path in sock_paths {
        if sock_path.exists() {
            let _ = std::fs::remove_file(sock_path);
        }
        let listener = UnixListener::bind(sock_path)
            .with_context(|| format!("bind mux socket {}", sock_path.display()))?;
        // Local-trust: let the logged-in user's `hop connect` reach the daemon's
        // socket (the daemon may run as _hop/root). Single-user posture; multi-user
        // hosts should group-scope this rather than world-rw (tracked follow-up).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o666));
        }
        tracing::info!("daemon mux service listening on {}", sock_path.display());
        listeners.push(listener);
    }
    // One actor (one pool, one probe per connection) behind every socket.
    let handle = spawn_agent_actor(endpoint.clone());
    let flush_tx = spawn_pool_flush_watchers(endpoint, handle.clone());
    let active_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for listener in listeners {
        let handle = handle.clone();
        let active_sessions = active_sessions.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let h = handle.clone();
                        let sessions = active_sessions.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, h, sessions).await {
                                tracing::debug!("daemon mux client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("daemon mux accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
    Ok(flush_tx)
}

async fn run_agent(config_dir: &Path, daemon: bool, reload_handle: ReloadHandle) -> Result<()> {
    let sock_path = mux::agent_sock_path(config_dir);
    let pid_path = mux::agent_pid_path(config_dir);

    // A socket that still answers belongs to a live agent or to the host
    // daemon's mux service: do not unlink it from under them. That made a
    // second agent orphan the first (still holding its connections and
    // probes), and an agent steal the daemon's mux socket when both serve the
    // same config dir. Only a socket nobody answers on is stale.
    if sock_path.exists() {
        if UnixStream::connect(&sock_path).await.is_ok() {
            if !daemon {
                eprintln!("An agent (or the host daemon) is already serving {}", sock_path.display());
            }
            tracing::info!(
                "agent: {} is already served; not starting a second agent",
                sock_path.display()
            );
            return Ok(());
        }
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

    // Set up signal handlers: graceful shutdown + SIGUSR1 debug toggle
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("failed to register SIGINT handler")?;
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("failed to register SIGUSR1 handler")?;
    let mut debug_enabled = false;
    let mut yield_check = tokio::time::interval(Duration::from_secs(5));
    yield_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let secret_key = config::load_or_generate_identity(config_dir)?;
    let endpoint = net::create_client_endpoint(secret_key).await?;
    let _ = std::fs::remove_file(agent_health_path(config_dir));
    let _ = AGENT_HEALTH_PATH.set(agent_health_path(config_dir));
    let handle = spawn_agent_actor(endpoint.clone());
    let active_sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    tracing::info!("Agent started (PID {})", std::process::id());

    // Network-change → pool-flush wiring. Shared with the daemon's mux service
    // (`spawn_mux_listener`) so the two can never drift apart again.
    let flush_tx = spawn_pool_flush_watchers(endpoint.clone(), handle.clone());

    // Interface-address watcher (calls network_change internally on change).
    let _netmon = net::netmon::spawn_interface_watcher(endpoint.clone(), Some(flush_tx.clone()));
    // Relay-health watcher: catches a dead path when the local interface address
    // looks unchanged — same DHCP range or carried while asleep — which the
    // interface watcher cannot see. This is the gap that made a network move
    // strand the agent on a dead pooled connection.
    let _relay_health = net::netmon::spawn_relay_health_watcher(endpoint.clone(), Some(flush_tx));

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
            _ = sigusr1.recv() => {
                debug_enabled = !debug_enabled;
                let new_filter = if debug_enabled {
                    tracing::info!("Agent debug logging ENABLED (send SIGUSR1 again to disable)");
                    "hop=debug,hop_core=debug,iroh=debug,iroh_relay=debug"
                        .parse::<Targets>().expect("valid directives")
                } else {
                    tracing::info!("Agent debug logging DISABLED (back to info level)");
                    "hop=info,hop_core=info".parse::<Targets>().expect("valid directives")
                };
                if let Err(e) = reload_handle.reload(new_filter) {
                    tracing::error!("Failed to reload log filter: {e}");
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
            _ = yield_check.tick() => {
                // A host daemon now serves this config dir: its mux is the one
                // endpoint for this node id, and clients prefer it. A user agent
                // beside it is a second endpoint (one the relay prunes against
                // the daemon); bow out once nothing is using us. Covers an agent
                // a client started a moment before the daemon came up.
                if active_sessions.load(std::sync::atomic::Ordering::Relaxed) == 0
                    && UnixStream::connect(mux::daemon_mux_sock_path(config_dir)).await.is_ok()
                {
                    tracing::info!("Host daemon serves this config dir; user agent exiting");
                    break;
                }
            }
        }
    }

    // Cleanup: flush all pooled connections, then close the endpoint
    handle.flush_all().await;
    drop(handle);
    endpoint.close().await;
    // Remove our socket and PID file — only if they are still ours. Another
    // agent may have bound `agent.sock` or written `agent.pid` since; removing
    // those unconditionally left that agent running on an unlinked socket
    // (alive, holding an endpoint, unreachable).
    drop(listener);
    if UnixStream::connect(&sock_path).await.is_err() {
        let _ = std::fs::remove_file(&sock_path);
    }
    let ours = std::fs::read_to_string(&pid_path)
        .map(|p| p.trim() == std::process::id().to_string())
        .unwrap_or(false);
    if ours {
        let _ = std::fs::remove_file(&pid_path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    /// A local hop/4 "host" that answers `Ping` on every stream, as the real
    /// host does (`hop-cli/src/main.rs`, before session dispatch).
    async fn ping_host() -> iroh::Endpoint {
        use hop_core::proto::{self, ClientMessage, HostMessage};
        let host = iroh::endpoint::Builder::empty()
            .alpns(vec![hop_core::proto::ALPN_V4.to_vec()])
            .bind()
            .await
            .unwrap();
        let h = host.clone();
        tokio::spawn(async move {
            while let Some(incoming) = h.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            if let Ok(ClientMessage::Ping) = proto::read_message(&mut recv).await {
                                let _ = proto::write_message(&mut send, &HostMessage::Pong).await;
                                let _ = send.finish();
                            }
                        });
                    }
                });
            }
        });
        host
    }

    /// The quality probe's swap: only the connection it measured may be
    /// replaced, the replacement is what the pool hands out next, and the
    /// degraded one is closed so its sessions resume on the new one.
    #[tokio::test]
    async fn replace_connection_swaps_only_the_measured_connection() {
        let host = ping_host().await;
        let client = iroh::endpoint::Builder::empty().bind().await.unwrap();
        let host_id = host.id();
        let alpn = hop_core::proto::ALPN_V4;
        let old = client.connect(host.addr(), alpn).await.unwrap();
        let new = client.connect(host.addr(), alpn).await.unwrap();
        let stranger = client.connect(host.addr(), alpn).await.unwrap();

        let handle = spawn_agent_actor(client.clone());
        handle
            .tx
            .send(AgentCommand::ConnectDone { host_id, result: Ok(old.clone()) })
            .await
            .unwrap();

        // Not the pooled connection: refused, pool untouched.
        assert!(!handle.replace_connection(host_id, stranger.stable_id(), new.clone()).await);
        let (pooled, _, _) = handle.get_connection(host_id, None).await.unwrap();
        assert_eq!(pooled.stable_id(), old.stable_id());

        // The measured one: swapped, and the old one is closed.
        assert!(handle.replace_connection(host_id, old.stable_id(), new.clone()).await);
        let (pooled, _, needs_check) = handle.get_connection(host_id, None).await.unwrap();
        assert_eq!(pooled.stable_id(), new.stable_id());
        assert!(!needs_check, "a replacement was just pinged; no second check");
        tokio::time::timeout(Duration::from_secs(5), old.closed()).await.unwrap();

        // And the replacement carries stream data.
        check_pooled_liveness(&pooled).await.unwrap();
    }

    /// A network-change flush must not close a connection dialed moments ago:
    /// it is already on the current network, and closing it dropped sessions
    /// 2-3 s after every reconnect (net_flap's 30 s outliers).
    #[tokio::test]
    async fn flush_spares_a_freshly_dialed_connection() {
        let host = ping_host().await;
        let client = iroh::endpoint::Builder::empty().bind().await.unwrap();
        let conn = client.connect(host.addr(), hop_core::proto::ALPN_V4).await.unwrap();
        let handle = spawn_agent_actor(client.clone());
        handle
            .tx
            .send(AgentCommand::ConnectDone { host_id: host.id(), result: Ok(conn.clone()) })
            .await
            .unwrap();
        handle.flush_all().await;
        let (pooled, _, _) = handle.get_connection(host.id(), None).await.unwrap();
        assert_eq!(pooled.stable_id(), conn.stable_id());
        assert!(conn.close_reason().is_none());
    }

    #[test]
    fn only_an_alpn_refusal_steps_the_protocol_down() {
        use super::{is_alpn_rejection, is_dial_timeout};
        let refused = anyhow::anyhow!(
            "Failed to connect to host: aborted by peer: the cryptographic handshake failed: error 120: peer doesn't support any known protocol"
        );
        assert!(is_alpn_rejection(&refused));
        let aborted = anyhow::anyhow!(
            "Failed to connect to host: aborted by peer: the application or application protocol caused the connection to be closed during the handshake"
        );
        assert!(!is_alpn_rejection(&aborted));
        let timed_out = anyhow::anyhow!("Connection timed out after 10s. The host may be offline");
        assert!(!is_alpn_rejection(&timed_out));
        assert!(is_dial_timeout(&timed_out));
    }

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

    // Regression: two concurrent `hop connect` sessions to one host share a single
    // pooled connection. A reconnect's evict_first must NOT close that connection
    // while another session is live, or the two sessions mutually evict each other
    // in an endless reconnect loop. Eviction is allowed only once the host is idle.
    #[test]
    fn eviction_gated_by_live_sessions() {
        let host = iroh::SecretKey::from_bytes(&[1u8; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[2u8; 32]).public();
        let mut active = HashMap::new();

        // No sessions yet: an idle/stale pooled connection may be evicted.
        assert!(may_evict(&active, &host));

        // Two sessions to `host` come up (they multiplex over one connection).
        session_inc(&mut active, host);
        session_inc(&mut active, host);
        assert_eq!(active.get(&host).copied(), Some(2));
        // A reconnect on either session must not evict the in-use connection.
        assert!(!may_evict(&active, &host));

        // A different host is unaffected — its idle connection can still be evicted.
        assert!(may_evict(&active, &other));

        // One session ends; the other is still live, so eviction stays blocked.
        session_dec(&mut active, &host);
        assert_eq!(active.get(&host).copied(), Some(1));
        assert!(!may_evict(&active, &host));

        // Last session ends: the host is idle and the entry is cleared, so a
        // genuinely stale pooled connection may now be evicted on reconnect.
        session_dec(&mut active, &host);
        assert!(!active.contains_key(&host));
        assert!(may_evict(&active, &host));

        // Decrementing an already-absent host is a no-op (no underflow panic).
        session_dec(&mut active, &host);
        assert!(may_evict(&active, &host));
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
            evict_first: false,
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
                        evict_first: false,
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

    /// THE regression test for "session came back but I couldn't type".
    ///
    /// When one proxy direction dies on a transport ERROR, the other MUST NOT
    /// keep running. It used to: host→client went on delivering output while
    /// client→host was dead, so the IPC socket stayed open, the client's
    /// keystrokes went into a socket nobody read, and no error surfaced — the
    /// session looked alive (output flowing) but accepted no input until the
    /// host's 75s read deadline reaped it.
    ///
    /// Note the setup: dropping the host end alone yields a clean EOF, not an
    /// error. To hit the error path the proxy must actually WRITE to the dead
    /// side, so the client sends a byte after the host is gone.
    #[tokio::test]
    async fn errored_direction_tears_down_the_whole_proxy() {
        let (mut a_client, a_proxy) = tokio::io::duplex(4096);
        let (b_proxy, b_host) = tokio::io::duplex(4096);
        let (a_proxy_r, a_proxy_w) = tokio::io::split(a_proxy);
        let (b_proxy_r, b_proxy_w) = tokio::io::split(b_proxy);

        let proxy = tokio::spawn(async move {
            proxy_pair_like_production(a_proxy_r, a_proxy_w, b_proxy_r, b_proxy_w).await
        });

        // Host is gone; the client keeps typing (exactly the reported case).
        drop(b_host);
        let _ = a_client.write_all(b"keystrokes").await;
        let _ = a_client.flush().await;

        // The proxy must tear down rather than sit half-alive forever.
        tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .expect("proxy did not tear down after a direction errored — input would be blackholed")
            .expect("proxy task panicked")
            .expect("proxy returned an error");

        // And the client must observe EOF, so its reconnect logic engages
        // instead of writing into a black hole.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), a_client.read(&mut buf))
            .await
            .expect("client socket never closed — the bug")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF on the client side after proxy teardown");
    }

    /// A CLEAN eof on one side must still let the other drain — the property
    /// the error-abort path must not regress.
    #[tokio::test]
    async fn clean_eof_still_drains_the_peer() {
        let (mut a_client, a_proxy) = tokio::io::duplex(4096);
        let (b_proxy, mut b_host) = tokio::io::duplex(4096);
        let (a_proxy_r, a_proxy_w) = tokio::io::split(a_proxy);
        let (b_proxy_r, b_proxy_w) = tokio::io::split(b_proxy);

        let proxy = tokio::spawn(async move {
            proxy_pair_like_production(a_proxy_r, a_proxy_w, b_proxy_r, b_proxy_w).await
        });

        a_client.write_all(b"hello").await.unwrap();
        a_client.flush().await.unwrap();

        let mut buf = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(5), b_host.read_exact(&mut buf))
            .await
            .expect("host never received the payload")
            .unwrap();
        assert_eq!(&buf, b"hello");

        // Close BOTH ends so the drain can complete: a clean EOF on one side
        // deliberately waits for the peer, which is the property under test.
        drop(a_client);
        drop(b_host);
        tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .expect("clean-EOF path did not complete")
            .expect("proxy task panicked")
            .expect("proxy returned an error");
    }
}
