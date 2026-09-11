//! Host-side reachability watchdog.
//!
//! Everything the daemon already watched (interface addresses, relay HTTPS)
//! proves the relay is *up*, not that this host is *reachable through it*. In
//! the 2026-09-11 incident every host-side check passed for an hour while no
//! inbound connection arrived. This module closes that gap:
//!
//! - [`note_inbound_ok`] / [`last_inbound_ok`]: the accept path records every
//!   completed inbound handshake, so "when did someone last reach us" is a
//!   question with an answer.
//! - [`spawn_inbound_probe`]: every few minutes, if nothing real has arrived
//!   recently, dial *ourselves* through the home relay from a throwaway endpoint
//!   (fresh random key, relay-only, no discovery) using [`ALPN_PROBE`]. A
//!   completed QUIC handshake proves the whole inbound path: relay session,
//!   relay forwarding, our endpoint, our accept loop. Consecutive failures
//!   escalate: force iroh re-discovery, then ask the daemon to restart itself.
//! - [`request_restart`]: the one restart channel, shared by the probe and the
//!   operator's `hop recover` over the daemon socket. The host installs a sender
//!   with [`install_restart_handle`]; the accept loop exits cleanly on receipt
//!   and the supervisor (privsep monitor, launchd `KeepAlive`, systemd
//!   `Restart=`) brings a fresh daemon up with a rebound endpoint.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode};

use crate::proto::ALPN_PROBE;

// ── Inbound bookkeeping ──────────────────────────────────────────────────────

/// Unix ms of the last completed inbound QUIC handshake (0 = never).
static LAST_INBOUND_OK_MS: AtomicU64 = AtomicU64::new(0);
/// Monotonic instant of the same, for elapsed() without clock skew.
static LAST_INBOUND_OK: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
static HANDSHAKES_OK: AtomicU64 = AtomicU64::new(0);
static HANDSHAKES_ABORTED: AtomicU64 = AtomicU64::new(0);
static HANDSHAKES_TIMED_OUT: AtomicU64 = AtomicU64::new(0);

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record a completed inbound QUIC handshake (any ALPN, including the probe's).
pub fn note_inbound_ok() {
    HANDSHAKES_OK.fetch_add(1, Ordering::Relaxed);
    LAST_INBOUND_OK_MS.store(unix_now_ms(), Ordering::Relaxed);
    if let Ok(mut g) = LAST_INBOUND_OK.lock() {
        *g = Some(Instant::now());
    }
}

/// Record an inbound handshake the peer abandoned (closed during the handshake).
pub fn note_inbound_aborted() {
    HANDSHAKES_ABORTED.fetch_add(1, Ordering::Relaxed);
}

/// Record an inbound connection that completed QUIC but never finished the
/// application handshake within the deadline.
pub fn note_inbound_timed_out() {
    HANDSHAKES_TIMED_OUT.fetch_add(1, Ordering::Relaxed);
}

/// How long since the last completed inbound handshake, if any.
pub fn last_inbound_ok() -> Option<Duration> {
    LAST_INBOUND_OK.lock().ok().and_then(|g| g.map(|t| t.elapsed()))
}

/// Snapshot of the inbound counters: `(ok, aborted, timed_out, last_ok_unix_ms)`.
pub fn inbound_counters() -> (u64, u64, u64, u64) {
    (
        HANDSHAKES_OK.load(Ordering::Relaxed),
        HANDSHAKES_ABORTED.load(Ordering::Relaxed),
        HANDSHAKES_TIMED_OUT.load(Ordering::Relaxed),
        LAST_INBOUND_OK_MS.load(Ordering::Relaxed),
    )
}

// ── Self-restart ─────────────────────────────────────────────────────────────

static RESTART: OnceLock<tokio::sync::mpsc::Sender<String>> = OnceLock::new();

/// Install the daemon's restart channel. The host's accept loop owns the
/// receiver; the first message ends the loop cleanly (sessions checkpointed).
/// Idempotent — a second install is ignored.
pub fn install_restart_handle(tx: tokio::sync::mpsc::Sender<String>) {
    let _ = RESTART.set(tx);
}

/// Ask the running daemon to restart itself, giving `reason` for the log.
/// Returns `false` when no restart handle is installed (not a host, or a
/// restart is already in flight — the channel holds one message).
pub fn request_restart(reason: &str) -> bool {
    match RESTART.get() {
        Some(tx) => tx.try_send(reason.to_string()).is_ok(),
        None => false,
    }
}

// ── Inbound liveness probe ───────────────────────────────────────────────────

/// How often the probe considers dialing. Real inbound traffic within this
/// window makes the probe skip a round (it has already been proven).
/// `HOP_INBOUND_PROBE_SECS` overrides it (and the initial delay) for tests
/// and for an operator who wants a faster verdict.
const PROBE_INTERVAL: Duration = Duration::from_secs(300);
/// Let the endpoint, relay session and discovery settle after startup first.
const PROBE_INITIAL_DELAY: Duration = Duration::from_secs(120);

fn probe_interval() -> Duration {
    std::env::var("HOP_INBOUND_PROBE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|s| *s >= 10)
        .map(Duration::from_secs)
        .unwrap_or(PROBE_INTERVAL)
}

fn probe_initial_delay() -> Duration {
    if std::env::var_os("HOP_INBOUND_PROBE_SECS").is_some() {
        probe_interval()
    } else {
        PROBE_INITIAL_DELAY
    }
}
/// Budget for the throwaway endpoint to reach the relay.
const PROBE_ONLINE_TIMEOUT: Duration = Duration::from_secs(15);
/// Budget for the self-dial's QUIC handshake. Generous: a host swapped out
/// under memory pressure answers late, and a late answer is not "unreachable".
const PROBE_DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for the relay-reachability precondition (HTTPS to the relay).
const RELAY_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive probe failures before forcing iroh re-discovery.
const REDISCOVER_AFTER: u32 = 2;
/// Consecutive probe failures before asking the daemon to restart itself
/// (4 × 5 min = 20 min of provable unreachability through a reachable relay).
const RESTART_AFTER: u32 = 4;

/// Why one probe round did not count as a success.
enum ProbeSkip {
    /// No home relay yet (offline or still bootstrapping) — nothing to prove.
    NoRelay,
    /// The relay itself does not answer HTTPS; that is the relay watcher's
    /// problem, and a restart would not help.
    RelayDown(String),
}

/// Spawn the inbound-liveness watchdog for `endpoint` (the host's shell
/// endpoint, identity `host_id`).
pub fn spawn_inbound_probe(endpoint: Endpoint, host_id: PublicKey) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = probe_interval();
        tokio::time::sleep(probe_initial_delay()).await;
        let http = reqwest::Client::builder().timeout(RELAY_CHECK_TIMEOUT).build().ok();
        let mut failures: u32 = 0;
        let mut successes: u64 = 0;
        tracing::info!(
            "Inbound liveness probe started (every {}s; re-discovery after {} failures, self-restart after {})",
            interval.as_secs(),
            REDISCOVER_AFTER,
            RESTART_AFTER
        );
        loop {
            // Real traffic proves reachability better than a synthetic dial.
            if let Some(age) = last_inbound_ok()
                && age < interval
            {
                failures = 0;
                tokio::time::sleep(interval - age).await;
                continue;
            }

            match probe_once(&endpoint, host_id, http.as_ref()).await {
                Ok(Ok(elapsed)) => {
                    successes += 1;
                    if failures > 0 {
                        tracing::info!(
                            "Inbound probe succeeded again after {failures} failure(s) ({} ms)",
                            elapsed.as_millis()
                        );
                    } else if successes == 1 {
                        tracing::info!(
                            "Inbound probe ok: this host is reachable through its relay ({} ms)",
                            elapsed.as_millis()
                        );
                    } else {
                        tracing::debug!("Inbound probe ok ({} ms)", elapsed.as_millis());
                    }
                    failures = 0;
                }
                Ok(Err(ProbeSkip::NoRelay)) => {
                    tracing::debug!("Inbound probe skipped: no home relay");
                }
                Ok(Err(ProbeSkip::RelayDown(e))) => {
                    tracing::warn!("Inbound probe skipped: relay not reachable over HTTPS ({e}); not counted");
                }
                Err(e) => {
                    failures += 1;
                    let (ok, aborted, timed_out, _) = inbound_counters();
                    tracing::error!(
                        "Inbound probe FAILED ({failures} in a row): this host did not answer a dial to \
                         itself through its relay: {e:#} (lifetime handshakes ok={ok} aborted={aborted} \
                         timed_out={timed_out})"
                    );
                    if failures == REDISCOVER_AFTER {
                        tracing::error!("Forcing iroh re-discovery after {failures} consecutive inbound probe failures");
                        endpoint.network_change().await;
                    }
                    if failures >= RESTART_AFTER {
                        let reason = format!(
                            "inbound liveness probe failed {failures}× in a row ({} min) while the relay \
                             answered HTTPS — endpoint presumed wedged",
                            (failures as u64) * interval.as_secs() / 60
                        );
                        if request_restart(&reason) {
                            tracing::error!("Requesting daemon self-restart: {reason}");
                            return;
                        }
                        tracing::error!("Self-restart unavailable (no restart handle); will keep probing");
                        failures = 0;
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// One probe round. `Ok(Ok(elapsed))`: reachable. `Ok(Err(skip))`: could not be
/// judged (does not count). `Err(e)`: the relay is fine but we are not reachable
/// through it.
async fn probe_once(
    endpoint: &Endpoint,
    host_id: PublicKey,
    http: Option<&reqwest::Client>,
) -> anyhow::Result<Result<Duration, ProbeSkip>> {
    let Some(relay) = endpoint.addr().relay_urls().next().cloned() else {
        return Ok(Err(ProbeSkip::NoRelay));
    };

    // Precondition: the relay answers HTTPS at all. Any HTTP status counts
    // (iroh-relay 404s unknown paths); only a connection-level error means down.
    if let Some(client) = http {
        let url = format!("{}generate_204", relay.as_str());
        if let Err(e) = client.get(&url).send().await {
            return Ok(Err(ProbeSkip::RelayDown(e.to_string())));
        }
    }

    let started = Instant::now();
    // Throwaway identity: relay-only, no address lookup, no mDNS, so the dial
    // can only succeed the way a remote client's would — through the relay.
    let probe_ep = Endpoint::empty_builder()
        .relay_mode(RelayMode::custom([relay.clone()]))
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("bind probe endpoint: {e}"))?;
    let result = async {
        if tokio::time::timeout(PROBE_ONLINE_TIMEOUT, probe_ep.online()).await.is_err() {
            anyhow::bail!(
                "probe endpoint could not reach relay {relay} within {}s",
                PROBE_ONLINE_TIMEOUT.as_secs()
            );
        }
        let addr = EndpointAddr::from(host_id).with_relay_url(relay.clone());
        let conn = tokio::time::timeout(PROBE_DIAL_TIMEOUT, probe_ep.connect(addr, ALPN_PROBE))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "self-dial via {relay} did not complete a QUIC handshake within {}s",
                    PROBE_DIAL_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| anyhow::anyhow!("self-dial via {relay} failed: {e}"))?;
        conn.close(0u32.into(), b"probe");
        Ok(started.elapsed())
    }
    .await;
    probe_ep.close().await;
    result.map(Ok)
}
