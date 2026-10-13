//! Process-wide health registry (Phase 1 of `docs/technical/self-healing.md`).
//!
//! Records, per component, when it last did real work and how it last failed,
//! so a failure that the data plane would otherwise absorb silently (the
//! 2026-10-12 VPN: weeks of dials failing at `debug` level, counted only as
//! "no route") is visible in the log and over the daemon socket.
//!
//! The snapshot crosses the daemon socket as **JSON** inside
//! `DsResponse::Health`, not as a bincode struct: bincode cannot tolerate an
//! appended field, and this registry is meant to grow (agent connections,
//! netdoc probe, relay) while a newer CLI still talks to an older daemon.

use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// While a peer keeps failing, repeat the WARN at most this often.
const DIAL_WARN_EVERY: Duration = Duration::from_secs(300);

/// Process-global registry. One instance, read by [`snapshot`].
static HEALTH: LazyLock<Mutex<Registry>> = LazyLock::new(Default::default);

#[derive(Default)]
struct Registry {
    vpn_dial_ok: u64,
    vpn_dial_failed: u64,
    vpn_peers: HashMap<String, PeerDial>,
    agent_conns: HashMap<String, AgentConnSnapshot>,
    agent_replacements: u64,
    vpn_probes: HashMap<String, VpnProbeSnapshot>,
    vpn_ladder: Option<String>,
    /// (Unix ms, resident bytes), oldest first; at most `RSS_SAMPLES`.
    rss: std::collections::VecDeque<(u64, u64)>,
}

/// 24 h of 5-minute resident-memory samples.
const RSS_SAMPLES: usize = 288;

#[derive(Default)]
struct PeerDial {
    consecutive_failures: u64,
    total_failures: u64,
    last_error: Option<String>,
    last_failure_ms: Option<u64>,
    last_success_ms: Option<u64>,
    /// Wall-clock start of the current failure streak.
    failing_since_ms: Option<u64>,
    /// Monotonic start of the current failure streak, for its duration.
    failing_since: Option<Instant>,
    last_warn: Option<Instant>,
}

/// What [`snapshot`] returns, serialized as JSON for the daemon socket.
/// Fields may be appended freely; readers must ignore unknown ones.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HealthSnapshot {
    #[serde(default)]
    pub vpn_dial_ok: u64,
    #[serde(default)]
    pub vpn_dial_failed: u64,
    /// Per peer VPN endpoint (short id), sorted for stable output.
    #[serde(default)]
    pub vpn_peers: BTreeMap<String, PeerDialSnapshot>,
    /// Client agent: per host (short id), its pooled connection's quality.
    #[serde(default)]
    pub agent_conns: BTreeMap<String, AgentConnSnapshot>,
    /// Client agent: degraded connections replaced since the agent started.
    #[serde(default)]
    pub agent_replacements: u64,
    /// VPN peer probe: per peer node (short id), the last round's result.
    #[serde(default)]
    pub vpn_probes: BTreeMap<String, VpnProbeSnapshot>,
    /// VPN peer probe: the escalation ladder's state, human-readable.
    #[serde(default)]
    pub vpn_ladder: Option<String>,
    /// Host endpoint: completed / aborted / timed-out inbound handshakes since
    /// start, and when the last one completed (Unix ms, 0 = never). From
    /// `net::health`; the inbound probe counts as one.
    #[serde(default)]
    pub inbound_ok: u64,
    #[serde(default)]
    pub inbound_aborted: u64,
    #[serde(default)]
    pub inbound_timed_out: u64,
    #[serde(default)]
    pub inbound_last_ok_ms: u64,
    /// This process's resident memory at the last sample (MB).
    #[serde(default)]
    pub rss_mb: Option<f64>,
    /// Least-squares growth of resident memory over the sampled window (MB/h),
    /// and how many hours that window covers. A leak shows as a steady slope
    /// (the 2026-09 iroh-docs actor leak was ~65 MB/h); one-off work as steps.
    #[serde(default)]
    pub rss_slope_mb_per_hour: Option<f64>,
    #[serde(default)]
    pub rss_window_hours: Option<f64>,
    /// Warren (netdoc) entries refused because their timestamp was more than
    /// ten minutes ahead of this node's clock: this clock is behind, or the
    /// author's is ahead. Also the largest lead seen (s) and this node's clock
    /// (Unix ms) at the latest refusal.
    #[serde(default)]
    pub netdoc_future_refused: u64,
    #[serde(default)]
    pub netdoc_future_max_lead_secs: u64,
    #[serde(default)]
    pub netdoc_future_last_ms: u64,
}

/// One peer in the last VPN probe round.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VpnProbeSnapshot {
    /// Its VPN traffic was fresh, so it was not dialed.
    #[serde(default)]
    pub fresh: bool,
    /// Its host endpoint answered a `hop/probe/1` dial (it is up).
    #[serde(default)]
    pub host_ok: Option<bool>,
    /// Its VPN endpoint accepted a `hop/vpn/1` dial.
    #[serde(default)]
    pub vpn_ok: Option<bool>,
    #[serde(default)]
    pub at_ms: Option<u64>,
}

/// One pooled agent connection, as its quality probe last saw it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentConnSnapshot {
    #[serde(default)]
    pub last_rtt_ms: Option<u64>,
    #[serde(default)]
    pub baseline_ms: Option<u64>,
    #[serde(default)]
    pub on_relay: Option<bool>,
    /// Bad probes in a row (unanswered, slow vs baseline, or stuck on relay).
    #[serde(default)]
    pub consecutive_bad: u32,
    /// `Good`, `Unanswered`, `Slow`, `StuckOnRelay`.
    #[serde(default)]
    pub last_verdict: Option<String>,
    #[serde(default)]
    pub last_probe_ms: Option<u64>,
    /// The last replace decision for this host, human-readable.
    #[serde(default)]
    pub last_event: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerDialSnapshot {
    #[serde(default)]
    pub consecutive_failures: u64,
    #[serde(default)]
    pub total_failures: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_failure_ms: Option<u64>,
    #[serde(default)]
    pub last_success_ms: Option<u64>,
    #[serde(default)]
    pub failing_since_ms: Option<u64>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A VPN dial to `peer` completed. Logs the recovery if it ends a failure streak.
pub fn note_vpn_dial_ok(peer: &str) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    reg.vpn_dial_ok += 1;
    let p = reg.vpn_peers.entry(peer.to_string()).or_default();
    if p.consecutive_failures > 0 {
        let lasted = p.failing_since.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        tracing::info!(
            "vpn: dial to {peer} recovered after {} failed attempt(s) over {lasted}s",
            p.consecutive_failures
        );
    }
    p.consecutive_failures = 0;
    p.failing_since = None;
    p.failing_since_ms = None;
    p.last_warn = None;
    p.last_success_ms = Some(now_ms());
}

/// A VPN dial to `peer` failed with `err`. WARNs on the first failure of a
/// streak and then at most every [`DIAL_WARN_EVERY`] while it continues, so a
/// peer that stays unreachable is in the log without flooding it (the
/// forwarder redials every few seconds while traffic is queued).
pub fn note_vpn_dial_failed(peer: &str, err: &str) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    reg.vpn_dial_failed += 1;
    let p = reg.vpn_peers.entry(peer.to_string()).or_default();
    let now = Instant::now();
    p.consecutive_failures += 1;
    p.total_failures += 1;
    p.last_error = Some(err.to_string());
    p.last_failure_ms = Some(now_ms());
    if p.failing_since.is_none() {
        p.failing_since = Some(now);
        p.failing_since_ms = p.last_failure_ms;
    }
    let due = p.last_warn.is_none_or(|t| now.duration_since(t) >= DIAL_WARN_EVERY);
    if due {
        p.last_warn = Some(now);
        let lasted = p.failing_since.map(|t| now.duration_since(t).as_secs()).unwrap_or(0);
        tracing::warn!(
            "vpn: dial to {peer} failed ({} in a row, failing for {lasted}s): {err}",
            p.consecutive_failures
        );
    }
}

/// The agent's quality probe for `host` reports its latest state.
pub fn note_agent_conn(host: &str, mut conn: AgentConnSnapshot) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    conn.last_probe_ms = Some(now_ms());
    let prev_event = reg.agent_conns.get(host).and_then(|c| c.last_event.clone());
    if conn.last_event.is_none() {
        conn.last_event = prev_event;
    }
    reg.agent_conns.insert(host.to_string(), conn);
}

/// The agent replaced (or declined to replace) `host`'s connection.
pub fn note_agent_event(host: &str, event: String, replaced: bool) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    if replaced {
        reg.agent_replacements += 1;
    }
    reg.agent_conns.entry(host.to_string()).or_default().last_event = Some(event);
}

/// The VPN peer probe's result for `peer` this round.
pub fn note_vpn_probe(peer: &str, mut probe: VpnProbeSnapshot) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    probe.at_ms = Some(now_ms());
    reg.vpn_probes.insert(peer.to_string(), probe);
}

/// The VPN escalation ladder's state after a round.
pub fn note_vpn_ladder(state: String) {
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    reg.vpn_ladder = Some(state);
}

/// Test-only fault: while the file named by `HOP_FAULT_VPN_WEDGE_FILE` exists,
/// this node's outbound VPN dials fail — "this node's VPN endpoint is broken,
/// its host endpoint fine", the 2026-10-12 member. The worker deletes the file
/// when it starts, so a restart "fixes" it, as a fresh endpoint did that day.
/// Inert unless the variable is set (`tests/e2e/vpn-e2e.sh`).
pub fn fault_vpn_wedged() -> bool {
    std::env::var_os("HOP_FAULT_VPN_WEDGE_FILE")
        .is_some_and(|p| std::path::Path::new(&p).exists())
}

/// Clear the VPN wedge fault (worker start).
pub fn clear_fault_vpn_wedge() {
    if let Some(p) = std::env::var_os("HOP_FAULT_VPN_WEDGE_FILE") {
        let _ = std::fs::remove_file(p);
    }
}

/// This process's resident set size in bytes, if the platform tells us.
pub fn resident_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: u64 = status
            .lines()
            .find(|l| l.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info.pti_resident_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Milliseconds on a monotonic clock (since first use). The RSS trend is timed
/// with it, not wall time: a device that boots at 1970 and then syncs its clock,
/// or an NTP step, would otherwise stretch, squash or invert the slope.
fn mono_ms() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_millis() as u64
}

/// Record a resident-memory sample (the daemon calls this every 5 minutes).
pub fn sample_rss() {
    let Some(bytes) = resident_bytes() else { return };
    let mut reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    reg.rss.push_back((mono_ms(), bytes));
    while reg.rss.len() > RSS_SAMPLES {
        reg.rss.pop_front();
    }
}

/// Least-squares slope of `samples` (monotonic ms, bytes) in MB/h, and the hours it
/// spans. `None` with fewer than 3 samples or no time span.
pub fn rss_slope(samples: &[(u64, u64)]) -> Option<(f64, f64)> {
    if samples.len() < 3 {
        return None;
    }
    let t0 = samples[0].0 as f64;
    let xs: Vec<f64> = samples.iter().map(|(t, _)| (*t as f64 - t0) / 3_600_000.0).collect();
    let ys: Vec<f64> = samples.iter().map(|(_, b)| *b as f64 / 1_048_576.0).collect();
    let n = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let sxx: f64 = xs.iter().map(|x| (x - mx) * (x - mx)).sum();
    if sxx <= 0.0 {
        return None;
    }
    let sxy: f64 = xs.iter().zip(&ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    Some((sxy / sxx, xs.last().copied().unwrap_or(0.0)))
}

/// A copy of the registry at one instant.
pub fn snapshot() -> HealthSnapshot {
    let reg = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    HealthSnapshot {
        vpn_dial_ok: reg.vpn_dial_ok,
        vpn_dial_failed: reg.vpn_dial_failed,
        vpn_peers: reg
            .vpn_peers
            .iter()
            .map(|(k, p)| {
                (
                    k.clone(),
                    PeerDialSnapshot {
                        consecutive_failures: p.consecutive_failures,
                        total_failures: p.total_failures,
                        last_error: p.last_error.clone(),
                        last_failure_ms: p.last_failure_ms,
                        last_success_ms: p.last_success_ms,
                        failing_since_ms: p.failing_since_ms,
                    },
                )
            })
            .collect(),
        agent_conns: reg.agent_conns.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        agent_replacements: reg.agent_replacements,
        vpn_probes: reg.vpn_probes.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        vpn_ladder: reg.vpn_ladder.clone(),
        inbound_ok: crate::net::health::inbound_counters().0,
        inbound_aborted: crate::net::health::inbound_counters().1,
        inbound_timed_out: crate::net::health::inbound_counters().2,
        inbound_last_ok_ms: crate::net::health::inbound_counters().3,
        rss_mb: reg.rss.back().map(|(_, b)| *b as f64 / 1_048_576.0),
        rss_slope_mb_per_hour: rss_slope(&reg.rss.iter().copied().collect::<Vec<_>>()).map(|(s, _)| s),
        rss_window_hours: rss_slope(&reg.rss.iter().copied().collect::<Vec<_>>()).map(|(_, h)| h),
        netdoc_future_refused: iroh_docs::REJECTED_TOO_FAR_IN_FUTURE.load(std::sync::atomic::Ordering::Relaxed),
        netdoc_future_max_lead_secs: iroh_docs::REJECTED_MAX_LEAD_MICROS.load(std::sync::atomic::Ordering::Relaxed)
            / 1_000_000,
        netdoc_future_last_ms: iroh_docs::REJECTED_LAST_AT_MICROS.load(std::sync::atomic::Ordering::Relaxed) / 1000,
    }
}

/// [`snapshot`] as the JSON string carried by `DsResponse::Health`.
pub fn snapshot_json() -> String {
    serde_json::to_string(&snapshot()).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_entry(
        ns: &iroh_docs::NamespaceSecret,
        author: &iroh_docs::Author,
        key: &[u8],
        timestamp: u64,
    ) -> iroh_docs::SignedEntry {
        let record = iroh_docs::Record::new(iroh_blobs::Hash::new(key), 1, timestamp);
        iroh_docs::SignedEntry::from_parts(ns, author, key, record)
    }

    /// The vendored iroh-docs fix: a peer whose clock is a few seconds fast is
    /// accepted (the stock 0.6 s tolerance dropped its gossip), one an hour fast
    /// is refused and shows up in the health counters.
    #[tokio::test]
    async fn warren_entries_from_a_fast_clock_within_ten_minutes_are_accepted() {
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(iroh_docs::MAX_TIMESTAMP_FUTURE_SHIFT, 600_000_000, "ten minutes in µs");
        let mut rng = rand::rng();
        let ns = iroh_docs::NamespaceSecret::new(&mut rng);
        let author = iroh_docs::Author::new(&mut rng);
        let mut store = iroh_docs::store::Store::memory();
        let mut replica = store.new_replica(ns.clone()).unwrap();
        let now_us = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
        let fast = remote_entry(&ns, &author, b"fast", now_us + 5_000_000);
        replica
            .insert_remote_entry(fast, [7u8; 32], iroh_docs::ContentStatus::Complete)
            .await
            .expect("an entry 5 s ahead must be accepted");
        let before = iroh_docs::REJECTED_TOO_FAR_IN_FUTURE.load(Relaxed);
        let far = remote_entry(&ns, &author, b"far", now_us + 3_600_000_000);
        assert!(
            replica
                .insert_remote_entry(far, [7u8; 32], iroh_docs::ContentStatus::Complete)
                .await
                .is_err()
        );
        let s = snapshot();
        assert!(s.netdoc_future_refused > before);
        assert!(s.netdoc_future_max_lead_secs >= 3000);
        assert!(s.netdoc_future_last_ms > 0);
    }

    // The registry is process-global, so each test uses its own peer key and
    // reads only that peer's entry.

    #[test]
    fn failure_streak_then_recovery() {
        let peer = "test-streak";
        note_vpn_dial_failed(peer, "timed out");
        note_vpn_dial_failed(peer, "timed out again");
        let s = snapshot();
        let p = &s.vpn_peers[peer];
        assert_eq!(p.consecutive_failures, 2);
        assert_eq!(p.total_failures, 2);
        assert_eq!(p.last_error.as_deref(), Some("timed out again"));
        assert!(p.failing_since_ms.is_some());
        assert!(p.last_success_ms.is_none());

        note_vpn_dial_ok(peer);
        let p = &snapshot().vpn_peers[peer];
        assert_eq!(p.consecutive_failures, 0);
        assert_eq!(p.total_failures, 2);
        assert!(p.failing_since_ms.is_none());
        assert!(p.last_success_ms.is_some());
    }

    #[test]
    fn rss_slope_tells_a_leak_from_a_step() {
        let h = 3_600_000u64;
        let mb = 1_048_576u64;
        // 65 MB/h, the 2026-09 netdoc leak.
        let leak: Vec<(u64, u64)> = (0..12).map(|i| (i * h / 4, (100 + 65 * i / 4) * mb)).collect();
        let (slope, hours) = rss_slope(&leak).unwrap();
        assert!((slope - 65.0).abs() < 5.0, "{slope}");
        assert!(hours > 2.5);
        // Flat with one 4 MB step: a small slope, nowhere near a leak.
        let step: Vec<(u64, u64)> = (0..12).map(|i| (i * h / 4, if i < 6 { 120 } else { 124 } * mb)).collect();
        assert!(rss_slope(&step).unwrap().0 < 5.0);
        assert!(rss_slope(&leak[..2]).is_none());
        assert!(resident_bytes().is_some_and(|b| b > 0));
    }

    #[test]
    fn snapshot_json_tolerates_unknown_and_missing_fields() {
        note_vpn_dial_failed("test-json", "boom");
        let json = snapshot_json();
        let back: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert!(back.vpn_peers.contains_key("test-json"));

        // An older daemon's (smaller) or newer daemon's (larger) snapshot still parses.
        let old: HealthSnapshot = serde_json::from_str("{}").unwrap();
        assert_eq!(old.vpn_dial_failed, 0);
        let newer: HealthSnapshot =
            serde_json::from_str(r#"{"vpn_dial_ok":1,"agent_conns":{}}"#).unwrap();
        assert_eq!(newer.vpn_dial_ok, 1);
    }
}
