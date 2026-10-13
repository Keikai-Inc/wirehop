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
}

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
    }
}

/// [`snapshot`] as the JSON string carried by `DsResponse::Health`.
pub fn snapshot_json() -> String {
    serde_json::to_string(&snapshot()).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
