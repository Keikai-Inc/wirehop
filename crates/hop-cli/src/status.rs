//! `hop status` — is this node healthy, and if not, which part is broken.
//!
//! Reads the health registry the daemon serves over its socket
//! (`DsRequest::Health`) and the client agent's `agent-health.json`, and turns
//! them into a short verdict. Exits 1 when it finds a problem, so it doubles as
//! a container / cron health check. See `docs/technical/self-healing.md`.

use std::path::Path;

use anyhow::Result;
use hop_core::datastore::protocol::{DsRequest, DsResponse};
use hop_core::datastore::socket::DaemonConnection;
use hop_core::health::HealthSnapshot;

/// One thing `hop status` thinks is wrong, and what is already being done.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Problem {
    pub component: &'static str,
    pub detail: String,
}

/// Sustained growth this fast, over at least this long, is reported as a leak.
const LEAK_MB_PER_HOUR: f64 = 20.0;
const LEAK_MIN_HOURS: f64 = 3.0;

/// Inbound handshakes stalling counts as a problem only past this many.
const INBOUND_TIMEOUTS_WARN: u64 = 3;

/// Judge the snapshots. Pure, for tests: `now_ms` is the current Unix ms.
pub fn assess(host: Option<&HealthSnapshot>, agent: Option<&HealthSnapshot>, now_ms: u64) -> Vec<Problem> {
    let mut out = Vec::new();
    let ago = |ms: u64| now_ms.saturating_sub(ms) / 1000;
    if let Some(h) = host {
        for (peer, p) in &h.vpn_probes {
            if p.host_ok == Some(true) && p.vpn_ok == Some(false) {
                out.push(Problem {
                    component: "vpn",
                    detail: format!("peer {peer} is up (its host endpoint answers) but refuses this node's VPN"),
                });
            }
        }
        for (peer, d) in &h.vpn_peers {
            if d.consecutive_failures > 0 {
                let since = d.failing_since_ms.map(|t| format!(" for {}s", ago(t))).unwrap_or_default();
                out.push(Problem {
                    component: "vpn",
                    detail: format!(
                        "VPN dials to {peer} failing ({} in a row{since}): {}",
                        d.consecutive_failures,
                        d.last_error.as_deref().unwrap_or("?")
                    ),
                });
            }
        }
        if let Some(l) = &h.vpn_ladder
            && !l.ends_with("; 0 bad round(s) in a row")
        {
            out.push(Problem { component: "vpn", detail: format!("self-repair: {l}") });
        }
        if let (Some(slope), Some(hours)) = (h.rss_slope_mb_per_hour, h.rss_window_hours)
            && hours >= LEAK_MIN_HOURS
            && slope >= LEAK_MB_PER_HOUR
        {
            out.push(Problem {
                component: "memory",
                detail: format!(
                    "daemon memory has grown steadily at {slope:.0} MB/h over {hours:.1} h (now {:.0} MB) — likely a leak",
                    h.rss_mb.unwrap_or(0.0)
                ),
            });
        }
        if h.inbound_timed_out >= INBOUND_TIMEOUTS_WARN {
            out.push(Problem {
                component: "host",
                detail: format!(
                    "{} inbound handshake(s) stalled since start (clients that connected but never authenticated)",
                    h.inbound_timed_out
                ),
            });
        }
    }
    for (src, snap) in [("daemon mux", host), ("agent", agent)] {
        let Some(s) = snap else { continue };
        for (peer, c) in &s.agent_conns {
            if c.consecutive_bad > 0 {
                out.push(Problem {
                    component: "connection",
                    detail: format!(
                        "{src} connection to {peer}: {} ({} bad probe(s) in a row; it is replaced after 3 if a fresh one is better)",
                        c.last_verdict.as_deref().unwrap_or("?"),
                        c.consecutive_bad
                    ),
                });
            }
        }
    }
    out
}

enum HostHealth {
    NoDaemon,
    /// The daemon answers its socket but predates the health registry.
    TooOld,
    Health(HealthSnapshot),
}

fn fetch_host_health(host_dir: &Path) -> HostHealth {
    let Ok(conn) = DaemonConnection::connect(host_dir) else { return HostHealth::NoDaemon };
    match conn.request(&DsRequest::Health) {
        Ok(DsResponse::Health(json)) => match serde_json::from_str(&json) {
            Ok(h) => HostHealth::Health(h),
            Err(_) => HostHealth::TooOld,
        },
        _ => HostHealth::TooOld,
    }
}

fn read_agent_health(user_dir: &Path) -> Option<HealthSnapshot> {
    let json = std::fs::read_to_string(user_dir.join("agent-health.json")).ok()?;
    serde_json::from_str(&json).ok()
}

/// `hop status`. Returns whether the node is healthy (the caller exits 1 if not).
pub fn run(host_dir: &Path, user_dir: &Path, json: bool) -> Result<bool> {
    let host_state = fetch_host_health(host_dir);
    let host = match &host_state {
        HostHealth::Health(h) => Some(h.clone()),
        _ => None,
    };
    let agent = if user_dir != host_dir { read_agent_health(user_dir) } else { None };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let problems = assess(host.as_ref(), agent.as_ref(), now_ms);
    let healthy = problems.is_empty();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "healthy": healthy,
                "problems": problems,
                "host": host,
                "host_daemon": match host_state {
                    HostHealth::NoDaemon => "not running",
                    HostHealth::TooOld => "too old to report health",
                    HostHealth::Health(_) => "running",
                },
                "agent": agent,
            }))?
        );
        return Ok(healthy);
    }

    match &host_state {
        HostHealth::NoDaemon => {
            println!("Host daemon: not running here (or not reachable at {})", host_dir.display())
        }
        HostHealth::TooOld => println!(
            "Host daemon: running, but too old to report its health (upgrade it, then `hop recover`)"
        ),
        HostHealth::Health(h) => {
            println!("Host daemon: running");
            let last_in = if h.inbound_last_ok_ms == 0 {
                "never".to_string()
            } else {
                format!("{}s ago", now_ms.saturating_sub(h.inbound_last_ok_ms) / 1000)
            };
            println!(
                "  inbound:  last client reached us {last_in} ({} ok, {} aborted, {} stalled)",
                h.inbound_ok, h.inbound_aborted, h.inbound_timed_out
            );
            if h.vpn_probes.is_empty() && h.vpn_peers.is_empty() {
                println!("  vpn:      no peers probed yet");
            } else {
                let up = h.vpn_probes.values().filter(|p| p.fresh || p.vpn_ok == Some(true)).count();
                println!("  vpn:      {up}/{} peer(s) reachable over the VPN", h.vpn_probes.len());
                if let Some(l) = &h.vpn_ladder {
                    println!("            last probe round: {l}");
                }
            }
            if !h.agent_conns.is_empty() {
                println!("  mux pool: {} connection(s), {} replaced since start", h.agent_conns.len(), h.agent_replacements);
            }
            if let Some(mb) = h.rss_mb {
                match (h.rss_slope_mb_per_hour, h.rss_window_hours) {
                    (Some(s), Some(w)) => println!("  memory:   {mb:.0} MB, {s:+.1} MB/h over {w:.1} h"),
                    _ => println!("  memory:   {mb:.0} MB"),
                }
            }
        }
    }
    if let Some(a) = &agent {
        println!(
            "Client agent: {} connection(s), {} replaced since start",
            a.agent_conns.len(),
            a.agent_replacements
        );
    }
    if healthy && host.is_none() && agent.is_none() {
        println!("\nNo problems found, but nothing reported its health either.");
    } else if healthy {
        println!("\nHealthy.");
    } else {
        println!("\nProblems:");
        for p in &problems {
            println!("  [{}] {}", p.component, p.detail);
        }
    }
    Ok(healthy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::health::{AgentConnSnapshot, PeerDialSnapshot, VpnProbeSnapshot};

    #[test]
    fn a_quiet_node_is_healthy() {
        let h = HealthSnapshot {
            vpn_ladder: Some("1 witness(es), VPN failed to 0; 0 bad round(s) in a row".into()),
            ..Default::default()
        };
        assert!(assess(Some(&h), None, 1_000).is_empty());
        assert!(assess(None, None, 1_000).is_empty());
    }

    #[test]
    fn the_2026_10_12_member_is_flagged() {
        let mut h = HealthSnapshot::default();
        h.vpn_probes.insert(
            "b6b6f845b1".into(),
            VpnProbeSnapshot { fresh: false, host_ok: Some(true), vpn_ok: Some(false), at_ms: Some(1) },
        );
        h.vpn_peers.insert(
            "b4f701b139".into(),
            PeerDialSnapshot {
                consecutive_failures: 4,
                last_error: Some("timed out".into()),
                failing_since_ms: Some(0),
                ..Default::default()
            },
        );
        h.vpn_ladder = Some("1 witness(es), VPN failed to 1; 2 bad round(s) in a row".into());
        let p = assess(Some(&h), None, 120_000);
        assert_eq!(p.iter().filter(|p| p.component == "vpn").count(), 3);
        assert!(p.iter().any(|p| p.detail.contains("for 120s")));
    }

    #[test]
    fn a_degraded_agent_connection_is_flagged() {
        let mut a = HealthSnapshot::default();
        a.agent_conns.insert(
            "b6b6f845b1".into(),
            AgentConnSnapshot { consecutive_bad: 2, last_verdict: Some("Slow (1450 ms vs 41 ms baseline)".into()), ..Default::default() },
        );
        let p = assess(None, Some(&a), 0);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].component, "connection");
    }
}
