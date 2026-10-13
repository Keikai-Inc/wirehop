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
/// A warren-update refusal for a future timestamp counts while this recent.
const CLOCK_REFUSAL_RECENT_MS: u64 = 30 * 60 * 1000;
/// No real clock reads earlier than this (2026-01-01): a node that does booted
/// without a real-time clock and has not synced yet.
const CLOCK_FLOOR_MS: u64 = 1_767_225_600_000;

/// A problem with this node's own clock, judged from `now_ms` alone (pure).
pub fn clock_problem(now_ms: u64) -> Option<Problem> {
    (now_ms < CLOCK_FLOOR_MS).then(|| Problem {
        component: "clock",
        detail: format!(
            "this node's clock reads about the year {} — it booted without a real-time clock and has not \
             synced; warren updates from peers are refused until it does (enable NTP)",
            1970 + now_ms / 31_557_600_000
        ),
    })
}

fn human_secs(s: u64) -> String {
    match s {
        0..=119 => format!("{s}s"),
        120..=7199 => format!("{}m", s / 60),
        7200..=172_799 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

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
    if let Some(h) = host
        && h.netdoc_future_refused > 0
        && h.netdoc_future_last_ms > 0
        && now_ms.saturating_sub(h.netdoc_future_last_ms) < CLOCK_REFUSAL_RECENT_MS
    {
        out.push(Problem {
            component: "clock",
            detail: format!(
                "{} warren update(s) refused for timestamps up to {} ahead of this node's clock — this \
                 clock is behind or a peer's is ahead; those updates wait until the clocks agree (check NTP)",
                h.netdoc_future_refused,
                human_secs(h.netdoc_future_max_lead_secs)
            ),
        });
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
    Health(Box<HealthSnapshot>),
}

fn fetch_host_health(host_dir: &Path) -> HostHealth {
    let Ok(conn) = DaemonConnection::connect(host_dir) else { return HostHealth::NoDaemon };
    match conn.request(&DsRequest::Health) {
        Ok(DsResponse::Health(json)) => match serde_json::from_str(&json) {
            Ok(h) => HostHealth::Health(Box::new(h)),
            Err(_) => HostHealth::TooOld,
        },
        _ => HostHealth::TooOld,
    }
}

fn read_agent_health(user_dir: &Path) -> Option<HealthSnapshot> {
    let json = std::fs::read_to_string(user_dir.join("agent-health.json")).ok()?;
    serde_json::from_str(&json).ok()
}

/// What `hop doctor` would do about a problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// Ask the host daemon to restart itself (rootless, over its socket).
    RestartDaemon,
    /// Stop the client agent; the next connection starts a fresh one.
    RestartAgent,
    /// Nothing safe to do automatically; the advice says what to do.
    Advice(&'static str),
}

/// The remedy for one problem (pure, for tests).
pub fn remedy_for(p: &Problem) -> Remedy {
    match p.component {
        "vpn" | "memory" => Remedy::RestartDaemon,
        "connection" if p.detail.starts_with("agent ") => Remedy::RestartAgent,
        "connection" => Remedy::RestartDaemon, // the daemon's own mux pool
        "clock" => Remedy::Advice("set this node's clock (enable NTP); restarting hop does not help"),
        _ => Remedy::Advice("watch it; if it persists, `hop recover`"),
    }
}

/// `hop doctor`: what `hop status` finds, what to do about each, and with
/// `fix` do the safe ones. Returns whether anything is still wrong afterwards.
pub fn doctor(
    host_dir: &Path,
    user_dir: &Path,
    fix: bool,
    restart_daemon: impl Fn() -> Result<()>,
    restart_agent: impl Fn() -> Result<()>,
) -> Result<bool> {
    let host_state = fetch_host_health(host_dir);
    match &host_state {
        HostHealth::NoDaemon => println!(
            "No host daemon serves {} — nothing to heal there (start one with `hop host`, or install it).",
            host_dir.display()
        ),
        HostHealth::TooOld => println!(
            "The host daemon is too old to report its health or heal itself: upgrade it, then `hop recover`."
        ),
        HostHealth::Health(_) => {}
    }
    let host = match &host_state {
        HostHealth::Health(h) => Some((**h).clone()),
        _ => None,
    };
    let agent = if user_dir != host_dir { read_agent_health(user_dir) } else { None };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut problems = assess(host.as_ref(), agent.as_ref(), now_ms);
    problems.extend(clock_problem(now_ms));
    if problems.is_empty() {
        println!("No problems found.");
        return Ok(true);
    }
    let mut want_daemon = false;
    let mut want_agent = false;
    for p in &problems {
        let r = remedy_for(p);
        let what = match r {
            Remedy::RestartDaemon => {
                want_daemon = true;
                "restart the host daemon (`hop recover`)"
            }
            Remedy::RestartAgent => {
                want_agent = true;
                "restart the client agent (`hop agent stop`; the next connection starts a fresh one)"
            }
            Remedy::Advice(a) => a,
        };
        println!("[{}] {}
    → {what}", p.component, p.detail);
    }
    if !fix {
        println!("
Run `hop doctor --fix` to apply the restarts above.");
        return Ok(false);
    }
    if want_agent {
        match restart_agent() {
            Ok(()) => println!("
Client agent stopped; the next connection starts a fresh one."),
            Err(e) => println!("
Could not stop the client agent: {e:#}"),
        }
    }
    if want_daemon {
        match restart_daemon() {
            Ok(()) => println!("Host daemon asked to restart (shells survive it; give it a few seconds)."),
            Err(e) => println!("Could not restart the host daemon: {e:#} (try `sudo hop recover`)"),
        }
    }
    Ok(false)
}

/// `hop status`. Returns whether the node is healthy (the caller exits 1 if not).
pub fn run(host_dir: &Path, user_dir: &Path, json: bool) -> Result<bool> {
    let host_state = fetch_host_health(host_dir);
    let host = match &host_state {
        HostHealth::Health(h) => Some((**h).clone()),
        _ => None,
    };
    let agent = if user_dir != host_dir { read_agent_health(user_dir) } else { None };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut problems = assess(host.as_ref(), agent.as_ref(), now_ms);
    problems.extend(clock_problem(now_ms));
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
    fn a_wrong_clock_is_flagged() {
        assert!(clock_problem(1_000).is_some_and(|p| p.detail.contains("year 1970")));
        assert!(clock_problem(1_790_000_000_000).is_none());
        let now = 1_790_000_000_000;
        let h = HealthSnapshot {
            netdoc_future_refused: 12,
            netdoc_future_max_lead_secs: 3 * 3600,
            netdoc_future_last_ms: now - 60_000,
            ..Default::default()
        };
        let p = assess(Some(&h), None, now);
        assert!(p.iter().any(|p| p.component == "clock" && p.detail.contains("up to 3h")), "{p:?}");
        // Long ago (the clock was fixed since): no longer a problem.
        let old = HealthSnapshot { netdoc_future_last_ms: now - 2 * 3600 * 1000, ..h };
        assert!(assess(Some(&old), None, now).is_empty());
    }

    #[test]
    fn doctor_picks_the_right_remedy() {
        let p = |c: &'static str, d: &str| Problem { component: c, detail: d.into() };
        assert_eq!(remedy_for(&p("vpn", "peer x refuses")), Remedy::RestartDaemon);
        assert_eq!(remedy_for(&p("memory", "grown")), Remedy::RestartDaemon);
        assert_eq!(remedy_for(&p("connection", "agent connection to x: Slow")), Remedy::RestartAgent);
        assert_eq!(remedy_for(&p("connection", "daemon mux connection to x: Slow")), Remedy::RestartDaemon);
        assert!(matches!(remedy_for(&p("host", "stalled")), Remedy::Advice(_)));
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
