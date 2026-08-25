//! `hop fleet grep` — federated log search.
//!
//! Fans a READ-ONLY search across the warren members matching a selector, each node
//! resolving its OWN source locally (so cross-platform is handled at the edge), and
//! reduces the per-node matches into one answer — no central collector.
//!
//! **Read-only guarantee.** Every node runs the search under the `audit` sandbox
//! preset (`read_only` + `no_network`) via `RequestExecV2`; the host merges it
//! *stricter*, so a node cannot be mutated regardless of the peer's invite. The
//! pattern is single-quoted into the command (data, never code).
//!
//! **Sources (per-node, three tiers).**
//! - `audit` (default): the structured hop audit log (`hop audit --json`) — identical
//!   on macOS + Linux; the search filters its lines for the pattern.
//! - `system`: well-known system logs, resolved per-OS at the node (journalctl on
//!   systemd, `/var/log/*` on other Linux, `/var/log/system.log` on macOS).
//! - `<path>`: an operator-named file (any `--source` value containing `/`).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use hop_core::config::KnownHostsStore;
use hop_core::proto::ClientMessage;
use hop_core::sandbox::SandboxPolicy;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::mux;

/// One node's slice of the reduced result.
#[derive(Serialize)]
struct NodeResult {
    name: String,
    node_id: String,
    count: usize,
    matches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct Reduced<'a> {
    pattern: &'a str,
    source: &'a str,
    since: &'a str,
    selector: &'a str,
    total: usize,
    nodes: Vec<NodeResult>,
}

/// Single-quote a string for safe embedding in a `sh` command (data, not code).
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the read-only search command a node runs, per source tier.
fn node_command(source: &str, pattern: &str, since: &str, limit: usize) -> String {
    let pat = shq(pattern);
    if source == "audit" {
        // Structured, uniform source — fetch recent events; the pattern is filtered
        // client-side (so the audit query stays injection-free).
        format!("hop audit --json --since {} --limit 2000", shq(since))
    } else if source == "system" {
        // Resolve the native system-log source at the node (cross-platform at the edge).
        format!(
            "PAT={pat}; \
             if command -v journalctl >/dev/null 2>&1; then \
                 journalctl --no-pager -n 5000 2>/dev/null | grep -iF -- \"$PAT\"; \
             elif [ -r /var/log/syslog ]; then \
                 grep -iF -- \"$PAT\" /var/log/syslog /var/log/auth.log 2>/dev/null; \
             elif [ -r /var/log/system.log ]; then \
                 grep -iF -- \"$PAT\" /var/log/system.log 2>/dev/null; \
             elif [ -r /var/log/messages ]; then \
                 grep -iF -- \"$PAT\" /var/log/messages /var/log/secure 2>/dev/null; \
             fi | head -n {limit}"
        )
    } else {
        // Operator-named path: a plain read-only file grep.
        format!("grep -iF -- {pat} {} 2>/dev/null | head -n {limit}", shq(source))
    }
}

/// Reduce one node's captured stdout into matching lines (filtering `audit` output
/// for the pattern client-side; `system`/path output is already grep'd).
fn extract_matches(source: &str, pattern: &str, raw: &str, limit: usize) -> Vec<String> {
    let needle = pattern.to_ascii_lowercase();
    raw.lines()
        .filter(|l| !l.is_empty())
        .filter(|l| source != "audit" || l.to_ascii_lowercase().contains(&needle))
        .take(limit)
        .map(|l| l.to_string())
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    host_config_dir: &Path,
    user_config_dir: &Path,
    selector: &str,
    pattern: &str,
    source: &str,
    since: &str,
    limit: usize,
    concurrency: usize,
    json: bool,
    include_offline: bool,
    liveness_window_secs: u64,
) -> Result<()> {
    // Target set: warren members (the roster snapshot) whose role or tags match the
    // selector, plus legacy known-host groups. Members are connected by node-id; the
    // HOST enforces authorization (a node that hasn't admitted this caller rejects the
    // exec and is reported as an error — that, plus the member-only roster, is the
    // access gate). Cedar VPN reach is orthogonal (it gates L3 forwarding, not exec).
    let all = selector == "all" || selector == "*";
    let mut seen = HashSet::new();
    let mut targets: Vec<(String, String)> = Vec::new();
    let mut skipped_offline = 0usize;
    let now = crate::unix_now_secs();
    let self_id = crate::id_via_daemon(host_config_dir).ok().flatten();
    let snap = hop_core::fleet::WarrenSnapshot::load(host_config_dir).unwrap_or_default();
    for m in &snap.members {
        let hit = all || m.role == selector || m.tags.iter().any(|t| t == selector);
        if !hit {
            continue;
        }
        // Skip self (can't connect to ourselves) and, by default, offline members
        // (stale last_seen) — they'd just time out and clutter the result.
        if self_id.as_deref() == Some(m.node_id.as_str()) {
            continue;
        }
        if !include_offline && !m.is_online(now, liveness_window_secs) {
            skipped_offline += 1;
            continue;
        }
        if seen.insert(m.node_id.clone()) {
            targets.push((m.node_id.clone(), m.name.clone()));
        }
    }
    if let Ok(hosts) = KnownHostsStore::load(user_config_dir) {
        for h in &hosts.hosts {
            if (all || h.groups.contains(&selector.to_string())) && seen.insert(h.node_id.clone()) {
                targets.push((h.name.clone(), h.name.clone()));
            }
        }
    }

    let offline_note = if skipped_offline > 0 {
        format!(" ({skipped_offline} offline skipped — use --include-offline)")
    } else {
        String::new()
    };

    if targets.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string(&Reduced {
                    pattern, source, since, selector, total: 0, nodes: vec![]
                })?
            );
        } else {
            println!("No reachable warren members or known hosts match '{selector}'.{offline_note}");
        }
        return Ok(());
    }

    let command = node_command(source, pattern, since, limit);
    // Read-only, no-network sandbox; the host merges it stricter — a node can't be
    // mutated. (`audit` preset: read anywhere, deny destructive commands, no writes.)
    let sandbox = SandboxPolicy::from_preset("audit").unwrap_or_default();

    if !json {
        println!(
            "Searching {} (source={source}, since={since}) across {} node(s) matching '{selector}'{offline_note}:\n",
            shq(pattern),
            targets.len()
        );
    }

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = JoinSet::new();
    for (target, name) in targets {
        let sem = sem.clone();
        let cfg = user_config_dir.to_path_buf();
        let command = command.clone();
        let sandbox = sandbox.clone();
        let source = source.to_string();
        let pattern = pattern.to_string();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let msg = ClientMessage::RequestExecV2 { command, sandbox };
            // Per-node timeout so one slow/hung node can't stall the whole search.
            let res = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                let (_resolved, _send, recv) =
                    mux::connect_to_host(&cfg, &target, None, &msg).await?;
                let (out, _code) = hop_core::shell::client_exec_capture(recv).await?;
                anyhow::Ok(out)
            })
            .await;
            match res {
                Ok(Ok(out)) => {
                    let matches = extract_matches(&source, &pattern, &out, limit);
                    NodeResult { count: matches.len(), name, node_id: target, matches, error: None }
                }
                Ok(Err(e)) => NodeResult {
                    count: 0,
                    name,
                    node_id: target,
                    matches: vec![],
                    error: Some(format!("{e:#}")),
                },
                Err(_) => NodeResult {
                    count: 0,
                    name,
                    node_id: target,
                    matches: vec![],
                    error: Some("timed out".to_string()),
                },
            }
        });
    }

    let mut nodes: Vec<NodeResult> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(nr) = joined {
            nodes.push(nr);
        }
    }
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    let total: usize = nodes.iter().map(|n| n.count).sum();

    if json {
        println!(
            "{}",
            serde_json::to_string(&Reduced { pattern, source, since, selector, total, nodes })?
        );
        return Ok(());
    }

    let mut errors = 0;
    for n in &nodes {
        let short = &n.node_id[..10.min(n.node_id.len())];
        if let Some(err) = &n.error {
            errors += 1;
            println!("=== {} ({short}) === ERROR: {err}", n.name);
        } else {
            println!("=== {} ({short}) === {} match(es)", n.name, n.count);
            for line in &n.matches {
                println!("  {line}");
            }
        }
        println!();
    }
    println!(
        "Total: {total} match(es) across {} node(s){}.",
        nodes.len(),
        if errors > 0 { format!(", {errors} unreachable/denied") } else { String::new() }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shq_blocks_injection() {
        // A pattern with shell metacharacters becomes an inert single-quoted literal.
        assert_eq!(shq("a'; rm -rf /; '"), "'a'\\''; rm -rf /; '\\'''");
        // The quoted form never contains an unescaped quote that could end the string.
        let q = shq("x' && touch pwned #");
        assert!(q.starts_with('\'') && q.ends_with('\''));
    }

    #[test]
    fn node_command_per_source() {
        let a = node_command("audit", "rejected", "1h", 50);
        assert!(a.starts_with("hop audit --json --since '1h'"));
        assert!(!a.contains("rejected"), "audit filters client-side, no pattern in cmd");

        let s = node_command("system", "failed login", "24h", 20);
        assert!(s.contains("journalctl") && s.contains("/var/log/syslog"));
        assert!(s.contains("'failed login'"), "pattern safely quoted");
        assert!(s.contains("grep -iF"), "fixed-string, read-only grep");

        let p = node_command("/var/log/nginx/access.log", "500", "1h", 10);
        assert!(p.starts_with("grep -iF -- '500' '/var/log/nginx/access.log'"));
    }

    #[test]
    fn extract_matches_filters_audit_by_pattern() {
        let raw = "{\"action\":\"connection.rejected\"}\n{\"action\":\"exec\"}\n";
        let m = extract_matches("audit", "rejected", raw, 100);
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("rejected"));
        // system/path output is pre-grep'd → kept as-is (no client filter).
        let m2 = extract_matches("system", "anything", "line1\nline2\n", 100);
        assert_eq!(m2.len(), 2);
        // limit is respected.
        assert_eq!(extract_matches("system", "x", "a\nb\nc\n", 2).len(), 2);
    }
}
