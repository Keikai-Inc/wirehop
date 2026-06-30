//! `hop fleet search` + `hop fleet sources` — the federated log-search UX (G24).
//!
//! Fans a search across the warren's **online** members, each node resolving its
//! OWN sources per-OS via `hop __logsearch` / `hop __logsources` (macOS unified
//! log, Linux journald/syslog, the hop audit log, well-known files) and doing the
//! matching in-process. Two front ends:
//!   * one-shot (non-TTY / `--json`): collect + print with `[node·source·time]`
//!     provenance — pipe- and agent/MCP-friendly;
//!   * interactive (a TTY): a live, fzf-style filter over streamed results (see
//!     [`tui`]).
//!
//! Default source is **system** (the OS logs), not hop's audit log — what a user
//! means by "search my machines' logs". `hop fleet sources` makes the menu of
//! searchable logs discoverable per machine instead of a guessed `--source` flag.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use hop_core::config::KnownHostsStore;
use hop_core::logsearch::{LogLine, LogSource};
use hop_core::proto::ClientMessage;
use hop_core::sandbox::SandboxPolicy;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::mux;

/// One matched line with its origin node — the unit the client renders/streams.
#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub node: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    pub line: String,
}

/// Options for `hop fleet search` (resolved from the CLI).
pub struct SearchOpts {
    pub selector: String,
    pub pattern: Option<String>,
    pub source: String,
    pub since: String,
    pub limit: usize,
    pub include_offline: bool,
    pub window_secs: u64,
    pub json: bool,
    pub interactive: bool,
}

/// Single-quote a string for safe embedding in a remote `sh` command.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The remote command each node runs for a search (read-only `hop __logsearch`).
pub(crate) fn search_command(source: &str, since: &str, grep: Option<&str>, limit: usize) -> String {
    let mut cmd = format!(
        "hop __logsearch --source {} --since {} --limit {}",
        shq(source),
        shq(since),
        limit
    );
    if let Some(g) = grep {
        cmd.push_str(&format!(" --grep {}", shq(g)));
    }
    cmd
}

/// Resolve the fan-out target set: online warren members (skip offline unless
/// forced) whose role/tags match the selector (`all`/`*` = every member), plus
/// legacy known-host groups. Returns `(targets, offline_skipped)` where each
/// target is `(connect_id, display_name)`.
pub fn resolve_targets(
    host_config_dir: &std::path::Path,
    user_config_dir: &std::path::Path,
    selector: &str,
    include_offline: bool,
    window_secs: u64,
) -> (Vec<(String, String)>, usize) {
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
        if self_id.as_deref() == Some(m.node_id.as_str()) {
            continue; // can't connect to ourselves
        }
        if !include_offline && !m.is_online(now, window_secs) {
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
    (targets, skipped_offline)
}

/// Run a remote `hop __...` read-only command on `target`, streaming each stdout
/// line to `on_line`. Used by both search and sources.
pub(crate) async fn stream_node(
    user_config_dir: &std::path::Path,
    target: &str,
    command: String,
    on_line: impl FnMut(String),
) -> Result<()> {
    let sandbox = SandboxPolicy::from_preset("audit").unwrap_or_default();
    let msg = ClientMessage::RequestExecV2 { command, sandbox };
    let (_resolved, _send, recv) = mux::connect_to_host(user_config_dir, target, None, &msg).await?;
    hop_core::shell::client_exec_stream(recv, on_line).await?;
    Ok(())
}

/// `hop fleet search` entry point.
pub async fn run_search(
    host_config_dir: &std::path::Path,
    user_config_dir: &std::path::Path,
    opts: SearchOpts,
) -> Result<()> {
    let (targets, skipped) = resolve_targets(
        host_config_dir,
        user_config_dir,
        &opts.selector,
        opts.include_offline,
        opts.window_secs,
    );
    if targets.is_empty() {
        let note = if skipped > 0 {
            format!(" ({skipped} offline skipped — use --include-offline)")
        } else {
            String::new()
        };
        if opts.json {
            println!("{}", serde_json::json!({"query": opts.pattern, "source": opts.source, "total": 0, "hits": []}));
        } else {
            println!("No reachable warren members or known hosts match '{}'.{note}", opts.selector);
        }
        return Ok(());
    }

    if opts.interactive {
        return crate::fleet_search_tui::run(user_config_dir, targets, opts).await;
    }
    oneshot(user_config_dir, targets, skipped, opts).await
}

/// One-shot (non-interactive / `--json`): fan out, collect, print.
async fn oneshot(
    user_config_dir: &std::path::Path,
    targets: Vec<(String, String)>,
    skipped: usize,
    opts: SearchOpts,
) -> Result<()> {
    let command = search_command(&opts.source, &opts.since, opts.pattern.as_deref(), opts.limit);
    let sem = Arc::new(Semaphore::new(8));
    let mut set = JoinSet::new();
    for (target, name) in targets.clone() {
        let sem = sem.clone();
        let cfg = user_config_dir.to_path_buf();
        let command = command.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let mut hits: Vec<Hit> = Vec::new();
            let res = tokio::time::timeout(std::time::Duration::from_secs(25), async {
                stream_node(&cfg, &target, command, |line| {
                    if let Ok(ll) = serde_json::from_str::<LogLine>(&line) {
                        hits.push(Hit { node: name.clone(), source: ll.source, ts: ll.ts, line: ll.line });
                    }
                })
                .await
            })
            .await;
            let err = match res {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(_) => Some("timed out".to_string()),
            };
            (name, hits, err)
        });
    }

    let mut all: Vec<(String, Vec<Hit>, Option<String>)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(r) = joined {
            all.push(r);
        }
    }
    all.sort_by(|a, b| a.0.cmp(&b.0));
    let total: usize = all.iter().map(|(_, h, _)| h.len()).sum();

    if opts.json {
        let nodes: Vec<_> = all
            .iter()
            .map(|(name, hits, err)| {
                serde_json::json!({"node": name, "count": hits.len(), "hits": hits, "error": err})
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "query": opts.pattern, "source": opts.source, "since": opts.since,
                "selector": opts.selector, "total": total, "nodes": nodes,
            })
        );
        return Ok(());
    }

    let offline_note = if skipped > 0 {
        format!(" ({skipped} offline skipped)")
    } else {
        String::new()
    };
    let pat = opts.pattern.as_deref().unwrap_or("(all)");
    println!(
        "Searched {} for {pat} (source={}, since={}) across {} node(s){offline_note}:\n",
        opts.selector,
        opts.source,
        opts.since,
        targets.len()
    );
    for (name, hits, err) in &all {
        if let Some(e) = err {
            println!("  {name}: error — {e}");
            continue;
        }
        for h in hits {
            let ts = h.ts.as_deref().unwrap_or("");
            println!("  {name} · {} · {ts}  {}", h.source, h.line);
        }
    }
    println!("\nTotal: {total} match(es) across {} node(s).", targets.len());
    Ok(())
}

/// `hop fleet sources` — show the menu of searchable logs per machine (discovery).
pub async fn run_sources(
    host_config_dir: &std::path::Path,
    user_config_dir: &std::path::Path,
    selector: &str,
    include_offline: bool,
    window_secs: u64,
) -> Result<()> {
    let (targets, skipped) =
        resolve_targets(host_config_dir, user_config_dir, selector, include_offline, window_secs);

    // This node's own sources first (no round-trip).
    println!("Searchable log sources (use with `hop fleet search <sel> <pattern> --source <id>`):\n");
    println!("this node:");
    for s in hop_core::logsearch::discover_sources() {
        print_source(&s);
    }

    if targets.is_empty() {
        if skipped > 0 {
            println!("\n({skipped} offline node(s) skipped — use --include-offline)");
        }
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(8));
    let mut set = JoinSet::new();
    for (target, name) in targets {
        let sem = sem.clone();
        let cfg = user_config_dir.to_path_buf();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let mut sources: Vec<LogSource> = Vec::new();
            let res = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                stream_node(&cfg, &target, "hop __logsources".to_string(), |line| {
                    if let Ok(s) = serde_json::from_str::<LogSource>(&line) {
                        sources.push(s);
                    }
                })
                .await
            })
            .await;
            let err = match res {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(_) => Some("timed out".to_string()),
            };
            (name, sources, err)
        });
    }
    let mut all: Vec<(String, Vec<LogSource>, Option<String>)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(r) = joined {
            all.push(r);
        }
    }
    all.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, sources, err) in &all {
        println!("\n{name}:");
        if let Some(e) = err {
            println!("  (unreachable — {e})");
            continue;
        }
        for s in sources {
            print_source(s);
        }
    }
    if skipped > 0 {
        println!("\n({skipped} offline node(s) skipped — use --include-offline)");
    }
    Ok(())
}

fn print_source(s: &LogSource) {
    let mark = if s.available { " " } else { "✗" };
    println!("  {mark} {:<14} {:<22} {}", s.id, s.label, s.detail);
}
