//! `hop audit` — query this node's per-node audit & flow log.
//!
//! Reads the append-only audit log from the running daemon's datastore over the
//! existing Unix socket (no central collector). `--json` emits one JSON object per
//! line in the OTel-aligned schema — the same shape the external-export layer
//! (roadmap G22) ships to Datadog/Splunk/OTLP.

use anyhow::{Context, Result};
use hop_core::audit::{AuditCategory, AuditEvent, AuditQuery, now_ms};
use hop_core::datastore::protocol::{DsRequest, DsResponse};
use hop_core::datastore::socket::DaemonConnection;

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_dir: &std::path::Path,
    since: Option<&str>,
    category: Option<&str>,
    actor: Option<&str>,
    limit: usize,
    json: bool,
) -> Result<()> {
    let category = match category {
        Some(c) => Some(
            AuditCategory::parse(c)
                .with_context(|| format!("unknown --category `{c}` (try connection, session, exec, transfer, reach, flow, membership, config)"))?,
        ),
        None => None,
    };
    // `--since 24h` (default) → an absolute lower bound.
    let since_ms = match since {
        Some(s) => Some(now_ms().saturating_sub(crate::parse_duration_ms(s)?)),
        None => Some(now_ms().saturating_sub(24 * 3600 * 1000)),
    };

    let query = AuditQuery {
        category,
        since_ms,
        until_ms: None,
        actor: actor.map(|s| s.to_string()),
        limit: Some(limit),
    };

    let conn = DaemonConnection::connect(config_dir).context(
        "could not reach the hop daemon socket. Is `hop host` running? \
         (audit reads the local audit log from it.)",
    )?;
    let events = match conn.request(&DsRequest::AuditQuery { query })? {
        DsResponse::AuditEvents(e) => e,
        DsResponse::Error(e) => anyhow::bail!("daemon error: {e}"),
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    };

    if json {
        for ev in &events {
            println!("{}", serde_json::to_string(ev)?);
        }
        return Ok(());
    }

    if events.is_empty() {
        println!("(no audit events in range)");
        return Ok(());
    }
    print_table(&events);
    Ok(())
}

fn print_table(events: &[AuditEvent]) {
    println!(
        "{:<19}  {:<11}  {:<22}  {:<7}  {:<12}  DETAIL",
        "TIME (UTC)", "CATEGORY", "ACTION", "OUTCOME", "WHO"
    );
    for ev in events {
        let who = ev
            .actor_user
            .clone()
            .or_else(|| ev.actor.as_deref().map(short_id))
            .unwrap_or_else(|| "-".into());
        let mut detail = ev.target.clone().unwrap_or_default();
        if let Some(d) = &ev.detail {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(d);
        }
        if let (Some(tx), Some(rx)) = (ev.bytes_tx, ev.bytes_rx) {
            detail = format!("{detail} tx={tx} rx={rx}").trim().to_string();
        }
        println!(
            "{:<19}  {:<11}  {:<22}  {:<7}  {:<12}  {}",
            fmt_utc(ev.ts_ms),
            ev.category.as_str(),
            truncate(&ev.action, 22),
            ev.outcome.as_str(),
            truncate(&who, 12),
            detail
        );
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(10).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

/// Format unix milliseconds as `YYYY-MM-DD HH:MM:SS` UTC, dependency-free
/// (civil-from-days, Howard Hinnant's algorithm).
fn fmt_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 → civil y-m-d
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}
