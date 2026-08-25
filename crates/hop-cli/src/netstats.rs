//! `hop debug net-stats` — read the VPN data-plane counters from the running
//! daemon and answer the three operational questions about the forwarding pipe:
//!
//!   - **Are packets being dropped?** — the drop counters (reach/no-route/
//!     send-closed/spoof/dest/TUN-error), shown as totals and (in `--watch`)
//!     per-second rates.
//!   - **Are queues filling / backing up?** — the egress send-backpressure
//!     counters: how often and how long the forwarder waited for QUIC datagram
//!     send-buffer space. Zero = the pipe keeps up.
//!   - **What's our per-packet handling latency?** — a log2 histogram of the
//!     time we hold each packet (TUN→send on egress, recv→TUN on ingress).
//!
//! The counters live in the worker process (where the data plane runs) and are
//! served over the existing daemon socket — no restart, no sudo for an
//! operator-group user, no measurable cost on the forwarder.

use std::time::Duration;

use anyhow::{Context, Result};
use hop_core::datastore::protocol::{DsRequest, DsResponse};
use hop_core::datastore::socket::DaemonConnection;
use hop_core::netstats::{LAT_BUCKETS, NetStatsSnapshot, lat_bucket_upper};

pub fn run(config_dir: &std::path::Path, watch: bool, interval: u64, json: bool) -> Result<()> {
    let conn = DaemonConnection::connect(config_dir).context(
        "could not reach the hop daemon socket. Is `hop host` running? \
         (net-stats reads the live data-plane counters from it.)",
    )?;

    if json && !watch {
        let snap = fetch(&conn)?;
        println!("{}", serde_json::to_string_pretty(&snap)?);
        return Ok(());
    }

    if !watch {
        let snap = fetch(&conn)?;
        print_totals(&snap);
        print_histograms(&snap);
        return Ok(());
    }

    // Watch mode: diff successive snapshots to show per-second rates. The first
    // frame has no prior sample, so it prints cumulative totals; thereafter it
    // prints rates over the interval.
    let interval = interval.max(1);
    let mut prev = fetch(&conn)?;
    print_totals(&prev);
    print_histograms(&prev);
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let cur = fetch(&conn)?;
        // Clear screen + home cursor for a stable live view.
        print!("\x1b[2J\x1b[H");
        print_rates(&prev, &cur, interval);
        print_histograms(&cur);
        prev = cur;
    }
}

fn fetch(conn: &DaemonConnection) -> Result<NetStatsSnapshot> {
    match conn.request(&DsRequest::NetStats)? {
        DsResponse::NetStats(s) => Ok(*s),
        DsResponse::Error(e) => anyhow::bail!("daemon error: {e}"),
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    }
}

// ── totals (single-shot / first watch frame) ─────────────────────────────────

fn print_totals(s: &NetStatsSnapshot) {
    let eg_drops =
        s.eg_drop_reach + s.eg_drop_noroute + s.eg_drop_send_closed + s.eg_drop_send_timeout;
    let in_drops = s.in_drop_via6
        + s.in_drop_unknown_peer
        + s.in_drop_spoof
        + s.in_drop_dest
        + s.in_drop_tun;

    println!("VPN data-plane counters (cumulative since daemon start)\n");

    println!("EGRESS  (this host's TUN → peers)");
    row("packets forwarded", s.eg_sent_ok);
    row("bytes read from TUN", s.eg_tun_bytes);
    row("DROP reach-denied", s.eg_drop_reach);
    row("DROP no route/endpoint", s.eg_drop_noroute);
    row("DROP send conn-closed", s.eg_drop_send_closed);
    row("DROP send timeout (full)", s.eg_drop_send_timeout);
    row("transient send retries", s.eg_send_transient);
    row("send backpressure waits", s.eg_backpressure_waits);
    if s.eg_backpressure_waits > 0 {
        let avg = s.eg_backpressure_nanos / s.eg_backpressure_waits.max(1);
        println!(
            "    {:<28} {}  (avg {} blocked)",
            "  total time blocked",
            human_dur_ns(s.eg_backpressure_nanos),
            human_dur_ns(avg)
        );
    }
    println!("    {:<28} {}", "TOTAL egress drops", warn_count(eg_drops));

    println!("\nINGRESS (peers → this host's TUN)");
    row("packets delivered to TUN", s.in_tun_written);
    row("bytes written to TUN", s.in_tun_bytes);
    row("keepalives received", s.in_keepalive);
    row("DROP 4via6 rejected", s.in_drop_via6);
    row("DROP unknown peer", s.in_drop_unknown_peer);
    row("DROP source spoofed", s.in_drop_spoof);
    row("DROP wrong destination", s.in_drop_dest);
    row("DROP TUN write error", s.in_drop_tun);
    println!("    {:<28} {}", "TOTAL ingress drops", warn_count(in_drops));
}

// ── rates (subsequent watch frames) ──────────────────────────────────────────

fn print_rates(prev: &NetStatsSnapshot, cur: &NetStatsSnapshot, secs: u64) {
    let d = secs as f64;
    let r = |a: u64, b: u64| (b.saturating_sub(a)) as f64 / d;
    let eg_drops_now = (cur.eg_drop_reach
        + cur.eg_drop_noroute
        + cur.eg_drop_send_closed
        + cur.eg_drop_send_timeout)
        .saturating_sub(
            prev.eg_drop_reach
                + prev.eg_drop_noroute
                + prev.eg_drop_send_closed
                + prev.eg_drop_send_timeout,
        );
    let in_drops_now = (cur.in_drop_via6
        + cur.in_drop_unknown_peer
        + cur.in_drop_spoof
        + cur.in_drop_dest
        + cur.in_drop_tun)
        .saturating_sub(
            prev.in_drop_via6
                + prev.in_drop_unknown_peer
                + prev.in_drop_spoof
                + prev.in_drop_dest
                + prev.in_drop_tun,
        );

    println!("VPN data-plane rates (per second, over {secs}s window)\n");

    println!("EGRESS  (this host's TUN → peers)");
    rate("packets forwarded", r(prev.eg_sent_ok, cur.eg_sent_ok));
    rate("throughput (B/s)", r(prev.eg_tun_bytes, cur.eg_tun_bytes));
    rate("DROP reach-denied", r(prev.eg_drop_reach, cur.eg_drop_reach));
    rate("DROP no route/endpoint", r(prev.eg_drop_noroute, cur.eg_drop_noroute));
    rate("DROP send conn-closed", r(prev.eg_drop_send_closed, cur.eg_drop_send_closed));
    rate("DROP send timeout (full)", r(prev.eg_drop_send_timeout, cur.eg_drop_send_timeout));
    rate("backpressure waits", r(prev.eg_backpressure_waits, cur.eg_backpressure_waits));
    println!(
        "    {:<28} {}",
        "TOTAL egress drops/s",
        warn_rate(eg_drops_now as f64 / d)
    );

    println!("\nINGRESS (peers → this host's TUN)");
    rate("packets delivered", r(prev.in_tun_written, cur.in_tun_written));
    rate("throughput (B/s)", r(prev.in_bytes, cur.in_bytes));
    rate("DROP unknown peer", r(prev.in_drop_unknown_peer, cur.in_drop_unknown_peer));
    rate("DROP source spoofed", r(prev.in_drop_spoof, cur.in_drop_spoof));
    rate("DROP wrong destination", r(prev.in_drop_dest, cur.in_drop_dest));
    rate("DROP TUN write error", r(prev.in_drop_tun, cur.in_drop_tun));
    println!(
        "    {:<28} {}",
        "TOTAL ingress drops/s",
        warn_rate(in_drops_now as f64 / d)
    );
}

// ── latency histograms ───────────────────────────────────────────────────────

fn print_histograms(s: &NetStatsSnapshot) {
    println!("\nPER-PACKET HANDLING LATENCY (hold time inside hop)");
    histogram("egress  TUN→send", &s.eg_lat);
    histogram("ingress recv→TUN", &s.in_lat);
}

/// Render a log2 latency histogram as a horizontal bar chart over its non-empty
/// range. Each bucket `i` covers `[2^(i-1), 2^i)` ns.
fn histogram(label: &str, buckets: &[u64]) {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        println!("  {label}: (no samples)");
        return;
    }
    let max = *buckets.iter().max().unwrap_or(&1);
    let first = buckets.iter().position(|&c| c > 0).unwrap_or(0);
    let last = buckets.iter().rposition(|&c| c > 0).unwrap_or(0);
    // p50/p99 from the cumulative distribution (upper bound of the bucket).
    let p = |q: f64| -> String {
        let target = (total as f64 * q).ceil() as u64;
        let mut acc = 0u64;
        for (i, &c) in buckets.iter().enumerate() {
            acc += c;
            if acc >= target {
                return human_dur_ns(lat_bucket_upper(i).as_nanos() as u64);
            }
        }
        human_dur_ns(lat_bucket_upper(LAT_BUCKETS - 1).as_nanos() as u64)
    };
    println!(
        "  {label}: {total} samples   p50 ≤ {}   p99 ≤ {}",
        p(0.50),
        p(0.99)
    );
    for (i, &c) in buckets.iter().enumerate().take(last + 1).skip(first) {
        let bar_len = ((c as f64 / max as f64) * 32.0).round() as usize;
        let bar: String = "█".repeat(bar_len);
        println!(
            "    ≤{:>7}  {:<32} {}",
            human_dur_ns(lat_bucket_upper(i).as_nanos() as u64),
            bar,
            c
        );
    }
}

// ── formatting helpers ───────────────────────────────────────────────────────

fn row(label: &str, n: u64) {
    println!("    {label:<28} {n}");
}

fn rate(label: &str, per_sec: f64) {
    println!("    {label:<28} {per_sec:.1}/s");
}

/// A drop count, flagged with a marker when non-zero so it stands out.
fn warn_count(n: u64) -> String {
    if n > 0 {
        format!("{n}  ⚠")
    } else {
        format!("{n}")
    }
}

fn warn_rate(per_sec: f64) -> String {
    if per_sec > 0.0 {
        format!("{per_sec:.1}/s  ⚠")
    } else {
        format!("{per_sec:.1}/s")
    }
}

/// Human-readable duration from a nanosecond count.
fn human_dur_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}
