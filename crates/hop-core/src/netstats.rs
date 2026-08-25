//! Lock-free, always-on counters for the VPN data-plane pipeline.
//!
//! The forwarding hot path (egress: TUN → QUIC datagrams; ingress: QUIC
//! datagrams → TUN) updates these counters per packet. They answer three
//! operational questions for `hop debug net-stats`:
//!
//!   1. **Are packets being dropped?** — a counter at every drop site
//!      (reach-denied, no-route, send-buffer-full, spoof, TUN-write error …).
//!   2. **Are queues filling / backing up?** — the send-backpressure counters
//!      (`eg_backpressure_*`): how often, and for how long, the egress task had
//!      to wait for QUIC datagram send-buffer space. Zero waits = the pipe keeps
//!      up; rising wait-time = the data plane is the bottleneck.
//!   3. **What's our per-packet handling latency?** — a log2 histogram of the
//!      time from `tun.recv` to `send_datagram` completing (egress), and from
//!      `read_datagram` to `tun.send` completing (ingress).
//!
//! **Non-invasive by construction.** Every update is a single relaxed
//! `AtomicU64::fetch_add` (~1 ns, no lock, no alloc, no syscall) plus, for
//! latency, two `Instant` reads per packet. Nothing here can block the
//! forwarder or contend a lock, so it is always on — the data is already there
//! the instant an operator connects, with no "enable profiling" round-trip.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Number of log2 latency buckets. Bucket `i` counts samples whose service time
/// in nanoseconds has its most-significant bit at position `i` — i.e. roughly
/// `[2^(i-1), 2^i)` ns. `2^31` ns ≈ 2.1 s, so 32 buckets bracket everything from
/// a cache-hit forward (tens of ns) to a multi-second stall (the top bucket is
/// the catch-all).
pub const LAT_BUCKETS: usize = 32;

/// Process-global data-plane counters. One instance, read by `snapshot()`.
#[derive(Default)]
pub struct NetStats {
    // ── egress: this host's TUN → QUIC datagrams to peers ──────────────
    /// IP packets read from the TUN for forwarding.
    pub eg_tun_pkts: AtomicU64,
    /// Bytes read from the TUN for forwarding.
    pub eg_tun_bytes: AtomicU64,
    /// Dropped: member-to-member reach ACL denied the packet.
    pub eg_drop_reach: AtomicU64,
    /// Dropped: no endpoint could be resolved for the destination.
    pub eg_drop_noroute: AtomicU64,
    /// Datagrams successfully handed to QUIC for sending.
    pub eg_sent_ok: AtomicU64,
    /// Dropped: send failed because the connection was closed.
    pub eg_drop_send_closed: AtomicU64,
    /// Send returned an error but the connection was kept (transient).
    pub eg_send_transient: AtomicU64,
    /// Dropped: the backpressuring send blocked past its timeout (the send
    /// buffer stayed full — the path can't drain). The connection is kept; the
    /// packet is dropped to free the single serial forwarder.
    pub eg_drop_send_timeout: AtomicU64,
    /// Egress had to wait for QUIC datagram send-buffer space (backpressure):
    /// how many sends blocked at all (the "queue is backing up" signal). Zero =
    /// the pipe keeps up; rising = the data plane is the bottleneck.
    pub eg_backpressure_waits: AtomicU64,
    /// Total nanoseconds spent blocked waiting for send-buffer space.
    pub eg_backpressure_nanos: AtomicU64,
    /// Per-packet egress handling time (`tun.recv` → `send_datagram` done).
    eg_lat: [AtomicU64; LAT_BUCKETS],

    // ── ingress: QUIC datagrams from peers → this host's TUN ────────────
    /// Datagrams read from peers (excludes keepalives, counted separately).
    pub in_dg: AtomicU64,
    /// Bytes read from peers.
    pub in_bytes: AtomicU64,
    /// Keepalive heartbeats received (path-liveness markers, not user traffic).
    pub in_keepalive: AtomicU64,
    /// Dropped: 4via6 ingress rejected (not a client, unauthorized, pool full).
    pub in_drop_via6: AtomicU64,
    /// Dropped: datagram from a peer with no endpoint→vIP mapping yet.
    pub in_drop_unknown_peer: AtomicU64,
    /// Dropped: source vIP failed the anti-spoofing check.
    pub in_drop_spoof: AtomicU64,
    /// Dropped: not destined for us nor any gateway route we advertise.
    pub in_drop_dest: AtomicU64,
    /// Datagrams successfully written to the TUN.
    pub in_tun_written: AtomicU64,
    /// Bytes written to the TUN.
    pub in_tun_bytes: AtomicU64,
    /// Dropped: TUN write returned an error.
    pub in_drop_tun: AtomicU64,
    /// Per-datagram ingress handling time (`read_datagram` → `tun.send` done).
    in_lat: [AtomicU64; LAT_BUCKETS],
}

/// The single process-global instance the data plane updates.
pub static NET_STATS: LazyLock<NetStats> = LazyLock::new(NetStats::default);

/// Bucket index for a service time: the position of the high bit of its
/// nanosecond count, clamped to the array. Saturates into the top bucket.
#[inline]
fn bucket_of(d: Duration) -> usize {
    let ns = (d.as_nanos() as u64).max(1);
    let bits = 64 - ns.leading_zeros() as usize; // 1..=64
    bits.min(LAT_BUCKETS - 1)
}

impl NetStats {
    /// Record an egress per-packet handling time.
    #[inline]
    pub fn record_egress_latency(&self, d: Duration) {
        self.eg_lat[bucket_of(d)].fetch_add(1, Relaxed);
    }

    /// Record an ingress per-datagram handling time.
    #[inline]
    pub fn record_ingress_latency(&self, d: Duration) {
        self.in_lat[bucket_of(d)].fetch_add(1, Relaxed);
    }

    /// Read every counter into a serializable, transport-friendly snapshot.
    pub fn snapshot(&self) -> NetStatsSnapshot {
        let v = |a: &AtomicU64| a.load(Relaxed);
        let buckets = |arr: &[AtomicU64; LAT_BUCKETS]| arr.iter().map(v).collect::<Vec<_>>();
        NetStatsSnapshot {
            eg_tun_pkts: v(&self.eg_tun_pkts),
            eg_tun_bytes: v(&self.eg_tun_bytes),
            eg_drop_reach: v(&self.eg_drop_reach),
            eg_drop_noroute: v(&self.eg_drop_noroute),
            eg_sent_ok: v(&self.eg_sent_ok),
            eg_drop_send_closed: v(&self.eg_drop_send_closed),
            eg_send_transient: v(&self.eg_send_transient),
            eg_drop_send_timeout: v(&self.eg_drop_send_timeout),
            eg_backpressure_waits: v(&self.eg_backpressure_waits),
            eg_backpressure_nanos: v(&self.eg_backpressure_nanos),
            eg_lat: buckets(&self.eg_lat),
            in_dg: v(&self.in_dg),
            in_bytes: v(&self.in_bytes),
            in_keepalive: v(&self.in_keepalive),
            in_drop_via6: v(&self.in_drop_via6),
            in_drop_unknown_peer: v(&self.in_drop_unknown_peer),
            in_drop_spoof: v(&self.in_drop_spoof),
            in_drop_dest: v(&self.in_drop_dest),
            in_tun_written: v(&self.in_tun_written),
            in_tun_bytes: v(&self.in_tun_bytes),
            in_drop_tun: v(&self.in_drop_tun),
            in_lat: buckets(&self.in_lat),
        }
    }
}

/// A plain-data copy of every counter at one instant — what crosses the daemon
/// socket to `hop debug net-stats`. The latency vectors are `LAT_BUCKETS` long.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetStatsSnapshot {
    pub eg_tun_pkts: u64,
    pub eg_tun_bytes: u64,
    pub eg_drop_reach: u64,
    pub eg_drop_noroute: u64,
    pub eg_sent_ok: u64,
    pub eg_drop_send_closed: u64,
    pub eg_send_transient: u64,
    pub eg_drop_send_timeout: u64,
    pub eg_backpressure_waits: u64,
    pub eg_backpressure_nanos: u64,
    pub eg_lat: Vec<u64>,
    pub in_dg: u64,
    pub in_bytes: u64,
    pub in_keepalive: u64,
    pub in_drop_via6: u64,
    pub in_drop_unknown_peer: u64,
    pub in_drop_spoof: u64,
    pub in_drop_dest: u64,
    pub in_tun_written: u64,
    pub in_tun_bytes: u64,
    pub in_drop_tun: u64,
    pub in_lat: Vec<u64>,
}

/// Inclusive-exclusive upper bound of latency bucket `i`, as a `Duration`:
/// bucket `i` holds samples in `[2^(i-1), 2^i)` ns. The renderer uses this to
/// label each bucket. The top bucket saturates, so its label means "and up".
pub fn lat_bucket_upper(i: usize) -> Duration {
    Duration::from_nanos(1u64 << (i.min(LAT_BUCKETS - 1) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_increase_with_latency() {
        assert!(bucket_of(Duration::from_nanos(1)) < bucket_of(Duration::from_micros(1)));
        assert!(bucket_of(Duration::from_micros(1)) < bucket_of(Duration::from_millis(1)));
        // Saturates into the top bucket rather than panicking.
        assert_eq!(bucket_of(Duration::from_secs(60)), LAT_BUCKETS - 1);
    }

    #[test]
    fn snapshot_reads_counters() {
        let s = NetStats::default();
        s.eg_tun_pkts.fetch_add(3, Relaxed);
        s.record_egress_latency(Duration::from_micros(5));
        let snap = s.snapshot();
        assert_eq!(snap.eg_tun_pkts, 3);
        assert_eq!(snap.eg_lat.len(), LAT_BUCKETS);
        assert_eq!(snap.eg_lat.iter().sum::<u64>(), 1);
    }
}
