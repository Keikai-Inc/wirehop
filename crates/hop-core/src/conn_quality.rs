//! Connection quality judged against the connection's own history
//! (`docs/technical/self-healing.md`, "Pre-emptive detection").
//!
//! Pure bookkeeping, no I/O: the caller feeds probe results and asks whether
//! the connection has degraded. A fixed threshold would be wrong in both
//! directions (a satellite link's normal is a fibre link's outage), so a probe
//! is "bad" relative to the best round trip this connection has recently shown.

use std::collections::VecDeque;
use std::time::Duration;

/// How many recent good probes the baseline is the minimum of.
const BASELINE_WINDOW: usize = 20;
/// Consecutive bad probes before the connection counts as degraded. One slow
/// probe is noise; three in a row (~45 s at the agent's cadence) is a path.
pub const DEGRADED_AFTER: u32 = 3;
/// A probe is slow when its RTT is at least this multiple of the baseline...
const SLOW_FACTOR: u32 = 3;
/// ...and at least this much above it (so a 2 ms LAN path at 7 ms is not "slow").
const SLOW_MARGIN: Duration = Duration::from_millis(250);

/// Why a probe or a connection was judged bad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Good,
    /// The probe got no answer within its budget.
    Unanswered,
    /// The probe answered, but far slower than this connection's baseline.
    Slow { rtt: Duration, baseline: Duration },
    /// Traffic is on the relay although a direct path worked on this connection.
    StuckOnRelay,
    /// The probe answered, but the path lost this share of what was sent since
    /// the last probe — interactive use suffers long before the RTT shows it.
    Lossy { loss_pct: u32 },
}

/// Loss over a probe interval counts as bad from this share...
pub const LOSSY_FRACTION: f64 = 0.30;
/// ...and only once this many packets were sent (a quiet path proves nothing).
pub const LOSS_MIN_SENT: u64 = 50;

/// The loss over a probe interval as a fraction, if enough was sent to judge.
pub fn loss_fraction(lost_delta: u64, sent_delta: u64) -> Option<f64> {
    (sent_delta >= LOSS_MIN_SENT).then(|| lost_delta as f64 / sent_delta as f64)
}

#[derive(Debug, Default)]
pub struct QualityTracker {
    recent_good: VecDeque<Duration>,
    consecutive_bad: u32,
    last: Option<Verdict>,
    last_rtt: Option<Duration>,
    ever_direct: bool,
}

impl QualityTracker {
    /// The best RTT among recent good probes, if any.
    pub fn baseline(&self) -> Option<Duration> {
        self.recent_good.iter().min().copied()
    }

    pub fn last_rtt(&self) -> Option<Duration> {
        self.last_rtt
    }

    pub fn last_verdict(&self) -> Option<&Verdict> {
        self.last.as_ref()
    }

    pub fn consecutive_bad(&self) -> u32 {
        self.consecutive_bad
    }

    /// Record one probe: `rtt` is `None` when it went unanswered; `on_relay`
    /// is whether the connection's selected path is the relay (if known).
    pub fn record(&mut self, rtt: Option<Duration>, on_relay: Option<bool>) -> &Verdict {
        self.record_with_loss(rtt, on_relay, None)
    }

    /// `record`, plus the path's loss over the interval (see `loss_fraction`).
    pub fn record_with_loss(&mut self, rtt: Option<Duration>, on_relay: Option<bool>, loss: Option<f64>) -> &Verdict {
        if on_relay == Some(false) {
            self.ever_direct = true;
        }
        self.last_rtt = rtt;
        let verdict = match rtt {
            None => Verdict::Unanswered,
            Some(rtt) => match self.baseline() {
                Some(base) if rtt >= base * SLOW_FACTOR && rtt >= base + SLOW_MARGIN => {
                    Verdict::Slow { rtt, baseline: base }
                }
                _ if on_relay == Some(true) && self.ever_direct => Verdict::StuckOnRelay,
                _ if loss.is_some_and(|l| l >= LOSSY_FRACTION) => Verdict::Lossy {
                    loss_pct: (loss.unwrap_or(0.0) * 100.0).round() as u32,
                },
                _ => Verdict::Good,
            },
        };
        if verdict == Verdict::Good {
            self.consecutive_bad = 0;
            if let Some(rtt) = rtt {
                self.recent_good.push_back(rtt);
                if self.recent_good.len() > BASELINE_WINDOW {
                    self.recent_good.pop_front();
                }
            }
        } else {
            self.consecutive_bad += 1;
        }
        self.last = Some(verdict);
        self.last.as_ref().unwrap()
    }

    /// Bad for long enough that the caller should try a replacement.
    pub fn degraded(&self) -> bool {
        self.consecutive_bad >= DEGRADED_AFTER
    }

    /// Accept the current path as the new normal (a replacement was no better,
    /// so the path itself is slow): restart the baseline and the bad streak so
    /// the caller does not redial in a loop.
    pub fn rebase(&mut self) {
        self.recent_good.clear();
        if let Some(rtt) = self.last_rtt {
            self.recent_good.push_back(rtt);
        }
        self.consecutive_bad = 0;
        self.ever_direct = false;
    }
}

/// Whether a freshly dialed replacement is worth swapping to: the old
/// connection stopped answering, or the new one is clearly faster than the
/// old one's latest probe (not merely within noise of it).
pub fn replacement_is_better(old_last_rtt: Option<Duration>, new_rtt: Duration) -> bool {
    match old_last_rtt {
        None => true,
        Some(old) => new_rtt * 2 <= old || (new_rtt + SLOW_MARGIN <= old),
    }
}

/// What a VPN probe round asks the caller to do (`VpnLadder::on_round`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpnAction {
    None,
    /// Force iroh re-discovery on this node's netdoc endpoint.
    Rediscover,
    /// Restart the worker (fresh endpoints). Rate-limited.
    Restart,
}

/// Rounds in a row with every witnessed peer unreachable over the VPN before
/// re-discovery, and before a restart.
pub const VPN_REDISCOVER_AFTER: u32 = 3;
pub const VPN_RESTART_AFTER: u32 = 5;

/// Escalation for "this node's VPN is broken" (`docs/technical/self-healing.md`).
///
/// A round's *witnesses* are peers whose **host** endpoint answered a probe:
/// they are up and reachable, so their VPN endpoint should answer too. If at
/// least one witness exists and the VPN dial failed to **every** witness, the
/// common factor is this node's netdoc endpoint — the 2026-10-12 laptop, whose
/// VPN dials failed for days while hop shells over the host endpoint worked.
/// Peers whose host does not answer either are just offline and say nothing,
/// so a node whose peers are all powered off never escalates.
#[derive(Debug, Default)]
pub struct VpnLadder {
    bad_rounds: u32,
    rounds_since_restart: Option<u32>,
}

impl VpnLadder {
    /// Rounds between restarts (at ~60 s per round, about 30 min).
    pub const RESTART_COOLDOWN_ROUNDS: u32 = 30;

    pub fn bad_rounds(&self) -> u32 {
        self.bad_rounds
    }

    pub fn on_round(&mut self, witnesses: usize, vpn_failed_to_witnesses: usize) -> VpnAction {
        if let Some(n) = self.rounds_since_restart.as_mut() {
            *n += 1;
        }
        if witnesses == 0 || vpn_failed_to_witnesses < witnesses {
            self.bad_rounds = 0;
            return VpnAction::None;
        }
        self.bad_rounds += 1;
        if self.bad_rounds >= VPN_RESTART_AFTER {
            let cooled = self
                .rounds_since_restart
                .is_none_or(|n| n >= Self::RESTART_COOLDOWN_ROUNDS);
            if cooled {
                self.rounds_since_restart = Some(0);
                self.bad_rounds = 0;
                return VpnAction::Restart;
            }
            return VpnAction::None;
        }
        if self.bad_rounds == VPN_REDISCOVER_AFTER {
            return VpnAction::Rediscover;
        }
        VpnAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_ladder_needs_a_witness() {
        let mut l = VpnLadder::default();
        for _ in 0..20 {
            assert_eq!(l.on_round(0, 0), VpnAction::None, "all peers offline is not our fault");
        }
    }

    #[test]
    fn vpn_ladder_ignores_a_single_bad_peer() {
        let mut l = VpnLadder::default();
        for _ in 0..20 {
            assert_eq!(l.on_round(2, 1), VpnAction::None, "one peer's own VPN is its problem");
        }
    }

    #[test]
    fn vpn_ladder_rediscovers_then_restarts_then_cools_down() {
        let mut l = VpnLadder::default();
        assert_eq!(l.on_round(1, 1), VpnAction::None);
        assert_eq!(l.on_round(1, 1), VpnAction::None);
        assert_eq!(l.on_round(1, 1), VpnAction::Rediscover);
        assert_eq!(l.on_round(1, 1), VpnAction::None);
        assert_eq!(l.on_round(1, 1), VpnAction::Restart);
        // Still broken right after the restart: no second restart inside the cooldown.
        for _ in 0..(VpnLadder::RESTART_COOLDOWN_ROUNDS - 2) {
            assert_ne!(l.on_round(1, 1), VpnAction::Restart);
        }
        let mut restarted = false;
        for _ in 0..10 {
            restarted |= l.on_round(1, 1) == VpnAction::Restart;
        }
        assert!(restarted, "a restart is allowed again after the cooldown");
    }

    #[test]
    fn vpn_ladder_resets_on_any_good_round() {
        let mut l = VpnLadder::default();
        l.on_round(1, 1);
        l.on_round(1, 1);
        l.on_round(1, 0);
        assert_eq!(l.bad_rounds(), 0);
    }


    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn steady_path_is_never_degraded() {
        let mut q = QualityTracker::default();
        for rtt in [40, 55, 38, 70, 45, 120, 41] {
            q.record(Some(ms(rtt)), Some(false));
        }
        assert!(!q.degraded());
        assert_eq!(q.baseline(), Some(ms(38)));
    }

    #[test]
    fn slow_relative_to_baseline_after_three_probes() {
        let mut q = QualityTracker::default();
        for _ in 0..5 {
            q.record(Some(ms(40)), Some(false));
        }
        q.record(Some(ms(900)), Some(false));
        q.record(Some(ms(1100)), Some(false));
        assert!(!q.degraded());
        assert!(matches!(q.record(Some(ms(950)), Some(false)), Verdict::Slow { .. }));
        assert!(q.degraded());
        // Bad probes never pull the baseline up.
        assert_eq!(q.baseline(), Some(ms(40)));
    }

    #[test]
    fn small_absolute_change_on_a_fast_path_is_not_slow() {
        let mut q = QualityTracker::default();
        q.record(Some(ms(2)), Some(false));
        // 4x the baseline but only +6 ms: noise, not a degraded path.
        assert_eq!(q.record(Some(ms(8)), Some(false)), &Verdict::Good);
    }

    #[test]
    fn unanswered_probes_degrade_and_a_good_probe_resets() {
        let mut q = QualityTracker::default();
        q.record(Some(ms(50)), Some(false));
        q.record(None, None);
        q.record(None, None);
        q.record(Some(ms(50)), Some(false));
        assert_eq!(q.consecutive_bad(), 0);
        for _ in 0..DEGRADED_AFTER {
            q.record(None, None);
        }
        assert!(q.degraded());
    }

    #[test]
    fn relay_only_counts_once_direct_has_worked() {
        let mut q = QualityTracker::default();
        // Relay from the start (e.g. a strict NAT): that is this path's normal.
        for _ in 0..5 {
            assert_eq!(q.record(Some(ms(150)), Some(true)), &Verdict::Good);
        }
        q.record(Some(ms(30)), Some(false));
        assert_eq!(q.record(Some(ms(150)), Some(true)), &Verdict::StuckOnRelay);
    }

    #[test]
    fn rebase_accepts_a_slow_path_as_normal() {
        let mut q = QualityTracker::default();
        q.record(Some(ms(40)), Some(false));
        for _ in 0..DEGRADED_AFTER {
            q.record(Some(ms(900)), Some(false));
        }
        assert!(q.degraded());
        q.rebase();
        assert!(!q.degraded());
        assert_eq!(q.record(Some(ms(950)), Some(false)), &Verdict::Good);
    }

    #[test]
    fn heavy_loss_is_bad_light_or_unmeasured_loss_is_not() {
        let mut q = QualityTracker::default();
        q.record(Some(ms(40)), Some(false));
        assert_eq!(q.record_with_loss(Some(ms(45)), Some(false), Some(0.10)), &Verdict::Good);
        assert!(matches!(
            q.record_with_loss(Some(ms(45)), Some(false), Some(0.40)),
            Verdict::Lossy { loss_pct: 40 }
        ));
        assert_eq!(q.consecutive_bad(), 1);
        // Too little sent to judge: no verdict from loss.
        assert_eq!(loss_fraction(30, 40), None);
        assert_eq!(loss_fraction(20, 100), Some(0.2));
    }

    #[test]
    fn replacement_must_be_clearly_better() {
        assert!(replacement_is_better(None, ms(500)));
        assert!(replacement_is_better(Some(ms(900)), ms(60)));
        assert!(!replacement_is_better(Some(ms(900)), ms(800)));
        assert!(!replacement_is_better(Some(ms(60)), ms(50)));
    }
}
