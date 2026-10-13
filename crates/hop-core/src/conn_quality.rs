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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn replacement_must_be_clearly_better() {
        assert!(replacement_is_better(None, ms(500)));
        assert!(replacement_is_better(Some(ms(900)), ms(60)));
        assert!(!replacement_is_better(Some(ms(900)), ms(800)));
        assert!(!replacement_is_better(Some(ms(60)), ms(50)));
    }
}
