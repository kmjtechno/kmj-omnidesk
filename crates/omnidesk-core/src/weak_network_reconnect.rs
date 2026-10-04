//! Reconnect policy shaped by observed network conditions (M6).
//!
//! `reconnect::ReconnectPolicy` answers "how long do we wait between direct
//! attempts?" with a single geometric curve. That is the right answer when a
//! connection is dropping because a port changed or a peer went away.
//!
//! It is the wrong answer on a weak link. When loss is already high, the
//! session's own retry traffic competes with the user's actual traffic for
//! the same scarce capacity, and retrying immediately makes the link worse
//! for the very session being recovered. Backing off in proportion to
//! observed loss is what stops a weak network from being driven into the
//! ground by its own recovery mechanism.
//!
//! The policy is deterministic: the same loss history always produces the same
//! schedule, which is what lets M6's "reproducible results" criterion apply to
//! recovery behaviour as well as to quality adaptation.

use std::time::Duration;

use crate::weak_network::NetworkSample;

/// Ceiling on the doubling count.
///
/// Bounds the shift so `1_u32 << doublings` cannot overflow. The ceiling on
/// the resulting duration is enforced separately by
/// [`WeakNetworkReconnectPolicy::max_backoff`].
const MAX_DOUBLINGS: u32 = 16;

/// Why a reconnect is being attempted.
///
/// The distinction matters because the two failures want opposite responses: a
/// peer that vanished should be retried promptly, while a link that is merely
/// congested should be retried slowly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectCause {
    /// The peer went away or the path changed. Likely to resolve quickly.
    PeerUnavailable,
    /// The link is congested or lossy. Retrying hard makes it worse.
    LinkDegraded,
    /// Cause not known. Treated as [`Self::LinkDegraded`], the cautious
    /// assumption: assuming congestion costs latency, assuming availability
    /// costs the link.
    Unknown,
}

impl DisconnectCause {
    /// Whether this cause warrants an immediate retry.
    #[must_use]
    pub const fn warrants_immediate_retry(self) -> bool {
        matches!(self, Self::PeerUnavailable)
    }
}

/// Reconnect backoff shaped by both the cause and the observed link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeakNetworkReconnectPolicy {
    /// Backoff used when the link is healthy and the peer merely vanished.
    pub base: Duration,
    /// Ceiling on any single backoff.
    pub max_backoff: Duration,
    /// Loss (ppm) at which backoff reaches its ceiling on the first delay.
    ///
    /// Loss scales the *starting* backoff, continuously from
    /// `base * degraded_multiplier` up to [`Self::max_backoff`]. Scaling the
    /// doubling count instead cannot work: the base already passes the ceiling
    /// within a handful of doublings, so every cap above that point would
    /// produce an identical schedule and loss would affect nothing.
    pub loss_for_max_backoff_ppm: u16,
    /// Multiplier applied on a degraded link before loss is taken into account.
    ///
    /// Even with zero observed loss, a degraded disconnect is assumed to need
    /// a longer pause than a vanished peer. This is the asymmetry that keeps
    /// recovery traffic from becoming the congestion.
    pub degraded_multiplier: u32,
}

impl Default for WeakNetworkReconnectPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
            loss_for_max_backoff_ppm: 500,
            degraded_multiplier: 4,
        }
    }
}

impl WeakNetworkReconnectPolicy {
    /// Backoff before attempt `round`, counting from 1.
    ///
    /// Round 1 is never delayed: a session that just dropped should try once
    /// immediately, because a peer that is merely restarting often comes back
    /// within a second and the user should not watch a countdown.
    #[must_use]
    pub fn backoff_before(
        self,
        round: u32,
        cause: DisconnectCause,
        last: Option<&NetworkSample>,
    ) -> Duration {
        if round <= 1 {
            return Duration::ZERO;
        }

        let start = self.starting_backoff(cause, last);
        let doublings = round.saturating_sub(2).min(MAX_DOUBLINGS);
        start
            .checked_mul(1_u32 << doublings)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff)
    }

    /// The backoff before any doubling is applied.
    ///
    /// This is where loss is felt. Everything about the shape of the schedule
    /// beyond this point is identical regardless of link conditions.
    #[must_use]
    pub fn starting_backoff(
        self,
        cause: DisconnectCause,
        last: Option<&NetworkSample>,
    ) -> Duration {
        if cause.warrants_immediate_retry() {
            return self.base.min(self.max_backoff);
        }

        let degraded_base = self
            .base
            .checked_mul(self.degraded_multiplier)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff);
        self.loss_scaled_backoff(degraded_base, last)
    }

    /// Interpolate between `clean` and [`Self::max_backoff`] by observed loss.
    ///
    /// Linear in loss so a partly degraded link is waited out longer without
    /// being treated as though it were already dead. Saturates at the ceiling.
    #[must_use]
    pub fn loss_scaled_backoff(self, clean: Duration, last: Option<&NetworkSample>) -> Duration {
        let Some(sample) = last else {
            return clean.min(self.max_backoff);
        };
        if self.loss_for_max_backoff_ppm == 0 || sample.loss_ppm >= self.loss_for_max_backoff_ppm {
            // The link is unusable. Waiting less than the ceiling here would
            // keep hammering a link that cannot carry the traffic at all.
            return self.max_backoff;
        }

        let clean_ms = u64::try_from(clean.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.max_backoff.as_millis()).unwrap_or(u64::MAX);
        if max_ms <= clean_ms {
            // Degenerate configuration: there is no range to scale across.
            return clean;
        }

        let span = max_ms - clean_ms;
        let loss = u64::from(sample.loss_ppm);
        let threshold = u64::from(self.loss_for_max_backoff_ppm);
        // `span * loss` is bounded by `u64::MAX^2` under a pathological config;
        // saturating keeps it finite and the result is still clamped below.
        Duration::from_millis(clean_ms.saturating_add(span.saturating_mul(loss) / threshold))
    }

    /// Total time a full bounded retry sequence would take.
    ///
    /// Exposed so a caller can decide the budget up front, and so tests can
    /// assert a bounded schedule without simulating every round.
    #[must_use]
    pub fn total_backoff_for(
        self,
        rounds: u32,
        cause: DisconnectCause,
        last: Option<&NetworkSample>,
    ) -> Duration {
        let mut total = Duration::ZERO;
        for round in 1..=rounds {
            total = total.saturating_add(self.backoff_before(round, cause, last));
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(loss_ppm: u16) -> NetworkSample {
        NetworkSample {
            latency: Duration::from_millis(100),
            loss_ppm,
            throughput_bps: 2_000_000,
        }
    }

    #[test]
    fn first_attempt_is_never_delayed() {
        let policy = WeakNetworkReconnectPolicy::default();

        assert_eq!(
            policy.backoff_before(1, DisconnectCause::PeerUnavailable, None),
            Duration::ZERO
        );
        assert_eq!(
            policy.backoff_before(1, DisconnectCause::LinkDegraded, None),
            Duration::ZERO
        );
    }

    #[test]
    fn unavailable_peer_backs_off_faster_than_a_degraded_link() {
        let policy = WeakNetworkReconnectPolicy::default();

        let peer = policy.backoff_before(3, DisconnectCause::PeerUnavailable, None);
        let degraded = policy.backoff_before(3, DisconnectCause::LinkDegraded, None);

        assert!(
            degraded > peer,
            "a degraded link must back off further than a vanished peer"
        );
    }

    #[test]
    fn unknown_cause_is_treated_as_degraded() {
        let policy = WeakNetworkReconnectPolicy::default();

        assert_eq!(
            policy.backoff_before(3, DisconnectCause::Unknown, None),
            policy.backoff_before(3, DisconnectCause::LinkDegraded, None)
        );
    }

    #[test]
    fn backoff_grows_with_round_but_is_bounded() {
        let policy = WeakNetworkReconnectPolicy::default();

        let first = policy.backoff_before(2, DisconnectCause::PeerUnavailable, None);
        let later = policy.backoff_before(4, DisconnectCause::PeerUnavailable, None);
        let far = policy.backoff_before(40, DisconnectCause::PeerUnavailable, None);

        assert!(later > first);
        assert_eq!(far, policy.max_backoff, "backoff must be bounded");
    }

    #[test]
    fn loss_changes_the_first_delay_not_only_the_late_rounds() {
        let policy = WeakNetworkReconnectPolicy::default();
        let clean = sample(0);
        let lossy = sample(450);

        // Round 2 is the first delay. If loss only changed how fast later
        // rounds grew, these would be identical and the policy would be doing
        // nothing on a link that is degrading right now.
        let clean_first = policy.backoff_before(2, DisconnectCause::LinkDegraded, Some(&clean));
        let lossy_first = policy.backoff_before(2, DisconnectCause::LinkDegraded, Some(&lossy));

        assert!(
            lossy_first > clean_first,
            "lossy link ({lossy_first:?}) must wait longer than clean ({clean_first:?})"
        );
    }

    #[test]
    fn higher_loss_waits_longer_at_every_round_before_the_ceiling() {
        let policy = WeakNetworkReconnectPolicy::default();

        for round in 2..=6 {
            let mut previous = Duration::ZERO;
            for loss in [0, 50, 150, 300, 450] {
                let observed = sample(loss);
                let backoff =
                    policy.backoff_before(round, DisconnectCause::LinkDegraded, Some(&observed));
                assert!(
                    backoff >= previous,
                    "round {round}: {loss}ppm waited {backoff:?}, less than the previous loss level's {previous:?}"
                );
                previous = backoff;
            }
        }
    }

    #[test]
    fn the_starting_backoff_rises_steadily_with_loss() {
        let policy = WeakNetworkReconnectPolicy::default();

        let start = |loss: u16| {
            let observed = sample(loss);
            policy.starting_backoff(DisconnectCause::LinkDegraded, Some(&observed))
        };

        assert_eq!(
            start(0),
            policy.starting_backoff(DisconnectCause::LinkDegraded, None),
            "a clean link must not be penalised"
        );

        let mut previous = start(0);
        for loss in (25..500).step_by(25) {
            let current = start(loss);
            assert!(
                current >= previous,
                "starting backoff fell at {loss}ppm: {current:?} after {previous:?}"
            );
            previous = current;
        }

        assert_eq!(
            start(policy.loss_for_max_backoff_ppm),
            policy.max_backoff,
            "an unusable link must wait the full ceiling at once"
        );
    }

    #[test]
    fn half_the_threshold_lands_halfway_to_the_ceiling() {
        let policy = WeakNetworkReconnectPolicy::default();
        let clean = policy.starting_backoff(DisconnectCause::LinkDegraded, None);
        let half = policy.starting_backoff(
            DisconnectCause::LinkDegraded,
            Some(&sample(policy.loss_for_max_backoff_ppm / 2)),
        );
        let clean_ms = u64::try_from(clean.as_millis()).unwrap();
        let half_ms = u64::try_from(half.as_millis()).unwrap();
        let max_ms = u64::try_from(policy.max_backoff.as_millis()).unwrap();

        assert_eq!(
            half_ms.saturating_sub(clean_ms),
            max_ms.saturating_sub(clean_ms) / 2,
            "half the threshold loss must add half the remaining headroom"
        );
    }

    #[test]
    fn a_fully_degraded_link_hits_the_ceiling_on_the_first_delay() {
        let policy = WeakNetworkReconnectPolicy::default();
        let unusable = sample(policy.loss_for_max_backoff_ppm);

        assert_eq!(
            policy.backoff_before(2, DisconnectCause::LinkDegraded, Some(&unusable)),
            policy.max_backoff
        );
    }

    #[test]
    fn a_vanished_peer_is_not_penalised_for_loss_on_a_warm_link() {
        let policy = WeakNetworkReconnectPolicy::default();
        let lossy = sample(400);

        // Loss scales the degraded path only. A peer that is simply gone will
        // still be gone in a second, and waiting longer for it wastes the
        // session's chance of recovering at all.
        assert_eq!(
            policy.backoff_before(3, DisconnectCause::PeerUnavailable, Some(&lossy)),
            policy.backoff_before(3, DisconnectCause::PeerUnavailable, None)
        );
    }

    #[test]
    fn backoff_never_exceeds_the_ceiling_on_any_round() {
        let policy = WeakNetworkReconnectPolicy::default();

        for round in 1..=64 {
            for cause in [
                DisconnectCause::PeerUnavailable,
                DisconnectCause::LinkDegraded,
                DisconnectCause::Unknown,
            ] {
                for loss in [0, 50, 250, 500, 900] {
                    let observed = sample(loss);
                    let backoff = policy.backoff_before(round, cause, Some(&observed));
                    assert!(
                        backoff <= policy.max_backoff,
                        "round {round} with {loss}ppm produced {backoff:?}, over the ceiling"
                    );
                }
            }
        }
    }

    #[test]
    fn total_backoff_over_a_bounded_sequence_is_bounded() {
        let policy = WeakNetworkReconnectPolicy::default();
        let observed = sample(100);

        let total = policy.total_backoff_for(10, DisconnectCause::LinkDegraded, Some(&observed));

        assert!(
            total <= policy.max_backoff * 10,
            "a 10-round sequence took {total:?}, which is not bounded as expected"
        );
    }

    #[test]
    fn the_schedule_is_reproducible() {
        let policy = WeakNetworkReconnectPolicy::default();
        let observed = sample(120);

        let first: Vec<Duration> = (1..=8)
            .map(|round| {
                policy.backoff_before(round, DisconnectCause::LinkDegraded, Some(&observed))
            })
            .collect();
        let second: Vec<Duration> = (1..=8)
            .map(|round| {
                policy.backoff_before(round, DisconnectCause::LinkDegraded, Some(&observed))
            })
            .collect();

        assert_eq!(first, second);
    }

    #[test]
    fn a_missing_sample_does_not_make_the_schedule_worse() {
        let policy = WeakNetworkReconnectPolicy::default();
        let clean = sample(0);

        // With no observation the controller must not assume the worst.
        assert!(
            policy.backoff_before(6, DisconnectCause::LinkDegraded, None)
                <= policy.backoff_before(6, DisconnectCause::LinkDegraded, Some(&clean))
        );
    }

    #[test]
    fn a_degenerate_ceiling_below_the_base_does_not_panic() {
        // A misconfigured policy must degrade to a bounded schedule, not to a
        // subtraction overflow or an infinite loop.
        let policy = WeakNetworkReconnectPolicy {
            base: Duration::from_secs(60),
            max_backoff: Duration::from_millis(100),
            loss_for_max_backoff_ppm: 500,
            degraded_multiplier: 4,
        };

        for round in 1..=8 {
            let backoff =
                policy.backoff_before(round, DisconnectCause::LinkDegraded, Some(&sample(300)));
            assert!(backoff <= policy.max_backoff);
        }
    }

    #[test]
    fn a_zero_loss_threshold_treats_the_link_as_unusable() {
        let policy = WeakNetworkReconnectPolicy {
            loss_for_max_backoff_ppm: 0,
            ..WeakNetworkReconnectPolicy::default()
        };

        assert_eq!(
            policy.backoff_before(2, DisconnectCause::LinkDegraded, Some(&sample(0))),
            policy.max_backoff
        );
    }
}
