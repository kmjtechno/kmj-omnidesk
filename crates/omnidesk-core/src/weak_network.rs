//! Adaptive quality under constrained and unstable networks (M6).
//!
//! A remote session has one job when the network is bad: stay usable. That
//! means giving up quality early and often rather than holding a high setting
//! the link cannot carry, which is what produces the freeze-and-thrash
//! behaviour that makes a session unusable rather than merely degraded.
//!
//! Two properties drive the design:
//!
//! * Degradation is progressive. Quality steps down through fixed rungs on
//!   evidence, never all at once, so a transient spike cannot collapse the
//!   session to its lowest setting.
//! * Recovery is earned. Quality steps up only after sustained good
//!   conditions, so a link oscillating around a threshold cannot make the
//!   image pump between two settings.
//!
//! Everything here is deterministic and integer-based. The M6 exit criteria
//! require reproducible results per profile and forbid unverified "fastest"
//! claims, so no float, no wall-clock read, and no randomness enters a
//! decision. The same observation sequence always yields the same quality.

use std::time::Duration;

/// Quality ladder rung.
///
/// Ordered from best to worst, so the derived `Ord` is the ladder ordering and
/// the discriminant is the rung index. Adaptation moves along this list and
/// never invents a level, so behaviour under stress is bounded by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum QualityLevel {
    /// Full resolution and frame rate.
    Ultra = 0,
    /// Slightly reduced frame rate.
    High = 1,
    /// Reduced frame rate.
    Medium = 2,
    /// Reduced resolution and frame rate.
    Low = 3,
    /// Minimum viable session: readable, not smooth.
    Minimal = 4,
}

impl QualityLevel {
    /// Every rung, best first.
    pub const ALL: [Self; 5] = [
        Self::Ultra,
        Self::High,
        Self::Medium,
        Self::Low,
        Self::Minimal,
    ];

    /// Scale numerator for this level's resolution, out of 100.
    ///
    /// `Ultra` and `High` share full resolution and differ only in frame rate,
    /// which is why they share a value here.
    ///
    /// Kept as a numerator so callers apply it to their own source
    /// resolution instead of this module guessing a display size.
    #[must_use]
    pub const fn resolution_percent(self) -> u16 {
        match self {
            Self::Ultra | Self::High => 100,
            Self::Medium => 75,
            Self::Low => 50,
            Self::Minimal => 25,
        }
    }

    /// Target frames per second for this level.
    #[must_use]
    pub const fn target_fps(self) -> u16 {
        match self {
            Self::Ultra => 60,
            Self::High => 30,
            Self::Medium => 20,
            Self::Low => 10,
            Self::Minimal => 5,
        }
    }

    /// Bytes-per-second budget for this level, per stream.
    ///
    /// Monotonically non-increasing down the ladder. Adaptation relies on
    /// this: a level with a larger budget than a worse one would make the
    /// controller chase its own tail under a tight link.
    #[must_use]
    pub const fn bitrate_bps(self) -> u32 {
        match self {
            Self::Ultra => 12_000_000,
            Self::High => 6_000_000,
            Self::Medium => 2_500_000,
            Self::Low => 900_000,
            Self::Minimal => 250_000,
        }
    }

    /// Index in the ladder, where `0` is best.
    ///
    /// Reads the discriminant rather than remapping it, so the enum
    /// declaration is the single source of truth for the ordering.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The rung `steps` places away, clamped at both ends.
    ///
    /// Clamping is what makes degradation progressive and bounded: no
    /// observation can skip past `Minimal` or jump above `Ultra`.
    #[must_use]
    pub fn shifted(self, steps: i32) -> Self {
        // Uses the ladder's inherent `Ord` rather than integer index
        // arithmetic. `steps` is only ever a small offset from the current
        // rung, so saturating on it cannot overflow in practice, and `Ord`
        // keeps the bounds correct without casting between integer widths.
        let mut level = self;
        let mut remaining = steps;
        while remaining > 0 {
            if level == Self::Minimal {
                break;
            }
            level = level.worse();
            remaining -= 1;
        }
        while remaining < 0 {
            if level == Self::Ultra {
                break;
            }
            level = level.better();
            remaining += 1;
        }
        level
    }

    /// The next rung down, or `self` at the floor.
    #[must_use]
    pub const fn worse(self) -> Self {
        match self {
            Self::Ultra => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low | Self::Minimal => Self::Minimal,
        }
    }

    /// The next rung up, or `self` at the ceiling.
    #[must_use]
    pub const fn better(self) -> Self {
        match self {
            Self::Ultra | Self::High => Self::Ultra,
            Self::Medium => Self::High,
            Self::Low => Self::Medium,
            Self::Minimal => Self::Low,
        }
    }
}

/// A network condition sample fed to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkSample {
    /// Round-trip latency observed.
    pub latency: Duration,
    /// Fraction of packets lost, in parts per thousand.
    pub loss_ppm: u16,
    /// Measured throughput available, in bits per second.
    pub throughput_bps: u32,
}

/// The conditions under which adaptation should not yet act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptationPolicy {
    /// Loss above this (ppm) forces a step down immediately.
    pub loss_step_down_ppm: u16,
    /// Latency above this forces a step down immediately.
    pub latency_step_down: Duration,
    /// Throughput below this (bps) forces a step down immediately.
    pub throughput_step_down_bps: u32,
    /// Consecutive healthy samples required before stepping back up.
    ///
    /// This is the anti-oscillation control. Without it a link hovering at the
    /// threshold alternates rungs every sample and the image visibly pumps.
    pub samples_to_improve: u32,
}

impl Default for AdaptationPolicy {
    fn default() -> Self {
        Self {
            loss_step_down_ppm: 20,
            latency_step_down: Duration::from_millis(200),
            // Derived from the ladder rather than picked by hand. A rung is
            // "usable" when throughput >= its budget, and a link is
            // "constrained" when throughput <= this threshold, so the two
            // overlap whenever some rung's budget is <= the threshold. The
            // controller would then deadlock at that rung, permanently
            // constrained and unable to recover. Keeping the threshold one
            // unit below the lowest rung makes that overlap impossible for
            // every rung, including if the ladder is later re-tuned.
            throughput_step_down_bps: QualityLevel::Minimal.bitrate_bps() - 1,
            samples_to_improve: 8,
        }
    }
}

/// Tracks quality across samples and reports the resulting settings.
#[derive(Debug, Clone)]
pub struct AdaptiveQualityController {
    level: QualityLevel,
    policy: AdaptationPolicy,
    healthy_streak: u32,
}

impl AdaptiveQualityController {
    /// Starts at [`QualityLevel::Ultra`] with the default policy.
    ///
    /// Starting high is deliberate: a session that opens on a good link should
    /// show full quality immediately, and a bad link will be corrected within
    /// a sample or two.
    #[must_use]
    pub const fn new(policy: AdaptationPolicy) -> Self {
        Self {
            level: QualityLevel::Ultra,
            policy,
            healthy_streak: 0,
        }
    }

    #[must_use]
    pub const fn level(&self) -> QualityLevel {
        self.level
    }

    /// Applies one observation and returns the level now in force.
    ///
    /// Steps down at most one rung per call. A catastrophic sample therefore
    /// still walks quality down one step at a time, which is what keeps
    /// degradation progressive rather than sudden.
    pub fn observe(&mut self, sample: NetworkSample) -> QualityLevel {
        if self.is_constrained(sample) {
            self.healthy_streak = 0;
            self.level = self.level.shifted(1);
            return self.level;
        }

        self.healthy_streak = self.healthy_streak.saturating_add(1);
        if self.healthy_streak >= self.policy.samples_to_improve {
            self.healthy_streak = 0;
            self.level = self.level.shifted(-1);
        }
        self.level
    }

    const fn is_constrained(&self, sample: NetworkSample) -> bool {
        // `Duration`'s `PartialOrd` is not const-stable, so compare the
        // underlying whole-seconds and nanosecond parts directly.
        let threshold = self.policy.latency_step_down;
        let latency_exceeded = sample.latency.as_secs() > threshold.as_secs()
            || (sample.latency.as_secs() == threshold.as_secs()
                && sample.latency.subsec_nanos() >= threshold.subsec_nanos());

        // Throughput is judged against the budget of the rung currently in
        // force, not against one global line. A fixed threshold cannot work:
        // 2 Mbps comfortably clears any sensible "good enough" line while
        // still being unable to carry the 12 Mbps Ultra rung. Comparing the
        // link to the active rung makes the question the right one -- "can
        // this link carry what we are currently sending?" -- and it makes the
        // controller self-correcting when the ladder is re-tuned.
        let rung_unsustainable = sample.throughput_bps < self.level.bitrate_bps();

        sample.loss_ppm >= self.policy.loss_step_down_ppm
            || latency_exceeded
            || rung_unsustainable
            || sample.throughput_bps <= self.policy.throughput_step_down_bps
    }

    /// The resolution this level implies for a given source size.
    ///
    /// Dimensions are rounded down to even values so a scaled frame keeps the
    /// byte alignment the BGRA stride assumes.
    #[must_use]
    pub fn scaled_dimensions(&self, source_width: u32, source_height: u32) -> (u32, u32) {
        let percent = self.level.resolution_percent();
        let width = source_width.saturating_mul(u32::from(percent)) / 100;
        let height = source_height.saturating_mul(u32::from(percent)) / 100;
        (align_down(width), align_down(height))
    }

    /// Whether this level is the minimum and should be treated as a
    /// last-resort mode.
    #[must_use]
    pub const fn is_low_bandwidth_mode(&self) -> bool {
        matches!(self.level, QualityLevel::Minimal)
    }
}

/// Rounds a dimension down to an even number.
const fn align_down(value: u32) -> u32 {
    value / 2 * 2
}

/// One profile's reproducible outcome.
///
/// No public fields, and no `Default`. Every value is measured by
/// [`evaluate_samples`]; a caller that could write `worst_single_step: 7`
/// directly would be able to make [`Self::degradation_was_progressive`] a
/// self-fulfilling claim rather than a measurement, which is the whole thing
/// the M6 criterion is meant to rule out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileOutcome {
    /// Index into [`QualityLevel::ALL`].
    final_level: usize,
    /// Rungs stepped down over the run.
    step_downs: u32,
    /// Rungs stepped up over the run.
    step_ups: u32,
    /// Largest single-step drop in rungs. Never exceeds 1.
    worst_single_step: u32,
}

impl ProfileOutcome {
    /// Whether degradation was progressive.
    ///
    /// Catastrophic degradation is a multi-rung drop from a single sample.
    /// Requiring this to be `true` is how the M6 exit criterion
    /// `degradation_is_progressive_not_catastrophic` becomes checkable rather
    /// than asserted.
    #[must_use]
    pub const fn degradation_was_progressive(self) -> bool {
        self.worst_single_step <= 1
    }

    #[must_use]
    pub const fn final_level(&self) -> usize {
        self.final_level
    }

    /// Rungs stepped down over the run.
    #[must_use]
    pub const fn step_downs(&self) -> u32 {
        self.step_downs
    }

    /// Rungs stepped up over the run.
    #[must_use]
    pub const fn step_ups(&self) -> u32 {
        self.step_ups
    }

    #[must_use]
    pub const fn worst_single_step(&self) -> u32 {
        self.worst_single_step
    }
}

/// Replays a sample sequence and reports what the controller did.
///
/// Deterministic by construction: no clock, no randomness, so two runs over
/// the same sequence produce identical output. That is the M6 criterion
/// `every_profile_has_reproducible_results` expressed as code.
#[must_use]
pub fn evaluate_samples(
    profile: &[NetworkSample],
    policy: AdaptationPolicy,
) -> (QualityLevel, ProfileOutcome) {
    let mut controller = AdaptiveQualityController::new(policy);
    let mut step_downs = 0_u32;
    let mut step_ups = 0_u32;
    let mut worst_single_step = 0_u32;
    let mut previous = controller.level();

    for sample in profile {
        let next = controller.observe(*sample);
        match next.index().cmp(&previous.index()) {
            std::cmp::Ordering::Greater => {
                step_downs = step_downs.saturating_add(1);
                // `next` is at most one rung below `previous`, and the
                // ladder is five rungs wide, so this always fits u32.
                let drop = u32::try_from(next.index() - previous.index()).unwrap_or(u32::MAX);
                worst_single_step = worst_single_step.max(drop);
            }
            std::cmp::Ordering::Less => step_ups = step_ups.saturating_add(1),
            std::cmp::Ordering::Equal => {}
        }
        previous = next;
    }

    let level = controller.level();
    (
        level,
        ProfileOutcome {
            final_level: level.index(),
            step_downs,
            step_ups,
            worst_single_step,
        },
    )
}

/// A degraded-but-usable session never drops straight to the floor.
///
/// Reports whether the ladder satisfies the M6 shape: every rung strictly
/// reduces budget, and no rung is skipped on the way down.
#[must_use]
pub fn ladder_is_monotonic() -> bool {
    // Window over consecutive rungs. Seeding `previous` with the top rung and
    // then re-testing it in the first iteration would compare Ultra to
    // itself and report a false failure.
    QualityLevel::ALL
        .windows(2)
        .all(|pair| pair[0].bitrate_bps() > pair[1].bitrate_bps())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The M6 profiles as declared in `ROADMAP.yaml`.
    ///
    /// Held here so the roadmap's own numbers drive the tests rather than
    /// numbers chosen to make them pass. Changing a profile means changing
    /// `ROADMAP.yaml` too.
    const PROFILES: [(&str, NetworkSample); 4] = [
        (
            "office_good",
            NetworkSample {
                latency: Duration::from_millis(20),
                loss_ppm: 0,
                throughput_bps: 20_000_000,
            },
        ),
        (
            "mobile_constrained",
            NetworkSample {
                latency: Duration::from_millis(80),
                loss_ppm: 10,
                throughput_bps: 2_000_000,
            },
        ),
        (
            "weak_mobile",
            NetworkSample {
                latency: Duration::from_millis(150),
                loss_ppm: 30,
                throughput_bps: 750_000,
            },
        ),
        (
            "severe",
            NetworkSample {
                latency: Duration::from_millis(250),
                loss_ppm: 50,
                throughput_bps: 350_000,
            },
        ),
    ];

    #[test]
    fn every_declared_profile_degrades_progressively_and_reproducibly() {
        for (name, sample) in PROFILES {
            // A sustained profile, long enough for the controller to settle.
            let series = vec![sample; 30];

            let (level, outcome) = evaluate_samples(&series, AdaptationPolicy::default());
            let (_, again) = evaluate_samples(&series, AdaptationPolicy::default());

            assert_eq!(
                outcome, again,
                "{name}: the same profile must produce the same outcome twice"
            );
            // The measured worst step is checked directly rather than only
            // through `degradation_was_progressive()`. Asserting the predicate
            // alone means a predicate that unconditionally returned `true`
            // would pass this test: the controller's actual drops would go
            // unchecked. The pair makes both halves load-bearing.
            assert!(
                outcome.worst_single_step() <= 1,
                "{name}: dropped {} rungs in one sample",
                outcome.worst_single_step()
            );
            assert!(
                outcome.degradation_was_progressive(),
                "{name}: the worst single step of {} must not be catastrophic",
                outcome.worst_single_step()
            );
            // Whatever the profile, the rung in force must actually fit the
            // link that is being described. This is the check that would have
            // caught the threshold/ladder deadlock.
            assert!(
                sample.throughput_bps >= level.bitrate_bps() || level == QualityLevel::Minimal,
                "{name}: settled at {level:?}, which the link cannot carry"
            );
        }
    }

    /// The predicate must be able to say *no*.
    ///
    /// Mutation: change `self.worst_single_step <= 1` to `<= 99` and this
    /// test is the only one that notices, because every other test asserts
    /// the predicate is `true` for a real profile and so cannot tell an
    /// honest `true` from a hard-coded one.
    #[test]
    fn a_multi_rung_drop_is_reported_as_catastrophic() {
        // Built inside the module so the fields stay private to callers.
        let catastrophic = ProfileOutcome {
            final_level: 0,
            step_downs: 1,
            step_ups: 0,
            worst_single_step: 2,
        };
        assert!(
            !catastrophic.degradation_was_progressive(),
            "a 2-rung single step is catastrophic by definition and must not verify"
        );

        let progressive = ProfileOutcome {
            final_level: 0,
            step_downs: 1,
            step_ups: 0,
            worst_single_step: 1,
        };
        assert!(progressive.degradation_was_progressive());
    }

    #[test]
    fn office_profile_holds_full_quality_and_severe_profile_reaches_the_floor() {
        let office = PROFILES[0].1;
        let severe = PROFILES[3].1;

        let (office_level, office_outcome) =
            evaluate_samples(&vec![office; 30], AdaptationPolicy::default());
        let (severe_level, severe_outcome) =
            evaluate_samples(&vec![severe; 30], AdaptationPolicy::default());

        assert_eq!(office_level, QualityLevel::Ultra);
        assert_eq!(office_outcome.step_downs, 0);

        assert_eq!(severe_level, QualityLevel::Minimal);
        assert_eq!(severe_outcome.final_level, QualityLevel::Minimal.index());
    }

    #[test]
    fn quality_decreases_monotonically_across_the_declared_profiles() {
        // Ordered best-link-first in ROADMAP.yaml, so each successive profile
        // must settle at the same quality or worse -- never better.
        let settled: Vec<(&str, usize)> = PROFILES
            .iter()
            .map(|(name, sample)| {
                let (level, _) = evaluate_samples(&vec![*sample; 30], AdaptationPolicy::default());
                (*name, level.index())
            })
            .collect();

        for pair in settled.windows(2) {
            assert!(
                pair[1].1 >= pair[0].1,
                "{} settled at rung {} but the worse link {} settled at rung {}",
                pair[1].0,
                pair[1].1,
                pair[0].0,
                pair[0].1
            );
        }
    }

    fn healthy() -> NetworkSample {
        // Comfortably above the Ultra rung's 12 Mbps budget, so a "healthy"
        // sample genuinely sustains full quality. An earlier fixture used
        // 10 Mbps, which the rung-relative rule correctly rejected.
        NetworkSample {
            latency: Duration::from_millis(20),
            loss_ppm: 0,
            throughput_bps: 20_000_000,
        }
    }

    fn severe() -> NetworkSample {
        NetworkSample {
            latency: Duration::from_millis(250),
            loss_ppm: 50,
            throughput_bps: 100_000,
        }
    }

    #[test]
    fn controller_starts_at_best_quality() {
        let controller = AdaptiveQualityController::new(AdaptationPolicy::default());
        assert_eq!(controller.level(), QualityLevel::Ultra);
    }

    #[test]
    fn constrained_sample_steps_down_one_rung() {
        let mut controller = AdaptiveQualityController::new(AdaptationPolicy::default());

        assert_eq!(controller.observe(severe()), QualityLevel::High);
    }

    #[test]
    fn degradation_steps_down_one_rung_per_sample_never_jumping() {
        let mut controller = AdaptiveQualityController::new(AdaptationPolicy::default());
        let mut previous = controller.level();

        // A link that is completely unusable, sampled repeatedly.
        for _ in 0..20 {
            let next = controller.observe(severe());
            assert!(
                previous.index() + 1 >= next.index(),
                "quality must never drop more than one rung at a time"
            );
            previous = next;
        }

        assert_eq!(controller.level(), QualityLevel::Minimal);
    }

    #[test]
    fn quality_floors_at_minimal_and_never_goes_below() {
        let mut controller = AdaptiveQualityController::new(AdaptationPolicy::default());

        for _ in 0..50 {
            controller.observe(severe());
        }

        assert_eq!(controller.level(), QualityLevel::Minimal);
        assert!(controller.is_low_bandwidth_mode());
    }

    #[test]
    fn a_single_bad_sample_does_not_collapse_the_session() {
        let mut controller = AdaptiveQualityController::new(AdaptationPolicy::default());
        controller.observe(severe());

        assert_ne!(
            controller.level(),
            QualityLevel::Minimal,
            "one bad sample must not drop to the floor"
        );
    }

    #[test]
    fn recovery_requires_sustained_good_conditions() {
        let policy = AdaptationPolicy {
            samples_to_improve: 8,
            ..AdaptationPolicy::default()
        };
        let mut controller = AdaptiveQualityController::new(policy);
        let degraded = controller.observe(severe());

        // Fewer healthy samples than required must not restore quality.
        for _ in 0..policy.samples_to_improve - 1 {
            controller.observe(healthy());
        }
        assert_eq!(controller.level(), degraded);

        // The next one completes the streak.
        assert_eq!(controller.observe(healthy()), QualityLevel::Ultra);
    }

    #[test]
    fn an_interrupted_recovery_resets_the_streak() {
        let policy = AdaptationPolicy {
            samples_to_improve: 4,
            ..AdaptationPolicy::default()
        };
        let mut controller = AdaptiveQualityController::new(policy);

        // Three good samples, then one bad, then three more: the second run
        // never completes a streak of four, so no step up is earned.
        for _ in 0..3 {
            controller.observe(healthy());
        }
        let before = controller.level();
        controller.observe(severe());
        let after_bad = controller.level();
        for _ in 0..3 {
            controller.observe(healthy());
        }

        assert_eq!(before, QualityLevel::Ultra, "streak of 3 must not recover");
        // `after_bad` already reflects the step down caused by the bad
        // sample, so the three later healthy samples must leave it there.
        assert_eq!(
            controller.level(),
            after_bad,
            "quality must not recover on an interrupted streak"
        );
    }

    #[test]
    fn bitrate_budget_falls_monotonically_down_the_ladder() {
        assert!(ladder_is_monotonic());
    }

    #[test]
    fn a_link_never_settles_on_a_rung_it_cannot_carry() {
        // The property that matters: whatever rung the controller settles on,
        // the link must actually be able to carry it. This is what a fixed
        // global threshold could not guarantee -- a 2 Mbps link clears any
        // reasonable "good enough" line while still being unable to carry the
        // 12 Mbps Ultra rung.
        for (name, sample) in PROFILES {
            let (level, _) = evaluate_samples(&vec![sample; 30], AdaptationPolicy::default());
            assert!(
                sample.throughput_bps >= level.bitrate_bps(),
                "{name}: settled at {level:?} needing {} bps but the link carries {} bps",
                level.bitrate_bps(),
                sample.throughput_bps
            );
        }
    }

    #[test]
    fn the_lowest_rung_always_fits_so_the_controller_can_always_settle() {
        // Guarantees the ladder has a floor the worst declared link can reach,
        // so adaptation always terminates instead of running out of rungs.
        let worst = PROFILES
            .iter()
            .map(|(_, sample)| sample.throughput_bps)
            .min()
            .expect("profiles declared");
        assert!(worst >= QualityLevel::Minimal.bitrate_bps());
    }

    #[test]
    fn severe_profile_ends_degraded_but_progressively() {
        let profile = vec![healthy(); 2];
        let profile: Vec<NetworkSample> = [profile, vec![severe(); 10]].concat();

        let (_, outcome) = evaluate_samples(&profile, AdaptationPolicy::default());

        assert_eq!(outcome.final_level, QualityLevel::Minimal.index());
        assert!(
            outcome.degradation_was_progressive(),
            "no single sample may drop more than one rung"
        );
    }

    #[test]
    fn office_profile_never_leaves_full_quality() {
        let profile = vec![healthy(); 50];
        let (level, outcome) = evaluate_samples(&profile, AdaptationPolicy::default());

        assert_eq!(level, QualityLevel::Ultra);
        assert_eq!(outcome.step_downs, 0);
    }

    #[test]
    fn evaluation_is_reproducible() {
        let profile = vec![healthy(); 3]
            .into_iter()
            .chain(std::iter::repeat_n(severe(), 7))
            .collect::<Vec<_>>();

        let first = evaluate_samples(&profile, AdaptationPolicy::default());
        let second = evaluate_samples(&profile, AdaptationPolicy::default());

        assert_eq!(first, second);
    }

    #[test]
    fn scaled_dimensions_stay_even_and_shrink_with_level() {
        let controller = AdaptiveQualityController::new(AdaptationPolicy::default());

        let (ultra_w, ultra_h) = controller.scaled_dimensions(1920, 1080);
        assert_eq!((ultra_w, ultra_h), (1920, 1080));

        let mut degraded = AdaptiveQualityController::new(AdaptationPolicy::default());
        for _ in 0..4 {
            degraded.observe(severe());
        }
        let (min_w, min_h) = degraded.scaled_dimensions(1920, 1080);

        assert!(min_w < ultra_w && min_h < ultra_h);
        assert_eq!(min_w % 2, 0, "width must stay byte-aligned");
        assert_eq!(min_h % 2, 0, "height must stay byte-aligned");
    }
}
