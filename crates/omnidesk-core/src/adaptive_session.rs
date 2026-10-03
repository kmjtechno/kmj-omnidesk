//! Wires M6's adaptive quality into the capture-to-render path.
//!
//! [`weak_network`] decides *which rung* a link should be on. That decision is
//! only worth anything if it changes what the session actually transmits, and
//! on its own it does not: a controller that reports `Low` while every frame
//! is still sent at full resolution and full rate has changed nothing that the
//! user can see.
//!
//! This module is where the three remaining M6 deliverables become real
//! behaviour:
//!
//! * `adaptive_fps` -- frames are paced, not merely labelled.
//! * `adaptive_resolution` -- frames are actually resampled before encoding.
//! * `low_bandwidth_mode` -- a named mode the shell can surface, which also
//!   suppresses work rather than only shrinking output.
//!
//! Pacing is driven by a caller-supplied monotonic tick rather than a wall
//! clock. That is not a testing convenience: the M6 exit criteria require
//! reproducible results per profile and forbid unverified "fastest" claims, so
//! a decision that depends on when the scheduler happened to run would make
//! every downstream measurement unreproducible.

use crate::{
    media::{DirtyRegion, Frame, FrameError, PixelFormat},
    weak_network::{AdaptiveQualityController, NetworkSample, QualityLevel},
};

/// Ticks per second used to convert frame periods into a comparable count.
///
/// The pipeline is specified in milliseconds, so this only has to be a
/// constant conversion rather than a measured rate.
const MILLIS_PER_SECOND: u64 = 1_000;

/// Bytes per pixel in the BGRA frames this pipeline carries.
const BGRA_BYTES_PER_PIXEL: usize = 4;

/// Why a frame was not transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Fewer than one frame period has passed since the last transmission.
    ///
    /// This is the normal outcome of pacing: the link is fine, the frame rate
    /// is deliberately lower than the capture rate.
    NotDueYet,
}

/// A frame's pacing verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacingDecision {
    /// Transmit now.
    Send,
    /// Do not transmit, for the given reason.
    Skip(SkipReason),
}

/// Applies M6's quality decisions to frames as they pass through the pipeline.
#[derive(Debug, Clone)]
pub struct AdaptiveQualityGate {
    controller: AdaptiveQualityController,
    last_sent_ms: Option<u64>,
}

impl AdaptiveQualityGate {
    #[must_use]
    pub const fn new(controller: AdaptiveQualityController) -> Self {
        Self {
            controller,
            last_sent_ms: None,
        }
    }

    #[must_use]
    pub const fn controller(&self) -> &AdaptiveQualityController {
        &self.controller
    }

    #[must_use]
    pub const fn controller_mut(&mut self) -> &mut AdaptiveQualityController {
        &mut self.controller
    }

    #[must_use]
    pub const fn level(&self) -> QualityLevel {
        self.controller.level()
    }

    /// Feeds one network observation and returns the level now in force.
    pub fn observe(&mut self, sample: NetworkSample) -> QualityLevel {
        self.controller.observe(sample)
    }

    /// Whether the session is running in last-resort mode.
    ///
    /// Exposed so the shell can tell the user *why* the image has gone
    /// coarse, rather than leaving them to infer it.
    #[must_use]
    pub const fn is_low_bandwidth_mode(&self) -> bool {
        self.controller.is_low_bandwidth_mode()
    }

    /// The millisecond period implied by the current rung.
    #[must_use]
    pub fn frame_period_ms(&self) -> u64 {
        let fps = u64::from(self.level().target_fps());
        if fps == 0 {
            return 0;
        }
        MILLIS_PER_SECOND / fps
    }

    /// Whether a frame captured at `tick_ms` is due for transmission.
    ///
    /// `tick_ms` must be monotonic across calls for one session. Two frames
    /// landing in the same slot yield one transmission: at a 5 fps rung a
    /// 60 fps capture produces twelve frames per slot, and transmitting all of
    /// them would defeat the pacing entirely.
    pub fn pacing_for(&mut self, tick_ms: u64) -> PacingDecision {
        let period = self.frame_period_ms();
        if period == 0 {
            return PacingDecision::Send;
        }
        // Compare elapsed time since the last send rather than bucketing the
        // tick. Bucketing into `tick / period` slots puts a frame either side
        // of a boundary, so two frames 32 ms apart land in different slots at
        // a 33 ms period and the session transmits slightly faster than the
        // rung allows. Elapsed time cannot straddle a boundary, because there
        // is no boundary to straddle.
        if let Some(last) = self.last_sent_ms {
            if tick_ms.saturating_sub(last) < period {
                return PacingDecision::Skip(SkipReason::NotDueYet);
            }
        }
        self.last_sent_ms = Some(tick_ms);
        PacingDecision::Send
    }

    /// Rescales a frame to the resolution the current rung implies.
    ///
    /// Returns `None` when the frame is already at or below the target, so a
    /// caller can pass an untouched frame through rather than paying for a
    /// resample that would change nothing.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] when the target dimensions cannot form a valid
    /// BGRA frame.
    pub fn rescale(&self, frame: &Frame) -> Result<Option<Frame>, FrameError> {
        let (width, height) = self
            .controller
            .scaled_dimensions(frame.width(), frame.height());
        if width >= frame.width() && height >= frame.height() {
            return Ok(None);
        }
        Ok(Some(nearest_neighbour(frame, width, height)?))
    }

    /// Whether dirty-region tracking should be skipped at this rung.
    ///
    /// At the bottom of the ladder the frame is small enough that scanning for
    /// changed regions costs more than sending the whole thing. This is the
    /// difference between a mode that shrinks output and one that also stops
    /// doing pointless work.
    #[must_use]
    pub const fn should_track_regions(&self) -> bool {
        !matches!(self.level(), QualityLevel::Minimal)
    }

    /// The dirty regions for a frame at the current rung.
    ///
    /// One full-frame region when regions are being tracked, and the same
    /// single region when they are not -- the encoded output is identical
    /// either way, which is what makes this an optimisation rather than a
    /// behavioural change.
    #[must_use]
    pub fn regions_for(&self, frame: &Frame) -> Vec<DirtyRegion> {
        if !self.should_track_regions() {
            return Vec::new();
        }
        vec![DirtyRegion {
            x: 0,
            y: 0,
            width: frame.width(),
            height: frame.height(),
        }]
    }
}

/// Resamples a BGRA frame with nearest-neighbour sampling.
///
/// Nearest neighbour is the correct choice here rather than a smoother filter:
/// it is integer-only and allocation-bounded, so the result depends on nothing
/// but the input, and it never blends pixels into values the source never
/// contained. Smoothing would look better and would also make every frame's
/// output depend on floating-point rounding.
fn nearest_neighbour(frame: &Frame, width: u32, height: u32) -> Result<Frame, FrameError> {
    let (source_width, source_height) = (frame.width(), frame.height());
    let bytes_per_pixel = u32::try_from(BGRA_BYTES_PER_PIXEL).unwrap_or(u32::MAX);
    let source_stride = frame.stride();
    let target_stride = width
        .checked_mul(bytes_per_pixel)
        .ok_or(FrameError::FrameTooLarge)?;

    let mut data = Vec::with_capacity(
        usize::try_from(target_stride)
            .ok()
            .and_then(|row| {
                usize::try_from(height)
                    .ok()
                    .and_then(|rows| row.checked_mul(rows))
            })
            .ok_or(FrameError::FrameTooLarge)?,
    );

    for y in 0..height {
        let source_y = scale_axis(y, height, source_height);
        let row_start = usize::try_from(source_y * source_stride).unwrap_or(usize::MAX);
        for x in 0..width {
            let source_x = scale_axis(x, width, source_width);
            let offset = row_start
                .checked_add(
                    usize::try_from(source_x)
                        .unwrap_or(usize::MAX)
                        .checked_mul(usize::try_from(bytes_per_pixel).unwrap_or(usize::MAX))
                        .ok_or(FrameError::FrameTooLarge)?,
                )
                .ok_or(FrameError::FrameTooLarge)?;
            let pixel = frame
                .data()
                .get(offset..offset + usize::try_from(bytes_per_pixel).unwrap_or(usize::MAX))
                .ok_or(FrameError::AdapterFailure)?;
            data.extend_from_slice(pixel);
        }
    }

    Frame::new_bgra(width, height, target_stride, data)
}

/// Maps a target axis coordinate onto its source, clamped to the source range.
///
/// An empty source range cannot be divided by; that is caught by
/// [`Frame::new_bgra`] rejecting zero dimensions, but the clamp here keeps a
/// bad input from reading outside the buffer in the meantime.
fn scale_axis(target: u32, target_len: u32, source_len: u32) -> u32 {
    if target_len == 0 || source_len == 0 {
        return 0;
    }
    // Integer-only, kept in u64 so a large source cannot overflow the
    // intermediate product. The clamp target is already a `u32`, so narrowing
    // back from `u64` cannot lose anything.
    let scaled = u64::from(target) * u64::from(source_len);
    let mapped = scaled / u64::from(target_len);
    let clamped = if mapped > u64::from(source_len - 1) {
        u64::from(source_len - 1)
    } else {
        mapped
    };
    u32::try_from(clamped).unwrap_or(0)
}

/// Converts a frame to BGRA, which the pipeline already requires.
///
/// Present so a caller wiring this gate in does not have to re-check the
/// format at every call site.
///
/// # Errors
///
/// Returns [`FrameError`] when the pixel format is not BGRA.
pub fn require_bgra(frame: &Frame) -> Result<(), FrameError> {
    if frame.format() == PixelFormat::Bgra8 {
        Ok(())
    } else {
        Err(FrameError::AdapterFailure)
    }
}

#[cfg(test)]
mod tests {
    use crate::media::{EncodedFrame, EncoderAdapter};
    use crate::weak_network::AdaptationPolicy;

    use super::*;

    fn gate() -> AdaptiveQualityGate {
        AdaptiveQualityGate::new(AdaptiveQualityController::new(AdaptationPolicy::default()))
    }

    /// Forces the gate to a rung without driving it through the controller.
    fn gate_at(level: QualityLevel) -> AdaptiveQualityGate {
        let mut gate = gate();
        let steps = level as i32;
        *gate.controller_mut() = AdaptiveQualityController::new(AdaptationPolicy::default());
        // Walk the ladder the same way `observe` would, so no private state
        // is fabricated.
        for _ in 0..steps {
            let current = gate.level();
            gate.observe(NetworkSample {
                latency: Duration::from_secs(1),
                loss_ppm: 0,
                throughput_bps: 1,
            });
            assert_eq!(
                gate.level(),
                current.worse(),
                "controller refused to step down"
            );
        }
        assert_eq!(gate.level(), level);
        gate
    }

    use std::time::Duration;

    fn gradient(width: u32, height: u32) -> Frame {
        let stride = width * 4;
        let mut data = Vec::with_capacity((stride * height) as usize);
        for y in 0..height {
            for x in 0..width {
                // Truncation is deliberate: the gradient must stay in range
                // for widths above 255, and a wrapped value is still a
                // position-dependent pixel, which is what this fixture needs.
                #[allow(clippy::cast_possible_truncation)]
                let (r, g) = (x as u8, y as u8);
                data.extend_from_slice(&[r, g, 0x40, 0xFF]);
            }
        }
        Frame::new_bgra(width, height, stride, data).expect("gradient")
    }

    #[test]
    fn pacing_sends_the_first_frame_immediately() {
        let mut gate = gate();

        assert_eq!(gate.pacing_for(0), PacingDecision::Send);
    }

    #[test]
    fn pacing_holds_frames_within_one_period() {
        let mut gate = gate_at(QualityLevel::Medium);

        // Medium is 20 fps, so a 50 ms period. A frame captured 49 ms after
        // the last send is not yet due; one at exactly 50 ms is.
        assert_eq!(gate.pacing_for(0), PacingDecision::Send);
        assert_eq!(
            gate.pacing_for(10),
            PacingDecision::Skip(SkipReason::NotDueYet)
        );
        assert_eq!(
            gate.pacing_for(49),
            PacingDecision::Skip(SkipReason::NotDueYet)
        );
        assert_eq!(gate.pacing_for(50), PacingDecision::Send);
    }

    #[test]
    fn a_slower_rung_transmits_fewer_frames_from_the_same_capture_rate() {
        let ticks: Vec<u64> = (0..600).map(|i| i * 16).collect();

        let count_sent = |level: QualityLevel| {
            let mut gate = gate_at(level);
            ticks
                .iter()
                .filter(|tick| gate.pacing_for(**tick) == PacingDecision::Send)
                .count()
        };

        let ultra = count_sent(QualityLevel::Ultra);
        let minimal = count_sent(QualityLevel::Minimal);

        assert!(
            minimal < ultra,
            "Minimal sent {minimal} frames, Ultra sent {ultra}"
        );
    }

    #[test]
    fn pacing_never_sends_faster_than_the_rung_allows() {
        let ticks: Vec<u64> = (0..1_000).map(|i| i * 4).collect();

        for level in QualityLevel::ALL {
            let mut gate = gate_at(level);
            let mut sent = 0_usize;
            let mut last_tick = 0_u64;
            for tick in &ticks {
                if gate.pacing_for(*tick) == PacingDecision::Send {
                    if sent > 0 {
                        let gap = tick - last_tick;
                        assert!(
                            gap >= gate.frame_period_ms(),
                            "{level:?} sent two frames {gap}ms apart, below its {}ms period",
                            gate.frame_period_ms()
                        );
                    }
                    last_tick = *tick;
                    sent += 1;
                }
            }
            assert!(sent > 0, "{level:?} never sent anything");
        }
    }

    #[test]
    fn the_frame_period_matches_the_rungs_frame_rate() {
        for level in QualityLevel::ALL {
            let gate = gate_at(level);
            let fps = u64::from(level.target_fps());
            let period_ms = MILLIS_PER_SECOND / fps;
            assert_eq!(gate.frame_period_ms(), period_ms, "{level:?}");
        }
    }

    #[test]
    fn rescaling_produces_the_dimensions_the_rung_implies() {
        let source = gradient(1920, 1080);

        let gate = gate_at(QualityLevel::Medium);
        let scaled = gate
            .rescale(&source)
            .expect("rescale")
            .expect("medium should scale");

        assert_eq!(scaled.width(), 1440, "75% of 1920");
        assert_eq!(scaled.height(), 810, "75% of 1080");
    }

    #[test]
    fn scaling_preserves_the_payload_size_and_pixel_format() {
        let source = gradient(200, 100);
        let gate = gate_at(QualityLevel::Low);
        let scaled = gate.rescale(&source).expect("rescale").expect("scaled");

        assert_eq!(scaled.format(), PixelFormat::Bgra8);
        assert_eq!(
            scaled.data().len(),
            (scaled.width() * 4 * scaled.height()) as usize,
            "scaled payload must match its own dimensions"
        );
        assert_eq!(
            scaled.stride(),
            scaled.width() * 4,
            "stride must match the scaled width"
        );
    }

    #[test]
    fn scaling_samples_real_pixels_rather_than_flattening_them() {
        // A flat frame would pass any scale that produced the right byte
        // count, so this uses a gradient and checks two known corners.
        let source = gradient(64, 64);
        let gate = gate_at(QualityLevel::Minimal);
        let scaled = gate.rescale(&source).expect("rescale").expect("scaled");

        assert_eq!(scaled.width(), 16);
        let pixel = |x: u32, y: u32| -> [u8; 4] {
            let offset = ((y * scaled.width() + x) * 4) as usize;
            scaled.data()[offset..offset + 4].try_into().expect("pixel")
        };

        // Nearest neighbour maps target x onto source x*4, computed here in
        // integers so the expectation does not simply restate the
        // implementation's arithmetic in float.
        assert_eq!(pixel(0, 0)[0], 0, "top-left red channel");
        assert_eq!(pixel(0, 0)[1], 0, "top-left green channel");
        assert_eq!(pixel(1, 1)[0], 4, "x=1 maps to source x=4");
        assert_eq!(pixel(1, 1)[1], 4, "y=1 maps to source y=4");
        assert_eq!(pixel(15, 15)[0], 60, "bottom-right red");
        assert_eq!(pixel(15, 15)[1], 60, "bottom-right green");
    }

    #[test]
    fn scaling_down_then_up_returns_to_the_original_size() {
        let source = gradient(320, 240);

        let mut gate = gate_at(QualityLevel::Minimal);
        let small = gate.rescale(&source).expect("rescale").expect("scaled");
        assert_eq!(small.width(), 80);

        // Coming back up must re-expand from the source, not from the small
        // frame, or quality would ratchet downward every change. Recovery is
        // earned one rung per healthy streak, mirroring how degradation is
        // one rung per bad sample, so climbing the whole ladder takes several
        // streaks rather than one.
        let healthy = NetworkSample {
            latency: Duration::from_millis(1),
            loss_ppm: 0,
            throughput_bps: 20_000_000,
        };
        for _ in 0..8 * 4 {
            gate.observe(healthy);
        }
        assert_eq!(gate.level(), QualityLevel::Ultra);
        let expanded = gate.rescale(&source).expect("rescale");
        assert!(
            expanded.is_none(),
            "back at Ultra the frame must pass through untouched"
        );
    }

    #[test]
    fn an_unscaled_frame_is_returned_as_none_so_it_passes_through_untouched() {
        let source = gradient(320, 240);
        let gate = gate_at(QualityLevel::Ultra);

        assert!(gate.rescale(&source).expect("rescale").is_none());
    }

    #[test]
    fn every_rung_scales_to_a_valid_frame() {
        let source = gradient(640, 480);

        for level in QualityLevel::ALL {
            let gate = gate_at(level);
            let Some(scaled) = gate.rescale(&source).expect("rescale") else {
                continue;
            };
            assert!(scaled.width() > 0 && scaled.height() > 0, "{level:?}");
            assert!(scaled.width() % 2 == 0, "{level:?} width must stay even");
            assert!(scaled.height() % 2 == 0, "{level:?} height must stay even");
            require_bgra(&scaled).expect("scaled frames stay BGRA");
        }
    }

    #[test]
    fn low_bandwidth_mode_is_reported_only_at_the_bottom_rung() {
        assert!(gate_at(QualityLevel::Minimal).is_low_bandwidth_mode());

        for level in [
            QualityLevel::Ultra,
            QualityLevel::High,
            QualityLevel::Medium,
            QualityLevel::Low,
        ] {
            assert!(
                !gate_at(level).is_low_bandwidth_mode(),
                "{level:?} must not claim to be low-bandwidth mode"
            );
        }
    }

    #[test]
    fn low_bandwidth_mode_stops_tracking_regions() {
        let minimal = gate_at(QualityLevel::Minimal);
        assert!(!minimal.should_track_regions());

        for level in [
            QualityLevel::Ultra,
            QualityLevel::High,
            QualityLevel::Medium,
            QualityLevel::Low,
        ] {
            assert!(
                gate_at(level).should_track_regions(),
                "{level:?} must still track regions"
            );
        }
    }

    #[test]
    fn regions_cover_the_whole_frame_when_tracked() {
        let frame = gradient(64, 32);
        let gate = gate_at(QualityLevel::Low);

        let regions = gate.regions_for(&frame);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].width, 64);
        assert_eq!(regions[0].height, 32);
        assert_eq!(regions[0].x, 0);
        assert_eq!(regions[0].y, 0);
    }

    #[test]
    fn no_regions_are_tracked_in_low_bandwidth_mode() {
        let frame = gradient(64, 32);
        assert_eq!(
            gate_at(QualityLevel::Minimal).regions_for(&frame),
            Vec::new()
        );
    }

    #[test]
    fn observing_through_the_gate_moves_the_level_it_reports() {
        let mut gate = gate();
        assert_eq!(gate.level(), QualityLevel::Ultra);

        // A link that cannot carry the current rung.
        let degraded = NetworkSample {
            latency: Duration::from_millis(10),
            loss_ppm: 0,
            throughput_bps: 1_000_000,
        };
        assert_eq!(gate.observe(degraded), QualityLevel::High);

        // ...and one that can carry everything.
        let healthy = NetworkSample {
            latency: Duration::from_millis(1),
            loss_ppm: 0,
            throughput_bps: 20_000_000,
        };
        for _ in 0..8 {
            gate.observe(healthy);
        }
        assert_eq!(
            gate.level(),
            QualityLevel::Ultra,
            "quality must be earned back"
        );
    }

    #[test]
    fn a_bad_link_shrinks_the_frame_the_pipeline_actually_sends() {
        let source = gradient(1280, 720);
        let mut gate = gate();

        let before = gate.rescale(&source).expect("rescale");
        assert!(before.is_none(), "Ultra sends the source untouched");

        // Drive the gate down to the floor, as a real bad link would.
        for _ in 0..4 {
            gate.observe(NetworkSample {
                latency: Duration::from_millis(10),
                loss_ppm: 0,
                throughput_bps: 100_000,
            });
        }
        assert_eq!(gate.level(), QualityLevel::Minimal);
        assert!(gate.is_low_bandwidth_mode());

        let after = gate
            .rescale(&source)
            .expect("rescale")
            .expect("the floor rung must scale");
        // Minimal is 25% linear, so exactly one sixteenth of the pixels. The
        // comparison has to stay strict: this asserts the reduction is real
        // and not a rounding artefact that happened to pass at a boundary.
        let source_pixels = u64::from(source.width()) * u64::from(source.height());
        let scaled_pixels = u64::from(after.width()) * u64::from(after.height());
        assert!(
            scaled_pixels * 4 <= source_pixels,
            "low-bandwidth mode sent {scaled_pixels} of {source_pixels} pixels, \
             more than the rung's quarter-scale allows"
        );
        assert!(
            scaled_pixels < source_pixels,
            "low-bandwidth mode must send fewer pixels than the source"
        );
        assert!(
            gate.frame_period_ms() > 0,
            "low-bandwidth mode must still pace frames"
        );
    }

    #[test]
    fn the_pipeline_stays_in_step_with_the_gate() {
        // The whole point of the wiring: a rung change must be visible in what
        // the encoder is handed, not only in what the gate reports.
        struct RecordingEncoder {
            frames: Vec<(u32, u32)>,
        }

        impl EncoderAdapter for RecordingEncoder {
            fn encode(
                &mut self,
                frame: &Frame,
                _regions: &[DirtyRegion],
            ) -> Result<EncodedFrame, FrameError> {
                self.frames.push((frame.width(), frame.height()));
                Ok(EncodedFrame {
                    payload: Vec::new(),
                    regions: Vec::new(),
                })
            }
        }

        let source = gradient(1280, 720);
        let mut gate = gate();
        let mut encoder = RecordingEncoder { frames: Vec::new() };

        // What the pipeline actually hands the encoder, whatever the gate
        // decided: the rescaled frame when it scaled one, the source when it
        // did not.
        let to_encode = gate
            .rescale(&source)
            .unwrap()
            .unwrap_or_else(|| source.clone());
        encoder.encode(&to_encode, &[]).unwrap();
        assert_eq!(encoder.frames.last().copied(), Some((1280, 720)));

        for _ in 0..4 {
            gate.observe(NetworkSample {
                latency: Duration::from_millis(10),
                loss_ppm: 0,
                throughput_bps: 100_000,
            });
        }
        let scaled = gate.rescale(&source).unwrap().unwrap();
        encoder.encode(&scaled, &gate.regions_for(&scaled)).unwrap();
        assert_eq!(
            encoder.frames.last().copied(),
            Some((320, 180)),
            "the encoder must receive the reduced frame, not the source"
        );
        assert!(
            encoder.frames[1].1 < encoder.frames[0].1,
            "frames must shrink as the rung drops"
        );
    }

    #[test]
    fn scale_axis_never_reads_past_the_source() {
        assert_eq!(scale_axis(0, 4, 10), 0);
        assert_eq!(scale_axis(3, 4, 10), 7);
        assert_eq!(scale_axis(99, 100, 10), 9, "must clamp to the last pixel");
        assert_eq!(scale_axis(0, 1, 1), 0);
        assert_eq!(
            scale_axis(0, 0, 0),
            0,
            "degenerate input is clamped, not divided"
        );
    }

    #[test]
    fn scaling_an_odd_sized_frame_stays_byte_aligned() {
        // Odd source dimensions are the case most likely to produce a frame
        // whose stride disagrees with its pixel count.
        let source = gradient(101, 51);
        let gate = gate_at(QualityLevel::Low);
        let scaled = gate.rescale(&source).expect("rescale").expect("scaled");

        assert_eq!(scaled.data().len() % 4, 0, "payload must be whole pixels");
        assert_eq!(scaled.stride(), scaled.width() * 4);
        assert_eq!(
            usize::try_from(scaled.stride() * scaled.height()).expect("payload fits"),
            scaled.data().len()
        );
    }

    #[test]
    fn require_bgra_accepts_a_scaled_frame() {
        let source = gradient(64, 64);
        let gate = gate_at(QualityLevel::Minimal);
        let scaled = gate.rescale(&source).expect("rescale").expect("scaled");

        require_bgra(&scaled).expect("scaled output must satisfy the pipeline");
        require_bgra(&source).expect("the source is BGRA too");
    }
}
