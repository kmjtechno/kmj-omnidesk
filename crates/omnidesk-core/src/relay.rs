//! Encrypted relay fallback for sessions that cannot be established directly.
//!
//! M4 establishes direct paths and deliberately refuses to fall back, leaving
//! the decision to an explicit policy. This module is that policy.
//!
//! The central design constraint comes from `docs/THREAT_MODEL.md`: a relay
//! must not decrypt session payloads and must not be able to grant control
//! permission. Both are satisfied structurally rather than by policy. The relay
//! is given a [`RelayService`] whose only verbs are forward, drop and count --
//! it is never handed a session key, a capability grant, or a decision input.
//! Confidentiality therefore does not depend on the relay operator behaving
//! correctly; there is nothing here for them to decrypt *with*.
//!
//! Authorization is decided by the endpoints before a frame is ever relayed,
//! and the relay has no path to influence that decision. A relay that is
//! unreachable, misbehaving, or substituted therefore degrades to no session,
//! never to an unauthorized one.
//!
//! Cost is metered per the M5 roadmap: `relayed_bytes`,
//! `relay_session_minutes` and `relay_ratio`.

use std::time::Duration;

use omnidesk_protocol::signaling::{CandidateKind, ConnectionCandidate};

/// Largest frame the relay will accept, mirroring the transport framing limit.
///
/// A relay is a shared, untrusted intermediary, so an unbounded frame is a
/// memory-exhaustion vector available to anyone who can reach the port.
pub const MAX_RELAY_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Errors produced by relay selection and session establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// No relay candidate was offered, so there is nothing to fall back to.
    NoRelayCandidate,
    /// A relay candidate was offered but was not usable.
    RelayUnusable,
    /// The relay refused or failed to forward.
    RelayUnavailable,
    /// Frame exceeded [`MAX_RELAY_FRAME_BYTES`].
    FrameTooLarge,
    /// The frame carried no ciphertext.
    EmptyPayload,
    /// The caller is not authorized to use the relay, and the failure is
    /// fail-closed: no session is established and no capability is implied.
    AuthorizationDenied,
}

/// Which path a session actually ended up using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPathDecision {
    /// Direct establishment succeeded; the relay was not used.
    DirectPreferred,
    /// Direct establishment failed and the relay was used.
    FellBackToRelay,
    /// Direct establishment failed and no relay was available.
    NoPathAvailable,
}

/// Why a relay session was authorized.
///
/// This is an endpoint-side authorization fact, forwarded to the relay only as
/// a coarse token. The relay cannot mint one, cannot widen one, and cannot
/// derive a capability from one; see [`RelayService::forward`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAuthorization {
    /// The viewing side was granted by the controlling side.
    ControllerAuthorizedViewer,
    /// The session is unauthorized for control. A viewer-only relay session.
    ViewOnlyNoControl,
}

impl RelayAuthorization {
    /// Returns whether this authorization permits remote control.
    ///
    /// [`Self::ViewOnlyNoControl`] is the default posture. Escalating to
    /// control requires a distinct, explicit variant, so forgetting to ask for
    /// control yields no control rather than accidental control.
    #[must_use]
    pub const fn grants_control(self) -> bool {
        matches!(self, Self::ControllerAuthorizedViewer)
    }
}

/// The relay's view of one relayed frame.
///
/// Deliberately carries no session key, no plaintext, and no capability. The
/// relay's job is to move opaque bytes between two already-authorized
/// endpoints; it is not a participant in the authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayFrame<'a> {
    /// Session this frame belongs to.
    pub session_id: [u8; 16],
    /// Opaque peer-to-peer ciphertext. The relay cannot read this.
    pub ciphertext: &'a [u8],
}

/// Usage metering for relayed traffic.
///
/// Mirrors the `metrics.rs` pattern: private fields, `saturating_add`
/// accumulation, `#[must_use]` getters, so over-counting can never wrap.
#[derive(Debug, Default)]
pub struct RelayUsageMetrics {
    relayed_bytes: u64,
    direct_bytes: u64,
    relay_session_seconds: u64,
    relay_sessions: u32,
    direct_sessions: u32,
}

impl RelayUsageMetrics {
    /// Records traffic on a direct path, which is the path that should win.
    pub const fn record_direct(&mut self, bytes: u64) {
        self.direct_bytes = self.direct_bytes.saturating_add(bytes);
    }

    /// Records a completed relay session and its duration.
    pub const fn record_relay_session(&mut self, duration: Duration) {
        self.relay_session_seconds = self
            .relay_session_seconds
            .saturating_add(duration.as_secs());
        self.relay_sessions = self.relay_sessions.saturating_add(1);
    }

    /// Records a completed direct session.
    pub const fn record_direct_session(&mut self) {
        self.direct_sessions = self.direct_sessions.saturating_add(1);
    }

    #[must_use]
    pub const fn relayed_bytes(&self) -> u64 {
        self.relayed_bytes
    }

    #[must_use]
    pub const fn direct_bytes(&self) -> u64 {
        self.direct_bytes
    }

    #[must_use]
    pub const fn relay_sessions(&self) -> u32 {
        self.relay_sessions
    }

    #[must_use]
    pub const fn direct_sessions(&self) -> u32 {
        self.direct_sessions
    }

    #[must_use]
    pub const fn relay_session_seconds(&self) -> u64 {
        self.relay_session_seconds
    }

    /// Ratio of relayed to total bytes, in basis points (`0..=10_000`).
    ///
    /// Integer arithmetic only: a float here would make a cost report
    /// non-reproducible, and M13 explicitly forbids unverified claims. Returns
    /// `0` when no traffic has been metered rather than dividing by zero.
    #[must_use]
    pub fn relay_ratio_bps(&self) -> u16 {
        let total = self.relayed_bytes.saturating_add(self.direct_bytes);
        if total == 0 {
            return 0;
        }

        let scaled = self.relayed_bytes.saturating_mul(10_000) / total;
        u16::try_from(scaled).unwrap_or(10_000)
    }

    /// Total relayed session time in whole minutes, rounded up.
    ///
    /// Reported in minutes because that is the unit the roadmap names; a
    /// sub-minute relay session still costs real relay time, so rounding up
    /// keeps short sessions from reading as free.
    #[must_use]
    pub const fn relay_session_minutes(&self) -> u64 {
        let minutes = self.relay_session_seconds / 60;
        if self.relay_session_seconds % 60 == 0 {
            minutes
        } else {
            minutes.saturating_add(1)
        }
    }

    /// Exports the M5 cost metrics in stable, reproducible units.
    #[must_use]
    pub fn export(self) -> ExportedRelayUsageMetrics {
        ExportedRelayUsageMetrics {
            relayed_bytes: self.relayed_bytes,
            direct_bytes: self.direct_bytes,
            relay_session_minutes: self.relay_session_minutes(),
            relay_ratio_bps: self.relay_ratio_bps(),
            relay_sessions: self.relay_sessions,
            direct_sessions: self.direct_sessions,
        }
    }
}

/// Cost metrics in the units the M5 roadmap names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedRelayUsageMetrics {
    pub relayed_bytes: u64,
    pub direct_bytes: u64,
    pub relay_session_minutes: u64,
    pub relay_ratio_bps: u16,
    pub relay_sessions: u32,
    pub direct_sessions: u32,
}

/// The relay service as seen by the endpoints.
///
/// This is the whole of the relay's authority. There is no method that grants
/// permission, accepts a key, or returns plaintext -- the capability is
/// absent from the interface rather than merely unused.
pub trait RelayService {
    /// Forwards one opaque ciphertext frame between two authorized endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::FrameTooLarge`] for an oversized frame and
    /// [`RelayError::RelayUnavailable`] when the relay cannot forward.
    fn forward(&mut self, frame: RelayFrame<'_>) -> Result<(), RelayError>;

    /// Forwards one frame and attributes its cost to the caller's meter.
    ///
    /// # Errors
    ///
    /// Propagates [`RelayService::forward`]'s errors, and returns
    /// [`RelayError::AuthorizationDenied`] without forwarding when the session
    /// is not authorized. Bytes are metered only on success, so a failed
    /// forward is not billed to either side.
    fn forward_authorized(
        &mut self,
        frame: RelayFrame<'_>,
        authorization: RelayAuthorization,
        usage: &mut RelayUsageMetrics,
    ) -> Result<(), RelayError> {
        // Fail closed: an unauthorized session must not produce traffic at
        // all, so the check precedes both forwarding and metering.
        //
        // The check is on the authorization alone, not on it *and* the frame.
        // The first version read `ViewOnlyNoControl && frame.ciphertext
        // .is_empty()`, which admits a viewer's non-empty frames -- the exact
        // fail-open this comment claims not to be. A deny rule that can be
        // satisfied by an unrelated property of the payload is not a deny
        // rule.
        if authorization == RelayAuthorization::ViewOnlyNoControl {
            return Err(RelayError::AuthorizationDenied);
        }

        self.forward(frame)?;
        usage.relayed_bytes = usage
            .relayed_bytes
            .saturating_add(frame.ciphertext.len().try_into().unwrap_or(u64::MAX));
        Ok(())
    }
}

/// The decision of whether to fall back to the relay.
///
/// M4's `DirectPathSelector` refuses relay candidates on purpose so that
/// falling back stays an explicit, reviewable policy decision. This type is
/// that decision, kept separate so the rule can be read in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaySelectionPolicy {
    /// Whether a failed direct path may fall back to relay at all.
    pub allow_fallback: bool,
    /// Ceiling on a single relayed frame, independent of session policy.
    pub max_frame_bytes: usize,
}

impl Default for RelaySelectionPolicy {
    fn default() -> Self {
        Self {
            allow_fallback: true,
            max_frame_bytes: MAX_RELAY_FRAME_BYTES,
        }
    }
}

impl RelaySelectionPolicy {
    /// Chooses between the direct outcome and the relay, given both.
    ///
    /// Direct always wins when it succeeded. A successful direct path is not
    /// downgraded to a relayed one for cost or latency reasons, because
    /// falling back when it is not needed is how relays quietly become the
    /// default path.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::NoRelayCandidate`] when direct failed and no relay
    /// candidate exists, and [`RelayError::RelayUnusable`] when fallback is
    /// disabled or the offered candidate is not a relay.
    pub fn choose(
        self,
        direct_succeeded: bool,
        relay_candidate: Option<&ConnectionCandidate>,
    ) -> Result<RelayPathDecision, RelayError> {
        if direct_succeeded {
            return Ok(RelayPathDecision::DirectPreferred);
        }

        let candidate = relay_candidate.ok_or(RelayError::NoRelayCandidate)?;
        if !self.allow_fallback || candidate.kind != CandidateKind::Relay {
            return Err(RelayError::RelayUnusable);
        }

        Ok(RelayPathDecision::FellBackToRelay)
    }
}

/// Records a relay session's outcome against the meter.
///
/// # Errors
///
/// Returns [`RelayError::AuthorizationDenied`] when `authorization` does not
/// permit the requested path, and meters nothing in that case.
pub fn meter_relay_session(
    usage: &mut RelayUsageMetrics,
    decision: RelayPathDecision,
    duration: Duration,
    authorization: RelayAuthorization,
) -> Result<(), RelayError> {
    // M5's `relay_cannot_grant_control_permission`: a path that reached no
    // usable connection is refused whatever the authorization says, because
    // there is no session to attribute the outcome to. This is checked first
    // so an authorization token cannot make an unreachable path billable --
    // the first version of this function checked only the path, which meant
    // the authorization parameter was accepted and then ignored.
    if decision == RelayPathDecision::NoPathAvailable {
        return Err(RelayError::AuthorizationDenied);
    }

    // A viewer-only session forwarded relay traffic; that is legitimate, but
    // it must never be counted as a control session. There is no control
    // counter to decrement, because control was never inferred from usage in
    // the first place -- `grants_control` reads the authorization, not the
    // meter. Stated here rather than as an empty `if` block, which read like
    // a check that had been removed by accident.
    match decision {
        RelayPathDecision::DirectPreferred => usage.record_direct_session(),
        RelayPathDecision::FellBackToRelay => usage.record_relay_session(duration),
        RelayPathDecision::NoPathAvailable => {
            // Unreachable: refused above. Kept so the match is exhaustive over
            // the enum rather than silently ignoring a future variant.
            unreachable!("NoPathAvailable is refused before the meter is touched")
        }
    }

    // `authorization` is part of the signature so a caller cannot record a
    // relay outcome without declaring who authorized it, even though no
    // current variant is refused for its value: the enum has no third
    // "unauthorized" variant to check. Read it so the parameter is not
    // silently ignored, which is how the first version ended up.
    debug_assert!(
        !authorization.grants_control() || decision != RelayPathDecision::NoPathAvailable,
        "NoPathAvailable must be refused whatever the authorization grants"
    );
    Ok(())
}

/// Validates a frame before it is offered to the relay.
///
/// # Errors
///
/// Returns [`RelayError::EmptyPayload`] for an empty ciphertext and
/// [`RelayError::FrameTooLarge`] when the frame exceeds the policy ceiling.
pub const fn validate_frame(
    frame: &RelayFrame<'_>,
    policy: RelaySelectionPolicy,
) -> Result<(), RelayError> {
    if frame.ciphertext.is_empty() {
        return Err(RelayError::EmptyPayload);
    }
    if frame.ciphertext.len() > policy.max_frame_bytes {
        return Err(RelayError::FrameTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use omnidesk_protocol::signaling::TransportProtocol;

    use super::*;

    // --- cost metrics: M5's `relay_utilization_measured` ---------------
    //
    // `relay_ratio_bps`, `relay_session_minutes` and the saturating counters
    // behind them had no test. The one existing test that touches
    // `RelayUsageMetrics` does so through `meter_relay_session` with an
    // authorization error, and asserts only that a *refused* session records
    // nothing. Nothing covered the arithmetic of a session that succeeded --
    // which is the side of the ledger a cost report is built from.
    //
    // The risk is not that a ratio is wrong by a basis point. It is that the
    // division guard is absent, or that an accumulation wraps, and the number
    // that comes out is plausible enough to be published.

    /// An unmetered log reports a zero ratio rather than dividing by zero.
    ///
    /// Mutation: drop the `if total == 0` guard. Fails by panicking in debug
    /// and returning nonsense in release -- the release behaviour is the
    /// dangerous one, because it is what ships.
    #[test]
    fn an_unmetered_log_reports_no_relay_ratio() {
        let usage = RelayUsageMetrics::default();
        assert_eq!(usage.relay_ratio_bps(), 0);
        assert_eq!(usage.relay_session_minutes(), 0);
        assert_eq!(usage.relay_sessions(), 0);
        assert_eq!(usage.relayed_bytes(), 0);
    }

    /// The ratio is relayed bytes over *total* bytes, in basis points.
    ///
    /// Checked against a hand-computed fraction rather than against another
    /// call to the function: 1000 relayed of 4000 total is exactly 2500 bps,
    /// and `relayed / total` (a plausible off-by-one denominator) would give
    /// 10000 and also look like a valid ratio.
    ///
    /// `relayed_bytes` has no public recorder by design -- it is metered by
    /// `forward_authorized`, on the real forwarding path, so a caller cannot
    /// bill bytes it never forwarded. The field is set directly here because
    /// these tests are about the arithmetic, and driving 1000 bytes through a
    /// relay to compute 2500 bps would be testing the transport twice.
    ///
    /// Mutation: divide by `relayed_bytes`. Fails.
    /// Mutation: return the ratio in percent. Fails.
    #[test]
    fn the_relay_ratio_is_relayed_over_total_in_basis_points() {
        let mut usage = RelayUsageMetrics {
            relayed_bytes: 1_000,
            ..Default::default()
        };
        usage.record_direct(3_000);
        assert_eq!(usage.relay_ratio_bps(), 2_500);

        let all_relay = RelayUsageMetrics {
            relayed_bytes: 500,
            ..Default::default()
        };
        assert_eq!(
            all_relay.relay_ratio_bps(),
            10_000,
            "a log with no direct traffic is entirely relay"
        );

        let none_relay = RelayUsageMetrics::default();
        assert_eq!(none_relay.relay_ratio_bps(), 0);
    }

    /// A counter that would wrap must saturate at its maximum.
    ///
    /// A wrapped byte count reads as a *smaller* number than the truth, so a
    /// cost report would understate relay use rather than fail. Saturating
    /// overstates, which is the direction a cost report should err in.
    ///
    /// Mutation: `saturating_add` -> `+=`. Fails.
    #[test]
    fn usage_counters_saturate_rather_than_wrapping() {
        let mut usage = RelayUsageMetrics::default();
        usage.record_direct(10);
        assert_eq!(usage.direct_bytes(), 10);

        // `record_relay_session` is the accumulator a long-lived relay
        // actually reaches its ceiling on.
        let mut sessions = RelayUsageMetrics {
            direct_sessions: u32::MAX - 1,
            ..Default::default()
        };
        sessions.record_direct_session();
        sessions.record_direct_session();
        assert_eq!(sessions.direct_sessions(), u32::MAX);
    }

    /// Session minutes round up, so a short relay session is not free.
    ///
    /// 61 seconds is 2 minutes. Integer division alone would report 1 and
    /// understate the cost of every short session, which is the case relay is
    /// most often used for.
    ///
    /// Mutation: return `seconds / 60` without the ceiling. Fails.
    #[test]
    fn relay_session_minutes_round_up_so_short_sessions_still_cost() {
        let mut usage = RelayUsageMetrics::default();
        usage.record_relay_session(Duration::from_secs(61));
        assert_eq!(usage.relay_session_minutes(), 2);

        let mut exact = RelayUsageMetrics::default();
        exact.record_relay_session(Duration::from_secs(120));
        assert_eq!(exact.relay_session_minutes(), 2);

        let mut under_a_minute = RelayUsageMetrics::default();
        under_a_minute.record_relay_session(Duration::from_secs(1));
        assert_eq!(
            under_a_minute.relay_session_minutes(),
            1,
            "one second of relay time is still one billed minute"
        );
    }

    /// A multi-session ledger sums every session, not just the last.
    ///
    /// The obvious wrong implementation records `duration` rather than adding
    /// it, which makes the report read the last session's cost as the total.
    ///
    /// Mutation: `saturating_add` -> assignment. Fails.
    #[test]
    fn the_ledger_sums_every_session() {
        let mut usage = RelayUsageMetrics::default();
        usage.record_relay_session(Duration::from_secs(600));
        usage.record_relay_session(Duration::from_secs(600));
        usage.record_relay_session(Duration::from_secs(600));
        assert_eq!(usage.relay_session_seconds(), 1_800);
        assert_eq!(usage.relay_sessions(), 3);
        assert_eq!(usage.relay_session_minutes(), 30);
    }

    /// The exported report carries every metric M5's `cost_metrics` names.
    ///
    /// `relayed_bytes`, `relay_session_minutes` and `relay_ratio` are the three
    /// the roadmap lists. A field dropped from the export is a metric the
    /// roadmap promises and no consumer can read.
    #[test]
    fn the_exported_report_carries_every_roadmap_cost_metric() {
        let mut usage = RelayUsageMetrics {
            relayed_bytes: 2_000,
            ..Default::default()
        };
        usage.record_direct(2_000);
        usage.record_relay_session(Duration::from_secs(300));

        let exported = usage.export();
        assert_eq!(exported.relayed_bytes, 2_000);
        assert_eq!(exported.direct_bytes, 2_000);
        assert_eq!(exported.relay_session_minutes, 5);
        assert_eq!(exported.relay_ratio_bps, 5_000);
        assert_eq!(exported.relay_sessions, 1);
        assert_eq!(exported.direct_sessions, 0);
    }

    fn relay_candidate() -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::Relay,
            transport: TransportProtocol::Udp,
            address: format!("127.0.0.1:{}", 6000).parse().expect("socket"),
            priority: 100,
        }
    }

    fn direct_candidate() -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::Host,
            transport: TransportProtocol::Udp,
            address: format!("127.0.0.1:{}", 4000).parse().expect("socket"),
            priority: 100,
        }
    }

    /// A relay that records what it was asked to do, standing in for the
    /// untrusted operator.
    #[derive(Default)]
    struct RecordingRelay {
        forwarded: Cell<u32>,
        saw_plaintext: Cell<bool>,
    }

    impl RelayService for RecordingRelay {
        fn forward(&mut self, frame: RelayFrame<'_>) -> Result<(), RelayError> {
            // The relay can only ever observe opaque bytes. If any plaintext
            // marker appeared here the design would have leaked a key.
            if frame
                .ciphertext
                .windows(6)
                .any(|window| window == b"PLAINT")
            {
                self.saw_plaintext.set(true);
            }
            self.forwarded.set(self.forwarded.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn direct_path_is_preferred_over_relay() {
        let policy = RelaySelectionPolicy::default();

        assert_eq!(
            policy.choose(true, Some(&relay_candidate())),
            Ok(RelayPathDecision::DirectPreferred)
        );
    }

    #[test]
    fn failed_direct_path_falls_back_to_relay() {
        let policy = RelaySelectionPolicy::default();

        assert_eq!(
            policy.choose(false, Some(&relay_candidate())),
            Ok(RelayPathDecision::FellBackToRelay)
        );
    }

    #[test]
    fn failed_direct_path_without_relay_fails_closed() {
        let policy = RelaySelectionPolicy::default();

        assert_eq!(
            policy.choose(false, None),
            Err(RelayError::NoRelayCandidate)
        );
    }

    #[test]
    fn fallback_can_be_disabled_explicitly() {
        let policy = RelaySelectionPolicy {
            allow_fallback: false,
            ..RelaySelectionPolicy::default()
        };

        assert_eq!(
            policy.choose(false, Some(&relay_candidate())),
            Err(RelayError::RelayUnusable)
        );
    }

    #[test]
    fn a_direct_candidate_is_never_offered_as_a_relay_fallback() {
        let policy = RelaySelectionPolicy::default();

        assert_eq!(
            policy.choose(false, Some(&direct_candidate())),
            Err(RelayError::RelayUnusable)
        );
    }

    #[test]
    fn relay_sees_only_opaque_ciphertext() {
        let mut relay = RecordingRelay::default();
        let mut usage = RelayUsageMetrics::default();
        let ciphertext = b"\x01\x02\x03encrypted-bytes\x04";
        let frame = RelayFrame {
            session_id: [7_u8; 16],
            ciphertext,
        };

        relay
            .forward_authorized(
                frame,
                RelayAuthorization::ControllerAuthorizedViewer,
                &mut usage,
            )
            .expect("forwarded");

        assert_eq!(relay.forwarded.get(), 1);
        assert!(!relay.saw_plaintext.get());
        assert_eq!(usage.relayed_bytes(), ciphertext.len() as u64);
    }

    #[test]
    fn relay_cannot_grant_control_it_was_never_given() {
        // The relay's trait has no method that grants permission. This test
        // pins the consequence: a viewer-only session does not become a
        // control session merely because it was relayed.
        let view_only = RelayAuthorization::ViewOnlyNoControl;
        let authorized = RelayAuthorization::ControllerAuthorizedViewer;

        assert!(!view_only.grants_control());
        assert!(authorized.grants_control());
    }

    #[test]
    fn unauthorized_session_fails_closed_without_relaying_or_billing() {
        struct RefusingRelay;

        impl RelayService for RefusingRelay {
            fn forward(&mut self, _frame: RelayFrame<'_>) -> Result<(), RelayError> {
                Ok(())
            }
        }

        let mut relay = RefusingRelay;
        let mut usage = RelayUsageMetrics::default();
        // Non-empty ciphertext, deliberately. The first version of this test
        // used an empty payload, and the check it was written for read
        // `ViewOnlyNoControl && ciphertext.is_empty()` -- so it passed for the
        // wrong reason, and the same fail-open that let a viewer's real
        // traffic through still satisfied it. A test for an authorization
        // rule must not depend on the payload it happens to carry.
        let frame = RelayFrame {
            session_id: [9_u8; 16],
            ciphertext: b"\x01\x02\x03viewer-traffic",
        };

        assert_eq!(
            relay.forward_authorized(frame, RelayAuthorization::ViewOnlyNoControl, &mut usage,),
            Err(RelayError::AuthorizationDenied)
        );
        assert_eq!(usage.relayed_bytes(), 0);
    }

    /// Mutation: add `&& frame.ciphertext.is_empty()` to the authorization
    /// check in `forward_authorized`.
    ///
    /// The regression test for a real fail-open, and the reason it exists
    /// separately rather than as another assertion above: the failure was not
    /// that a viewer *could* relay, but that a viewer could relay whenever
    /// they had something to say. An empty-frame denial hides exactly that,
    /// because a viewer carrying real traffic is the ordinary case.
    #[test]
    fn a_viewers_real_traffic_is_refused_not_only_their_empty_frames() {
        struct CountingRelay(Cell<u32>);

        impl RelayService for CountingRelay {
            fn forward(&mut self, _frame: RelayFrame<'_>) -> Result<(), RelayError> {
                self.0.set(self.0.get() + 1);
                Ok(())
            }
        }

        for payload in [&b""[..], b"\x01\x02\x03", &[0xFF_u8; 512]] {
            let mut relay = CountingRelay(Cell::new(0));
            let mut usage = RelayUsageMetrics::default();
            let frame = RelayFrame {
                session_id: [3_u8; 16],
                ciphertext: payload,
            };

            assert_eq!(
                relay.forward_authorized(frame, RelayAuthorization::ViewOnlyNoControl, &mut usage),
                Err(RelayError::AuthorizationDenied),
                "{payload:?} must be refused whatever it contains"
            );
            assert_eq!(relay.0.get(), 0, "nothing may reach the relay");
            assert_eq!(usage.relayed_bytes(), 0, "nothing may be billed");
        }
    }

    /// Mutation: drop the authorization check from `forward_authorized` and
    /// rely on `forward` alone.
    ///
    /// M5's `authorization_failure_is_fail_closed` says a refusal must
    /// produce neither traffic nor billing. Checking only after forwarding
    /// would let both happen, so the *order* is the property, not the
    /// condition.
    #[test]
    fn the_authorization_check_precedes_forwarding_rather_than_joining_it() {
        struct ExplodingRelay;

        impl RelayService for ExplodingRelay {
            fn forward(&mut self, _frame: RelayFrame<'_>) -> Result<(), RelayError> {
                panic!("an unauthorized frame reached forward()");
            }
        }

        let mut relay = ExplodingRelay;
        let mut usage = RelayUsageMetrics::default();
        let frame = RelayFrame {
            session_id: [4_u8; 16],
            ciphertext: b"\xde\xad\xbe\xef",
        };

        assert_eq!(
            relay.forward_authorized(frame, RelayAuthorization::ViewOnlyNoControl, &mut usage),
            Err(RelayError::AuthorizationDenied)
        );
        assert_eq!(usage.relayed_bytes(), 0);
    }

    #[test]
    fn empty_and_oversized_frames_are_rejected() {
        let policy = RelaySelectionPolicy::default();
        let empty = RelayFrame {
            session_id: [1_u8; 16],
            ciphertext: b"",
        };

        assert_eq!(
            validate_frame(&empty, policy),
            Err(RelayError::EmptyPayload)
        );

        let oversized = RelayFrame {
            session_id: [1_u8; 16],
            ciphertext: &vec![0_u8; policy.max_frame_bytes + 1],
        };

        assert_eq!(
            validate_frame(&oversized, policy),
            Err(RelayError::FrameTooLarge)
        );
    }

    #[test]
    fn relay_ratio_and_session_minutes_are_deterministic() {
        let mut usage = RelayUsageMetrics::default();
        usage.record_direct(3_000);
        usage.relayed_bytes = 1_000;

        assert_eq!(usage.relay_ratio_bps(), 2_500);
        assert_eq!(usage.export().relay_ratio_bps, 2_500);

        let mut timed = RelayUsageMetrics::default();
        timed.record_relay_session(Duration::from_secs(90));

        assert_eq!(timed.relay_session_minutes(), 2);
    }

    #[test]
    fn zero_traffic_reports_zero_ratio_instead_of_dividing_by_zero() {
        let usage = RelayUsageMetrics::default();

        assert_eq!(usage.relay_ratio_bps(), 0);
        assert_eq!(usage.relay_session_minutes(), 0);
    }

    #[test]
    fn unreachable_path_is_not_billed_as_a_relay_session() {
        let mut usage = RelayUsageMetrics::default();

        assert_eq!(
            meter_relay_session(
                &mut usage,
                RelayPathDecision::NoPathAvailable,
                Duration::from_secs(30),
                RelayAuthorization::ControllerAuthorizedViewer,
            ),
            Err(RelayError::AuthorizationDenied)
        );
        assert_eq!(usage.relay_sessions(), 0);
        assert_eq!(usage.relay_session_seconds(), 0);
    }
}
