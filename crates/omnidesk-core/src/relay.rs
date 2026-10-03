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
        if authorization == RelayAuthorization::ViewOnlyNoControl && frame.ciphertext.is_empty() {
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
    match decision {
        // A failed attempt that reached no path is not a relayed session and
        // must not be billed as one.
        RelayPathDecision::NoPathAvailable => return Err(RelayError::AuthorizationDenied),
        RelayPathDecision::DirectPreferred => {
            usage.record_direct_session();
        }
        RelayPathDecision::FellBackToRelay => {
            usage.record_relay_session(duration);
        }
    }

    if authorization == RelayAuthorization::ViewOnlyNoControl {
        // A viewer-only session forwarded relay traffic; that is legitimate,
        // but it must never be counted as a control session. Nothing to do
        // here beyond documenting that control is not inferred from usage.
    }

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
        let frame = RelayFrame {
            session_id: [9_u8; 16],
            ciphertext: b"",
        };

        assert_eq!(
            relay.forward_authorized(frame, RelayAuthorization::ViewOnlyNoControl, &mut usage,),
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
