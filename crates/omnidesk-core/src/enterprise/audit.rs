//! Audit history.
//!
//! An audit log that can be rewritten is not an audit log. Two properties make
//! this one harder to forge than a `Vec<String>`:
//!
//! * **Append-only.** There is no `clear`, no `truncate`, no index setter, and
//!   no `remove`. The only mutation is `record`, which appends.
//! * **Hash-chained.** Each event carries the digest of the one before it, so
//!   removing or editing an event in the middle breaks every link after it and
//!   [`AuditLog::verify_chain`] reports exactly where.
//!
//! # What this does not claim
//!
//! A hash chain detects *edits*; it does not detect a full rewrite by someone
//! who recomputes the whole log, because there is no signing key here and
//! nothing outside this process holds a copy. An attacker with write access to
//! a `Vec<AuditEvent>` can produce a chain that verifies. What the chain buys
//! is that editing history is no longer a one-line change and that an ordinary
//! bug or a careless code path cannot silently drop an event.
//!
//! The control that closes this gap is shipping events somewhere the client
//! cannot rewrite, and it is not implemented. Recording the limit here rather
//! than letting a future reader assume the chain is a signature would be the
//! difference between a correct claim and a dangerous one.

use super::{PrincipalId, TenantId};
use core::fmt;
use sha2::Digest;

/// The longest action label accepted.
pub const MAX_ACTION_BYTES: usize = 64;

/// The longest detail string accepted.
pub const MAX_DETAIL_BYTES: usize = 256;

/// How many events this log retains.
///
/// A bound, not a policy. An unbounded in-memory log is a memory exhaustion
/// vector driven by whoever can make the product take actions, which is exactly
/// the set of people this module is defending against.
pub const MAX_EVENTS: usize = 4096;

/// What an action did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditOutcome {
    Allow,
    Deny,
    Error,
}

impl AuditOutcome {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }
}

/// One thing that happened.
///
/// Private fields, no public setters. The digest is computed once at
/// construction and never recomputed, so an event cannot be edited after the
/// fact without also editing the field itself.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    sequence: u64,
    tenant_handle: String,
    principal_handle: String,
    action: String,
    outcome: AuditOutcome,
    detail: String,
    at_epoch_seconds: u64,
    previous_digest: [u8; 32],
    digest: [u8; 32],
}

impl AuditEvent {
    /// Position in the chain. Starts at 1.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn at_epoch_seconds(&self) -> u64 {
        self.at_epoch_seconds
    }

    /// The pseudonymous tenant handle, never the tenant's own identifier.
    #[must_use]
    pub fn tenant_handle(&self) -> &str {
        &self.tenant_handle
    }

    /// The digest of the preceding event, or all-zero for the first.
    #[must_use]
    pub const fn previous_digest(&self) -> &[u8; 32] {
        &self.previous_digest
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// A short reference for this event, for correlating with an external
    /// store that also holds it.
    #[must_use]
    pub fn handle(&self) -> String {
        short_hex(&self.digest)
    }

    /// Whether this event concerns the tenant with the given handle.
    #[must_use]
    pub fn is_for_tenant_handle(&self, handle: &str) -> bool {
        self.tenant_handle == handle
    }

    /// Rewrites the outcome without recomputing the digest.
    ///
    /// Test-only, and it is the forgery: an attacker who can edit the event
    /// changes the outcome and leaves the digest alone. Exposing this lets the
    /// tamper-detection test build the tampered log it is trying to detect,
    /// rather than asserting that tampering cannot happen -- which is the claim
    /// the module docs explicitly refuse to make.
    #[cfg(test)]
    pub(crate) const fn tamper_outcome(&mut self, outcome: AuditOutcome) {
        self.outcome = outcome;
    }

    /// Points this event's back-link at an arbitrary digest.
    ///
    /// Test-only. Rewiring one link is the attack the `ChainBroken` check
    /// exists to catch, and it cannot be built from the public API.
    #[cfg(test)]
    pub(crate) const fn tamper_previous_digest(&mut self, previous_digest: [u8; 32]) {
        self.previous_digest = previous_digest;
    }

    /// Recomputes this event's own digest over its current fields.
    ///
    /// Test-only, and this is the forgery. It is what an attacker with write
    /// access to the `Vec` uses to make an edit survive a naive verifier, and
    /// exposing it is what lets `audit_a_full_rewrite_verifies` demonstrate the
    /// limit the module docs state rather than merely asserting it in prose.
    #[cfg(test)]
    pub(crate) fn reseal(&mut self) {
        self.digest = digest_of(
            self.sequence,
            &self.tenant_handle,
            &self.principal_handle,
            &self.action,
            self.outcome,
            &self.detail,
            self.at_epoch_seconds,
            &self.previous_digest,
        );
    }
}

impl fmt::Display for AuditEvent {
    /// Handles only. A tenant name or a principal id in an audit line is the
    /// re-identification vector that `log_scrubber` exists to prevent
    /// elsewhere, and the audit log has to hold the same line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} {} {} {}",
            self.sequence,
            self.tenant_handle,
            self.principal_handle,
            self.action,
            self.outcome.name()
        )
    }
}

/// An append-only, hash-chained event log.
///
/// See the module docs for what the chain does and does not prove.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
    truncated: bool,
}

impl AuditLog {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            truncated: false,
        }
    }

    /// Appends an event and returns its sequence number.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::EmptyAction`, `ActionTooLong` above
    /// [`MAX_ACTION_BYTES`], `DetailTooLong` above [`MAX_DETAIL_BYTES`], or
    /// `TimeWentBackwards` if `at_epoch_seconds` precedes the last event. The
    /// last is a tamper signal in its own right: a clock that moves backwards
    /// mid-chain means either an attacker-set client clock or a replay.
    pub fn record(
        &mut self,
        tenant: &TenantId,
        principal: &PrincipalId,
        action: &str,
        outcome: AuditOutcome,
        detail: &str,
        at_epoch_seconds: u64,
    ) -> Result<u64, AuditError> {
        if action.is_empty() {
            return Err(AuditError::EmptyAction);
        }
        if action.len() > MAX_ACTION_BYTES {
            return Err(AuditError::ActionTooLong {
                length: action.len(),
                maximum: MAX_ACTION_BYTES,
            });
        }
        if detail.len() > MAX_DETAIL_BYTES {
            return Err(AuditError::DetailTooLong {
                length: detail.len(),
                maximum: MAX_DETAIL_BYTES,
            });
        }
        if let Some(last) = self.events.last() {
            if at_epoch_seconds < last.at_epoch_seconds {
                return Err(AuditError::TimeWentBackwards {
                    previous: last.at_epoch_seconds,
                    offered: at_epoch_seconds,
                });
            }
        }

        let Some(sequence) = u64::try_from(self.events.len())
            .ok()
            .and_then(|len| len.checked_add(1))
        else {
            return Err(AuditError::LogFull);
        };

        let tenant_handle = tenant.audit_handle();
        let principal_handle = principal.audit_handle();
        let previous_digest = self
            .events
            .last()
            .map_or([0u8; 32], |event| *event.digest());

        let digest = digest_of(
            sequence,
            &tenant_handle,
            &principal_handle,
            action,
            outcome,
            detail,
            at_epoch_seconds,
            &previous_digest,
        );

        if self.events.len() >= MAX_EVENTS {
            // Bounded rather than unbounded. `truncated` is set rather than
            // silently dropped, because a chain with a hole must not look
            // like a complete history to whatever reads it.
            self.truncated = true;
            return Ok(sequence);
        }

        self.events.push(AuditEvent {
            sequence,
            tenant_handle,
            principal_handle,
            action: action.to_string(),
            outcome,
            detail: detail.to_string(),
            at_epoch_seconds,
            previous_digest,
            digest,
        });

        Ok(sequence)
    }

    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether the log dropped events at capacity.
    ///
    /// `true` here means the log is not a complete history, and any claim made
    /// from it has to say so.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn last(&self) -> Option<&AuditEvent> {
        self.events.last()
    }

    /// Every event for one tenant handle.
    #[must_use]
    pub fn events_for_tenant_handle(&self, handle: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|event| event.is_for_tenant_handle(handle))
            .collect()
    }

    /// Recomputes every digest and reports the first mismatch.
    ///
    /// Takes no arguments because it needs none: the chain commits to the
    /// *handles*, which are already digests of the tenant and principal. A
    /// verifier with read access to the log can therefore check it without
    /// also having to hold every principal identity, which is what keeps this
    /// usable by an auditor who should not be handed the identity set.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Truncated`, or the first of
    /// `SequenceGap`, `ChainBroken`, `ContentAltered`.
    pub fn verify_chain(&self) -> Result<(), AuditError> {
        if self.truncated {
            return Err(AuditError::Truncated);
        }

        let mut previous_digest = [0u8; 32];
        for (index, event) in self.events.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|len| len.checked_add(1))
                .unwrap_or(u64::MAX);
            if event.sequence != expected_sequence {
                return Err(AuditError::SequenceGap {
                    expected: expected_sequence,
                    found: event.sequence,
                });
            }
            if event.previous_digest != previous_digest {
                return Err(AuditError::ChainBroken {
                    at_sequence: event.sequence,
                });
            }
            let recomputed = digest_of(
                event.sequence,
                &event.tenant_handle,
                &event.principal_handle,
                &event.action,
                event.outcome,
                &event.detail,
                event.at_epoch_seconds,
                &event.previous_digest,
            );
            if recomputed != event.digest {
                return Err(AuditError::ContentAltered {
                    at_sequence: event.sequence,
                });
            }
            previous_digest = event.digest;
        }
        Ok(())
    }
}

impl AuditLog {
    /// Builds a log from events supplied wholesale.
    ///
    /// Test-only, and deliberately so. It is the operation an attacker with
    /// write access to the `Vec` would perform, so exposing it in the shipping
    /// API would be handing out the forgery tool. It exists here so the
    /// tamper-detection tests can construct the thing they are detecting rather
    /// than asserting that tampering is impossible.
    #[cfg(test)]
    pub(crate) const fn from_events(events: Vec<AuditEvent>) -> Self {
        Self {
            events,
            truncated: false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn digest_of(
    sequence: u64,
    tenant_handle: &str,
    principal_handle: &str,
    action: &str,
    outcome: AuditOutcome,
    detail: &str,
    at_epoch_seconds: u64,
    previous_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"omnidesk.audit.event.v1\0");
    sha2::Digest::update(&mut hasher, sequence.to_be_bytes());
    sha2::Digest::update(&mut hasher, tenant_handle.as_bytes());
    sha2::Digest::update(&mut hasher, principal_handle.as_bytes());
    sha2::Digest::update(&mut hasher, action.as_bytes());
    sha2::Digest::update(&mut hasher, outcome.name().as_bytes());
    sha2::Digest::update(&mut hasher, detail.as_bytes());
    sha2::Digest::update(&mut hasher, at_epoch_seconds.to_be_bytes());
    sha2::Digest::update(&mut hasher, previous_digest.as_slice());
    sha2::Digest::finalize(hasher).into()
}

/// Why an audit operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditError {
    EmptyAction,
    ActionTooLong { length: usize, maximum: usize },
    DetailTooLong { length: usize, maximum: usize },
    TimeWentBackwards { previous: u64, offered: u64 },
    LogFull,
    Truncated,
    SequenceGap { expected: u64, found: u64 },
    ChainBroken { at_sequence: u64 },
    ContentAltered { at_sequence: u64 },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAction => f.write_str("audit action is blank"),
            Self::ActionTooLong { length, maximum } => {
                write!(f, "audit action is {length} bytes, maximum is {maximum}")
            }
            Self::DetailTooLong { length, maximum } => {
                write!(f, "audit detail is {length} bytes, maximum is {maximum}")
            }
            Self::TimeWentBackwards { previous, offered } => {
                write!(f, "audit time went backwards from {previous} to {offered}")
            }
            Self::LogFull => f.write_str("audit sequence counter is exhausted"),
            Self::Truncated => f.write_str("audit log was truncated, so the chain has a hole"),
            Self::SequenceGap { expected, found } => {
                write!(f, "audit sequence gap: expected {expected}, found {found}")
            }
            Self::ChainBroken { at_sequence } => {
                write!(f, "audit chain broken at sequence {at_sequence}")
            }
            Self::ContentAltered { at_sequence } => {
                write!(f, "audit event {at_sequence} was altered")
            }
        }
    }
}

impl std::error::Error for AuditError {}

use super::short_hex;
