//! Device trust.
//!
//! "This machine is one of ours" is a different claim from "this person is one
//! of ours", and it has to be answerable without either being assumed from the
//! other. A device certificate proves possession of a key; it does not prove
//! the device is still enrolled, still under management, or still the same
//! machine that was enrolled. Those are answers that come from a control plane,
//! so this module is the boundary that records them and refuses when the
//! answer is absent.

use super::{PolicyError, short_hex};
use sha2::Digest;

/// The longest device identifier accepted.
pub const MAX_DEVICE_ID_BYTES: usize = 128;

/// The longest attestation reference accepted.
pub const MAX_ATTESTATION_BYTES: usize = 256;

/// What a control plane said about a device, at a point in time.
///
/// Private fields and no `Deserialize`: a `TrustAssessment` that can be built
/// from JSON is a trust assessment an attacker can write. It is constructed
/// only by [`TrustRegistry::assess`], which is the only path that can also
/// record the revocation that would contradict it.
#[derive(Clone, Debug)]
#[must_use = "device trust is only meaningful when consulted"]
pub struct DeviceTrust {
    device_id: String,
    enrolled_at: u64,
    trust_expires_at: u64,
    managed: bool,
    revoked: bool,
    /// The instant this assessment is valid for.
    ///
    /// Carried on the value rather than passed to `evaluate` so that the
    /// authorization path has exactly one time input. Two clocks in one
    /// decision is one clock someone forgets to thread.
    assessed_at: u64,
}

impl DeviceTrust {
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Whether an administrator manages this device through the control plane.
    ///
    /// False for a device the tenant merely added to its own list. The two are
    /// different: a self-enrolled device is a device someone claims is theirs.
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        self.managed
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// When the control plane enrolled this device.
    ///
    /// Part of the record rather than of the decision: a control plane needs it
    /// to age devices out, and an age-out rule that reads it is a rule this
    /// repository does not implement yet. Recorded so the value survives to
    /// the point where it does.
    #[must_use]
    pub const fn enrolled_at(&self) -> u64 {
        self.enrolled_at
    }

    #[must_use]
    pub const fn trust_expires_at(&self) -> u64 {
        self.trust_expires_at
    }

    #[must_use]
    pub const fn assessed_at(&self) -> u64 {
        self.assessed_at
    }

    /// Whether this device is currently trusted.
    ///
    /// `now` is passed in. A trust check against a wall clock cannot be tested,
    /// and a trust check against a clock the client controls is not a trust
    /// check.
    #[must_use]
    pub const fn is_trusted_at(&self, now: u64) -> bool {
        !self.revoked && now < self.trust_expires_at
    }

    /// Whether this device is trusted at the instant it was assessed.
    ///
    /// The form [`PolicyEngine::evaluate`](super::PolicyEngine::evaluate) uses.
    /// A caller holding an older assessment and no clock argument gets the
    /// answer for when the control plane was asked, not for now.
    #[must_use]
    pub const fn is_trusted_at_now(&self) -> bool {
        self.is_trusted_at(self.assessed_at)
    }
}

/// The result of asking whether a device is trusted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrustDecision {
    Trusted,
    NotEnrolled,
    Revoked,
    Expired,
}

impl TrustDecision {
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// The tenant's view of its enrolled devices.
///
/// In memory and passed in. A registry that read a file or made a network call
/// would make every authorization decision depend on infrastructure, and the
/// properties that matter here are about what happens when the answer is
/// *wrong*, which a test can only exercise by supplying the wrong answer.
#[derive(Clone, Debug, Default)]
pub struct TrustRegistry {
    devices: Vec<DeviceTrust>,
}

impl TrustRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Records an enrolment and returns the resulting assessment.
    ///
    /// `assessed_at` is the instant the control plane answered. It is recorded
    /// on the returned value so the decision that consumes it does not need a
    /// separate clock argument.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::DeviceIdTooLong` above
    /// [`MAX_DEVICE_ID_BYTES`], or `DeviceIdNotAcceptable`.
    ///
    /// # Panics
    ///
    /// Never in practice: the returned reference indexes the element this
    /// function just pushed, which is the last one.
    pub fn enroll(
        &mut self,
        device_id: &str,
        enrolled_at: u64,
        trust_expires_at: u64,
        assessed_at: u64,
        managed: bool,
    ) -> Result<&DeviceTrust, PolicyError> {
        if device_id.is_empty() {
            return Err(PolicyError::EmptyDeviceId);
        }
        if device_id.len() > MAX_DEVICE_ID_BYTES {
            return Err(PolicyError::DeviceIdTooLong {
                length: device_id.len(),
                maximum: MAX_DEVICE_ID_BYTES,
            });
        }
        if !device_id.is_ascii() || device_id.chars().any(char::is_control) {
            return Err(PolicyError::DeviceIdNotAcceptable);
        }
        if trust_expires_at <= enrolled_at {
            return Err(PolicyError::TrustExpiryNotAfterEnrolment);
        }

        let trust = DeviceTrust {
            device_id: device_id.to_string(),
            enrolled_at,
            trust_expires_at,
            managed,
            revoked: false,
            assessed_at,
        };
        // A re-enrolment replaces rather than appends. Two rows for one device
        // would mean the lookup below depends on order, and an order-dependent
        // trust check is a trust check an attacker picks.
        self.devices
            .retain(|existing| existing.device_id != device_id);
        self.devices.push(trust);
        Ok(self.devices.last().expect("just pushed"))
    }

    /// Marks a device revoked.
    ///
    /// Revocation is a separate operation from removal so that a device
    /// retired from the tenant still produces a `Revoked` answer rather than
    /// `NotEnrolled`, which reads as "never existed" and hides the retirement.
    pub fn revoke(&mut self, device_id: &str) -> bool {
        let Some(device) = self.devices.iter_mut().find(|d| d.device_id == device_id) else {
            return false;
        };
        device.revoked = true;
        true
    }

    #[must_use]
    pub fn get(&self, device_id: &str) -> Option<&DeviceTrust> {
        self.devices.iter().find(|d| d.device_id == device_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Decides whether a device id is trusted.
    ///
    /// Absent from the registry is `NotEnrolled`, not `Trusted`. This is the
    /// single most important line in the module and it is why the return type
    /// has four variants instead of a bool.
    #[must_use]
    pub fn assess(&self, device_id: &str, now: u64) -> TrustDecision {
        let Some(device) = self.get(device_id) else {
            return TrustDecision::NotEnrolled;
        };
        if device.is_revoked() {
            return TrustDecision::Revoked;
        }
        if !device.is_trusted_at(now) {
            return TrustDecision::Expired;
        }
        TrustDecision::Trusted
    }
}

/// A device's proof of possession, as presented by a control plane.
///
/// The attestation reference is an opaque handle to whatever proof was checked
/// -- an attestation statement, a certificate chain id, a TPM quote hash. The
/// module deliberately does not parse it. A verifier that accepts arbitrary
/// bytes is a verifier whose correctness nobody can check from here, and
/// resolving that reference to a real attestation format is an integration with
/// a hardware vendor, not a decision this repository can make alone.
#[derive(Clone, Debug)]
pub struct DeviceProof {
    device_id: String,
    attestation: String,
    presented_at: u64,
}

impl DeviceProof {
    /// # Errors
    ///
    /// Returns `PolicyError::DeviceIdNotAcceptable`, or
    /// `AttestationTooLong` above [`MAX_ATTESTATION_BYTES`].
    pub fn new(device_id: &str, attestation: &str, presented_at: u64) -> Result<Self, PolicyError> {
        if device_id.is_empty() || !device_id.is_ascii() || device_id.chars().any(char::is_control)
        {
            return Err(PolicyError::DeviceIdNotAcceptable);
        }
        if device_id.len() > MAX_DEVICE_ID_BYTES {
            return Err(PolicyError::DeviceIdTooLong {
                length: device_id.len(),
                maximum: MAX_DEVICE_ID_BYTES,
            });
        }
        if attestation.is_empty() {
            return Err(PolicyError::EmptyAttestation);
        }
        if attestation.len() > MAX_ATTESTATION_BYTES {
            return Err(PolicyError::AttestationTooLong {
                length: attestation.len(),
                maximum: MAX_ATTESTATION_BYTES,
            });
        }
        Ok(Self {
            device_id: device_id.to_string(),
            attestation: attestation.to_string(),
            presented_at,
        })
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub const fn presented_at(&self) -> u64 {
        self.presented_at
    }

    /// A stable pseudonymous handle, safe to place in an audit record.
    /// The opaque reference to whatever proof was verified.
    ///
    /// Deliberately not parsed. Resolving it to an attestation format is an
    /// integration with a hardware vendor, and this module does not have one to
    /// test against -- so the reference is carried, and nothing pretends to
    /// have checked it.
    #[must_use]
    pub fn attestation(&self) -> &str {
        &self.attestation
    }

    #[must_use]
    pub fn audit_handle(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"omnidesk.audit.device.v1\0");
        sha2::Digest::update(&mut hasher, self.device_id.as_bytes());
        let digest = sha2::Digest::finalize(hasher);
        short_hex(&digest)
    }
}
