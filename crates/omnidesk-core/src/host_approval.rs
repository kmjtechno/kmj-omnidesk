//! Fail-closed host-local approval preflight for ONE verified attended peer.
//!
//! A valid temporary password does not grant permission to see the screen,
//! send mouse/keyboard input or transfer files. This module requires a
//! fresh, non-cloneable proof receipt, exact Noise transcript, live pinned
//! trust, current host policy and a real Main Platform Ed25519 signed lease.
//!
//! The preflight is NOT a network control token. Future media/input must
//! additionally require a live encrypted channel, visible local permission,
//! independent capability/role checks and continuous revocation enforcement.

use crate::{
    activation_proof::fingerprint_public_key_bytes,
    attended_proof_wire::HostPasswordProofReceipt,
    device_identity::DeviceIdentity,
    licensing::{
        Ed25519SignatureVerifier, LicenseError, LicenseState, ResourceLimitKind,
        VerificationContext, verify_signed_entitlement,
    },
    password_auth::HostPasswordManager,
    trusted_device_store::TrustedDeviceStore,
};

/// Maximum time from successful password proof to a visible host decision.
pub const HOST_APPROVAL_WINDOW_SECS: u64 = 30;

/// Fail-closed refusal reasons for one locally visible host click.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostApprovalError {
    AlreadyConsumed,
    ProofExpired,
    PeerMismatch,
    HostMismatch,
    NoiseTranscriptMismatch,
    HostSharingDisabled,
    PasswordGenerationChanged,
    PeerUntrusted,
    PeerRevokedOrExpired,
    PeerPublicKeyChanged,
    License(LicenseError),
    LicenseBindingMismatch,
    LicenseNotActive,
    LicenseCapabilityMissing,
    ConcurrentSessionLimit,
    TimeMismatch,
}

/// One-use pending approval produced only by a successful encrypted password
/// verifier. Neither the remote peer nor UI strings can create a valid proof.
pub struct PendingHostApproval {
    proof: Option<HostPasswordProofReceipt>,
}

impl PendingHostApproval {
    #[must_use]
    pub const fn new(proof: HostPasswordProofReceipt) -> Self {
        Self { proof: Some(proof) }
    }

    /// Consume and permanently deny the pending local permission request.
    pub fn deny(&mut self) {
        self.proof.take();
    }

    /// Whether a host decision has already consumed the pending request.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.proof.is_none()
    }

    /// Called ONLY by the host GUI's explicit, visible Allow decision.
    ///
    /// Re-verifies enrolled peer/key, current password policy, the exact
    /// locally witnessed Noise transcript and a real platform-signed
    /// entitlement for THIS host. An arbitrary bool never authorizes control.
    /// Any attempt (successful or rejected) consumes the proof permanently.
    ///
    /// The returned preflight is NOT accepted by the current
    /// `TransportSessionAdapter::authorize_session` network gate.
    ///
    /// # Errors
    /// Refuses missing/replayed approval, stale or switched sessions,
    /// disabled host sharing, trust changes, invalid platform signing keys,
    /// revoked/restricted licensing or insufficient licensed capacity.
    #[allow(clippy::too_many_arguments)]
    pub fn approve_after_visible_host_click(
        &mut self,
        expected_peer_id: &str,
        current_noise_hash: &[u8; 32],
        local_identity: &DeviceIdentity,
        trust_store: &TrustedDeviceStore,
        password_manager: &HostPasswordManager,
        license_verifier: &Ed25519SignatureVerifier,
        signed_entitlement_payload: &[u8],
        signed_entitlement_signature: &[u8],
        license_context: &VerificationContext<'_>,
        active_session_count: u64,
        now_epoch_secs: u64,
    ) -> Result<HostApprovalPreflight, HostApprovalError> {
        let proof = self
            .proof
            .take()
            .ok_or(HostApprovalError::AlreadyConsumed)?;
        let verified_at = proof.verified_at_epoch_secs();
        if now_epoch_secs < verified_at
            || now_epoch_secs >= verified_at.saturating_add(HOST_APPROVAL_WINDOW_SECS)
        {
            return Err(HostApprovalError::ProofExpired);
        }
        if proof.peer_id() != expected_peer_id {
            return Err(HostApprovalError::PeerMismatch);
        }
        if proof.noise_handshake_hash() != current_noise_hash || *current_noise_hash == [0_u8; 32] {
            return Err(HostApprovalError::NoiseTranscriptMismatch);
        }
        if proof.host_id() != local_identity.public_id()
            || *proof.host_public_key() != local_identity.public_key_bytes()
        {
            return Err(HostApprovalError::HostMismatch);
        }
        if !password_manager.allow_remote_control()
            || password_manager.is_locked_out(now_epoch_secs)
            || password_manager.is_expired(now_epoch_secs)
        {
            return Err(HostApprovalError::HostSharingDisabled);
        }
        if proof.password_generation() != password_manager.approval_generation() {
            return Err(HostApprovalError::PasswordGenerationChanged);
        }
        let record = trust_store
            .get(expected_peer_id)
            .ok_or(HostApprovalError::PeerUntrusted)?;
        if record.revoked || now_epoch_secs > record.trust_expires_at_epoch_secs {
            return Err(HostApprovalError::PeerRevokedOrExpired);
        }
        if record.public_key != *proof.peer_public_key() {
            return Err(HostApprovalError::PeerPublicKeyChanged);
        }
        if license_context.clock.now != now_epoch_secs {
            return Err(HostApprovalError::TimeMismatch);
        }
        // No caller-supplied "verified entitlement" flag: the actual Main
        // Platform public key validates the signed canonical bytes HERE.
        let lease = verify_signed_entitlement(
            license_verifier,
            signed_entitlement_payload,
            signed_entitlement_signature,
            license_context,
        )
        .map_err(HostApprovalError::License)?;
        if lease.payload.device_public_key_fingerprint
            != fingerprint_public_key_bytes(&local_identity.public_key_bytes())
        {
            return Err(HostApprovalError::LicenseBindingMismatch);
        }
        if !matches!(
            lease.state,
            LicenseState::Active | LicenseState::RenewalDue | LicenseState::Grace
        ) {
            return Err(HostApprovalError::LicenseNotActive);
        }
        if !lease.has_capability("remote.interactive") {
            return Err(HostApprovalError::LicenseCapabilityMissing);
        }
        let requested_usage = active_session_count
            .checked_add(1)
            .ok_or(HostApprovalError::ConcurrentSessionLimit)?;
        if !lease.permits_resource(ResourceLimitKind::ConcurrentSessions, requested_usage) {
            return Err(HostApprovalError::ConcurrentSessionLimit);
        }
        Ok(HostApprovalPreflight {
            peer_id: expected_peer_id.to_owned(),
            host_id: local_identity.public_id().to_owned(),
            noise_handshake_hash: *current_noise_hash,
            session_id: *proof.session_id(),
            signed_license_jti: lease.payload.jti,
            preflight_expires_at: verified_at.saturating_add(HOST_APPROVAL_WINDOW_SECS),
        })
    }
}

/// Host consent + entitlement PRE-FLIGHT only, NOT screen/input authorization.
///
/// The current network transport adapter deliberately has no API that
/// accepts this object; real session start still needs a separately reviewed
/// permission state machine bound to the *live* AEAD channel and revocation.
pub struct HostApprovalPreflight {
    peer_id: String,
    host_id: String,
    noise_handshake_hash: [u8; 32],
    session_id: [u8; 16],
    signed_license_jti: String,
    preflight_expires_at: u64,
}

impl HostApprovalPreflight {
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    #[must_use]
    pub const fn noise_handshake_hash(&self) -> &[u8; 32] {
        &self.noise_handshake_hash
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    #[must_use]
    pub fn signed_license_jti(&self) -> &str {
        &self.signed_license_jti
    }

    #[must_use]
    pub const fn preflight_expires_at(&self) -> u64 {
        self.preflight_expires_at
    }
}
