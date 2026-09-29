//! Fail-closed local enforcement for the KMJ Main Platform licensing contract.
//!
//! Cryptographic signature verification is injected through `SignatureVerifier`.
//! Production Ed25519 key resolution/signature verification belongs to the reviewed
//! crypto adapter; policy evaluation remains deterministic and independently testable.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::{PRODUCT_ID, PRODUCT_SLUG};

pub const LICENSE_CONTRACT_VERSION: &str = "kmj.omnidesk.license.v1";
pub const LICENSE_PROTOCOL_VERSION: &str = "KSLP-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseState {
    Active,
    RenewalDue,
    Grace,
    Restricted,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    Clear,
    LicenseRevoked,
    EntitlementRevoked,
    ActivationRevoked,
    SigningKeyRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    InvalidSignature,
    UnknownOrRevokedKey,
    ProtocolMismatch,
    ContractMismatch,
    ProductMismatch,
    DeviceBindingMismatch,
    InvalidTemporalBounds,
    NotYetValid,
    Expired,
    LeaseExpired,
    ReplayOrStaleSequence,
    Revoked,
    ClockRollback,
    MalformedPayload,
}

pub const MAX_SIGNED_ENTITLEMENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum LicensePlan {
    #[serde(rename = "Personal_Free")]
    PersonalFree,
    Trial,
    Professional,
    Business,
    Enterprise,
    #[serde(rename = "OEM_Custom")]
    OemCustom,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct NullableLimit(pub Option<u64>);

impl NullableLimit {
    #[must_use]
    pub const fn allows(&self, usage: u64) -> bool {
        match self.0 {
            Some(limit) => usage <= limit,
            None => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub licensed_users: NullableLimit,
    pub managed_devices: NullableLimit,
    pub concurrent_sessions: NullableLimit,
    pub unattended_devices: NullableLimit,
    pub relay_bytes_monthly: NullableLimit,
    pub relay_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLimitKind {
    LicensedUsers,
    ManagedDevices,
    ConcurrentSessions,
    UnattendedDevices,
    RelayBytesMonthly,
}

impl ResourceLimits {
    #[must_use]
    pub const fn permits(&self, kind: ResourceLimitKind, usage: u64) -> bool {
        match kind {
            ResourceLimitKind::LicensedUsers => self.licensed_users.allows(usage),
            ResourceLimitKind::ManagedDevices => self.managed_devices.allows(usage),
            ResourceLimitKind::ConcurrentSessions => self.concurrent_sessions.allows(usage),
            ResourceLimitKind::UnattendedDevices => self.unattended_devices.allows(usage),
            ResourceLimitKind::RelayBytesMonthly => self.relay_bytes_monthly.allows(usage),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEntitlementPayload {
    pub protocol_version: String,
    pub contract_version: String,
    pub jti: String,
    pub kid: String,
    pub license_id: String,
    pub entitlement_id: String,
    pub customer_id: String,
    pub organization_id: Option<String>,
    pub product_id: String,
    pub product_slug: String,
    pub plan: LicensePlan,
    pub activation_id: String,
    pub device_public_key_fingerprint: String,
    pub installation_id: String,
    pub capabilities: Vec<String>,
    pub limits: ResourceLimits,
    #[serde(rename = "iat")]
    pub issued_at: u64,
    #[serde(rename = "nbf")]
    pub not_before: u64,
    #[serde(rename = "exp")]
    pub expires_at: u64,
    pub lease_expires_at: u64,
    pub sequence: u64,
    pub nonce: String,
}

impl SignedEntitlementPayload {
    fn semantic_shape_is_valid(&self) -> bool {
        let identity_fields = [
            self.jti.as_str(),
            self.kid.as_str(),
            self.license_id.as_str(),
            self.entitlement_id.as_str(),
            self.customer_id.as_str(),
            self.activation_id.as_str(),
            self.device_public_key_fingerprint.as_str(),
            self.installation_id.as_str(),
            self.nonce.as_str(),
        ];
        if identity_fields.iter().any(|value| value.trim().is_empty()) {
            return false;
        }
        if self
            .organization_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return false;
        }
        if self.limits.relay_policy.trim().is_empty() {
            return false;
        }
        if self.capabilities.iter().any(|value| value.trim().is_empty()) {
            return false;
        }

        let mut capabilities = BTreeSet::new();
        self.capabilities
            .iter()
            .all(|capability| capabilities.insert(capability.as_str()))
    }
}

pub trait SignatureVerifier {
    /// Verifies the canonical entitlement payload against the selected signing key.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed licensing error when the key is unknown/revoked or the
    /// signature cannot be verified.
    fn verify(
        &self,
        kid: &str,
        canonical_payload: &[u8],
        signature: &[u8],
    ) -> Result<(), LicenseError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicensePublicKey {
    pub kid: String,
    pub public_key: [u8; 32],
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseKeySetError {
    EmptyKeyId,
    DuplicateKeyId,
    InvalidPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519SignatureVerifier {
    keys: Vec<LicensePublicKey>,
}

impl Ed25519SignatureVerifier {
    /// Builds a fail-closed verifier from the currently trusted public keys.
    ///
    /// # Errors
    ///
    /// Rejects empty/duplicate key identifiers and invalid Ed25519 public keys.
    pub fn new(keys: Vec<LicensePublicKey>) -> Result<Self, LicenseKeySetError> {
        let mut key_ids = BTreeSet::new();
        for key in &keys {
            if key.kid.trim().is_empty() {
                return Err(LicenseKeySetError::EmptyKeyId);
            }
            if !key_ids.insert(key.kid.as_str()) {
                return Err(LicenseKeySetError::DuplicateKeyId);
            }
            VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| LicenseKeySetError::InvalidPublicKey)?;
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(
        &self,
        kid: &str,
        canonical_payload: &[u8],
        signature: &[u8],
    ) -> Result<(), LicenseError> {
        let key = self
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .filter(|key| !key.revoked)
            .ok_or(LicenseError::UnknownOrRevokedKey)?;

        let public_key = VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| LicenseError::UnknownOrRevokedKey)?;
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| LicenseError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);

        public_key
            .verify_strict(canonical_payload, &signature)
            .map_err(|_| LicenseError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseClaims<'a> {
    pub protocol_version: &'a str,
    pub contract_version: &'a str,
    pub kid: &'a str,
    pub product_id: &'a str,
    pub product_slug: &'a str,
    pub activation_id: &'a str,
    pub device_public_key_fingerprint: &'a str,
    pub installation_id: &'a str,
    pub capabilities: &'a [&'a str],
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub lease_expires_at: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBinding<'a> {
    pub activation_id: &'a str,
    pub device_public_key_fingerprint: &'a str,
    pub installation_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalLicenseClock {
    pub now: u64,
    pub last_trusted_server_time: u64,
    pub grace_expires_at: u64,
    pub renewal_due_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationContext<'a> {
    pub binding: DeviceBinding<'a>,
    pub last_accepted_sequence: u64,
    pub revocation: RevocationState,
    pub clock: LocalLicenseClock,
}

#[must_use]
pub fn has_capability(claims: &LicenseClaims<'_>, capability: &str) -> bool {
    claims.capabilities.contains(&capability)
}

const fn temporal_bounds_are_valid(claims: &LicenseClaims<'_>, clock: LocalLicenseClock) -> bool {
    let issued_at = claims.issued_at;
    let not_before = claims.not_before;
    let lease_expires_at = claims.lease_expires_at;
    let expires_at = claims.expires_at;
    let renewal_due_at = clock.renewal_due_at;
    let grace_expires_at = clock.grace_expires_at;

    let entitlement_order =
        issued_at <= not_before && not_before < lease_expires_at && lease_expires_at <= expires_at;
    let renewal_window = renewal_due_at >= not_before && renewal_due_at <= lease_expires_at;
    let grace_window = grace_expires_at >= lease_expires_at && grace_expires_at <= expires_at;

    entitlement_order && renewal_window && grace_window
}

/// Verifies a signed entitlement and evaluates its local lifecycle state.
///
/// # Errors
///
/// Returns a fail-closed licensing error for invalid signatures, contract/product
/// mismatch, invalid device binding, replay, revocation, invalid time bounds, or
/// clock rollback.
pub fn verify_and_evaluate(
    verifier: &dyn SignatureVerifier,
    canonical_payload: &[u8],
    signature: &[u8],
    claims: &LicenseClaims<'_>,
    context: &VerificationContext<'_>,
) -> Result<LicenseState, LicenseError> {
    verifier.verify(claims.kid, canonical_payload, signature)?;

    if claims.protocol_version != LICENSE_PROTOCOL_VERSION {
        return Err(LicenseError::ProtocolMismatch);
    }
    if claims.contract_version != LICENSE_CONTRACT_VERSION {
        return Err(LicenseError::ContractMismatch);
    }
    if claims.product_id != PRODUCT_ID || claims.product_slug != PRODUCT_SLUG {
        return Err(LicenseError::ProductMismatch);
    }
    if claims.activation_id != context.binding.activation_id
        || claims.device_public_key_fingerprint != context.binding.device_public_key_fingerprint
        || claims.installation_id != context.binding.installation_id
    {
        return Err(LicenseError::DeviceBindingMismatch);
    }
    if context.revocation != RevocationState::Clear {
        return Err(LicenseError::Revoked);
    }
    if claims.sequence <= context.last_accepted_sequence {
        return Err(LicenseError::ReplayOrStaleSequence);
    }
    if !temporal_bounds_are_valid(claims, context.clock) {
        return Err(LicenseError::InvalidTemporalBounds);
    }
    if context.clock.now < context.clock.last_trusted_server_time {
        return Err(LicenseError::ClockRollback);
    }
    if context.clock.now < claims.issued_at || context.clock.now < claims.not_before {
        return Err(LicenseError::NotYetValid);
    }
    if context.clock.now >= claims.expires_at {
        return Err(LicenseError::Expired);
    }

    if context.clock.now < context.clock.renewal_due_at {
        return Ok(LicenseState::Active);
    }
    if context.clock.now < claims.lease_expires_at {
        return Ok(LicenseState::RenewalDue);
    }
    if context.clock.now < context.clock.grace_expires_at {
        return Ok(LicenseState::Grace);
    }

    Ok(LicenseState::Restricted)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptSignature;

    impl SignatureVerifier for AcceptSignature {
        fn verify(&self, kid: &str, payload: &[u8], signature: &[u8]) -> Result<(), LicenseError> {
            if kid == "kid-2026-01" && !payload.is_empty() && !signature.is_empty() {
                Ok(())
            } else {
                Err(LicenseError::InvalidSignature)
            }
        }
    }

    fn claims() -> LicenseClaims<'static> {
        LicenseClaims {
            protocol_version: LICENSE_PROTOCOL_VERSION,
            contract_version: LICENSE_CONTRACT_VERSION,
            kid: "kid-2026-01",
            product_id: PRODUCT_ID,
            product_slug: PRODUCT_SLUG,
            activation_id: "activation-1",
            device_public_key_fingerprint: "device-fingerprint",
            installation_id: "install-1",
            capabilities: &["remote.interactive", "file.transfer"],
            issued_at: 900,
            not_before: 900,
            expires_at: 10_000,
            lease_expires_at: 2_000,
            sequence: 2,
        }
    }

    fn context(now: u64) -> VerificationContext<'static> {
        VerificationContext {
            binding: DeviceBinding {
                activation_id: "activation-1",
                device_public_key_fingerprint: "device-fingerprint",
                installation_id: "install-1",
            },
            last_accepted_sequence: 1,
            revocation: RevocationState::Clear,
            clock: LocalLicenseClock {
                now,
                last_trusted_server_time: 900,
                renewal_due_at: 1_500,
                grace_expires_at: 3_000,
            },
        }
    }

    fn evaluate(
        claims: &LicenseClaims<'_>,
        context: &VerificationContext<'_>,
    ) -> Result<LicenseState, LicenseError> {
        verify_and_evaluate(
            &AcceptSignature,
            b"canonical",
            b"signature",
            claims,
            context,
        )
    }

    #[test]
    fn ed25519_verifier_accepts_known_key_and_rejects_tampering() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
        let verifier = Ed25519SignatureVerifier::new(vec![LicensePublicKey {
            kid: "kid-2026-01".to_owned(),
            public_key: signing_key.verifying_key().to_bytes(),
            revoked: false,
        }])
        .unwrap();
        let payload = b"canonical-license-payload";
        let signature = signing_key.sign(payload).to_bytes();

        assert_eq!(verifier.verify("kid-2026-01", payload, &signature), Ok(()));
        assert_eq!(
            verifier.verify("kid-2026-01", b"tampered", &signature),
            Err(LicenseError::InvalidSignature)
        );
        assert_eq!(
            verifier.verify("unknown", payload, &signature),
            Err(LicenseError::UnknownOrRevokedKey)
        );
    }

    #[test]
    fn revoked_signing_key_fails_closed() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
        let verifier = Ed25519SignatureVerifier::new(vec![LicensePublicKey {
            kid: "kid-revoked".to_owned(),
            public_key: signing_key.verifying_key().to_bytes(),
            revoked: true,
        }])
        .unwrap();
        let payload = b"canonical";
        let signature = signing_key.sign(payload).to_bytes();

        assert_eq!(
            verifier.verify("kid-revoked", payload, &signature),
            Err(LicenseError::UnknownOrRevokedKey)
        );
    }

    #[test]
    fn duplicate_or_empty_key_ids_are_rejected() {
        use ed25519_dalek::SigningKey;

        let public_key = SigningKey::from_bytes(&[43_u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            Ed25519SignatureVerifier::new(vec![LicensePublicKey {
                kid: String::new(),
                public_key,
                revoked: false,
            }]),
            Err(LicenseKeySetError::EmptyKeyId)
        );
        assert_eq!(
            Ed25519SignatureVerifier::new(vec![
                LicensePublicKey {
                    kid: "same".to_owned(),
                    public_key,
                    revoked: false,
                },
                LicensePublicKey {
                    kid: "same".to_owned(),
                    public_key,
                    revoked: false,
                },
            ]),
            Err(LicenseKeySetError::DuplicateKeyId)
        );
    }

    #[test]
    fn active_renewal_grace_and_restricted_states_are_deterministic() {
        assert_eq!(
            evaluate(&claims(), &context(1_000)),
            Ok(LicenseState::Active)
        );
        assert_eq!(
            evaluate(&claims(), &context(1_600)),
            Ok(LicenseState::RenewalDue)
        );
        assert_eq!(
            evaluate(&claims(), &context(2_100)),
            Ok(LicenseState::Grace)
        );
        assert_eq!(
            evaluate(&claims(), &context(3_100)),
            Ok(LicenseState::Restricted)
        );
    }

    #[test]
    fn forged_signature_fails_closed() {
        let result = verify_and_evaluate(&AcceptSignature, b"", b"", &claims(), &context(1_000));
        assert_eq!(result, Err(LicenseError::InvalidSignature));
    }

    #[test]
    fn wrong_product_fails_closed() {
        let mut value = claims();
        value.product_id = "OTHER_PRODUCT";
        assert_eq!(
            evaluate(&value, &context(1_000)),
            Err(LicenseError::ProductMismatch)
        );
    }

    #[test]
    fn wrong_device_binding_fails_closed() {
        let mut value = claims();
        value.installation_id = "other-install";
        assert_eq!(
            evaluate(&value, &context(1_000)),
            Err(LicenseError::DeviceBindingMismatch)
        );
    }

    #[test]
    fn replayed_sequence_fails_closed() {
        let mut value = claims();
        value.sequence = 1;
        assert_eq!(
            evaluate(&value, &context(1_000)),
            Err(LicenseError::ReplayOrStaleSequence)
        );
    }

    #[test]
    fn known_revocation_overrides_offline_grace() {
        let mut ctx = context(2_100);
        ctx.revocation = RevocationState::ActivationRevoked;
        assert_eq!(evaluate(&claims(), &ctx), Err(LicenseError::Revoked));
    }

    #[test]
    fn clock_rollback_does_not_extend_grace() {
        let mut ctx = context(800);
        ctx.clock.last_trusted_server_time = 900;
        assert_eq!(evaluate(&claims(), &ctx), Err(LicenseError::ClockRollback));
    }

    #[test]
    fn malformed_temporal_bounds_fail_closed() {
        let mut value = claims();
        value.lease_expires_at = value.expires_at + 1;
        assert_eq!(
            evaluate(&value, &context(1_000)),
            Err(LicenseError::InvalidTemporalBounds)
        );

        let value = claims();
        let mut ctx = context(1_000);
        ctx.clock.renewal_due_at = value.lease_expires_at + 1;
        assert_eq!(
            evaluate(&value, &ctx),
            Err(LicenseError::InvalidTemporalBounds)
        );

        let mut ctx = context(1_000);
        ctx.clock.grace_expires_at = value.expires_at + 1;
        assert_eq!(
            evaluate(&value, &ctx),
            Err(LicenseError::InvalidTemporalBounds)
        );

        let mut value = claims();
        value.issued_at = value.not_before + 1;
        assert_eq!(
            evaluate(&value, &context(1_000)),
            Err(LicenseError::InvalidTemporalBounds)
        );
    }

    #[test]
    fn entitlement_cannot_become_active_before_issue_time() {
        let mut value = claims();
        value.issued_at = 950;
        value.not_before = 950;
        let mut ctx = context(940);
        ctx.clock.last_trusted_server_time = 900;
        assert_eq!(evaluate(&value, &ctx), Err(LicenseError::NotYetValid));
    }

    #[test]
    fn expired_entitlement_fails_closed() {
        let mut value = claims();
        value.lease_expires_at = 950;
        value.expires_at = 1_000;
        let mut ctx = context(1_000);
        ctx.clock.renewal_due_at = 925;
        ctx.clock.grace_expires_at = 975;

        assert_eq!(evaluate(&value, &ctx), Err(LicenseError::Expired));
    }

    #[test]
    fn capability_lookup_is_explicit() {
        let value = claims();
        assert!(has_capability(&value, "remote.interactive"));
        assert!(!has_capability(&value, "enterprise.sso"));
    }
}
