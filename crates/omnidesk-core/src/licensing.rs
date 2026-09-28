//! Fail-closed local enforcement for the KMJ Main Platform licensing contract.
//!
//! Cryptographic signature verification is injected through `SignatureVerifier`.
//! Production Ed25519 key resolution/signature verification belongs to the reviewed
//! crypto adapter; policy evaluation remains deterministic and independently testable.

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
    NotYetValid,
    Expired,
    LeaseExpired,
    ReplayOrStaleSequence,
    Revoked,
    ClockRollback,
}

pub trait SignatureVerifier {
    fn verify(&self, kid: &str, canonical_payload: &[u8], signature: &[u8]) -> Result<(), LicenseError>;
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    if context.clock.now < context.clock.last_trusted_server_time {
        return Err(LicenseError::ClockRollback);
    }
    if context.clock.now < claims.not_before {
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

    fn evaluate(claims: &LicenseClaims<'_>, context: &VerificationContext<'_>) -> Result<LicenseState, LicenseError> {
        verify_and_evaluate(&AcceptSignature, b"canonical", b"signature", claims, context)
    }

    #[test]
    fn active_renewal_grace_and_restricted_states_are_deterministic() {
        assert_eq!(evaluate(&claims(), &context(1_000)), Ok(LicenseState::Active));
        assert_eq!(evaluate(&claims(), &context(1_600)), Ok(LicenseState::RenewalDue));
        assert_eq!(evaluate(&claims(), &context(2_100)), Ok(LicenseState::Grace));
        assert_eq!(evaluate(&claims(), &context(3_100)), Ok(LicenseState::Restricted));
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
        assert_eq!(evaluate(&value, &context(1_000)), Err(LicenseError::ProductMismatch));
    }

    #[test]
    fn wrong_device_binding_fails_closed() {
        let mut value = claims();
        value.installation_id = "other-install";
        assert_eq!(evaluate(&value, &context(1_000)), Err(LicenseError::DeviceBindingMismatch));
    }

    #[test]
    fn replayed_sequence_fails_closed() {
        let mut value = claims();
        value.sequence = 1;
        assert_eq!(evaluate(&value, &context(1_000)), Err(LicenseError::ReplayOrStaleSequence));
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
    fn expired_entitlement_fails_closed() {
        let mut value = claims();
        value.expires_at = 1_000;
        assert_eq!(evaluate(&value, &context(1_000)), Err(LicenseError::Expired));
    }

    #[test]
    fn capability_lookup_is_explicit() {
        let value = claims();
        assert!(has_capability(&value, "remote.interactive"));
        assert!(!has_capability(&value, "enterprise.sso"));
    }
}
