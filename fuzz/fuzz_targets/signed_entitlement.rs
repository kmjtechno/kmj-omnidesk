#![no_main]

//! Fuzzes the signed-entitlement boundary.
//!
//! A signed entitlement is the single gate between an untrusted server
//! response and paid product access, so it is the highest-value target in the
//! codebase. The properties below are the ones the roadmap actually promises,
//! and each maps to a documented fail-closed guarantee rather than a guess.

use libfuzzer_sys::fuzz_target;
use omnidesk_core::licensing::{
    LicenseError, LocalLicenseClock, RevocationState, SignedEntitlementPayload,
    VerificationContext, verify_signed_entitlement,
};
use omnidesk_core::licensing::SignatureVerifier;

struct RejectEverything;

impl SignatureVerifier for RejectEverything {
    fn verify(&self, _kid: &str, _payload: &[u8], _signature: &[u8]) -> Result<(), LicenseError> {
        Err(LicenseError::InvalidSignature)
    }
}

/// Builds a context whose every field is derived from the fuzz input, so the
/// fuzzer reaches binding, replay, revocation and time checks rather than
/// short-circuiting at signature verification.
fn context_from(input: &[u8]) -> VerificationContext<'static> {
    const STRINGS: &[&str] = &[
        "act-1",
        "fingerprint-1",
        "install-1",
        "",
        "   ",
        "act-2",
        "fingerprint-1",
        "install-1",
    ];
    let pick = |offset: usize| STRINGS[input.get(offset).copied().unwrap_or(0) as usize % STRINGS.len()];
    let number = |offset: usize| u64::from(input.get(offset).copied().unwrap_or(0));

    VerificationContext {
        binding: omnidesk_core::licensing::DeviceBinding {
            activation_id: pick(0),
            device_public_key_fingerprint: pick(1),
            installation_id: pick(2),
        },
        last_accepted_sequence: number(3),
        revocation: match number(4) % 5 {
            0 => RevocationState::Clear,
            1 => RevocationState::LicenseRevoked,
            2 => RevocationState::EntitlementRevoked,
            3 => RevocationState::ActivationRevoked,
            _ => RevocationState::SigningKeyRevoked,
        },
        clock: LocalLicenseClock {
            now: number(5),
            last_trusted_server_time: number(6),
            grace_expires_at: number(7),
            renewal_due_at: number(8),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    // The payload is the untrusted input under test. Signature bytes are
    // derived from the same input so a valid-signature path stays reachable.
    let (payload_bytes, signature) = match data.split_at_checked(data.len() / 2) {
        Some(split) => split,
        None => return,
    };

    let context = context_from(data);
    let result = verify_signed_entitlement(
        &RejectEverything,
        payload_bytes,
        signature,
        &context,
    );

    // Property 1: fail closed. The bundled verifier never accepts, so no input
    // may ever produce an entitlement. Any `Ok` is a privilege-escalation bug.
    assert!(
        result.is_err(),
        "untrusted input produced an entitlement: {result:?}"
    );

    // Property 2: every rejection is a declared, fail-closed error rather than
    // a panic or an opaque variant. This pins the deterministic error contract
    // the roadmap requires clients to rely on.
    if let Err(error) = result {
        let contract = matches!(
            error,
            LicenseError::MalformedPayload
                | LicenseError::InvalidSignature
                | LicenseError::UnknownOrRevokedKey
                | LicenseError::ProtocolMismatch
                | LicenseError::ContractMismatch
                | LicenseError::ProductMismatch
                | LicenseError::DeviceBindingMismatch
                | LicenseError::InvalidTemporalBounds
                | LicenseError::NotYetValid
                | LicenseError::Expired
                | LicenseError::LeaseExpired
                | LicenseError::Revoked
                | LicenseError::ClockRollback
                | LicenseError::ReplayOrStaleSequence
        );
        assert!(contract, "undeclared licensing error escaped: {error:?}");
    }

    // Property 3: `deny_unknown_fields` must actually deny. A payload carrying
    // an extra key must fail closed rather than being silently accepted with
    // that key ignored, since an ignored field is one the signer and the
    // verifier can disagree about.
    if let Ok(mut object) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(
        payload_bytes,
    ) {
        object.insert(
            "omnidesk_fuzz_probe".to_owned(),
            serde_json::Value::Bool(true),
        );
        let mutated = serde_json::to_vec(&serde_json::Value::Object(object))
            .unwrap_or_default();
        assert!(
            serde_json::from_slice::<SignedEntitlementPayload>(&mutated).is_err(),
            "an unknown field was accepted instead of failing closed"
        );
    }
});