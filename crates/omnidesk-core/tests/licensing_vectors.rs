use base64::{Engine as _, engine::general_purpose::STANDARD};
use omnidesk_core::licensing::{
    DeviceBinding, Ed25519SignatureVerifier, LICENSE_CONTRACT_VERSION, LICENSE_PROTOCOL_VERSION,
    LicenseClaims, LicenseError, LicensePublicKey, LicenseState, LocalLicenseClock,
    RevocationState, SignatureVerifier, VerificationContext,
};
use omnidesk_core::{PRODUCT_ID, PRODUCT_SLUG};
use serde_json::Value;

const ED25519_VECTOR: &str =
    include_str!("../../../protocol/licensing/test-vectors/ed25519-v1.json");
const POLICY_VECTORS: &str =
    include_str!("../../../protocol/licensing/test-vectors/policy-v1.json");

struct AcceptTestSignature;

impl SignatureVerifier for AcceptTestSignature {
    fn verify(
        &self,
        _kid: &str,
        _canonical_payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), LicenseError> {
        Ok(())
    }
}

fn value_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn value_u64(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing u64 field {key}"))
}

fn value_bool(value: &Value, key: &str) -> bool {
    value[key]
        .as_bool()
        .unwrap_or_else(|| panic!("missing bool field {key}"))
}

fn normalized_outcome(result: Result<LicenseState, LicenseError>) -> &'static str {
    match result {
        Ok(LicenseState::Active) => "ACTIVE",
        Ok(LicenseState::RenewalDue) => "RENEWAL_DUE",
        Ok(LicenseState::Grace) => "GRACE",
        Ok(LicenseState::Restricted) => "RESTRICTED",
        Ok(LicenseState::Revoked) | Err(LicenseError::Revoked) => "REVOKED",
        Err(LicenseError::ReplayOrStaleSequence) => "REPLAY_DETECTED",
        Err(LicenseError::ClockRollback) => "CLOCK_ROLLBACK",
        Err(other) => panic!("unexpected licensing outcome: {other:?}"),
    }
}

#[test]
fn committed_ed25519_vector_matches_client_verifier() {
    let vector: Value = serde_json::from_str(ED25519_VECTOR).expect("valid Ed25519 vector JSON");
    assert_eq!(value_str(&vector, "algorithm"), "Ed25519");
    assert_eq!(value_str(&vector, "kid"), "test-kid-ed25519-v1");
    assert_eq!(vector["expected_signature_valid"].as_bool(), Some(true));

    let public_key = STANDARD
        .decode(value_str(&vector, "public_key_base64"))
        .expect("valid public key base64");
    let public_key: [u8; 32] = public_key
        .try_into()
        .expect("Ed25519 public key must be 32 bytes");

    let signature = STANDARD
        .decode(value_str(&vector, "signature_base64"))
        .expect("valid signature base64");

    let verifier = Ed25519SignatureVerifier::new(vec![LicensePublicKey {
        kid: value_str(&vector, "kid").to_owned(),
        public_key,
        revoked: false,
    }])
    .expect("test vector public key must be accepted");

    let payload = value_str(&vector, "canonical_payload_utf8").as_bytes();
    assert_eq!(
        verifier.verify(value_str(&vector, "kid"), payload, &signature),
        Ok(())
    );

    let mut tampered = payload.to_vec();
    tampered.push(b' ');
    assert_eq!(
        verifier.verify(value_str(&vector, "kid"), &tampered, &signature),
        Err(LicenseError::InvalidSignature)
    );
}

#[test]
fn committed_policy_vectors_match_client_state_machine() {
    let document: Value = serde_json::from_str(POLICY_VECTORS).expect("valid policy vector JSON");
    assert_eq!(
        value_str(&document, "contract_version"),
        LICENSE_CONTRACT_VERSION
    );

    let vectors = document["vectors"]
        .as_array()
        .expect("policy vector list must be an array");

    for vector in vectors {
        let lease_expires_at = value_u64(vector, "lease_expires_at");
        let grace_expires_at = value_u64(vector, "grace_expires_at");
        let expires_at = grace_expires_at.saturating_add(10_000);

        let claims = LicenseClaims {
            protocol_version: LICENSE_PROTOCOL_VERSION,
            contract_version: LICENSE_CONTRACT_VERSION,
            kid: "test-policy-kid",
            product_id: PRODUCT_ID,
            product_slug: PRODUCT_SLUG,
            activation_id: "activation-vector",
            device_public_key_fingerprint: "vector-device-fingerprint",
            installation_id: "vector-install",
            capabilities: &["remote.interactive"],
            issued_at: 900,
            not_before: 900,
            expires_at,
            lease_expires_at,
            sequence: value_u64(vector, "sequence"),
        };

        let context = VerificationContext {
            binding: DeviceBinding {
                activation_id: "activation-vector",
                device_public_key_fingerprint: "vector-device-fingerprint",
                installation_id: "vector-install",
            },
            last_accepted_sequence: value_u64(vector, "last_sequence"),
            revocation: if value_bool(vector, "revoked") {
                RevocationState::EntitlementRevoked
            } else {
                RevocationState::Clear
            },
            clock: LocalLicenseClock {
                now: value_u64(vector, "now"),
                last_trusted_server_time: value_u64(vector, "last_trusted_server_time"),
                grace_expires_at,
                renewal_due_at: value_u64(vector, "renewal_due_at"),
            },
        };

        let result = omnidesk_core::licensing::verify_and_evaluate(
            &AcceptTestSignature,
            b"vector-policy-payload",
            b"vector-policy-signature",
            &claims,
            &context,
        );
        assert_eq!(
            normalized_outcome(result),
            value_str(vector, "expected"),
            "policy vector {} drifted from client behavior",
            value_str(vector, "name")
        );
    }
}
