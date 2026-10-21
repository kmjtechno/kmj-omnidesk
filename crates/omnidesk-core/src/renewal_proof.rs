//! Domain-separated Ed25519 proof-of-possession for lease renewal.
//!
//! Renewal must prove that the caller still controls the device key bound to
//! the activation. The signed message binds the current lease identity,
//! monotonic sequence, server challenge, fresh client nonce, and client
//! version so a signature cannot be replayed across renewals or protocols.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};

const RENEWAL_PROOF_DOMAIN: &[u8] = b"KMJ-OMNIDESK-RENEW-v1";

#[derive(Debug, Clone, Copy)]
pub struct RenewalProofInput<'a> {
    pub activation_id: &'a str,
    pub current_jti: &'a str,
    pub current_sequence: u64,
    pub server_challenge: &'a str,
    pub client_nonce: &'a str,
    pub client_version: &'a str,
}

fn push_field(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

/// Canonical binary message signed for one renewal request.
#[must_use]
pub fn renewal_proof_message(input: RenewalProofInput<'_>) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(RENEWAL_PROOF_DOMAIN);
    for value in [
        input.activation_id,
        input.current_jti,
        &input.current_sequence.to_string(),
        input.server_challenge,
        input.client_nonce,
        input.client_version,
    ] {
        push_field(&mut output, value);
    }
    output
}

/// Returns the canonical base64url-no-padding Ed25519 renewal signature.
#[must_use]
pub fn sign_renewal_proof(signing_key: &SigningKey, input: RenewalProofInput<'_>) -> String {
    let signature = signing_key.sign(&renewal_proof_message(input));
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};

    use super::*;

    fn input() -> RenewalProofInput<'static> {
        RenewalProofInput {
            activation_id: "activation-12345678",
            current_jti: "jti-0123456789abcdef",
            current_sequence: 7,
            server_challenge: "challenge-0123456789abcdef",
            client_nonce: "nonce-fedcba9876543210",
            client_version: "0.0.1",
        }
    }

    #[test]
    fn renewal_signature_verifies_only_for_exact_request() {
        let key = SigningKey::from_bytes(&[20_u8; 32]);
        let original = input();
        let encoded = sign_renewal_proof(&key, original);
        let raw = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();

        key.verifying_key()
            .verify(&renewal_proof_message(original), &signature)
            .unwrap();

        let mut changed = input();
        changed.server_challenge = "challenge-fedcba9876543210";
        assert!(
            key.verifying_key()
                .verify(&renewal_proof_message(changed), &signature)
                .is_err()
        );
    }

    #[test]
    fn sequence_nonce_and_jti_are_cryptographically_bound() {
        let original = renewal_proof_message(input());

        let mut changed = input();
        changed.current_sequence = 8;
        assert_ne!(original, renewal_proof_message(changed));

        let mut changed = input();
        changed.client_nonce = "nonce-0123456789abcdef";
        assert_ne!(original, renewal_proof_message(changed));

        let mut changed = input();
        changed.current_jti = "jti-fedcba9876543210";
        assert_ne!(original, renewal_proof_message(changed));
    }

    #[test]
    fn golden_vector_is_stable_for_cross_language_verifiers() {
        let key = SigningKey::from_bytes(&[20_u8; 32]);
        let proof = input();

        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            "IIKL9cW9ystoSGMzbCAvtVmdpIvlWWYVdCFwcFvsqfc"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(renewal_proof_message(proof)),
            "S01KLU9NTklERVNLLVJFTkVXLXYxAAAAE2FjdGl2YXRpb24tMTIzNDU2NzgAAAAUanRpLTAxMjM0NTY3ODlhYmNkZWYAAAABNwAAABpjaGFsbGVuZ2UtMDEyMzQ1Njc4OWFiY2RlZgAAABZub25jZS1mZWRjYmE5ODc2NTQzMjEwAAAABTAuMC4x"
        );
        assert_eq!(
            sign_renewal_proof(&key, proof),
            "wlnKmf7B4cEBJbctnucygV9z-bz1Is5psWXdVgP5GgE0J6IvjzucJv-2mphxh7ztYj6JuO1N03_HLET1jLt_BQ"
        );
    }
}
