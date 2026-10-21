//! Fail-closed proof-of-possession for first-device activation.
//!
//! Main Platform must never bind a commercial entitlement to a caller merely
//! because the caller supplied a public key. The activation request therefore
//! signs a domain-separated, length-prefixed message with that device key.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const ACTIVATION_PROOF_DOMAIN: &[u8] = b"KMJ-OMNIDESK-ACTIVATE-v1";

#[derive(Debug, Clone, Copy)]
pub struct ActivationProofInput<'a> {
    pub idempotency_key: &'a str,
    pub license_or_entitlement_reference: &'a str,
    pub device_public_key: &'a str,
    pub device_public_key_fingerprint: &'a str,
    pub installation_id: &'a str,
    pub client_version: &'a str,
    pub protocol_version: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub client_nonce: &'a str,
}

fn push_field(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

/// Canonical binary message signed by the device during first activation.
///
/// Each UTF-8 field is prefixed by a 32-bit big-endian byte length. This avoids
/// delimiter ambiguity and is straightforward to reproduce in other languages.
#[must_use]
pub fn activation_proof_message(input: ActivationProofInput<'_>) -> Vec<u8> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(ACTIVATION_PROOF_DOMAIN);
    for value in [
        input.idempotency_key,
        input.license_or_entitlement_reference,
        input.device_public_key,
        input.device_public_key_fingerprint,
        input.installation_id,
        input.client_version,
        input.protocol_version,
        input.platform,
        input.architecture,
        input.client_nonce,
    ] {
        push_field(&mut output, value);
    }
    output
}

/// Returns the canonical base64url-no-padding Ed25519 signature for activation.
#[must_use]
pub fn sign_activation_proof(signing_key: &SigningKey, input: ActivationProofInput<'_>) -> String {
    let signature = signing_key.sign(&activation_proof_message(input));
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

/// Canonical SHA-256 fingerprint for the raw 32-byte Ed25519 public key.
#[must_use]
pub fn device_public_key_fingerprint(signing_key: &SigningKey) -> String {
    let digest = Sha256::digest(signing_key.verifying_key().to_bytes());
    format!("sha256:{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};

    use super::*;

    fn input<'a>(public_key: &'a str, fingerprint: &'a str) -> ActivationProofInput<'a> {
        ActivationProofInput {
            idempotency_key: "idem-0123456789abcdef",
            license_or_entitlement_reference: "entitlement-123",
            device_public_key: public_key,
            device_public_key_fingerprint: fingerprint,
            installation_id: "install-12345678",
            client_version: "0.0.1",
            protocol_version: "KSLP-v1",
            platform: "windows",
            architecture: "x86_64",
            client_nonce: "nonce-0123456789abcdef",
        }
    }

    #[test]
    fn activation_signature_verifies_only_for_exact_request() {
        let key = SigningKey::from_bytes(&[17_u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let fingerprint = device_public_key_fingerprint(&key);
        let original = input(&public, &fingerprint);
        let encoded = sign_activation_proof(&key, original);
        let raw = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();

        key.verifying_key()
            .verify(&activation_proof_message(original), &signature)
            .unwrap();

        let mut changed = input(&public, &fingerprint);
        changed.client_nonce = "nonce-fedcba9876543210";
        assert!(
            key.verifying_key()
                .verify(&activation_proof_message(changed), &signature)
                .is_err()
        );
    }

    #[test]
    fn idempotency_key_is_cryptographically_bound() {
        let key = SigningKey::from_bytes(&[18_u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        let fingerprint = device_public_key_fingerprint(&key);
        let original = input(&public, &fingerprint);
        let message = activation_proof_message(original);

        let mut changed = input(&public, &fingerprint);
        changed.idempotency_key = "idem-fedcba9876543210";
        assert_ne!(message, activation_proof_message(changed));
    }

    #[test]
    fn fingerprint_is_stable_and_domain_tagged() {
        let key = SigningKey::from_bytes(&[19_u8; 32]);
        let fingerprint = device_public_key_fingerprint(&key);
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), 71);
    }
}
