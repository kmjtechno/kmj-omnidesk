//! Strict parser for KMJ Main Platform `OmniDesk` verification-key discovery.
//!
//! The network transport is intentionally outside this module. Callers provide
//! the response bytes from the trusted Main Platform endpoint and this boundary
//! validates the exact protocol/product/algorithm envelope before constructing
//! the local Ed25519 verifier.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::{
    PRODUCT_ID,
    licensing::{
        Ed25519SignatureVerifier, LICENSE_CONTRACT_VERSION, LICENSE_PROTOCOL_VERSION,
        LicenseKeySetError, LicenseKeyStatus, LicensePublicKey,
    },
};

const SIGNING_ALGORITHM: &str = "Ed25519";
const MAX_KEY_DISCOVERY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDiscoveryError {
    EmptyResponse,
    ResponseTooLarge,
    MalformedResponse,
    ProtocolMismatch,
    ContractMismatch,
    ProductMismatch,
    AlgorithmMismatch,
    EmptyKeySet,
    InvalidKeyEncoding,
    InvalidKeySet(LicenseKeySetError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryEnvelope {
    protocol_version: String,
    contract_version: String,
    product_id: String,
    algorithm: String,
    keys: Vec<DiscoveryKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryKey {
    kid: String,
    algorithm: String,
    public_key_base64: String,
    not_before: u64,
    not_after: u64,
    status: DiscoveryStatus,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum DiscoveryStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "ROLLOVER")]
    Rollover,
}

/// Parses the Main Platform verification-key response and builds the
/// fail-closed local Ed25519 verifier.
///
/// # Errors
///
/// Rejects malformed/oversized responses, protocol or product drift, any
/// non-Ed25519 key, malformed key bytes, an empty key set, and invalid or
/// duplicate key metadata.
pub fn verifier_from_main_platform_keys(
    response: &[u8],
    trusted_time: u64,
) -> Result<Ed25519SignatureVerifier, KeyDiscoveryError> {
    if response.is_empty() {
        return Err(KeyDiscoveryError::EmptyResponse);
    }
    if response.len() > MAX_KEY_DISCOVERY_BYTES {
        return Err(KeyDiscoveryError::ResponseTooLarge);
    }

    let envelope: DiscoveryEnvelope =
        serde_json::from_slice(response).map_err(|_| KeyDiscoveryError::MalformedResponse)?;

    if envelope.protocol_version != LICENSE_PROTOCOL_VERSION {
        return Err(KeyDiscoveryError::ProtocolMismatch);
    }
    if envelope.contract_version != LICENSE_CONTRACT_VERSION {
        return Err(KeyDiscoveryError::ContractMismatch);
    }
    if envelope.product_id != PRODUCT_ID {
        return Err(KeyDiscoveryError::ProductMismatch);
    }
    if envelope.algorithm != SIGNING_ALGORITHM {
        return Err(KeyDiscoveryError::AlgorithmMismatch);
    }
    if envelope.keys.is_empty() {
        return Err(KeyDiscoveryError::EmptyKeySet);
    }

    let mut keys = Vec::with_capacity(envelope.keys.len());
    for key in envelope.keys {
        if key.algorithm != SIGNING_ALGORITHM {
            return Err(KeyDiscoveryError::AlgorithmMismatch);
        }

        let decoded = STANDARD
            .decode(key.public_key_base64.as_bytes())
            .map_err(|_| KeyDiscoveryError::InvalidKeyEncoding)?;
        let public_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| KeyDiscoveryError::InvalidKeyEncoding)?;

        keys.push(LicensePublicKey {
            kid: key.kid,
            public_key,
            not_before: key.not_before,
            not_after: key.not_after,
            status: match key.status {
                DiscoveryStatus::Active => LicenseKeyStatus::Active,
                DiscoveryStatus::Rollover => LicenseKeyStatus::Rollover,
            },
        });
    }

    Ed25519SignatureVerifier::new(keys, trusted_time).map_err(KeyDiscoveryError::InvalidKeySet)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::licensing::{LicenseError, SignatureVerifier};

    fn response(keys: &str) -> Vec<u8> {
        format!(
            r#"{{"protocol_version":"KSLP-v1","contract_version":"kmj.omnidesk.license.v1","product_id":"KMJ_OMNIDESK","algorithm":"Ed25519","keys":[{keys}]}}"#
        )
        .into_bytes()
    }

    fn key_json(kid: &str, seed: u8, status: &str, not_before: u64, not_after: u64) -> String {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let encoded = STANDARD.encode(signing.verifying_key().to_bytes());
        format!(
            r#"{{"kid":"{kid}","algorithm":"Ed25519","public_key_base64":"{encoded}","not_before":{not_before},"not_after":{not_after},"status":"{status}"}}"#
        )
    }

    #[test]
    fn main_platform_active_and_rollover_keys_verify_cross_service_shape() {
        let active = key_json("active-1", 31, "ACTIVE", 900, 1_100);
        let rollover = key_json("rollover-1", 32, "ROLLOVER", 800, 1_050);
        let verifier =
            verifier_from_main_platform_keys(&response(&format!("{active},{rollover}")), 1_000)
                .unwrap();

        assert_eq!(verifier.key_count(), 2);

        let signing = SigningKey::from_bytes(&[31_u8; 32]);
        let payload = b"main-platform-cross-service-vector";
        let signature = signing.sign(payload).to_bytes();
        assert_eq!(verifier.verify("active-1", payload, &signature), Ok(()));
    }

    #[test]
    fn wrong_product_algorithm_or_unknown_fields_fail_closed() {
        let valid = key_json("active-1", 33, "ACTIVE", 900, 1_100);
        let wrong_product = String::from_utf8(response(&valid))
            .unwrap()
            .replace("\"KMJ_OMNIDESK\"", "\"OTHER_PRODUCT\"")
            .into_bytes();
        assert_eq!(
            verifier_from_main_platform_keys(&wrong_product, 1_000),
            Err(KeyDiscoveryError::ProductMismatch)
        );

        let wrong_algorithm = String::from_utf8(response(&valid))
            .unwrap()
            .replace("\"algorithm\":\"Ed25519\"", "\"algorithm\":\"RSA\"")
            .into_bytes();
        assert_eq!(
            verifier_from_main_platform_keys(&wrong_algorithm, 1_000),
            Err(KeyDiscoveryError::AlgorithmMismatch)
        );

        let unknown = String::from_utf8(response(&valid))
            .unwrap()
            .replace("\"keys\":[", "\"unexpected\":true,\"keys\":[")
            .into_bytes();
        assert_eq!(
            verifier_from_main_platform_keys(&unknown, 1_000),
            Err(KeyDiscoveryError::MalformedResponse)
        );
    }

    #[test]
    fn malformed_key_material_empty_set_and_duplicate_kids_are_rejected() {
        assert_eq!(
            verifier_from_main_platform_keys(&response(""), 1_000),
            Err(KeyDiscoveryError::EmptyKeySet)
        );

        let malformed = r#"{"kid":"bad","algorithm":"Ed25519","public_key_base64":"AQID","not_before":900,"not_after":1100,"status":"ACTIVE"}"#;
        assert_eq!(
            verifier_from_main_platform_keys(&response(malformed), 1_000),
            Err(KeyDiscoveryError::InvalidKeyEncoding)
        );

        let one = key_json("same", 34, "ACTIVE", 900, 1_100);
        let two = key_json("same", 35, "ROLLOVER", 900, 1_100);
        assert_eq!(
            verifier_from_main_platform_keys(&response(&format!("{one},{two}")), 1_000),
            Err(KeyDiscoveryError::InvalidKeySet(
                LicenseKeySetError::DuplicateKeyId
            ))
        );
    }

    #[test]
    fn trusted_time_still_enforces_key_window_after_discovery() {
        let key = key_json("windowed", 36, "ACTIVE", 900, 1_100);
        let verifier = verifier_from_main_platform_keys(&response(&key), 1_100).unwrap();
        let signing = SigningKey::from_bytes(&[36_u8; 32]);
        let payload = b"expired-key-window";
        let signature = signing.sign(payload).to_bytes();

        assert_eq!(
            verifier.verify("windowed", payload, &signature),
            Err(LicenseError::UnknownOrRevokedKey)
        );
    }
}
