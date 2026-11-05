//! Stable public device identifiers for a single, dual-role OmniDesk application.
//!
//! IDs are derived from a verified Ed25519 public key. They identify the
//! *intended* peer for discovery, but never prove trust or authorize control.
//! A remote must still pass signed enrollment, tenant checks and local consent.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

const DEVICE_ID_DOMAIN: &[u8] = b"KMJ_OMNIDESK_PUBLIC_DEVICE_ID_V1";
const DEVICE_ID_PREFIX: &str = "KMJ-";
pub const DEVICE_ID_LENGTH: usize = 68;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDeviceIdError {
    InvalidPublicKey,
    InvalidFormat,
    OwnDevice,
}

impl std::fmt::Display for PublicDeviceIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("device public key is invalid"),
            Self::InvalidFormat => f.write_str("remote device ID has invalid format"),
            Self::OwnDevice => f.write_str("cannot connect to this device itself"),
        }
    }
}
impl std::error::Error for PublicDeviceIdError {}

/// A canonical, public, non-secret locator that can be copied between PCs.
/// It must NOT be treated as an authenticated or authorized peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicDeviceId(String);

impl PublicDeviceId {
    /// Derive a stable 256-bit public locator from a valid Ed25519 public key.
    ///
    /// # Errors
    /// Rejects invalid Ed25519 point encodings and the all-zero key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Result<Self, PublicDeviceIdError> {
        if public_key.iter().all(|&b| b == 0)
            || VerifyingKey::from_bytes(public_key).is_err()
        {
            return Err(PublicDeviceIdError::InvalidPublicKey);
        }
        let digest = Sha256::new()
            .chain_update(DEVICE_ID_DOMAIN)
            .chain_update(public_key)
            .finalize();
        let mut id = String::with_capacity(DEVICE_ID_LENGTH);
        id.push_str(DEVICE_ID_PREFIX);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut id, "{byte:02X}").expect("writing into a String cannot fail");
        }
        Ok(Self(id))
    }

    /// Parse only the exact canonical ID representation (no silent normalization).
    ///
    /// # Errors
    /// Rejects whitespace, Unicode lookalikes, lowercase, punctuation, and
    /// non-canonical lengths. Parsing NEVER establishes peer trust.
    pub fn parse(value: &str) -> Result<Self, PublicDeviceIdError> {
        let body = value
            .strip_prefix(DEVICE_ID_PREFIX)
            .ok_or(PublicDeviceIdError::InvalidFormat)?;
        if value.len() != DEVICE_ID_LENGTH
            || !body.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        {
            return Err(PublicDeviceIdError::InvalidFormat);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Prevent a selected local ID from being silently routed to self.
    ///
    /// # Errors
    /// Refuses a self-target. Other IDs still require signed pairing and consent.
    pub fn require_remote(&self, own: &Self) -> Result<(), PublicDeviceIdError> {
        if self == own {
            Err(PublicDeviceIdError::OwnDevice)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use super::*;

    fn id_for(seed: u8) -> PublicDeviceId {
        let public_key = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        PublicDeviceId::from_public_key(&public_key).expect("valid public key")
    }

    #[test]
    fn stable_and_different_for_distinct_install_keys() {
        assert_eq!(id_for(7), id_for(7));
        assert_ne!(id_for(7), id_for(8));
        assert_eq!(id_for(7).as_str().len(), DEVICE_ID_LENGTH);
    }

    #[test]
    fn canonical_round_trip_and_ascii_only() {
        let generated = id_for(7);
        assert_eq!(PublicDeviceId::parse(generated.as_str()).unwrap(), generated);
        assert!(generated.as_str().starts_with("KMJ-"));
        assert!(generated.as_str()[4..].bytes().all(|c|
            c.is_ascii_digit() || (b'A'..=b'F').contains(&c)));
    }

    #[test]
    fn rejects_ambiguous_or_malformed_remote_ids() {
        let valid = id_for(7).as_str().to_owned();
        for invalid in [
            "".to_owned(),
            " ".to_owned(),
            format!(" {valid}"),
            format!("{valid} "),
            valid.to_lowercase(),
            valid.replace("KMJ-", "KМJ-"), // Cyrillic homoglyph
            format!("{valid}0"),
            valid[..valid.len() - 1].to_owned(),
            format!("KMJ-{}", "G".repeat(64)),
            format!("KMJ-{}", "0".repeat(63) + "\n"),
        ] {
            assert_eq!(PublicDeviceId::parse(&invalid), Err(PublicDeviceIdError::InvalidFormat));
        }
    }

    #[test]
    fn rejects_zero_key_and_self_connection() {
        assert_eq!(PublicDeviceId::from_public_key(&[0; 32]),
            Err(PublicDeviceIdError::InvalidPublicKey));
        assert_eq!(id_for(7).require_remote(&id_for(7)),
            Err(PublicDeviceIdError::OwnDevice));
        assert_eq!(id_for(7).require_remote(&id_for(8)), Ok(()));
    }
}
