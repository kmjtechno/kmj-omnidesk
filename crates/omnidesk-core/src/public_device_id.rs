//! Stable public device identifiers for a single, dual-role `OmniDesk` application.
//!
//! IDs are derived from a verified Ed25519 public key. They identify the
//! *intended* peer for discovery, but never prove trust or authorize control.
//! A remote must still pass signed enrollment, tenant checks and local consent.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use crate::trusted_device_store::{TrustedDeviceRecord, TrustedDeviceStore};

const DEVICE_ID_DOMAIN: &[u8] = b"KMJ_OMNIDESK_PUBLIC_DEVICE_ID_V1";
const DEVICE_ID_PREFIX: &str = "KMJ-";
// 224-bit public locator fits the existing 64-byte peer-identity bound.
pub const DEVICE_ID_LENGTH: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDeviceIdError {
    InvalidPublicKey,
    InvalidFormat,
    OwnDevice,
    PeerKeyMismatch,
    UntrustedPeer,
    AmbiguousPeer,
}

impl std::fmt::Display for PublicDeviceIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("device public key is invalid"),
            Self::InvalidFormat => f.write_str("remote device ID has invalid format"),
            Self::OwnDevice => f.write_str("cannot connect to this device itself"),
            Self::PeerKeyMismatch => {
                f.write_str("authenticated peer key does not match requested device ID")
            }
            Self::UntrustedPeer => f.write_str("peer is not enrolled or trust has expired"),
            Self::AmbiguousPeer => f.write_str("multiple trust records match the same peer key"),
        }
    }
}
impl std::error::Error for PublicDeviceIdError {}

/// A canonical, public, non-secret locator that can be copied between PCs.
/// It must NOT be treated as an authenticated or authorized peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicDeviceId(String);

impl PublicDeviceId {
    /// Derive a stable 224-bit public locator from a valid Ed25519 public key.
    ///
    /// # Errors
    /// Rejects invalid Ed25519 point encodings and the all-zero key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Result<Self, PublicDeviceIdError> {
        if public_key.iter().all(|&b| b == 0) || VerifyingKey::from_bytes(public_key).is_err() {
            return Err(PublicDeviceIdError::InvalidPublicKey);
        }
        let digest = Sha256::new()
            .chain_update(DEVICE_ID_DOMAIN)
            .chain_update(public_key)
            .finalize();
        let mut id = String::with_capacity(DEVICE_ID_LENGTH);
        id.push_str(DEVICE_ID_PREFIX);
        for byte in digest.iter().take(28) {
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
            || !body
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        {
            return Err(PublicDeviceIdError::InvalidFormat);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Bind the selected remote ID to the peer's authenticated public key.
    ///
    /// This must be called *after* independent signature authentication, not
    /// as a substitute for it. A valid ID or matching key does not authorize
    /// screen, input or unattended access.
    ///
    /// # Errors
    /// Rejects invalid peer key encodings or a key different from the
    /// public identity selected by the user.
    pub fn require_matching_public_key(
        &self,
        authenticated_public_key: &[u8; 32],
    ) -> Result<(), PublicDeviceIdError> {
        let authenticated_id = Self::from_public_key(authenticated_public_key)?;
        if self == &authenticated_id {
            Ok(())
        } else {
            Err(PublicDeviceIdError::PeerKeyMismatch)
        }
    }

    /// Resolve exactly one unrevoked, unexpired, enrolled public key for a requested ID.
    ///
    /// Do not interpret a returned record as permission to control the device:
    /// the separate transport must authenticate the key, bind session/tenant,
    /// enforce encryption and require consent or valid unattended proof.
    ///
    /// # Errors
    /// Rejects unknown/expired/revoked identities and ambiguous trust entries.
    pub fn resolve_trusted_peer<'a>(
        &self,
        store: &'a TrustedDeviceStore,
        now_epoch_secs: u64,
    ) -> Result<&'a TrustedDeviceRecord, PublicDeviceIdError> {
        let mut matching = store.devices().iter().filter(|record| {
            Self::from_public_key(&record.public_key)
                .is_ok_and(|derived| &derived == self)
        });
        let record = matching.next().ok_or(PublicDeviceIdError::UntrustedPeer)?;
        if matching.next().is_some() {
            return Err(PublicDeviceIdError::AmbiguousPeer);
        }
        if now_epoch_secs < record.enrolled_at_epoch_secs || !record.is_trusted_at(now_epoch_secs) {
            return Err(PublicDeviceIdError::UntrustedPeer);
        }
        Ok(record)
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
    use super::*;
    use ed25519_dalek::SigningKey;

    fn id_for(seed: u8) -> PublicDeviceId {
        let public_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        PublicDeviceId::from_public_key(&public_key).expect("valid public key")
    }

    #[test]
    fn stable_and_different_for_distinct_install_keys() {
        assert_eq!(id_for(7), id_for(7));
        assert_ne!(id_for(7), id_for(8));
        assert_eq!(id_for(7).as_str().len(), DEVICE_ID_LENGTH);
    }

    #[test]
    fn public_id_fits_existing_session_identity_boundary() {
        use crate::session::{MAX_PEER_IDENTITY_BYTES, PeerIdentity};
        let id = id_for(7);
        assert!(id.as_str().len() <= MAX_PEER_IDENTITY_BYTES);
        assert_eq!(
            PeerIdentity::new(id.as_str()).unwrap().as_str(),
            id.as_str()
        );
    }

    #[test]
    fn canonical_round_trip_and_ascii_only() {
        let generated = id_for(7);
        assert_eq!(
            PublicDeviceId::parse(generated.as_str()).unwrap(),
            generated
        );
        assert!(generated.as_str().starts_with("KMJ-"));
        assert!(
            generated.as_str()[4..]
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
        );
    }

    #[test]
    fn rejects_ambiguous_or_malformed_remote_ids() {
        let valid = id_for(7).as_str().to_owned();
        for invalid in [
            String::new(),
            " ".to_owned(),
            format!(" {valid}"),
            format!("{valid} "),
            valid.to_lowercase(),
            valid.replace("KMJ-", "KМJ-"), // Cyrillic homoglyph
            format!("{valid}0"),
            valid[..valid.len() - 1].to_owned(),
            format!("KMJ-{}", "G".repeat(56)),
            format!("KMJ-{}", "0".repeat(55) + "\n"),
        ] {
            assert_eq!(
                PublicDeviceId::parse(&invalid),
                Err(PublicDeviceIdError::InvalidFormat)
            );
        }
    }

    #[test]
    fn requested_id_must_match_authenticated_peer_key() {
        let expected = id_for(7);
        let correct = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let impostor = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(expected.require_matching_public_key(&correct), Ok(()));
        assert_eq!(
            expected.require_matching_public_key(&impostor),
            Err(PublicDeviceIdError::PeerKeyMismatch)
        );
        assert_eq!(
            expected.require_matching_public_key(&[0; 32]),
            Err(PublicDeviceIdError::InvalidPublicKey)
        );
    }

    #[test]
    fn trusted_lookup_rejects_unknown_revoked_expired_and_duplicate_keys() {
        use crate::trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord};
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let id = id_for(7);
        let mut store = TrustedDeviceStore::new();
        assert_eq!(
            id.resolve_trusted_peer(&store, 100).err(),
            Some(PublicDeviceIdError::UntrustedPeer)
        );
        let record = TrustedDeviceRecord {
            device_id: "peer-1".to_owned(),
            display_name: "Peer".to_owned(),
            public_key: key,
            enrolled_at_epoch_secs: 10,
            trust_expires_at_epoch_secs: 200,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        };
        store.add(record.clone()).unwrap();
        assert_eq!(
            id.resolve_trusted_peer(&store, 100).unwrap().device_id,
            "peer-1"
        );
        assert_eq!(
            id.resolve_trusted_peer(&store, 200).err(),
            Some(PublicDeviceIdError::UntrustedPeer)
        );
        assert!(store.revoke("peer-1"));
        assert_eq!(
            id.resolve_trusted_peer(&store, 100).err(),
            Some(PublicDeviceIdError::UntrustedPeer)
        );
        let mut duplicate_store = TrustedDeviceStore::new();
        duplicate_store.add(record.clone()).unwrap();
        let mut duplicate = record;
        duplicate.device_id = "peer-2".to_owned();
        duplicate_store.add(duplicate).unwrap();
        assert_eq!(
            id.resolve_trusted_peer(&duplicate_store, 100).err(),
            Some(PublicDeviceIdError::AmbiguousPeer)
        );
    }

    #[test]
    fn rejects_zero_key_and_self_connection() {
        assert_eq!(
            PublicDeviceId::from_public_key(&[0; 32]),
            Err(PublicDeviceIdError::InvalidPublicKey)
        );
        assert_eq!(
            id_for(7).require_remote(&id_for(7)),
            Err(PublicDeviceIdError::OwnDevice)
        );
        assert_eq!(id_for(7).require_remote(&id_for(8)), Ok(()));
    }
}
