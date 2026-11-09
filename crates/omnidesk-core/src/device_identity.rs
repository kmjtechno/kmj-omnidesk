//! Persistent cryptographic device identity.
//!
//! Provides:
//! - Ed25519 per-install cryptographic keypair.
//! - Canonical public Device ID (e.g., `KMJ-XXX-XXX-XXX`) derived strictly from the
//!   public key, independent of hostname or IP address.
//! - Safe local persistence with atomic file replace.
//! - Redacted [`std::fmt::Debug`] to ensure secret keys are never leaked to logs or displays.
//! - Strict validation and normalization for Remote ID inputs.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::device_enrollment::generate_csprng_nonce;

const IDENTITY_DOMAIN: &[u8] = b"KMJ_OMNIDESK_DEVICE_ID_V1";

/// Maximum length of a valid Remote ID input string in bytes.
pub const MAX_REMOTE_ID_LEN: usize = 32;

/// Minimum length of a valid Remote ID input string in bytes.
pub const MIN_REMOTE_ID_LEN: usize = 3;

/// Errors arising during device identity operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceIdentityError {
    Io(String),
    Json(String),
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidPublicKey,
    InvalidPrivateKey,
    CorruptedData(String),
}

impl std::fmt::Display for DeviceIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "identity I/O error: {err}"),
            Self::Json(err) => write!(f, "identity serialization error: {err}"),
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::InvalidPrivateKey => write!(f, "invalid Ed25519 private key"),
            Self::CorruptedData(reason) => write!(f, "corrupted identity data: {reason}"),
        }
    }
}

impl std::error::Error for DeviceIdentityError {}

/// Errors encountered when validating a user-provided Remote ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteIdError {
    Empty,
    TooShort { len: usize, min: usize },
    TooLong { len: usize, max: usize },
    InvalidCharacter(char),
    SelfConnectionBlocked,
}

impl std::fmt::Display for RemoteIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Remote ID cannot be empty"),
            Self::TooShort { len, min } => {
                write!(
                    f,
                    "Remote ID length ({len}) is shorter than minimum ({min})"
                )
            }
            Self::TooLong { len, max } => {
                write!(f, "Remote ID length ({len}) exceeds maximum ({max})")
            }
            Self::InvalidCharacter(c) => write!(f, "Remote ID contains invalid character: '{c}'"),
            Self::SelfConnectionBlocked => {
                write!(f, "Cannot connect to self: Remote ID matches local Your ID")
            }
        }
    }
}

impl std::error::Error for RemoteIdError {}

/// On-disk representation of the device cryptographic identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedIdentity {
    schema_version: u32,
    public_id: String,
    public_key_hex: String,
    private_key_hex: String,
    created_at_epoch_secs: u64,
}

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Cryptographic device identity.
///
/// Contains the Ed25519 private key, public key, and canonical formatted public ID.
/// [`std::fmt::Debug`] explicitly redacts the private key.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_id: String,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public_id", &self.public_id)
            .field(
                "public_key_hex",
                &encode_hex(&self.verifying_key.to_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Generates a fresh device identity with a CSPRNG seed.
    #[must_use]
    pub fn generate(now_epoch_secs: u64) -> Self {
        let seed = generate_csprng_nonce(now_epoch_secs);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_id = format_public_id(&verifying_key.to_bytes());
        Self {
            signing_key,
            verifying_key,
            public_id,
        }
    }

    /// Constructs an identity from an explicit 32-byte Ed25519 private key seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_id = format_public_id(&verifying_key.to_bytes());
        Self {
            signing_key,
            verifying_key,
            public_id,
        }
    }

    /// Canonical human-readable public device ID (e.g. `KMJ-123-456-789`).
    #[must_use]
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// Ed25519 verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// 32-byte Ed25519 public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Signs a byte message using the device's private key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Loads an existing identity from disk or creates and saves a fresh one.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIdentityError`] on I/O, parsing, or file creation failures.
    pub fn load_or_create(path: &Path, now_epoch_secs: u64) -> Result<Self, DeviceIdentityError> {
        if path.exists() {
            Self::load_from_path(path)
        } else {
            let identity = Self::generate(now_epoch_secs);
            identity.save_to_path(path, now_epoch_secs)?;
            Ok(identity)
        }
    }

    /// Loads an identity from a specific file path.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIdentityError`] if the file cannot be read or parsed.
    pub fn load_from_path(path: &Path) -> Result<Self, DeviceIdentityError> {
        let mut file = File::open(path)
            .map_err(|err| DeviceIdentityError::Io(format!("cannot open identity file: {err}")))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|err| DeviceIdentityError::Io(format!("cannot read identity file: {err}")))?;

        let persisted: PersistedIdentity = serde_json::from_slice(&content).map_err(|err| {
            DeviceIdentityError::Json(format!("cannot deserialize identity: {err}"))
        })?;

        let private_bytes = decode_hex(&persisted.private_key_hex).map_err(|e| {
            DeviceIdentityError::CorruptedData(format!("invalid private key hex: {e}"))
        })?;
        if private_bytes.len() != 32 {
            return Err(DeviceIdentityError::InvalidKeyLength {
                expected: 32,
                actual: private_bytes.len(),
            });
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&private_bytes);

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let expected_public_hex = encode_hex(&verifying_key.to_bytes());

        if !expected_public_hex.eq_ignore_ascii_case(&persisted.public_key_hex) {
            return Err(DeviceIdentityError::CorruptedData(
                "public key does not match private key".to_owned(),
            ));
        }

        let canonical_id = format_public_id(&verifying_key.to_bytes());
        Ok(Self {
            signing_key,
            verifying_key,
            public_id: canonical_id,
        })
    }

    /// Atomically saves the identity to disk via a temporary sibling file and replace.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIdentityError`] on serialization or filesystem errors.
    pub fn save_to_path(
        &self,
        target_path: &Path,
        now_epoch_secs: u64,
    ) -> Result<(), DeviceIdentityError> {
        if let Some(parent) = target_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    DeviceIdentityError::Io(format!("cannot create directory: {err}"))
                })?;
            }
        }

        let persisted = PersistedIdentity {
            schema_version: CURRENT_SCHEMA_VERSION,
            public_id: self.public_id.clone(),
            public_key_hex: encode_hex(&self.verifying_key.to_bytes()),
            private_key_hex: encode_hex(&self.signing_key.to_bytes()),
            created_at_epoch_secs: now_epoch_secs,
        };

        let json_bytes = serde_json::to_vec_pretty(&persisted).map_err(|err| {
            DeviceIdentityError::Json(format!("cannot serialize identity: {err}"))
        })?;

        let temp_path = target_path.with_extension(format!("tmp.{}", std::process::id()));

        let mut temp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|err| {
                DeviceIdentityError::Io(format!("cannot open temporary identity file: {err}"))
            })?;

        temp_file.write_all(&json_bytes).map_err(|err| {
            let _ = std::fs::remove_file(&temp_path);
            DeviceIdentityError::Io(format!("cannot write temporary identity file: {err}"))
        })?;

        temp_file.sync_all().map_err(|err| {
            let _ = std::fs::remove_file(&temp_path);
            DeviceIdentityError::Io(format!("cannot sync temporary identity file: {err}"))
        })?;

        drop(temp_file);

        std::fs::rename(&temp_path, target_path).map_err(|err| {
            let _ = std::fs::remove_file(&temp_path);
            DeviceIdentityError::Io(format!("cannot replace target identity file: {err}"))
        })?;

        Ok(())
    }
}

/// Derives a deterministic canonical public ID from an Ed25519 public key.
///
/// Formats as `KMJ-XXX-XXX-XXX` (9 digits grouped in threes).
#[must_use]
pub fn format_public_id(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(public_key);
    let hash = hasher.finalize();

    let num = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 900_000_000 + 100_000_000;
    let g1 = num / 1_000_000;
    let g2 = (num / 1_000) % 1_000;
    let g3 = num % 1_000;
    format!("KMJ-{g1:03}-{g2:03}-{g3:03}")
}

/// Normalizes a user-entered Remote ID into canonical `KMJ-XXX-XXX-XXX` format.
///
/// Strips spaces, dashes, and optional "KMJ" prefix, or preserves valid network endpoints.
#[must_use]
pub fn normalize_remote_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
        return Some(addr.to_string());
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(format!("{ip}:21118"));
    }

    let mut digits = String::with_capacity(16);
    let body = if trimmed.len() >= 3 && trimmed[..3].eq_ignore_ascii_case("KMJ") {
        &trimmed[3..]
    } else {
        trimmed
    };

    for c in body.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if c != '-' && c != ' ' && c != '_' {
            return None;
        }
    }

    if digits.len() == 9 {
        let g1 = &digits[0..3];
        let g2 = &digits[3..6];
        let g3 = &digits[6..9];
        Some(format!("KMJ-{g1}-{g2}-{g3}"))
    } else if digits.len() >= 3 && digits.len() <= 16 {
        Some(format!("KMJ-{digits}"))
    } else {
        None
    }
}

/// Validates a candidate Remote ID string, returning normalized canonical format on success.
///
/// # Errors
///
/// Returns [`RemoteIdError`] on empty input, invalid length, or invalid characters.
pub fn validate_remote_id(input: &str, local_id: Option<&str>) -> Result<String, RemoteIdError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(RemoteIdError::Empty);
    }
    if trimmed.len() < MIN_REMOTE_ID_LEN {
        return Err(RemoteIdError::TooShort {
            len: trimmed.len(),
            min: MIN_REMOTE_ID_LEN,
        });
    }
    if trimmed.len() > MAX_REMOTE_ID_LEN {
        return Err(RemoteIdError::TooLong {
            len: trimmed.len(),
            max: MAX_REMOTE_ID_LEN,
        });
    }

    for c in trimmed.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != ' ' && c != '_' && c != '.' && c != ':' {
            return Err(RemoteIdError::InvalidCharacter(c));
        }
    }

    let normalized = normalize_remote_id(trimmed).ok_or(RemoteIdError::TooShort {
        len: trimmed.len(),
        min: 9,
    })?;

    if let Some(local) = local_id {
        if normalized.eq_ignore_ascii_case(local) {
            return Err(RemoteIdError::SelfConnectionBlocked);
        }
    }

    Ok(normalized)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex length must be even".to_owned());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at {i}: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_public_id_is_deterministic_and_canonical() {
        let key = [42_u8; 32];
        let id1 = format_public_id(&key);
        let id2 = format_public_id(&key);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("KMJ-"));
        assert_eq!(id1.len(), 15); // "KMJ-XXX-XXX-XXX"
    }

    #[test]
    fn normalize_remote_id_accepts_various_formats() {
        let expected = "KMJ-123-456-789";
        assert_eq!(
            normalize_remote_id("123 456 789").as_deref(),
            Some(expected)
        );
        assert_eq!(
            normalize_remote_id("123-456-789").as_deref(),
            Some(expected)
        );
        assert_eq!(normalize_remote_id("123456789").as_deref(), Some(expected));
        assert_eq!(
            normalize_remote_id("KMJ-123-456-789").as_deref(),
            Some(expected)
        );
        assert_eq!(
            normalize_remote_id("kmj 123 456 789").as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn validate_remote_id_rejects_empty_and_invalid() {
        assert_eq!(validate_remote_id("", None), Err(RemoteIdError::Empty));
        assert_eq!(validate_remote_id("  ", None), Err(RemoteIdError::Empty));
        assert!(matches!(
            validate_remote_id("12", None),
            Err(RemoteIdError::TooShort { .. })
        ));
        assert!(matches!(
            validate_remote_id("123$456", None),
            Err(RemoteIdError::InvalidCharacter('$'))
        ));
    }

    #[test]
    fn validate_remote_id_rejects_self_connection() {
        let local = "KMJ-123-456-789";
        assert_eq!(
            validate_remote_id("123 456 789", Some(local)),
            Err(RemoteIdError::SelfConnectionBlocked)
        );
        assert_eq!(
            validate_remote_id("KMJ-123-456-789", Some(local)),
            Err(RemoteIdError::SelfConnectionBlocked)
        );
        assert_eq!(
            validate_remote_id("kmj-123-456-789", Some(local)),
            Err(RemoteIdError::SelfConnectionBlocked)
        );
    }

    #[test]
    fn identity_persistence_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("omnidesk-ident-test-{}", std::process::id()));
        let ident_path = temp_dir.join("identity.json");

        let identity1 = DeviceIdentity::generate(1_700_000_000);
        let id1_str = identity1.public_id().to_owned();
        identity1
            .save_to_path(&ident_path, 1_700_000_000)
            .expect("save should succeed");

        let identity2 = DeviceIdentity::load_from_path(&ident_path).expect("load should succeed");
        assert_eq!(identity2.public_id(), id1_str);
        assert_eq!(identity2.public_key_bytes(), identity1.public_key_bytes());

        // Signature verification roundtrip
        let msg = b"test message to sign";
        let sig = identity1.sign(msg);
        let verifying = identity2.verifying_key();
        assert!(
            verifying
                .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );

        // Cleanup
        let _ = std::fs::remove_file(&ident_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn debug_redacts_private_key() {
        let identity = DeviceIdentity::generate(1_700_000_000);
        let debug_str = format!("{identity:?}");
        assert!(debug_str.contains("DeviceIdentity"));
        assert!(debug_str.contains("public_id"));
        assert!(!debug_str.contains("signing_key"));
        assert!(!debug_str.contains("private_key"));
    }
}
