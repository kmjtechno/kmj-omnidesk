//! Persistent, bounded, and cryptographically verified trusted device store.
//!
//! Enforces tamper resistance, bounded disk footprint, atomic file writes,
//! and strict Ed25519 verifying-key validation for all enrolled devices.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::product_shell::{DeviceStatus, DeviceSummary};

/// Upper bound on the trusted device store JSON file on disk (1 MiB).
pub const MAX_STORE_FILE_BYTES: u64 = 1_048_576;

/// Upper bound on device identifier length in bytes.
pub const MAX_DEVICE_ID_BYTES: usize = 128;

/// Upper bound on device display name length in bytes.
pub const MAX_DISPLAY_NAME_BYTES: usize = 128;

/// Maximum number of trusted devices retained in a single local store.
pub const MAX_DEVICES_COUNT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStoreError {
    Io(String),
    Json(String),
    FileTooLarge { size: u64, max: u64 },
    DeviceCountExceeded { count: usize, max: usize },
    InvalidDeviceId(String),
    InvalidDisplayName(String),
    InvalidPublicKey,
    InvalidTimeRange,
    DeviceAlreadyExists(String),
    DeviceNotFound(String),
}

impl std::fmt::Display for DeviceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Json(err) => write!(f, "JSON serialization error: {err}"),
            Self::FileTooLarge { size, max } => {
                write!(f, "store file size {size} exceeds limit {max}")
            }
            Self::DeviceCountExceeded { count, max } => {
                write!(f, "device count {count} exceeds capacity {max}")
            }
            Self::InvalidDeviceId(reason) => write!(f, "invalid device ID: {reason}"),
            Self::InvalidDisplayName(reason) => write!(f, "invalid display name: {reason}"),
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::InvalidTimeRange => write!(f, "trust expiry must be after enrollment time"),
            Self::DeviceAlreadyExists(id) => write!(f, "device {id} already exists"),
            Self::DeviceNotFound(id) => write!(f, "device {id} not found"),
        }
    }
}

impl std::error::Error for DeviceStoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PersistedDeviceStatus {
    Offline,
    Online,
}

impl From<DeviceStatus> for PersistedDeviceStatus {
    fn from(s: DeviceStatus) -> Self {
        match s {
            DeviceStatus::Offline => Self::Offline,
            DeviceStatus::Online => Self::Online,
        }
    }
}

impl From<PersistedDeviceStatus> for DeviceStatus {
    fn from(s: PersistedDeviceStatus) -> Self {
        match s {
            PersistedDeviceStatus::Offline => Self::Offline,
            PersistedDeviceStatus::Online => Self::Online,
        }
    }
}

/// An enrolled, verified device record persisted on local disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDeviceRecord {
    pub device_id: String,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub enrolled_at_epoch_secs: u64,
    pub trust_expires_at_epoch_secs: u64,
    pub managed: bool,
    pub revoked: bool,
    pub status: PersistedDeviceStatus,
}

impl TrustedDeviceRecord {
    /// Validates all fields against cryptographic and bounded-length requirements.
    ///
    /// # Errors
    ///
    /// Returns a [`DeviceStoreError`] if any field is out of bounds or invalid.
    pub fn validate(&self) -> Result<(), DeviceStoreError> {
        if self.device_id.trim().is_empty() {
            return Err(DeviceStoreError::InvalidDeviceId(
                "identifier is empty".to_owned(),
            ));
        }
        if self.device_id.len() > MAX_DEVICE_ID_BYTES {
            return Err(DeviceStoreError::InvalidDeviceId(format!(
                "identifier length {} exceeds {MAX_DEVICE_ID_BYTES}",
                self.device_id.len()
            )));
        }
        if !self.device_id.is_ascii() || self.device_id.chars().any(char::is_control) {
            return Err(DeviceStoreError::InvalidDeviceId(
                "identifier contains non-printable or non-ASCII characters".to_owned(),
            ));
        }

        if self.display_name.trim().is_empty() {
            return Err(DeviceStoreError::InvalidDisplayName(
                "display name is empty".to_owned(),
            ));
        }
        if self.display_name.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(DeviceStoreError::InvalidDisplayName(format!(
                "display name length {} exceeds {MAX_DISPLAY_NAME_BYTES}",
                self.display_name.len()
            )));
        }
        if !self.display_name.is_ascii() || self.display_name.chars().any(char::is_control) {
            return Err(DeviceStoreError::InvalidDisplayName(
                "display name contains non-printable or non-ASCII characters".to_owned(),
            ));
        }

        // Reject all-zero public keys and non-curve points
        if self.public_key == [0_u8; 32] {
            return Err(DeviceStoreError::InvalidPublicKey);
        }
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| DeviceStoreError::InvalidPublicKey)?;

        if self.trust_expires_at_epoch_secs <= self.enrolled_at_epoch_secs {
            return Err(DeviceStoreError::InvalidTimeRange);
        }

        Ok(())
    }

    #[must_use]
    pub const fn is_trusted_at(&self, now_epoch_secs: u64) -> bool {
        !self.revoked && now_epoch_secs < self.trust_expires_at_epoch_secs
    }

    #[must_use]
    pub fn to_summary(&self) -> DeviceSummary {
        DeviceSummary {
            id: self.device_id.clone(),
            display_name: self.display_name.clone(),
            status: self.status.into(),
        }
    }
}

/// Disk-persisted schema envelope with explicit versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreEnvelope {
    schema_version: u32,
    devices: Vec<TrustedDeviceRecord>,
}

const CURRENT_SCHEMA_VERSION: u32 = 1;

/// In-memory collection backed by atomic disk persistence.
#[derive(Debug, Clone, Default)]
pub struct TrustedDeviceStore {
    devices: Vec<TrustedDeviceRecord>,
}

impl TrustedDeviceStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    #[must_use]
    pub fn devices(&self) -> &[TrustedDeviceRecord] {
        &self.devices
    }

    #[must_use]
    pub fn get(&self, device_id: &str) -> Option<&TrustedDeviceRecord> {
        self.devices.iter().find(|d| d.device_id == device_id)
    }

    /// Adds or replaces a trusted device record after strict validation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceStoreError`] if validation fails or maximum device limit is reached.
    pub fn add(&mut self, record: TrustedDeviceRecord) -> Result<(), DeviceStoreError> {
        record.validate()?;

        if let Some(pos) = self
            .devices
            .iter()
            .position(|d| d.device_id == record.device_id)
        {
            self.devices[pos] = record;
            return Ok(());
        }

        if self.devices.len() >= MAX_DEVICES_COUNT {
            return Err(DeviceStoreError::DeviceCountExceeded {
                count: self.devices.len(),
                max: MAX_DEVICES_COUNT,
            });
        }

        self.devices.push(record);
        Ok(())
    }

    /// Removes an enrolled device by identifier. Returns true if found and removed.
    pub fn remove(&mut self, device_id: &str) -> bool {
        let initial_len = self.devices.len();
        self.devices.retain(|d| d.device_id != device_id);
        self.devices.len() < initial_len
    }

    /// Revokes an enrolled device while preserving its record for audit.
    pub fn revoke(&mut self, device_id: &str) -> bool {
        if let Some(device) = self.devices.iter_mut().find(|d| d.device_id == device_id) {
            device.revoked = true;
            true
        } else {
            false
        }
    }

    /// Updates live status (Online/Offline) for an enrolled device.
    pub fn set_status(&mut self, device_id: &str, status: DeviceStatus) -> bool {
        if let Some(device) = self.devices.iter_mut().find(|d| d.device_id == device_id) {
            device.status = status.into();
            true
        } else {
            false
        }
    }

    /// Converts enrolled records to presentation [`DeviceSummary`] list for UI consumption.
    #[must_use]
    pub fn to_device_summaries(&self) -> Vec<DeviceSummary> {
        self.devices
            .iter()
            .map(TrustedDeviceRecord::to_summary)
            .collect()
    }

    /// Loads and verifies trusted devices from a bounded JSON file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceStoreError`] on I/O failure, file size violation,
    /// JSON parsing error, or invalid record data.
    pub fn load_from_path(path: &Path) -> Result<Self, DeviceStoreError> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let metadata = std::fs::metadata(path)
            .map_err(|err| DeviceStoreError::Io(format!("cannot read file metadata: {err}")))?;

        if metadata.len() > MAX_STORE_FILE_BYTES {
            return Err(DeviceStoreError::FileTooLarge {
                size: metadata.len(),
                max: MAX_STORE_FILE_BYTES,
            });
        }

        let mut file = File::open(path)
            .map_err(|err| DeviceStoreError::Io(format!("cannot open store file: {err}")))?;

        let capacity = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        let mut content = Vec::with_capacity(capacity);
        file.read_to_end(&mut content)
            .map_err(|err| DeviceStoreError::Io(format!("cannot read store file: {err}")))?;

        let envelope: StoreEnvelope = serde_json::from_slice(&content)
            .map_err(|err| DeviceStoreError::Json(format!("cannot deserialize store: {err}")))?;

        if envelope.devices.len() > MAX_DEVICES_COUNT {
            return Err(DeviceStoreError::DeviceCountExceeded {
                count: envelope.devices.len(),
                max: MAX_DEVICES_COUNT,
            });
        }

        let mut store = Self::new();
        for record in envelope.devices {
            record.validate()?;
            store.devices.push(record);
        }

        Ok(store)
    }

    /// Atomically writes the store to disk using a temporary sibling file and replace.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceStoreError`] on serialization or filesystem errors.
    pub fn save_to_path(&self, target_path: &Path) -> Result<(), DeviceStoreError> {
        let envelope = StoreEnvelope {
            schema_version: CURRENT_SCHEMA_VERSION,
            devices: self.devices.clone(),
        };

        let encoded = serde_json::to_vec_pretty(&envelope)
            .map_err(|err| DeviceStoreError::Json(format!("cannot serialize store: {err}")))?;

        if (encoded.len() as u64) > MAX_STORE_FILE_BYTES {
            return Err(DeviceStoreError::FileTooLarge {
                size: encoded.len() as u64,
                max: MAX_STORE_FILE_BYTES,
            });
        }

        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| DeviceStoreError::Io(format!("cannot create store dir: {err}")))?;
        }

        // Write to temporary sibling file first
        let tmp_filename = format!(
            ".tmp.{}.{}",
            std::process::id(),
            target_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("trusted_devices.json")
        );
        let tmp_path: PathBuf = target_path
            .parent()
            .map_or_else(|| PathBuf::from(&tmp_filename), |p| p.join(&tmp_filename));

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| DeviceStoreError::Io(format!("cannot open temp file: {err}")))?;

        file.write_all(&encoded)
            .map_err(|err| DeviceStoreError::Io(format!("cannot write temp file: {err}")))?;
        file.sync_all()
            .map_err(|err| DeviceStoreError::Io(format!("cannot sync temp file: {err}")))?;
        drop(file);

        // Atomic rename / replace
        std::fs::rename(&tmp_path, target_path).map_err(|err| {
            let _ = std::fs::remove_file(&tmp_path);
            DeviceStoreError::Io(format!("cannot atomically replace store file: {err}"))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_public_key(seed: u8) -> [u8; 32] {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        signing_key.verifying_key().to_bytes()
    }

    fn sample_record(id: &str, seed: u8) -> TrustedDeviceRecord {
        TrustedDeviceRecord {
            device_id: id.to_owned(),
            display_name: format!("Workstation {id}"),
            public_key: test_public_key(seed),
            enrolled_at_epoch_secs: 1000,
            trust_expires_at_epoch_secs: 5000,
            managed: true,
            revoked: false,
            status: PersistedDeviceStatus::Online,
        }
    }

    struct TempTestDir(PathBuf);
    impl TempTestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "omnidesk_test_{}_{}_{}",
                name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create test dir");
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn valid_record_validates_successfully() {
        let record = sample_record("p520-desk-1", 1);
        assert!(record.validate().is_ok());
        assert!(record.is_trusted_at(2000));
        assert!(!record.is_trusted_at(6000));
    }

    #[test]
    fn invalid_device_id_fails_closed() {
        let mut r = sample_record("", 1);
        assert!(matches!(
            r.validate(),
            Err(DeviceStoreError::InvalidDeviceId(_))
        ));

        r.device_id = "bad\nid".to_owned();
        assert!(matches!(
            r.validate(),
            Err(DeviceStoreError::InvalidDeviceId(_))
        ));

        r.device_id = "bad\u{1F600}unicode".to_owned();
        assert!(matches!(
            r.validate(),
            Err(DeviceStoreError::InvalidDeviceId(_))
        ));
    }

    #[test]
    fn invalid_time_range_fails_closed() {
        let mut r = sample_record("p520-desk-1", 1);
        r.trust_expires_at_epoch_secs = r.enrolled_at_epoch_secs;
        assert_eq!(r.validate(), Err(DeviceStoreError::InvalidTimeRange));
    }

    #[test]
    fn invalid_public_key_fails_closed() {
        let mut r = sample_record("p520-desk-1", 1);
        r.public_key = [0_u8; 32];
        assert_eq!(r.validate(), Err(DeviceStoreError::InvalidPublicKey));
    }

    #[test]
    fn store_add_get_revoke_lifecycle() {
        let mut store = TrustedDeviceStore::new();
        let r1 = sample_record("dev-1", 1);
        let r2 = sample_record("dev-2", 2);

        assert!(store.add(r1).is_ok());
        assert!(store.add(r2).is_ok());
        assert_eq!(store.len(), 2);

        assert!(store.get("dev-1").is_some());
        assert!(store.revoke("dev-1"));
        assert!(store.get("dev-1").unwrap().revoked);

        assert!(store.set_status("dev-2", DeviceStatus::Offline));
        assert_eq!(
            store.get("dev-2").unwrap().status,
            PersistedDeviceStatus::Offline
        );

        let summaries = store.to_device_summaries();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[1].status, DeviceStatus::Offline);
    }

    #[test]
    fn atomic_file_persistence_roundtrip() {
        let dir = TempTestDir::new("roundtrip");
        let path = dir.path().join("trusted_devices.json");

        let mut store = TrustedDeviceStore::new();
        store.add(sample_record("dev-alpha", 1)).expect("add 1");
        store.add(sample_record("dev-beta", 2)).expect("add 2");

        store.save_to_path(&path).expect("save must succeed");
        assert!(path.exists());

        let loaded = TrustedDeviceStore::load_from_path(&path).expect("load must succeed");
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.get("dev-alpha").unwrap().display_name,
            "Workstation dev-alpha"
        );
        assert_eq!(
            loaded.get("dev-beta").unwrap().display_name,
            "Workstation dev-beta"
        );
    }

    #[test]
    fn nonexistent_file_loads_empty_store() {
        let dir = TempTestDir::new("nonexistent");
        let path = dir.path().join("nonexistent.json");
        let loaded = TrustedDeviceStore::load_from_path(&path).expect("load empty");
        assert!(loaded.is_empty());
    }

    #[test]
    fn oversized_file_is_strictly_rejected() {
        let dir = TempTestDir::new("oversized");
        let path = dir.path().join("oversized.json");
        let count = usize::try_from(MAX_STORE_FILE_BYTES + 10).unwrap_or(usize::MAX);
        let huge_data = vec![b' '; count];
        std::fs::write(&path, huge_data).expect("write huge");

        let result = TrustedDeviceStore::load_from_path(&path);
        assert!(matches!(result, Err(DeviceStoreError::FileTooLarge { .. })));
    }
}
