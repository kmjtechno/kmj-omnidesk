//! Secure M8 collaboration and peripheral feature contracts.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    LocalToRemote,
    RemoteToLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardPolicy {
    pub send_allowed: bool,
    pub receive_allowed: bool,
}

impl ClipboardPolicy {
    #[must_use]
    pub const fn permits(self, direction: DataDirection) -> bool {
        match direction {
            DataDirection::LocalToRemote => self.send_allowed,
            DataDirection::RemoteToLocal => self.receive_allowed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    PermissionDenied,
    PayloadTooLarge,
}

pub const MAX_CLIPBOARD_BYTES: usize = 4 * 1024 * 1024;

/// Validates a clipboard transfer before bytes cross the session boundary.
///
/// # Errors
///
/// Returns an error when the requested direction is not explicitly permitted or
/// when the payload exceeds the bounded clipboard budget.
pub const fn validate_clipboard_transfer(
    policy: ClipboardPolicy,
    direction: DataDirection,
    payload_len: usize,
) -> Result<(), ClipboardError> {
    if !policy.permits(direction) {
        return Err(ClipboardError::PermissionDenied);
    }
    if payload_len > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::PayloadTooLarge);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardSyncError {
    Validation(ClipboardError),
    ReplayOrOutOfOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardSyncState {
    sent_sequence: Option<u64>,
    received_sequence: Option<u64>,
    payload_sha256: Option<[u8; 32]>,
}

impl ClipboardSyncState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sent_sequence: None,
            received_sequence: None,
            payload_sha256: None,
        }
    }

    /// Validates and records one ordered clipboard update.
    ///
    /// # Errors
    ///
    /// Fails when permission/size validation fails or when the sequence number is
    /// replayed or moves backwards for the selected transfer direction.
    pub fn accept(
        &mut self,
        policy: ClipboardPolicy,
        direction: DataDirection,
        sequence: u64,
        payload: &[u8],
    ) -> Result<[u8; 32], ClipboardSyncError> {
        validate_clipboard_transfer(policy, direction, payload.len())
            .map_err(ClipboardSyncError::Validation)?;

        let previous = match direction {
            DataDirection::LocalToRemote => self.sent_sequence,
            DataDirection::RemoteToLocal => self.received_sequence,
        };
        if previous.is_some_and(|previous| sequence <= previous) {
            return Err(ClipboardSyncError::ReplayOrOutOfOrder);
        }

        let digest: [u8; 32] = Sha256::digest(payload).into();
        match direction {
            DataDirection::LocalToRemote => self.sent_sequence = Some(sequence),
            DataDirection::RemoteToLocal => self.received_sequence = Some(sequence),
        }
        self.payload_sha256 = Some(digest);
        Ok(digest)
    }

    #[must_use]
    pub const fn last_payload_sha256(&self) -> Option<[u8; 32]> {
        self.payload_sha256
    }

    /// Forgets every observation, so no state from a finished session survives
    /// into the next one.
    ///
    /// Without this, sequence numbers carry across a session boundary and the
    /// first update of a new session is rejected as a replay, or worse, an
    /// old sequence is accepted because the counter happens to be lower.
    /// Either way the state outlives what it was evidence for.
    ///
    /// Also called on revoke, not only on a clean end: a session cut short is
    /// exactly the case where the previous peer's clipboard history is least
    /// wanted.
    pub const fn clear(&mut self) {
        *self = Self::new();
    }

    /// Whether any state is currently held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sent_sequence.is_none()
            && self.received_sequence.is_none()
            && self.payload_sha256.is_none()
    }
}

impl Default for ClipboardSyncState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferPathError {
    Empty,
    Absolute,
    Traversal,
    PlatformPrefix,
}

/// Sanitizes a user-visible relative transfer path.
///
/// # Errors
///
/// Rejects empty, absolute, parent-traversal, drive/prefix-like, and backslash
/// paths so a remote peer cannot escape the selected transfer root.
pub fn sanitize_transfer_path(path: &str) -> Result<String, TransferPathError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(TransferPathError::Empty);
    }
    if trimmed.starts_with('/') {
        return Err(TransferPathError::Absolute);
    }
    if trimmed.contains('\\') || trimmed.contains(':') {
        return Err(TransferPathError::PlatformPrefix);
    }

    let candidate = Path::new(trimmed);
    if candidate.is_absolute() {
        return Err(TransferPathError::Absolute);
    }

    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => return Err(TransferPathError::Traversal),
            Component::RootDir | Component::Prefix(_) => {
                return Err(TransferPathError::PlatformPrefix);
            }
        }
    }

    Ok(candidate.to_string_lossy().into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferChunk {
    pub index: u32,
    pub offset: u64,
    pub size: u32,
    pub sha256: [u8; 32],
}

impl TransferChunk {
    #[must_use]
    pub fn from_bytes(index: u32, offset: u64, bytes: &[u8]) -> Self {
        Self {
            index,
            offset,
            size: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    #[must_use]
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        usize::try_from(self.size).ok() == Some(bytes.len())
            && self.sha256 == <[u8; 32]>::from(Sha256::digest(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferManifest {
    pub relative_path: String,
    pub total_size: u64,
    pub chunks: Vec<TransferChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferManifestError {
    UnsafePath(TransferPathError),
    EmptyChunks,
    TooManyChunks,
    NonContiguous,
    TotalSizeMismatch,
}

pub const MAX_TRANSFER_CHUNKS: usize = 65_536;

impl FileTransferManifest {
    /// Validates transfer structure and path safety.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is unsafe, chunk count is unbounded,
    /// chunks are non-contiguous, or their declared sizes do not equal the file size.
    pub fn validate(&self) -> Result<(), TransferManifestError> {
        sanitize_transfer_path(&self.relative_path).map_err(TransferManifestError::UnsafePath)?;
        if self.chunks.is_empty() {
            return Err(TransferManifestError::EmptyChunks);
        }
        if self.chunks.len() > MAX_TRANSFER_CHUNKS {
            return Err(TransferManifestError::TooManyChunks);
        }

        let mut expected_offset = 0_u64;
        for (position, chunk) in self.chunks.iter().enumerate() {
            if usize::try_from(chunk.index).ok() != Some(position)
                || chunk.offset != expected_offset
                || chunk.size == 0
            {
                return Err(TransferManifestError::NonContiguous);
            }
            expected_offset = expected_offset.saturating_add(u64::from(chunk.size));
        }

        if expected_offset != self.total_size {
            return Err(TransferManifestError::TotalSizeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferReceiveError {
    InvalidManifest(TransferManifestError),
    UnexpectedChunk,
    ChunkIntegrityFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCheckpoint {
    completed: BTreeSet<u32>,
}

impl TransferCheckpoint {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            completed: BTreeSet::new(),
        }
    }

    pub fn completed_chunks(&self) -> impl Iterator<Item = u32> + '_ {
        self.completed.iter().copied()
    }

    #[must_use]
    pub fn next_missing_chunk(&self, manifest: &FileTransferManifest) -> Option<u32> {
        manifest
            .chunks
            .iter()
            .map(|chunk| chunk.index)
            .find(|index| !self.completed.contains(index))
    }

    /// Verifies and records a received chunk.
    ///
    /// # Errors
    ///
    /// Fails when the manifest is invalid, the chunk index is unknown, or bytes
    /// do not match the manifest's size and SHA-256 digest.
    pub fn accept(
        &mut self,
        manifest: &FileTransferManifest,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), TransferReceiveError> {
        manifest
            .validate()
            .map_err(TransferReceiveError::InvalidManifest)?;
        let chunk = manifest
            .chunks
            .get(usize::try_from(index).map_err(|_| TransferReceiveError::UnexpectedChunk)?)
            .filter(|chunk| chunk.index == index)
            .ok_or(TransferReceiveError::UnexpectedChunk)?;

        if !chunk.verifies(bytes) {
            return Err(TransferReceiveError::ChunkIntegrityFailed);
        }
        self.completed.insert(index);
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self, manifest: &FileTransferManifest) -> bool {
        self.completed.len() == manifest.chunks.len()
            && manifest
                .chunks
                .iter()
                .all(|chunk| self.completed.contains(&chunk.index))
    }
}

impl Default for TransferCheckpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioPermission {
    Denied,
    Allowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioError {
    PermissionDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteAudioState {
    permission: AudioPermission,
    active: bool,
}

impl RemoteAudioState {
    #[must_use]
    pub const fn new(permission: AudioPermission) -> Self {
        Self {
            permission,
            active: false,
        }
    }

    /// Starts remote audio only after explicit permission.
    ///
    /// # Errors
    ///
    /// Returns `AudioError::PermissionDenied` when audio was not explicitly allowed.
    pub const fn start(&mut self) -> Result<(), AudioError> {
        if !matches!(self.permission, AudioPermission::Allowed) {
            return Err(AudioError::PermissionDenied);
        }
        self.active = true;
        Ok(())
    }

    pub const fn stop(&mut self) {
        self.active = false;
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorDescriptor {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorLayoutError {
    Empty,
    InvalidDimensions,
    DuplicateId,
    PrimaryCount,
    UnknownMonitor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorLayout {
    monitors: Vec<MonitorDescriptor>,
    selected_id: String,
}

impl MonitorLayout {
    /// Builds a bounded logical monitor layout.
    ///
    /// # Errors
    ///
    /// Rejects empty layouts, zero-sized monitors, duplicate identifiers, or
    /// layouts without exactly one primary display.
    pub fn new(monitors: Vec<MonitorDescriptor>) -> Result<Self, MonitorLayoutError> {
        if monitors.is_empty() {
            return Err(MonitorLayoutError::Empty);
        }
        if monitors
            .iter()
            .any(|monitor| monitor.width == 0 || monitor.height == 0)
        {
            return Err(MonitorLayoutError::InvalidDimensions);
        }

        let mut ids = BTreeSet::new();
        if monitors.iter().any(|monitor| !ids.insert(&monitor.id)) {
            return Err(MonitorLayoutError::DuplicateId);
        }

        let primaries: Vec<&MonitorDescriptor> =
            monitors.iter().filter(|monitor| monitor.primary).collect();
        if primaries.len() != 1 {
            return Err(MonitorLayoutError::PrimaryCount);
        }

        Ok(Self {
            selected_id: primaries[0].id.clone(),
            monitors,
        })
    }

    /// Selects a known monitor for the session view.
    ///
    /// # Errors
    ///
    /// Returns `MonitorLayoutError::UnknownMonitor` for an unknown identifier.
    pub fn select(&mut self, monitor_id: &str) -> Result<(), MonitorLayoutError> {
        if !self.monitors.iter().any(|monitor| monitor.id == monitor_id) {
            return Err(MonitorLayoutError::UnknownMonitor);
        }
        monitor_id.clone_into(&mut self.selected_id);
        Ok(())
    }

    #[must_use]
    pub fn selected(&self) -> &str {
        &self.selected_id
    }

    #[must_use]
    pub fn monitors(&self) -> &[MonitorDescriptor] {
        &self.monitors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebootReconnectPolicy {
    pub explicitly_allowed: bool,
    pub max_attempts: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootReconnectError {
    PermissionDenied,
    AttemptBudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebootReconnectState {
    policy: RebootReconnectPolicy,
    attempts: u8,
}

impl RebootReconnectState {
    #[must_use]
    pub const fn new(policy: RebootReconnectPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
        }
    }

    /// Consumes one explicitly authorized reconnect attempt after a peer reboot.
    ///
    /// # Errors
    ///
    /// Fails closed when reboot reconnect was not explicitly authorized or the
    /// bounded attempt budget has been exhausted.
    pub const fn begin_attempt(&mut self) -> Result<u8, RebootReconnectError> {
        if !self.policy.explicitly_allowed {
            return Err(RebootReconnectError::PermissionDenied);
        }
        if self.attempts >= self.policy.max_attempts {
            return Err(RebootReconnectError::AttemptBudgetExhausted);
        }
        self.attempts = self.attempts.saturating_add(1);
        Ok(self.attempts)
    }

    #[must_use]
    pub const fn attempts(self) -> u8 {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_manifest() -> (FileTransferManifest, Vec<Vec<u8>>) {
        let chunks = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
        let mut offset = 0_u64;
        let descriptors = chunks
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let descriptor = TransferChunk::from_bytes(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    offset,
                    bytes,
                );
                offset = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                descriptor
            })
            .collect();

        (
            FileTransferManifest {
                relative_path: "reports/final.bin".to_owned(),
                total_size: offset,
                chunks: descriptors,
            },
            chunks,
        )
    }

    #[test]
    fn clipboard_permission_is_explicit_and_directional() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: false,
        };
        assert_eq!(
            validate_clipboard_transfer(policy, DataDirection::LocalToRemote, 128),
            Ok(())
        );
        assert_eq!(
            validate_clipboard_transfer(policy, DataDirection::RemoteToLocal, 128),
            Err(ClipboardError::PermissionDenied)
        );
    }

    #[test]
    fn clipboard_payload_is_bounded() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: true,
        };
        assert_eq!(
            validate_clipboard_transfer(
                policy,
                DataDirection::LocalToRemote,
                MAX_CLIPBOARD_BYTES + 1
            ),
            Err(ClipboardError::PayloadTooLarge)
        );
    }

    #[test]
    fn clipboard_sync_rejects_replay_and_tracks_digest() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: true,
        };
        let mut state = ClipboardSyncState::new();

        let digest = state
            .accept(policy, DataDirection::LocalToRemote, 1, b"hello")
            .unwrap();
        assert_eq!(state.last_payload_sha256(), Some(digest));
        assert_eq!(
            state.accept(policy, DataDirection::LocalToRemote, 1, b"replay"),
            Err(ClipboardSyncError::ReplayOrOutOfOrder)
        );
        assert_eq!(
            state.accept(policy, DataDirection::LocalToRemote, 0, b"older"),
            Err(ClipboardSyncError::ReplayOrOutOfOrder)
        );

        assert!(
            state
                .accept(policy, DataDirection::RemoteToLocal, 1, b"remote")
                .is_ok()
        );
    }

    #[test]
    fn a_new_session_starts_with_no_clipboard_state() {
        assert!(ClipboardSyncState::new().is_empty());
        assert!(ClipboardSyncState::default().is_empty());
    }

    #[test]
    fn clearing_removes_the_digest_and_both_sequence_numbers() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: true,
        };
        let mut state = ClipboardSyncState::new();

        state
            .accept(policy, DataDirection::LocalToRemote, 7, b"outgoing")
            .expect("accept");
        state
            .accept(policy, DataDirection::RemoteToLocal, 9, b"incoming")
            .expect("accept");

        assert!(!state.is_empty());
        assert!(state.last_payload_sha256().is_some());

        state.clear();

        assert!(
            state.is_empty(),
            "state from a finished session must not survive into the next"
        );
        assert_eq!(state.last_payload_sha256(), None);
    }

    #[test]
    fn a_new_session_can_restart_its_sequence_from_one() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: true,
        };
        let mut state = ClipboardSyncState::new();

        state
            .accept(policy, DataDirection::LocalToRemote, 42, b"first")
            .expect("first session");

        // Without a clear, the new session's first update would be rejected as
        // a replay of the previous one's numbering.
        state.clear();

        assert!(
            state
                .accept(policy, DataDirection::LocalToRemote, 1, b"second")
                .is_ok(),
            "a new session must be able to start its sequence again"
        );
    }

    #[test]
    fn replay_protection_still_holds_after_a_clear_within_a_session() {
        let policy = ClipboardPolicy {
            send_allowed: true,
            receive_allowed: true,
        };
        let mut state = ClipboardSyncState::new();

        state
            .accept(policy, DataDirection::LocalToRemote, 5, b"one")
            .expect("accept");

        // `clear` is a session-lifecycle operation, not a way to sidestep
        // ordering. Within one session the sequence must still move forward.
        state.clear();
        state
            .accept(policy, DataDirection::LocalToRemote, 5, b"again")
            .expect("after clear");
        assert_eq!(
            state.accept(policy, DataDirection::LocalToRemote, 5, b"replay"),
            Err(ClipboardSyncError::ReplayOrOutOfOrder),
            "a repeated sequence must still be refused after a clear"
        );
    }

    #[test]
    fn clearing_twice_is_harmless() {
        let mut state = ClipboardSyncState::new();
        state.clear();
        state.clear();
        assert!(state.is_empty());
    }

    #[test]
    fn transfer_paths_reject_escape_and_platform_prefixes() {
        assert_eq!(
            sanitize_transfer_path("../secret.txt"),
            Err(TransferPathError::Traversal)
        );
        assert_eq!(
            sanitize_transfer_path("/etc/passwd"),
            Err(TransferPathError::Absolute)
        );
        assert_eq!(
            sanitize_transfer_path("C:\\Windows\\secret.txt"),
            Err(TransferPathError::PlatformPrefix)
        );
        assert_eq!(
            sanitize_transfer_path("safe/report.txt"),
            Ok("safe/report.txt".to_owned())
        );
    }

    #[test]
    fn transfer_integrity_and_resume_survive_interruption() {
        let (manifest, chunks) = transfer_manifest();
        assert_eq!(manifest.validate(), Ok(()));

        let mut checkpoint = TransferCheckpoint::new();
        checkpoint.accept(&manifest, 0, &chunks[0]).unwrap();
        assert_eq!(checkpoint.next_missing_chunk(&manifest), Some(1));

        let persisted = checkpoint.clone();
        let mut resumed = persisted;
        resumed.accept(&manifest, 1, &chunks[1]).unwrap();
        resumed.accept(&manifest, 2, &chunks[2]).unwrap();

        assert!(resumed.is_complete(&manifest));
        assert_eq!(resumed.next_missing_chunk(&manifest), None);
    }

    #[test]
    fn modified_transfer_chunk_is_rejected() {
        let (manifest, _) = transfer_manifest();
        let mut checkpoint = TransferCheckpoint::new();
        assert_eq!(
            checkpoint.accept(&manifest, 0, b"tampered"),
            Err(TransferReceiveError::ChunkIntegrityFailed)
        );
    }

    #[test]
    fn remote_audio_requires_explicit_permission() {
        let mut denied = RemoteAudioState::new(AudioPermission::Denied);
        assert_eq!(denied.start(), Err(AudioError::PermissionDenied));
        assert!(!denied.is_active());

        let mut allowed = RemoteAudioState::new(AudioPermission::Allowed);
        assert_eq!(allowed.start(), Ok(()));
        assert!(allowed.is_active());
        allowed.stop();
        assert!(!allowed.is_active());
    }

    #[test]
    fn multi_monitor_layout_requires_one_primary_and_known_selection() {
        let mut layout = MonitorLayout::new(vec![
            MonitorDescriptor {
                id: "primary".to_owned(),
                width: 1920,
                height: 1080,
                primary: true,
            },
            MonitorDescriptor {
                id: "secondary".to_owned(),
                width: 1280,
                height: 1024,
                primary: false,
            },
        ])
        .unwrap();

        assert_eq!(layout.selected(), "primary");
        assert_eq!(layout.select("secondary"), Ok(()));
        assert_eq!(layout.selected(), "secondary");
        assert_eq!(
            layout.select("unknown"),
            Err(MonitorLayoutError::UnknownMonitor)
        );
    }

    #[test]
    fn reboot_reconnect_is_explicit_and_bounded() {
        let mut denied = RebootReconnectState::new(RebootReconnectPolicy {
            explicitly_allowed: false,
            max_attempts: 2,
        });
        assert_eq!(
            denied.begin_attempt(),
            Err(RebootReconnectError::PermissionDenied)
        );

        let mut allowed = RebootReconnectState::new(RebootReconnectPolicy {
            explicitly_allowed: true,
            max_attempts: 2,
        });
        assert_eq!(allowed.begin_attempt(), Ok(1));
        assert_eq!(allowed.begin_attempt(), Ok(2));
        assert_eq!(
            allowed.begin_attempt(),
            Err(RebootReconnectError::AttemptBudgetExhausted)
        );
    }
}
