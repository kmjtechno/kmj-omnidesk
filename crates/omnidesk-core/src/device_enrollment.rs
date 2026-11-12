//! Cryptographic device discovery and enrollment protocol.
//!
//! Handles single-use challenge creation, signature verification over
//! domain-separated enrollment payloads, and clock-drift bounded authentication.

use std::{
    collections::HashMap,
    path::Path,
};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    PROTOCOL_VERSION,
    trusted_device_store::{
        DeviceStoreError, PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore,
    },
};

const ENROLLMENT_DOMAIN: &[u8] = b"KMJ_OMNIDESK_DEVICE_ENROLLMENT_V1";

/// Maximum allowed clock skew for enrollment requests (60 seconds).
pub const MAX_CLOCK_DRIFT_SECS: u64 = 60;

/// Default lifespan of an enrollment challenge (300 seconds / 5 minutes).
pub const DEFAULT_CHALLENGE_LIFETIME_SECS: u64 = 300;

/// Default trust validity granted upon successful enrollment (30 days).
pub const DEFAULT_TRUST_DURATION_SECS: u64 = 30 * 86400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    ZeroNonce,
    NonceMismatch,
    ChallengeExpired { expired_at: u64, now: u64 },
    ChallengeAlreadyConsumed,
    TimestampInFuture { request_time: u64, max_allowed: u64 },
    TimestampTooOld { request_time: u64, min_allowed: u64 },
    InvalidPublicKey,
    InvalidSignature,
    Store(DeviceStoreError),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroNonce => write!(f, "challenge nonce cannot be all zeros"),
            Self::NonceMismatch => write!(f, "request nonce does not match issued challenge"),
            Self::ChallengeExpired { expired_at, now } => {
                write!(f, "challenge expired at {expired_at} (current time {now})")
            }
            Self::ChallengeAlreadyConsumed => {
                write!(
                    f,
                    "enrollment challenge was already consumed or does not exist"
                )
            }
            Self::TimestampInFuture {
                request_time,
                max_allowed,
            } => {
                write!(
                    f,
                    "request timestamp {request_time} exceeds maximum allowed {max_allowed}"
                )
            }
            Self::TimestampTooOld {
                request_time,
                min_allowed,
            } => {
                write!(
                    f,
                    "request timestamp {request_time} precedes minimum allowed {min_allowed}"
                )
            }
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::InvalidSignature => write!(f, "cryptographic signature verification failed"),
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl From<DeviceStoreError> for EnrollmentError {
    fn from(e: DeviceStoreError) -> Self {
        Self::Store(e)
    }
}

use serde::{Deserialize, Serialize};

/// A fresh, single-use enrollment challenge issued to an enrolling peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    pub nonce: [u8; 32],
    pub issued_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
}

impl EnrollmentChallenge {
    /// Creates a challenge bounded by explicit issue and expiry timestamps.
    #[must_use]
    pub const fn new(
        nonce: [u8; 32],
        issued_at_epoch_secs: u64,
        expires_at_epoch_secs: u64,
    ) -> Self {
        Self {
            nonce,
            issued_at_epoch_secs,
            expires_at_epoch_secs,
        }
    }

    #[must_use]
    pub const fn is_valid_at(&self, now_epoch_secs: u64) -> bool {
        !self.is_all_zero_nonce()
            && now_epoch_secs >= self.issued_at_epoch_secs
            && now_epoch_secs <= self.expires_at_epoch_secs
    }

    #[must_use]
    pub const fn is_all_zero_nonce(&self) -> bool {
        let mut i = 0;
        while i < 32 {
            if self.nonce[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// An enrollment request submitted by a candidate device answering a challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub device_id: String,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
    pub timestamp_epoch_secs: u64,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

pub mod serde_bytes_64 {
    use serde::{Deserializer, Serializer, de::Error};

    /// Serializes a 64-byte array as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns serializer error on serialization failure.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::Serialize::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes a 64-byte array from a byte sequence.
    ///
    /// # Errors
    ///
    /// Returns deserializer error if the input sequence length is not exactly 64.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|v: Vec<u8>| D::Error::invalid_length(v.len(), &"a 64-byte array"))
    }
}

/// Constructs the exact domain-separated message byte buffer that must be signed.
#[must_use]
pub fn build_enrollment_message(
    device_id: &str,
    public_key: &[u8; 32],
    nonce: &[u8; 32],
    timestamp_epoch_secs: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        ENROLLMENT_DOMAIN.len() + 2 + 2 + device_id.len() + public_key.len() + nonce.len() + 8,
    );
    msg.extend_from_slice(ENROLLMENT_DOMAIN);
    msg.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "device_id length is bounded by MAX_DEVICE_ID_BYTES"
    )]
    msg.extend_from_slice(&(device_id.len() as u16).to_be_bytes());
    msg.extend_from_slice(device_id.as_bytes());
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&timestamp_epoch_secs.to_be_bytes());
    msg
}

/// Strictly verifies an enrollment request against an active challenge and clock.
///
/// # Errors
///
/// Returns an [`EnrollmentError`] if the signature, nonce, timestamp, or public key
/// fails verification.
pub fn verify_enrollment(
    challenge: &EnrollmentChallenge,
    request: &EnrollmentRequest,
    now_epoch_secs: u64,
) -> Result<TrustedDeviceRecord, EnrollmentError> {
    if challenge.nonce == [0_u8; 32] || request.nonce == [0_u8; 32] {
        return Err(EnrollmentError::ZeroNonce);
    }

    if challenge.nonce != request.nonce {
        return Err(EnrollmentError::NonceMismatch);
    }

    if now_epoch_secs > challenge.expires_at_epoch_secs {
        return Err(EnrollmentError::ChallengeExpired {
            expired_at: challenge.expires_at_epoch_secs,
            now: now_epoch_secs,
        });
    }

    let max_future = now_epoch_secs.saturating_add(MAX_CLOCK_DRIFT_SECS);
    if request.timestamp_epoch_secs > max_future {
        return Err(EnrollmentError::TimestampInFuture {
            request_time: request.timestamp_epoch_secs,
            max_allowed: max_future,
        });
    }

    let min_past = challenge
        .issued_at_epoch_secs
        .saturating_sub(MAX_CLOCK_DRIFT_SECS);
    if request.timestamp_epoch_secs < min_past {
        return Err(EnrollmentError::TimestampTooOld {
            request_time: request.timestamp_epoch_secs,
            min_allowed: min_past,
        });
    }

    let verifying_key = VerifyingKey::from_bytes(&request.public_key)
        .map_err(|_| EnrollmentError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(&request.signature);
    let message = build_enrollment_message(
        &request.device_id,
        &request.public_key,
        &request.nonce,
        request.timestamp_epoch_secs,
    );

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| EnrollmentError::InvalidSignature)?;

    let record = TrustedDeviceRecord {
        device_id: request.device_id.clone(),
        display_name: request.display_name.clone(),
        public_key: request.public_key,
        enrolled_at_epoch_secs: now_epoch_secs,
        trust_expires_at_epoch_secs: now_epoch_secs.saturating_add(DEFAULT_TRUST_DURATION_SECS),
        managed: false,
        revoked: false,
        status: PersistedDeviceStatus::Offline,
    };

    record.validate()?;
    Ok(record)
}

/// In-memory tracker for active, single-use enrollment challenges.
///
/// Ensures each challenge is consumed at most once and unconsumed challenges
/// expire deterministically.
#[derive(Debug, Default)]
pub struct ChallengeTracker {
    challenges: HashMap<[u8; 32], EnrollmentChallenge>,
}

impl ChallengeTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    /// Issues and registers a new challenge for a given nonce.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::ZeroNonce`] if the nonce is all zeros.
    pub fn issue(
        &mut self,
        nonce: [u8; 32],
        now_epoch_secs: u64,
        lifetime_secs: u64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        let challenge = EnrollmentChallenge::new(
            nonce,
            now_epoch_secs,
            now_epoch_secs.saturating_add(lifetime_secs),
        );
        if challenge.is_all_zero_nonce() {
            return Err(EnrollmentError::ZeroNonce);
        }
        self.challenges.insert(nonce, challenge);
        Ok(challenge)
    }

    /// Consumes and removes a challenge by nonce if it is valid at `now_epoch_secs`.
    ///
    /// Single-use semantics: Once consumed, the challenge is removed and cannot be reused.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::ChallengeAlreadyConsumed`] if the challenge does not exist
    /// or was already consumed, or [`EnrollmentError::ChallengeExpired`] if the challenge has expired.
    pub fn consume(
        &mut self,
        nonce: &[u8; 32],
        now_epoch_secs: u64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        let challenge = self
            .challenges
            .remove(nonce)
            .ok_or(EnrollmentError::ChallengeAlreadyConsumed)?;

        if now_epoch_secs > challenge.expires_at_epoch_secs {
            return Err(EnrollmentError::ChallengeExpired {
                expired_at: challenge.expires_at_epoch_secs,
                now: now_epoch_secs,
            });
        }

        Ok(challenge)
    }

    /// Purges expired challenges from the tracker.
    pub fn prune_expired(&mut self, now_epoch_secs: u64) {
        self.challenges
            .retain(|_, c| now_epoch_secs <= c.expires_at_epoch_secs);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.challenges.len()
    }
}

/// Strictly verifies an enrollment request and consumes the challenge from the tracker.
///
/// Ensures single-use challenge consumption: the challenge is removed upon consumption
/// so subsequent verification attempts with the same nonce will fail closed.
///
/// # Errors
///
/// Returns an [`EnrollmentError`] if the challenge is missing, expired, or if verification fails.
pub fn verify_and_consume_enrollment(
    tracker: &mut ChallengeTracker,
    request: &EnrollmentRequest,
    now_epoch_secs: u64,
) -> Result<TrustedDeviceRecord, EnrollmentError> {
    let challenge = tracker.consume(&request.nonce, now_epoch_secs)?;
    verify_enrollment(&challenge, request, now_epoch_secs)
}

/// Lifecycle stage for active device pairing coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnrollmentStage {
    #[default]
    Idle,
    ChallengeIssued {
        issued_at_epoch_secs: u64,
        expires_at_epoch_secs: u64,
    },
    Enrolled {
        enrolled_at_epoch_secs: u64,
    },
    Failed,
}

/// Generates a fresh 256-bit nonce with the operating system's CSPRNG.
///
/// The timestamp remains in the signature for compatibility, but is not a
/// substitute for cryptographic entropy. Refuse to issue a predictable
/// enrollment challenge or local password if the OS source fails.
#[must_use]
pub fn generate_csprng_nonce(_now_epoch_secs: u64) -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut nonce)
        .expect("KMJ OmniDesk: OS cryptographic entropy unavailable; refusing weak secret");
    nonce
}

/// Auditable pairing and enrollment coordinator.
///
/// Coordinates CSPRNG challenge creation, single-use consumption, cryptographic verification,
/// atomic disk persistence, and real UI progress reporting.
/// Newly enrolled records strictly default to [`PersistedDeviceStatus::Offline`].
#[derive(Debug, Default)]
pub struct EnrollmentCoordinator {
    tracker: ChallengeTracker,
    active_nonce: Option<[u8; 32]>,
    stage: EnrollmentStage,
    last_error: Option<String>,
}

impl EnrollmentCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tracker: ChallengeTracker::new(),
            active_nonce: None,
            stage: EnrollmentStage::Idle,
            last_error: None,
        }
    }

    #[must_use]
    pub const fn stage(&self) -> EnrollmentStage {
        self.stage
    }

    #[must_use]
    pub const fn active_nonce(&self) -> Option<&[u8; 32]> {
        self.active_nonce.as_ref()
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    #[must_use]
    pub const fn is_challenge_active(&self, now_epoch_secs: u64) -> bool {
        match self.stage {
            EnrollmentStage::ChallengeIssued {
                expires_at_epoch_secs,
                ..
            } => now_epoch_secs <= expires_at_epoch_secs && self.active_nonce.is_some(),
            _ => false,
        }
    }

    /// Creates a fresh challenge using system CSPRNG entropy mixed through SHA-256.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::ZeroNonce`] if the generated nonce is somehow all zeros.
    pub fn create_challenge(
        &mut self,
        now_epoch_secs: u64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        let nonce = generate_csprng_nonce(now_epoch_secs);
        if nonce == [0_u8; 32] {
            return Err(EnrollmentError::ZeroNonce);
        }
        self.create_challenge_with_nonce(nonce, now_epoch_secs, DEFAULT_CHALLENGE_LIFETIME_SECS)
    }

    /// Creates a challenge with an explicit nonce and lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::ZeroNonce`] if the nonce is all zeros.
    pub fn create_challenge_with_nonce(
        &mut self,
        nonce: [u8; 32],
        now_epoch_secs: u64,
        lifetime_secs: u64,
    ) -> Result<EnrollmentChallenge, EnrollmentError> {
        let challenge = self.tracker.issue(nonce, now_epoch_secs, lifetime_secs)?;
        self.active_nonce = Some(nonce);
        self.stage = EnrollmentStage::ChallengeIssued {
            issued_at_epoch_secs: now_epoch_secs,
            expires_at_epoch_secs: now_epoch_secs.saturating_add(lifetime_secs),
        };
        self.last_error = None;
        Ok(challenge)
    }

    /// Verifies an incoming enrollment request, single-use consumes the active challenge,
    /// atomically saves to disk if a path is given, and updates the trusted device store.
    ///
    /// The newly enrolled device record is ALWAYS offline by default (`PersistedDeviceStatus::Offline`).
    /// Online status is NEVER fabricated.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] on any signature, nonce, timestamp, or storage error.
    pub fn complete_enrollment(
        &mut self,
        request: &EnrollmentRequest,
        store: &mut TrustedDeviceStore,
        store_path: Option<&Path>,
        now_epoch_secs: u64,
    ) -> Result<TrustedDeviceRecord, EnrollmentError> {
        if self.active_nonce != Some(request.nonce) {
            self.stage = EnrollmentStage::Failed;
            self.last_error = Some("request nonce does not match active challenge".to_owned());
            self.active_nonce = None;
            return Err(EnrollmentError::ChallengeAlreadyConsumed);
        }

        let record = match verify_and_consume_enrollment(&mut self.tracker, request, now_epoch_secs)
        {
            Ok(rec) => rec,
            Err(err) => {
                self.stage = EnrollmentStage::Failed;
                self.last_error = Some(err.to_string());
                self.active_nonce = None;
                return Err(err);
            }
        };

        debug_assert_eq!(record.status, PersistedDeviceStatus::Offline);

        if let Err(err) = store.add(record.clone()) {
            self.stage = EnrollmentStage::Failed;
            self.last_error = Some(err.to_string());
            self.active_nonce = None;
            return Err(EnrollmentError::Store(err));
        }

        if let Some(path) = store_path {
            if let Err(err) = store.save_to_path(path) {
                self.stage = EnrollmentStage::Failed;
                self.last_error = Some(err.to_string());
                self.active_nonce = None;
                return Err(EnrollmentError::Store(err));
            }
        }

        self.stage = EnrollmentStage::Enrolled {
            enrolled_at_epoch_secs: now_epoch_secs,
        };
        self.active_nonce = None;
        self.last_error = None;
        Ok(record)
    }

    /// Cancels any active enrollment challenge and resets coordinator to Idle.
    pub fn cancel(&mut self) {
        if let Some(nonce) = self.active_nonce.take() {
            let _ = self.tracker.challenges.remove(&nonce);
        }
        self.stage = EnrollmentStage::Idle;
        self.last_error = None;
    }
}

/// Wire protocol for pairing challenge-response exchange over any [`Transport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingMessage {
    /// Peer initiates pairing by requesting an enrollment challenge.
    RequestChallenge,
    /// Host responds with a single-use CSPRNG challenge.
    Challenge(EnrollmentChallenge),
    /// Peer submits signed enrollment response.
    SubmitEnrollment(EnrollmentRequest),
    /// Host confirms enrollment and reports persisted trust record details.
    EnrollmentSuccess {
        device_id: String,
        trust_expires_at_epoch_secs: u64,
    },
    /// Host or peer reports failure.
    EnrollmentFailure { reason: String },
}

impl PairingMessage {
    /// Serializes pairing message to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] on serialization failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnrollmentError> {
        serde_json::to_vec(self)
            .map_err(|err| EnrollmentError::Store(DeviceStoreError::Json(err.to_string())))
    }

    /// Deserializes pairing message from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] on deserialization failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        serde_json::from_slice(bytes)
            .map_err(|err| EnrollmentError::Store(DeviceStoreError::Json(err.to_string())))
    }
}

/// Coordinates a pairing exchange on the host side over an established transport.
///
/// Reads incoming pairing messages, handles challenge requests and enrollment submissions,
/// verifies and single-use consumes challenges, updates the store, and transmits replies.
///
/// # Errors
///
/// Returns [`EnrollmentError`] on network or verification failures.
pub fn host_process_pairing_exchange<T: crate::transport::Transport>(
    coordinator: &mut EnrollmentCoordinator,
    store: &mut TrustedDeviceStore,
    store_path: Option<&Path>,
    transport: &mut T,
    now_epoch_secs: u64,
) -> Result<Option<TrustedDeviceRecord>, EnrollmentError> {
    let payload = match transport.receive() {
        Ok(Some(p)) => p,
        Ok(None) => return Ok(None),
        Err(err) => {
            return Err(EnrollmentError::Store(DeviceStoreError::Io(format!(
                "{err:?}"
            ))));
        }
    };

    let msg = PairingMessage::from_bytes(&payload)?;
    match msg {
        PairingMessage::RequestChallenge => {
            let challenge = coordinator.create_challenge(now_epoch_secs)?;
            let reply = PairingMessage::Challenge(challenge);
            let reply_bytes = reply.to_bytes()?;
            transport
                .send(&reply_bytes)
                .map_err(|err| EnrollmentError::Store(DeviceStoreError::Io(format!("{err:?}"))))?;
            Ok(None)
        }
        PairingMessage::SubmitEnrollment(request) => {
            match coordinator.complete_enrollment(&request, store, store_path, now_epoch_secs) {
                Ok(record) => {
                    let reply = PairingMessage::EnrollmentSuccess {
                        device_id: record.device_id.clone(),
                        trust_expires_at_epoch_secs: record.trust_expires_at_epoch_secs,
                    };
                    let reply_bytes = reply.to_bytes()?;
                    transport.send(&reply_bytes).map_err(|err| {
                        EnrollmentError::Store(DeviceStoreError::Io(format!("{err:?}")))
                    })?;
                    Ok(Some(record))
                }
                Err(err) => {
                    let reply = PairingMessage::EnrollmentFailure {
                        reason: err.to_string(),
                    };
                    if let Ok(reply_bytes) = reply.to_bytes() {
                        let _ = transport.send(&reply_bytes);
                    }
                    Err(err)
                }
            }
        }
        _ => Err(EnrollmentError::Store(DeviceStoreError::Json(
            "unexpected pairing message kind for host".to_owned(),
        ))),
    }
}

/// Helper for a candidate peer completing a pairing exchange over a transport.
///
/// # Errors
///
/// Returns [`EnrollmentError`] on transport or protocol error.
pub fn peer_execute_pairing_handshake<T: crate::transport::Transport>(
    transport: &mut T,
    signing_key: &ed25519_dalek::SigningKey,
    device_id: &str,
    display_name: &str,
    now_epoch_secs: u64,
) -> Result<PairingMessage, EnrollmentError> {
    use ed25519_dalek::Signer;
    let req_bytes = PairingMessage::RequestChallenge.to_bytes()?;
    transport
        .send(&req_bytes)
        .map_err(|e| EnrollmentError::Store(DeviceStoreError::Io(format!("{e:?}"))))?;

    let challenge_payload = transport
        .receive()
        .map_err(|e| EnrollmentError::Store(DeviceStoreError::Io(format!("{e:?}"))))?
        .ok_or_else(|| {
            EnrollmentError::Store(DeviceStoreError::Io("no challenge received".to_owned()))
        })?;

    let challenge = match PairingMessage::from_bytes(&challenge_payload)? {
        PairingMessage::Challenge(c) => c,
        other => {
            return Err(EnrollmentError::Store(DeviceStoreError::Json(format!(
                "expected Challenge, got {other:?}"
            ))));
        }
    };

    let public_key = signing_key.verifying_key().to_bytes();
    let msg = build_enrollment_message(device_id, &public_key, &challenge.nonce, now_epoch_secs);
    let signature = signing_key.sign(&msg).to_bytes();

    let request = EnrollmentRequest {
        device_id: device_id.to_owned(),
        display_name: display_name.to_owned(),
        public_key,
        nonce: challenge.nonce,
        timestamp_epoch_secs: now_epoch_secs,
        signature,
    };

    let sub_bytes = PairingMessage::SubmitEnrollment(request).to_bytes()?;
    transport
        .send(&sub_bytes)
        .map_err(|e| EnrollmentError::Store(DeviceStoreError::Io(format!("{e:?}"))))?;

    let confirm_payload = transport
        .receive()
        .map_err(|e| EnrollmentError::Store(DeviceStoreError::Io(format!("{e:?}"))))?
        .ok_or_else(|| {
            EnrollmentError::Store(DeviceStoreError::Io("no confirmation received".to_owned()))
        })?;

    PairingMessage::from_bytes(&confirm_payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keys(seed: u8) -> (SigningKey, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    fn sample_challenge(now: u64) -> EnrollmentChallenge {
        EnrollmentChallenge::new([42_u8; 32], now, now + DEFAULT_CHALLENGE_LIFETIME_SECS)
    }

    fn sample_signed_request(
        signing: &SigningKey,
        public_key: [u8; 32],
        challenge: &EnrollmentChallenge,
        now: u64,
    ) -> EnrollmentRequest {
        let device_id = "test-device-p520";
        let display_name = "P520 Workstation";
        let message = build_enrollment_message(device_id, &public_key, &challenge.nonce, now);
        let signature = signing.sign(&message).to_bytes();

        EnrollmentRequest {
            device_id: device_id.to_owned(),
            display_name: display_name.to_owned(),
            public_key,
            nonce: challenge.nonce,
            timestamp_epoch_secs: now,
            signature,
        }
    }

    #[test]
    fn os_rng_nonce_is_fresh_for_identical_timestamps() {
        let first = generate_csprng_nonce(1_700_000_000);
        let second = generate_csprng_nonce(1_700_000_000);
        assert_ne!(first, [0_u8; 32]);
        assert_ne!(first, second, "OS RNG must not return a time-derived nonce");
    }

    #[test]
    fn valid_enrollment_request_succeeds() {
        let (signing, public_key) = test_keys(10);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let req = sample_signed_request(&signing, public_key, &challenge, now);

        let record = verify_enrollment(&challenge, &req, now).expect("valid enrollment");
        assert_eq!(record.device_id, "test-device-p520");
        assert_eq!(record.public_key, public_key);
        assert_eq!(record.enrolled_at_epoch_secs, now);
        assert!(record.is_trusted_at(now + 100));
    }

    #[test]
    fn tampered_nonce_fails_closed() {
        let (signing, public_key) = test_keys(11);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let mut req = sample_signed_request(&signing, public_key, &challenge, now);
        req.nonce[0] ^= 0xFF;

        assert_eq!(
            verify_enrollment(&challenge, &req, now),
            Err(EnrollmentError::NonceMismatch)
        );
    }

    #[test]
    fn expired_challenge_fails_closed() {
        let (signing, public_key) = test_keys(12);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let req = sample_signed_request(&signing, public_key, &challenge, now);

        let check_time = now + DEFAULT_CHALLENGE_LIFETIME_SECS + 1;
        assert!(matches!(
            verify_enrollment(&challenge, &req, check_time),
            Err(EnrollmentError::ChallengeExpired { .. })
        ));
    }

    #[test]
    fn corrupted_signature_fails_closed() {
        let (signing, public_key) = test_keys(13);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let mut req = sample_signed_request(&signing, public_key, &challenge, now);
        req.signature[5] ^= 0x01;

        assert_eq!(
            verify_enrollment(&challenge, &req, now),
            Err(EnrollmentError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_key_fails_closed() {
        let (signing, public_key) = test_keys(14);
        let (_, wrong_public_key) = test_keys(15);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let mut req = sample_signed_request(&signing, public_key, &challenge, now);
        req.public_key = wrong_public_key;

        assert_eq!(
            verify_enrollment(&challenge, &req, now),
            Err(EnrollmentError::InvalidSignature)
        );
    }

    #[test]
    fn future_timestamp_beyond_drift_fails_closed() {
        let (signing, public_key) = test_keys(16);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let bad_time = now + MAX_CLOCK_DRIFT_SECS + 5;
        let req = sample_signed_request(&signing, public_key, &challenge, bad_time);

        assert!(matches!(
            verify_enrollment(&challenge, &req, now),
            Err(EnrollmentError::TimestampInFuture { .. })
        ));
    }

    #[test]
    fn valid_nonce_with_first_byte_zero_succeeds() {
        let (signing, public_key) = test_keys(17);
        let now = 1_000_000;
        let mut nonce = [0x55_u8; 32];
        nonce[0] = 0x00; // First byte zero, but not all zeros
        let challenge = EnrollmentChallenge::new(nonce, now, now + DEFAULT_CHALLENGE_LIFETIME_SECS);

        assert!(challenge.is_valid_at(now));
        assert!(!challenge.is_all_zero_nonce());

        let req = sample_signed_request(&signing, public_key, &challenge, now);
        let record =
            verify_enrollment(&challenge, &req, now).expect("valid enrollment with zero byte 0");
        assert_eq!(record.device_id, "test-device-p520");
        assert_eq!(record.status, PersistedDeviceStatus::Offline);
    }

    #[test]
    fn all_zero_nonce_fails_closed() {
        let now = 1_000_000;
        let challenge =
            EnrollmentChallenge::new([0_u8; 32], now, now + DEFAULT_CHALLENGE_LIFETIME_SECS);

        assert!(!challenge.is_valid_at(now));
        assert!(challenge.is_all_zero_nonce());

        let (signing, public_key) = test_keys(18);
        let req = sample_signed_request(&signing, public_key, &challenge, now);
        assert_eq!(
            verify_enrollment(&challenge, &req, now),
            Err(EnrollmentError::ZeroNonce)
        );
    }

    #[test]
    fn enrolled_record_defaults_to_offline_status() {
        let (signing, public_key) = test_keys(19);
        let now = 1_000_000;
        let challenge = sample_challenge(now);
        let req = sample_signed_request(&signing, public_key, &challenge, now);

        let record = verify_enrollment(&challenge, &req, now).expect("valid enrollment");
        assert_eq!(record.status, PersistedDeviceStatus::Offline);
    }

    #[test]
    fn challenge_tracker_issues_and_consumes_single_use() {
        let mut tracker = ChallengeTracker::new();
        let now = 1_000_000;
        let nonce = [0x77_u8; 32];

        let challenge = tracker
            .issue(nonce, now, DEFAULT_CHALLENGE_LIFETIME_SECS)
            .expect("issue challenge");
        assert_eq!(challenge.nonce, nonce);
        assert_eq!(tracker.len(), 1);

        // First consumption succeeds
        let consumed = tracker
            .consume(&nonce, now + 10)
            .expect("consume challenge");
        assert_eq!(consumed.nonce, nonce);
        assert_eq!(tracker.len(), 0);

        // Replay consumption fails closed
        assert_eq!(
            tracker.consume(&nonce, now + 10),
            Err(EnrollmentError::ChallengeAlreadyConsumed)
        );
    }

    #[test]
    fn challenge_tracker_rejects_zero_nonce_and_expired() {
        let mut tracker = ChallengeTracker::new();
        let now = 1_000_000;

        assert_eq!(
            tracker.issue([0_u8; 32], now, DEFAULT_CHALLENGE_LIFETIME_SECS),
            Err(EnrollmentError::ZeroNonce)
        );

        let nonce = [0x88_u8; 32];
        tracker.issue(nonce, now, 60).unwrap();

        assert!(matches!(
            tracker.consume(&nonce, now + 61),
            Err(EnrollmentError::ChallengeExpired { .. })
        ));
    }

    #[test]
    fn challenge_tracker_prunes_only_expired() {
        let mut tracker = ChallengeTracker::new();
        let now = 1_000_000;

        let active_nonce = [0x11_u8; 32];
        let expired_nonce = [0x22_u8; 32];

        tracker.issue(active_nonce, now, 300).unwrap();
        tracker.issue(expired_nonce, now, 50).unwrap();
        assert_eq!(tracker.len(), 2);

        tracker.prune_expired(now + 100);
        assert_eq!(tracker.len(), 1);
        assert!(tracker.consume(&active_nonce, now + 100).is_ok());
        assert_eq!(
            tracker.consume(&expired_nonce, now + 100),
            Err(EnrollmentError::ChallengeAlreadyConsumed)
        );
    }

    #[test]
    fn verify_and_consume_enrollment_prevents_replay() {
        let (signing, public_key) = test_keys(20);
        let mut tracker = ChallengeTracker::new();
        let now = 1_000_000;
        let nonce = [0x99_u8; 32];

        tracker
            .issue(nonce, now, DEFAULT_CHALLENGE_LIFETIME_SECS)
            .unwrap();

        let challenge = EnrollmentChallenge::new(nonce, now, now + DEFAULT_CHALLENGE_LIFETIME_SECS);
        let req = sample_signed_request(&signing, public_key, &challenge, now);

        let record =
            verify_and_consume_enrollment(&mut tracker, &req, now).expect("first enrollment");
        assert_eq!(record.device_id, "test-device-p520");
        assert_eq!(record.status, PersistedDeviceStatus::Offline);

        // Replay attempt fails because challenge was consumed
        assert_eq!(
            verify_and_consume_enrollment(&mut tracker, &req, now),
            Err(EnrollmentError::ChallengeAlreadyConsumed)
        );
    }
}
