//! Cryptographic device discovery and enrollment protocol.
//!
//! Handles single-use challenge creation, signature verification over
//! domain-separated enrollment payloads, and clock-drift bounded authentication.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    PROTOCOL_VERSION,
    trusted_device_store::{DeviceStoreError, PersistedDeviceStatus, TrustedDeviceRecord},
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

/// A fresh, single-use enrollment challenge issued to an enrolling peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        self.nonce[0] != 0
            && now_epoch_secs >= self.issued_at_epoch_secs
            && now_epoch_secs <= self.expires_at_epoch_secs
    }
}

/// An enrollment request submitted by a candidate device answering a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub device_id: String,
    pub display_name: String,
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
    pub timestamp_epoch_secs: u64,
    pub signature: [u8; 64],
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
        status: PersistedDeviceStatus::Online,
    };

    record.validate()?;
    Ok(record)
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
}
