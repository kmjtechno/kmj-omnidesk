//! End-to-end client licensing lifecycle management for KMJ `OmniDesk` (KSLP-v1).
//!
//! Integrates key discovery, device key custody, proof-of-possession signing,
//! wire protocol serialization/deserialization, entitlement verification,
//! offline grace policy, clock rollback detection, and resource limit enforcement.
//!
//! # Non-Negotiable Invariants
//!
//! 1. **No Master Unlock**: The client cannot authorize itself or bypass
//!    cryptographic verification. Every entitlement must be signed by an
//!    active or rollover Ed25519 key published by KMJ Main Platform.
//! 2. **Private Key Custody**: The device's private signing key is stored
//!    only in client memory and is never serialized, logged, exported, or
//!    transmitted across the network.
//! 3. **Fail-Closed Offline Grace**: When the server is unreachable or
//!    returns a transient 5xx error, an existing valid lease may operate in
//!    offline grace until `grace_expires_at`. Once grace expires, operation
//!    fails closed into `Restricted` state.
//! 4. **Clock Rollback Resistance**: Local clock movements behind the last
//!    trusted server timestamp fail closed immediately and never extend grace.
//! 5. **Revocation Supremacy**: Explicit revocation (license, entitlement, or
//!    activation) overrides offline grace immediately and permanently.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{
    activation_proof::{
        ActivationProofInput, device_public_key_fingerprint, sign_activation_proof,
    },
    licensing::{
        DeviceBinding, Ed25519SignatureVerifier, LICENSE_PROTOCOL_VERSION, LicenseError,
        LicenseState, LocalLicenseClock, ResourceLimitKind, RevocationState, VerificationContext,
        VerifiedEntitlement, verify_signed_entitlement,
    },
    licensing_key_discovery::{KeyDiscoveryError, verifier_from_main_platform_keys},
    renewal_proof::{RenewalProofInput, sign_renewal_proof},
};

pub const ACTIVATION_PROOF_SCHEME: &str = "KMJ-OMNIDESK-ACTIVATE-v1";
pub const RENEWAL_PROOF_SCHEME: &str = "KMJ-OMNIDESK-RENEW-v1";

/// Maximum length of a signed entitlement compact token string (128 KiB).
pub const MAX_SIGNED_ENTITLEMENT_STRING_LEN: usize = 128 * 1024;

/// Wire request payload for `POST /api/v1/licensing/omnidesk/activations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub license_or_entitlement_reference: String,
    pub device_public_key: String,
    pub device_public_key_fingerprint: String,
    pub installation_id: String,
    pub client_version: String,
    pub protocol_version: String,
    pub platform: String,
    pub architecture: String,
    pub client_nonce: String,
    pub proof_scheme: String,
    pub device_signature: String,
}

/// Wire response payload from `POST /api/v1/licensing/omnidesk/activations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationResponse {
    pub activation_id: String,
    pub signed_entitlement: String,
    pub lease_expires_at: u64,
    pub server_time: u64,
    pub key_set_version: String,
}

/// Wire request payload for `POST /api/v1/licensing/omnidesk/leases/renew`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewLeaseRequest {
    pub activation_id: String,
    pub current_jti: String,
    pub current_sequence: u64,
    pub server_challenge: String,
    pub proof_scheme: String,
    pub device_signature: String,
    pub client_nonce: String,
    pub client_version: String,
}

/// Wire response payload from `POST /api/v1/licensing/omnidesk/leases/renew`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewLeaseResponse {
    pub signed_entitlement: String,
    pub lease_expires_at: u64,
    pub next_renewal_at: u64,
    pub server_time: u64,
}

/// Wire response payload from `GET /api/v1/licensing/omnidesk/activations/{id}/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationStatusResponse {
    pub activation_id: String,
    pub state: String,
    pub sequence: u64,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<u64>,
    pub server_time: u64,
}

/// Wire error response for deterministic licensing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensingErrorResponse {
    pub error: String,
    pub request_id: String,
    #[serde(default)]
    pub retry_after_seconds: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Reason for a server communication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFailureReason {
    HttpError(u16),
    NetworkUnreachable,
    Timeout,
    MalformedResponse,
}

/// Errors originating from client-side licensing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicensingClientError {
    KeyDiscovery(KeyDiscoveryError),
    Verification(LicenseError),
    ServerRejected {
        error: String,
        request_id: String,
        message: Option<String>,
    },
    InvalidResponseFormat(&'static str),
    MissingActiveLease,
    ClockRollback {
        now: u64,
        last_trusted_server_time: u64,
    },
    OfflineGraceExpired {
        now: u64,
        grace_expires_at: u64,
    },
    Revoked {
        reason: Option<String>,
    },
    LimitExceeded {
        kind: ResourceLimitKind,
        limit: u64,
        requested: u64,
    },
    CapabilityMissing(String),
}

impl From<KeyDiscoveryError> for LicensingClientError {
    fn from(err: KeyDiscoveryError) -> Self {
        Self::KeyDiscovery(err)
    }
}

impl From<LicenseError> for LicensingClientError {
    fn from(err: LicenseError) -> Self {
        Self::Verification(err)
    }
}

/// Holds the local device keypair without exposing private key bytes.
#[derive(Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
    public_key_base64url: String,
    fingerprint: String,
}

impl DeviceIdentity {
    /// Creates a device identity from raw 32-byte private seed bytes.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_key_base64url = URL_SAFE_NO_PAD.encode(public_bytes);
        let fingerprint = device_public_key_fingerprint(&signing_key);
        Self {
            signing_key,
            public_key_base64url,
            fingerprint,
        }
    }

    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Cached state of an actively verified entitlement lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLease {
    pub activation_id: String,
    pub verified_entitlement: VerifiedEntitlement,
    pub last_accepted_sequence: u64,
    pub last_trusted_server_time: u64,
    pub renewal_due_at: u64,
    pub grace_expires_at: u64,
    pub known_revocation: RevocationState,
}

impl CachedLease {
    /// Evaluates current state based on local time and revocation status.
    ///
    /// # Errors
    ///
    /// Returns `Revoked` if revocation is active, or `ClockRollback` if clock is behind last trusted server time.
    pub fn evaluate_state(&self, now: u64) -> Result<LicenseState, LicensingClientError> {
        if self.known_revocation != RevocationState::Clear {
            return Err(LicensingClientError::Revoked {
                reason: Some(format!("{:?}", self.known_revocation)),
            });
        }
        if now < self.last_trusted_server_time {
            return Err(LicensingClientError::ClockRollback {
                now,
                last_trusted_server_time: self.last_trusted_server_time,
            });
        }
        if now >= self.verified_entitlement.payload.expires_at {
            return Ok(LicenseState::Restricted);
        }
        if now < self.renewal_due_at {
            return Ok(LicenseState::Active);
        }
        if now < self.verified_entitlement.payload.lease_expires_at {
            return Ok(LicenseState::RenewalDue);
        }
        if now < self.grace_expires_at {
            return Ok(LicenseState::Grace);
        }
        Ok(LicenseState::Restricted)
    }
}

#[derive(Deserialize)]
struct JsonContainer {
    #[serde(alias = "canonical_payload_utf8", alias = "payload")]
    payload: String,
    #[serde(alias = "signature_base64", alias = "signature")]
    signature: String,
}

/// Decodes a signed entitlement token into canonical payload bytes and Ed25519 signature.
///
/// Accepts:
/// 1. Compact dot-separated token: `<base64url_or_base64(payload)>.<base64url_or_base64(sig)>`
/// 2. JSON container: `{"canonical_payload_utf8":"...","signature_base64":"..."}` or
///    `{"payload":"...","signature":"..."}`
///
/// # Errors
///
/// Returns `InvalidResponseFormat` if the format is unrecognized, oversized, or malformed.
pub fn decode_signed_entitlement(token: &str) -> Result<(Vec<u8>, [u8; 64]), LicensingClientError> {
    if token.is_empty() || token.len() > MAX_SIGNED_ENTITLEMENT_STRING_LEN {
        return Err(LicensingClientError::InvalidResponseFormat(
            "signed entitlement string length out of bounds",
        ));
    }

    // Try compact format: payload.signature
    if let Some((payload_str, sig_str)) = token.split_once('.') {
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_str.as_bytes())
            .or_else(|_| STANDARD.decode(payload_str.as_bytes()))
            .or_else(|_| {
                // If payload is already raw valid JSON
                if payload_str.starts_with('{') && payload_str.ends_with('}') {
                    Ok(payload_str.as_bytes().to_vec())
                } else {
                    Err(base64::DecodeError::InvalidByte(0, 0))
                }
            })
            .map_err(|_| {
                LicensingClientError::InvalidResponseFormat("failed to decode compact payload part")
            })?;

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_str.as_bytes())
            .or_else(|_| STANDARD.decode(sig_str.as_bytes()))
            .map_err(|_| {
                LicensingClientError::InvalidResponseFormat(
                    "failed to decode compact signature part",
                )
            })?;

        let signature: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            LicensingClientError::InvalidResponseFormat("signature must be exactly 64 bytes")
        })?;

        return Ok((payload_bytes, signature));
    }

    if let Ok(container) = serde_json::from_str::<JsonContainer>(token) {
        let payload_bytes = if container.payload.starts_with('{') {
            container.payload.into_bytes()
        } else {
            URL_SAFE_NO_PAD
                .decode(container.payload.as_bytes())
                .or_else(|_| STANDARD.decode(container.payload.as_bytes()))
                .map_err(|_| {
                    LicensingClientError::InvalidResponseFormat(
                        "failed to decode json container payload",
                    )
                })?
        };

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(container.signature.as_bytes())
            .or_else(|_| STANDARD.decode(container.signature.as_bytes()))
            .map_err(|_| {
                LicensingClientError::InvalidResponseFormat(
                    "failed to decode json container signature",
                )
            })?;

        let signature: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            LicensingClientError::InvalidResponseFormat("signature must be exactly 64 bytes")
        })?;

        return Ok((payload_bytes, signature));
    }

    Err(LicensingClientError::InvalidResponseFormat(
        "unrecognized signed entitlement encoding",
    ))
}

/// End-to-end client licensing lifecycle manager.
pub struct LicensingManager {
    identity: DeviceIdentity,
    installation_id: String,
    client_version: String,
    platform: String,
    architecture: String,
    verifier: Option<Ed25519SignatureVerifier>,
    active_lease: Option<CachedLease>,
}

impl LicensingManager {
    /// Creates a new licensing manager with a private device key and platform metadata.
    #[must_use]
    pub fn new(
        seed: &[u8; 32],
        installation_id: String,
        client_version: String,
        platform: String,
        architecture: String,
    ) -> Self {
        Self {
            identity: DeviceIdentity::from_seed(seed),
            installation_id,
            client_version,
            platform,
            architecture,
            verifier: None,
            active_lease: None,
        }
    }

    #[must_use]
    pub fn device_fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    #[must_use]
    pub fn device_public_key(&self) -> &str {
        self.identity.public_key_base64url()
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    #[must_use]
    pub const fn active_lease(&self) -> Option<&CachedLease> {
        self.active_lease.as_ref()
    }

    /// Loads and verifies trusted verification keys from Main Platform discovery response.
    ///
    /// # Errors
    ///
    /// Fails closed if the discovery envelope is malformed, has invalid signatures, or has no keys.
    pub fn update_verification_keys(
        &mut self,
        response_bytes: &[u8],
        trusted_time: u64,
    ) -> Result<(), LicensingClientError> {
        let verifier = verifier_from_main_platform_keys(response_bytes, trusted_time)?;
        self.verifier = Some(verifier);
        Ok(())
    }

    /// Prepares an activation request and its corresponding `Idempotency-Key` header.
    #[must_use]
    pub fn create_activation_request(
        &self,
        reference: &str,
        idempotency_key: &str,
        client_nonce: &str,
    ) -> (ActivationRequest, String) {
        let input = ActivationProofInput {
            idempotency_key,
            license_or_entitlement_reference: reference,
            device_public_key: self.identity.public_key_base64url(),
            device_public_key_fingerprint: self.identity.fingerprint(),
            installation_id: &self.installation_id,
            client_version: &self.client_version,
            protocol_version: LICENSE_PROTOCOL_VERSION,
            platform: &self.platform,
            architecture: &self.architecture,
            client_nonce,
        };

        let device_signature = sign_activation_proof(&self.identity.signing_key, input);

        let request = ActivationRequest {
            license_or_entitlement_reference: reference.to_owned(),
            device_public_key: self.identity.public_key_base64url().to_owned(),
            device_public_key_fingerprint: self.identity.fingerprint().to_owned(),
            installation_id: self.installation_id.clone(),
            client_version: self.client_version.clone(),
            protocol_version: LICENSE_PROTOCOL_VERSION.to_owned(),
            platform: self.platform.clone(),
            architecture: self.architecture.clone(),
            client_nonce: client_nonce.to_owned(),
            proof_scheme: ACTIVATION_PROOF_SCHEME.to_owned(),
            device_signature,
        };

        (request, idempotency_key.to_owned())
    }

    /// Processes an activation response, verifying the signed entitlement.
    ///
    /// # Errors
    ///
    /// Fails closed if no verifier is loaded, response is invalid JSON or server error,
    /// or if cryptographic signature/temporal/binding checks fail.
    pub fn process_activation_response(
        &mut self,
        response_bytes: &[u8],
        now: u64,
    ) -> Result<LicenseState, LicensingClientError> {
        let verifier = self
            .verifier
            .as_ref()
            .ok_or(LicensingClientError::Verification(
                LicenseError::UnknownOrRevokedKey,
            ))?;

        if let Ok(error_resp) = serde_json::from_slice::<LicensingErrorResponse>(response_bytes) {
            return Err(LicensingClientError::ServerRejected {
                error: error_resp.error,
                request_id: error_resp.request_id,
                message: error_resp.message,
            });
        }

        let resp: ActivationResponse = serde_json::from_slice(response_bytes).map_err(|_| {
            LicensingClientError::InvalidResponseFormat("malformed ActivationResponse")
        })?;

        let (payload_bytes, signature) = decode_signed_entitlement(&resp.signed_entitlement)?;

        let binding = DeviceBinding {
            activation_id: &resp.activation_id,
            device_public_key_fingerprint: self.identity.fingerprint(),
            installation_id: &self.installation_id,
        };

        let renewal_due_at = now.saturating_add(resp.lease_expires_at.saturating_sub(now) / 2);
        let grace_duration = resp.lease_expires_at.saturating_sub(now).min(86_400);
        let grace_expires_at = resp.lease_expires_at.saturating_add(grace_duration);

        let context = VerificationContext {
            binding,
            last_accepted_sequence: 0,
            revocation: RevocationState::Clear,
            clock: LocalLicenseClock {
                now,
                last_trusted_server_time: resp.server_time,
                renewal_due_at,
                grace_expires_at,
            },
        };

        let entitlement =
            verify_signed_entitlement(verifier, &payload_bytes, &signature, &context)?;
        let state = entitlement.state;

        self.active_lease = Some(CachedLease {
            activation_id: resp.activation_id,
            last_accepted_sequence: entitlement.payload.sequence,
            last_trusted_server_time: resp.server_time,
            renewal_due_at,
            grace_expires_at,
            known_revocation: RevocationState::Clear,
            verified_entitlement: entitlement,
        });

        Ok(state)
    }

    /// Prepares a renewal request using the currently active lease.
    ///
    /// # Errors
    ///
    /// Returns `MissingActiveLease` if no lease is currently active.
    pub fn create_renewal_request(
        &self,
        server_challenge: &str,
        client_nonce: &str,
    ) -> Result<RenewLeaseRequest, LicensingClientError> {
        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        let input = RenewalProofInput {
            activation_id: &lease.activation_id,
            current_jti: &lease.verified_entitlement.payload.jti,
            current_sequence: lease.last_accepted_sequence,
            server_challenge,
            client_nonce,
            client_version: &self.client_version,
        };

        let device_signature = sign_renewal_proof(&self.identity.signing_key, input);

        Ok(RenewLeaseRequest {
            activation_id: lease.activation_id.clone(),
            current_jti: lease.verified_entitlement.payload.jti.clone(),
            current_sequence: lease.last_accepted_sequence,
            server_challenge: server_challenge.to_owned(),
            proof_scheme: RENEWAL_PROOF_SCHEME.to_owned(),
            device_signature,
            client_nonce: client_nonce.to_owned(),
            client_version: self.client_version.clone(),
        })
    }

    /// Processes a lease renewal response, verifying strictly monotonic sequence advance.
    ///
    /// # Errors
    ///
    /// Fails closed if response is invalid, sequence is not advancing, or signature fails.
    pub fn process_renewal_response(
        &mut self,
        response_bytes: &[u8],
        now: u64,
    ) -> Result<LicenseState, LicensingClientError> {
        let verifier = self
            .verifier
            .as_ref()
            .ok_or(LicensingClientError::Verification(
                LicenseError::UnknownOrRevokedKey,
            ))?;

        if let Ok(error_resp) = serde_json::from_slice::<LicensingErrorResponse>(response_bytes) {
            return Err(LicensingClientError::ServerRejected {
                error: error_resp.error,
                request_id: error_resp.request_id,
                message: error_resp.message,
            });
        }

        let resp: RenewLeaseResponse = serde_json::from_slice(response_bytes).map_err(|_| {
            LicensingClientError::InvalidResponseFormat("malformed RenewLeaseResponse")
        })?;

        let current_lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        let (payload_bytes, signature) = decode_signed_entitlement(&resp.signed_entitlement)?;

        let binding = DeviceBinding {
            activation_id: &current_lease.activation_id,
            device_public_key_fingerprint: self.identity.fingerprint(),
            installation_id: &self.installation_id,
        };

        let renewal_due_at = resp.next_renewal_at;
        let grace_duration = resp.lease_expires_at.saturating_sub(now).min(86_400);
        let grace_expires_at = resp.lease_expires_at.saturating_add(grace_duration);

        let context = VerificationContext {
            binding,
            last_accepted_sequence: current_lease.last_accepted_sequence,
            revocation: current_lease.known_revocation,
            clock: LocalLicenseClock {
                now,
                last_trusted_server_time: resp.server_time,
                renewal_due_at,
                grace_expires_at,
            },
        };

        let entitlement =
            verify_signed_entitlement(verifier, &payload_bytes, &signature, &context)?;
        let state = entitlement.state;

        self.active_lease = Some(CachedLease {
            activation_id: current_lease.activation_id.clone(),
            last_accepted_sequence: entitlement.payload.sequence,
            last_trusted_server_time: resp.server_time,
            renewal_due_at,
            grace_expires_at,
            known_revocation: current_lease.known_revocation,
            verified_entitlement: entitlement,
        });

        Ok(state)
    }

    /// Processes an activation status response from Main Platform.
    ///
    /// Explicit revocation permanently overrides offline grace.
    ///
    /// # Errors
    ///
    /// Returns `ServerRejected` on server error response, `DeviceBindingMismatch` on
    /// activation ID mismatch, `ClockRollback` on backwards clock movement, or
    /// `Revoked` when the status indicates revocation.
    pub fn process_status_response(
        &mut self,
        response_bytes: &[u8],
        now: u64,
    ) -> Result<LicenseState, LicensingClientError> {
        if let Ok(error_resp) = serde_json::from_slice::<LicensingErrorResponse>(response_bytes) {
            return Err(LicensingClientError::ServerRejected {
                error: error_resp.error,
                request_id: error_resp.request_id,
                message: error_resp.message,
            });
        }

        let resp: ActivationStatusResponse =
            serde_json::from_slice(response_bytes).map_err(|_| {
                LicensingClientError::InvalidResponseFormat("malformed ActivationStatusResponse")
            })?;

        let lease = self
            .active_lease
            .as_mut()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        if resp.activation_id != lease.activation_id {
            return Err(LicensingClientError::Verification(
                LicenseError::DeviceBindingMismatch,
            ));
        }

        if now < lease.last_trusted_server_time {
            return Err(LicensingClientError::ClockRollback {
                now,
                last_trusted_server_time: lease.last_trusted_server_time,
            });
        }

        lease.last_trusted_server_time = resp.server_time;

        if resp.state == "REVOKED" {
            lease.known_revocation = RevocationState::ActivationRevoked;
            return Err(LicensingClientError::Revoked {
                reason: resp.reason_code,
            });
        }

        lease.evaluate_state(now)
    }

    /// Evaluates current state without contacting the server, adhering to offline grace policy.
    ///
    /// # Errors
    ///
    /// Returns `MissingActiveLease` if no lease is cached, or error from lease evaluation.
    pub fn evaluate_state(&self, now: u64) -> Result<LicenseState, LicensingClientError> {
        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;
        lease.evaluate_state(now)
    }

    /// Handles a server failure (HTTP 5xx, timeout, unreachable network) safely.
    ///
    /// If an active lease is in its offline grace period, returns `LicenseState::Grace`.
    /// If grace has expired, fails closed with `LicenseState::Restricted`.
    /// If clock rollback or revocation is detected, fails closed with error.
    ///
    /// # Errors
    ///
    /// Returns `MissingActiveLease` if no lease is cached, or clock rollback / revocation error.
    pub fn handle_server_failure(
        &self,
        now: u64,
        _reason: ServerFailureReason,
    ) -> Result<LicenseState, LicensingClientError> {
        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        let state = lease.evaluate_state(now)?;
        match state {
            LicenseState::Active | LicenseState::RenewalDue => Ok(state),
            LicenseState::Grace => Ok(LicenseState::Grace),
            LicenseState::Restricted | LicenseState::Revoked => Ok(LicenseState::Restricted),
        }
    }

    /// Checks whether starting a new session is permitted under current entitlement and limits.
    ///
    /// # Errors
    ///
    /// Returns `OfflineGraceExpired` if grace expired, `CapabilityMissing` if interactive
    /// capability is not granted, or `LimitExceeded` if concurrent sessions limit is reached.
    pub fn check_session_allowed(
        &self,
        now: u64,
        current_concurrent_sessions: u64,
    ) -> Result<(), LicensingClientError> {
        let state = self.evaluate_state(now)?;
        if state == LicenseState::Restricted || state == LicenseState::Revoked {
            return Err(LicensingClientError::OfflineGraceExpired {
                now,
                grace_expires_at: self.active_lease.as_ref().map_or(0, |l| l.grace_expires_at),
            });
        }

        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        if !lease
            .verified_entitlement
            .has_capability("remote.interactive")
        {
            return Err(LicensingClientError::CapabilityMissing(
                "remote.interactive".to_owned(),
            ));
        }

        let limit = lease
            .verified_entitlement
            .payload
            .limits
            .concurrent_sessions
            .0;
        if let Some(max_sessions) = limit {
            if current_concurrent_sessions >= max_sessions {
                return Err(LicensingClientError::LimitExceeded {
                    kind: ResourceLimitKind::ConcurrentSessions,
                    limit: max_sessions,
                    requested: current_concurrent_sessions.saturating_add(1),
                });
            }
        }

        Ok(())
    }

    /// Checks whether a capability is granted under the active lease.
    ///
    /// # Errors
    ///
    /// Returns `OfflineGraceExpired` if grace expired, or `CapabilityMissing` if not granted.
    pub fn check_capability(&self, now: u64, capability: &str) -> Result<(), LicensingClientError> {
        let state = self.evaluate_state(now)?;
        if state == LicenseState::Restricted || state == LicenseState::Revoked {
            return Err(LicensingClientError::OfflineGraceExpired {
                now,
                grace_expires_at: self.active_lease.as_ref().map_or(0, |l| l.grace_expires_at),
            });
        }

        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        if !lease.verified_entitlement.has_capability(capability) {
            return Err(LicensingClientError::CapabilityMissing(
                capability.to_owned(),
            ));
        }

        Ok(())
    }

    /// Checks whether a resource limit permits the requested usage.
    ///
    /// # Errors
    ///
    /// Returns `OfflineGraceExpired` if grace expired, or `LimitExceeded` if usage exceeds limit.
    pub fn check_resource_limit(
        &self,
        now: u64,
        kind: ResourceLimitKind,
        usage: u64,
    ) -> Result<(), LicensingClientError> {
        let state = self.evaluate_state(now)?;
        if state == LicenseState::Restricted || state == LicenseState::Revoked {
            return Err(LicensingClientError::OfflineGraceExpired {
                now,
                grace_expires_at: self.active_lease.as_ref().map_or(0, |l| l.grace_expires_at),
            });
        }

        let lease = self
            .active_lease
            .as_ref()
            .ok_or(LicensingClientError::MissingActiveLease)?;

        if !lease.verified_entitlement.permits_resource(kind, usage) {
            let limit = match kind {
                ResourceLimitKind::LicensedUsers => {
                    lease.verified_entitlement.payload.limits.licensed_users.0
                }
                ResourceLimitKind::ManagedDevices => {
                    lease.verified_entitlement.payload.limits.managed_devices.0
                }
                ResourceLimitKind::ConcurrentSessions => {
                    lease
                        .verified_entitlement
                        .payload
                        .limits
                        .concurrent_sessions
                        .0
                }
                ResourceLimitKind::UnattendedDevices => {
                    lease
                        .verified_entitlement
                        .payload
                        .limits
                        .unattended_devices
                        .0
                }
                ResourceLimitKind::RelayBytesMonthly => {
                    lease
                        .verified_entitlement
                        .payload
                        .limits
                        .relay_bytes_monthly
                        .0
                }
            }
            .unwrap_or(0);

            return Err(LicensingClientError::LimitExceeded {
                kind,
                limit,
                requested: usage,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PRODUCT_ID, PRODUCT_SLUG,
        licensing::{
            LICENSE_CONTRACT_VERSION, LicensePlan, NullableLimit, ResourceLimits,
            SignedEntitlementPayload,
        },
    };
    use ed25519_dalek::Signer;

    const TEST_SERVER_SEED: [u8; 32] = [88_u8; 32];
    const TEST_CLIENT_SEED: [u8; 32] = [77_u8; 32];
    const TEST_KID: &str = "kid-mainplatform-test-01";

    fn test_server_signer() -> SigningKey {
        SigningKey::from_bytes(&TEST_SERVER_SEED)
    }

    fn test_keys_discovery_json() -> Vec<u8> {
        let signer = test_server_signer();
        let pub_base64 = STANDARD.encode(signer.verifying_key().to_bytes());
        format!(
            r#"{{"protocol_version":"KSLP-v1","contract_version":"kmj.omnidesk.license.v1","product_id":"KMJ_OMNIDESK","algorithm":"Ed25519","keys":[{{"kid":"{TEST_KID}","algorithm":"Ed25519","public_key_base64":"{pub_base64}","not_before":0,"not_after":2000000000,"status":"ACTIVE"}}]}}"#
        )
        .into_bytes()
    }

    fn make_test_manager() -> LicensingManager {
        let mut mgr = LicensingManager::new(
            &TEST_CLIENT_SEED,
            "install-test-p520".to_owned(),
            "0.0.1".to_owned(),
            "windows".to_owned(),
            "x86_64".to_owned(),
        );
        mgr.update_verification_keys(&test_keys_discovery_json(), 1_000_000)
            .expect("valid keys discovery");
        mgr
    }

    #[allow(clippy::too_many_arguments)]
    fn make_signed_entitlement_token(
        signer: &SigningKey,
        activation_id: &str,
        device_fingerprint: &str,
        installation_id: &str,
        sequence: u64,
        iat: u64,
        nbf: u64,
        lease_exp: u64,
        exp: u64,
        capabilities: Vec<String>,
        concurrent_sessions: Option<u64>,
    ) -> String {
        let payload = SignedEntitlementPayload {
            protocol_version: LICENSE_PROTOCOL_VERSION.to_owned(),
            contract_version: LICENSE_CONTRACT_VERSION.to_owned(),
            jti: format!("jti-seq-{sequence:08}"),
            kid: TEST_KID.to_owned(),
            license_id: "55555555-1111-4111-8111-111111111111".to_owned(),
            entitlement_id: "55555555-2222-4222-8222-222222222222".to_owned(),
            customer_id: "55555555-3333-4333-8333-333333333333".to_owned(),
            organization_id: None,
            product_id: PRODUCT_ID.to_owned(),
            product_slug: PRODUCT_SLUG.to_owned(),
            plan: LicensePlan::Professional,
            activation_id: activation_id.to_owned(),
            device_public_key_fingerprint: device_fingerprint.to_owned(),
            installation_id: installation_id.to_owned(),
            capabilities,
            limits: ResourceLimits {
                licensed_users: NullableLimit(Some(1)),
                managed_devices: NullableLimit(Some(5)),
                concurrent_sessions: NullableLimit(concurrent_sessions),
                unattended_devices: NullableLimit(Some(3)),
                relay_bytes_monthly: NullableLimit(Some(1000)),
                relay_policy: "direct_preferred".to_owned(),
            },
            issued_at: iat,
            not_before: nbf,
            expires_at: exp,
            lease_expires_at: lease_exp,
            sequence,
            nonce: format!("nonce-seq-{sequence:08}"),
        };

        let canonical_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signature = signer.sign(&canonical_bytes);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&canonical_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{payload_b64}.{sig_b64}")
    }

    #[test]
    fn full_activate_and_renew_lifecycle_advances_sequence() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let (req, idem) =
            mgr.create_activation_request("entitlement-test-1", "idem-0001", "nonce-0001");
        assert_eq!(req.proof_scheme, "KMJ-OMNIDESK-ACTIVATE-v1");
        assert_eq!(idem, "idem-0001");
        assert_eq!(req.device_public_key_fingerprint, mgr.device_fingerprint());

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token_seq1 = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned(), "file.transfer".to_owned()],
            Some(2),
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token_seq1,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();

        let state = mgr
            .process_activation_response(&activation_resp, 1_000_050)
            .expect("activation succeeds");
        assert_eq!(state, LicenseState::Active);

        let renew_req = mgr
            .create_renewal_request("challenge-srv-0001", "nonce-renew-0001")
            .expect("prepare renewal");
        assert_eq!(renew_req.activation_id, activation_id);
        assert_eq!(renew_req.current_sequence, 1);
        assert_eq!(renew_req.proof_scheme, "KMJ-OMNIDESK-RENEW-v1");

        let token_seq2 = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            2,
            1_001_800,
            1_001_800,
            1_007_200,
            1_086_400,
            vec!["remote.interactive".to_owned(), "file.transfer".to_owned()],
            Some(2),
        );

        let renew_resp = serde_json::to_vec(&RenewLeaseResponse {
            signed_entitlement: token_seq2,
            lease_expires_at: 1_007_200,
            next_renewal_at: 1_004_500,
            server_time: 1_001_800,
        })
        .unwrap();

        let new_state = mgr
            .process_renewal_response(&renew_resp, 1_001_850)
            .expect("renewal succeeds");
        assert_eq!(new_state, LicenseState::Active);
        assert_eq!(mgr.active_lease().unwrap().last_accepted_sequence, 2);
    }

    #[test]
    fn replay_or_stale_sequence_in_renewal_is_rejected() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token_seq2 = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            2,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token_seq2,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();
        mgr.process_activation_response(&activation_resp, 1_000_050)
            .unwrap();

        // Stale renewal: sequence 2 again (must strictly increase)
        let stale_token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            2,
            1_001_000,
            1_001_000,
            1_005_000,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );
        let stale_resp = serde_json::to_vec(&RenewLeaseResponse {
            signed_entitlement: stale_token,
            lease_expires_at: 1_005_000,
            next_renewal_at: 1_003_000,
            server_time: 1_001_000,
        })
        .unwrap();

        let err = mgr
            .process_renewal_response(&stale_resp, 1_001_050)
            .unwrap_err();
        assert_eq!(
            err,
            LicensingClientError::Verification(LicenseError::ReplayOrStaleSequence)
        );
    }

    #[test]
    fn offline_grace_and_expiration_transitions_are_fail_closed() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();
        mgr.process_activation_response(&activation_resp, 1_000_050)
            .unwrap();

        // 1. Within normal active window (before renewal due: 1_000_050 + 1775 = 1_001_825)
        assert_eq!(mgr.evaluate_state(1_001_000).unwrap(), LicenseState::Active);

        // 2. Renewal due window (1_001_825 <= now < 1_003_600)
        assert_eq!(
            mgr.evaluate_state(1_002_000).unwrap(),
            LicenseState::RenewalDue
        );

        // 3. Server failure during renewal due -> remains allowed in RenewalDue/Grace
        let server_down_state = mgr
            .handle_server_failure(1_002_000, ServerFailureReason::HttpError(503))
            .unwrap();
        assert_eq!(server_down_state, LicenseState::RenewalDue);

        // 4. Offline grace window (1_003_600 <= now < grace_expires_at)
        assert_eq!(mgr.evaluate_state(1_004_000).unwrap(), LicenseState::Grace);
        let grace_fallback = mgr
            .handle_server_failure(1_004_000, ServerFailureReason::NetworkUnreachable)
            .unwrap();
        assert_eq!(grace_fallback, LicenseState::Grace);

        // Sessions still allowed in grace
        assert!(mgr.check_session_allowed(1_004_000, 0).is_ok());

        // 5. Offline grace expired (now >= grace_expires_at)
        let grace_exp = mgr.active_lease().unwrap().grace_expires_at;
        assert_eq!(
            mgr.evaluate_state(grace_exp + 1).unwrap(),
            LicenseState::Restricted
        );
        let expired_fallback = mgr
            .handle_server_failure(grace_exp + 1, ServerFailureReason::Timeout)
            .unwrap();
        assert_eq!(expired_fallback, LicenseState::Restricted);

        // Sessions blocked when grace expired
        assert!(mgr.check_session_allowed(grace_exp + 1, 0).is_err());
    }

    #[test]
    fn clock_rollback_fails_closed_and_does_not_extend_grace() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();
        mgr.process_activation_response(&activation_resp, 1_000_050)
            .unwrap();

        // Clock moves backwards behind last trusted server time (1_000_000)
        let err = mgr.evaluate_state(999_999).unwrap_err();
        assert_eq!(
            err,
            LicensingClientError::ClockRollback {
                now: 999_999,
                last_trusted_server_time: 1_000_000,
            }
        );

        // Check session allowed also fails closed with clock rollback
        assert!(mgr.check_session_allowed(999_999, 0).is_err());
    }

    #[test]
    fn explicit_revocation_overrides_offline_grace_permanently() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();
        mgr.process_activation_response(&activation_resp, 1_000_050)
            .unwrap();

        // Receive REVOKED status from server
        let status_resp = serde_json::to_vec(&ActivationStatusResponse {
            activation_id: activation_id.to_owned(),
            state: "REVOKED".to_owned(),
            sequence: 1,
            reason_code: Some("DEVICE_TRANSFERRED".to_owned()),
            revoked_at: Some(1_001_000),
            server_time: 1_001_000,
        })
        .unwrap();

        let status_err = mgr
            .process_status_response(&status_resp, 1_001_000)
            .unwrap_err();
        assert_eq!(
            status_err,
            LicensingClientError::Revoked {
                reason: Some("DEVICE_TRANSFERRED".to_owned()),
            }
        );

        // Even though time is within original lease window, revocation holds permanently
        assert!(matches!(
            mgr.evaluate_state(1_001_050),
            Err(LicensingClientError::Revoked { .. })
        ));
        assert!(mgr.check_session_allowed(1_001_050, 0).is_err());
    }

    #[test]
    fn concurrent_sessions_and_resource_limits_are_strictly_enforced() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned(), "file.transfer".to_owned()],
            Some(2), // Max 2 concurrent sessions
        );

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: token,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();
        mgr.process_activation_response(&activation_resp, 1_000_050)
            .unwrap();

        // Session 1: allowed (current usage = 0)
        assert!(mgr.check_session_allowed(1_001_000, 0).is_ok());

        // Session 2: allowed (current usage = 1)
        assert!(mgr.check_session_allowed(1_001_000, 1).is_ok());

        // Session 3: rejected (current usage = 2, limit = 2)
        let err = mgr.check_session_allowed(1_001_000, 2).unwrap_err();
        assert_eq!(
            err,
            LicensingClientError::LimitExceeded {
                kind: ResourceLimitKind::ConcurrentSessions,
                limit: 2,
                requested: 3,
            }
        );

        // Capability check: granted vs ungranted
        assert!(
            mgr.check_capability(1_001_000, "remote.interactive")
                .is_ok()
        );
        assert!(mgr.check_capability(1_001_000, "file.transfer").is_ok());
        assert_eq!(
            mgr.check_capability(1_001_000, "enterprise.sso")
                .unwrap_err(),
            LicensingClientError::CapabilityMissing("enterprise.sso".to_owned())
        );

        // Monthly relay limit check: 1000 allowed, 1001 rejected
        assert!(
            mgr.check_resource_limit(1_001_000, ResourceLimitKind::RelayBytesMonthly, 1000)
                .is_ok()
        );
        assert_eq!(
            mgr.check_resource_limit(1_001_000, ResourceLimitKind::RelayBytesMonthly, 1001)
                .unwrap_err(),
            LicensingClientError::LimitExceeded {
                kind: ResourceLimitKind::RelayBytesMonthly,
                limit: 1000,
                requested: 1001,
            }
        );
    }

    #[test]
    fn forged_or_tampered_signed_entitlement_fails_closed() {
        let mut mgr = make_test_manager();
        let server_signer = test_server_signer();

        let activation_id = "55555555-5555-4555-8555-555555555555";
        let valid_token = make_signed_entitlement_token(
            &server_signer,
            activation_id,
            mgr.device_fingerprint(),
            mgr.installation_id(),
            1,
            1_000_000,
            1_000_000,
            1_003_600,
            1_086_400,
            vec!["remote.interactive".to_owned()],
            Some(2),
        );

        // Tamper with payload
        let parts: Vec<&str> = valid_token.split('.').collect();
        assert_eq!(parts.len(), 2);
        let mut tampered_payload = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        tampered_payload[10] ^= 0x01; // flip 1 bit
        let tampered_part0 = URL_SAFE_NO_PAD.encode(&tampered_payload);
        let tampered_token = format!("{tampered_part0}.{}", parts[1]);

        let activation_resp = serde_json::to_vec(&ActivationResponse {
            activation_id: activation_id.to_owned(),
            signed_entitlement: tampered_token,
            lease_expires_at: 1_003_600,
            server_time: 1_000_000,
            key_set_version: "keys-v1".to_owned(),
        })
        .unwrap();

        let err = mgr
            .process_activation_response(&activation_resp, 1_000_050)
            .unwrap_err();
        assert!(matches!(
            err,
            LicensingClientError::Verification(
                LicenseError::InvalidSignature | LicenseError::MalformedPayload
            )
        ));
    }

    #[test]
    fn server_error_json_is_parsed_without_panicking() {
        let mut mgr = make_test_manager();
        let error_json = br#"{"error":"DEVICE_LIMIT_REACHED","request_id":"req-999999","retry_after_seconds":3600,"message":"Maximum devices activated for this license"}"#;

        let err = mgr
            .process_activation_response(error_json, 1_000_000)
            .unwrap_err();
        assert_eq!(
            err,
            LicensingClientError::ServerRejected {
                error: "DEVICE_LIMIT_REACHED".to_owned(),
                request_id: "req-999999".to_owned(),
                message: Some("Maximum devices activated for this license".to_owned()),
            }
        );
    }
}
