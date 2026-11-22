//! Attended password proof on a mutually authenticated Noise channel.
//!
//! A successful proof does NOT authorize remote screen/input.
//! Visible host consent and licensing are still mandatory.
//!
//! Never expose a SHA-256 password proof over raw TCP: it is not a PAKE.

use serde::{Deserialize, Serialize};

use crate::{
    device_identity::DeviceIdentity,
    mutual_identity::{
        MutualIdentityError, client_mutual_identity_handshake, host_mutual_identity_handshake,
    },
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    password_auth::{HostPasswordManager, PasswordVerificationError, generate_password_proof},
    transport::{Transport, TransportError},
    trusted_device_store::TrustedDeviceStore,
};

const MAX_ATTENDED_WIRE_BYTES: usize = 2048;

/// Non-cloneable proof witnessed by the host only AFTER it has verified
/// mutual pinned identities and a single-use password challenge inside
/// the exact Noise session. Fields are private; callers cannot construct
/// this receipt from a UI flag, socket address or untrusted claimed ID.
///
/// The receipt by itself CANNOT authorize a transport, media or input.
pub struct HostPasswordProofReceipt {
    peer_id: String,
    peer_public_key: [u8; 32],
    host_id: String,
    host_public_key: [u8; 32],
    noise_handshake_hash: [u8; 32],
    session_id: [u8; 16],
    verified_at_epoch_secs: u64,
}

impl HostPasswordProofReceipt {
    /// Enrolled client device identity verified by both key and signature.
    #[must_use]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Client public key pinned to this verified peer ID.
    #[must_use]
    pub const fn peer_public_key(&self) -> &[u8; 32] {
        &self.peer_public_key
    }

    /// Host ID verified and bound to the password challenge.
    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Host public key bound to this exact encrypted handshake.
    #[must_use]
    pub const fn host_public_key(&self) -> &[u8; 32] {
        &self.host_public_key
    }

    /// Noise transcript binding, not a bearer token or encryption key.
    #[must_use]
    pub const fn noise_handshake_hash(&self) -> &[u8; 32] {
        &self.noise_handshake_hash
    }

    /// One-use challenge ID. Never a standalone authorization secret.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// When the host witnessed a successful proof.
    #[must_use]
    pub const fn verified_at_epoch_secs(&self) -> u64 {
        self.verified_at_epoch_secs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttendedProofError {
    Identity(MutualIdentityError),
    Password(PasswordVerificationError),
    Transport(TransportError),
    Protocol,
    Denied,
}

impl From<MutualIdentityError> for AttendedProofError {
    fn from(value: MutualIdentityError) -> Self {
        Self::Identity(value)
    }
}
impl From<PasswordVerificationError> for AttendedProofError {
    fn from(value: PasswordVerificationError) -> Self {
        Self::Password(value)
    }
}
impl From<TransportError> for AttendedProofError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Wire {
    Challenge {
        host_id: String,
        session_id: [u8; 16],
        nonce: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
        noise_hash: [u8; 32],
    },
    Proof {
        digest: [u8; 32],
    },
    Denied,
    Verified,
}

fn send<T: Transport>(
    channel: &mut UnauthenticatedNoiseChannel<T>,
    message: &Wire,
) -> Result<(), AttendedProofError> {
    let serialized = serde_json::to_vec(message).map_err(|_| AttendedProofError::Protocol)?;
    if serialized.len() > MAX_ATTENDED_WIRE_BYTES {
        return Err(AttendedProofError::Protocol);
    }
    channel.send(&serialized)?;
    Ok(())
}

fn receive<T: Transport>(
    channel: &mut UnauthenticatedNoiseChannel<T>,
) -> Result<Wire, AttendedProofError> {
    let bytes = channel.receive()?.ok_or(AttendedProofError::Protocol)?;
    if bytes.len() > MAX_ATTENDED_WIRE_BYTES {
        return Err(AttendedProofError::Protocol);
    }
    serde_json::from_slice(&bytes).map_err(|_| AttendedProofError::Protocol)
}

/// Verify host-owned temporary password proof *after* mutually pinned
/// Ed25519 identities have authenticated the SAME encrypted Noise transcript.
///
/// On success, the function reports identity-and-password proof only. It
/// NEVER activates a desktop session, permissions, or transport controls.
///
/// # Errors
/// Returns a fail-closed error if identity, password, expiry, lockout,
/// challenge framing, or encrypted transport verification fails.
pub fn host_verify_attended_password<T: Transport>(
    channel: &mut UnauthenticatedNoiseChannel<T>,
    identity: &DeviceIdentity,
    store: &TrustedDeviceStore,
    manager: &mut HostPasswordManager,
    tenant: &str,
    now_epoch_secs: u64,
) -> Result<(), AttendedProofError> {
    host_verify_attended_password_with_receipt(
        channel,
        identity,
        store,
        manager,
        tenant,
        now_epoch_secs,
    )
    .map(|_| ())
}

/// Issues an unforgeable-in-crate, non-cloneable proof receipt only after
/// encrypted host password verification and successful wire confirmation.
///
/// The result must be consumed by a separate, visible, license-validated
/// host-approval preflight and can NEVER directly enable network input.
///
/// # Errors
/// Rejects failed cryptographic handshakes, invalid password, expired or
/// replayed challenge, lockout and any wire I/O error.
pub fn host_verify_attended_password_with_receipt<T: Transport>(
    channel: &mut UnauthenticatedNoiseChannel<T>,
    identity: &DeviceIdentity,
    store: &TrustedDeviceStore,
    manager: &mut HostPasswordManager,
    tenant: &str,
    now_epoch_secs: u64,
) -> Result<HostPasswordProofReceipt, AttendedProofError> {
    let peer = host_mutual_identity_handshake(channel, identity, store, tenant, now_epoch_secs)?;
    let host_key = identity.public_key_bytes();
    let mut challenge = manager.issue_proof_challenge(
        identity.public_id(),
        peer.peer_public_key,
        host_key,
        now_epoch_secs,
    )?;
    let noise_hash = *channel.handshake_hash();
    challenge.bind_noise_hash(&noise_hash)?;
    send(
        channel,
        &Wire::Challenge {
            host_id: challenge.host_device_id().to_owned(),
            session_id: *challenge.session_id(),
            nonce: *challenge.nonce(),
            client_key: *challenge.client_public_key(),
            host_key: *challenge.host_public_key(),
            noise_hash,
        },
    )?;
    let Wire::Proof { digest } = receive(channel)? else {
        return Err(AttendedProofError::Protocol);
    };
    match manager.verify_proof_once(&mut challenge, &digest, now_epoch_secs) {
        Ok(()) => {
            send(channel, &Wire::Verified)?;
            Ok(HostPasswordProofReceipt {
                peer_id: peer.peer_id,
                peer_public_key: peer.peer_public_key,
                host_id: identity.public_id().to_owned(),
                host_public_key: host_key,
                noise_handshake_hash: noise_hash,
                session_id: *challenge.session_id(),
                verified_at_epoch_secs: now_epoch_secs,
            })
        }
        Err(err) => {
            // No password, attempts remaining, or host secret in wire result.
            let _ = send(channel, &Wire::Denied);
            Err(AttendedProofError::Password(err))
        }
    }
}

/// Respond to a challenge only after verifying the enrolled host identity
/// over an encrypted, transcript-bound Noise session.
///
/// No plaintext password bytes ever enter the wire protocol. The received
/// proof digest is vulnerable to offline password guessing if encryption
/// or mutual key verification is bypassed: do not permit raw Transport here.
///
/// # Errors
/// Rejects malformed, mismatched, replayed, or rejected challenges.
pub fn client_prove_attended_password<T: Transport>(
    channel: &mut UnauthenticatedNoiseChannel<T>,
    identity: &DeviceIdentity,
    store: &TrustedDeviceStore,
    expected_host_id: &str,
    tenant: &str,
    password: &str,
    now_epoch_secs: u64,
) -> Result<(), AttendedProofError> {
    let peer = client_mutual_identity_handshake(
        channel,
        identity,
        store,
        expected_host_id,
        tenant,
        now_epoch_secs,
    )?;
    let Wire::Challenge {
        host_id,
        session_id,
        nonce,
        client_key,
        host_key,
        noise_hash,
    } = receive(channel)?
    else {
        return Err(AttendedProofError::Protocol);
    };
    if host_id != peer.peer_id
        || host_id != expected_host_id
        || host_key != peer.peer_public_key
        || client_key != identity.public_key_bytes()
        || noise_hash != *channel.handshake_hash()
        || session_id == [0_u8; 16]
        || nonce == [0_u8; 32]
    {
        return Err(AttendedProofError::Protocol);
    }
    let digest = generate_password_proof(
        password,
        &host_id,
        &session_id,
        &nonce,
        &client_key,
        &host_key,
    );
    send(channel, &Wire::Proof { digest })?;
    match receive(channel)? {
        Wire::Verified => Ok(()),
        Wire::Denied => Err(AttendedProofError::Denied),
        _ => Err(AttendedProofError::Protocol),
    }
}
