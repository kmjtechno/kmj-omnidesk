//! Mutually verified client/host identities **bound to encrypted Noise NN**.
//!
//! Each Ed25519 signature covers the *same* 32-byte Noise handshake hash
//! plus both device keys/IDs, random nonces, tenant and sender role.
//! This prevents active relay/MITM from splicing two unauthenticated NN
//! channels. An identity-only receipt is still NOT attended password proof,
//! user consent, media/input authorization or a commercial release.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    PROTOCOL_VERSION,
    device_enrollment::generate_csprng_nonce,
    device_identity::DeviceIdentity,
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    session::PeerIdentity,
    transport::{Transport, TransportError},
    trusted_device_store::TrustedDeviceStore,
};

const TRANSCRIPT_DOMAIN: &[u8] = b"KMJ_OMNIDESK_MUTUAL_IDENTITY_V2";
const MAX_AUTH_MESSAGE_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutualIdentityError {
    Transport(TransportError),
    InvalidFrame,
    InvalidIdentity,
    TenantMismatch,
    UntrustedPeer,
    IdentityMismatch,
    Revoked,
    Expired,
    InvalidSignature,
}

impl From<TransportError> for MutualIdentityError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Receipt for both pinned identities on one Noise encrypted transcript.
///
/// This is not a password-proof or remote-control authorization token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityOnlyReceipt {
    pub peer_id: String,
    pub peer_public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Message {
    Hello {
        client_id: String,
        tenant: String,
        client_public_key: [u8; 32],
        client_nonce: [u8; 32],
    },
    Challenge {
        host_id: String,
        host_public_key: [u8; 32],
        host_nonce: [u8; 32],
        #[serde(with = "crate::device_enrollment::serde_bytes_64")]
        signature: [u8; 64],
    },
    Proof {
        #[serde(with = "crate::device_enrollment::serde_bytes_64")]
        signature: [u8; 64],
    },
    Success {
        #[serde(with = "crate::device_enrollment::serde_bytes_64")]
        signature: [u8; 64],
    },
    Reject,
}

fn send<T: Transport>(transport: &mut T, message: &Message) -> Result<(), MutualIdentityError> {
    let bytes = serde_json::to_vec(message).map_err(|_| MutualIdentityError::InvalidFrame)?;
    if bytes.len() > MAX_AUTH_MESSAGE_BYTES {
        return Err(MutualIdentityError::InvalidFrame);
    }
    transport.send(&bytes)?;
    Ok(())
}

fn receive<T: Transport>(transport: &mut T) -> Result<Message, MutualIdentityError> {
    let bytes = transport
        .receive()?
        .ok_or(MutualIdentityError::InvalidFrame)?;
    if bytes.len() > MAX_AUTH_MESSAGE_BYTES {
        return Err(MutualIdentityError::InvalidFrame);
    }
    serde_json::from_slice(&bytes).map_err(|_| MutualIdentityError::InvalidFrame)
}

fn valid_identity(value: &str) -> Result<(), MutualIdentityError> {
    PeerIdentity::new(value).map_err(|_| MutualIdentityError::InvalidIdentity)?;
    Ok(())
}

fn require_pinned(
    store: &TrustedDeviceStore,
    id: &str,
    key: &[u8; 32],
    now_epoch_secs: u64,
) -> Result<(), MutualIdentityError> {
    let record = store.get(id).ok_or(MutualIdentityError::UntrustedPeer)?;
    if &record.public_key != key {
        return Err(MutualIdentityError::IdentityMismatch);
    }
    if record.revoked {
        return Err(MutualIdentityError::Revoked);
    }
    if now_epoch_secs >= record.trust_expires_at_epoch_secs {
        return Err(MutualIdentityError::Expired);
    }
    Ok(())
}

struct Transcript<'a> {
    noise_hash: &'a [u8; 32],
    tenant: &'a str,
    client_id: &'a str,
    client_public_key: &'a [u8; 32],
    client_nonce: &'a [u8; 32],
    host_id: &'a str,
    host_public_key: &'a [u8; 32],
    host_nonce: &'a [u8; 32],
}

fn append_string(message: &mut Vec<u8>, value: &str) {
    let length = u16::try_from(value.len()).expect("bounded identity must fit u16");
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
}

fn signed_message(role: &[u8], transcript: &Transcript<'_>) -> Vec<u8> {
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(TRANSCRIPT_DOMAIN);
    message.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    message.extend_from_slice(transcript.noise_hash);
    message.push(u8::try_from(role.len()).expect("short authentication role"));
    message.extend_from_slice(role);
    append_string(&mut message, transcript.tenant);
    append_string(&mut message, transcript.client_id);
    message.extend_from_slice(transcript.client_public_key);
    message.extend_from_slice(transcript.client_nonce);
    append_string(&mut message, transcript.host_id);
    message.extend_from_slice(transcript.host_public_key);
    message.extend_from_slice(transcript.host_nonce);
    message
}

fn verify(
    key: &[u8; 32],
    signed_payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), MutualIdentityError> {
    let verifier =
        VerifyingKey::from_bytes(key).map_err(|_| MutualIdentityError::InvalidSignature)?;
    verifier
        .verify_strict(signed_payload, &Signature::from_bytes(signature))
        .map_err(|_| MutualIdentityError::InvalidSignature)
}

/// Host-side handshake: verify the client's pinned signing key, then prove
/// the host's pinned identity with two nonce-bound signed transcripts.
///
/// The caller must CLOSE the encrypted channel on any error and must not
/// authorize remote control until bound attended password proof + consent.
///
/// # Errors
/// Fails on any untrusted/mismatched identity, replayed transcript, invalid
/// signature, wrong tenant or malformed wire frame.
pub fn host_mutual_identity_handshake<T: Transport>(
    transport: &mut UnauthenticatedNoiseChannel<T>,
    identity: &DeviceIdentity,
    store: &TrustedDeviceStore,
    tenant: &str,
    now_epoch_secs: u64,
) -> Result<IdentityOnlyReceipt, MutualIdentityError> {
    valid_identity(tenant)?;
    let noise_hash = *transport.handshake_hash();
    let Message::Hello {
        client_id,
        tenant: received_tenant,
        client_public_key,
        client_nonce,
    } = receive(transport)?
    else {
        return Err(MutualIdentityError::InvalidFrame);
    };
    valid_identity(&client_id)?;
    if received_tenant != tenant {
        return Err(MutualIdentityError::TenantMismatch);
    }
    if client_nonce == [0_u8; 32] {
        return Err(MutualIdentityError::InvalidFrame);
    }
    require_pinned(store, &client_id, &client_public_key, now_epoch_secs)?;

    let host_nonce = generate_csprng_nonce(now_epoch_secs);
    let host_public_key = identity.public_key_bytes();
    let transcript = Transcript {
        noise_hash: &noise_hash,
        tenant,
        client_id: &client_id,
        client_public_key: &client_public_key,
        client_nonce: &client_nonce,
        host_id: identity.public_id(),
        host_public_key: &host_public_key,
        host_nonce: &host_nonce,
    };
    send(
        transport,
        &Message::Challenge {
            host_id: identity.public_id().to_owned(),
            host_public_key,
            host_nonce,
            signature: identity.sign(&signed_message(b"host", &transcript)),
        },
    )?;
    let Message::Proof { signature } = receive(transport)? else {
        return Err(MutualIdentityError::InvalidFrame);
    };
    verify(
        &client_public_key,
        &signed_message(b"client", &transcript),
        &signature,
    )?;
    send(
        transport,
        &Message::Success {
            signature: identity.sign(&signed_message(b"host-confirm", &transcript)),
        },
    )?;
    Ok(IdentityOnlyReceipt {
        peer_id: client_id,
        peer_public_key: client_public_key,
    })
}

/// Client-side handshake: first verify the remote host against a pinned
/// trusted key and its signed challenge. Only then sign the client response.
///
/// This channel is encrypted, but ID proof is not host password proof or
/// permission; caller MUST deny every privileged payload until both pass.
///
/// # Errors
/// Rejects untrusted host, incorrect tenant, mismatched host ID/key,
/// invalid signed transcript or unauthenticated confirmation.
pub fn client_mutual_identity_handshake<T: Transport>(
    transport: &mut UnauthenticatedNoiseChannel<T>,
    identity: &DeviceIdentity,
    store: &TrustedDeviceStore,
    expected_host_id: &str,
    tenant: &str,
    now_epoch_secs: u64,
) -> Result<IdentityOnlyReceipt, MutualIdentityError> {
    valid_identity(tenant)?;
    valid_identity(expected_host_id)?;
    let noise_hash = *transport.handshake_hash();
    let client_id = identity.public_id();
    let client_public_key = identity.public_key_bytes();
    let client_nonce = generate_csprng_nonce(now_epoch_secs);
    send(
        transport,
        &Message::Hello {
            client_id: client_id.to_owned(),
            tenant: tenant.to_owned(),
            client_public_key,
            client_nonce,
        },
    )?;
    let Message::Challenge {
        host_id,
        host_public_key,
        host_nonce,
        signature,
    } = receive(transport)?
    else {
        return Err(MutualIdentityError::InvalidFrame);
    };
    if host_id != expected_host_id || host_nonce == [0_u8; 32] {
        return Err(MutualIdentityError::IdentityMismatch);
    }
    require_pinned(store, &host_id, &host_public_key, now_epoch_secs)?;
    let transcript = Transcript {
        noise_hash: &noise_hash,
        tenant,
        client_id,
        client_public_key: &client_public_key,
        client_nonce: &client_nonce,
        host_id: &host_id,
        host_public_key: &host_public_key,
        host_nonce: &host_nonce,
    };
    verify(
        &host_public_key,
        &signed_message(b"host", &transcript),
        &signature,
    )?;
    send(
        transport,
        &Message::Proof {
            signature: identity.sign(&signed_message(b"client", &transcript)),
        },
    )?;
    let Message::Success { signature } = receive(transport)? else {
        return Err(MutualIdentityError::InvalidFrame);
    };
    verify(
        &host_public_key,
        &signed_message(b"host-confirm", &transcript),
        &signature,
    )?;
    Ok(IdentityOnlyReceipt {
        peer_id: host_id,
        peer_public_key: host_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_each_nonce_are_bound_to_both_device_keys() {
        let client = DeviceIdentity::from_seed(&[17_u8; 32]);
        let host = DeviceIdentity::from_seed(&[18_u8; 32]);
        let client_key = client.public_key_bytes();
        let host_key = host.public_key_bytes();
        let client_nonce = [21_u8; 32];
        let host_nonce = [22_u8; 32];
        let noise_hash = [31_u8; 32];
        let transcript = Transcript {
            noise_hash: &noise_hash,
            tenant: "kmj-tenant",
            client_id: client.public_id(),
            client_public_key: &client_key,
            client_nonce: &client_nonce,
            host_id: host.public_id(),
            host_public_key: &host_key,
            host_nonce: &host_nonce,
        };
        let signed = signed_message(b"host", &transcript);
        let signature = host.sign(&signed);
        assert!(verify(&host_key, &signed, &signature).is_ok());
        assert_eq!(
            verify(
                &host_key,
                &signed_message(b"client", &transcript),
                &signature
            ),
            Err(MutualIdentityError::InvalidSignature)
        );
        let different_hash = [32_u8; 32];
        let another_secure_channel = Transcript {
            noise_hash: &different_hash,
            ..transcript
        };
        assert_eq!(
            verify(
                &host_key,
                &signed_message(b"host", &another_secure_channel),
                &signature
            ),
            Err(MutualIdentityError::InvalidSignature),
            "a signature on another Noise handshake must never authenticate this one"
        );
        let different_nonce = [23_u8; 32];
        let stale = Transcript {
            host_nonce: &different_nonce,
            ..transcript
        };
        assert_eq!(
            verify(&host_key, &signed_message(b"host", &stale), &signature),
            Err(MutualIdentityError::InvalidSignature)
        );
    }

    #[test]
    fn oversized_and_empty_wire_messages_fail() {
        let mut transport = crate::transport::LoopbackTransport::default();
        assert_eq!(
            receive(&mut transport),
            Err(MutualIdentityError::InvalidFrame)
        );
        transport
            .send(&vec![0x40; MAX_AUTH_MESSAGE_BYTES + 1])
            .unwrap();
        assert_eq!(
            receive(&mut transport),
            Err(MutualIdentityError::InvalidFrame)
        );
    }
}
