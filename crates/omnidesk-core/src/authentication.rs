//! Cryptographic peer-authentication proof for pre-alpha LAN sessions.
//!
//! This module uses Ed25519 signatures for challenge verification. It does not
//! perform key agreement or session encryption; those remain separate protocol
//! stages and require dedicated security review before production.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::PROTOCOL_VERSION;

const PEER_AUTH_DOMAIN: &[u8] = b"KMJ_OMNIDESK_PEER_AUTH_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationError {
    ZeroNonce,
    InvalidPublicKey,
    InvalidSignature,
}

/// Proof that a peer answered a fresh, domain-separated challenge with the
/// private key corresponding to the expected Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAuthenticationProof {
    public_key: [u8; 32],
    nonce: [u8; 32],
}

impl PeerAuthenticationProof {
    /// Returns the authenticated peer public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the challenge nonce bound into this proof.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

/// Builds the exact domain-separated message that a peer must sign.
///
/// The caller must provide a cryptographically random, single-use nonce. A
/// successful signature does not grant remote-control permission by itself.
#[must_use]
pub fn peer_auth_message(public_key: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        PEER_AUTH_DOMAIN.len() + size_of::<u16>() + public_key.len() + nonce.len(),
    );
    message.extend_from_slice(PEER_AUTH_DOMAIN);
    message.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    message.extend_from_slice(public_key);
    message.extend_from_slice(nonce);
    message
}

/// Verifies an Ed25519 response to a fresh peer-authentication challenge.
///
/// # Errors
///
/// Returns `AuthenticationError::ZeroNonce` for an all-zero challenge,
/// `AuthenticationError::InvalidPublicKey` for an invalid expected key, or
/// `AuthenticationError::InvalidSignature` when signature verification fails.
pub fn verify_peer_authentication(
    public_key: [u8; 32],
    nonce: [u8; 32],
    signature: [u8; 64],
) -> Result<PeerAuthenticationProof, AuthenticationError> {
    if nonce == [0_u8; 32] {
        return Err(AuthenticationError::ZeroNonce);
    }

    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AuthenticationError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature);
    let message = peer_auth_message(&public_key, &nonce);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| AuthenticationError::InvalidSignature)?;

    Ok(PeerAuthenticationProof { public_key, nonce })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn nonce() -> [u8; 32] {
        [9_u8; 32]
    }

    #[test]
    fn valid_challenge_signature_authenticates_expected_peer() {
        let signing_key = signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let nonce = nonce();
        let message = peer_auth_message(&public_key, &nonce);
        let signature = signing_key.sign(&message).to_bytes();

        let proof =
            verify_peer_authentication(public_key, nonce, signature).expect("valid peer proof");

        assert_eq!(proof.public_key(), &public_key);
        assert_eq!(proof.nonce(), &nonce);
    }

    #[test]
    fn tampered_nonce_fails_closed() {
        let signing_key = signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let original_nonce = nonce();
        let message = peer_auth_message(&public_key, &original_nonce);
        let signature = signing_key.sign(&message).to_bytes();
        let mut tampered_nonce = original_nonce;
        tampered_nonce[0] ^= 1;

        assert_eq!(
            verify_peer_authentication(public_key, tampered_nonce, signature),
            Err(AuthenticationError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_peer_key_fails_closed() {
        let signing_key = signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let nonce = nonce();
        let signature = signing_key
            .sign(&peer_auth_message(&public_key, &nonce))
            .to_bytes();
        let wrong_key = SigningKey::from_bytes(&[8_u8; 32])
            .verifying_key()
            .to_bytes();

        assert_eq!(
            verify_peer_authentication(wrong_key, nonce, signature),
            Err(AuthenticationError::InvalidSignature)
        );
    }

    #[test]
    fn zero_nonce_is_rejected() {
        let signing_key = signing_key();
        let public_key = signing_key.verifying_key().to_bytes();

        assert_eq!(
            verify_peer_authentication(public_key, [0_u8; 32], [0_u8; 64]),
            Err(AuthenticationError::ZeroNonce)
        );
    }
}
