//! Ephemeral Noise NN / ChaCha20-Poly1305 encrypted transport foundation.
//!
//! **NOT AUTHENTICATED. NOT FOR REMOTE CONTROL.** Noise NN establishes a
//! confidential AEAD channel against passive observers, but active peers can
//! interpose two different channels. Do not send the attended password or
//! privileged frames until BOTH enrolled Ed25519 peers and a single-use host
//! password proof are authenticated *against this exact handshake hash*.
//!
//! The existing `TransportSessionAdapter` network-authorization refusal is
//! intentionally unchanged. This separate transport cannot grant consent.

use std::io::ErrorKind;

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

use crate::transport::{HostTransport, PathKind, Transport, TransportError};

const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE_BYTES: usize = 1024;
const MAX_NOISE_FRAME_BYTES: usize = 65_535;
const NOISE_AEAD_TAG_BYTES: usize = 16;
const MAX_NOISE_PLAINTEXT_BYTES: usize = MAX_NOISE_FRAME_BYTES - NOISE_AEAD_TAG_BYTES;

/// Errors establishing the ephemeral, unauthenticated encryption handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseSetupError {
    /// Raw transport framing or I/O failed.
    Transport(TransportError),
    /// Malformed/oversized handshake or missing handshake frame.
    Protocol,
    /// Noise handshake/authentication algorithm failure.
    Cryptography,
}

impl From<TransportError> for NoiseSetupError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// An **unauthenticated** encrypted transport (the channel-binding substrate).
///
/// The original transport path kind is preserved so authorization policy
/// cannot mistake this for host proof, identity verification, or local consent.
pub struct UnauthenticatedNoiseChannel<T: Transport> {
    inner: T,
    cipher: TransportState,
    handshake_hash: [u8; 32],
    closed: bool,
}

impl<T: Transport> UnauthenticatedNoiseChannel<T> {
    /// Starts an ephemeral initiator-side Noise NN handshake.
    ///
    /// # Errors
    /// Fails closed when randomness, noise negotiation, or transport fails.
    pub fn connect(mut inner: T) -> Result<Self, NoiseSetupError> {
        let mut handshake = create_handshake(true)?;
        let mut scratch = [0_u8; MAX_HANDSHAKE_BYTES];

        let length = handshake
            .write_message(&[], &mut scratch)
            .map_err(|_| NoiseSetupError::Cryptography)?;
        inner.send(&scratch[..length])?;

        let response = receive_handshake(&mut inner)?;
        handshake
            .read_message(&response, &mut scratch)
            .map_err(|_| NoiseSetupError::Cryptography)?;
        Self::finish(inner, handshake)
    }

    /// Accepts one ephemeral responder-side Noise NN handshake.
    ///
    /// # Errors
    /// Fails closed on untrusted frames, missing input, and cipher errors.
    pub fn accept(mut inner: T) -> Result<Self, NoiseSetupError> {
        let mut handshake = create_handshake(false)?;
        let mut scratch = [0_u8; MAX_HANDSHAKE_BYTES];

        let first_message = receive_handshake(&mut inner)?;
        handshake
            .read_message(&first_message, &mut scratch)
            .map_err(|_| NoiseSetupError::Cryptography)?;
        let length = handshake
            .write_message(&[], &mut scratch)
            .map_err(|_| NoiseSetupError::Cryptography)?;
        inner.send(&scratch[..length])?;
        Self::finish(inner, handshake)
    }

    fn finish(inner: T, handshake: HandshakeState) -> Result<Self, NoiseSetupError> {
        if !handshake.is_handshake_finished() {
            return Err(NoiseSetupError::Cryptography);
        }
        let transcript = handshake.get_handshake_hash();
        if transcript.len() != 32 {
            return Err(NoiseSetupError::Cryptography);
        }
        let mut handshake_hash = [0_u8; 32];
        handshake_hash.copy_from_slice(transcript);
        if handshake_hash == [0_u8; 32] {
            return Err(NoiseSetupError::Cryptography);
        }
        let cipher = handshake
            .into_transport_mode()
            .map_err(|_| NoiseSetupError::Cryptography)?;
        Ok(Self {
            inner,
            cipher,
            handshake_hash,
            closed: false,
        })
    }

    /// Public channel binding, **not** an authorization token or secret.
    ///
    /// Future verified Ed25519 proof must sign this transcript hash so an
    /// active relay cannot splice two independently encrypted sessions.
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    fn poison(&mut self) {
        self.closed = true;
        self.inner.close();
    }
}

impl UnauthenticatedNoiseChannel<HostTransport> {
    /// Increase the read deadline for a host decision only AFTER the native
    /// caller has verified both pinned identities and the one-use password.
    /// This changes I/O timing only; it never grants session authority.
    ///
    /// # Errors
    /// Fails closed when the transport was closed or socket policy fails.
    pub fn configure_attended_consent_timeout(&self) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        self.inner.configure_attended_consent_timeout()
    }
}

fn create_handshake(initiator: bool) -> Result<HandshakeState, NoiseSetupError> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|_| NoiseSetupError::Cryptography)?;
    let builder = Builder::new(params);
    if initiator {
        builder
            .build_initiator()
            .map_err(|_| NoiseSetupError::Cryptography)
    } else {
        builder
            .build_responder()
            .map_err(|_| NoiseSetupError::Cryptography)
    }
}

fn receive_handshake<T: Transport>(inner: &mut T) -> Result<Vec<u8>, NoiseSetupError> {
    let bytes = inner.receive()?.ok_or(NoiseSetupError::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_BYTES {
        return Err(NoiseSetupError::Protocol);
    }
    Ok(bytes)
}

impl<T: Transport> Transport for UnauthenticatedNoiseChannel<T> {
    fn path_kind(&self) -> PathKind {
        self.inner.path_kind()
    }

    fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        if payload.is_empty() {
            return Err(TransportError::EmptyPayload);
        }
        if payload.len() > MAX_NOISE_PLAINTEXT_BYTES {
            return Err(TransportError::PayloadTooLarge);
        }
        let mut ciphertext = vec![0_u8; payload.len() + NOISE_AEAD_TAG_BYTES];
        let Ok(length) = self.cipher.write_message(payload, &mut ciphertext) else {
            self.poison();
            return Err(TransportError::Io(ErrorKind::InvalidData));
        };
        if let Err(error) = self.inner.send(&ciphertext[..length]) {
            self.poison();
            return Err(error);
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let ciphertext = match self.inner.receive() {
            Ok(Some(ciphertext)) => ciphertext,
            Ok(None) => return Ok(None),
            Err(error) => {
                self.poison();
                return Err(error);
            }
        };
        if !(NOISE_AEAD_TAG_BYTES..=MAX_NOISE_FRAME_BYTES).contains(&ciphertext.len()) {
            self.poison();
            return Err(TransportError::Io(ErrorKind::InvalidData));
        }
        let mut plain = vec![0_u8; ciphertext.len()];
        let Ok(length) = self.cipher.read_message(&ciphertext, &mut plain) else {
            self.poison();
            return Err(TransportError::Io(ErrorKind::InvalidData));
        };
        if length == 0 {
            self.poison();
            return Err(TransportError::EmptyPayload);
        }
        plain.truncate(length);
        Ok(Some(plain))
    }

    fn close(&mut self) {
        self.poison();
    }
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, thread, time::Duration};

    use super::*;
    use crate::transport::TcpLanTransport;

    #[test]
    fn ephemeral_noise_nn_confidential_two_way_tcp_channel_matches_binding_hash() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("listener address");
        let host = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let transport = TcpLanTransport::from_stream(stream).expect("tcp transport");
            let mut channel =
                UnauthenticatedNoiseChannel::accept(transport).expect("noise responder");
            assert_eq!(channel.path_kind(), PathKind::Lan);
            let hash = *channel.handshake_hash();
            let request = channel.receive().expect("decrypt").expect("request");
            assert_eq!(request, b"encrypted transport prototype");
            channel.send(b"protected reply").expect("encrypt reply");
            channel.close();
            hash
        });
        let transport =
            TcpLanTransport::connect(address, Duration::from_secs(2)).expect("tcp connection");
        let mut client = UnauthenticatedNoiseChannel::connect(transport).expect("noise initiator");
        assert_eq!(client.path_kind(), PathKind::Lan);
        let binding = *client.handshake_hash();
        client.send(b"encrypted transport prototype").expect("send");
        assert_eq!(
            client.receive().expect("decrypt response"),
            Some(b"protected reply".to_vec())
        );
        client.close();
        assert_eq!(client.send(b"late"), Err(TransportError::Closed));
        assert_eq!(host.join().expect("host"), binding);
        assert_ne!(binding, [0_u8; 32]);
    }

    #[test]
    fn tampered_aead_ciphertext_closes_channel_and_denies_replay() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("listener address");
        let host = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let transport = TcpLanTransport::from_stream(stream).expect("tcp transport");
            let mut channel =
                UnauthenticatedNoiseChannel::accept(transport).expect("noise responder");
            assert_eq!(
                channel.receive(),
                Err(TransportError::Io(ErrorKind::InvalidData))
            );
            assert_eq!(channel.receive(), Err(TransportError::Closed));
        });
        let transport =
            TcpLanTransport::connect(address, Duration::from_secs(2)).expect("tcp connection");
        let mut client = UnauthenticatedNoiseChannel::connect(transport).expect("noise initiator");
        let mut ciphertext = [0_u8; 64];
        let len = client
            .cipher
            .write_message(b"tampering must fail", &mut ciphertext)
            .expect("encrypted payload");
        ciphertext[len - 1] ^= 1;
        client
            .inner
            .send(&ciphertext[..len])
            .expect("deliver corrupted frame");
        client.close();
        host.join().expect("host");
    }

    #[test]
    fn unauthenticated_noise_channel_alone_is_never_a_control_capability() {
        // Noise NN has no identity: the outer session authorization gate must
        // keep reporting PathKind::Lan, even after AEAD is established.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("listener address");
        let host = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let transport = TcpLanTransport::from_stream(stream).expect("tcp transport");
            let channel = UnauthenticatedNoiseChannel::accept(transport).expect("noise responder");
            assert_eq!(channel.path_kind(), PathKind::Lan);
        });
        let transport =
            TcpLanTransport::connect(address, Duration::from_secs(2)).expect("tcp connection");
        let client = UnauthenticatedNoiseChannel::connect(transport).expect("noise initiator");
        assert_eq!(client.path_kind(), PathKind::Lan);
        host.join().expect("host");
    }
}
