//! Cryptographically authenticated transport session adapter.
//!
//! Enforces:
//! - Strict Ed25519 challenge-response peer authentication
//! - Trusted device store verification (revocation check and expiration check)
//! - Cross-tenant isolation (strict fail-closed boundary enforcement)
//! - Fail-closed payload gating: all frames, control, and keystrokes/clicks
//!   are rejected unless the session is fully authenticated and authorized.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    PROTOCOL_VERSION,
    authentication::{AuthenticationError, peer_auth_message, verify_peer_authentication},
    device_enrollment::generate_csprng_nonce,
    session::{PeerIdentity, Session, SessionError, SessionState},
    transport::{Transport, TransportError},
    trusted_device_store::{TrustedDeviceRecord, TrustedDeviceStore},
};

/// Errors encountered during authenticated transport session lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSessionError {
    Transport(TransportError),
    Session(SessionError),
    Auth(AuthenticationError),
    UntrustedPeer,
    PeerRevoked,
    TrustExpired,
    TenantMismatch { expected: String, received: String },
    UnverifiedControlBlocked,
    Protocol(String),
}

impl fmt::Display for TransportSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "transport error: {err:?}"),
            Self::Session(err) => write!(f, "session error: {err:?}"),
            Self::Auth(err) => write!(f, "authentication error: {err:?}"),
            Self::UntrustedPeer => write!(f, "peer public key is not enrolled in trusted store"),
            Self::PeerRevoked => write!(f, "peer trust record has been revoked"),
            Self::TrustExpired => write!(f, "peer trust has expired"),
            Self::TenantMismatch { expected, received } => {
                write!(
                    f,
                    "cross-tenant boundary violation: expected '{expected}', received '{received}'"
                )
            }
            Self::UnverifiedControlBlocked => {
                write!(
                    f,
                    "action blocked: peer transport is not authenticated or authorized"
                )
            }
            Self::Protocol(err) => write!(f, "session auth protocol error: {err}"),
        }
    }
}

impl std::error::Error for TransportSessionError {}

impl From<TransportError> for TransportSessionError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<SessionError> for TransportSessionError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<AuthenticationError> for TransportSessionError {
    fn from(e: AuthenticationError) -> Self {
        Self::Auth(e)
    }
}

/// Adapts an underlying [`Transport`] into a cryptographically authenticated session.
#[derive(Debug)]
pub struct TransportSessionAdapter<T: Transport> {
    transport: T,
    session: Session,
    local_tenant: String,
    authenticated_device_id: Option<String>,
}

impl<T: Transport> TransportSessionAdapter<T> {
    /// Creates a new adapter wrapping the given transport and enforcing the local tenant.
    #[must_use]
    pub fn new(transport: T, local_tenant: impl Into<String>) -> Self {
        Self {
            transport,
            session: Session::default(),
            local_tenant: local_tenant.into(),
            authenticated_device_id: None,
        }
    }

    /// Accesses the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably accesses the underlying transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Accesses the session state machine.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Local tenant identifier enforced on incoming peer connections.
    #[must_use]
    pub fn local_tenant(&self) -> &str {
        &self.local_tenant
    }

    /// Enrolled device identifier proven during authentication.
    #[must_use]
    pub fn authenticated_device_id(&self) -> Option<&str> {
        self.authenticated_device_id.as_deref()
    }

    /// Whether the session has completed negotiation and authorization.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.session.state(), SessionState::Active)
    }

    /// Whether control operations are cryptographically authorized.
    #[must_use]
    pub const fn is_control_authorized(&self) -> bool {
        self.session.control_authorized() && matches!(self.session.state(), SessionState::Active)
    }

    /// Initiates session negotiation with a verified peer identity.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError`] if negotiation cannot begin.
    pub fn begin_negotiation(
        &mut self,
        peer_identity: PeerIdentity,
    ) -> Result<(), TransportSessionError> {
        self.session
            .begin(peer_identity, PROTOCOL_VERSION)
            .map_err(TransportSessionError::Session)
    }

    /// Authenticates the remote peer cryptographically against the trusted device store.
    ///
    /// Strictly verifies:
    /// 1. Tenant boundary matches `local_tenant`.
    /// 2. Ed25519 signature verifies over the domain-separated authentication challenge.
    /// 3. Public key exists in `store`.
    /// 4. Trust record is not revoked.
    /// 5. Trust record has not expired at `now_epoch_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError`] on any boundary or cryptographic failure.
    pub fn authenticate_peer(
        &mut self,
        public_key: [u8; 32],
        nonce: [u8; 32],
        signature: [u8; 64],
        peer_tenant: &str,
        store: &TrustedDeviceStore,
        now_epoch_secs: u64,
    ) -> Result<TrustedDeviceRecord, TransportSessionError> {
        if self.local_tenant != peer_tenant {
            return Err(TransportSessionError::TenantMismatch {
                expected: self.local_tenant.clone(),
                received: peer_tenant.to_owned(),
            });
        }

        let proof = verify_peer_authentication(public_key, nonce, signature)?;

        let record = store
            .find_by_public_key(&public_key)
            .ok_or(TransportSessionError::UntrustedPeer)?;

        if record.revoked {
            return Err(TransportSessionError::PeerRevoked);
        }

        if now_epoch_secs > record.trust_expires_at_epoch_secs {
            return Err(TransportSessionError::TrustExpired);
        }

        self.session
            .authenticate_with_trusted_store(&proof, store, now_epoch_secs)?;

        self.authenticated_device_id = Some(record.device_id.clone());
        Ok(record.clone())
    }

    /// Authorizes remote session control once authentication has succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError`] if the session is not awaiting authorization.
    pub fn authorize_session(&mut self) -> Result<(), TransportSessionError> {
        self.session
            .authorize_control()
            .map_err(TransportSessionError::Session)
    }

    /// Sends a payload through the transport ONLY if the session is active and control authorized.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError::UnverifiedControlBlocked`] if not authorized,
    /// or transport error.
    pub fn send(&mut self, payload: &[u8]) -> Result<(), TransportSessionError> {
        if !self.is_control_authorized() {
            return Err(TransportSessionError::UnverifiedControlBlocked);
        }
        self.transport
            .send(payload)
            .map_err(TransportSessionError::Transport)
    }

    /// Receives a payload through the transport ONLY if the session is active and control authorized.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError::UnverifiedControlBlocked`] if not authorized,
    /// or transport error.
    pub fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportSessionError> {
        if !self.is_control_authorized() {
            return Err(TransportSessionError::UnverifiedControlBlocked);
        }
        self.transport
            .receive()
            .map_err(TransportSessionError::Transport)
    }

    /// Closes the session and transport, resetting all authorization.
    pub fn close(&mut self) {
        self.authenticated_device_id = None;
        self.session.disconnect();
        self.transport.close();
    }
}

/// Wire protocol messages for in-band peer session authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionAuthWireMessage {
    /// Peer begins authentication negotiation
    Hello {
        device_id: String,
        peer_tenant: String,
    },
    /// Host responds with a fresh CSPRNG nonce challenge for session auth
    Challenge { nonce: [u8; 32] },
    /// Peer returns cryptographic proof
    Proof {
        public_key: [u8; 32],
        #[serde(with = "crate::device_enrollment::serde_bytes_64")]
        signature: [u8; 64],
    },
    /// Peer returns password proof
    PasswordProof {
        host_id: String,
        client_id: String,
        proof: [u8; 32],
    },
    /// Host confirms session is authenticated
    Success { device_id: String },
    /// Host or peer rejects
    Reject { reason: String },
}

impl SessionAuthWireMessage {
    /// Serializes auth wire message to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError::Protocol`] on serialization failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransportSessionError> {
        serde_json::to_vec(self).map_err(|e| TransportSessionError::Protocol(e.to_string()))
    }

    /// Deserializes auth wire message from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TransportSessionError::Protocol`] on deserialization failure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransportSessionError> {
        serde_json::from_slice(bytes).map_err(|e| TransportSessionError::Protocol(e.to_string()))
    }
}

/// Executes the host-side authentication handshake over the adapter's transport,
/// supporting both trusted public-key proof and in-band session password proof.
///
/// On any failure, transmits `Reject { reason }`, closes the session, and fails closed.
///
/// # Errors
///
/// Returns [`TransportSessionError`] if negotiation, authentication, or transport fails.
#[allow(clippy::too_many_lines)]
pub fn host_negotiate_and_authenticate_session_with_password<T: Transport>(
    adapter: &mut TransportSessionAdapter<T>,
    store: &TrustedDeviceStore,
    local_device_id: &str,
    mut password_mgr: Option<&mut crate::password_auth::SessionPasswordManager>,
    now_epoch_secs: u64,
) -> Result<TrustedDeviceRecord, TransportSessionError> {
    let raw = adapter.transport_mut().receive()?.ok_or_else(|| {
        TransportSessionError::Protocol("connection closed before hello".to_owned())
    })?;

    let hello = SessionAuthWireMessage::from_bytes(&raw)?;
    let (device_id, peer_tenant) = match hello {
        SessionAuthWireMessage::Hello {
            device_id,
            peer_tenant,
        } => (device_id, peer_tenant),
        SessionAuthWireMessage::Reject { reason } => {
            return Err(TransportSessionError::Protocol(format!(
                "peer rejected: {reason}"
            )));
        }
        _ => {
            return Err(TransportSessionError::Protocol(
                "expected Hello message".to_owned(),
            ));
        }
    };

    let peer_id = PeerIdentity::new(&device_id).map_err(TransportSessionError::Session)?;
    adapter.begin_negotiation(peer_id)?;

    let nonce = generate_csprng_nonce(now_epoch_secs);
    let challenge_msg = SessionAuthWireMessage::Challenge { nonce };
    adapter.transport_mut().send(&challenge_msg.to_bytes()?)?;

    let raw_proof = adapter.transport_mut().receive()?.ok_or_else(|| {
        TransportSessionError::Protocol("connection closed before proof".to_owned())
    })?;

    let proof_msg = SessionAuthWireMessage::from_bytes(&raw_proof)?;
    match proof_msg {
        SessionAuthWireMessage::Proof {
            public_key,
            signature,
        } => {
            match adapter.authenticate_peer(
                public_key,
                nonce,
                signature,
                &peer_tenant,
                store,
                now_epoch_secs,
            ) {
                Ok(record) => {
                    let success_msg = SessionAuthWireMessage::Success {
                        device_id: record.device_id.clone(),
                    };
                    adapter.transport_mut().send(&success_msg.to_bytes()?)?;
                    Ok(record)
                }
                Err(err) => {
                    let reject_msg = SessionAuthWireMessage::Reject {
                        reason: err.to_string(),
                    };
                    if let Ok(bytes) = reject_msg.to_bytes() {
                        let _ = adapter.transport_mut().send(&bytes);
                    }
                    adapter.close();
                    Err(err)
                }
            }
        }
        SessionAuthWireMessage::PasswordProof {
            host_id,
            client_id,
            proof,
        } => {
            let res = password_mgr.as_mut().map_or_else(
                || {
                    Err(TransportSessionError::Protocol(
                        "no session password active".to_owned(),
                    ))
                },
                |mgr| {
                    mgr.verify_proof(&host_id, &client_id, &nonce, &proof, now_epoch_secs)
                        .map_err(|e| TransportSessionError::Protocol(e.to_string()))
                },
            );

            match res {
                Ok(()) => {
                    let host_display_id = if local_device_id.is_empty() {
                        "KMJ-HOST".to_owned()
                    } else {
                        local_device_id.to_owned()
                    };
                    let success_msg = SessionAuthWireMessage::Success {
                        device_id: host_display_id,
                    };
                    adapter.transport_mut().send(&success_msg.to_bytes()?)?;
                    Ok(TrustedDeviceRecord {
                        device_id: client_id.clone(),
                        display_name: format!("Password-Auth Peer ({client_id})"),
                        public_key: [0_u8; 32],
                        enrolled_at_epoch_secs: now_epoch_secs,
                        trust_expires_at_epoch_secs: now_epoch_secs.saturating_add(86_400),
                        managed: false,
                        revoked: false,
                        status: crate::trusted_device_store::PersistedDeviceStatus::Online,
                    })
                }
                Err(err) => {
                    let reject_msg = SessionAuthWireMessage::Reject {
                        reason: err.to_string(),
                    };
                    if let Ok(bytes) = reject_msg.to_bytes() {
                        let _ = adapter.transport_mut().send(&bytes);
                    }
                    adapter.close();
                    Err(err)
                }
            }
        }
        SessionAuthWireMessage::Reject { reason } => Err(TransportSessionError::Protocol(format!(
            "peer rejected: {reason}"
        ))),
        _ => Err(TransportSessionError::Protocol(
            "expected Proof or PasswordProof message".to_owned(),
        )),
    }
}

/// Executes the host-side authentication handshake over the adapter's transport.
///
/// 1. Receives `Hello { device_id, peer_tenant }`.
/// 2. Begins session negotiation with `PeerIdentity::new(&device_id)`.
/// 3. Generates a fresh CSPRNG nonce and sends `Challenge { nonce }`.
/// 4. Receives `Proof { public_key, signature }`.
/// 5. Strictly authenticates via `adapter.authenticate_peer(public_key, nonce, signature, &peer_tenant, store, now_epoch_secs)`.
/// 6. Sends `Success { device_id }` and returns the verified [`TrustedDeviceRecord`].
///
/// On any failure, transmits `Reject { reason }`, closes the session, and fails closed.
///
/// # Errors
///
/// Returns [`TransportSessionError`] if negotiation, authentication, or transport fails.
pub fn host_negotiate_and_authenticate_session<T: Transport>(
    adapter: &mut TransportSessionAdapter<T>,
    store: &TrustedDeviceStore,
    now_epoch_secs: u64,
) -> Result<TrustedDeviceRecord, TransportSessionError> {
    host_negotiate_and_authenticate_session_with_password(adapter, store, "", None, now_epoch_secs)
}

/// Executes the client/peer side authentication handshake over any transport.
///
/// 1. Sends `Hello { device_id, peer_tenant }`.
/// 2. Receives `Challenge { nonce }`.
/// 3. Signs the challenge using `signing_key`.
/// 4. Sends `Proof { public_key, signature }`.
/// 5. Receives `Success { device_id }` from host.
///
/// # Errors
///
/// Returns [`TransportSessionError`] if rejected or transport error occurs.
pub fn peer_negotiate_and_authenticate_session<T: Transport>(
    transport: &mut T,
    signing_key: &ed25519_dalek::SigningKey,
    device_id: &str,
    tenant: &str,
) -> Result<String, TransportSessionError> {
    use ed25519_dalek::Signer;
    let hello = SessionAuthWireMessage::Hello {
        device_id: device_id.to_owned(),
        peer_tenant: tenant.to_owned(),
    };
    transport.send(&hello.to_bytes()?)?;

    let raw_challenge = transport
        .receive()?
        .ok_or_else(|| TransportSessionError::Protocol("no challenge received".to_owned()))?;

    let nonce = match SessionAuthWireMessage::from_bytes(&raw_challenge)? {
        SessionAuthWireMessage::Challenge { nonce } => nonce,
        SessionAuthWireMessage::Reject { reason } => {
            return Err(TransportSessionError::Protocol(format!(
                "host rejected: {reason}"
            )));
        }
        _ => {
            return Err(TransportSessionError::Protocol(
                "expected Challenge".to_owned(),
            ));
        }
    };

    let public_key = signing_key.verifying_key().to_bytes();
    let auth_msg = peer_auth_message(&public_key, &nonce);
    let signature = signing_key.sign(&auth_msg).to_bytes();

    let proof = SessionAuthWireMessage::Proof {
        public_key,
        signature,
    };
    transport.send(&proof.to_bytes()?)?;

    let raw_response = transport
        .receive()?
        .ok_or_else(|| TransportSessionError::Protocol("no auth response received".to_owned()))?;

    match SessionAuthWireMessage::from_bytes(&raw_response)? {
        SessionAuthWireMessage::Success { device_id } => Ok(device_id),
        SessionAuthWireMessage::Reject { reason } => Err(TransportSessionError::Protocol(format!(
            "auth rejected by host: {reason}"
        ))),
        _ => Err(TransportSessionError::Protocol(
            "unexpected response".to_owned(),
        )),
    }
}

/// Executes client/peer password authentication handshake over any transport.
///
/// 1. Sends `Hello { device_id, peer_tenant }`.
/// 2. Receives `Challenge { nonce }`.
/// 3. Computes HMAC-SHA256 password proof with `(password, host_id, client_id, nonce)`.
/// 4. Sends `PasswordProof { host_id, client_id, proof }`.
/// 5. Receives `Success { device_id }` from host.
///
/// # Errors
///
/// Returns [`TransportSessionError`] on rejection or transport error.
pub fn peer_negotiate_and_authenticate_with_password<T: Transport>(
    transport: &mut T,
    client_id: &str,
    host_id: &str,
    password: &str,
    tenant: &str,
) -> Result<String, TransportSessionError> {
    let hello = SessionAuthWireMessage::Hello {
        device_id: client_id.to_owned(),
        peer_tenant: tenant.to_owned(),
    };
    transport.send(&hello.to_bytes()?)?;

    let raw_challenge = transport
        .receive()?
        .ok_or_else(|| TransportSessionError::Protocol("no challenge received".to_owned()))?;

    let nonce = match SessionAuthWireMessage::from_bytes(&raw_challenge)? {
        SessionAuthWireMessage::Challenge { nonce } => nonce,
        SessionAuthWireMessage::Reject { reason } => {
            return Err(TransportSessionError::Protocol(format!(
                "host rejected: {reason}"
            )));
        }
        _ => {
            return Err(TransportSessionError::Protocol(
                "expected Challenge".to_owned(),
            ));
        }
    };

    let proof = crate::password_auth::compute_password_proof(password, host_id, client_id, &nonce);
    let proof_msg = SessionAuthWireMessage::PasswordProof {
        host_id: host_id.to_owned(),
        client_id: client_id.to_owned(),
        proof,
    };
    transport.send(&proof_msg.to_bytes()?)?;

    let raw_response = transport.receive()?.ok_or_else(|| {
        TransportSessionError::Protocol("no response received after proof".to_owned())
    })?;

    match SessionAuthWireMessage::from_bytes(&raw_response)? {
        SessionAuthWireMessage::Success { device_id } => Ok(device_id),
        SessionAuthWireMessage::Reject { reason } => Err(TransportSessionError::Protocol(format!(
            "password authentication rejected: {reason}"
        ))),
        _ => Err(TransportSessionError::Protocol(
            "unexpected auth wire response".to_owned(),
        )),
    }
}
