//! Cryptographically authenticated transport session adapter.
//!
//! Enforces:
//! - Strict Ed25519 challenge-response peer authentication
//! - Trusted device store verification (revocation check and expiration check)
//! - Cross-tenant isolation (strict fail-closed boundary enforcement)
//! - Fail-closed payload gating: all frames, control, and keystrokes/clicks
//!   are rejected unless the session is fully authenticated and authorized.

use std::fmt;

use crate::{
    PROTOCOL_VERSION,
    authentication::{AuthenticationError, verify_peer_authentication},
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
