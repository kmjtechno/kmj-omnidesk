use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Disconnected,
    Negotiating,
    AwaitingAuthorization,
    Active,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    InvalidTransition {
        from: SessionState,
        operation: &'static str,
    },
    ProtocolVersionMismatch {
        expected: u16,
        received: u16,
    },
    EmptyPeerIdentity,
    ControlNotAuthorized,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity(String);

impl PeerIdentity {
    /// Creates a non-empty peer identity.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::EmptyPeerIdentity` when the supplied identity is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SessionError::EmptyPeerIdentity);
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct Session {
    state: SessionState,
    peer: Option<PeerIdentity>,
    control_authorized: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            state: SessionState::Disconnected,
            peer: None,
            control_authorized: false,
        }
    }
}

impl Session {
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub const fn peer(&self) -> Option<&PeerIdentity> {
        self.peer.as_ref()
    }

    #[must_use]
    pub const fn control_authorized(&self) -> bool {
        self.control_authorized
    }

    /// Begins protocol negotiation with a peer.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state or protocol-version mismatch.
    pub fn begin(
        &mut self,
        peer: PeerIdentity,
        remote_protocol_version: u16,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Disconnected, "begin")?;

        if remote_protocol_version != PROTOCOL_VERSION {
            return Err(SessionError::ProtocolVersionMismatch {
                expected: PROTOCOL_VERSION,
                received: remote_protocol_version,
            });
        }

        self.peer = Some(peer);
        self.state = SessionState::Negotiating;
        Ok(())
    }

    /// Records successful peer authentication.
    ///
    /// # Errors
    ///
    /// Returns an error unless the session is currently negotiating.
    pub fn authentication_succeeded(&mut self) -> Result<(), SessionError> {
        self.require_state(SessionState::Negotiating, "authentication_succeeded")?;
        self.state = SessionState::AwaitingAuthorization;
        Ok(())
    }

    /// Grants remote-control permission after authentication.
    ///
    /// # Errors
    ///
    /// Returns an error unless the session is awaiting explicit authorization.
    pub fn authorize_control(&mut self) -> Result<(), SessionError> {
        self.require_state(SessionState::AwaitingAuthorization, "authorize_control")?;
        self.control_authorized = true;
        self.state = SessionState::Active;
        Ok(())
    }

    /// Revokes remote-control permission.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::Closed` when the session is already closed.
    pub fn revoke_control(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }

        self.control_authorized = false;
        Ok(())
    }

    /// Verifies that remote control is currently authorized.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the session is closed, inactive, or control
    /// permission has not been explicitly granted.
    pub fn require_control(&self) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }

        if self.state != SessionState::Active || !self.control_authorized {
            return Err(SessionError::ControlNotAuthorized);
        }

        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.control_authorized = false;
        self.peer = None;
        self.state = SessionState::Closed;
    }

    fn require_state(
        &self,
        required: SessionState,
        operation: &'static str,
    ) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }

        if self.state != required {
            return Err(SessionError::InvalidTransition {
                from: self.state,
                operation,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerIdentity {
        PeerIdentity::new("device:test-peer").expect("valid peer")
    }

    #[test]
    fn happy_path_requires_authentication_then_authorization() {
        let mut session = Session::default();

        session.begin(peer(), PROTOCOL_VERSION).expect("begin");
        assert_eq!(session.state(), SessionState::Negotiating);
        assert_eq!(
            session.require_control(),
            Err(SessionError::ControlNotAuthorized)
        );

        session.authentication_succeeded().expect("authenticate");
        assert_eq!(session.state(), SessionState::AwaitingAuthorization);
        assert_eq!(
            session.require_control(),
            Err(SessionError::ControlNotAuthorized)
        );

        session.authorize_control().expect("authorize");
        assert_eq!(session.state(), SessionState::Active);
        assert!(session.require_control().is_ok());
    }

    #[test]
    fn protocol_mismatch_fails_closed() {
        let mut session = Session::default();
        let result = session.begin(peer(), PROTOCOL_VERSION.saturating_add(1));

        assert_eq!(
            result,
            Err(SessionError::ProtocolVersionMismatch {
                expected: PROTOCOL_VERSION,
                received: PROTOCOL_VERSION.saturating_add(1),
            })
        );
        assert_eq!(session.state(), SessionState::Disconnected);
        assert!(!session.control_authorized());
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let mut session = Session::default();

        assert_eq!(
            session.authorize_control(),
            Err(SessionError::InvalidTransition {
                from: SessionState::Disconnected,
                operation: "authorize_control",
            })
        );
    }

    #[test]
    fn revoke_and_disconnect_remove_control_permission() {
        let mut session = Session::default();
        session.begin(peer(), PROTOCOL_VERSION).expect("begin");
        session.authentication_succeeded().expect("authenticate");
        session.authorize_control().expect("authorize");

        session.revoke_control().expect("revoke");
        assert_eq!(
            session.require_control(),
            Err(SessionError::ControlNotAuthorized)
        );

        session.disconnect();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(!session.control_authorized());
        assert!(session.peer().is_none());
        assert_eq!(session.require_control(), Err(SessionError::Closed));
    }

    #[test]
    fn empty_peer_identity_is_rejected() {
        assert_eq!(
            PeerIdentity::new("   "),
            Err(SessionError::EmptyPeerIdentity)
        );
    }
}
