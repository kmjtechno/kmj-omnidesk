use crate::{PROTOCOL_VERSION, authentication::PeerAuthenticationProof};

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
    PeerIdentityTooLong {
        length: usize,
        maximum: usize,
    },
    PeerIdentityNotAscii,
    PeerIdentityHasControlCharacter,
    ControlNotAuthorized,
    UntrustedPublicKey,
    PeerRevoked,
    TrustExpired,
    CrossTenantMismatch {
        expected: String,
        received: String,
    },
    Closed,
}

/// Upper bound on a peer identity's length.
///
/// A peer identity reaches the UI, the clipboard-adjacent surfaces, and
/// eventually a log record. An unbounded string from a remote party is a
/// cheap way to make all three expensive, so it is bounded at the point it
/// enters the process rather than at each consumer.
pub const MAX_PEER_IDENTITY_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity(String);

impl PeerIdentity {
    /// Creates a peer identity from a bounded, printable ASCII string.
    ///
    /// The contents are deliberately *not* required to look like any
    /// particular identifier format. Constraining the shape here would reject
    /// legitimate peers for a reason this repository cannot verify, and the
    /// identity is authenticated by key, not by how its label reads.
    ///
    /// What is enforced is only what has to hold for the value to be safe to
    /// carry: it is short, and it is printable ASCII. Rejecting non-ASCII
    /// means a value can never contain a bidi override, which would let a
    /// peer render a label that reads differently from its actual bytes.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::EmptyPeerIdentity` when blank,
    /// `PeerIdentityTooLong` above [`MAX_PEER_IDENTITY_BYTES`],
    /// `PeerIdentityNotAscii` for any non-ASCII byte, and
    /// `PeerIdentityHasControlCharacter` for any control character including
    /// newline and tab.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(SessionError::EmptyPeerIdentity);
        }
        if value.len() > MAX_PEER_IDENTITY_BYTES {
            return Err(SessionError::PeerIdentityTooLong {
                length: value.len(),
                maximum: MAX_PEER_IDENTITY_BYTES,
            });
        }
        if !value.is_ascii() {
            return Err(SessionError::PeerIdentityNotAscii);
        }
        if value.chars().any(char::is_control) {
            return Err(SessionError::PeerIdentityHasControlCharacter);
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The identity's byte length.
    ///
    /// Supports diagnosis without exposing the identity, which is what
    /// `log_scrubber::PeerSummary` records.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug)]
pub struct Session {
    state: SessionState,
    peer: Option<PeerIdentity>,
    control_authorized: bool,
    authenticated_public_key: Option<[u8; 32]>,
    authentication_nonce: Option<[u8; 32]>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            state: SessionState::Disconnected,
            peer: None,
            control_authorized: false,
            authenticated_public_key: None,
            authentication_nonce: None,
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

    /// Returns the public key proven during peer authentication.
    #[must_use]
    pub const fn authenticated_public_key(&self) -> Option<&[u8; 32]> {
        self.authenticated_public_key.as_ref()
    }

    /// Returns the fresh authentication challenge bound to this session.
    #[must_use]
    pub const fn authentication_nonce(&self) -> Option<&[u8; 32]> {
        self.authentication_nonce.as_ref()
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

    /// Records a cryptographically verified peer-authentication proof.
    ///
    /// # Errors
    ///
    /// Returns an error unless the session is currently negotiating.
    pub fn authentication_succeeded(
        &mut self,
        proof: &PeerAuthenticationProof,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Negotiating, "authentication_succeeded")?;
        self.authenticated_public_key = Some(*proof.public_key());
        self.authentication_nonce = Some(*proof.nonce());
        self.state = SessionState::AwaitingAuthorization;
        Ok(())
    }

    /// Verifies peer authentication proof against a trusted device store.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not enrolled, if the trust record
    /// is marked revoked, if trust has expired, or if the session is not negotiating.
    pub fn authenticate_with_trusted_store(
        &mut self,
        proof: &PeerAuthenticationProof,
        store: &crate::trusted_device_store::TrustedDeviceStore,
        current_epoch_secs: u64,
    ) -> Result<(), SessionError> {
        self.require_state(SessionState::Negotiating, "authenticate_with_trusted_store")?;

        let record = store
            .find_by_public_key(proof.public_key())
            .ok_or(SessionError::UntrustedPublicKey)?;

        if record.revoked {
            return Err(SessionError::PeerRevoked);
        }

        if current_epoch_secs > record.trust_expires_at_epoch_secs {
            return Err(SessionError::TrustExpired);
        }

        self.authenticated_public_key = Some(*proof.public_key());
        self.authentication_nonce = Some(*proof.nonce());
        self.state = SessionState::AwaitingAuthorization;
        Ok(())
    }

    /// Verifies that both peers belong to the exact same organization tenant.
    ///
    /// Cross-tenant connections are strictly rejected fail-closed; no media
    /// or control transport is ever permitted across tenant boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::CrossTenantMismatch`] if `expected_tenant` != `peer_tenant`.
    pub fn enforce_tenant_boundary(
        &self,
        expected_tenant: &str,
        peer_tenant: &str,
    ) -> Result<(), SessionError> {
        if expected_tenant != peer_tenant {
            return Err(SessionError::CrossTenantMismatch {
                expected: expected_tenant.to_owned(),
                received: peer_tenant.to_owned(),
            });
        }
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
        self.authenticated_public_key = None;
        self.authentication_nonce = None;
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
    use ed25519_dalek::{Signer, SigningKey};

    use crate::authentication::{peer_auth_message, verify_peer_authentication};

    use super::*;

    fn peer() -> PeerIdentity {
        PeerIdentity::new("device:test-peer").expect("valid peer")
    }

    fn proof() -> PeerAuthenticationProof {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let nonce = [9_u8; 32];
        let signature = signing_key
            .sign(&peer_auth_message(&public_key, &nonce))
            .to_bytes();

        verify_peer_authentication(public_key, nonce, signature).expect("valid proof")
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

        session
            .authentication_succeeded(&proof())
            .expect("authenticate");
        assert_eq!(session.state(), SessionState::AwaitingAuthorization);
        assert!(session.authenticated_public_key().is_some());
        assert_eq!(session.authentication_nonce(), Some(&[9_u8; 32]));
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
        session
            .authentication_succeeded(&proof())
            .expect("authenticate");
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
        assert!(session.authenticated_public_key().is_none());
        assert!(session.authentication_nonce().is_none());
        assert_eq!(session.require_control(), Err(SessionError::Closed));
    }

    #[test]
    fn empty_peer_identity_is_rejected() {
        assert_eq!(
            PeerIdentity::new("   "),
            Err(SessionError::EmptyPeerIdentity)
        );
    }

    #[test]
    fn an_identity_at_the_length_limit_is_accepted() {
        let at_limit = "a".repeat(MAX_PEER_IDENTITY_BYTES);
        assert!(PeerIdentity::new(&at_limit).is_ok());

        let over_limit = "a".repeat(MAX_PEER_IDENTITY_BYTES + 1);
        assert_eq!(
            PeerIdentity::new(over_limit),
            Err(SessionError::PeerIdentityTooLong {
                length: MAX_PEER_IDENTITY_BYTES + 1,
                maximum: MAX_PEER_IDENTITY_BYTES,
            })
        );
    }

    #[test]
    fn non_ascii_identities_are_rejected() {
        // A bidi override is the reason: a peer must not be able to render a
        // label that reads differently from the bytes that were authenticated.
        assert_eq!(
            PeerIdentity::new("device\u{202E}moc"),
            Err(SessionError::PeerIdentityNotAscii)
        );
        assert_eq!(
            PeerIdentity::new("caf\u{00E9}"),
            Err(SessionError::PeerIdentityNotAscii)
        );
    }

    #[test]
    fn control_characters_are_rejected_including_newline_and_tab() {
        for bad in ["a\nb", "a\tb", "a\rb", "a\u{0}b", "a\u{7F}b"] {
            assert_eq!(
                PeerIdentity::new(bad),
                Err(SessionError::PeerIdentityHasControlCharacter),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_newline_in_an_identity_cannot_forge_a_second_log_line() {
        // The concrete attack the control-character rule prevents: an
        // identity rendered into a log line that then splits into two.
        let forged = "device\nadmin=true";
        assert_eq!(
            PeerIdentity::new(forged),
            Err(SessionError::PeerIdentityHasControlCharacter)
        );
    }

    #[test]
    fn printable_punctuation_and_spaces_are_accepted() {
        for good in [
            "device-abc123",
            "device_abc.123",
            "DESKTOP-ABC",
            "a name with spaces",
            "dev!ce#1",
            "~!@#$%^&*()",
        ] {
            assert!(
                PeerIdentity::new(good).is_ok(),
                "{good:?} should be accepted"
            );
        }
    }

    #[test]
    fn an_identity_never_carries_a_bidi_override() {
        // Property rather than a fixed list, so a future encoding change
        // cannot reintroduce a direction override through another route.
        for candidate in ["a\u{202B}b", "a\u{202C}b", "a\u{2066}b", "a\u{2069}b"] {
            let result = PeerIdentity::new(candidate);
            assert!(
                result.is_err(),
                "{candidate:?} must not be accepted as an identity"
            );
        }
    }

    #[test]
    fn the_byte_length_is_reported_without_exposing_the_identity() {
        let identity = PeerIdentity::new("device-abc123").expect("identity");
        assert_eq!(identity.byte_len(), "device-abc123".len());
    }

    #[test]
    fn an_over_long_identity_is_rejected_before_it_is_stored() {
        // The bound has to apply at construction. A limit enforced only when
        // rendering leaves the oversized value resident in the process.
        let huge = "x".repeat(100_000);
        assert!(PeerIdentity::new(huge).is_err());
    }

    #[test]
    fn authenticate_with_trusted_store_enforces_enrollment_revocation_and_expiry() {
        use crate::{
            authentication::verify_peer_authentication,
            trusted_device_store::{
                PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore,
            },
        };
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[0x42_u8; 32]);
        let pk = signing_key.verifying_key().to_bytes();
        let nonce = [0x99_u8; 32];
        let msg = crate::authentication::peer_auth_message(&pk, &nonce);
        let sig = signing_key.sign(&msg).to_bytes();
        let proof = verify_peer_authentication(pk, nonce, sig).unwrap();

        let mut store = TrustedDeviceStore::new();
        store
            .add(TrustedDeviceRecord {
                device_id: "desk-trusted".to_owned(),
                display_name: "Desk Trusted".to_owned(),
                public_key: pk,
                enrolled_at_epoch_secs: 1000,
                trust_expires_at_epoch_secs: 2000,
                managed: true,
                revoked: false,
                status: PersistedDeviceStatus::Online,
            })
            .unwrap();

        let mut session = Session::default();
        session
            .begin(PeerIdentity::new("desk-trusted").unwrap(), PROTOCOL_VERSION)
            .unwrap();

        // 1. Success on valid proof and valid record
        session
            .authenticate_with_trusted_store(&proof, &store, 1500)
            .unwrap();
        assert_eq!(session.state(), SessionState::AwaitingAuthorization);

        // 2. Reject if public key is not enrolled
        let other_key = SigningKey::from_bytes(&[0x77_u8; 32]);
        let other_pk = other_key.verifying_key().to_bytes();
        let other_sig = other_key
            .sign(&crate::authentication::peer_auth_message(&other_pk, &nonce))
            .to_bytes();
        let other_proof = verify_peer_authentication(other_pk, nonce, other_sig).unwrap();

        let mut session2 = Session::default();
        session2
            .begin(PeerIdentity::new("unknown").unwrap(), PROTOCOL_VERSION)
            .unwrap();
        assert_eq!(
            session2.authenticate_with_trusted_store(&other_proof, &store, 1500),
            Err(SessionError::UntrustedPublicKey)
        );

        // 3. Reject if revoked
        store.revoke("desk-trusted");
        let mut session3 = Session::default();
        session3
            .begin(PeerIdentity::new("desk-trusted").unwrap(), PROTOCOL_VERSION)
            .unwrap();
        assert_eq!(
            session3.authenticate_with_trusted_store(&proof, &store, 1500),
            Err(SessionError::PeerRevoked)
        );
    }

    #[test]
    fn cross_tenant_boundaries_are_strictly_rejected() {
        let session = Session::default();
        assert_eq!(
            session.enforce_tenant_boundary("tenant-alpha", "tenant-alpha"),
            Ok(())
        );
        assert_eq!(
            session.enforce_tenant_boundary("tenant-alpha", "tenant-bravo"),
            Err(SessionError::CrossTenantMismatch {
                expected: "tenant-alpha".to_owned(),
                received: "tenant-bravo".to_owned(),
            })
        );
    }
}
