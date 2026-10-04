//! Fail-closed remote-input protocol and dispatch boundary.

use crate::session::{Session, SessionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPayload {
    KeyDown { key_code: u16 },
    KeyUp { key_code: u16 },
    PointerMove { x: i32, y: i32 },
    PointerButton { button: u8, pressed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub session_nonce: [u8; 32],
    pub sequence: u64,
    pub payload: InputPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Session(SessionError),
    StaleSession,
    StaleSequence,
    InvalidKeyCode,
    InvalidPointerButton,
    AdapterFailure,
}

impl From<SessionError> for InputError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

pub trait InputAdapter {
    /// Applies one validated input event to the local OS adapter.
    ///
    /// # Errors
    ///
    /// Returns `InputError::AdapterFailure` when the platform adapter rejects
    /// or cannot apply the event.
    fn apply(&mut self, event: InputEvent) -> Result<(), InputError>;
}

#[derive(Debug)]
pub struct AuthorizedInputDispatcher<A> {
    adapter: A,
    last_sequence: u64,
}

impl<A: InputAdapter> AuthorizedInputDispatcher<A> {
    #[must_use]
    pub const fn new(adapter: A) -> Self {
        Self {
            adapter,
            last_sequence: 0,
        }
    }

    /// Dispatches input only when session control is currently authorized.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for inactive/unauthorized sessions, stale session bindings,
    /// stale sequence numbers, malformed key/button values, or adapter failure.
    pub fn dispatch(&mut self, session: &Session, event: InputEvent) -> Result<(), InputError> {
        session.require_control()?;

        if session.authentication_nonce() != Some(&event.session_nonce) {
            return Err(InputError::StaleSession);
        }
        if event.sequence <= self.last_sequence {
            return Err(InputError::StaleSequence);
        }
        validate(event)?;
        self.adapter.apply(event)?;
        self.last_sequence = event.sequence;
        Ok(())
    }

    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub const fn adapter(&self) -> &A {
        &self.adapter
    }
}

const fn validate(event: InputEvent) -> Result<(), InputError> {
    match event.payload {
        InputPayload::KeyDown { key_code } | InputPayload::KeyUp { key_code } if key_code == 0 => {
            Err(InputError::InvalidKeyCode)
        }
        InputPayload::PointerButton { button: 0, .. } => Err(InputError::InvalidPointerButton),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use crate::{
        PROTOCOL_VERSION,
        authentication::{peer_auth_message, verify_peer_authentication},
        session::PeerIdentity,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingAdapter {
        events: Vec<InputEvent>,
    }

    impl InputAdapter for RecordingAdapter {
        fn apply(&mut self, event: InputEvent) -> Result<(), InputError> {
            self.events.push(event);
            Ok(())
        }
    }

    fn active_session() -> Session {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let nonce = [9_u8; 32];
        let signature = signing_key
            .sign(&peer_auth_message(&public_key, &nonce))
            .to_bytes();
        let proof = verify_peer_authentication(public_key, nonce, signature).expect("peer proof");

        let mut session = Session::default();
        session
            .begin(
                PeerIdentity::new("device:input-peer").expect("peer"),
                PROTOCOL_VERSION,
            )
            .expect("begin");
        session
            .authentication_succeeded(&proof)
            .expect("authenticate");
        session.authorize_control().expect("authorize");
        session
    }

    #[test]
    fn unauthenticated_or_unauthorized_input_is_rejected() {
        let session = Session::default();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());

        let result = dispatcher.dispatch(
            &session,
            InputEvent {
                session_nonce: [9_u8; 32],
                sequence: 1,
                payload: InputPayload::PointerMove { x: 10, y: 20 },
            },
        );

        assert_eq!(
            result,
            Err(InputError::Session(SessionError::ControlNotAuthorized))
        );
        assert_eq!(dispatcher.adapter().events.len(), 0);
    }

    #[test]
    fn authorized_input_round_trip_is_recorded() {
        let session = active_session();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());
        let event = InputEvent {
            session_nonce: [9_u8; 32],
            sequence: 1,
            payload: InputPayload::PointerMove { x: 10, y: 20 },
        };

        dispatcher.dispatch(&session, event).expect("dispatch");

        assert_eq!(dispatcher.adapter().events, vec![event]);
        assert_eq!(dispatcher.last_sequence(), 1);
    }

    #[test]
    fn stale_session_input_is_rejected() {
        let session = active_session();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());
        let event = InputEvent {
            session_nonce: [8_u8; 32],
            sequence: 1,
            payload: InputPayload::PointerMove { x: 10, y: 20 },
        };

        assert_eq!(
            dispatcher.dispatch(&session, event),
            Err(InputError::StaleSession)
        );
        assert_eq!(dispatcher.adapter().events.len(), 0);
    }

    #[test]
    fn stale_sequence_is_rejected() {
        let session = active_session();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());
        let event = InputEvent {
            session_nonce: [9_u8; 32],
            sequence: 2,
            payload: InputPayload::KeyDown { key_code: 65 },
        };

        dispatcher
            .dispatch(&session, event)
            .expect("first dispatch");
        assert_eq!(
            dispatcher.dispatch(&session, event),
            Err(InputError::StaleSequence)
        );
    }

    #[test]
    fn malformed_input_is_rejected() {
        let session = active_session();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());

        assert_eq!(
            dispatcher.dispatch(
                &session,
                InputEvent {
                    session_nonce: [9_u8; 32],
                    sequence: 1,
                    payload: InputPayload::KeyDown { key_code: 0 },
                },
            ),
            Err(InputError::InvalidKeyCode)
        );
    }

    #[test]
    fn emergency_revoke_stops_future_input() {
        let mut session = active_session();
        let mut dispatcher = AuthorizedInputDispatcher::new(RecordingAdapter::default());

        session.revoke_control().expect("revoke");
        assert_eq!(
            dispatcher.dispatch(
                &session,
                InputEvent {
                    session_nonce: [9_u8; 32],
                    sequence: 1,
                    payload: InputPayload::PointerMove { x: 1, y: 1 },
                },
            ),
            Err(InputError::Session(SessionError::ControlNotAuthorized))
        );
    }
}
