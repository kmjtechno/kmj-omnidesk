use std::{net::TcpListener, thread, time::Duration};

use ed25519_dalek::{Signer, SigningKey};
use omnidesk_core::{
    PROTOCOL_VERSION,
    authentication::{peer_auth_message, verify_peer_authentication},
    session::{PeerIdentity, Session, SessionState},
    transport::{TcpLanTransport, Transport},
};

#[test]
fn authenticated_lan_session_requires_peer_proof_then_explicit_control_authorization() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind LAN listener");
    let address = listener.local_addr().expect("LAN listener address");

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept LAN client");
        let mut transport = TcpLanTransport::from_stream(stream).expect("server LAN transport");

        assert_eq!(
            transport.receive().expect("receive authenticated payload"),
            Some(b"authorized-control-probe".to_vec())
        );
        transport.send(b"ack").expect("send LAN acknowledgement");
    });

    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let nonce = [9_u8; 32];
    let signature = signing_key
        .sign(&peer_auth_message(&public_key, &nonce))
        .to_bytes();
    let proof =
        verify_peer_authentication(public_key, nonce, signature).expect("verify peer proof");

    let mut session = Session::default();
    session
        .begin(
            PeerIdentity::new("device:lan-peer").expect("peer identity"),
            PROTOCOL_VERSION,
        )
        .expect("begin session");
    session
        .authentication_succeeded(&proof)
        .expect("bind peer authentication");

    assert_eq!(session.state(), SessionState::AwaitingAuthorization);
    assert!(session.require_control().is_err());

    session.authorize_control().expect("authorize control");
    session.require_control().expect("control is authorized");

    let mut transport =
        TcpLanTransport::connect(address, Duration::from_secs(2)).expect("connect LAN transport");
    transport
        .send(b"authorized-control-probe")
        .expect("send authenticated payload");
    assert_eq!(
        transport.receive().expect("receive acknowledgement"),
        Some(b"ack".to_vec())
    );

    session.disconnect();
    assert!(session.require_control().is_err());
    server.join().expect("LAN server");
}
