//! Encrypted loopback-LAN + mutually pinned identity channel binding.
//! Even a successful signed and encrypted handshake does not enable control.

use std::{
    net::{TcpListener, TcpStream},
    thread,
};

use omnidesk_core::{
    device_identity::DeviceIdentity,
    mutual_identity::{
        MutualIdentityError, client_mutual_identity_handshake, host_mutual_identity_handshake,
    },
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    transport::{HostTransport, Transport},
    trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore},
};

fn store_one(identity: &DeviceIdentity, now: u64, revoked: bool) -> TrustedDeviceStore {
    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: identity.public_id().to_owned(),
            display_name: "Verified Test Peer".to_owned(),
            public_key: identity.public_key_bytes(),
            enrolled_at_epoch_secs: now - 20,
            trust_expires_at_epoch_secs: now + 600,
            managed: false,
            revoked,
            status: PersistedDeviceStatus::Offline,
        })
        .expect("test trusted identity");
    store
}

#[test]
fn tcp_mutual_identity_verifies_both_pinned_keys_without_authorizing_control() {
    let now = 10_000;
    let client = DeviceIdentity::from_seed(&[81; 32]);
    let host = DeviceIdentity::from_seed(&[82; 32]);
    let expected_host_id = host.public_id().to_owned();
    let expected_client_id = client.public_id().to_owned();
    let host_store = store_one(&client, now, false);
    let client_store = store_one(&host, now, false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let tcp = HostTransport::from_tcp_stream(stream).expect("transport");
        let mut transport = UnauthenticatedNoiseChannel::accept(tcp).expect("Noise handshake");
        let receipt =
            host_mutual_identity_handshake(&mut transport, &host, &host_store, "kmj-tenant", now)
                .expect("signed host and trusted client");
        assert_eq!(receipt.peer_id, expected_client_id);
        transport.close();
    });
    let stream = TcpStream::connect(addr).expect("connect");
    let tcp = HostTransport::from_tcp_stream(stream).expect("transport");
    let mut transport = UnauthenticatedNoiseChannel::connect(tcp).expect("Noise handshake");
    let receipt = client_mutual_identity_handshake(
        &mut transport,
        &client,
        &client_store,
        &expected_host_id,
        "kmj-tenant",
        now,
    )
    .expect("verified host");
    assert_eq!(receipt.peer_id, expected_host_id);
    // Pinned identity and confidentiality are NOT attended password proof,
    // visible host consent, or remote input authorization.
    transport.close();
    handle.join().expect("host");
}

#[test]
fn tcp_mutual_identity_rejects_impostor_host_key_before_client_proof() {
    let now = 11_000;
    let client = DeviceIdentity::from_seed(&[83; 32]);
    let legitimate_host = DeviceIdentity::from_seed(&[84; 32]);
    let impostor = DeviceIdentity::from_seed(&[85; 32]);
    let expected_host_id = legitimate_host.public_id().to_owned();
    let host_store = store_one(&client, now, false);
    let client_store = store_one(&legitimate_host, now, false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let tcp = HostTransport::from_tcp_stream(stream).expect("transport");
        let mut transport = UnauthenticatedNoiseChannel::accept(tcp).expect("Noise handshake");
        let result = host_mutual_identity_handshake(
            &mut transport,
            &impostor,
            &host_store,
            "kmj-tenant",
            now,
        );
        assert!(result.is_err(), "client must refuse impostor");
        transport.close();
    });
    let tcp = HostTransport::from_tcp_stream(TcpStream::connect(addr).expect("connect"))
        .expect("transport");
    let mut transport = UnauthenticatedNoiseChannel::connect(tcp).expect("Noise handshake");
    assert_eq!(
        client_mutual_identity_handshake(
            &mut transport,
            &client,
            &client_store,
            &expected_host_id,
            "kmj-tenant",
            now
        ),
        Err(MutualIdentityError::IdentityMismatch)
    );
    transport.close();
    handle.join().expect("host");
}

#[test]
fn tcp_mutual_identity_rejects_revoked_client_before_host_challenge() {
    let now = 12_000;
    let client = DeviceIdentity::from_seed(&[86; 32]);
    let host = DeviceIdentity::from_seed(&[87; 32]);
    let expected_host_id = host.public_id().to_owned();
    let host_store = store_one(&client, now, true);
    let client_store = store_one(&host, now, false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let tcp = HostTransport::from_tcp_stream(stream).expect("transport");
        let mut transport = UnauthenticatedNoiseChannel::accept(tcp).expect("Noise handshake");
        assert_eq!(
            host_mutual_identity_handshake(&mut transport, &host, &host_store, "kmj-tenant", now),
            Err(MutualIdentityError::Revoked)
        );
        transport.close();
    });
    let tcp = HostTransport::from_tcp_stream(TcpStream::connect(addr).expect("connect"))
        .expect("transport");
    let mut transport = UnauthenticatedNoiseChannel::connect(tcp).expect("Noise handshake");
    let result = client_mutual_identity_handshake(
        &mut transport,
        &client,
        &client_store,
        &expected_host_id,
        "kmj-tenant",
        now,
    );
    assert!(result.is_err());
    transport.close();
    handle.join().expect("host");
}
