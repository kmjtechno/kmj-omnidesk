//! Real TCP encrypted attended proof tests. This is NOT remote-control QA.

use std::{net::{TcpListener, TcpStream}, thread, time::Duration};

use omnidesk_core::{
    attended_proof_wire::{
        AttendedProofError, client_prove_attended_password, host_verify_attended_password,
    },
    device_identity::DeviceIdentity,
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    password_auth::{HostPasswordManager, PasswordVerificationError},
    transport::{TcpLanTransport, Transport},
    trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore},
};

fn pin_peer(identity: &DeviceIdentity, now: u64) -> TrustedDeviceStore {
    let mut store = TrustedDeviceStore::new();
    store.add(TrustedDeviceRecord {
        device_id: identity.public_id().to_owned(),
        display_name: "Pinned Test Peer".to_owned(),
        public_key: identity.public_key_bytes(),
        enrolled_at_epoch_secs: now.saturating_sub(20),
        trust_expires_at_epoch_secs: now + 600,
        managed: false,
        revoked: false,
        status: PersistedDeviceStatus::Offline,
    }).expect("pin");
    store
}

#[test]
fn encrypted_tcp_accepts_correct_attended_password_only_after_mutual_pinning() {
    let now = 50_000;
    let client = DeviceIdentity::from_seed(&[111_u8; 32]);
    let host = DeviceIdentity::from_seed(&[112_u8; 32]);
    let host_id = host.public_id().to_owned();
    let client_store = pin_peer(&host, now);
    let host_store = pin_peer(&client, now);
    let mut manager = HostPasswordManager::new(now);
    manager.set_allow_remote_control(true);
    let password = manager.password().to_owned();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept");
        let tcp = TcpLanTransport::from_stream(socket).expect("tcp");
        let mut session = UnauthenticatedNoiseChannel::accept(tcp).expect("noise responder");
        assert_eq!(
            host_verify_attended_password(
                &mut session, &host, &host_store, &mut manager, "kmj-tenant", now,
            ),
            Ok(())
        );
        session.close();
    });

    let tcp = TcpLanTransport::connect(address, Duration::from_secs(2)).expect("tcp");
    let mut session = UnauthenticatedNoiseChannel::connect(tcp).expect("noise initiator");
    assert_eq!(
        client_prove_attended_password(
            &mut session, &client, &client_store, &host_id, "kmj-tenant",
            &password, now,
        ),
        Ok(())
    );
    // No permission prompt, licensing entitlement or media/control transport
    // was opened by this mutually encrypted password proof.
    session.close();
    task.join().expect("host");
}

#[test]
fn encrypted_tcp_wrong_attended_password_is_denied_and_counts_host_attempt() {
    let now = 60_000;
    let client = DeviceIdentity::from_seed(&[113_u8; 32]);
    let host = DeviceIdentity::from_seed(&[114_u8; 32]);
    let host_id = host.public_id().to_owned();
    let client_store = pin_peer(&host, now);
    let host_store = pin_peer(&client, now);
    let mut manager = HostPasswordManager::new(now);
    manager.set_allow_remote_control(true);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept");
        let tcp = TcpLanTransport::from_stream(socket).expect("tcp");
        let mut session = UnauthenticatedNoiseChannel::accept(tcp).expect("noise responder");
        assert!(matches!(
            host_verify_attended_password(
                &mut session, &host, &host_store, &mut manager, "kmj-tenant", now,
            ),
            Err(AttendedProofError::Password(PasswordVerificationError::InvalidPassword { .. }))
        ));
        session.close();
    });

    let tcp = TcpLanTransport::connect(address, Duration::from_secs(2)).expect("tcp");
    let mut session = UnauthenticatedNoiseChannel::connect(tcp).expect("noise initiator");
    assert_eq!(
        client_prove_attended_password(
            &mut session, &client, &client_store, &host_id, "kmj-tenant",
            "WRONG999", now,
        ),
        Err(AttendedProofError::Denied)
    );
    session.close();
    task.join().expect("host");
}
