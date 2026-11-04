use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use omnidesk_core::{
    PROTOCOL_VERSION,
    authentication::{peer_auth_message, verify_peer_authentication},
    device_enrollment::{
        ChallengeTracker, DEFAULT_CHALLENGE_LIFETIME_SECS, EnrollmentChallenge,
        EnrollmentCoordinator, EnrollmentError, EnrollmentRequest, EnrollmentStage, PairingMessage,
        build_enrollment_message, host_process_pairing_exchange, peer_execute_pairing_handshake,
        verify_and_consume_enrollment, verify_enrollment,
    },
    product_shell::{ConnectError, DeviceStatus, DeviceSummary, ProductShell, SecurityState},
    session::{PeerIdentity, Session, SessionError, SessionState},
    transport::{HostTransport, LoopbackTransport, TcpLanTransport, Transport},
    transport_adapter::{TransportSessionAdapter, TransportSessionError},
    trusted_device_store::{
        DeviceStoreError, PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore,
    },
};

fn temp_store_path(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("omnidesk-test-store-{tag}-{epoch}.json"));
    path
}

#[test]
fn full_enrollment_and_trusted_session_lifecycle_with_disk_persistence() {
    let path = temp_store_path("full-lifecycle");
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Device keypair generation
    let device_signing_key = SigningKey::from_bytes(&[0x11_u8; 32]);
    let device_verifying_key = device_signing_key.verifying_key().to_bytes();

    // 2. Cryptographic enrollment challenge-response
    let challenge_nonce = [0x44_u8; 32];
    let challenge =
        EnrollmentChallenge::new(challenge_nonce, now, now + DEFAULT_CHALLENGE_LIFETIME_SECS);
    assert_ne!(challenge.nonce, [0_u8; 32]);
    assert!(challenge.is_valid_at(now));

    // Sign enrollment challenge
    let msg = build_enrollment_message(
        "P520 Workstation",
        &device_verifying_key,
        &challenge_nonce,
        now,
    );
    let signature = device_signing_key.sign(&msg).to_bytes();

    let request = EnrollmentRequest {
        device_id: "P520 Workstation".to_owned(),
        display_name: "P520 Workstation".to_owned(),
        public_key: device_verifying_key,
        nonce: challenge_nonce,
        timestamp_epoch_secs: now,
        signature,
    };

    // Verify enrollment
    let record = verify_enrollment(&challenge, &request, now + 5).expect("verify enrollment");
    assert_eq!(record.device_id, "P520 Workstation");
    assert_eq!(record.public_key, device_verifying_key);
    assert!(!record.revoked);
    assert_eq!(record.status, PersistedDeviceStatus::Offline);

    // 3. Persist to disk using atomic rename
    let mut store = TrustedDeviceStore::new();
    store.add(record).expect("add record to store");
    store.save_to_path(&path).expect("save store to disk");
    assert!(path.exists());

    // 4. Reload from disk
    let loaded_store = TrustedDeviceStore::load_from_path(&path).expect("reload store from disk");
    assert_eq!(loaded_store.len(), 1);
    let loaded_rec = loaded_store.get("P520 Workstation").expect("get record");
    assert_eq!(loaded_rec.public_key, device_verifying_key);
    assert_eq!(loaded_rec.status, PersistedDeviceStatus::Offline);

    // 5. ProductShell trusted connection attempt
    let mut shell = ProductShell::new();
    shell.replace_devices(vec![DeviceSummary {
        id: "P520 Workstation".to_owned(),
        display_name: "P520 Workstation".to_owned(),
        status: DeviceStatus::Online,
    }]);

    shell
        .begin_connect_trusted("P520 Workstation", &loaded_store, now + 20)
        .expect("begin connect trusted");
    assert_eq!(shell.selected_device(), Some("P520 Workstation"));
    assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);

    // 6. Session authentication against trusted store
    let session_nonce = [0x77_u8; 32];
    let auth_msg = peer_auth_message(&device_verifying_key, &session_nonce);
    let auth_sig = device_signing_key.sign(&auth_msg).to_bytes();
    let auth_proof =
        verify_peer_authentication(device_verifying_key, session_nonce, auth_sig).unwrap();

    let mut session = Session::default();
    session
        .begin(
            PeerIdentity::new("P520 Workstation").unwrap(),
            PROTOCOL_VERSION,
        )
        .expect("begin session");
    assert_eq!(session.state(), SessionState::Negotiating);

    session
        .authenticate_with_trusted_store(&auth_proof, &loaded_store, now + 30)
        .expect("authenticate with trusted store");
    assert_eq!(session.state(), SessionState::AwaitingAuthorization);

    // 7. Explicit control authorization
    session.authorize_control().expect("authorize control");
    assert_eq!(session.state(), SessionState::Active);
    assert!(session.require_control().is_ok());

    // Clean up
    let _ = fs::remove_file(&path);
}

#[test]
fn negative_auth_and_enrollment_failure_cases_fail_closed() {
    let now = 1_000_000_u64;
    let challenge_nonce = [0x55_u8; 32];
    let challenge = EnrollmentChallenge::new(challenge_nonce, now, now + 300);

    let signing_key = SigningKey::from_bytes(&[0x22_u8; 32]);
    let pk = signing_key.verifying_key().to_bytes();
    let msg = build_enrollment_message("Test-Device", &pk, &challenge_nonce, now);
    let sig = signing_key.sign(&msg).to_bytes();

    // 1. Invalid signature rejected
    let mut bad_sig = sig;
    bad_sig[0] ^= 0xFF;
    let request1 = EnrollmentRequest {
        device_id: "Test-Device".to_owned(),
        display_name: "Test-Device".to_owned(),
        public_key: pk,
        nonce: challenge_nonce,
        timestamp_epoch_secs: now,
        signature: bad_sig,
    };
    assert_eq!(
        verify_enrollment(&challenge, &request1, now),
        Err(EnrollmentError::InvalidSignature)
    );

    // 2. Mismatched challenge nonce rejected
    let mut bad_nonce = challenge_nonce;
    bad_nonce[0] ^= 0xAA;
    let request2 = EnrollmentRequest {
        device_id: "Test-Device".to_owned(),
        display_name: "Test-Device".to_owned(),
        public_key: pk,
        nonce: bad_nonce,
        timestamp_epoch_secs: now,
        signature: sig,
    };
    assert_eq!(
        verify_enrollment(&challenge, &request2, now),
        Err(EnrollmentError::NonceMismatch)
    );

    // 3. Expired challenge rejected (> 300s TTL)
    let request3 = EnrollmentRequest {
        device_id: "Test-Device".to_owned(),
        display_name: "Test-Device".to_owned(),
        public_key: pk,
        nonce: challenge_nonce,
        timestamp_epoch_secs: now + 301,
        signature: sig,
    };
    assert_eq!(
        verify_enrollment(&challenge, &request3, now + 301),
        Err(EnrollmentError::ChallengeExpired {
            expired_at: now + 300,
            now: now + 301,
        })
    );

    // 4. Excessive future clock drift rejected (> 60s future drift)
    let request4 = EnrollmentRequest {
        device_id: "Test-Device".to_owned(),
        display_name: "Test-Device".to_owned(),
        public_key: pk,
        nonce: challenge_nonce,
        timestamp_epoch_secs: now + 65,
        signature: sig,
    };
    assert_eq!(
        verify_enrollment(&challenge, &request4, now),
        Err(EnrollmentError::TimestampInFuture {
            request_time: now + 65,
            max_allowed: now + 60,
        })
    );
}

#[test]
fn negative_session_connect_failure_cases_fail_closed() {
    let now = 1_000_000_u64;

    let trusted_key = SigningKey::from_bytes(&[0x33_u8; 32]);
    let trusted_pk = trusted_key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "trusted-dev".to_owned(),
            display_name: "Trusted Device".to_owned(),
            public_key: trusted_pk,
            enrolled_at_epoch_secs: now - 100,
            trust_expires_at_epoch_secs: now + 500,
            managed: true,
            revoked: false,
            status: PersistedDeviceStatus::Online,
        })
        .unwrap();

    store
        .add(TrustedDeviceRecord {
            device_id: "revoked-dev".to_owned(),
            display_name: "Revoked Device".to_owned(),
            public_key: trusted_pk,
            enrolled_at_epoch_secs: now - 100,
            trust_expires_at_epoch_secs: now + 500,
            managed: true,
            revoked: true,
            status: PersistedDeviceStatus::Online,
        })
        .unwrap();

    let mut shell = ProductShell::new();
    shell.replace_devices(vec![
        DeviceSummary {
            id: "trusted-dev".to_owned(),
            display_name: "Trusted Device".to_owned(),
            status: DeviceStatus::Online,
        },
        DeviceSummary {
            id: "revoked-dev".to_owned(),
            display_name: "Revoked Device".to_owned(),
            status: DeviceStatus::Online,
        },
        DeviceSummary {
            id: "untrusted-dev".to_owned(),
            display_name: "Untrusted Device".to_owned(),
            status: DeviceStatus::Online,
        },
    ]);

    // 1. Untrusted peer rejected at ProductShell connect
    assert_eq!(
        shell.begin_connect_trusted("untrusted-dev", &store, now),
        Err(ConnectError::UntrustedPeer("untrusted-dev".to_owned()))
    );

    // 2. Revoked peer rejected at ProductShell connect
    assert_eq!(
        shell.begin_connect_trusted("revoked-dev", &store, now),
        Err(ConnectError::DeviceRevoked("revoked-dev".to_owned()))
    );

    // 3. Expired trust rejected at ProductShell connect
    assert_eq!(
        shell.begin_connect_trusted("trusted-dev", &store, now + 501),
        Err(ConnectError::TrustExpired("trusted-dev".to_owned()))
    );

    // 4. Session authentication rejects unenrolled public key
    let unknown_key = SigningKey::from_bytes(&[0x99_u8; 32]);
    let unknown_pk = unknown_key.verifying_key().to_bytes();
    let nonce = [0x55_u8; 32];
    let msg = peer_auth_message(&unknown_pk, &nonce);
    let sig = unknown_key.sign(&msg).to_bytes();
    let proof = verify_peer_authentication(unknown_pk, nonce, sig).unwrap();

    let mut session = Session::default();
    session
        .begin(PeerIdentity::new("trusted-dev").unwrap(), PROTOCOL_VERSION)
        .unwrap();

    assert_eq!(
        session.authenticate_with_trusted_store(&proof, &store, now),
        Err(SessionError::UntrustedPublicKey)
    );

    // 5. Cross-tenant boundaries strictly rejected
    assert_eq!(
        session.enforce_tenant_boundary("org-corp-a", "org-corp-b"),
        Err(SessionError::CrossTenantMismatch {
            expected: "org-corp-a".to_owned(),
            received: "org-corp-b".to_owned(),
        })
    );

    // 6. No control authorization without valid session state transition
    assert_eq!(
        session.authorize_control(),
        Err(SessionError::InvalidTransition {
            from: SessionState::Negotiating,
            operation: "authorize_control",
        })
    );
    assert!(session.require_control().is_err());
}

#[test]
fn single_use_challenge_consumption_and_zero_byte_nonce_e2e() {
    let mut tracker = ChallengeTracker::new();
    let now = 1_000_000_u64;

    // Challenge with first byte zero but not all zeros
    let mut nonce = [0xAA_u8; 32];
    nonce[0] = 0x00;

    let challenge = tracker
        .issue(nonce, now, DEFAULT_CHALLENGE_LIFETIME_SECS)
        .expect("issue challenge with byte 0 = 0");
    assert!(challenge.is_valid_at(now));
    assert_eq!(tracker.len(), 1);

    let signing_key = SigningKey::from_bytes(&[0x44_u8; 32]);
    let pk = signing_key.verifying_key().to_bytes();
    let msg = build_enrollment_message("Peer-520", &pk, &nonce, now);
    let sig = signing_key.sign(&msg).to_bytes();

    let request = EnrollmentRequest {
        device_id: "Peer-520".to_owned(),
        display_name: "Peer-520 Display".to_owned(),
        public_key: pk,
        nonce,
        timestamp_epoch_secs: now,
        signature: sig,
    };

    // First consumption verifies and removes the challenge
    let record = verify_and_consume_enrollment(&mut tracker, &request, now)
        .expect("verify and consume enrollment");
    assert_eq!(record.device_id, "Peer-520");
    assert_eq!(record.status, PersistedDeviceStatus::Offline);
    assert_eq!(tracker.len(), 0);

    // Replay attempt fails closed: challenge already consumed
    assert_eq!(
        verify_and_consume_enrollment(&mut tracker, &request, now),
        Err(EnrollmentError::ChallengeAlreadyConsumed)
    );
}

#[test]
fn enrollment_coordinator_csprng_and_single_use_lifecycle() {
    let mut coordinator = EnrollmentCoordinator::new();
    let mut store = TrustedDeviceStore::new();
    let now = 1_000_000_u64;

    assert_eq!(coordinator.stage(), EnrollmentStage::Idle);
    assert!(coordinator.active_nonce().is_none());

    // 1. CSPRNG challenge issuance
    let challenge = coordinator.create_challenge(now).expect("create challenge");
    assert_ne!(challenge.nonce, [0_u8; 32]);
    assert!(challenge.is_valid_at(now));
    assert!(coordinator.is_challenge_active(now));
    assert_eq!(coordinator.active_nonce(), Some(&challenge.nonce));

    // 2. Sign response
    let signing_key = SigningKey::from_bytes(&[0x55_u8; 32]);
    let pk = signing_key.verifying_key().to_bytes();
    let msg = build_enrollment_message("Peer-CSPRNG", &pk, &challenge.nonce, now);
    let sig = signing_key.sign(&msg).to_bytes();

    let request = EnrollmentRequest {
        device_id: "Peer-CSPRNG".to_owned(),
        display_name: "Peer CSPRNG Display".to_owned(),
        public_key: pk,
        nonce: challenge.nonce,
        timestamp_epoch_secs: now,
        signature: sig,
    };

    // 3. Complete enrollment
    let record = coordinator
        .complete_enrollment(&request, &mut store, None, now)
        .expect("complete enrollment");
    assert_eq!(record.device_id, "Peer-CSPRNG");
    assert_eq!(record.status, PersistedDeviceStatus::Offline);
    assert_eq!(
        coordinator.stage(),
        EnrollmentStage::Enrolled {
            enrolled_at_epoch_secs: now
        }
    );
    assert!(coordinator.active_nonce().is_none());
    assert!(!coordinator.is_challenge_active(now));
    assert_eq!(store.len(), 1);

    // 4. Replay rejected fail-closed
    assert_eq!(
        coordinator.complete_enrollment(&request, &mut store, None, now),
        Err(EnrollmentError::ChallengeAlreadyConsumed)
    );
}

#[test]
fn enrollment_coordinator_atomic_persistence_and_restart() {
    let path = temp_store_path("coord-restart");
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let mut coordinator = EnrollmentCoordinator::new();
    let mut store = TrustedDeviceStore::new();
    let now = 2_000_000_u64;

    let challenge = coordinator.create_challenge(now).expect("challenge");
    let signing_key = SigningKey::from_bytes(&[0x66_u8; 32]);
    let pk = signing_key.verifying_key().to_bytes();
    let msg = build_enrollment_message("Peer-Restart", &pk, &challenge.nonce, now);
    let sig = signing_key.sign(&msg).to_bytes();

    let request = EnrollmentRequest {
        device_id: "Peer-Restart".to_owned(),
        display_name: "Peer Restart Display".to_owned(),
        public_key: pk,
        nonce: challenge.nonce,
        timestamp_epoch_secs: now,
        signature: sig,
    };

    // Enroll and atomically persist
    let record = coordinator
        .complete_enrollment(&request, &mut store, Some(&path), now)
        .expect("enroll and persist");
    assert_eq!(record.status, PersistedDeviceStatus::Offline);
    assert!(path.exists());

    // Restart: reload from disk
    let loaded = TrustedDeviceStore::load_from_path(&path).expect("reload store");
    assert_eq!(loaded.len(), 1);
    let loaded_rec = loaded.get("Peer-Restart").expect("found peer");
    assert_eq!(loaded_rec.public_key, pk);
    assert_eq!(loaded_rec.status, PersistedDeviceStatus::Offline);

    let _ = fs::remove_file(&path);
}

#[test]
fn enrollment_coordinator_corrupted_store_fails_closed() {
    let path = temp_store_path("coord-corrupt");
    fs::write(&path, b"corrupted non-json bytes!").expect("write corrupt file");

    let err = TrustedDeviceStore::load_from_path(&path);
    assert!(matches!(err, Err(DeviceStoreError::Json(_))));

    let _ = fs::remove_file(&path);
}

#[test]
fn transport_session_adapter_full_success_lifecycle() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-acme");
    let now = 3_000_000_u64;

    let peer_key = SigningKey::from_bytes(&[0x77_u8; 32]);
    let peer_pk = peer_key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "trusted-acme-peer".to_owned(),
            display_name: "ACME Peer".to_owned(),
            public_key: peer_pk,
            enrolled_at_epoch_secs: now - 100,
            trust_expires_at_epoch_secs: now + 5000,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    // 1. Begin negotiation
    adapter
        .begin_negotiation(PeerIdentity::new("trusted-acme-peer").unwrap())
        .expect("begin");
    assert_eq!(adapter.session().state(), SessionState::Negotiating);
    assert!(!adapter.is_control_authorized());

    // 2. Authenticate peer
    let nonce = [0x88_u8; 32];
    let msg = peer_auth_message(&peer_pk, &nonce);
    let sig = peer_key.sign(&msg).to_bytes();

    let record = adapter
        .authenticate_peer(peer_pk, nonce, sig, "tenant-acme", &store, now)
        .expect("authenticate peer");
    assert_eq!(record.device_id, "trusted-acme-peer");
    assert_eq!(adapter.authenticated_device_id(), Some("trusted-acme-peer"));
    assert_eq!(
        adapter.session().state(),
        SessionState::AwaitingAuthorization
    );
    assert!(!adapter.is_control_authorized());

    // 3. Authorize session
    adapter.authorize_session().expect("authorize");
    assert!(adapter.is_active());
    assert!(adapter.is_control_authorized());

    // 4. Send and receive payload
    adapter.send(b"hello authenticated peer").expect("send");
    let received = adapter.receive().expect("receive");
    assert_eq!(received, Some(b"hello authenticated peer".to_vec()));

    // 5. Close resets authorization
    adapter.close();
    assert!(!adapter.is_active());
    assert!(!adapter.is_control_authorized());
    assert!(adapter.authenticated_device_id().is_none());
}

#[test]
fn transport_session_adapter_unverified_payload_blocked() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-xyz");

    // Unauthenticated/unauthorized payload blocked fail-closed
    assert_eq!(
        adapter.send(b"unverified command"),
        Err(TransportSessionError::UnverifiedControlBlocked)
    );
    assert_eq!(
        adapter.receive(),
        Err(TransportSessionError::UnverifiedControlBlocked)
    );
}

#[test]
fn transport_session_adapter_cross_tenant_rejected() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-corp-a");
    let now = 3_000_000_u64;

    let peer_key = SigningKey::from_bytes(&[0x88_u8; 32]);
    let peer_pk = peer_key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "peer-b".to_owned(),
            display_name: "Peer B".to_owned(),
            public_key: peer_pk,
            enrolled_at_epoch_secs: now - 100,
            trust_expires_at_epoch_secs: now + 5000,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    adapter
        .begin_negotiation(PeerIdentity::new("peer-b").unwrap())
        .expect("begin");

    let nonce = [0x99_u8; 32];
    let msg = peer_auth_message(&peer_pk, &nonce);
    let sig = peer_key.sign(&msg).to_bytes();

    // Cross-tenant attempt rejected fail-closed
    let err = adapter.authenticate_peer(peer_pk, nonce, sig, "tenant-corp-b", &store, now);
    assert_eq!(
        err,
        Err(TransportSessionError::TenantMismatch {
            expected: "tenant-corp-a".to_owned(),
            received: "tenant-corp-b".to_owned(),
        })
    );
}

#[test]
fn transport_session_adapter_untrusted_peer_rejected() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-main");
    let now = 3_000_000_u64;

    let unlisted_key = SigningKey::from_bytes(&[0x99_u8; 32]);
    let unlisted_pk = unlisted_key.verifying_key().to_bytes();

    let empty_store = TrustedDeviceStore::new();

    adapter
        .begin_negotiation(PeerIdentity::new("unlisted").unwrap())
        .expect("begin");

    let nonce = [0xAA_u8; 32];
    let msg = peer_auth_message(&unlisted_pk, &nonce);
    let sig = unlisted_key.sign(&msg).to_bytes();

    assert_eq!(
        adapter.authenticate_peer(unlisted_pk, nonce, sig, "tenant-main", &empty_store, now),
        Err(TransportSessionError::UntrustedPeer)
    );
}

#[test]
fn transport_session_adapter_revoked_peer_rejected() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-main");
    let now = 3_000_000_u64;

    let key = SigningKey::from_bytes(&[0xAB_u8; 32]);
    let pk = key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "revoked-peer".to_owned(),
            display_name: "Revoked Peer".to_owned(),
            public_key: pk,
            enrolled_at_epoch_secs: now - 100,
            trust_expires_at_epoch_secs: now + 5000,
            managed: false,
            revoked: true,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    adapter
        .begin_negotiation(PeerIdentity::new("revoked-peer").unwrap())
        .expect("begin");

    let nonce = [0xBB_u8; 32];
    let msg = peer_auth_message(&pk, &nonce);
    let sig = key.sign(&msg).to_bytes();

    assert_eq!(
        adapter.authenticate_peer(pk, nonce, sig, "tenant-main", &store, now),
        Err(TransportSessionError::PeerRevoked)
    );
}

#[test]
fn transport_session_adapter_expired_trust_rejected() {
    let transport = LoopbackTransport::default();
    let mut adapter = TransportSessionAdapter::new(transport, "tenant-main");
    let now = 3_000_000_u64;

    let key = SigningKey::from_bytes(&[0xAC_u8; 32]);
    let pk = key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "expired-peer".to_owned(),
            display_name: "Expired Peer".to_owned(),
            public_key: pk,
            enrolled_at_epoch_secs: now - 5000,
            trust_expires_at_epoch_secs: now - 100,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    adapter
        .begin_negotiation(PeerIdentity::new("expired-peer").unwrap())
        .expect("begin");

    let nonce = [0xCC_u8; 32];
    let msg = peer_auth_message(&pk, &nonce);
    let sig = key.sign(&msg).to_bytes();

    assert_eq!(
        adapter.authenticate_peer(pk, nonce, sig, "tenant-main", &store, now),
        Err(TransportSessionError::TrustExpired)
    );
}

#[test]
fn tcp_lan_pairing_exchange_e2e() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let path = temp_store_path("tcp-pairing");
    let path_clone = path.clone();
    let now = 4_000_000_u64;

    // Server thread (Host)
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept connection");
        let mut transport = TcpLanTransport::from_stream(stream).expect("from stream");
        let mut coordinator = EnrollmentCoordinator::new();
        let mut store = TrustedDeviceStore::new();

        // 1. Process RequestChallenge -> sends Challenge
        let res1 = host_process_pairing_exchange(
            &mut coordinator,
            &mut store,
            Some(&path_clone),
            &mut transport,
            now,
        );
        assert_eq!(res1, Ok(None));

        // 2. Process SubmitEnrollment -> verifies and persists
        let res2 = host_process_pairing_exchange(
            &mut coordinator,
            &mut store,
            Some(&path_clone),
            &mut transport,
            now,
        );
        let record = res2.expect("enrollment should succeed").expect("record");
        assert_eq!(record.device_id, "peer-tcp-520");
        assert_eq!(record.status, PersistedDeviceStatus::Offline);
    });

    // Client thread (Peer)
    let peer_signing = SigningKey::from_bytes(&[0xEE_u8; 32]);
    let mut client_transport =
        TcpLanTransport::connect(addr, Duration::from_secs(5)).expect("connect");

    let result = peer_execute_pairing_handshake(
        &mut client_transport,
        &peer_signing,
        "peer-tcp-520",
        "TCP Peer 520",
        now,
    )
    .expect("handshake success");

    assert!(matches!(result, PairingMessage::EnrollmentSuccess { .. }));
    server_handle.join().expect("server join");

    // Verify atomic disk persistence
    let reloaded = TrustedDeviceStore::load_from_path(&path).expect("reload");
    assert_eq!(reloaded.len(), 1);
    let dev = reloaded.get("peer-tcp-520").expect("get peer");
    assert_eq!(dev.status, PersistedDeviceStatus::Offline);

    let _ = fs::remove_file(&path);
}

#[test]
fn tcp_lan_authenticated_session_e2e() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let now = 5_000_000_u64;

    let peer_key = SigningKey::from_bytes(&[0xEF_u8; 32]);
    let peer_pk = peer_key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "tcp-session-peer".to_owned(),
            display_name: "TCP Session Peer".to_owned(),
            public_key: peer_pk,
            enrolled_at_epoch_secs: now - 50,
            trust_expires_at_epoch_secs: now + 5000,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    let store_arc = store;

    // Server thread (Host)
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept connection");
        let transport = HostTransport::from_tcp_stream(stream).expect("from stream");
        let mut adapter = TransportSessionAdapter::new(transport, "kmj-tenant");

        adapter
            .begin_negotiation(PeerIdentity::new("tcp-session-peer").unwrap())
            .expect("begin");

        let nonce = [0x5A_u8; 32];
        let auth_msg = peer_auth_message(&peer_pk, &nonce);
        let sig = peer_key.sign(&auth_msg).to_bytes();

        let rec = adapter
            .authenticate_peer(peer_pk, nonce, sig, "kmj-tenant", &store_arc, now)
            .expect("auth");
        assert_eq!(rec.device_id, "tcp-session-peer");

        adapter.authorize_session().expect("authorize");
        assert!(adapter.is_control_authorized());

        // Echo server over TCP
        let payload = adapter.receive().expect("receive").expect("payload");
        assert_eq!(payload, b"ping tcp remote desktop");
        adapter.send(b"pong tcp remote desktop").expect("send");

        adapter.close();
        assert!(!adapter.is_control_authorized());
    });

    // Client thread
    let client_stream = std::net::TcpStream::connect(addr).expect("connect client");
    let mut client_transport = TcpLanTransport::from_stream(client_stream).expect("from stream");

    // Client sends ping payload and receives pong over TCP
    client_transport
        .send(b"ping tcp remote desktop")
        .expect("client send");
    let resp = client_transport
        .receive()
        .expect("client receive")
        .expect("resp");
    assert_eq!(resp, b"pong tcp remote desktop");

    server_handle.join().expect("server join");
}

#[test]
fn tcp_lan_wrong_tenant_rejected_fail_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let now = 6_000_000_u64;

    let peer_key = SigningKey::from_bytes(&[0xF1_u8; 32]);
    let peer_pk = peer_key.verifying_key().to_bytes();

    let mut store = TrustedDeviceStore::new();
    store
        .add(TrustedDeviceRecord {
            device_id: "tenant-peer".to_owned(),
            display_name: "Tenant Peer".to_owned(),
            public_key: peer_pk,
            enrolled_at_epoch_secs: now - 50,
            trust_expires_at_epoch_secs: now + 5000,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport = HostTransport::from_tcp_stream(stream).expect("transport");
        let mut adapter = TransportSessionAdapter::new(transport, "tenant-alpha");

        adapter
            .begin_negotiation(PeerIdentity::new("tenant-peer").unwrap())
            .expect("begin");

        let nonce = [0x6B_u8; 32];
        let auth_msg = peer_auth_message(&peer_pk, &nonce);
        let sig = peer_key.sign(&auth_msg).to_bytes();

        // Cross-tenant attempt fails closed
        let err = adapter.authenticate_peer(peer_pk, nonce, sig, "tenant-beta", &store, now);
        assert!(matches!(
            err,
            Err(TransportSessionError::TenantMismatch { .. })
        ));
        assert!(!adapter.is_control_authorized());
    });

    let _client = std::net::TcpStream::connect(addr).expect("client connect");
    server_handle.join().expect("server finish");
}

#[test]
fn host_transport_loopback_and_tcp_conformance() {
    let mut loopback = HostTransport::loopback();
    assert_eq!(
        loopback.path_kind(),
        omnidesk_core::transport::PathKind::Loopback
    );
    loopback.send(b"loopback-test").expect("send");
    assert_eq!(
        loopback.receive().expect("receive"),
        Some(b"loopback-test".to_vec())
    );
    loopback.close();
    assert_eq!(
        loopback.send(b"after-close"),
        Err(omnidesk_core::transport::TransportError::Closed)
    );
}
