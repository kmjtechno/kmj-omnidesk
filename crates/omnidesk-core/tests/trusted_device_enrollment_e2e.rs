use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer, SigningKey};
use omnidesk_core::{
    PROTOCOL_VERSION,
    authentication::{peer_auth_message, verify_peer_authentication},
    device_enrollment::{
        DEFAULT_CHALLENGE_LIFETIME_SECS, EnrollmentChallenge, EnrollmentError, EnrollmentRequest,
        build_enrollment_message, verify_enrollment,
    },
    product_shell::{ConnectError, DeviceStatus, DeviceSummary, ProductShell, SecurityState},
    session::{PeerIdentity, Session, SessionError, SessionState},
    trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore},
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
