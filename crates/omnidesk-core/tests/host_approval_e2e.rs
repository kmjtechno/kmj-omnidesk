//! Real Noise TCP password proof -> local consent -> real Ed25519 license.
//! No test below activates or authorizes remote screen/input.

use std::{net::TcpListener, thread, time::Duration};

use ed25519_dalek::{Signer, SigningKey};
use omnidesk_core::{
    PRODUCT_ID, PRODUCT_SLUG,
    activation_proof::fingerprint_public_key_bytes,
    attended_proof_wire::{
        HostPasswordProofReceipt, client_prove_attended_password,
        host_verify_attended_password_with_receipt,
    },
    device_identity::DeviceIdentity,
    host_approval::{HostApprovalError, PendingHostApproval},
    licensing::{
        DeviceBinding, Ed25519SignatureVerifier, LICENSE_CONTRACT_VERSION,
        LICENSE_PROTOCOL_VERSION, LicenseError, LicenseKeyStatus, LicensePlan, LicensePublicKey,
        LocalLicenseClock, NullableLimit, ResourceLimits, RevocationState,
        SignedEntitlementPayload, VerificationContext,
    },
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    password_auth::HostPasswordManager,
    transport::{TcpLanTransport, Transport},
    trusted_device_store::{PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore},
};

const NOW: u64 = 202_000;

/// Fixed test key is used only for CI validation, never installed as a
/// production Main Platform trusted issuer.
fn signed_test_lease(
    host_key: &[u8; 32],
    now: u64,
) -> (
    Vec<u8>,
    [u8; 64],
    Ed25519SignatureVerifier,
    SignedEntitlementPayload,
) {
    let issuer = SigningKey::from_bytes(&[77; 32]);
    let payload = SignedEntitlementPayload {
        protocol_version: LICENSE_PROTOCOL_VERSION.to_owned(),
        contract_version: LICENSE_CONTRACT_VERSION.to_owned(),
        jti: "test-host-approval-lease-001".to_owned(),
        kid: "isolated-approval-test-key".to_owned(),
        license_id: "licensed-session".to_owned(),
        entitlement_id: "entitlement-session".to_owned(),
        customer_id: "customer-session".to_owned(),
        organization_id: None,
        product_id: PRODUCT_ID.to_owned(),
        product_slug: PRODUCT_SLUG.to_owned(),
        plan: LicensePlan::Professional,
        activation_id: "activation-host".to_owned(),
        device_public_key_fingerprint: fingerprint_public_key_bytes(host_key),
        installation_id: "host-install-1".to_owned(),
        capabilities: vec!["remote.interactive".to_owned()],
        limits: ResourceLimits {
            licensed_users: NullableLimit(Some(1)),
            managed_devices: NullableLimit(Some(5)),
            concurrent_sessions: NullableLimit(Some(1)),
            unattended_devices: NullableLimit(Some(0)),
            relay_bytes_monthly: NullableLimit(Some(0)),
            relay_policy: "disabled".to_owned(),
        },
        issued_at: now - 120,
        not_before: now - 120,
        expires_at: now + 3600,
        lease_expires_at: now + 1800,
        sequence: 10,
        nonce: "license-bound-nonce".to_owned(),
    };
    let canonical = serde_json::to_vec(&payload).expect("encode signed entitlement");
    let signature = issuer.sign(&canonical).to_bytes();
    let verifier = Ed25519SignatureVerifier::new(
        vec![LicensePublicKey {
            kid: payload.kid.clone(),
            public_key: issuer.verifying_key().to_bytes(),
            not_before: now - 200,
            not_after: now + 7000,
            status: LicenseKeyStatus::Active,
        }],
        now,
    )
    .expect("test issuer");
    (canonical, signature, verifier, payload)
}

fn context(payload: &SignedEntitlementPayload, now: u64) -> VerificationContext<'_> {
    VerificationContext {
        binding: DeviceBinding {
            activation_id: &payload.activation_id,
            device_public_key_fingerprint: &payload.device_public_key_fingerprint,
            installation_id: &payload.installation_id,
        },
        last_accepted_sequence: 9,
        revocation: RevocationState::Clear,
        clock: LocalLicenseClock {
            now,
            last_trusted_server_time: now.saturating_sub(60),
            renewal_due_at: now + 900,
            grace_expires_at: now + 3500,
        },
    }
}

fn pin_client(client: &DeviceIdentity, now: u64) -> TrustedDeviceStore {
    let mut trust_store = TrustedDeviceStore::new();
    trust_store
        .add(TrustedDeviceRecord {
            device_id: client.public_id().to_owned(),
            display_name: "Known client device".to_owned(),
            public_key: client.public_key_bytes(),
            enrolled_at_epoch_secs: now - 200,
            trust_expires_at_epoch_secs: now + 600,
            managed: false,
            revoked: false,
            status: PersistedDeviceStatus::Offline,
        })
        .expect("pin client once");
    trust_store
}

/// Obtain a genuine host proof over a pair of OS TCP streams: the private
/// receipt cannot be created from an unchecked bool or manually in tests.
fn real_host_proof() -> (
    HostPasswordProofReceipt,
    HostPasswordManager,
    DeviceIdentity,
    TrustedDeviceStore,
) {
    let client = DeviceIdentity::from_seed(&[94; 32]);
    let host = DeviceIdentity::from_seed(&[95; 32]);
    let host_id = host.public_id().to_owned();
    let client_store = pin_client(&host, NOW);
    let host_store = pin_client(&client, NOW);
    let mut manager = HostPasswordManager::new(NOW);
    manager.set_allow_remote_control(true);
    let password = manager.password().to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let address = listener.local_addr().expect("address");
    let host_task = thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept");
        let tcp = TcpLanTransport::from_stream(socket).expect("host TCP");
        let mut channel = UnauthenticatedNoiseChannel::accept(tcp).expect("host Noise");
        let receipt = host_verify_attended_password_with_receipt(
            &mut channel,
            &host,
            &host_store,
            &mut manager,
            "kmj-tenant",
            NOW,
        )
        .expect("real encrypted password proof");
        channel.close();
        (receipt, manager, host, host_store)
    });

    let tcp = TcpLanTransport::connect(address, Duration::from_secs(2)).expect("client TCP");
    let mut channel = UnauthenticatedNoiseChannel::connect(tcp).expect("client Noise");
    assert_eq!(
        client_prove_attended_password(
            &mut channel,
            &client,
            &client_store,
            &host_id,
            "kmj-tenant",
            &password,
            NOW,
        ),
        Ok(())
    );
    channel.close();
    host_task.join().expect("host thread")
}

#[test]
fn host_click_requires_real_signed_lease_and_consumes_proof_once() {
    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    let (payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    let grant = pending
        .approve_after_visible_host_click(
            &peer_id,
            &hash,
            &host,
            &trust,
            &manager,
            &issuer,
            &payload,
            &signature,
            &context(&claims, NOW),
            0,
            NOW,
        )
        .expect("all independent checks pass");
    assert_eq!(grant.peer_id(), peer_id);
    assert_eq!(grant.host_id(), host.public_id());
    assert_eq!(grant.noise_handshake_hash(), &hash);
    assert_eq!(grant.signed_license_jti(), claims.jti);
    assert!(pending.is_consumed());
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::AlreadyConsumed),
    );
}

#[test]
fn host_click_rejects_a_different_channel_and_forbids_retry() {
    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let real_hash = *proof.noise_handshake_hash();
    let (payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &[19; 32],
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::NoiseTranscriptMismatch),
    );
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &real_hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::AlreadyConsumed),
    );
}

#[test]
fn host_click_refuses_revoked_peer_and_password_rotation() {
    let (proof, manager, host, mut trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    trust.revoke(&peer_id);
    let (payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::PeerRevokedOrExpired),
    );

    let (proof, mut manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    manager.rotate(NOW);
    let (payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::PasswordGenerationChanged),
    );
}

#[test]
fn host_click_rejects_modified_signed_entitlement_and_over_capacity() {
    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    let (mut payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    payload.push(b' ');
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                0,
                NOW,
            )
            .err(),
        Some(HostApprovalError::License(LicenseError::InvalidSignature)),
    );

    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    let (payload, signature, issuer, claims) = signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW),
                1,
                NOW,
            )
            .err(),
        Some(HostApprovalError::ConcurrentSessionLimit),
    );
}

#[test]
fn host_click_expires_at_thirty_seconds_without_control() {
    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    let (payload, signature, issuer, claims) =
        signed_test_lease(&host.public_key_bytes(), NOW + 30);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending
            .approve_after_visible_host_click(
                &peer_id,
                &hash,
                &host,
                &trust,
                &manager,
                &issuer,
                &payload,
                &signature,
                &context(&claims, NOW + 30),
                0,
                NOW + 30,
            )
            .err(),
        Some(HostApprovalError::ProofExpired),
    );
}

#[test]
fn host_click_refuses_trust_expiry_at_exact_boundary() {
    let (proof, manager, host, trust) = real_host_proof();
    let peer_id = proof.peer_id().to_owned();
    let hash = *proof.noise_handshake_hash();
    let mut expired_trust = TrustedDeviceStore::new();
    let mut record = trust.get(&peer_id).expect("original enrolled client").clone();
    record.trust_expires_at_epoch_secs = NOW;
    expired_trust.add(record).expect("record remains well formed");
    let (payload, signature, issuer, claims) =
        signed_test_lease(&host.public_key_bytes(), NOW);
    let mut pending = PendingHostApproval::new(proof);
    assert_eq!(
        pending.approve_after_visible_host_click(
            &peer_id, &hash, &host, &expired_trust, &manager, &issuer,
            &payload, &signature, &context(&claims, NOW), 0, NOW,
        ).err(),
        Some(HostApprovalError::PeerRevokedOrExpired),
    );
    assert!(pending.is_consumed());
}
