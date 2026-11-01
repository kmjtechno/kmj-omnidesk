//! End-to-end integration tests for KMJ `OmniDesk` licensing lifecycle (KSLP-v1).
//!
//! Verifies the complete client lifecycle interaction with KMJ Main Platform wire contracts:
//! discovery, proof-of-possession activation, lease renewal, status query, offline grace,
//! clock rollback detection, replay protection, revocation supremacy, and resource quotas.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use omnidesk_core::{
    PRODUCT_ID, PRODUCT_SLUG,
    activation_proof::{ActivationProofInput, activation_proof_message},
    licensing::{
        LICENSE_CONTRACT_VERSION, LICENSE_PROTOCOL_VERSION, LicenseError, LicensePlan,
        LicenseState, NullableLimit, ResourceLimitKind, ResourceLimits, SignedEntitlementPayload,
    },
    licensing_lifecycle::{
        ACTIVATION_PROOF_SCHEME, ActivationResponse, ActivationStatusResponse,
        LicensingClientError, LicensingManager, RENEWAL_PROOF_SCHEME, RenewLeaseResponse,
        ServerFailureReason,
    },
    renewal_proof::{RenewalProofInput, renewal_proof_message},
};

const MOCK_SERVER_SEED: [u8; 32] = [42_u8; 32];
const MOCK_CLIENT_SEED: [u8; 32] = [99_u8; 32];
const MOCK_KID: &str = "kid-mainplatform-production-01";

fn server_signing_key() -> SigningKey {
    SigningKey::from_bytes(&MOCK_SERVER_SEED)
}

fn mock_keys_discovery_json() -> Vec<u8> {
    let signer = server_signing_key();
    let pub_base64 = STANDARD.encode(signer.verifying_key().to_bytes());
    format!(
        r#"{{"protocol_version":"KSLP-v1","contract_version":"kmj.omnidesk.license.v1","product_id":"KMJ_OMNIDESK","algorithm":"Ed25519","keys":[{{"kid":"{MOCK_KID}","algorithm":"Ed25519","public_key_base64":"{pub_base64}","not_before":0,"not_after":2000000000,"status":"ACTIVE"}}]}}"#
    )
    .into_bytes()
}

#[allow(clippy::too_many_arguments)]
fn server_issue_signed_entitlement(
    signer: &SigningKey,
    activation_id: &str,
    device_fingerprint: &str,
    installation_id: &str,
    sequence: u64,
    iat: u64,
    nbf: u64,
    lease_exp: u64,
    exp: u64,
    concurrent_sessions: Option<u64>,
) -> String {
    let payload = SignedEntitlementPayload {
        protocol_version: LICENSE_PROTOCOL_VERSION.to_owned(),
        contract_version: LICENSE_CONTRACT_VERSION.to_owned(),
        jti: format!("jti-e2e-{sequence:08}"),
        kid: MOCK_KID.to_owned(),
        license_id: "77777777-1111-4111-8111-111111111111".to_owned(),
        entitlement_id: "77777777-2222-4222-8222-222222222222".to_owned(),
        customer_id: "77777777-3333-4333-8333-333333333333".to_owned(),
        organization_id: Some("77777777-4444-4444-8444-444444444444".to_owned()),
        product_id: PRODUCT_ID.to_owned(),
        product_slug: PRODUCT_SLUG.to_owned(),
        plan: LicensePlan::Enterprise,
        activation_id: activation_id.to_owned(),
        device_public_key_fingerprint: device_fingerprint.to_owned(),
        installation_id: installation_id.to_owned(),
        capabilities: vec![
            "remote.interactive".to_owned(),
            "remote.audio".to_owned(),
            "remote.file_transfer".to_owned(),
            "remote.multi_monitor".to_owned(),
        ],
        limits: ResourceLimits {
            licensed_users: NullableLimit(Some(10)),
            managed_devices: NullableLimit(Some(50)),
            concurrent_sessions: NullableLimit(concurrent_sessions),
            unattended_devices: NullableLimit(Some(20)),
            relay_bytes_monthly: NullableLimit(None),
            relay_policy: "allowed".to_owned(),
        },
        issued_at: iat,
        not_before: nbf,
        expires_at: exp,
        lease_expires_at: lease_exp,
        sequence,
        nonce: format!("nonce-server-e2e-{sequence:08}"),
    };

    let canonical_bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let signature = signer.sign(&canonical_bytes);

    let payload_part = URL_SAFE_NO_PAD.encode(&canonical_bytes);
    let sig_part = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{payload_part}.{sig_part}")
}

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_activation_and_renewal_lifecycle() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-prod".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;

    // Step 1: Update verification keys from Main Platform discovery response
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .expect("key discovery succeeds");

    // Step 2: Client prepares activation request
    let (req, idempotency_key) = manager.create_activation_request(
        "ENT-COMMERCIAL-ENTERPRISE-2026",
        "idem-p520-act-001",
        "client-nonce-001",
    );
    assert_eq!(req.proof_scheme, ACTIVATION_PROOF_SCHEME);
    assert_eq!(idempotency_key, "idem-p520-act-001");

    // Step 3: Main Platform backend verifies proof-of-possession
    let client_pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&req.device_public_key)
        .expect("decode client pubkey");
    let client_pubkey: [u8; 32] = client_pubkey_bytes
        .try_into()
        .expect("32 byte client pubkey");
    let client_verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&client_pubkey).expect("valid verifying key");

    let proof_msg = activation_proof_message(ActivationProofInput {
        idempotency_key: &idempotency_key,
        license_or_entitlement_reference: &req.license_or_entitlement_reference,
        device_public_key: &req.device_public_key,
        device_public_key_fingerprint: &req.device_public_key_fingerprint,
        installation_id: &req.installation_id,
        client_version: &req.client_version,
        protocol_version: &req.protocol_version,
        platform: &req.platform,
        architecture: &req.architecture,
        client_nonce: &req.client_nonce,
    });
    let sig_raw = URL_SAFE_NO_PAD
        .decode(&req.device_signature)
        .expect("decode device signature");
    let sig = Signature::from_slice(&sig_raw).expect("signature slice");
    client_verifying_key
        .verify(&proof_msg, &sig)
        .expect("server must verify client activation proof");

    // Step 4: Main Platform issues signed entitlement token for activation
    let server_signer = server_signing_key();
    let activation_id = "act-p520-commercial-001";
    let token_seq1 = server_issue_signed_entitlement(
        &server_signer,
        activation_id,
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(5),
    );

    let activation_resp = ActivationResponse {
        activation_id: activation_id.to_owned(),
        signed_entitlement: token_seq1,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "2026-10-31.1".to_owned(),
    };
    let activation_bytes = serde_json::to_vec(&activation_resp).unwrap();

    // Step 5: Client processes activation response
    let state = manager
        .process_activation_response(&activation_bytes, now)
        .expect("process activation succeeds");
    assert_eq!(state, LicenseState::Active);

    let lease = manager.active_lease().expect("active lease present");
    assert_eq!(lease.last_accepted_sequence, 1);
    assert_eq!(lease.activation_id, activation_id);

    // Step 6: Query status response at now + 500
    let status_resp = ActivationStatusResponse {
        activation_id: activation_id.to_owned(),
        state: "ACTIVE".to_owned(),
        sequence: 1,
        reason_code: None,
        revoked_at: None,
        server_time: now + 500,
    };
    let status_bytes = serde_json::to_vec(&status_resp).unwrap();
    let status_state = manager
        .process_status_response(&status_bytes, now + 500)
        .expect("status check succeeds");
    assert_eq!(status_state, LicenseState::Active);

    // Step 7: Renewal flow at now + 2000 (after renewal_due_at = now + 1800)
    let renewal_time = now + 2000;
    assert_eq!(
        manager.evaluate_state(renewal_time).unwrap(),
        LicenseState::RenewalDue
    );

    let renew_req = manager
        .create_renewal_request("srv-challenge-xyz", "client-nonce-002")
        .expect("create renewal request");
    assert_eq!(renew_req.proof_scheme, RENEWAL_PROOF_SCHEME);
    assert_eq!(renew_req.current_sequence, 1);

    // Step 8: Main Platform verifies renewal proof
    let renew_msg = renewal_proof_message(RenewalProofInput {
        activation_id: &renew_req.activation_id,
        current_jti: &renew_req.current_jti,
        current_sequence: renew_req.current_sequence,
        server_challenge: &renew_req.server_challenge,
        client_nonce: &renew_req.client_nonce,
        client_version: &renew_req.client_version,
    });
    let renew_sig_raw = URL_SAFE_NO_PAD
        .decode(&renew_req.device_signature)
        .expect("decode renew signature");
    let renew_sig = Signature::from_slice(&renew_sig_raw).expect("renew signature slice");
    client_verifying_key
        .verify(&renew_msg, &renew_sig)
        .expect("server must verify renewal proof");

    // Step 9: Server issues renewed entitlement (sequence 2)
    let token_seq2 = server_issue_signed_entitlement(
        &server_signer,
        activation_id,
        manager.device_fingerprint(),
        manager.installation_id(),
        2,
        renewal_time,
        renewal_time,
        renewal_time + 3600,
        now + 86400 * 30,
        Some(5),
    );

    let renew_resp = RenewLeaseResponse {
        signed_entitlement: token_seq2,
        lease_expires_at: renewal_time + 3600,
        next_renewal_at: renewal_time + 1800,
        server_time: renewal_time,
    };
    let renew_bytes = serde_json::to_vec(&renew_resp).unwrap();

    // Step 10: Client processes renewal response
    let renewed_state = manager
        .process_renewal_response(&renew_bytes, renewal_time)
        .expect("process renewal succeeds");
    assert_eq!(renewed_state, LicenseState::Active);

    let renewed_lease = manager.active_lease().unwrap();
    assert_eq!(renewed_lease.last_accepted_sequence, 2);
}

#[test]
fn e2e_replay_and_stale_sequence_rejection() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-replay".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();
    let activation_id = "act-replay-001";

    let token_seq1 = server_issue_signed_entitlement(
        &server_signer,
        activation_id,
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(5),
    );

    let act_resp = ActivationResponse {
        activation_id: activation_id.to_owned(),
        signed_entitlement: token_seq1.clone(),
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();

    // Advancing to sequence 2
    let token_seq2 = server_issue_signed_entitlement(
        &server_signer,
        activation_id,
        manager.device_fingerprint(),
        manager.installation_id(),
        2,
        now + 100,
        now + 100,
        now + 3700,
        now + 86400 * 30,
        Some(5),
    );
    let renew_resp = RenewLeaseResponse {
        signed_entitlement: token_seq2,
        lease_expires_at: now + 3700,
        next_renewal_at: now + 1900,
        server_time: now + 100,
    };
    manager
        .process_renewal_response(&serde_json::to_vec(&renew_resp).unwrap(), now + 100)
        .unwrap();

    // Replay sequence 1: must fail closed
    let replayed_resp = RenewLeaseResponse {
        signed_entitlement: token_seq1,
        lease_expires_at: now + 3600,
        next_renewal_at: now + 1800,
        server_time: now + 200,
    };
    let err = manager
        .process_renewal_response(&serde_json::to_vec(&replayed_resp).unwrap(), now + 200)
        .unwrap_err();

    assert_eq!(
        err,
        LicensingClientError::Verification(LicenseError::ReplayOrStaleSequence)
    );
}

#[test]
fn e2e_offline_grace_and_network_outage_handling() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-grace".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();
    let activation_id = "act-grace-001";
    let lease_duration = 3600; // 1 hour lease
    let lease_exp = now + lease_duration;

    let token = server_issue_signed_entitlement(
        &server_signer,
        activation_id,
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        lease_exp,
        now + 86400 * 30,
        Some(2),
    );

    let act_resp = ActivationResponse {
        activation_id: activation_id.to_owned(),
        signed_entitlement: token,
        lease_expires_at: lease_exp,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();

    // 1. Within normal active window
    assert_eq!(
        manager.evaluate_state(now + 1000).unwrap(),
        LicenseState::Active
    );

    // 2. Beyond renewal_due_at (now + 1800), before lease_expires_at
    assert_eq!(
        manager.evaluate_state(now + 2000).unwrap(),
        LicenseState::RenewalDue
    );

    // 3. Server outage during lease: handle_server_failure maintains safe operation
    let outage_state = manager
        .handle_server_failure(now + 2000, ServerFailureReason::NetworkUnreachable)
        .unwrap();
    assert_eq!(outage_state, LicenseState::RenewalDue);

    // 4. Past lease_expires_at, but within grace_expires_at (grace is +3600 = now + 7200)
    let grace_time = now + 4000;
    assert_eq!(
        manager.evaluate_state(grace_time).unwrap(),
        LicenseState::Grace
    );
    let grace_failure_state = manager
        .handle_server_failure(grace_time, ServerFailureReason::HttpError(503))
        .unwrap();
    assert_eq!(grace_failure_state, LicenseState::Grace);

    // 5. Beyond grace_expires_at (now + 7500): fails closed to Restricted
    let expired_time = now + 7500;
    assert_eq!(
        manager.evaluate_state(expired_time).unwrap(),
        LicenseState::Restricted
    );
    let expired_failure_state = manager
        .handle_server_failure(expired_time, ServerFailureReason::Timeout)
        .unwrap();
    assert_eq!(expired_failure_state, LicenseState::Restricted);
}

#[test]
fn e2e_clock_rollback_fails_closed() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-rollback".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();
    let token = server_issue_signed_entitlement(
        &server_signer,
        "act-rollback-001",
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(2),
    );

    let act_resp = ActivationResponse {
        activation_id: "act-rollback-001".to_owned(),
        signed_entitlement: token,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();

    // Advance time safely
    assert_eq!(
        manager.evaluate_state(now + 100).unwrap(),
        LicenseState::Active
    );

    // Clock set backwards behind trusted server time: must fail closed immediately
    let rollback_time = now - 500;
    let err = manager.evaluate_state(rollback_time).unwrap_err();
    assert_eq!(
        err,
        LicensingClientError::ClockRollback {
            now: rollback_time,
            last_trusted_server_time: now,
        }
    );
}

#[test]
fn e2e_revocation_overrides_grace_permanently() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-revoked".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();
    let token = server_issue_signed_entitlement(
        &server_signer,
        "act-revoked-001",
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(2),
    );

    let act_resp = ActivationResponse {
        activation_id: "act-revoked-001".to_owned(),
        signed_entitlement: token,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();

    // Server announces revocation via status endpoint
    let status_resp = ActivationStatusResponse {
        activation_id: "act-revoked-001".to_owned(),
        state: "REVOKED".to_owned(),
        sequence: 1,
        reason_code: Some("DEVICE_TRANSFERRED".to_owned()),
        revoked_at: Some(now + 50),
        server_time: now + 50,
    };
    let status_bytes = serde_json::to_vec(&status_resp).unwrap();
    let err = manager
        .process_status_response(&status_bytes, now + 50)
        .unwrap_err();

    assert_eq!(
        err,
        LicensingClientError::Revoked {
            reason: Some("DEVICE_TRANSFERRED".to_owned()),
        }
    );

    // Subsequent evaluations fail closed permanently
    assert!(matches!(
        manager.evaluate_state(now + 100),
        Err(LicensingClientError::Revoked { .. })
    ));
}

#[test]
fn e2e_resource_quotas_and_server_error_responses() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-limits".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();
    let token = server_issue_signed_entitlement(
        &server_signer,
        "act-limits-001",
        manager.device_fingerprint(),
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(3), // Limit of 3 concurrent sessions
    );

    let act_resp = ActivationResponse {
        activation_id: "act-limits-001".to_owned(),
        signed_entitlement: token,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();

    let lease = manager.active_lease().unwrap();
    let limits = &lease.verified_entitlement.payload.limits;

    // Concurrent sessions check via permits
    assert!(limits.permits(ResourceLimitKind::ConcurrentSessions, 1));
    assert!(limits.permits(ResourceLimitKind::ConcurrentSessions, 3));
    assert!(!limits.permits(ResourceLimitKind::ConcurrentSessions, 4));

    // Session gating via check_session_allowed
    assert!(manager.check_session_allowed(now + 10, 2).is_ok());
    assert_eq!(
        manager.check_session_allowed(now + 10, 3),
        Err(LicensingClientError::LimitExceeded {
            kind: ResourceLimitKind::ConcurrentSessions,
            limit: 3,
            requested: 4,
        })
    );

    // Server error payload
    let error_payload = br#"{"error":"TENANT_SEAT_QUOTA_EXCEEDED","request_id":"req-err-999","message":"Maximum active seats reached for tenant"}"#;
    let err = manager
        .process_activation_response(error_payload, now + 10)
        .unwrap_err();
    assert_eq!(
        err,
        LicensingClientError::ServerRejected {
            error: "TENANT_SEAT_QUOTA_EXCEEDED".to_owned(),
            request_id: "req-err-999".to_owned(),
            message: Some("Maximum active seats reached for tenant".to_owned()),
        }
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_key_rotation_and_unknown_key_rejection() {
    let key1 = SigningKey::from_bytes(&[101_u8; 32]);
    let key2 = SigningKey::from_bytes(&[102_u8; 32]);
    let unknown_key = SigningKey::from_bytes(&[103_u8; 32]);

    let pub1 = STANDARD.encode(key1.verifying_key().to_bytes());
    let pub2 = STANDARD.encode(key2.verifying_key().to_bytes());

    let discovery_json = format!(
        r#"{{"protocol_version":"KSLP-v1","contract_version":"kmj.omnidesk.license.v1","product_id":"KMJ_OMNIDESK","algorithm":"Ed25519","keys":[{{"kid":"kid-platform-old","algorithm":"Ed25519","public_key_base64":"{pub1}","not_before":0,"not_after":2000000000,"status":"ROLLOVER"}},{{"kid":"kid-platform-new","algorithm":"Ed25519","public_key_base64":"{pub2}","not_before":0,"not_after":2000000000,"status":"ACTIVE"}}]}}"#
    );

    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-rotation".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(discovery_json.as_bytes(), now)
        .unwrap();

    // 1. Activation signed by old rollover key
    let mut payload = SignedEntitlementPayload {
        protocol_version: LICENSE_PROTOCOL_VERSION.to_owned(),
        contract_version: LICENSE_CONTRACT_VERSION.to_owned(),
        jti: "jti-rot-001".to_owned(),
        kid: "kid-platform-old".to_owned(),
        license_id: "77777777-1111-4111-8111-111111111111".to_owned(),
        entitlement_id: "77777777-2222-4222-8222-222222222222".to_owned(),
        customer_id: "77777777-3333-4333-8333-333333333333".to_owned(),
        organization_id: None,
        product_id: PRODUCT_ID.to_owned(),
        product_slug: PRODUCT_SLUG.to_owned(),
        plan: LicensePlan::Professional,
        activation_id: "act-rot-001".to_owned(),
        device_public_key_fingerprint: manager.device_fingerprint().to_owned(),
        installation_id: manager.installation_id().to_owned(),
        capabilities: vec!["remote.interactive".to_owned()],
        limits: ResourceLimits {
            licensed_users: NullableLimit(Some(1)),
            managed_devices: NullableLimit(Some(1)),
            concurrent_sessions: NullableLimit(Some(1)),
            unattended_devices: NullableLimit(Some(1)),
            relay_bytes_monthly: NullableLimit(None),
            relay_policy: "allowed".to_owned(),
        },
        issued_at: now,
        not_before: now,
        expires_at: now + 86400 * 30,
        lease_expires_at: now + 3600,
        sequence: 1,
        nonce: "nonce-rot-1".to_owned(),
    };

    let canonical1 = serde_json::to_vec(&payload).unwrap();
    let sig1 = key1.sign(&canonical1);
    let token1 = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&canonical1),
        URL_SAFE_NO_PAD.encode(sig1.to_bytes())
    );

    let act_resp = ActivationResponse {
        activation_id: "act-rot-001".to_owned(),
        signed_entitlement: token1,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "2026-10-31.2".to_owned(),
    };
    let state = manager
        .process_activation_response(&serde_json::to_vec(&act_resp).unwrap(), now)
        .unwrap();
    assert_eq!(state, LicenseState::Active);

    // 2. Renewal signed by new active key
    payload.kid = "kid-platform-new".to_owned();
    payload.sequence = 2;
    payload.issued_at = now + 1000;
    payload.not_before = now + 1000;
    payload.lease_expires_at = now + 4600;
    let canonical2 = serde_json::to_vec(&payload).unwrap();
    let sig2 = key2.sign(&canonical2);
    let token2 = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&canonical2),
        URL_SAFE_NO_PAD.encode(sig2.to_bytes())
    );

    let renew_resp = RenewLeaseResponse {
        signed_entitlement: token2,
        lease_expires_at: now + 4600,
        next_renewal_at: now + 2800,
        server_time: now + 1000,
    };
    let renewed_state = manager
        .process_renewal_response(&serde_json::to_vec(&renew_resp).unwrap(), now + 1000)
        .unwrap();
    assert_eq!(renewed_state, LicenseState::Active);

    // 3. Unknown kid: fails closed
    payload.kid = "kid-unknown-rogue".to_owned();
    payload.sequence = 3;
    payload.issued_at = now + 2000;
    payload.not_before = now + 2000;
    payload.lease_expires_at = now + 5600;
    let canonical3 = serde_json::to_vec(&payload).unwrap();
    let sig3 = unknown_key.sign(&canonical3);
    let rogue_token = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&canonical3),
        URL_SAFE_NO_PAD.encode(sig3.to_bytes())
    );

    let rogue_resp = RenewLeaseResponse {
        signed_entitlement: rogue_token,
        lease_expires_at: now + 5600,
        next_renewal_at: now + 3800,
        server_time: now + 2000,
    };
    let err = manager
        .process_renewal_response(&serde_json::to_vec(&rogue_resp).unwrap(), now + 2000)
        .unwrap_err();
    assert_eq!(
        err,
        LicensingClientError::Verification(LicenseError::UnknownOrRevokedKey)
    );
}

#[test]
fn e2e_device_and_installation_binding_mismatch_rejected() {
    let mut manager = LicensingManager::new(
        &MOCK_CLIENT_SEED,
        "install-p520-binding".to_owned(),
        "0.0.2".to_owned(),
        "windows".to_owned(),
        "x86_64".to_owned(),
    );

    let now = 1_000_000_u64;
    manager
        .update_verification_keys(&mock_keys_discovery_json(), now)
        .unwrap();

    let server_signer = server_signing_key();

    // Mismatched device fingerprint
    let token_wrong_device = server_issue_signed_entitlement(
        &server_signer,
        "act-binding-001",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        manager.installation_id(),
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(1),
    );

    let act_resp_wrong_device = ActivationResponse {
        activation_id: "act-binding-001".to_owned(),
        signed_entitlement: token_wrong_device,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    let err = manager
        .process_activation_response(&serde_json::to_vec(&act_resp_wrong_device).unwrap(), now)
        .unwrap_err();
    assert_eq!(
        err,
        LicensingClientError::Verification(LicenseError::DeviceBindingMismatch)
    );

    // Mismatched installation ID
    let token_wrong_install = server_issue_signed_entitlement(
        &server_signer,
        "act-binding-002",
        manager.device_fingerprint(),
        "install-different-machine-999",
        1,
        now,
        now,
        now + 3600,
        now + 86400 * 30,
        Some(1),
    );

    let act_resp_wrong_install = ActivationResponse {
        activation_id: "act-binding-002".to_owned(),
        signed_entitlement: token_wrong_install,
        lease_expires_at: now + 3600,
        server_time: now,
        key_set_version: "v1".to_owned(),
    };
    let err2 = manager
        .process_activation_response(&serde_json::to_vec(&act_resp_wrong_install).unwrap(), now)
        .unwrap_err();
    assert_eq!(
        err2,
        LicensingClientError::Verification(LicenseError::DeviceBindingMismatch)
    );
}
