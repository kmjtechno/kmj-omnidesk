# KMJ OmniDesk Licensing Contract v1

**Status:** Contract locked; production signing remains gated.

KMJ Main Platform is the sole commercial and licensing authority for KMJ OmniDesk. OmniDesk consumes versioned APIs and signed artifacts; it never reads Main Platform databases and never contains a master commercial unlock secret.

The machine-readable source of truth is `protocol/licensing/omnidesk-licensing-v1.yaml`.

## Trust model

Main Platform decides whether a customer, organization, entitlement, activation, and plan are valid. The OmniDesk endpoint independently verifies the signed result and enforces it locally. Payment evidence is never itself a license.

Production entitlement signatures use Ed25519. The private signing key is isolated in KMS/HSM and is never exported to OmniDesk, relay nodes, source control, or application database rows. Verification keys are identified by `kid`, support overlap during rotation, and may be revoked.

## Activation

On first install OmniDesk creates a local asymmetric device keypair. Activation binds the commercial entitlement to an `activation_id`, device public-key fingerprint, and installation identity. Activation is idempotent and Main Platform enforces device limits, duplicate-activation policy, replay protection, and suspicious-activation rate controls.

## Signed entitlement

Every accepted artifact binds at least the protocol/contract version, unique token ID, signing-key ID, license and entitlement IDs, customer/organization, `KMJ_OMNIDESK`, plan, activation/device/install identity, capabilities, resource limits, issue/not-before/expiry/lease times, nonce, and monotonically increasing sequence.

Verification order is strict: schema → trusted key → signature → version/product → time → device binding → sequence/replay → revocation → capability/limit enforcement.

## Renewal and offline operation

A short-lived renewable lease is cached as the last-known-good authorization. Renewal proves possession of the activated device key and advances sequence/nonce. A central outage does not instantly terminate a valid session authorization: the state machine is:

`ACTIVE → RENEWAL_DUE → GRACE → RESTRICTED → REACTIVATED/REVOKED`

Offline grace duration is policy/plan-driven rather than a universal client constant. Clock rollback must not extend grace. Expiry/restriction must not delete customer data.

## Revocation

License, entitlement, activation/device-transfer, and signing-key revocation are independently representable. A known explicit revocation overrides offline grace. Revocation restricts future licensed operation but does not destructively delete local customer data.

## API boundary

- `GET /api/v1/licensing/keys` — verification-key discovery.
- `POST /api/v1/licensing/omnidesk/activations` — entitlement/device binding.
- `POST /api/v1/licensing/omnidesk/leases/renew` — renewable lease.
- `GET /api/v1/licensing/omnidesk/activations/{activation_id}/status` — status/revocation.
- `POST /api/v1/licensing/omnidesk/activations/{activation_id}/deactivate` — release binding.
- `POST /api/v1/licensing/omnidesk/activations/{activation_id}/transfer` — controlled transfer.
- `GET /api/v1/licensing/omnidesk/entitlements/current` — customer/client entitlement summary.

Private endpoints require authorization, tenant isolation, rate limiting, deterministic error codes, audit events, and secret/token redaction.

## Billing boundary

Payment providers remain a Main Platform concern. The client never receives payment-provider credentials and payment success never directly unlocks features. The commercial path is:

`Plan/payment → Main Platform reconciliation → explicit entitlement → activation/renewal → signed entitlement → local enforcement`

## Production gate

This contract does **not** authorize production signing yet. Production requires KMS/HSM custody, key rotation/revocation tests, activation idempotency, replay/sequence tests, duplicate activation handling, clock-rollback tests, offline-grace tests, revocation propagation, tenant/IDOR/race tests, secret redaction, client forgery negative tests, and cross-language signed test vectors.
