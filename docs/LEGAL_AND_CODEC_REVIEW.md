# KMJ OmniDesk — Legal and Codec Release Review (UNAPPROVED)

> **M14 release gate: BLOCKED — legal counsel sign-off not obtained.**
> This is an engineering checklist, not legal advice, patent clearance, export
> classification, a privacy audit, or authorization for commercial distribution.

## 1. Dependency license evidence

`Cargo.lock` records dependency names, versions, sources and checksums; it
does **not** provide a complete, independently verified SPDX license inventory.
`deny.toml` is a policy allowlist with selected operator-supplied
clarifications. Neither file establishes that every dependency is permissively
licensed or that reciprocal obligations are absent.

`scripts/collect_license_inventory.py --check` checks lockfile/policy
structure only. Unknown licenses are explicitly `null` and marked `unknown`;
clarifications are labeled `policy_clarification_only`. This script does
**not** issue legal clearance or certify "0 copyleft dependencies."

The CI `cargo-deny` action separately checks dependency license policy.
Before distribution, retain an exact-lockfile cargo-deny receipt, independently
inspect upstream license files and attribution obligations for **all** shipped
dependencies, check target-specific dependencies, and generate verified
third-party notices. MPL-2.0 and any other reciprocal licenses require
specific obligations review rather than automatic dismissal.

## 2. Codec and patent risk

AV1, VP8, VP9, Opus, LZ4, PNG, and OS-native codecs must each be evaluated
against the actual shipped binaries, enabled features, target platforms,
patent claims and distribution jurisdictions. Open specifications and host
operating-system APIs do **not** by themselves prove royalty-free distribution
or immunity from third-party patent claims. No "zero royalties" claim is
approved here. Counsel must document the final codec inventory and patent
analysis before the release gate can pass.

## 3. Cryptography, export, privacy and support

Use of Ed25519, X25519 or AEAD primitives does not establish an export-control
classification or jurisdictional compliance. No ECCN, ENC eligibility,
data-retention, zero-knowledge relay, or privacy-policy compliance is certified
by this document. Require a technical data-flow audit, regulatory review,
and customer-facing policy verification using the exact release candidate.

## 4. Mock signer versus production authority

The offline licensing E2E suite uses test keys. It is not evidence of a live,
protected KMJ Main Platform production signer, revocation service, tenant/seat
enforcement, or customer entitlement issuance. M9 production signer and
independent release receipts remain mandatory.

## 5. Outstanding sign-off checklist

- [ ] Exact-release dependency license and attribution audit
- [ ] Codec inventory and patent/royalty assessment by qualified counsel
- [ ] Export-control classification and jurisdiction review
- [ ] Privacy/telemetry and relay data-flow review
- [ ] Protected production signer and commercial entitlement evidence
- [ ] Support lead and legal counsel approvals on exact candidate SHA

```yaml
signoff_gate: legal_and_codec_license_review_complete
requires_role: legal_counsel
status: PENDING_HUMAN_SIGNOFF
reviewer: ""
date: ""
candidate_sha: ""
notes: "No legal, patent, export, or commercial clearance asserted."
```
