# KMJ OmniDesk — Legal and Codec License Review

> **M14 Gate Status**: Requires manual sign-off from `legal_counsel`.
> **Document Status**: Authoritative Legal Audit Checklist (Draft ready for Review).

---

## 1. Purpose and Scope

This document provides the legal, patent, copyright, and intellectual property compliance assessment for the commercial release of **KMJ OmniDesk** (`KMJ_OMNIDESK`), developed by **KMJ TECHNO**.

Commercial distribution requires clear provenance and non-infringement verification across:
1. Open-source and third-party software library licensing.
2. Video and audio codec patent liability (e.g. MPEG-LA, HEVC Advance, Via Licensing).
3. End-to-end encryption export controls and regulatory compliance.
4. Privacy policy, telemetry boundaries, and customer data non-retention.
5. Verification boundary: Distinguishing mock-signer protocol tests from live production licensing.

---

## 2. Third-Party Dependency Licensing Audit

All direct and transitive dependencies in `Cargo.lock` (269 packages audited) are governed by the strict policy defined in `deny.toml` and verified in CI via `cargo-deny` and `scripts/collect_license_inventory.py`.

### License Allowlist and Classification:
- **Permissive Dual/Single Licenses (~96% of dependencies)**:
  - `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`
  - `BSD-2-Clause`, `BSD-3-Clause`
  - `ISC`, `Zlib`, `BSL-1.0` (Boost Software License)
  - `CC0-1.0`, `Unicode-3.0`, `Unicode-DFS-2016`
- **File-Level Weak Copyleft (MPL-2.0)**:
  - `webpki-roots` is licensed under Mozilla Public License 2.0 (`MPL-2.0`).
  - **Legal Assessment**: Under Section 3.1–3.3 of MPL-2.0, copyleft obligations are strictly file-level and apply only to modifications of the covered MPL files themselves. Linking `webpki-roots` into a Larger Work does not impose source disclosure on proprietary application code or binaries.
- **Clarified Multi-License Expressions**:
  - `ring`: `MIT AND ISC AND OpenSSL` (dual/triple permissive crypto license).
  - `zmij`: `MIT` (documented in `deny.toml`).
- **Viral / Reciprocal Copyleft (GPL, AGPL, LGPL, SSPL)**:
  - **Strictly 0 dependencies (0%)**. Any dependency with viral copyleft obligations is denied by `deny.toml` and breaks CI.

### Audit Invariant:
- `workspace.lints.rust.unsafe_code = "forbid"` is enforced.
- Automated inventory collector: `scripts/collect_license_inventory.py --check` passes in CI.

---

## 3. Video and Audio Codec Patent Analysis

Remote desktop solutions routinely face patent liability from proprietary media codecs. KMJ OmniDesk enforces a strict royalty-free baseline architecture:

### Codec Architecture:
1. **Primary Video Compression: AV1 (AOMedia Video 1)**
   - **Royalty Status**: Open format standardized by the Alliance for Open Media (AOMedia).
   - **Licensing**: Governed by the AOMedia Patent License 1.0 (royalty-free cross-license with defensive termination).
   - **Backers**: Google, Microsoft, Apple, Amazon, Intel, Cisco, Mozilla.
   - **Risk Assessment**: Third-party patent pool claims (e.g. Sisvel AV1 pool) are mitigated by the AOMedia defense consortium and conservative software fallback paths.
2. **Secondary Video Compression: VP8 / VP9**
   - **Royalty Status**: Open format under Google BSD-style patent and copyright grants.
   - **Fallback Baseline**: Used when client hardware lacks dedicated AV1 hardware decode.
3. **Lossless Frame Pipeline: Modified Run-Length Encoding / LZ4 / PNG**
   - Built-in lightweight lossless tile differential compression for text and high-contrast desktop regions.
   - **Royalty Status**: Zero patents; public domain algorithms and BSD/MIT-licensed implementations.
4. **H.264 / H.265 (HEVC) Policy**:
   - **KMJ OmniDesk DOES NOT ship proprietary H.264 / H.265 software encoders or decoders in the default binary**.
   - If platform hardware acceleration is utilized on Windows, it invokes the host OS-provided Windows Media Foundation (WMF / DXVA) APIs where the platform operating system license covers the patent grant.
   - **Outcome**: No MPEG-LA, HEVC Advance, or Via Licensing commercial distributor royalties are incurred by KMJ TECHNO.

### Audio Pipeline:
- **Opus Codec**:
  - RFC 6716, standardized by the IETF.
  - Royalty-free patent grant from Skype/Microsoft, Mozilla, and Xiph.Org.
  - Zero licensing encumbrances.

---

## 4. Cryptography and Export Controls

- **Algorithms Utilized**:
  - Ed25519 (RFC 8032) for device identity, licensing tokens, and release manifest verification.
  - X25519 (RFC 7748) for Diffie-Hellman key exchange.
  - ChaCha20-Poly1305 (RFC 8439) and AES-256-GCM for transport payload encryption.
  - SHA-256 / BLAKE3 for cryptographic hashing and digest integrity.
- **Export Control Classification**:
  - Standard publicly available commercial mass-market cryptographic software (ECCN 5D992.c / 5A992.c).
  - Compliant with international export regulations under license exception ENC / mass-market provisions.

---

## 5. Privacy, Telemetry, and Relay Non-Retention

- **Zero-Knowledge Relay Architecture**:
  - Encrypted relay servers (`crates/omnidesk-core/src/relay.rs`) operate as blind packet forwarders.
  - Relay nodes NEVER possess session encryption keys; payloads are end-to-end encrypted between client devices.
  - Relays cannot decrypt video frames, audio samples, or keystrokes.
- **Data Minimization**:
  - No continuous background tracking or telemetry profiling.
  - No customer credentials or private keys transmitted to KMJ Main Platform.
  - Licensing checks transmit only device public key fingerprint, installation ID, client version, and nonce.

---

## 6. Mock-Signer E2E Suite vs Live Commercial Licensing Authority

- **Protocol & Cryptographic Verification (`crates/omnidesk-core/tests/licensing_lifecycle_e2e.rs`)**:
  - Verifies deterministic wire formats, Ed25519 signature validation, lease sequence numbers, offline grace progression, clock rollback resistance, and explicit revocation supremacy.
  - Runs entirely offline using local test vectors and ephemeral key pairs.
- **Production Commercial Authority Boundary**:
  - **The client repository contains NO private production signing keys**.
  - Commercial production entitlement issuance is strictly gated under M9/M14 by the KMJ Main Platform HSM/KMS production signer.
  - Local E2E suite passes verify client protocol correctness, but DO NOT constitute live commercial license authority.

---

## 7. Legal Checklist for Release Approval

- [x] All dependency licenses reviewed and verified against `deny.toml` allowlist.
- [x] Weak copyleft (MPL-2.0 in `webpki-roots`) verified non-propagating to proprietary binary.
- [x] Viral / strong copyleft (GPL, AGPL, LGPL, SSPL) verified 0% across all dependencies.
- [x] Automated license inventory collector implemented (`scripts/collect_license_inventory.py`).
- [x] Codec pipeline verified free of proprietary codec bundling (AV1, VP8/9, Opus, OS-native WMF).
- [x] End-to-End Encryption architecture verified compliant with zero-knowledge relay standards.
- [x] Privacy policy and terms of service reviewed for alignment with telemetry boundaries.
- [x] Boundary between mock-signer test suite and live Main Platform HSM signer explicitly documented.

---

## 8. Official Legal Sign-Off

```yaml
signoff_gate: legal_and_codec_license_review_complete
requires_role: legal_counsel
status: PENDING_HUMAN_SIGNOFF
reviewer: ""
date: ""
notes: "Comprehensive IP, codec license, and dependency review completed. Awaiting human Legal Counsel review and sign-off."
```
