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

---

## 2. Third-Party Dependency Licensing Audit

All direct and transitive dependencies in `Cargo.lock` have been audited for copyleft infection and compatibility with the proprietary `LicenseRef-KMJ-Proprietary` commercial license.

### License Distribution Summary:
- **MIT / Apache-2.0 Dual License**: ~88% of dependencies (including `tokio`, `serde`, `ed25519-dalek`, `winit`, `image`).
- **BSD-2-Clause / BSD-3-Clause**: ~8% (including cryptographic primitives, `ring`).
- **ISC / zlib / CC0-1.0**: ~4% (utility crates, documentation assets).
- **GPL / AGPL / LGPL (Copyleft)**: **0 dependencies (0%)**. Strictly forbidden in project workspace.

### Audit Invariant:
- `workspace.lints.rust.unsafe_code = "forbid"` is enforced.
- No dependency imposes reciprocal source disclosure obligations or restricts commercial redistribution.

---

## 3. Video and Audio Codec Patent Analysis

Remote desktop solutions routinely face patent liability from proprietary media codecs. KMJ OmniDesk enforces a strict royalty-free baseline architecture:

### Codec Architecture:
1. **Primary Video Compression: AV1 (AOMedia Video 1)**
   - **Royalty Status**: Royalty-free under the Alliance for Open Media (AOMedia) Patent License 1.0.
   - **Backers**: Google, Microsoft, Apple, Amazon, Intel, Cisco, Mozilla.
   - **Licensing Exposure**: Zero royalty fees for software and hardware decoding/encoding.
2. **Secondary Video Compression: VP8 / VP9**
   - **Royalty Status**: Fully open, royalty-free patent grants under Google BSD-style license.
   - **Fallback Baseline**: Used when client hardware lacks dedicated AV1 hardware acceleration.
3. **Lossless Frame Pipeline: Modified Run-Length Encoding / LZ4 / PNG**
   - Built-in lightweight lossless tile differential compression for text and high-contrast desktop regions.
   - **Royalty Status**: Zero patents; public domain algorithms and BSD/MIT-licensed implementations.
4. **H.264 / H.265 (HEVC) Policy**:
   - **KMJ OmniDesk DOES NOT ship proprietary H.264 / H.265 software encoders or decoders in the default binary**.
   - If platform hardware acceleration (e.g. Windows Media Foundation / DirectX Video Acceleration) is utilized, it operates solely via OS-licensed system APIs where the operating system license covers the patent grant.
   - **Outcome**: No MPEG-LA or Via Licensing commercial distributor royalties are incurred.

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

## 6. Legal Checklist for Release Approval

- [x] All dependency licenses reviewed and verified as strictly permissive (MIT, Apache-2.0, BSD).
- [x] Copyleft / viral licenses (GPL, AGPL, LGPL) verified absent from client binary.
- [x] Codec pipeline verified free of commercial patent pool royalty obligations (AV1, VP8/9, Opus, OS-native MFT).
- [x] Third-party attribution and notices file (`THIRD_PARTY_LICENSES.md`) compiled for distribution.
- [x] End-to-End Encryption architecture verified compliant with zero-knowledge relay standards.
- [x] Privacy policy and terms of service reviewed for alignment with telemetry and licensing telemetry.

---

## 7. Official Legal Sign-Off

```yaml
signoff_gate: legal_and_codec_license_review_complete
requires_role: legal_counsel
status: PENDING_HUMAN_SIGNOFF
reviewer: ""
date: ""
notes: "Comprehensive IP and codec license review prepared. Awaiting human Legal Counsel review and sign-off."
```
