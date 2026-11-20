# KMJ OmniDesk Codec License Inventory

## Purpose

This inventory tracks all codec licenses required for M14 gate: `legal_and_codec_license_review_complete`.

---

## Declared Codec Licenses

| Codec | License | Source | Status |
|-------|---------|--------|--------|
| H264 | Hardware encoder (OS) | Windows Media Foundation | Licensed |
| HEVC | Hardware encoder (OS) | Windows Media Foundation | Licensed |
| AV1 | libdav1d/libsvtav1 | Apache-2.0 | Open source |
| Audio AAC | Hardware encoder (OS) | Windows Media Foundation | Licensed |
| Audio MP3 | Hardware encoder (OS) | Windows Media Foundation | Licensed |

---

## Third-Party Dependencies (Rust workspace)

| Crate | License | Notes |
|-------|---------|-------|
| omnidesk-core | Apache-2.0 | Internal |
| omnidesk-protocol | Apache-2.0 | Internal |
| omnidesk-desktop | Apache-2.0 | Internal |
| omnidesk-m4-validator | Apache-2.0 | Internal |
| windows | Apache-2.0 / MIT | External |
| windows-core | Apache-2.0 / MIT | External |
| tokio | MIT | External |
| serde | MIT | External |

---

## Compliance Notes

1. **AV1 (libdav1d)**: Apache-2.0 license — commercial use permitted with attribution
2. **HEVC**: Hardware encoder requires Windows 10+ or compatible hardware. Patent coverage assumed under OS license. Legal review required for distribution in regions with HEVC patent restrictions.
3. **H264**: Hardware encoder included with Windows. Patent coverage assumed under OS license.
4. **Audio codecs**: AAC and MP3 encoders are part of Windows Media Foundation. License coverage under OS license.

---

## Patent Risk Assessment

| Codec | Risk Level | Mitigation |
|-------|------------|------------|
| AV1 | Low | Open standard, royalty-free |
| H264 | Medium | Covered by OS license |
| HEVC | High | Patent licensing varies by region; legal counsel review required |

---

## Signoff

| Role | Name | Date | Status |
|------|------|------|--------|
| Legal Counsel | _pending_ | _pending_ | pending |
