# KMJ OmniDesk V5 — Native Readiness and Release Gate

**Updated:** 2026-11-10  
**Status:** **BLOCKED — UI source revised, but exact-branch build, native screenshot and secure remote-control release are not verified.**  
**Branch:** `feat/omnidesk-v5-native-modernization-20261110`

## Critical correction to earlier readiness claims

An earlier version of this report asserted complete UI parity, 522/522 passing tests, encrypted remote control, measured 2 ms latency / 60 FPS, and a deployed Windows executable. Those are **not accepted as current release evidence**. The user's 2026-11-10 11:06 screenshot showed an outdated four-column interface, and source inspection identified hard-coded connection metrics and a plain-TCP password-proof path that automatically granted access. No exact-head build/CI evidence after the corrective commits has been observed.

Do not treat previous success text or screenshots as authoritative evidence of product readiness.

## Changes committed to the GitHub feature branch

- Native UI geometry changed from permanent `nav | devices | workspace | inspector` to `nav | wide remote workspace | optional inspector`; at >=1024 px the inspector can collapse. Trusted devices are now a compact strip below the workspace.
- Remote ID and masked password fields placed before the Connect CTA, with standalone Share This Device ID/password card.
- KMJ TECHNO dark graphite and controlled red visual language; default screen prioritizes remote access rather than a business-admin dashboard.
- Removed invented live 60 FPS/codec/encryption values from the session overlay.
- Removed fake hard-coded device directory and historical transfer/status content from the desktop renderer.
- `windows_host.rs` now **refuses** remote and inbound sessions without verified encrypted peer transport and consent. The temporary listener is loopback-only, not publicly exposed. Disconnected is the truthful default.
- Prevented invisible trusted-device row clicks outside the new device strip.
- Existing `Cargo.toml` and the shared P520 working checkout were not reset/cleaned.

## Security blocker — must be fixed before real ID/password access

The earlier implementation accepted HMAC password proofs over a raw TCP channel, accepted session claims without a mutually authenticated encrypted transport, used local loopback fallback for apparently remote KMJ IDs, and filled metrics with hard-coded values. This fails the product's zero-trust design goal. A password-proof alone is **not an authenticated remote-control session**.

Future work must bind password proof to a reviewed mutually authenticated encrypted channel, verify target identity and session transcript, reject replay/guesses, isolate privileges, obtain explicit remote-user permission (or independently scoped unattended grant), and route actual decoded screen frames into the native display. Do not restore any previously removed auto-authorization or fake metric path to make demos look successful.

## Additional low-level password proof guard (2026-11-10)

The `Transport` interface now defaults `is_peer_authenticated_and_encrypted()` to `false`; all current loopback/TCP transports inherit this fail-closed default. The core host and client password authentication entrypoints refuse a raw password proof until a future independently verified encrypted, mutually authenticated transport explicitly implements that capability. A former integration test which expected password login to succeed on raw TCP has been replaced by a negative regression test.

**These are committed source changes, not executed Windows QA evidence.** The source is intentionally not production functional for ID+Password remote control at present.

**Remaining protocol-level blocker:** The signed-key `TransportSessionAdapter::authorize_session` / `send` / `receive` path also needs independent encryption/channel-binding admission before real remote input or screen data may be enabled. It must not be considered safe solely because an Ed25519 challenge passes. Do not implement secure-channel capability as a hardcoded `true` on raw TCP, LAN, or relay.

## Latest validation status

| Gate | Evidence |
|---|---|
| GitHub source commit | Updated on feature branch; changed paths verified |
| Existing P520 shared checkout baseline | Earlier `cargo_verify:test`, Clippy and format PASS, **before these new branch changes** |
| Exact-HEAD Rust fmt/clippy/test | **NOT RUN** after layout/security changes |
| Compiled Windows V5 executable | **NOT VERIFIED** after changes |
| New V5 screenshot from actual Windows app | **NOT VERIFIED** |
| Real two-PC ID + password auth + control | **BLOCKED** until authenticated encrypted transport |
| Unattended / file transfer / multi-monitor | **NOT VERIFIED** end-to-end |
| Signed installer + rollback | **NOT VERIFIED** |
| Paid hosted CI | Not used |

## Next owner-testable step

An isolated Windows preview build must be taken from exact feature-branch SHA with local Rust checks, then run side by side **without overwriting the currently installed program**. A guarded helper is supplied at `scripts/Build-V5-Windows-Preview.ps1`. Anigravity / authorized local operator can execute that script on P520. A build is not a production release.

**Acceptance criterion:** show a fresh screenshot of the actual installed preview with the V5 3-column workspace and record exact binary SHA, toolchain, test receipts, and security status. Then implement real transport/media and repeat full two-PC QA. Only promote to production after security + release gates are independently green.
