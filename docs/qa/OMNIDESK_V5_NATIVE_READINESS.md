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

**Signed-key control path also guarded:** `TransportSessionAdapter::authorize_session` now refuses unverified channels, and `is_control_authorized`, `send` and `receive` all require an authenticated encrypted transport and verified peer identity. Positive plain TCP/loopback control tests have been replaced by explicit denial tests. No current transport implementation advertises this capability, so remote control remains blocked until an independently audited encrypted transport exists. Do not implement secure-channel capability as a hardcoded `true` on raw TCP, LAN, or relay.

**Input hygiene:** remote session password input is capped consistently at 32 characters, control characters are filtered, and disconnect clears its logical value and focus. `String::clear()` is not a secure memory wipe; secret zeroization and clipboard expiry are still required before handling real production passwords.

## V5 accessibility and dependency security follow-up

- The native AccessKit tree no longer assumes a 960x640 window for all machines; it now derives physical bounds from the actual Windows window size. Hidden trusted-device rows beyond the visible three-tile strip cannot be activated by screen-reader actions.
- The 7 V5 sidebar actions and the Remote ID, password, Connect, Copy ID, reveal/copy/rotate password controls now have stable accessible node IDs and correct bounding rectangles. The password control uses `Role::PasswordInput`, with **no node value containing the password**. All additions are on the feature branch and still require exact-HEAD Windows accessibility tests.
- `accesskit` 0.25.2 was released on 2026-10-25 with a security-relevant fix to avoid disclosing password input contents (upstream changelog). The repository's observed lockfile used 0.25.1. **Required before release:** use an isolated Cargo resolution to update that patch version and regenerate `Cargo.lock` with a legitimate checksum, then run locked tests and screen-reader regression checks. Do not manually invent a lockfile checksum or claim this update is installed.
- The live installed P520 binary and real two-PC remote sessions have not been retested after these changes. Zero paid CI spent.

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
