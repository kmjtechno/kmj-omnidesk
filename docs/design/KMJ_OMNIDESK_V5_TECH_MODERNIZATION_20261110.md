# KMJ OmniDesk V5 — Native UI and 2026 technology modernization

Date: 2026-11-10 · Branch: `feat/omnidesk-v5-native-modernization-20261110`

## Change scope (delivered in this branch)

- Native Rust UI: KMJ TECHNO desktop branding, remote-access-specific navigation, V5 share/connect card labels, and revised graphite/red tokens.
- Geometric layout: separate **Your Password** and **Session Password** readiness rows. Layout + renderer tests ensure the new rows stay within their own cards at desktop viewports.
- Passwords currently read **NOT CONFIGURED**. They are **not** fake random secrets; these read-only slots are deliberately disabled. Remote ID still uses the existing verified-peer/target-permission path, not a new insecure password bypass.
- Removed an unverified blanket claim that direct E2E encryption / LAN / relay are all ready. Verified status must come from real transport evidence.
- Rust stable toolchain pinned to **1.99.1** (Rust team release of 2026-10-15) for reproducible future builds; the workspace continues to declare its existing 1.85 MSRV pending compatibility verification.

## Dependency baseline read from upstream Cargo.lock

| Crate | Current locked version | Decision |
|---|---|---|
| winit | 0.30.13 | Keep until native Windows event-loop QA passes against an evaluated newer release |
| softbuffer | 0.4.8 | Keep for lightweight CPU software-rendering budget until GPU/codec benchmarks justify a migration |
| accesskit | 0.25.1 | Hold pending accessibility API compatibility review |
| accesskit_winit | 0.34.1 | Hold alongside AccessKit version matrix |
| image | 0.25.10 | Hold until memory/format/license validation |
| ed25519-dalek | 2.2.0 | Treat as security-critical, do not unreviewedly change wire signatures |
| serde | 1.0.229 | Evaluate semver-compatible updates in a clean pinned worktree |
| serde_json | 1.0.151 | Evaluate semver-compatible updates with lockfile, parser and protocol regression tests |
| sha2 | 0.10.9 | Hold pending transcript/wire tests |
| ab_glyph | 0.2.32 | Keep compatibility with existing native font renderer |

The versions above are **observed locked versions, not claims that they are the latest available**. Any update must be resolved by Cargo and tested against the exact branch; never hand-edit Cargo.lock or force an unverified major bump. Preserve the owner's P520 dirty lockfile and shared checkout.

## Safe remaining implementation gates

1. Bring the exact new branch into a **separate clean checkout** on P520 without resetting or cleaning the existing main; verify installed Rust 1.99.1 before running builds.
2. `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`, `cargo test --locked --workspace --all-targets --all-features`; verify concrete SHA and exit codes. No paid GitHub Actions minutes.
3. Native UI capture & hit-map/keyboard/accessibility QA at 1024x768, 1280x800, 1920x1080 and 100%/125%/150% DPI.
4. Implement and review a real local temporary credential lifecycle: generation using approved OS randomness, secret-handling/zeroization, expiry/rotation, independent peer identity verification and password proof on the authenticated encrypted session. Do not send password plaintext or persist it in project files/logs.
5. Native remote password input must be masked and excluded from `PresentationModel`/accessibility announcements; require real server-side attempt limits and no password-only unattended/admin access.
6. Two independent Windows PC sessions must demonstrate authenticated peer, consent/unattended policy, input, clipboard, file transfer, multi-monitor, disconnection/replay/revocation/weak-network handling.
7. Review target-specific dependency releases, OS support, MSRV, feature flags, vulnerabilities, licenses and protocol compatibility **before** increasing crate versions; create one isolated update batch at a time with rollback receipts.
8. Packaging/signature, restore/rollback, and commercial release decisions remain separate from UX design.

## QA status

- **PASS:** P520 prior local checkout baseline `cargo_verify:test` exit 0 on 2026-11-10. That checkout was **54 commits behind** GitHub main and has dirty files.
- **NOT YET RUN:** exact-head compile, tests, formatting, native Windows capture of *this branch*. GitHub Actions quota/zero-spend constraint intentionally means no paid CI has been triggered for this work.
- **NOT SHIPPED:** working ID+Password remote control, full V5 prototype-to-native parity and signed Windows binary.

This document is a gated implementation receipt, not a production release claim.
