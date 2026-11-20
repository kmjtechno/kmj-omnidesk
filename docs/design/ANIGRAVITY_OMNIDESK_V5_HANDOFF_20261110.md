# ANIGRAVITY HANDOFF — KMJ OmniDesk V5

**Owner-approved direction, 2026-11-10:** Finish the actual native Windows OmniDesk product from the complete V5 design now committed on GitHub; modernize outdated technology safely; **zero additional paid services**. KMJ Main Platform is only a design/brand reference, **not** the desired business dashboard layout. Deliver **one Windows application across PCs**, with ID + Password secure remote control and correct device/session capabilities.

## Clone and source-of-truth (GitHub first)

- Repository: `kmjtechno/kmj-omnidesk`
- Work branch: `feat/omnidesk-v5-native-modernization-20261110`
- **Exact interactive final V5 design:** `docs/prototypes/omnidesk-v5/index.html` (offline, self-contained HTML with embedded first-party brand image; no network requests)
- Prototype instructions and QA evidence: `docs/prototypes/omnidesk-v5/README.md`, `QA_REPORT.json`
- Design direction: `docs/design/KMJ_OMNIDESK_REMOTE_WORKSPACE_V5_20261110.md`
- Modernization inventory / remaining gates: `docs/design/KMJ_OMNIDESK_V5_TECH_MODERNIZATION_20261110.md`

**Do not infer that these browser screens are native production implementation.** They are a final design reference; the native Rust code is only partially updated.

## Already committed on the branch

- `crates/omnidesk-desktop/src/lib.rs`: KMJ TECHNO graphite/near-black/red palette.
- `crates/omnidesk-desktop/src/layout.rs`: V5 share/connect card geometry; separate local/remote password readiness rows; responsive side-by-side layout on wide screens, stacked on smaller desktop widths; unit tests.
- `crates/omnidesk-desktop/src/render.rs`: branded navigation, remote-workspace labels, truthful `Your Password / Not configured`, `Session Password / Not configured`, offline remote display area, no bogus “LAN & relay ready” blanket claim; renderer test.
- `rust-toolchain.toml`: Rust stable toolchain pinned at `1.99.1` for repeatable release testing, **pending exact-branch confirmation**. Workspace `rust-version = "1.85"` is unchanged.
- Existing security and trust code must remain fail-closed.

## Critical environment constraints

P520 / `DESKTOP-5FVJMET`, project checkout at `E:\KMJ\KMJ OmniDesk`, is online through CodeBridge, but its **shared `main` checkout was 54 commits behind origin/main** with user modifications to `Cargo.lock` and scripts plus untracked files. **NO git reset, clean, forced checkout, or blind pull on that shared directory.** Fetch the specific GitHub feature branch and create a separate new worktree/clone in an owner-authorized project directory. Never overwrite ongoing local work.

The previous P520 checkout's `cargo_verify:test`, `clippy`, and `format_check` returned PASS; **those were not runs of this new GitHub branch**. Record exact-head SHA and local job results before making any QA claim. GitHub Actions quota was exhausted: **no paid hosted CI**, prefer P520/local test execution. Creating a PR may automatically trigger `pull_request` CI; avoid spending hosted quota before it is approved/available.

## Mandatory work in order

1. **Exact branch bring-up:** isolated fetch/checkout. Validate Rust toolchain installation/pinning and dependency MSRV/lockfile on Windows. Do not hand-edit lockfile.
2. **Native V5 parity:** adapt desktop renderer/layout/host/accessibility to match the task-focused `index.html`: KMJ TECHNO brand; Remote ID + Password connect panel; Your ID + Password share panel; remote display canvas, toolbar, session inspector; trusted devices, sessions, file transfer, security and preferences. Align pointer hit-testing, DPI and keyboard/AccessKit nodes with draw geometry.
3. **Real local password lifecycle:** use reviewed cryptography/OS entropy, ephemeral secure handling, expiration, regeneration, revocation, explicit masked/reveal/copy choices. **No demo password** in production UI or logs.
4. **Real authentication:** Remote ID is a locator, not proof. Cryptographically verify peer and a replay-resistant password proof over an authenticated encrypted transport; enforce rate limits/timeouts, refuse wrong/replayed/revoked credentials. Never transmit plaintext secrets, weaken trust store, silently elevate privileges or allow password-only administrator/unattended access.
5. **Remote control:** verified peer + scoped target consent (or separately authorized unattended grant) required before real mouse/keyboard/display/clipboard/file transfer. Enable fullscreen, multi-monitor, quality/performance choices only with verified session and measured values.
6. **Current dependency review:** inspect resolved versions and security/license compatibility (`winit`, `softbuffer`, `accesskit`, `accesskit_winit`, `image`, `ed25519-dalek`, `serde`, etc.). Upgrade in isolated compatible batches; benchmark GPU/codec decisions, don't switch native framework merely for novelty. Keep deterministic lockfile and rollback.
7. **Local QA:** `cargo fmt --all -- --check`; `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`; `cargo test --locked --workspace --all-targets --all-features`. Capture actual Windows screenshots at 1024×768, 1280×800, 1920×1080; 100/125/150% DPI. Test no clipping, accurate keyboard/focus, screen-reader roles, password masking/zeroized flow and truthful disconnected states.
8. **Two PC real network QA:** Windows P520 plus a second independently trusted computer, verify local device identity, real ID+password login, denial/replay/revocation, LAN + relay recovery, multi-monitor, clipboard, file transfer, screen frame/media and disconnect. Do not manufacture successful network or FPS evidence.
9. **Release:** separate signed package and rollback gates; publish only after owner-approved verified release acceptance. Main Platform production, licensing and keys remain untouched.

## Definition of done

A new owner-testable Windows build from an exact GitHub commit with documented zero-cost passing native tests, verified two-machine remote control using real ID+password, no unsafe fallback, correct UI/screenshots, and rollback/signature evidence. Explicitly report unresolved blockers rather than declaring 100% success.

## How to report back on GitHub

Commit each isolated tested increment to the same feature branch or focused branches based on it. Keep a running `docs/qa/OMNIDESK_V5_NATIVE_READINESS.md` with SHA, test command, exit code, captured artifacts and remaining gaps. **Do not merge unverified auth/transport into `main`.** The owner can review the branch and handoff without needing any local sandbox paths or old ChatGPT conversation context.
