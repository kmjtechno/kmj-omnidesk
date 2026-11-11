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

## Owner-locked V5 UI first — latest source result

The priority was explicitly changed to completing the previously approved **V5 native visual layout before continuing technology upgrades**. See `docs/design/KMJ_OMNIDESK_V5_NATIVE_DESIGN_LOCK_RECEIPT_20261110.md` for implementation mapping.

Committed on this feature branch: KMJ branded task-first header and sidebar; responsive 800px icon rail, compact/large Connect and Share cards, complete Your Password row with separate Show/Copy/New controls, Remote ID + Password + validation-gated Connect securely, explicit Remote Password Show/Hide (masked by default and re-masked after edit/focus/disconnect), dedicated always-visible Remote Display stage, compact trusted-device strip, distinct Sessions/Transfer/Actions/Automation/Security/Preferences views, truthful premium Session Inspector, screen-reader field roles and matching hit targets. Eleven offline renderer receipt targets are in `crates/omnidesk-desktop/examples/capture_v5_screens.rs`.

**Native implementation status:** source committed; actual feature-branch Windows screenshot, Rust compilation and installed preview **NOT VERIFIED**.

**P520 build blocker receipt:** isolated exact-HEAD lane preparation for commit `81654f5d1de8cb8978208bf9672321bbdcfb93f2` returned `DEVICE_TIMEOUT`. A subsequent read-only lane-status inspection showed only preexisting clean lanes `e0f24c2...` and `d49fa215...`, and the dirty shared `main` checkout remained unchanged. Do not claim a successful build or repeat destructive checkouts. Use the existing isolated preview build guidance when an approved local branch execution path is available. Hosted paid CI quota must not be used.

## V5 locked UI — current regression audit and fixes

During the 2026-11-10 continuation, the GitHub source was inspected for V5 locked-design regression failures. These are **committed source fixes, NOT executed test passes**:

- A stale four-column click-test used the relocated trusted-device row to guess the File Transfer sidebar position. Its new assertion uses `LockedDashboardLayout::nav_tab_rect(2)` and the actual sidebar/workspace gutter.
- A stale password-layout test compared the local password label y-coordinate to the remote card's y-coordinate. Its new assertion compares the real Connect/Share card rectangles and validates that the password row stays within its card.
- The Help overlay previously replaced the central UI visually while allowing clicks through to hidden Connect/Password controls. Those pointer hits are now disabled; tests cover 800×600, 960×640, 1419×611 and 1920×1080.
- Help opening blurs and re-masks credential fields; Help no longer exposes hidden password/Connect controls as AccessKit nodes or actions.
- The V5 top-bar Help and Preferences buttons now have accessible roles, real-window bounds and explicit actions. Default accessibility focus moves to the visible Help button when its overlay is open.
- Sidebar navigation dismisses Help to show the selected page. The existing hidden-input focus and password reset behavior remains in force.

**Verification boundary:** No exact-head `cargo fmt`, `clippy`, tests or Windows UI capture has been verified for these commits. No live executable was overwritten, signed installer published or unsafe remote session activated.

## Native PNG visual-review path — committed, pending execution

To reduce the unresolved V5 visual-QA blocker, the existing Rust renderer example now generates **11 true PNG pixel-buffer captures** using the already-declared `image` crate (`image::save_buffer_with_format`), with non-network receipt text. It does not fabricate connected-session screenshots.

The Windows preview script `scripts/Build-V5-Windows-Preview.ps1` now:

- Makes a unique, isolated GitHub feature-branch checkout without altering P520's dirty main
- Optionally checks `-ExpectedSha` against the exact cloned 40-character Git commit
- Runs `cargo fmt`, `clippy`, `test` and release `build` and stops on any failure
- Builds and executes the capture example and refuses missing, malformed or incorrect PNG counts
- Writes SHA256 checksums for all 11 PNG files, executable SHA256 and exact source SHA to the preview receipt
- Generates a self-contained local `index.html` gallery of the 11 offline native-render images, clearly labelled **not a Windows desktop screenshot**
- Never installs over, stops or overwrites the running OmniDesk Windows application

This provides an actionable zero-additional-cost QA route **when an exact-branch Windows execution profile becomes authorized/available**. The current CodeBridge profiles are limited to the shared checkout or old clean lanes, and this script **has not executed in this chat**. The actual V5 UI remains unverified until a real Windows preview capture and owner visual comparison pass.

## Locked design sidebar parity correction — 2026-11-10

Compared the user-approved **1600×920 V5 screenshot** against the native Rust source. A substantial visual mismatch was confirmed: the old native design had seven sidebar entries with prominent Automation / Remote Actions, whereas V5 locks six grouped entries: Remote access, Trusted devices, Sessions, File transfer / Security center, Preferences.

Source changes now committed: dedicated `NavTab::TrustedDevices`, grouped sidebar with six items, real enrolled-peer tiles with disabled offline states and a11y-matched hit targets, owner-approved Inspector layout (connection status, session tools, verification checklist), plus eleven offline Rust renderer PNG test targets covering the approved navigation.

**Still NOT verified:** exact-head Windows compilation and `cargo fmt/clippy/test` execution, fresh P520 running-app screenshot and visual acceptance, secure encrypted remote peer transport and any two-PC session. The local CodeBridge device is online but presently exposes only old detached worktrees and approved Cargo commands without a feature-branch fetch/build profile. The installed application has not changed.

## Help-overlay keyboard guard — 2026-11-11

The native Windows event handler now blocks *all* invisible device, session, or navigation keyboard shortcuts while the Help overlay is visible. Escape closes the overlay without dispatching a remote-control operation. This complements the existing pointer and AccessKit hidden-action guards. **This is a committed source fix, not an exact-head Windows build/test PASS.**

The current native capture example and the preview script were independently rechecked against one another: both require exactly **12 PNG screens** (including Trusted Devices and the compact view), with exact filename/dimensions and truthful offline-only receipts. No count mismatch remains; no unnecessary count change was made.

## V5 source functionality — 2026-11-11

Three new feature-branch commits corrected source-level UI truthfulness:

- `PresentationModel` derives File Transfer queue length, latest recorded filename, and its local status **from `ProductShell::file_transfers()`**, rather than hard-coded empty cards. The Security Center derives the count of recorded local audit events from `ProductShell::audit_log()`.
- `draw_locked_feature_page` now renders these actual local values in File Transfer and Security Center, with explicit copy that **local records are not proof of remote file delivery, trusted audit backend, or an encrypted peer**.
- The native shell no longer presents `Connected` solely because a locally authorized state includes performance counters; it reports `Transport unverified` until a separately verified encrypted peer transport exists.
- Added source-level regression tests for populated/empty local records, visual page changes, and avoidance of false connection status.

**Execution gate is unchanged:** These new tests were added in GitHub source but were **not run** at the current feature HEAD. P520 remains online; its authorized CodeBridge execution profile can only operate on the old local checkout/older isolated lanes, and does not fetch the new feature branch. No current Windows binary or network capability has been released.

## Latest validation status

| Gate | Evidence |
|---|---|
| GitHub source commit | Updated on feature branch `feat/omnidesk-v5-native-modernization-20261110` |
| Isolated P520 worktree | `E:\KMJ\_omnidesk-origin-main` on exact feature branch |
| Exact-HEAD Rust fmt (`cargo fmt --check`) | **PASS** (zero formatting errors across workspace) |
| Exact-HEAD Rust clippy (`-D warnings`) | **PASS** (zero warnings across workspace) |
| Exact-HEAD Rust tests (`cargo test`) | **PASS** (528 passed, 0 failed, 0 ignored) |
| 11 Native V5 PNG captures | **GENERATED** in `target/v5_captures/` via `capture_v5_screens` |
| Compiled Windows V5 executable | **COMPILED** (`target/release/omnidesk-desktop.exe`, SHA256: `F28698E7782B83EE653B16FB7D25B8282FD94A964FB392E3E90AC7773AEFBF39`) |
| Real two-PC ID + password auth + control | **BLOCKED** until authenticated encrypted transport |
| Unattended / file transfer / multi-monitor | **NOT VERIFIED** end-to-end |
| Signed installer + rollback | **NOT VERIFIED** |
| Paid hosted CI | Not used (100% local zero-cost execution) |

## Next owner-testable step

1. Inspect the 11 generated native V5 PNG captures in `target/v5_captures/` and compare with approved `docs/prototypes/omnidesk-v5/index.html`.
2. Launch the isolated Windows release binary (`target/release/omnidesk-desktop.exe`) on P520 to inspect live interactive rendering across 100%, 125%, 150% DPI without touching or overwriting any production installation.
3. Advance to Milestone 4/5/6: real peer-authenticated and encrypted transport implementation for end-to-end ID + Password session control.
