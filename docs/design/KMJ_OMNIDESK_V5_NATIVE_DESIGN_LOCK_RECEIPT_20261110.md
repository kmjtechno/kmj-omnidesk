# KMJ OmniDesk — Locked V5 Native UI Implementation Receipt

**Owner priority, 2026-11-10:** Finish the previously approved V5 design FIRST. KMJ Main Platform supplies brand tokens, not an admin-dashboard copy. No claims of tested Windows release until exact-head build and fresh native screenshots.

## Canonical source of truth

- `docs/prototypes/omnidesk-v5/index.html`: exact approved interactive browser V5
- `docs/design/KMJ_OMNIDESK_REMOTE_WORKSPACE_V5_20261110.md`: functional hierarchy
- This branch: `feat/omnidesk-v5-native-modernization-20261110`

## Native Rust implementation committed

| Locked design requirement | Native implementation location | Source status |
|---|---|---|
| Full KMJ TECHNO logo / dark graphite / restrained red | `brand.rs`, `lib.rs::VisualSystem`, `render.rs::draw_locked_header` | Committed |
| Remote-specific navigation, not Main Platform business metrics | `layout.rs::nav_tab_rect`, `render.rs::draw_locked_navigation` | Committed |
| Main Remote Access page, distinct Connect and Share cards | `layout.rs::{remote_id_card_rect,your_id_card_rect}`, `render.rs` | Committed |
| Remote ID + password; valid input enables Connect securely | `presentation_for`, `action_at_point`, `render.rs::draw_locked_remote_id_card` | Committed (network access still fail-closed) |
| Remote Password Show/Hide (masked by default, reset on edit/focus/disconnect) | `ProductShell`, `PresentationModel`, `layout.rs`, `render.rs`, `accesskit_tree.rs` | Committed; non-network UI only |
| Your ID, password status, Show/Hide, Copy, New | `layout.rs`, `render.rs::draw_locked_your_id_card`, native actions | Committed (no unverified host authentication) |
| Separate truthful Remote Display stage under forms | `layout.rs::remote_stage_rect`, `render.rs::draw_locked_dual_role_cards` | Committed |
| Compact trusted-device strip and session toolbar | `layout.rs::{devices,session_toolbar}`, `render.rs` | Committed |
| Locked six-entry sidebar and grouped Workspace / Protection sections | `layout.rs::nav_tab_rect`, `render.rs::draw_locked_navigation`, `accesskit_tree.rs` | Committed source; Windows visual QA pending |
| Separate Trusted Devices directory with enrolled peer tiles | `render.rs::draw_locked_trusted_devices_page`, `layout.rs::trusted_device_tile_rect`, `lib.rs` | Committed source; backend trust policy and real peer QA pending |
| Distinct Sessions / File Transfer / Security / Preferences pages | `render.rs::draw_locked_feature_page` | Committed truthful empty-state layouts; backend features unverified |
| Premium Session Inspector with real-only connection metrics | `render.rs::draw_locked_inspector` | Committed; no fake latency/FPS/encryption |
| Compact 800–1023px icon rail without obsolete fallback | `layout.rs::for_window`, `render.rs::draw_locked_navigation` | Committed |
| Accessibility labels/roles, actual window size, no hidden actions | `accesskit_tree.rs`, `windows_host.rs` | Committed; physical Windows screen-reader QA pending |
| Native renderer capture matrix (12 safe offline screen/size combinations) | `examples/capture_v5_screens.rs` | 12 PNG targets in current script; historical 11-PNG execution does not verify current exact HEAD |

## Built-in V5 regression tests verified

- Card/Stage/Toolbar/Device-strip boundaries at 800x600, 960x640, 1024x768, 1180x600, 1419x611, 1920x1080
- Password text vs Show/Copy/New buttons: no overlapping hit targets
- Remote Password reveal control stays inside the input; masked by default; screen reader never gets the raw secret; reveal resets on input edit or disconnect
- Invalid/self Remote ID and missing password keep Connect CTA disabled
- Remote Access clicks and screen-reader nodes inaccessible on unrelated tabs
- Actual Windows accessibility dimensions rather than fixed 960x640
- Visible Remote Display stage border in offline native pixel render
- Sessions/Transfer/Actions/Security/Preferences differ from Remote Access
- No faked connected session metrics or successful raw TCP remote control

**All 528 tests across workspace passed (`cargo test --locked --workspace --all-targets --all-features`).**

## Native interaction fixes committed in the current continuation

- Compact Remote ID field height reduced to preserve a visible gap before the Session Password label at 800×600, 960×640, 1180×600 and 1419×611; source geometry regression test added
- Windows password typing takes precedence over global sidebar shortcuts, so `s/c/f/m/o/d` cannot accidentally switch pages when typed inside the password field
- Physical keyboard `Tab` switches Remote ID / Password focus; `Backspace`, `Enter`, and `Escape` are handled explicitly while editing either credential
- Clicking noninteractive window chrome blurs both credential fields; remote-password reveal resets on blur
- Sidebar transitions clear hidden password state and focus; Copy Device ID releases password focus
- Copy Your ID and Copy Your Password now invoke the Windows clipboard only on explicit user action and do not report success when OS clipboard execution fails; password content is passed via child stdin, not argv or logs
- Added source regression tests for shortcut-safe credential input, compact field separation, secret re-masking on blur/navigation, and disabled ghost click behavior

**QA distinction:** these are GitHub source commits with static audit receipts, not proof that the new Windows preview compiled or passed tests. Exact feature-branch local build and fresh Windows screenshots remain mandatory.

## Continued source-level V5 regression fixes — 2026-11-10

- Repaired old four-column pointer regression: File Transfer is checked against the actual V5 sidebar rectangle, not the moved trusted-device row
- Repaired incorrect side-by-side test: compare actual Connect/Share card bounds rather than a password label's y position
- Help replaces the central Remote Access canvas; pointer actions can no longer click through to invisible Remote ID, password, reveal, Connect or Copy ID
- Help opening blurs both remote credential fields and re-masks the password; screen-reader tree omits hidden credential nodes and their actions
- The Help and Preferences top-bar buttons now have accessible roles, real-window rectangles and tested focus; when Help is open, accessible default focus moves to its visible toggle
- Sidebar selection closes Help so the requested page becomes visible; the existing password clearing and focus reset remain in force
- New tests document help-click isolation, screen-reader node omission, topbar focus, and sidebar overlay dismissal

**Verification boundary:** all fixes above are committed Rust source/tests, but neither exact-branch Cargo execution nor an actual P520 native Windows screenshot was available through the current authorized execution lane. Source inspection does not count as a passing build. Do not overwrite the installed executable.

## Owner-locked V5 navigation and Session Inspector parity

The approved `preview-desktop.png` design has **four Workspace entries** (Remote access, Trusted devices, Sessions, File transfer) and **two Protection entries** (Security center, Preferences). The earlier native renderer incorrectly used seven navigation entries with prominent Remote Actions / Automation instead of Trusted devices. This has been corrected at source level:

- Added `NavTab::TrustedDevices` to the product shell, with six visible, grouped native sidebar entries and matching accessible roles and keyboard/pointer actions
- Rendered a real Trusted Devices directory from the locally enrolled peer catalog instead of invented online devices; offline entries are disabled
- Added shared trusted-device tile rectangles for rendering, pointer hit targets and screen readers, with source-revision and visible-index checks so stale filter rows cannot retarget actions
- Preserved advanced remote actions/automation in internal application views, rather than adding unapproved top-level navigation items
- Restructured right-rail Session Inspector into Connection Status, Session Tools, and an explicit three-item Verification Checklist; no made-up FPS, encryption or remote screen is displayed
- Updated the native offline PNG capture plan to cover all six locked sidebar destinations, including Trusted Devices at compact 960×640

**Evidence limitation:** the feature-branch Rust source has been updated; these exact changes have NOT been successfully compiled into a real Windows executable or visually accepted on P520 yet.

## Exact-head local acceptance on P520

1. Use a **fresh isolated checkout** of the branch, never reset/clean the dirty shared `E:\KMJ\KMJ OmniDesk`.
2. With reviewed toolchain/lockfile, run `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`, `cargo test --locked --workspace --all-targets --all-features`.
3. Generate non-network V5 Rust-renderer captures: `cargo run --locked -p omnidesk-desktop --example capture_v5_screens -- target/v5_captures`. The current example targets **12 PNG images** and a receipt, rather than raw PPM files; compare them with the approved V5 `index.html`. These are actual renderer pixel buffers, **not Windows desktop screenshots or live sessions**.
4. Build and run the isolated Windows preview: `scripts/Build-V5-Windows-Preview.ps1`. Capture **real running Windows executable** at 800x600, 960x640, 1024x768, 1419x611, 1280x800, 1920x1080 and 100%/125%/150% DPI. The native PPM images are not a substitute for this.
5. Verify click alignment, Tab navigation, accessibility, password visual masking, stable output, screenshot comparison and *no invented session status*. Record binary SHA and QA exit codes.
6. Only after the design is visually accepted, finish **real** encrypted/verified ID+Password session, media/control protocol, file transfer, multi-monitor and two-PC QA. Never unblock unsafe plaintext login to make the UI seem complete.

## Zero-cost preview build workflow (new)

`scripts/Build-V5-Windows-Preview.ps1` requires mandatory `-ExpectedSha <full-40-hex>`, refuses a mismatched GitHub checkout, runs Cargo formatting/lint/tests/release build, then generates and checks 12 offline Rust-rendered PNG captures under the isolated preview folder. The generated receipt includes source SHA, executable SHA256, and explicitly marks physical Windows screenshot and secure remote access as **NOT VERIFIED**. It never overwrites the installed OmniDesk application.

Actual isolated P520 command execution remains blocked by the current CodeBridge profile; the script is committed and ready for an authorized local operator/Antigravity runtime, but **it has not been run in this chat**.

## Verification & Build Receipts

- Isolated worktree: `E:\KMJ\_omnidesk-origin-main` on branch `feat/omnidesk-v5-native-modernization-20261110`
- `cargo fmt --all -- --check`: PASS (zero errors)
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`: PASS (zero warnings)
- `cargo test --locked --workspace --all-targets --all-features`: PASS (528 tests passed, 0 failed)
- Historical 11 PNG captures generated in `target/v5_captures/`; current 12-capture exact-HEAD matrix remains unverified on P520
- Release executable built: `target/release/omnidesk-desktop.exe` (SHA256: `F28698E7782B83EE653B16FB7D25B8282FD94A964FB392E3E90AC7773AEFBF39`)

**Historical receipt:** A previous V5 revision passed 528 local Rust tests and produced 11 offline PNGs plus a Windows executable. That does **not** verify the further 12 November reference-geometry and scroll fixes. **Current-source exact-HEAD Cargo build, 12-PNG inspection, real running Windows screenshots and owner design acceptance remain pending.** See `docs/qa/OMNIDESK_V5_APPROVED_REFERENCE_GEOMETRY_20261112.md`.
