# OmniDesk V5 — P520 physical native acceptance protocol (2026-11-11)

Status: **NOT EXECUTED / NOT ACCEPTED**. This is a reproducible owner-locked visual QA procedure, not a Windows test receipt. Source baseline when authored: `c7afe58c612eed493a489ae35c9beb2845794c66`. Always resolve the current branch HEAD anew before running.

## Preconditions (fail closed)
1. Independently verify P520 device identity `kmj-kmj-omnidesk-desktop-5fvjmet`, CodeBridge project grants, and administrator-approved command profile. No arbitrary remote shell or command substitution.
2. Preserve the dirty shared checkout at `E:\KMJ\KMJ OmniDesk`. Never reset, clean, pull into, or overwrite it. Use only an explicitly authorized isolated exact-SHA lane; `scripts/Build-V5-Windows-Preview.ps1 -ExpectedSha <verified-40-hex-sha>` is a **reference procedure**, not an authorization to execute.
3. Record GitHub branch SHA, isolated checkout SHA, build binary SHA256, Rust toolchain versions, Windows version, physical display scale, monitor resolution, and capture timestamp. Stop if any SHA differs.
4. Require exact-head `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`, `cargo test --locked --workspace --all-targets --all-features`, and isolated Windows release build PASS. Do not use older shared-checkout or unrelated CI evidence.

## Physical capture matrix
For each client area **800x600, 960x640, 1024x768, 1419x611, 1920x1080**, capture a **real running native Windows window** at its measured client dimensions, not browser HTML, a resized screenshot, or `capture_v5_screens` pixel buffers. Record actual window bounds, DPI scale, monitor ID, screenshot SHA256, and whether the OS window was foreground. If the machine cannot present a size faithfully, mark that row BLOCKED rather than stretching an image.

For each viewport compare side-by-side with `docs/prototypes/omnidesk-v5/index.html` and `docs/design/KMJ_OMNIDESK_V5_NATIVE_DESIGN_LOCK_RECEIPT_20261110.md`: KMJ logo/brand, top bar, grouped six-entry navigation, Connect/Share card order, Remote ID and masked password, Connect CTA, remote display stage, compact device strip, Session Inspector, text truncation, spacing, contrast, and scroll/overflow. At 800/960 the compact icon rail must be usable; at 1024/1419 inspect inspector collapse; at 1920 inspect three-column balance. Record each mismatch with screenshot coordinates and source file.

## Keyboard and pointer geometry
At **every viewport**: Tab/Shift+Tab through visible fields and controls; Enter and Space on focused buttons; Escape blur/cancel; Backspace while editing; test letters `s,c,f,m,o,d` in password field without sidebar navigation; click text-field edges, Show/Hide, Copy/New, Connect, rail icons, stage border, device strip and blank chrome. Verify no invisible/overlapping click targets and no action on a hidden page. Record the focused accessible node and resulting state. Missing/invalid/self Remote ID or blank password must not claim a connection. Reveal must reset on edit, blur, navigation, and disconnect.

## Separate feature pages and accessibility
Capture Trusted Devices, Sessions, File Transfer, Security Center and Preferences at 1419x800; capture Trusted Devices at 960x640. Verify each page has distinct native content and truthful empty states. Inspect Windows UI Automation/AccessKit names, roles, focus order and bounds with a real screen reader; ensure password input is identified as secret and its value is never exposed. Test 100%, 125%, 150% Windows scaling on a supported display and document actual pixel/client sizes. Contrast failures and clipping are blockers, not cosmetic warnings.

## Truth, safety and evidence
No physical screenshot, measured latency, FPS, connected peer, encrypted session, or secure ID+Password transport may be marked PASS without independent real evidence. Offline renderer's 12 PNGs and `RECEIPT.txt` prove only pixel-buffer capture. Keep `WINDOWS_NATIVE_*=NOT_VERIFIED` and `V5_LOCKED_DESIGN_PARITY=NOT_ACCEPTED` until physical checks pass. Do not edit these fields by hand to create a success receipt. Never install or replace the existing executable, merge to main, start paid Actions, or activate a network listener as part of visual QA.

## Evidence record (one row per viewport)
`source_sha | binary_sha256 | windows_build | dpi_percent | client_px | screenshot_path | screenshot_sha256 | navigation | layout_parity | keyboard | pointer_hit | contrast | accesskit | observed_defects | reviewer | timestamp_utc`

Acceptance requires all five viewport rows PASS plus distinct feature-page captures, Windows screen-reader evidence, DPI evidence, and resolved P0 defects. A partial run is **INCOMPLETE**, never commercial-release approval. Secure authenticated transport work begins only after this native UI acceptance gate.
