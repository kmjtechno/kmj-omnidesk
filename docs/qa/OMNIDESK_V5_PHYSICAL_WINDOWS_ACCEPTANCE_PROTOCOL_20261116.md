# OmniDesk V5 — physical Windows screenshot acceptance protocol (P0)

**Status: NOT EXECUTED.** This is an inspection protocol, not evidence of a Windows build, screenshots, or design parity. Use the owner-locked `docs/prototypes/omnidesk-v5/index.html` and `docs/qa/OMNIDESK_V5_APPROVED_REFERENCE_GEOMETRY_20261112.md` as the only visual reference.

## Preconditions (fail closed)

1. On P520, use an administrator-approved **isolated exact-feature-SHA** execution profile. Never run Cargo in or reset/clean the dirty shared `E:\KMJ\KMJ OmniDesk` checkout. Do not substitute a cached `main` worktree for the feature branch.
2. Record the feature branch's independently fetched 40-character Git SHA and match it to the isolated checkout **before and after** testing. Any mismatch means STOP, not a partial PASS.
3. Run `scripts/Build-V5-Windows-Preview.ps1 -ExpectedSha <verified-sha>` only via the approved isolated Windows execution mechanism. Require `fmt --check`, locked Clippy/tests/release build, **13** renderer PNGs, source-integrity and PNG-dimension receipts. The PNGs are offline renderer buffers, **not** physical Windows screenshots.
4. Launch only the isolated preview EXE in the owner's interactive Windows desktop; preserve installed EXE and production settings. Capture the running application's **client area** with exact pixel dimensions, Windows DPI scaling, title-bar offset and font scaling recorded. Do not rescale screenshots after capture.

## Physical screenshot matrix (all required)

| Client viewport | Critical acceptance target |
|---|---|
| 800×600 | Icon rail; accessible controls; center scroll; no card-caption collision |
| 960×640 | Icon rail at the <=1020 breakpoint; scroll/hit alignment |
| 1024×768 | Full navigation, hidden inspector, two 363px cards and 315px stage; compare approved geometry |
| 1308×777 | Reproduce owner's defect viewport; no 173px mini-cards, caption overlap or inspector |
| 1309×777 | Separate owner screenshot gate; compare against `12_owner_screenshot_1309.png` as **offline** secondary evidence only |
| 1419×611 | Hidden inspector; scroll; no clipped interactive labels |
| 1600×920 | Inspector visible; full branded header, cards, stage and sidebar |
| 1920×1080 | Inspector visible; wide responsive layout and focus/hit targets |

At <=1510px the Session Inspector must not consume a column; at <=1020px the navigation must be an icon rail. At 1024×768 and 1308×777, check the reference coordinates in the geometry receipt with a documented tolerance for native DPI/title-bar and rasterization differences. Do **not** pass based on geometry alone: inspect actual text baselines, field-label separation, rounded corners, colors, fonts, clipping, scrollbar and Remote Display. Verify Connect/Share height **363px** and Remote Display stage **315px**, rather than the obsolete 173px cards.

## Interaction and accessibility evidence

For each viewport, test pointer activation and keyboard focus of Remote ID, Remote Password Show/Hide, Connect (disabled/denied truthfully), Copy ID, Your Password Show/Copy/New, navigation, Help and scrolling. Confirm scroll-transformed pointer and AccessKit bounds agree with the visible targets; no hidden inspector, offscreen device row or Help-obscured control may activate. Record a screenshot before and after center scrolling at 1024×768 and 1308×777. Verify focus outlines and label legibility at 100% and the actual P520 display DPI. Never enter production credentials in screenshots.

## Receipt and decision

Store the exact source SHA, binary SHA256, Rust/toolchain versions, isolated checkout identity, command exit codes, 13 PNG hashes, eight original physical captures, Windows build/DPI, and per-viewport visual/hit-test PASS/FAIL with a concrete defect description. Distinguish `OFFLINE_RENDER_PNG` from `RUNNING_WINDOWS_EXE_SCREENSHOT`. Any missing capture or mismatch => `NATIVE_V5_VISUAL_ACCEPTANCE=BLOCKED`. A reviewer must approve all eight physical captures before changing that status. This protocol never authorizes remote control, main merge, release, or installed EXE replacement.
