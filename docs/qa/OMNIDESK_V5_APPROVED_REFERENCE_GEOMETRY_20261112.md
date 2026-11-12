# KMJ OmniDesk V5 — Approved Reference / Native Geometry Receipt

**Date:** 12 November 2026  
**Source of truth:** `docs/prototypes/omnidesk-v5/index.html` (the owner-locked V5 design, not a new image).  
**Status:** **SOURCE GEOMETRY ALIGNED; NATIVE WINDOWS SCREENSHOT NOT YET VERIFIED.**

## The actual visual defect reported by the owner

The 1308 × 777 Windows screenshot shows the old cramped UI: 173px-tall Connect/Share cards, overlapping headings and field labels, a permanently occupying Session Inspector, and collapsed Remote Display/toolbar panels. The approved browser reference uses a 75px header, ~30px premium hero and **363px cards** above a separately labeled **315px Remote Display**. The browser permits vertical scrolling rather than crushing its content.

The feature branch now replaces height-dependent mini-cards with fixed reference geometry and center-only wheel scrolling. The KMJ branded header, navigation rail and Session Inspector remain fixed. Help and screen-reader focus preserve native hit-target alignment. The locked HTML hides the Session Inspector at viewport widths of 1510px or less (`@media(max-width:1510px)`), and switches the navigation to the compact icon rail at 1020px or less (`@media(max-width:1020px)`). Native Windows screenshots must independently verify these responsive states; source geometry is not physical-app acceptance. Raw TCP control remains intentionally blocked until authenticated encryption exists.

## Real reference measurements vs native source geometry

Measurements of the locked HTML's DOM boxes in Chromium, at 100% device scale; native geometry is derived from `LockedDashboardLayout` and enforced in source tests.

| Viewport | Approved HTML Connect x/y/w/h | Rust Connect x/y/w/h | Approved HTML Share x/y/w/h | Rust Share x/y/w/h | Approved stage x/y/w/h | Rust stage x/y/w/h |
|---|---|---|---|---|---|---|
| 1024×768 | 249 / 217 / 380 / 363 | 249 / 216 / 380 / 363 | 645 / 217 / 352 / 363 | 645 / 216 / 351 / 363 | 249 / 660 / 748 / 315 | 249 / 660 / 747 / 315 |
| 1308×777 | 249 / 219 / 528 / 363 | 249 / 218 / 527 / 363 | 793 / 219 / 488 / 363 | 792 / 218 / 488 / 363 | 249 / 662 / 1032 / 315 | 249 / 662 / 1031 / 315 |
| 1600×920 | 253 / 227 / 524 / 363 | 253 / 226 / 524 / 363 | 793 / 227 / 485 / 363 | 793 / 226 / 485 / 363 | 253 / 670 / 1025 / 315 | 253 / 670 / 1025 / 315 |

**The figures above prove only intended layout coordinates.** Font rasterization, curved border appearance, viewport clipping, physical DPI, Windows title-bar offsets, focus, colors, icons and actual app launch have not been independently confirmed.

## Changes represented in the native Rust branch

- `layout.rs`: breakpoint-correct Session Inspector, 363px owner-locked two-column cards, 315px stage and 1240px virtual document; source coordinates lock above.
- `render.rs`: 34px two-tone hero, rounded cards, distinct field labels, KMJ wordmark, semantic local/remote password rows, scrollable center, separate stage and premium inspector.
- `lib.rs`, `product_shell.rs`: persisted center-scroll position, pointer transform with view-scoped hits, tab navigation reset, truthful offline status and local-record-driven secondary views.
- `windows_host.rs`: native mouse wheel, safe redraw and Help guards, explicit keyboard focus, no plaintext control.
- `accesskit_tree.rs`: screen-reader bounds translated by the center scroll position, while header/rail remain fixed.
- `render.rs` and `layout.rs` regression tests: source layout and rounded-border rules, including 1024×768, 1308×777 and 1600×920.

## Release gate — still open

1. P520 CodeBridge online, but its shared Git checkout has owner changes and is far behind the V5 feature branch. A guarded isolated lane at the latest feature HEAD returned `WORKTREE_HEAD_MISMATCH`. No local source overwrite/reset/clean occurred.
2. This branch's exact-head Cargo fmt, Clippy, tests and Windows release build **have not been executed/verified**.
3. Required before accepting the design: run `scripts/Build-V5-Windows-Preview.ps1` in a permitted isolated branch lane, review its truthful PNG/source receipts, then capture the **real running Windows app** at the listed sizes/DPI and compare with the locked V5 reference.
4. After UI parity is visually verified, implement secure peer-authenticated encrypted remote control and two-PC QA; never treat locally granted permission or synthetic metrics as a connected session.

**Do not merge or overwrite the installed Windows executable until the above checks pass.**
