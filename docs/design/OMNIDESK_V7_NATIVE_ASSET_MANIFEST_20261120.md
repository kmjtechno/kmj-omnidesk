# OmniDesk V7 — Approved Native Visual Asset Manifest

**Owner reference approval:** 2026-11-20. **Scope:** visual assets only; no authorization to bypass production/security gates.

| Role | Repository file | SHA-256 | Source |
| --- | --- | --- | --- |
| Exact immutable design master (1672×941) | `docs/design/OMNIDESK_ENTERPRISE_V7_APPROVED_MASTER.png` | `e9bb46837cc2ee87eb5f83bc63d5f7d2fcb510e91bd65be257470b8d08a54b92` | User-approved V7 concept |
| Decorative global hero illustration (470×163) | `assets/ui/omnidesk-v7-approved-hero-art.png` | `e7e0bdea5a3270761234764930757ff3d8a37daaef16807a630368344baaebf3` | Crop of approved master, x=770–1239, y=77–239, palette reduced |
| Decorative sidebar red wave (260×178) | `assets/ui/omnidesk-v7-approved-sidebar-wave.png` | `3bfc1a8958888d14960a603173d5bb9a8dcd6df055c95e8981b1f3c51c1a43fc` | Crop of approved master x=0–259, y=710–887, palette reduced, alpha feather |
| Official single KMJ brand lockup | `assets/brand/kmj-mark.svg`, `assets/ui/kmj-premium-header-lockup.svg` | Refer to locked logo reference in `OMNIDESK_ENTERPRISE_V7_LOCK_20261120.md` | Official logo |

## Native integration
The Rust native renderer in `crates/omnidesk-desktop/src/render.rs` decodes the decorative PNGs once via `OnceLock` and displays them on the hero and sidebar. The approved PNG master is an **immutable screenshot for QA only**, not an interactive fake dashboard. The hero is edge-feathered at render time to avoid a hard rectangular boundary; it must never be treated as live remote video.

## Visual acceptance
- Compare the **actual Windows native window**, not only the deterministic PPM/PNG renderer export, against the exact master at 1672×941. Also test 1440×900, 1280×800, 1024×768 and DPI 100%, 125%, 150%, 200%.
- Confirm precisely one official KMJ TECHNO full lockup in top bar, correctly scaled fonts, panel spacing, nav, illustrative globe and sidebar wave.
- Contrast/focus, hitbox and accessibility tests must reflect controls actually rendered. Password, sharing, health, device list and license fields must derive from verified runtime state. Never replay the master screenshot to impersonate a live connected session.
- Password-based Connect Securely and host share must remain disabled until audited authentication and two-machine tests PASS.
- Artistic parity and actual commercial release require separate owner signoff; **CI SUCCESS alone is not visual acceptance**.

Source master remains SHA-pinned; any change to design must require a new owner-approved lock version. No paid service dependencies.
