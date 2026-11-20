# KMJ OmniDesk V7 — Antigravity parity rejection and native correction

**Owner-reported mismatch:** 2026-11-20, screenshot `image(20261120-095436).png` (1920×1200 desktop capture).

**Only approved canonical target:** `a_highly_detailed_realistic_ui_design_hero_screen.png` (1672×941; SHA-256 `e9bb46837cc2ee87eb5f83bc63d5f7d2fcb510e91bd65be257470b8d08a54b92`).
See `OMNIDESK_ENTERPRISE_V7_LOCK_20261120.md`.

## Current comparison: FAIL (not visually signed off)

| Category | Owner-approved target | Reported Antigravity output / root problem |
|---|---|---|
| Brand | Exactly one official KMJ TECHNO top-left header lockup | Small, low-emphasis company mark and a second large product label; avoid duplicating full company logo |
| Typography | Legible bold editorial title, consistent headline/body hierarchy | Tiny, low-contrast text; earlier scale=3 was mapped to 22px |
| Panels | Filled, smoothly rounded charcoal cards with restrained bright-red focus and ambient depth | Square/cut-out corners, thick square edge artifacts; approximation instead of correct rounded raster |
| Hero art | Large luminous red globe, laptops/screens, red/blue atmospheric light | Thin orbital wireframe; original decorative art is not shipped inside native binary |
| Sidebar | Focused dashboard nav, clear icons, characteristic red lower-left light-trail accent | Flat grey rail, tiny icons, no light trails |
| Remote workflows | Clear 2-way share/control cards; real ID and secure temporary password lifecycle | Sample ID/password and enabled-looking access actions are unacceptable without backend |
| My Devices / Sessions | Verified data only; truthful empty states | Fabricated machine names, online indicators, counts, timestamps and completed badges |
| Licensing / Network | Verified entitlement, network, E2E status and observed latency only | Hardcoded active license, seats, all healthy, 42ms, relay connected (FAIL) |
| Responsiveness | Comparable at 1672×941 plus stable compact states/DPI scales | First reported 1920×1200 capture visually compressed and inconsistent |

## Engineering corrections on branch

- Increased font mapping to 17px/24px/38px to restore title hierarchy.
- Replaced mock rounded-panel approximation with a filled, continuous, geometry-safe rounded raster.
- Restored restrained panel glow/top lip and lower sidebar red wave.
- Replaced sampled device IDs/passwords/toggle and advertised password CTA with truthful unavailable state.
- Removed static demo devices, recent sessions, seat counts/expiry, false green health and fabricated relay security or latency.
- Kept clicked UI hitboxes bound to real Rust layout; password connect cannot be clicked until password proof is implemented.
- No mock screenshot pasted as live frame, and no skipped consent or trusted-peer authorization.

## Required signoff / no silent release

- Commit exact master PNG as a binary reference when transfer to GitHub is possible; the textual SHA alone is not a Git asset.
- Commit/ship high-fidelity hero/sidebar illustration binaries, or produce equivalent native vector raster output.
- Compare **real Windows HWND capture**, native Rust screenshot export, and approved 1672×941 reference at 100%, 125%, 150%, 200% DPI.
- Verify consistent control geometry, real session/security states, Windows run and resource benchmarks.
- Result must remain **VISUAL_PARITY=FAIL** unless exact screenshots and owner-approved comparison prove otherwise.
- PR remains draft and main branch untouched. No production release claim.

This is an audit + corrective implementation record, not a claim that pixel-perfect parity has been reached.
