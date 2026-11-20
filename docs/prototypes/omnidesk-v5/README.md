# KMJ OmniDesk — V5 Remote Workspace

**Owner-selected design, 2026-11-10.** This is the canonical design reference for finishing KMJ OmniDesk, **not** a Main Platform Super Admin dashboard clone.

## Open the prototype

Open [`index.html`](./index.html) directly in a modern browser. It is a fully self-contained offline design demo: logo is embedded; there are no runtime dependencies or network calls. The small favicon points to the repository's canonical KMJ brand asset.

The two task-first panels are **Connect to another desktop** (Remote ID and Remote Password) and **Your ID & password** (local sample ID and temporary sample password, masked/reveal/copy/regenerate). The rest of the prototype covers remote display, trusted devices, active sessions, file transfer, security and preferences.

The **Preview session UI** control displays a clearly marked `UI SIMULATION / NO NETWORK` remote screen. This cannot authenticate or control another computer, and none of its tools perform live remote operations.

**DO NOT use any prototype password in production.** The browser generates its own disposable sample secret. Real Windows host credentials, peer verification, consent/unattended policies, two-device transport, clipboard and file movement remain separate native Rust engineering work.

## Approved look and feel

KMJ TECHNO brand at the top-left, black/graphite visual foundation, controlled KMJ red accent, restrained depth and dense but accessible enterprise controls. **Do not** replicate the Main Platform's Earth hero, revenue dashboard, business metrics or Kristi portrait dock. Keep the interface optimized for remote access.

## Working source and handoff

- [Owner's V5 design contract](../../design/KMJ_OMNIDESK_REMOTE_WORKSPACE_V5_20261110.md)
- [Native modernization and dependency audit](../../design/KMJ_OMNIDESK_V5_TECH_MODERNIZATION_20261110.md)
- [Anigravity implementation handoff](../../design/ANIGRAVITY_OMNIDESK_V5_HANDOFF_20261110.md)
- `crates/omnidesk-desktop/src/layout.rs`, `render.rs`, `lib.rs` contain initial native V5 layout/brand/readiness changes.

## QA scope

The archived prototype QA evidence is in [`QA_REPORT.json`](./QA_REPORT.json). Seven viewport sizes passed responsive, no JS error, local demo password controls, form validation, simulated session preview, and exit flows. **Browser QA does not verify the native Windows binary or cryptographic password login.**

Build and test the exact GitHub branch in a separate P520 working tree. Preserve the user's dirty `main` checkout. Do not spend paid GitHub Actions quota or bypass fail-closed authentication.
