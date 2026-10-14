# KMJ OmniDesk — FINAL LOCKED MAIN APPLICATION UI (2026-10-14)

## Source of truth (owner-approved)

**Reference**: owner-uploaded `image(20261014-112339).png` (1419 × 611 px).
**Reference SHA-256**: `281f0b5921b69e68ee16a7a6f52a02f5d9b3a9588e54378cc477f20d151a1948`.

This is the approved **main application window**, NOT the previous full-width
marketing banner. Any alternative conceptual mockup is non-canonical.
The original PNG is a user-provided design reference and must not be modified
or substituted with a newly generated image. Engineering comparisons must use
the exact reference digest. Do not call a render "pixel-perfect" before a real
Windows screenshot comparison at the same dimensions and DPI.

## Design structure (coordinates measured from the approved reference)

- Entire UI: dark near-black canvas, thin illuminated KMJ-red outer edge.
- Top bar: from y≈0 to 70; locked KMJ icon + `KMJ OmniDesk`, top search,
  Settings/Help and ordinary OS window controls. KMJ TECHNO brand remains
  the official logo, not a generic/KMJ Main Platform favicon.
- **Column 1**, x≈4–179: narrow permanent left rail. Devices selected in
  red; Connections, File Transfer, Remote Actions, Automation, Security,
  Settings. Bottom connection status card. Nonimplemented destinations must
  be visibly unavailable and never behave like functioning features.
- **Column 2**, x≈180–451: Devices heading, Add Device, All/Online/Offline
  filters; truthful registered devices and online states (never screenshot
  placeholders such as Office-PC/192.168.1.10 if not actually provisioned).
- **Column 3**, x≈454–1120: central device/session header and large framed
  remote desktop viewer; below is a row of session action tiles. No stock
  Windows wallpaper may masquerade as live decoded remote desktop frames.
- **Column 4**, x≈1122–1405: stacked Connection Status, Session Details
  and Actions cards. Show only authenticated, measured transport stats.
- Distinct semantic color roles: KMJ red = selected/primary/danger; green =
  verified online/success; neutral greys = secondary/disabled. No all-red UI.
- Compact professional typographic hierarchy, precise 8–12 px spacing,
  readable status values, consistent icons, muted separators, visible focus.
- Responsive: retain all four areas on sufficiently wide screens; on narrow
  windows use the existing safe compact shell until a dedicated responsive
  UX is implemented. No clipped or overlapping controls.

## Security and interaction constraints

* Never display a user-generated device as ONLINE without authoritative presence.
* Local permission approval is **not** an authenticated remote connection.
* No fabricated latency/FPS/bandwidth/encryption/NAT type/path status.
* Local keyboard/pointer hitboxes must exactly match the rendered row/tile.
* Features not wired to trusted backend must be disabled or identified as
  unavailable; nothing that looks enabled may silently do nothing.
* Real session viewer only displays decoded authenticated remote video.
* Unattended access, remote shell/reboot and file transfer remain subject to
  explicit security policy and authorization; no demo bypasses.

## Acceptance gates

1. Real native Windows `omnidesk-desktop.exe` starts and captures a
   screenshot via `scripts/windows_native_visual_smoke.ps1`.
2. Visual structure matches the four-column source image at 1419×611 and is
   legible at 100%, 125%, 150%, 200% DPI. Human design signoff remains
   separate from automated layout tests.
3. Mouse hit testing, keyboard and AccessKit actions all follow the same
   geometry. No click falls on a different control from the one displayed.
4. Empty, pending, connected, disabled, error, lost-network and reconnecting
   states are tested without inventing online peers or performance metrics.
5. Real two-endpoint session, REALNET-60, Main Platform M9 signing/rotation/
   revocation, rollback updater, install/uninstall and owner commercial
   release authorization must pass before any public release.

## Scope of first implementation PR

Establish canonical dashboard layout geometry, truthful four-panel native
shell rendering, aligned device hit targets, and an appropriate desktop
window size. This is a real engineering increment, not finished parity:
premium font assets, all modules, live video transport and commercial release
still need independent evidence.
