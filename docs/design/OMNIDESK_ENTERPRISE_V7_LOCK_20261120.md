# KMJ OmniDesk — Enterprise Premium Visual Lock V7

**Owner design approval:** 2026-11-20, 08:46 UTC (latest generated concept).
**State:** DESIGN LOCKED. This is a visual and interaction specification, **not** evidence that the pictured features are released.
**Product:** KMJ TECHNO OmniDesk (native Rust/Windows); one application is both the controller and the host.

## Canonical evidence and identity

- Approved master image: `a_highly_detailed_realistic_ui_design_hero_screen.png`.
- Master dimensions: **1672 × 941 px**.
- Master SHA-256: `e9bb46837cc2ee87eb5f83bc63d5f7d2fcb510e91bd65be257470b8d08a54b92`.
- Owner-uploaded **locked logo** sample: `image(20261120-083345).png`, SHA-256 `a6efa6a45dac967b1a1ab0f7c821a664edfa37489580b69fe4a2882b2e6bcfad`.
- Existing repo canonical icon asset: `assets/brand/kmj-mark.svg`. Reuse this exact mark; brand lockup displays **KMJ TECHNO** and **INNOVATE | BUILD | SCALE**.
- **Exactly one full KMJ TECHNO brand lockup per primary application window, in the top-left header.** No duplicate company logos in sidebar or hero or cards. OmniDesk wordmark adjacent, separate from KMJ lockup.
- The master image is an AI-generated design reference. Until the PNG is actually committed, its SHA here alone is **not** a claim that the binary is present in Git.

## Visual language (normative)

- Desktop reference artboard 1672×941; native responsive layout and OS DPI scaling. Maintain task hierarchy down to 1024×768; compact/scroll where needed, no overlapping or truncated active controls.
- Frame: deep black `#070910`; elevation surfaces `#0f1420`, `#141722`; elevated panel `#171725`; hairline border `#343647`.
- Text: high `#f7f7fa`, secondary `#b9becb`, muted `#858a9b`.
- Controlled brand red `#f7193b` → `#bd102e`; use red for primary CTA/active selection and deliberate focus, not all card borders. Green only for **verified** success; avoid blue primary CTAs.
- Brand visual: original angular K monogram + company lockup; restrained large red/pink wireframe globe/light-trail graphic **as decorative art only**. Graphic must not imply any real global routing, connections or relay health.
- 8 px grid, 12–16 px panel rounding, 1px neutral borders, calibrated drop shadows, red focus ring, Segoe UI / OS-native font. Vector icons for monitors, file, headset/audio, clipboard, shield, people, terminal and history. No bundled proprietary fonts.
- Light-emission gradients restricted to accents, headline/divider, brand globe; all text high contrast against backgrounds. Motion honors reduced-motion.

## Exact layout hierarchy

1. **Top bar**: a single company lockup at x≈32, OmniDesk wordmark near x≈335, Enterprise/product descriptor, help/settings, OS window controls. Keep one and only one logo lockup.
2. **Left navigation** (~260px): Dashboard (selected), Remote Access, My Devices, Sessions, File Transfer, Multi-Monitor, Collaboration, Security & Access, Users & Teams, Licensing, Reports & Logs, Settings. Non-integrated destinations display **Unavailable** and are noninteractive.
3. **Hero** (main center): `KMJ OmniDesk` editorial headline, `Secure Remote Access • Support • Manage • Collaborate`, decorative globe and paired-device illustration. No duplicate logo inside hero.
4. **Two equal primary workflow cards directly beneath the hero**:
   - **THIS DEVICE · SHARE ACCESS**: true local Device ID, Copy ID, session password masked, Show/Hide, Rotate, `Allow remote control` explicit consent switch. If credential lifecycle not implemented: `Password access not yet available`, disabled controls, no dummy password. To give another person access, the owner gives the real device ID and temporary password **after** actual host credential support ships.
   - **CONNECT TO REMOTE DEVICE**: Remote Device ID, password field, Connect securely CTA. Validating an ID is **not** password/peer authentication. CTA stays disabled until audited server/host password-proof and peer auth are wired.
5. **Capability row**: Remote Control, File Transfer, Multi-Monitor, Audio & Voice, Clipboard Sync, Session Record, Unattended Access. Availability based on authenticated runtime and policy; use disabled/unavailable for nonimplemented capabilities.
6. **Lower cards**: My Devices and Recent Sessions from authoritative data, empty states if none. No fabricated hostnames, counts or histories.
7. **Right column**: entitlement from KMJ Main Platform if verified, System Status from runtime probes, Quick Actions (New Session, Wake on LAN, Remote CMD, Send File, Get Logs, Invite User) as actual capabilities only. Do **not** show generated 250/1000 seats, Dec 31 2026, all healthy, 42ms or E2E/AES256 badges as facts.
8. **Bottom status bar**: only measured and authenticated transport, or `No verified session`; honest pre-alpha version. No invented Cloud Relay connection.

## User journeys (security-gated)

**Control another computer:** Enter Remote ID → enter masked short-lived remote session password → discovery → authenticated, bound peer identity → password proof over reviewed encrypted channel → local acceptance or valid scoped unattended grant → session toolbar. Error messaging for unknown/unreachable/revoked/expired/wrong-password/replay; failure never opens a session.

**Let someone control this computer:** Local identity provisioned → explicitly enable attended sharing → cryptographically generated temporary password with visibility/copy/reset and expiration → share ID/secret out of band → inbound remote caller authenticated → show verified peer and requested permissions → Allow/Deny (with easy Disconnect and revoke). Unattended permission is separate, explicitly scoped, time-bounded and policy-approved; not silently enabled by the attended password.

## Repo-backed implementation audit at lock time

- `crates/omnidesk-core/src/product_shell.rs`: remote ID handling exists; `begin_connect_remote_id` validates a locator, not password proof.
- `crates/omnidesk-desktop/src/lib.rs`: Remote ID input/click actions; no session password input path in current native view.
- `crates/omnidesk-desktop/src/windows_host.rs`: TCP listener, trusted-device handshake and permission flow exist, but explicit temporary-password lifecycle and proof are not integrated. Inbound auth failure branch requires fail-closed security remediation before host access can be considered release-ready.
- `crates/omnidesk-core/src/enterprise/unattended.rs`: grant policy model; not a production unattended host service.
- `README.md` and `ROADMAP.yaml`: release maturity **pre-alpha**, real-network and commercial release gates outstanding.

## Assets tracked by source

- Official mark: `assets/brand/kmj-mark.svg` (existing).
- New product background: `assets/ui/omnidesk-premium-network.svg` (decorative only; no real endpoints/metrics).
- New lockup reference: `assets/ui/kmj-premium-header-lockup.svg` (brand composition embedding the repo's existing mark, not a new mark).
- Static implementation reference: `docs/design/omnidesk-enterprise-v7-reference.html` (design-only; no live transport).
- Source screenshot: hash-pinned master as identified above; **binary must be added to the repo before claiming the screenshot is stored in Git**.

## Native acceptance gates

1. Compare real Windows app screenshots against this locked image at 1672×941 plus 1440×900, 1280×800, 1024×768, 125%/150%/200% DPI. Manual owner signoff for visual parity; no pixel-perfect claim from static HTML alone.
2. All rendered buttons align with pointer hit-testing and keyboard/AccessKit focus, including disabled states.
3. Native build and workspace rustfmt, clippy, tests; Windows UI and resource gates. No fake or hardcoded credentials/status.
4. Two physical machines, symmetric inbound and outbound authenticated session, correct approval/deny, bad password, revoked peer, relay/direct loss, clipboard/file permission, session teardown and reconnect trials.
5. Signed packaging, licensing signer/revocation, rollback, enterprise policy, QA and explicit commercial release approval before production.
6. Zero new paid services. No main-branch mutation, no reset/clean of owner checkout, no weakening security.

**Change control:** Any material alteration of logo, large visual hierarchy, two-workflow layout or key color system requires an updated design-lock version and owner approval.
