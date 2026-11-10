# KMJ OmniDesk — Remote Workspace V5 (owner UX direction)
Date: 2026-11-10
Scope: **OmniDesk-specific premium UX, not a Main Platform dashboard copy**.
Status: interactive static browser design prototype and native implementation brief; **not a production Windows build**.

## Visual direction
Owner clarification: Main Platform is a **brand reference only** (official KMJ TECHNO logo, "INNOVATE | BUILD | SCALE", graphite/near-black surfaces, restrained red primary accent). **Do not** copy the Super Admin's globe hero, revenue/customer metrics, catalog cards, generic command center or Kristi portrait dock. OmniDesk's workspace must prioritize its unique remote-control tasks. Keep browser and Windows native UI differentiated from business admin.

## V5 home hierarchy
1. Compact top bar with KMJ TECHNO logo + OmniDesk wordmark, status "No active session", shortcut search and preview/help.
2. Focused left rail: Remote access, Trusted devices, Sessions, File transfer; protection group: Security center, Preferences.
3. Primary card **Connect to another desktop**: Remote Device ID + masked Session password + clear connection CTA. Validate remote ID format but never treat validation as authentication. Show explicit errors/verification states.
4. Primary card **Your ID & password**: sample/actual local public ID, safe copy control, masked password with deliberate reveal/copy/regenerate, session-password lifecycle and Unattended Access state. The static demo's ID and secret are samples only; real values require native host credential integration.
5. Large **Remote display** canvas: truthful disconnected state; when actually connected, live remote video with multi-monitor switch, fullscreen, remote keyboard/mouse permission, clipboard, file transfer and a permanent disconnect control. Avoid invented latency/FPS/encryption badges.
6. Narrow **Session inspector** for larger screens: peer identity, connection path, measured latency, frame rate, encryption and permission gates. Collapse at laptop widths, not at the expense of core flows. Mobile prioritizes local ID/password and connection form.
7. Secondary screens for trusted device registration/revocation, active sessions, transfer queue, security status and viewing preferences.

## Concrete V5 prototype
- Standalone browser prototype delivered in ChatGPT artifact `KMJ_OmniDesk_Remote_Workspace_V5.zip` with embedded logo and no runtime dependencies. Its remote session simulation is explicitly marked **UI SIMULATION / NO NETWORK** and never changes verified connection status.
- Local preview shows ID/password reveal, copy, browser-generated *demo* secret rotation, format-gated Connect UI, navigation and file picker staged locally. No network connection, no native host password, no actual file transfer, no production session.
- Browser QA passed at 1920x1080, 1600x920, 1280x800, 1024x768, 820x1024, 390x844, 360x740: no horizontal overflow or JS errors; desktop/mobile interactions and simulated session view exit passed. This does **not** establish Windows native QA.

## Rust implementation map (future native phase)
- `crates/omnidesk-desktop/src/{lib.rs,layout.rs,render.rs,windows_host.rs,accesskit_tree.rs}`: port the visual system, use one pointer/render/accessibility geometry, handle focus, input and secret field safely, remove fake placeholder claims.
- `crates/omnidesk-core/src/{product_shell.rs,device_identity.rs,transport_adapter.rs}` and enterprise trust/unattended modules: reviewed peer-authenticated session handshake, password proof bound to verified device/session, replay-resistant cryptography, rate limits, scoped permission and verified session state. Do not use a browser-generated or hard-coded secret.
- Native Windows multi-monitor QA, non-shared-password input, accessibility, offline/denied/revoked/unreachable paths, two-device input/clipboard/file-transfer trials, signer and release gates must pass before saying "working".
- Protect current dirty checkout, zero extra paid spend, do not reset/clean or deploy unreviewed credential flows; no modifications to production Main Platform.

**Owner acceptance direction:** World-class enterprise UI quality means quick task completion and reliable state communication, not visual resemblance to the KMJ business-admin dashboard.
