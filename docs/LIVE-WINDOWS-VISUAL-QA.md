# Live Windows UI/UX QA through KMJ CodeBridge

**Approved design lock:** `image(20261014-112339).png`, 1419×611, SHA-256
`281f0b5921b69e68ee16a7a6f52a02f5d9b3a9588e54378cc477f20d151a1948`.

The design is the target for the application shell; its pictured remote PC,
device names, online peers and session metrics are illustrative and must **never**
be falsely rendered as a connected session.

## Preconditions

1. Enroll this repository as a separately authorized `kmj-omnidesk` project
   on an **interactive Lenovo P720 Windows user session**. Merely authorizing
   `kmj-codebridge` or `kmj-cinecore` does not authorize OmniDesk.
2. Administrator explicitly opts that OmniDesk project into the CodeBridge
   `windows-visual-qa` command preset. No other project permissions change.
3. Build `target/release/omnidesk-desktop.exe` with normal Cargo release
   checks. No paid SaaS or new application runtime dependencies.
4. Place the exact owner-approved PNG at
   `docs/design/locked-main-app-1419x611.png`. Hash is verified. Never
   substitute the old marketing hero or re-generated marketing images.
5. Produce the genuine 1419×611 disconnected-state Rust renderer artifact at
   `artifacts/locked-dashboard.png` using the existing
   `locked_dashboard_capture` example and converter.

## Three fixed commands

`run_project_command` profile `windows_visual_qa`:

| Variant | What it proves | Local evidence |
|---|---|---|
| `capture` | Start real `omnidesk-desktop.exe` and attempt Win32 PrintWindow capture | `artifacts/native-ui/native-ui-smoke.json`, PNG |
| `compare` | Verify exact locked design hash; compute native renderer-to-reference mismatch and RGB error | `artifacts/native-ui/visual-comparison.json` |
| `accessibility` | Launch native desktop and query Windows UI Automation visible interactive controls | `artifacts/native-ui/accessibility.json` |

All scripts run locally on the authorized device, and the command preset is
fixed and audited. No arbitrary CLI arguments or executable path can be passed
by a ChatGPT, Claude, or other MCP client. No screenshots are uploaded.

`REVIEW_REQUIRED` is the correct outcome of comparison even with low pixel
error: real device lists, connection metrics and remote frames must come from
authorized live data. Zero UIA buttons or no interactive desktop **fails** the
accessibility command instead of reporting PASS.

## Release QA

Review the native capture at 100%, 125%, 150%, 200% Windows DPI and verify
keyboard focus, pointer hit targets, screen-reader labels and high contrast.
Then run **two approved physical endpoints** across separate networks for
authenticated capture, input, multi-monitor, clipboard, file transfer, relay
fallback, reconnect and M4 REALNET-60. Main Platform M9 signing and the
commercial release gate remain separate, fail closed.

**Local-first:** the approved P720 checkout may have uncommitted changes. Use a
clean isolated Git worktree/branch when testing new software; never discard
another AI worker's edits or overwrite a dirty checkout.
