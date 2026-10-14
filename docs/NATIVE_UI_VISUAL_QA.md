# KMJ OmniDesk native UI — live visual QA (14 Oct 2026)

## Lock vs current implementation

Approved reference: KMJ OmniDesk Cyber Dashboard (premium black/red,
left navigation, connections, devices, security, accessibility, system status,
quick actions and readable professional typography). Public README imagery
must use **only** the three exact approved images; do not replace with
invented SVGs or alternate artwork.

Actual Windows desktop smoke reference: PR #68 Windows runner launches
omnidesk-desktop.exe and records native-ui/native-window.png alongside
native-ui/native-ui-smoke.json. This is a real PrintWindow capture,
NOT the media pipeline smoke frame.

## Observed gaps (before this PR)

- Quick-connect registration caption overlaps the remote ID column.
- Disabled No devices available row misleadingly says OFFLINE.
- Narrow title/footer can overlap the status text, violating small-DPI layout.
- Pixel-font rendering, limited hierarchy and missing left navigation are
  visibly not the locked premium desktop composition.
- Registration/directory integration is absent: Your OmniDesk ID is
  deliberately NOT ASSIGNED; Connect cannot be represented as live.
- Main Platform signer, REALNET-60, relay proof and installed updater
  remain outside UI signoff.

This PR addresses only **measurable clipping, inaccurate disabled label,
native-window evidence and narrow-width text collisions**. It is not a
claim that concept-design parity or live remote sessions are complete.

## Evidence distinctions

- An operating system window with verified title = native app started.
- A screenshot from PrintWindow = useful evidence for visual inspection,
  but may be incomplete under hosted runner/compositing limitations.
- A screenshot-state of CAPTURED_FROM_RUNNING_APP is not design PASS.
- An authenticated direct/relay remote-control session must be tested
  using two permitted real endpoints; no localhost fixture suffices.
- Final design approval must compare exact reference at 100%, 125%, 150%
  and 200% DPI, narrow/wide widths, keyboard focus, screen reader, and
  system high contrast without synthetic online devices.
