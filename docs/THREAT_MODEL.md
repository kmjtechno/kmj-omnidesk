# KMJ OmniDesk Threat Model — Pre-alpha

This document defines release-blocking security questions. It does not claim the current pre-alpha implementation is production secure.

## Assets

- remote screen contents;
- keyboard and pointer control;
- clipboard and transferred files;
- audio;
- user/device identity;
- organization policy;
- entitlement state;
- update/release integrity;
- audit metadata.

## Trust boundaries

1. Local OS and OmniDesk process.
2. Remote peer.
3. Untrusted network.
4. NAT traversal/signaling infrastructure.
5. Relay infrastructure.
6. KMJ Main Platform commercial/control plane.
7. Release/update distribution.

## Primary threats

- peer impersonation;
- man-in-the-middle session establishment;
- replay of authorization;
- stale-session input injection;
- unauthorized unattended access;
- malicious or compromised relay;
- signaling metadata tampering;
- entitlement forgery or local plan escalation;
- clipboard/file path abuse;
- malicious update or downgrade;
- credential/token leakage in logs;
- denial of service and resource exhaustion;
- cross-tenant authorization failure.

## Required invariants

- Relay infrastructure cannot decrypt end-to-end session payloads.
- A relay cannot grant control permission.
- Input is rejected until peer authentication and explicit authorization succeed.
- Closing/revoking a session removes control authority immediately.
- Main Platform entitlement is verified independently from session authentication.
- No master commercial unlock secret ships in the client.
- Update metadata and release artifacts require integrity verification.
- Sensitive payload contents are excluded from normal logs.

## Consent gaps in the current implementation

The invariants above concern what an attacker can do. These concern what the
software does without an attacker, which the threat model has to record
because it is a property of the build rather than of the protocol.

**Windows screen capture is currently silent.** `windows_capture.rs` calls
`win_screenshot::capture_display()`, a GDI `BitBlt` path. Windows shows no
consent prompt for it. A user running the current pre-alpha build has screen
capture performed on them with no OS-level indication and nothing in the
product telling them either.

This is a real exposure, not a theoretical one, and it is stated here rather
than left in M12's permission guide where a release reviewer would not look.
The fix is `Windows.Graphics.Capture`, which makes the OS draw a consent
banner and gives the user a revocation control. That is a security change, and
it also happens to be what M8's `multi_monitor` needs — GDI `BitBlt` cannot
capture a monitor the user did not select.

See [PLATFORM_PERMISSIONS.md](PLATFORM_PERMISSIONS.md) for the per-platform
requirement set and the denied/restricted/unavailable distinctions.

## Before production

Cryptographic protocol selection, key agreement, peer identity persistence, replay protection, key rotation, unattended-access storage, update signing, and recovery behavior require dedicated implementation plus adversarial review and tests.
