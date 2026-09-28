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

## Before production

Cryptographic protocol selection, key agreement, peer identity persistence, replay protection, key rotation, unattended-access storage, update signing, and recovery behavior require dedicated implementation plus adversarial review and tests.
