# KMJ OmniDesk Architecture

## Objective

Deliver a native remote-computing system that minimizes interactive latency, bandwidth, client overhead, and KMJ infrastructure cost while preserving explicit security and commercial-control boundaries.

## Data-plane rule

The preferred session path is:

```text
Host <================ authenticated encrypted P2P ================> Viewer
```

The KMJ control plane is not the normal screen/audio path. When direct connectivity cannot be established, policy may permit:

```text
Host <========== encrypted session ==========> Relay <==========> Viewer
```

Relay usage must be observable and measurable so infrastructure cost can be controlled.

## Logical planes

### Client data plane
Responsible for capture, media adaptation, transport, input, clipboard, file transfer, audio, multi-monitor state, reconnect, and session telemetry.

### Connectivity plane
Responsible for discovery, NAT traversal, path selection, path migration/fallback, congestion response, and relay selection.

### KMJ control plane
Responsible for identity, device registration, authorization, organization policy, entitlement/lease validation, signaling metadata, audit events, and release/update authority.

### Commercial plane
KMJ Main Platform is authoritative for product identity `KMJ_OMNIDESK` / `kmj-omnidesk`, trial state, plans, activations, entitlements, revocation, and future subscription policy.

## Performance strategy

Optimization decisions must be measurement-driven. The system will distinguish interactive desktop/text workloads from motion-heavy workloads and adapt transmission accordingly.

Target mechanisms include:

- dirty-region and static-screen suppression;
- adaptive frame rate and resolution;
- adaptive bitrate and congestion response;
- hardware encode/decode where supported;
- codec negotiation based on both endpoints and policy;
- independent treatment of latency-sensitive input/control and bulk file traffic;
- rapid reconnect and path recovery;
- explicit weak-network test profiles.

AV1, HEVC, and H.264 are candidates, not unconditional requirements. Shipping codec support depends on platform capability, interoperability, legal/licensing review, and measured benefit.

## Security boundary

No session is trusted merely because discovery succeeded. Authentication, authorization, session-key establishment, device trust, and permissions are separate decisions. Relay infrastructure must not require access to session plaintext.

## Technology direction

- Rust-first performance/security-sensitive core.
- Native/lightweight UI rather than a browser-heavy runtime as the default desktop shell.
- QUIC/UDP-oriented transport where it provides measured benefit, with practical fallback paths.
- Versioned protocol contracts independent from UI release cadence.
- Platform-native capture/input/hardware acceleration behind explicit adapters.

Exact libraries are selected only after compatibility, maintenance, license, security, and benchmark review.

## Release gates

A customer release requires evidence for:

1. correctness and automated tests;
2. authentication/authorization behavior;
3. cryptographic and threat-model review;
4. NAT/direct/relay interoperability;
5. weak-network behavior;
6. CPU, GPU, RAM, bandwidth and latency measurements;
7. reconnect/recovery behavior;
8. installer/update integrity;
9. KMJ Main Platform entitlement integration;
10. platform-specific permission and privacy behavior.

No claim such as "fastest" or "best" is accepted as a release fact without reproducible comparative evidence.
