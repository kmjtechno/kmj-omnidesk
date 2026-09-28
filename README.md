# KMJ OmniDesk

> **Access without distance.**

KMJ OmniDesk is KMJ TECHNO's next-generation remote access platform, engineered for extremely low latency, low bandwidth consumption, minimal infrastructure overhead, and a premium cross-platform experience.

> [!IMPORTANT]
> **Development status:** Pre-alpha. This private repository is under active development. Performance, security, platform support, pricing, and availability claims remain unverified until they pass the corresponding release gates.

## Product principles

- **Direct-first connectivity** — encrypted peer-to-peer sessions are preferred; relay is a fallback, not the default data path.
- **Minimal server load** — KMJ infrastructure handles identity, discovery, authorization, licensing, signaling, and fallback relay only where required.
- **Slow-network resilience** — adaptive bitrate, frame rate, resolution, region updates, congestion response, and reconnect behavior are first-class engineering targets.
- **Native performance** — a Rust-first core with platform-native capture, input, and hardware media acceleration where available.
- **Security by design** — authenticated encrypted sessions, explicit permissions, device trust, auditability, and fail-closed authorization.
- **Premium UX** — a lightweight native interface aligned with the KMJ Main Platform black-and-red visual language without trading performance for decoration.
- **Commercially governed** — trials, plans, activations, and entitlements are controlled by the KMJ Main Platform.

## Target architecture

```text
                         KMJ Main Platform
                    identity / licensing / policy
                              |
                              v
+----------------+      signaling/discovery      +----------------+
| OmniDesk Host  | <---------------------------> | OmniDesk Client|
| capture/input  |                               | decode/control |
+-------+--------+                               +--------+-------+
        |                                                 |
        +========== encrypted direct P2P session =========+
                              |
                    only when direct fails
                              v
                       +-------------+
                       | KMJ Relay   |
                       | fallback    |
                       +-------------+
```

The control plane must not become the normal screen/audio data path. Relay bandwidth is consumed only when direct connectivity cannot be established or policy requires relay.

## Planned capability set

**Remote session:** desktop viewing and keyboard/mouse control, attended/unattended access, multi-monitor, clipboard, resumable file transfer, remote audio, reboot/reconnect, and adaptive quality controls.

**Connectivity/performance:** NAT traversal, direct-connect preference, QUIC/UDP-oriented transport with robust fallback, hardware encode/decode, adaptive AV1/HEVC/H.264 subject to platform capability and licensing review, dirty-region optimization, low-bandwidth mode, and measurable relay fallback.

**Security/enterprise:** authenticated encrypted sessions, one-time authorization, trusted devices, unattended-access policy, MFA/SSO integration, RBAC, organization policy, audit history, privacy controls, enterprise deployment, and managed-device direction.

## Commercial authority

KMJ Main Platform is the authoritative commercial control plane for OmniDesk. Planned commercial states include Personal/Free, Trial, Professional, Business, Enterprise, and OEM/Custom. Trial and paid capabilities must be entitlement-driven rather than hard-coded into the client.

```text
product_slug: kmj-omnidesk
product_id:   KMJ_OMNIDESK
authority:    KMJ Main Platform
```

## Performance gates

No superlative performance claim is valid until measured. Release candidates will be tested across controlled bandwidth, latency, jitter, packet loss, CPU/GPU, memory, connection time, reconnect time, and relay utilization.

| Metric | Direction |
| --- | --- |
| Interactive latency | Minimize |
| Session connection time | Minimize |
| Static/office bandwidth | Minimize |
| CPU/GPU overhead | Minimize |
| Relay utilization | Minimize |
| Network-disruption recovery | Maximize reliability |
| Visual clarity per transmitted bit | Maximize |

## Repository direction

```text
crates/       Rust core libraries
apps/         Native desktop/client applications
services/     Signaling and relay components
protocol/     Versioned wire contracts and schemas
docs/         Architecture, security, UX, and performance decisions
tests/        Integration, network-impairment, and security tests
benchmarks/   Reproducible performance gates
```

Sensitive commercial authority, signing material, production secrets, and KMJ Main Platform private keys **must never be stored in this repository**.

## Release discipline

A feature is not complete because it compiles. A release gate requires relevant tests plus measurable performance and security evidence. Customer-facing availability remains fail-closed until a signed release is accepted.

## Canonical execution map

Engineering work is governed by [`ROADMAP.yaml`](./ROADMAP.yaml). Architecture decisions live in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md), protocol/authorization ordering in [`docs/PROTOCOL.md`](./docs/PROTOCOL.md), and release-blocking security assumptions in [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md).

**Rule:** roadmap status changes only after the milestone's declared acceptance gates are verified. Time targets never convert an unverified milestone into a completed milestone.

## Current milestone — M0 Foundation / Pre-alpha

1. Establish repository and architecture contracts.
2. Bootstrap the Rust workspace and CI quality gates.
3. Implement a local/LAN authenticated session proof.
4. Measure capture → encode → transport → decode.
5. Add input/control behind explicit authorization.
6. Add direct internet connectivity and relay fallback.
7. Integrate KMJ Main Platform licensing through versioned contracts.
8. Benchmark weak-network behavior before public performance claims.

---

**KMJ TECHNO** · KMJ OmniDesk · Private development repository
