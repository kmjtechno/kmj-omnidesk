# OmniDesk Protocol Contract

Protocol versioning is independent from desktop UI release versioning.

## Canonical identity

- Product ID: `KMJ_OMNIDESK`
- Product slug: `kmj-omnidesk`
- Current pre-alpha protocol version: `1`

## Session establishment order

1. Discover or select the intended peer.
2. Establish a candidate transport path.
3. Exchange protocol capabilities.
4. Authenticate peer identity.
5. Establish session encryption.
6. Evaluate device, user, organization, and entitlement policy.
7. Request/confirm interactive-control permission.
8. Enter active session.
9. Continuously enforce revocation and disconnect state.

Discovery, transport reachability, authentication, authorization, and licensing are separate decisions. Success in one stage must never imply success in another.

## Fail-closed rules

- Unknown protocol versions are rejected unless an explicit compatibility rule exists.
- Input events are rejected before control authorization.
- Stale or closed sessions cannot regain permission without a new session establishment.
- Relay selection cannot grant additional permissions.
- Commercial entitlement cannot replace peer authentication.
- Peer authentication cannot replace commercial entitlement.
- Client-side state cannot self-upgrade a plan.

## Channel priorities

Latency-sensitive control traffic must not be blocked behind bulk file transfer. Future multiplexing should distinguish at least:

- session/control;
- input;
- interactive video;
- audio;
- clipboard;
- file transfer;
- telemetry.

Exact framing and cryptographic primitives remain blocked on the dedicated threat-model/security milestone rather than being invented as an unreviewed wire format.
