# Privacy Review — Pre-alpha

This document is the `privacy_review` deliverable of M11. It records what
OmniDesk holds about its users, where that data can go, and what has been
decided to prevent it from going anywhere.

Two limits on its authority, stated up front:

- **It is not a compliance artifact.** No jurisdiction is claimed. A review
  that implies GDPR or DPDP conformance without legal review would be worse
  than none.
- **It describes the pre-alpha implementation as it stands**, not a future
  one. Where something is not implemented, this says so rather than
  describing intent.

## Data the code actually holds

Enumerated from the source, not from design documents.

### Identifying

| Item | Type | Where | Notes |
|---|---|---|---|
| Peer identity | `PeerIdentity(String)` | `session.rs` | Free-form. Not validated as an address or name, so nothing constrains its contents |
| Session public key | `[u8; 32]` | `session.rs` | Held only after authentication succeeds |
| Activation id | `&str` | `licensing.rs` | Issued by the control plane |
| Device key fingerprint | `&str` | `licensing.rs` | Of the device's own public key |
| Installation id | `&str` | `licensing.rs` | Per-installation, persistent |

The device fingerprint and installation id are deliberate and are what make
entitlement non-transferable. They are pseudonymous, not anonymous: they
identify an installation across sessions, and a control plane holding them can
recognise a returning one.

### Session content

Screen pixels, keyboard and pointer input, clipboard, transferred file names
and contents, audio. These exist in memory during a session. Per
[THREAT_MODEL.md](THREAT_MODEL.md), relay infrastructure cannot decrypt them
and the current relay frame carries only a session id and ciphertext.

### Operational

| Item | Where | Notes |
|---|---|---|
| Pipeline timings | `PipelineMeasurement.elapsed` | Wall-clock, in-memory |
| Transfer checkpoints | `TransferCheckpoint` | Chunk index and offsets |
| Network samples | `NetworkSample` | Throughput, latency, loss. Not device addresses |
| Clipboard state | `ClipboardSyncState` | Sequence numbers and a SHA-256 digest. **Not** the clipboard payload |

## Where it can go

### 1. Off the device — control plane

Entitlement verification is the only designed egress. The payload is the
signed entitlement claims above. It contains identifiers and plan state, not
session content.

The signed envelope is verifiable by the control plane's key, so the control
plane can correlate activations, installations, and devices. It receives
timestamps from `LocalLicenseClock` (`last_trusted_server_time`), which is a
behavioural signal: it reveals roughly when a client is active.

**Decision: no session content leaves the device to the control plane.** Clipboard,
files, input, screen, and audio are not entitlement inputs and must not become
them.

### 2. Through a relay

The relay sees the `session_id` and ciphertext length. It cannot decrypt.

Ciphertext length is a real, if minor, leak: a long paste or a large file
transfer is visible as a size change even when the contents are not. This is
inherent to not adding padding.

**Decision: accept the leak rather than pad.** Padding hides it at a
bandwidth cost that lands on the same weak links M6 exists to serve, and
against an adversary who can already observe sizes on the wire. Recorded as an
accepted risk rather than omitted.

### 3. Signaling

NAT traversal needs candidate addresses exchanged. These are network
identifiers that can be correlatable across sessions by the signaling
operator.

**Decision: signaling sees addresses by necessity.** Not mitigated in
pre-alpha; it is inherent to the traversal technique. Recorded so it is not
discovered later as a surprise.

### 4. Logs

There is no logging framework. The only output is `println!`/`eprintln!` in
examples, the desktop shell's control listing, and the validator's error
output. No log currently carries a peer identity, entitlement claim, or
session content.

This is true partly by accident — the feature is absent, not enforced.

**Decision: redaction is by type, not by pattern, and it is in place before
the logger.** `log_scrubber` gives values whose type marks them sensitive a
`Debug`/`Display` impl that prints `[redacted]`, and builds log records from a
closed set of value kinds — metric, flag, static state name, redacted length.
A record cannot hold an arbitrary string, so the "excluded from logs"
invariant is now constructible rather than aspirational.

Pattern-matching identities was rejected deliberately: it misses new formats
and leaks anything that does not match, and a filter that fails open is worse
than none because it implies a control that is not there.

### 5. On disk

Nothing is persisted. `TransferCheckpoint` is cloned and restored within a
test to simulate persistence; no filesystem write of session state exists.
The `output_bytes`/`input_bytes` in `PipelineMeasurement` and the example
outputs go to CI artifact JSON, which contains timings and sizes, not content.

**Decision: persistence must be introduced deliberately.** Clipboard and
transfer state are the two things most likely to be added to disk, and both
are session content.

## Required invariants

Mirrors the threat model's format. Each is stated so a test can refute it.

| # | Invariant |
|---|---|
| P1 | Session content — screen, input, clipboard, file, audio — is never transmitted to the control plane |
| P2 | No log, error message, or crash report contains peer identity, entitlement claims, or session content |
| P3 | Clipboard and transfer state are cleared when a session ends or is revoked, and retained state never contains clipboard or file content |
| P4 | A relay receives ciphertext and a session id, never plaintext and never a stable user identifier |
| P5 | Clipboard sync is disabled unless explicitly permitted, and the denial is visible to the user |
| P6 | No telemetry is sent that a user cannot disable, or that is required for the product to function |
| P7 | Entitlement identifiers are pseudonymous and never encode a name, email, or organisation in cleartext |

**P7 has a current finding.** `PeerIdentity` is free-form and `activation_id`,
`device_public_key_fingerprint`, and `installation_id` are opaque strings with
no format constraint in code. Whether a control plane ever places a name or
email in an activation id is a server-side decision this repository cannot
enforce. The invariant is recorded, and enforcement belongs to the control
plane's contract, not to this client.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| PR-1 | High | No logging framework, so the log-content invariant was unenforced and could regress silently | **Resolved** — `log_scrubber` makes a log record structurally incapable of carrying an identifier |
| PR-2 | Medium | Entitlement claims enable control-plane correlation of a returning installation | Accepted, documented above |
| PR-3 | Medium | `PeerIdentity` accepts arbitrary strings, so its contents are unconstrained | Open |
| PR-4 | Low | Ciphertext length leaks activity size through the relay | Accepted, documented above |
| PR-5 | Low | Signaling necessarily exposes correlatable network addresses | Accepted, inherent to NAT traversal |
| PR-6 | Low | Client activity is inferable from `last_trusted_server_time` | Accepted, inherent to lease validation |
| PR-7 | Low | `ClipboardSyncState` has no clear or reset, so its sequence numbers and digest survive session end | Open — the retained state is a hash, not content, which limits the impact |

M11's exit criteria require `critical_findings_zero` and
`high_findings_zero_or_explicitly_block_release`. PR-1 was the only High
finding and is now resolved by `log_scrubber`.

The criterion that remains unmet is `threat_model_reviewed`, which needs a
reviewer who is not the author. M11 stays `pending` on that, not on a finding.

## What is not covered

- Data-subject request handling (access, deletion, portability). No endpoint
  exists to be assessed.
- Retention. Nothing persists, so there is nothing to retain or delete.
- Third parties. None are integrated; no subprocessors are named.
- Children's data, health data, biometrics. No special-category handling is
  implemented or claimed.
- Cross-border transfer. No control plane exists to assess.
- Cross-tenant isolation beyond authorization. Assessed under M10, not here.

Listing these is the point. A privacy review that silently omits what it does
not cover is worse than one that names the gaps.

## Before production

The invariants above need enforcement, not documentation. Specifically: a
logging framework with scrubbing that drops identifiers by type rather than by
pattern, since pattern-matching identifiers is unreliable by construction and
fails open on formats nobody anticipated.