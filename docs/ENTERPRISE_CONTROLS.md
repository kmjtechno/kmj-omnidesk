# Enterprise Controls — M10

This document records what M10's seven deliverables actually are, what each one
enforces, and — more importantly — what each one does **not**.

## The seven deliverables

| Deliverable | Where | State |
|---|---|---|
| Organization policy | `enterprise::PolicyDocument` | Implemented and tested |
| RBAC | `enterprise::rbac` | Implemented and tested |
| Trusted devices | `enterprise::trusted_device` | Implemented and tested |
| Unattended access policy | `enterprise::unattended` | Implemented and tested |
| MFA / SSO boundary | `enterprise::Assurance` | Decision interface only — see below |
| Audit history | `enterprise::audit` | Implemented and tested |
| Managed deployment direction | The above, as a whole | No deployment client — see below |

## The design

Enterprise authorization fails in one direction far more often than the
other: **it grants when it should deny.** Every decision in the module is deny
by default, and there is no path to an allow without an explicit grant recorded
by something the caller already trusts.

Three boundaries are enforced structurally rather than by convention:

### 1. A request carries the subject's own context, never a claimed one

`AuthorizationContext` has no public field and no `Default`. Its only public
constructor takes the granted capabilities as an explicit argument, so a caller
cannot build a context asserting a grant it did not receive.

### 2. The signed grant is a ceiling that policy cannot raise

`AuthorizationContext::granted(permission)` checks what the *signed* grant
carries. `PolicyDocument` can forbid a permission and can demand stronger
authentication, but it has **no operation that adds one**. Without that
asymmetry, a policy document arriving from somewhere this process does not
control would be a privilege escalation channel.

This is checked first in `PolicyEngine::evaluate`, before anything a policy
could influence, and a test pins the ordering by asserting that a
not-granted *and* policy-forbidden permission reports `NotGranted` — the caller
reading "policy forbids" would go edit the policy.

`UnattendedAccess` carries the same rule: a grant hands out only the
intersection of what it claims and what the signed ceiling carries.

### 3. Policy evaluation returns a decision, never a default

`PolicyEngine::evaluate` returns `Decision::Deny(DenyReason::…)` with a
distinct reason per cause. There is no `is_allowed()` that hides a deny, and no
`Permission::Other(String)` variant — a variant that swallows unrecognised
input is how an unknown permission becomes a permission. `Permission::parse`
returns `None` rather than defaulting.

## Not implemented, and why

These are recorded so a future reader does not discover them as a surprise.

**No real identity provider.** The MFA/SSO boundary is a *decision interface*:
it takes a verified assertion and maps it to an `Assurance` strength. It does
not speak `SAML` or `OIDC`, because speaking them without an identity provider
to test against would be an untestable claim.

**No control plane.** `TrustRegistry` is an in-memory `Vec`, supplied by the
caller. A registry that read a file or made a network call would make every
authorization decision depend on infrastructure, and the properties that matter
here are about what happens when the answer is *wrong* — which a test can only
exercise by supplying the wrong answer.

**No deployment client.** "Managed deployment direction" is the design: a
tenant's policy and device registry are authoritative and a client is subject to
them. There is no mechanism that pushes policy to a managed device, no MDM
handshake, and no enrolment agent. The module makes such a client's decisions
correct; it does not deliver policy.

**The attestation reference is not parsed.** `DeviceProof` carries an opaque
handle to whatever proof was checked. Resolving it to an attestation format is
an integration with a hardware vendor, and nothing here pretends to have
verified one.

## Audit history: what the chain does and does not prove

`AuditLog` is append-only with no `clear`, `truncate`, or `remove`, and each
event carries the SHA-256 digest of the one before it. `verify_chain` detects
edits and splices and reports exactly where.

**It is not tamper-proof storage.** An attacker with write access to the
`Vec<AuditEvent>` can edit every field, recompute every digest, and produce a
chain that verifies — there is no signing key. The chain raises tampering from
"delete a line" to "replay the whole log," and it means an ordinary bug cannot
silently drop an event. `audit_a_full_rewrite_verifies_and_that_is_the_documented_limit`
asserts the limit in code so the docs cannot drift into claiming more than the
implementation delivers. The control that closes the gap — shipping events
somewhere the client cannot rewrite — is not implemented.

A truncated log reports `AuditError::Truncated` from `verify_chain` rather than
verifying a chain with a silent hole in it.

## Privacy

Tenant and principal identifiers never reach an audit record. Events carry
pseudonymous handles — SHA-256 domain-separated digests — and `Display` prints
handles only. `TenantId`'s `Debug` prints the handle and byte length, never the
organisation's own name, on the grounds that an audit log carrying tenant names
in the clear is a re-identification vector for anyone who obtains the log.

This extends P2 and P7 in [PRIVACY_REVIEW.md](PRIVACY_REVIEW.md), which flagged
"Cross-tenant isolation beyond authorization" as assessed under M10.

## Verification

62 tests in `enterprise`. Each carries a `Mutation:` line naming the single
edit that would make it fail.

All 25 of those mutations were applied and every one was caught. Two initially
reported as surviving were investigated manually and *were* caught — the
harness's match had been thrown off by a mutation that failed to compile
elsewhere. One mutation that removes a `let-else` guard breaks the build
rather than passing, which is the structural version of the same protection.

The gate runs in CI by name (`M10 enterprise authorization and audit gate`),
because a removed authorization check makes the code *more* permissive and
every unrelated test still passes.

## Exit criteria

| Criterion | Status |
|---|---|
| `tenant_boundary_tests_pass` | Met — `tenant_*` and `escalation_*` tests |
| `privilege_escalation_tests_pass` | Met — `escalation_*` tests |
| `audit_events_verified` | Met for the properties above; the audit chain's limits are stated, not papered over |

These three criteria are automated and pass. M10's overall status in
[ROADMAP.yaml](../ROADMAP.yaml) is not flipped on that basis alone: the
managed-deployment *direction* has no deployment client, and the MFA/SSO
boundary has no identity provider behind it. Recording that is more useful than
a green tick that overstates what ships.