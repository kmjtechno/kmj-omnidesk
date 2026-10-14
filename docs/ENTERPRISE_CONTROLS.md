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

72 tests in `enterprise`. Each carries a `Mutation:` line naming the edit that
would make it fail.

**Those lines were comments until `scripts/verify_enterprise_mutations.py`
existed.** Every other gate in this repository had a harness that CI runs and
that applies its own mutations; these 72 were applied by hand on one
afternoon and never re-checked. A `Mutation:` docstring with nothing applying
it is documentation of an intention, not evidence.

The harness now applies all of them on every CI run, and every mutation is
caught. It started with 22 — the load-bearing properties only — which left 50
docstrings as unapplied comments. That gap was recorded here rather than
smoothed over.

Closing it found two defects, both in the tests rather than in the code.

### Seven docstrings named mutations their own tests could not fail

Applying all fifty produced seven survivors. A docstring naming an edit its own
test is structurally incapable of detecting is the same defect as no docstring —
it reads like evidence, and it is not.

Five distinct causes turned up, and each needed a different fix.

**An inequality between two SHA-256 digests cannot see a removed
domain-separation prefix.** `tenant_handles_are_unique_and_stable` asserted that
two tenants' handles differ. They do differ — with or without the prefix mixed
in, because the underlying bytes differ. The same held for the principal and
device handles. Domain separation is a claim about two *different* digest
functions behaving differently, and no quantity of `assert_ne!` between outputs
of the same one will show it. Fixed with a cross-kind inequality *and* a
known-answer pin: `assert_eq!(acme.audit_handle(), "12ddd5913bae1479")`. The
handle is a published value an external store correlates against, so its exact
derivation is part of the contract rather than an implementation detail.

**A test that builds its input from the constant it is testing moves with the
constant.** `tenant_an_overlong_tenant_is_refused` used
`"a".repeat(MAX_TENANT_ID_BYTES + 1)`, which raises the bar along with the bound
and stays green. The bound is now pinned outright —
`assert_eq!(MAX_TENANT_ID_BYTES, 64)` — and the mutation was flipped downward,
64 → 8, where a length test can actually see it.

**Spot-checks are not pins.** `escalation_a_role_holds_exactly_its_declared_permissions`
asserted that the Administrator role held `DeviceList`, `PolicyEdit`, and one
other. That survives a table gutted down to those three entries, which is not a
mutation of the table so much as a replacement of it. Replaced with a full
`assert_eq!` against a literal nine-permission array, and the mutation changed
to "delete every entry except `PrincipalManage`".

**A test that cannot fail at all.** `mfa_strength_names_are_static` asserted
that each of four assurance names was non-empty, which every possible string
satisfies. Its mutation renamed `multi_factor` to `mfa` — itself unique, so
undetectable by construction too. The test now pins all four names and asserts
they are distinct; the mutation now changes `multi_factor` to `single_factor`, a
label another strength already uses.

**A test that never checked the property its docstring named.**
`audit_a_different_principal_produces_a_different_digest` asserted that two
principals produced two digests. Nothing checked that the *same* principal
produced the *same* digest, and nothing checked that the raw principal id had
been kept out of the record at all — the mutation it names swaps
`audit_handle()` for `as_str()`, and a record holding `"ann"` in the clear
produces a perfectly distinct digest for every principal, including two records
for the same one. Both are now asserted, the second through `Display`, which
already renders handles only.

The fix was to strengthen the tests, not to soften the mutations — with two
exceptions, where the mutation pointed at something undetectable by construction
and moving it was the only honest option.

The source needed no change. Every mutation the strengthened tests now catch was
already caught by *some* test; the seven were holes in coverage wearing a label
that said otherwise.

### A pairing error was invisible by construction

The original 22 entries were paired to their tests by reading the docstrings in
order, and several were off by one — the tenant-handle entry carried the
audit-query test's name, the administrative-classification entry carried the
managed-device test's, and so on. Nothing caught that, because an entry paired to
the wrong test name still applies and still fails, so the harness reported what
it reported regardless of whose name was on the label. Every entry now names its
test, and the harness checks those names against `tests.rs`, which makes a
pairing error a hard failure instead of a silent one.

Two entries are caught by a test other than the one they name, which is worth
recording rather than smoothing over. The two mutations that add a widening
setter to `PolicyDocument` are caught by
`policy_the_document_type_has_no_widening_operation`, which scans the impl
block for a setter by name, in addition to the test each is aimed at. That
redundancy is also why a mislabelled entry can survive a while: the wrong test
still sees it fail.

Of the 25 mutations applied by hand before the harness, all 25 were caught. Two
initially reported as surviving were investigated manually and *were* caught —
the harness's match had been thrown off by a mutation that failed to compile
elsewhere. One mutation that removes a `let-else` guard breaks the build rather
than passing, which is the structural version of the same protection.

The gate runs in CI by name (`M10 enterprise authorization and audit gate`),
because a removed authorization check makes the code *more* permissive and
every unrelated test still passes. It runs the tests. The mutation gate above
is what proves the tests would notice.

### Counts

72 tests, each declaring at least one `Mutation:` line. 73 mutations, because
`audit_principal_handles_are_unique_and_stable` names two edits to one function
— make `PrincipalId::audit_handle` return `self.0`, or drop its
domain-separation prefix. Both are applied, and they are now caught by different
assertions: the first by the substring check, the second only by the pinned
values.

## The mutation harness checks its own coverage

Every entry names the test whose `Mutation:` docstring it came from, and the
harness refuses to run if the entries and the docstrings disagree in either
direction — a declared mutation nothing applies, or an applied mutation whose
test declares none.

Without that check the gap reopens one test at a time: a test written next
month arrives carrying a `Mutation:` line, reads like evidence, and is not in
the list. The defect this harness was written to close would return wearing
the same shape it had before.

The check reads `tests.rs` for its own list of declared mutations rather than
comparing the two lists to each other. Two lists that agree with each other
and both miss the file are exactly the failure, and it is invisible to a
comparison that never opens the file.

## The mutation harness is multi-file

The other harnesses in this repository mutate one Python or one Rust file.
The enterprise module is five — `mod.rs`, `rbac.rs`, `trusted_device.rs`,
`unattended.rs`, `audit.rs` — so every mutation names its target file
explicitly.

That is not tidiness. Three of this repository's harnesses have shipped
mutations that silently never ran because a pattern did not match, and a
pattern that matches in the wrong module is the same failure wearing a
different hat: a mutation reported as applied when it landed somewhere else,
or reported as skipped when it never ran. A mutation that cannot be applied is
listed, never skipped — a skipped mutation is indistinguishable from a caught
one in a log full of checkmarks.

That is also why each entry names its *test* as well as its file. Six patterns
in this module match in more than one place — `value.trim().is_empty()` guards
both a tenant id and a principal id, and the tenant comparison appears in both
`evaluate` and `evaluate_unattended`. A short pattern that matches twice is
disambiguated by the surrounding lines, and the check above confirms every one
of them still matches exactly one.

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