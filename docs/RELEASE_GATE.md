# M14 — Commercial Release Gate

`ROADMAP.yaml` M14 declares seven gates and an objective: *enable customer
availability only after technical and commercial authority agree.*

Until `scripts/release_gate.py` existed, **none of the seven gates was
referenced anywhere in the repository.** Every one of them was satisfied by
nothing in particular. That is the same hole M12 and M13 each had, one level
up, and it was the last milestone never to have been touched.

## What the tool does, and what it deliberately does not

It does not decide whether to ship. It decides whether a *claim* that the gates
are met is backed by evidence, and refuses the claim when it is not.

A milestone flipping to `complete` is a status someone typed. This is the check
that makes typing it insufficient.

It cannot detect a dishonest report. It can only require the report to exist
and to be internally consistent with the manifests it points at.

## The check that matters most

**Every gate M14 declares must have a checker here, or be explicitly marked
`requires_signoff` with the authority who must provide it.** A gate that is
neither is an error, not a pass.

This is the enforcement that stops the milestone regrowing the hole it was
born with. Adding a gate to M14 without deciding how it is verified makes the
tool fail — which is the moment to decide.

The check runs in **both** directions:

- a gate in the roadmap that nothing checks is an error, and
- a checker here whose gate has been dropped from the roadmap is an error.

The second is the one usually forgotten. Without it, deleting a gate from
`ROADMAP.yaml` leaves a checker behind that no gate calls — a silent removal of
a release requirement, which is exactly what the milestone exists to make
impossible.

The gate list is read *back out of `ROADMAP.yaml`* rather than copied into the
tool. Copying it would defeat the check: adding a gate to the roadmap would
then go unnoticed, which is the one thing this must never miss.

## The seven gates

| Gate | How it is checked |
|---|---|
| `signed_release_artifacts` | Each artifact is on disk, its SHA-256 matches, and it carries a per-artifact `signature_declared` |
| `update_metadata_verified` | Every channel's metadata document exists, parses, and is declared signed |
| `licensing_integration_verified` | The contract exists, parses, and declares at least one plan |
| `security_gate_pass` | Every named CI check is reported `green`, and the set is not empty |
| `performance_gate_pass` | Delegated to `m13_matrix.py verify` — M13's rules decide admissibility, not this tool |
| `support_and_recovery_path_defined` | **Requires sign-off** from `support_lead` |
| `legal_and_codec_license_review_complete` | **Requires sign-off** from `legal_counsel` |

## Three distinctions this file is careful about

**`signature_declared` is not `signature_verified`.** This tool refuses a
release that merely *claims* to be signed. It cannot verify a signature — that
needs production keys and the real verifier, and it is why M14 stays pending.
But a gate that accepted the claim would be a gate about a field someone typed.

**A release-level `signed: true` is not a per-artifact signature.** Each
artifact must say so individually. The failure this exists for is a release
that certifies a signed set and ships an unsigned binary among them.

**An empty set is not a pass.** No artifacts, no security checks — both refuse.
This is the shape of check most easily written by accident, and it is exactly
how a gate that runs nothing certifies itself: "every check is green" is
vacuously true of the empty set.

## Sign-off gates

`requires_signoff` gates are **never** satisfied by this tool. They are
reported with the named authority and `satisfied_by_tool: false`, and while
any is outstanding the report cannot be `admissible`.

A sign-off gate the tool can pass on its own is not a sign-off gate — it is a
gate rubber-stamping its own most important requirement, on the one milestone
where that matters most.

The two are marked sign-off rather than automated because no program can check
them: a runbook either exists or it does not, and a codec licence question has
no automated oracle. Marking them as *deliberately* outside the tool's reach is
honest; marking them green would not be.

## Usage

```bash
python3 scripts/release_gate.py --release evidence/release/rc1.json
```

Exits non-zero whenever the report is not admissible, and prints the full
report to stdout either way.

## Verification

27 tests, each naming the single edit that would make it pass while the gate is
broken. All 24 mutations were applied and caught.

Three findings worth recording, because in each case the harness and the tests
disagreed and one of them was wrong:

- **A missing-document mutation survived.** Running it by hand confirmed the
  behaviour really had changed — a missing licensing contract went from refused
  to silently accepted — so the suite had *no test covering that path at all*,
  not that the mutation was equivalent. The lesson is the one this repo keeps
  relearning: an unchanged result is evidence about the test suite until proven
  otherwise.

- **The sign-off test proved nothing for a while.** It asserted `admissible` is
  `False` — but the fixture had no performance matrix, so it was `False` for an
  unrelated reason and stayed `False` even when sign-offs stopped counting. The
  mutation `admissible = not problems` passed it. It now runs against a gate set
  where the automatic gates are *all green*, so the sign-off is the only thing
  that can turn the result.

- **The digest test passed against its own mutation.** It forged an all-zeros
  digest, which fails a truncated comparison too. It now forges a digest sharing
  its first 12 characters with the real one, which only a full comparison
  rejects.

The complement test (`test_a_release_over_only_checkable_gates_is_admissible`)
exists because without it, "coverage problems are counted" and "the report is
never admissible" would both be satisfied by a tool that refuses everything —
and a mutation making `admissible` permanently `False` would pass every other
test in the file.

## What this does not deliver

**It cannot verify a signature.** U1 needs the real verifier and a real key.

**It cannot detect a forged report.** It requires the security checks to be
listed and green; it cannot tell a passing review from a report claiming one.

**It does not verify M13's numbers.** It delegates. M13's checker is the
authority on what an admissible matrix is, and a second implementation here
would be a second opinion nobody asked for.

**M14's status stays `pending`.** Two gates need a human authority this
repository does not have. What changed is that the milestone can no longer be
marked complete by typing.

There is no `--force` and no suppression flag, for the reason
`scan_secrets.py` documents: a flag to skip a gate is how a gate quietly stops
working.

## Relationship to M11 and M13

M11's `threat_model` and M13's `network-profiles.yaml` rules were each
statements with nothing enforcing them; both got checkers. M14 is the same
shape one level up, and it is the last milestone in the roadmap that had never
been touched at all.

The three share one property: the tool does not decide the thing. M11's checker
does not review a threat model, M13's does not judge a benchmark good, and
this one does not decide to ship. Each only makes the claim falsifiable.