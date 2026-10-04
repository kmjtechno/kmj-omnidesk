# M5 — Relay Evidence Admissibility

`ROADMAP.yaml` M5 declares three exit criteria and three security gates. Until
`scripts/m5_evidence.py` existed, **none of the six was referenced anywhere in
the repository.** `relay.rs` implemented the policy and `ci.yml` gated the
module's tests, but "the relay module has tests" and "a relay was observed
preserving a session on a real network" are different claims, and nothing in the
tree could tell them apart.

This tool does not decide whether M5 is done. It decides whether a *report*
claiming M5's gates are met rests on an observation that still holds, and
refuses the report when it does not.

## The distinction that makes it worth having

M5's exit criteria need two NAT networks, a relay operator, and a real session.
**This repository has none of those.** What it can do — and what was missing —
is make the absence visible instead of silent.

So the tool has three evidence classes, and the split is the whole design:

| Class | What it is | What it can establish |
|---|---|---|
| `code_observed` | The relay module's own tests | The interface gates only |
| `transport_observed` | A relay exercised over a real transport | Confidentiality, utilization |
| `link_forced_observed` | A shaped link that broke direct establishment *before* the session | Fallback, utilization |

The critical property is the one that is missing: **there is no class that lets
a cheap observation stand in for an expensive one.** If `code_observed` could
satisfy `end_to_end_confidentiality_preserved`, the exit criteria would be
satisfiable by running `cargo test`, which is precisely the equivalence this
exists to prevent.

Each criterion also has its own admitted classes rather than sharing a default.
`end_to_end_confidentiality_preserved` admits `transport_observed` but *not*
`link_forced_observed`: a shaped link tells you nothing about what the relay
could read. Those are different questions and the tool does not let one answer
for the other.

## The gate that must not pass on absence

`authorization_failure_is_fail_closed` gets a check of its own, because it is
the one gate where *missing* evidence is itself the finding.

A report whose runs contain no unauthorized attempt is refused with: *"a relay
that was never asked has not been shown to fail closed."* That is not
pedantry. A relay nobody asked to authorize anything has not failed closed —
it has simply never been asked, and returning clean here is how a report would
claim the property on no evidence at all.

The refusal only becomes a pass when a run records an unauthorized attempt, its
outcome is `refused`, **and that run's own observation is otherwise sound**.
A refusal claimed by a run whose raw file no longer hashes to what was recorded
is a claim about a file that may since have been replaced.

This is also the same defect class the tool exists to catch — an unbacked
assertion — turning up inside the tool itself. It was found by mutation, and the
test that found it is `test_a_refusal_on_a_tampered_run_does_not_satisfy_the_gate`.

## Coverage runs in both directions

Every criterion and gate M5 declares must have a check here, and every check
here must name a gate M5 *still* declares.

The second direction is the one usually forgotten, and it is the one that
catches a removal. Deleting `authorization_failure_is_fail_closed` from
`ROADMAP.yaml` is one line; without the reverse check, the checker for it would
go on running uninvoked and the gate would be gone with nothing reporting it.

The gate list is read back out of `ROADMAP.yaml` rather than copied into the
tool. A copy is not a check — adding a gate to the roadmap would go unnoticed,
which is the one thing this must never miss.

## Current state, honestly

`m5_satisfied` is **false**, and no amount of code changes it:

- The three exit criteria need a real relay over a real transport, and a shaped
  link broken before session establishment. Nobody has run that.
- The three security gates are reachable — two of them from `code_observed`,
  since the relay's interface settles them structurally — but the fail-closed
  gate additionally requires an unauthorized attempt to have been made and
  refused.

Recording a `code_observed` run is cheap and available today. It establishes the
interface gates and nothing else. That asymmetry is deliberate: it is better to
have two of six gates honestly observed than six unbacked.

## Usage

```bash
python3 scripts/m5_evidence.py init   --root evidence/m5
python3 scripts/m5_evidence.py record --root evidence/m5 \
    --run-id M5-TRANS-R001 \
    --evidence-class transport_observed \
    --raw artifacts/relay-session-001.json \
    --gate end_to_end_confidentiality_preserved \
    --relay-endpoint relay.example:4433 \
    --client-endpoint 10.0.0.1:9000 --server-endpoint 10.0.0.2:9000
python3 scripts/m5_evidence.py verify --root evidence/m5
```

`record` refuses a duplicate run id — the observable form of the failure
`cherry_picking_forbidden` names in M13: a bad run cannot be replaced by a good
one under the same name, because the name is taken.

## Verification

41 tests, each naming the single edit that would let the gate pass while it is
broken. All 30 mutations were applied and caught.

Four survived the first run, and in every case the harness and the tests
disagreed:

- **Both forward coverage checks were reported as covered but were not.** The
  tests added an unknown gate name to the input list and asserted *that name*
  appeared in the problems. But an unknown name also trips the *reverse*
  check, so both mutations that disabled the forward direction still passed —
  the assertion was satisfied by a different check reporting the same string.
  Each test now asserts on a message fragment only its own direction can
  produce (`"has no check"` vs `"no longer declares"`).

- **A refusal on a tampered run counted as refused.** The behaviour was already
  correct; nothing exercised it. The mutation survived because the path had no
  test at all.

- **Dropping `validate_run_id` from `record` changed nothing observable.** There
  was a test for the regex and no test for the *call*. Testing that a pattern
  rejects a bad string is not the same as proving `record` uses it, and the gap
  let a malformed run id walk into the ledger where `gate_runs` would later
  match it against a real gate name.

The same first-run harvest found six **real bugs in the tool itself**, which is
the more interesting result. `gate_satisfied` collected integrity and
class-requirement problems and appended them to a `problems` list that nothing
acted on — a deleted raw file, a missing endpoint, or a missing test binary was
reported and then ignored, and the gate still read `observed`. Six tests failed
on it. The lesson is the one this repository keeps relearning: a check wired to
no outcome looks identical to a check that works until something tries to break
it.

The complement test
(`test_a_run_observing_every_gate_with_admissible_evidence_satisfies_the_report`)
exists because without it, a tool that refused every report forever would pass
every other test in the file.

## What this does not deliver

**It cannot observe a relay.** It has no network access, starts no process, and
reads no transport. It checks a report.

**It cannot detect a forged observation file.** A run that hashes correctly and
names real endpoints may still describe something that did not happen. The
digest proves the file is unchanged; it says nothing about whether the file said
anything relevant.

**M5 stays `pending`.** Nothing here changes that. What changed is that M5's
status is no longer a sentence nobody is checking.

There is no `--force` and no suppression flag, for the reason
`scan_secrets.py` documents: a flag to skip a gate is how a gate quietly stops
working.

## Relationship to M13 and M14

M13's collector proves *what was published is what was measured*. This one
proves *the relay claim rests on an observation that still holds*. M14's
release gate delegates its performance check to M13's checker rather than
writing a second opinion; this tool follows the same rule and never judges
whether an observed relay was a *good* relay — only whether one was observed
and the observation still stands.
