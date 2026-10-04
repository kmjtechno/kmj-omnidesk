# Roadmap gate admissibility

Every gate `ROADMAP.yaml` declares must be enforced somewhere, and every gate
this repository believes it enforces must still be declared. `scripts/roadmap_admissibility.py`
checks both directions and exits non-zero when either fails.

```
python3 scripts/test_roadmap_admissibility.py      # 35 tests
python3 scripts/roadmap_admissibility.py           # the report
python3 scripts/verify_roadmap_admissibility_mutations.py   # 28 mutations
```

CI runs this as the **Roadmap gate admissibility gate** step. As of the commit
that added it the report is `roadmap_admissible: true` over 55 gates in 14
milestones, of which 6 are human sign-offs.

## Why this exists

A milestone marked `complete` is a claim about a state, not about a check.
Nothing about that state survives being read six months later except whether
something would notice if it stopped being true.

Two of this repository's milestones were in exactly that position, and neither
looked wrong from the outside:

- **M1** declared `authenticated_LAN_session_proof` as an exit criterion. The
  test that proves it existed the whole time in `tests/authenticated_lan.rs`
  and no CI step ever invoked that file. `complete` was accurate about the
  code and silent about the check.
- **M9** declared `purchase_stays_disabled_until_release_gate`.
  `commercial.purchase_enabled_now: false` was set in the roadmap and no code
  read it. There was no path that could consult the value, so it could not
  have been true or false in any sense the product could observe.

Both are now real (`crates/omnidesk-core/src/frame_queue.rs`,
`crates/omnidesk-core/src/commercial_gate.rs`) and both have named CI steps.

## The check that built itself on invention

The first version of the registry pointed at `scripts/verify_control_permission.py`,
`scripts/verify_static_suppression.py`, `scripts/verify_frame_queue_bound.py`,
`scripts/verify_input_roundtrip.py`, `scripts/verify_security_gates.py`,
`scripts/verify_keyboard_navigation.py`, `scripts/verify_audit_events.py`,
`scripts/verify_attachment_policy.py`.

**None of those files were ever written.** The registry was a plausible-looking
claim about enforcement that existed only as text.

The checker refused all 43 of them, and that refusal is the only reason the
invention became visible. This is the fifth harness in this repository where
the failure mode was identical: *an unchanged result is evidence about the test
suite until proven otherwise*. A registry that names a file which does not
exist produces a green run in every other suite in the repository.

Nearly all 43 turned out to be already enforced — as Rust tests whose names
nothing connected to their gates. The gates were **unnamed**, not unenforced,
which is a subtler defect and the reason the `module` enforcement kind exists.

## Enforcement kinds

| Kind | Count | Resolves to | Catches |
| --- | --- | --- | --- |
| `module` | 24 | `crate:path/to/file.rs::function_name` | the test or function being deleted or renamed |
| `ci_step` | 13 | a named step in `.github/workflows/ci.yml` | the step being renamed or removed |
| `checker` | 12 | a `scripts/*.py` file that must exist and run | the checker being deleted |
| `signoff` | 6 | a named human authority | a gate quietly becoming self-certified |

`module` is the newest kind and exists because of the invention above. A
`checker` entry only proved a script existed; it could not say which test in a
400-line Rust file enforced the gate. `module_declares` parses
`fn <name>(` with a regex rather than substring-matching, so a rename that
leaves the old word in a comment or in a longer sibling function does not read
as still-enforced:

```python
return re.search(rf"\bfn\s+{re.escape(function)}\s*\(", source) is not None
```

`test_a_module_entry_does_not_match_a_name_merely_mentioned` writes a probe file
containing `fn stale_session_input_is_rejected_by_policy_v2()` and asserts the
reference to `stale_session_input_is_rejected` does **not** resolve against it.

## Both directions, or neither

Coverage in one direction is not coverage. Two failure modes, both real:

1. **Forward** — a gate declared in `ROADMAP.yaml` with nothing enforcing it.
   Removing a `REGISTRY` entry produces a problem naming that gate.
2. **Reverse** — a `REGISTRY` entry for a gate the roadmap no longer declares.
   Deleting `malformed_input_rejected` from `ROADMAP.yaml` produces a
   `no longer declares` problem, so a requirement cannot be dropped without it
   being reported.

The reverse direction is what makes the registry trustworthy. A registry that
only grows can be made to look complete by adding entries for gates that were
already there.

## And the third direction: a check nobody runs

Everything above asks whether a gate names real enforcement. The opposite
mistake is a real check that nothing invokes, and it was live:

| Harness | Referenced by |
| --- | --- |
| `verify_uninstall_mutations.py` | 0 files |
| `verify_release_gate_mutations.py` | 0 files |
| `verify_m5_evidence_mutations.py` | 0 files |

All three worked when run by hand. No CI step ran any of them. An unrun harness
cannot fail, so it enforces nothing while sitting in the repository looking
like a gate — the same shape as M1's `authenticated_lan` test, one directory
over.

`orphaned_harnesses()` reports any `scripts/*.py` named only by the workflow or
the docs, and all three are now wired to named CI steps. The checker exempts
itself and its own test suite via `HARNESS_ENTRY_POINTS`, recording *why*: CI
reaches `roadmap_admissibility.py` through `test_roadmap_admissibility.py`, so
it never appears by name in `ci.yml`, and the alternative — a self-referencing
CI step that exists only to satisfy this check — would be worse than the
exemption.

### What counts as an invocation

A test suite naming a harness does **not** count. This was the bug that made
the check itself untrustworthy: the first version read every `scripts/*.py` as
evidence, so writing a probe inside a test put that probe's name into
`test_roadmap_admissibility.py`, which the check then read as proof the probe
was invoked. Two tests failed against a tool that was otherwise correct — it
could not see the exact case it exists to detect.

Test files are excluded from the haystack, and the tests build probe filenames
at run time (`uuid4`) rather than writing a literal, so no prose anywhere can
excuse a probe by having read its name. That is the same discipline
`module_declares` applies: a name in a comment is not a declaration.

A second bug surfaced the same way: `docs` was passed as a path rather than
globbed, so `read_text` on the directory raised `IsADirectoryError`, was
swallowed by `except OSError`, and the entire documentation tree was silently
skipped. A test asserting "docs count" failed against a tool whose own
docstring claimed docs counted.

## Sign-offs are not checkers

Six gates cannot be settled by a program, and the registry refuses to pretend:

```
M7  keyboard_navigation_verified                  accessibility review, on a real keyboard traversal
M11 critical_findings_zero                         security review, by a reviewer other than the author
M11 high_findings_zero_or_explicitly_block_release security review, by a reviewer other than the author
M11 threat_model_reviewed                         security review, by a reviewer other than the author
M12 signature_verification_pass                    release engineering, with a production key
M13 full_matrix_complete                           performance engineering, on real multi-hardware runs
```

`check_enforcement_exists(..., "signoff", "   ")` returns **False**. A
sign-off with nobody answerable for it is worse than an unimplemented gate,
because it reads as handled.

`test_the_human_judgement_gates_are_not_given_an_invented_checker` pins this:
registering `critical_findings_zero` against a script this repository wrote
would make it pass. The script would agree with its own author. That is the
specific failure a `signoff` kind exists to make unrepresentable.

No milestone status in `ROADMAP.yaml` was changed by any of this work.

## Per-milestone coverage

```
M0   3  checker 2, module 1        M8   6  ci_step 2, module 4
M1   3  ci_step 2, module 1        M9   7  ci_step 1, module 6
M2   4  ci_step 2, module 2        M10  3  module 3
M3   6  module 5, ci_step 1        M11  4  signoff 3, ci_step 1
M4   3  ci_step 2, checker 1       M12  2  checker 1, signoff 1
M5   6  checker 6                 M13  2  signoff 1, checker 1
M6   3  module 2, checker 1        M14  -  gates live in scripts/release_gate.py
M7   3  ci_step 2, signoff 1
```

M14 declares no gates in `ROADMAP.yaml` — its seven live in
`scripts/release_gate.py`, gated by `test_release_gate.py`. The checker
therefore reports 15 milestones parsed and 14 with gates, and
`test_every_milestone_with_gates_is_covered` compares against the milestones
that actually declare gates rather than against a constant, precisely so that
M14's absence is a derived fact and not an assumption.

## What this does not do

It does not verify that a named test asserts what its gate claims. It proves
the test **exists and runs**. M3's `malformed_input_rejected` resolves to a
`fn` name in `input.rs`; whether that function rejects malformed input is a
question about the test, and mutation verification is the answer to it — which
is what `scripts/verify_roadmap_admissibility_mutations.py` does for the checker
itself, and what the existing per-milestone mutation harnesses do for their own
code.

The boundary is deliberate. A checker that tried to verify test *semantics*
would be a second, weaker copy of the test suite, and it would pass whenever
the copy was wrong in the same way.

## A case where that boundary cost something

M10 declares three gates, all resolved by `module`, so all three were
"covered" while `enterprise::tests` held 62 passing tests. Auditing the public
functions of `enterprise/trusted_device.rs` by hand found a check that all 62
missed.

`TrustRegistry::assess` calls `device.is_revoked()` and returns before it ever
calls `device.is_trusted_at`. So the `!self.revoked` conjunct *inside*
`is_trusted_at` is never the deciding clause on that path. Deleting it leaves
every `assess` test green — verified, not inferred: the only failing test after
the edit was the one written to catch it.

It is load-bearing somewhere else. `PolicyEngine::evaluate` calls
`is_some_and(DeviceTrust::is_trusted_at_now)` with no earlier revoked check, so
removing the conjunct makes a `require_trusted_device` policy **allow** a
revoked device — and no test noticed, because no test called the predicate
directly.

The gate was enforced in both directions and neither direction saw it. What
caught it was reading which caller decided the outcome, not any checker.

Five tests now cover the predicates directly. Each was mutation-verified:
dropping the conjunct fails 1, `<` to `<=` fails 3, `assessed_at` to `u64::MAX`
fails 3, swapping the `assess` check order fails 2, inverting
`TrustDecision::is_trusted` fails 1.

The generalisable form: a predicate can be fully exercised through one caller
and entirely unguarded through another, and a coverage count cannot tell those
apart. Only the mutation does.

## Mutation coverage

`verify_roadmap_admissibility_mutations.py` applies 28 edits, one per
behaviour, and requires each to be caught. The survivors from the first run,
and what each was missing:

- **Inline list syntax** (`depends_on: [M4]`) had no test. A reader handling
  only block lists returns `[]` for every one of them — a silent wrong answer
  rather than an error.
- **An unclean tree being inadmissible** had no test. `test_every_declared_gate
  _is_enforced` and `test_the_real_roadmap_is_admissible` both pass on a tool
  that reports every problem and always says PASS. That is the complement-test
  gap, in its purest form.
- **`gates_covered` reported as a constant** survived because the test compared
  it to the roadmap's own total. `len(covered)` and the roadmap total are equal
  *exactly when the tool is working*, so substituting today's number left the
  test green. It now compares against the `REGISTRY` total and then removes an
  entry, so the two disagree and the constant cannot survive.

That third one is the general lesson, and it has now cost this repository four
harnesses: `M5`'s integrity problems computed and discarded, this test's
self-comparison, the invented script names, and M1's CI step that ran nothing.
