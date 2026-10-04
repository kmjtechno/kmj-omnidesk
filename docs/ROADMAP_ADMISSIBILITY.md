# Roadmap gate admissibility

Every gate `ROADMAP.yaml` declares must be enforced somewhere, and every gate
this repository believes it enforces must still be declared. `scripts/roadmap_admissibility.py`
checks both directions and exits non-zero when either fails.

```
python3 scripts/test_roadmap_admissibility.py      # 27 tests
python3 scripts/roadmap_admissibility.py           # the report
python3 scripts/verify_roadmap_admissibility_mutations.py   # 21 mutations
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

## Mutation coverage

`verify_roadmap_admissibility_mutations.py` applies 21 edits, one per
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
