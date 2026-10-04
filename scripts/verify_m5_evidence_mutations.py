"""Mutation harness for the M5 relay-evidence tool.

Applies one edit at a time, runs the tests, and reports whether any failed. A
mutation that leaves the suite green is a hole in the tests, not a win.

Matches against the whole file rather than line by line: a pattern `rustfmt`
or a long expression has wrapped across two lines never matches line-by-line,
so those mutations get reported as "apply failed" and silently never run. That
happened in the U8 harness and hid four mutations there, and again in the M14
harness.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "m5_evidence.py"

# (label, must-contain, replacement)
MUTATIONS: list[tuple[str, str, str]] = [
    # --- gate coverage: the rule that stops M5 regrowing its hole ----------
    (
        "gate_coverage ignores unenforced exit criteria",
        "if criterion not in EXIT_CRITERIA:\n            problems.append(",
        "if False:\n            problems.append(",
    ),
    (
        "gate_coverage ignores unenforced security gates",
        "if gate not in SECURITY_GATES:\n            problems.append(",
        "if False:\n            problems.append(",
    ),
    (
        "gate_coverage ignores a criterion dropped from the roadmap",
        'if criterion not in exit_criteria:\n            problems.append(',
        "if False:\n            problems.append(",
    ),
    (
        "gate_coverage ignores a gate dropped from the roadmap",
        'if gate not in security_gates:\n            problems.append(',
        "if False:\n            problems.append(",
    ),
    (
        "gate_coverage returns nothing",
        "    return problems\n\n\ndef gate_runs(",
        "    return []\n\n\ndef gate_runs(",
    ),
    (
        "coverage problems do not affect the report",
        'problems: list[str] = list(check_gate_coverage(exit_criteria, security_gates))',
        "problems: list[str] = []",
    ),
    # --- the evidence-class discipline: the tool's central claim ----------
    (
        "any evidence class establishes any exit criterion",
        "if evidence_class not in admitted:",
        "if False:",
    ),
    (
        "an unknown evidence class is accepted",
        "if evidence_class not in EVIDENCE_CLASSES:",
        "if False:",
    ),
    (
        "a forced link run establishes confidentiality too",
        '"end_to_end_confidentiality_preserved": ("transport_observed",),',
        '"end_to_end_confidentiality_preserved": ("transport_observed", "link_forced_observed"),',
    ),
    (
        "code observation satisfies the exit criteria",
        '"forced_direct_failure_falls_back_to_relay": ("link_forced_observed",),',
        '"forced_direct_failure_falls_back_to_relay": ("link_forced_observed", "code_observed"),',
    ),
    # --- observation integrity --------------------------------------------
    (
        "a deleted raw observation is skipped",
        "if not path.is_file():\n        problems.append(",
        "if False:\n        problems.append(",
    ),
    (
        "digest comparison is truncated",
        "if actual != digest:",
        "if actual[:12] != digest[:12]:",
    ),
    (
        "a missing digest counts as a match",
        'if not digest:\n        return [f"{run_id}: no raw observation hashed"]',
        "if not digest:\n        return []",
    ),
    (
        "integrity problems do not withhold satisfaction",
        "if not integrity and not class_errors:\n            honoured += 1",
        "honoured += 1",
    ),
    # --- class-specific requirements --------------------------------------
    (
        "a code run need not name its test binary",
        "if probe != CODE_EVIDENCE_REQUIRED_PROBE:",
        "if False:",
    ),
    (
        "a transport run need not name its endpoints",
        'for field in ("relay_endpoint", "client_endpoint", "server_endpoint"):\n            if not entry.get(field):',
        'for field in ("relay_endpoint", "client_endpoint", "server_endpoint"):\n            if False:',
    ),
    (
        "a forced link run need not record how the link was broken",
        'if not impairment.get("method") or not impairment.get("applied_before_session"):',
        "if False:",
    ),
    (
        "an impairment applied after the session is accepted",
        'not impairment.get("applied_before_session"):',
        "False:",
    ),
    (
        "an impairment document is not required at all",
        'if not isinstance(impairment, dict):\n            errors.append',
        "if False:\n            errors.append",
    ),
    # --- the fail-closed rule: the most consequential check here -----------
    (
        "a report with no unauthorized attempt passes",
        "    if not attempts:\n        return [",
        "    if not attempts:\n        return []\n    if not attempts:\n        return [",
    ),
    (
        "a forwarded unauthorized attempt is accepted",
        'if outcome == "refused":',
        'if outcome is not None:',
    ),
    (
        "a missing unauthorized outcome counts as a refusal",
        "if outcome is None:\n            problems.append(f\"{run_id}: unauthorized attempt records no outcome\")\n            continue",
        "if outcome is None:\n            outcome = 'refused'",
    ),
    (
        "an attempt on an unsound run still counts as refused",
        "if integrity or class_errors:\n                problems.extend(integrity)",
        "if False:\n                problems.extend(integrity)",
    ),
    # --- recording ---------------------------------------------------------
    (
        "a duplicate run id is accepted",
        "if entry_.get(\"run_id\") == run_id:",
        "if False:",
    ),
    (
        "a gate M5 does not declare is accepted",
        "if unknown:\n        fail(",
        "if False:\n        fail(",
    ),
    (
        "an unknown evidence class is accepted at record time",
        "if evidence_class not in EVIDENCE_CLASSES:\n        fail(",
        "if False:\n        fail(",
    ),
    (
        "the run id is not validated",
        'run_id = validate_run_id(args.run_id)\n\n    evidence_class',
        'run_id = args.run_id\n\n    evidence_class',
    ),
    # --- the report as a whole --------------------------------------------
    (
        "a run observing no gate still satisfies every gate",
        'if not candidates:\n        return False, [\n            f"{gate}: no recorded run observes this gate"\n        ]',
        "if not candidates:\n        candidates = entries",
    ),
    (
        "an empty ledger is not a problem",
        'if not entries:\n        problems.append(f"no runs recorded under {root}; nothing was observed")',
        "if False:\n        problems.append(f\"no runs recorded under {root}; nothing was observed\")",
    ),
    (
        "m5_satisfied ignores the problems",
        '"m5_satisfied": not problems,',
        '"m5_satisfied": True,',
    ),
    # --- a file named but unreadable --------------------------------------
    # The original `or {}` and the two failures it caused. Restoring `or {}`
    # is the historical bug verbatim, and the other two are the ways this
    # guard can stop working while still reading like a guard.
    (
        "an unreadable impairment file is recorded as an empty one",
        "    if document is None:\n        fail(f\"could not read {label} at {value}\")\n    return document",
        "    return document or {}",
    ),
    (
        "an unreadable file is recorded without complaint",
        "    if document is None:\n        fail(f\"could not read {label} at {value}\")\n    return document",
        "    return document",
    ),
    (
        "the refusal names no file to act on",
        'fail(f"could not read {label} at {value}")',
        "fail('could not read the document')",
    ),
    (
        "omitting an optional document is refused too",
        "    if not value:\n        return {}",
        "    if not value:\n        return {}\n    fail('naming a document is required')",
    ),
]


def apply_mutation(old: str, new: str) -> bool:
    """Apply one mutation, or report False so the caller can list it.

    Matches against the whole file rather than line by line: a pattern
    spanning two lines -- which is what a formatter produces for a long
    condition -- never matched, so the mutation was reported as "apply failed"
    and skipped rather than run. That has now hidden results in two separate
    harnesses in this repository.
    """
    source = TOOL.read_text(encoding="utf-8")
    if old not in source:
        return False
    TOOL.write_text(source.replace(old, new, 1), encoding="utf-8")
    return True


def run_tests() -> tuple[bool, str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "test_m5_evidence.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0, result.stdout + result.stderr


def main() -> int:
    original = TOOL.read_text(encoding="utf-8")
    baseline_failed, output = run_tests()
    if baseline_failed:
        print("FAIL: baseline m5-evidence tests do not pass")
        print(output[-2000:])
        TOOL.write_text(original, encoding="utf-8")
        return 1
    print(f"baseline: PASS ({len(MUTATIONS)} mutations)\n")

    survivors: list[str] = []
    skipped: list[str] = []
    for label, old, new in MUTATIONS:
        if not apply_mutation(old, new):
            skipped.append(label)
            continue
        caught, _ = run_tests()
        TOOL.write_text(original, encoding="utf-8")
        if caught:
            print(f"CAUGHT: {label}")
        else:
            print(f"SURVIVED: {label}")
            survivors.append(label)

    print()
    for item in skipped:
        print(f"APPLY-FAILED: {item}")
    if survivors:
        print(f"\n{len(survivors)} mutation(s) survived")
        return 1
    if skipped:
        print(f"\n{len(skipped)} mutation(s) were never applied")
        return 1
    print("all mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
