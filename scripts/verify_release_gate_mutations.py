"""Mutation harness for the M14 release gate.

Applies one edit at a time, runs the tests, and reports whether any failed. A
mutation that leaves the suite green is a hole in the tests, not a win.

Matches against the whole file rather than line by line: a pattern `rustfmt`
or a long expression has wrapped across two lines never matches line-by-line,
so those mutations get reported as "apply failed" and silently never run. That
happened in the U8 harness and hid four mutations there too.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "release_gate.py"

# (label, must-contain, replacement)
MUTATIONS: list[tuple[str, str, str]] = [
    # --- gate coverage: M14's defining property -------------------------
    (
        "gate_coverage ignores unenforced gates",
        'if gate not in GATES:\n            problems.append(',
        'if False:\n            problems.append(',
    ),
    (
        "gate_coverage ignores gates dropped from the roadmap",
        'if gate not in roadmap_m14_gates:\n            problems.append(',
        'if False:\n            problems.append(',
    ),
    (
        "gate_coverage returns nothing",
        "return problems\n\n\ndef evaluate(",
        "return []\n\n\ndef evaluate(",
    ),
    # --- signed artifacts ------------------------------------------------
    (
        "a missing digest counts as a match",
        'if not declared_digest:\n            problems.append(',
        'if False:\n            problems.append(',
    ),
    (
        "digest comparison is truncated",
        "elif declared_digest != actual_digest:",
        "elif declared_digest[:12] != actual_digest[:12]:",
    ),
    (
        "a missing signature is accepted",
        'if not entry.get("signature_declared"):\n            problems.append(',
        'if False:\n            problems.append(',
    ),
    (
        "an artifact absent from disk is skipped",
        "if not path.is_file():\n            problems.append(",
        "if False:\n            problems.append(",
    ),
    (
        "a release with no artifacts passes",
        'if not artifacts:\n        return ["signed_release_artifacts',
        "if not artifacts:\n        return []\n    if not artifacts:\n        return ['x'",
    ),
    # --- update metadata -------------------------------------------------
    (
        "metadata need not be signed",
        'elif not document.get("signature_declared"):\n            problems.append(',
        'elif False:\n            problems.append(',
    ),
    (
        "missing metadata is treated as satisfied",
        'if document is None:\n            problems.append(',
        'if document is None:\n            document = {}\n        if False:\n            problems.append(',
    ),
    (
        "no declared metadata passes",
        'if not metadata:\n        return ["update_metadata_verified',
        'if not metadata:\n        return []\n    if not metadata:\n        return ["update_metadata_verified',
    ),
    # --- licensing -------------------------------------------------------
    (
        "a contract with no plans passes",
        'if not isinstance(plans, list) or not plans:\n        return [',
        'if False:\n        return [',
    ),
    (
        "a missing contract passes",
        '    if document is None:\n        return [\n            f"licensing_integration_verified',
        '    if document is None:\n        return []\n    if False:\n        return [\n            f"licensing_integration_verified',
    ),
    (
        "no declared contract passes",
        'if not entry:\n        return ["licensing_integration_verified',
        'if not entry:\n        return []\n    if not entry:\n        return ["x"',
    ),
    # --- security gate ---------------------------------------------------
    (
        "only the presence of security checks is checked",
        'if check.get("status") != "green":',
        'if False:',
    ),
    (
        "an empty security check set passes",
        'if not isinstance(checks, list) or not checks:\n        return [\n            "security_gate_pass',
        'if not isinstance(checks, list) or not checks:\n        return []\n    if not isinstance(checks, list) or not checks:\n        return [\n            "security_gate_pass',
    ),
    # --- performance delegation ------------------------------------------
    (
        "a missing performance matrix is skipped",
        'if not matrix_root.is_dir():\n        return [',
        'if not matrix_root.is_dir():\n        return []\n    if not matrix_root.is_dir():\n        return ["x"',
    ),
    (
        "M13's refusal is swallowed",
        "except SystemExit as refusal:\n        return [f\"performance_gate_pass",
        "except SystemExit:\n        return []\n    except BaseException as refusal:\n        return [f\"performance_gate_pass",
    ),
    # --- the signoff rule: the most consequential check here -------------
    (
        "a signoff gate counts as satisfied",
        'and report["gates"][gate].get("status") == "requires_signoff"',
        "and False",
    ),
    (
        "admissible ignores pending signoffs",
        "report[\"admissible\"] = not problems and not signoffs_pending",
        "report[\"admissible\"] = not problems",
    ),
    (
        "signoffs_pending reads the wrong key",
        'and report["gates"][gate].get("status") == "requires_signoff"',
        'and report["gates"][gate].get("requires_signoff") is not None',
    ),
    (
        "a signoff gate is marked satisfied by the tool",
        '"satisfied_by_tool": False,',
        '"satisfied_by_tool": True,',
    ),
    # --- the report as a whole ------------------------------------------
    (
        "coverage problems do not affect admissibility",
        'problems: list[str] = list(gate_coverage(roadmap_m14_gates))',
        "problems: list[str] = []",
    ),
    (
        "the CLI always exits zero",
        "return 0 if report[\"admissible\"] else 1",
        "return 0",
    ),
]


def apply_mutation(old: str, new: str) -> bool:
    source = TOOL.read_text(encoding="utf-8")
    if old not in source:
        return False
    TOOL.write_text(source.replace(old, new, 1), encoding="utf-8")
    return True


def run_tests() -> tuple[bool, str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "test_release_gate.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0, result.stdout + result.stderr


def main() -> int:
    original = TOOL.read_text(encoding="utf-8")
    baseline_failed, output = run_tests()
    if baseline_failed:
        print("FAIL: baseline release-gate tests do not pass")
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