"""Mutation harness for the roadmap admissibility checker.

Applies one edit at a time, runs the tests, and reports whether any failed. A
mutation that leaves the suite green is a hole in the tests, not a win.

Matches against the whole file rather than line by line: a pattern that a
formatter wrapped across two lines never matches line-by-line, so those
mutations get reported as "apply failed" and silently never run. That has
hidden results in three separate harnesses in this repository.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "roadmap_admissibility.py"

# (label, must-contain, replacement)
MUTATIONS: list[tuple[str, str, str]] = [
    # --- the forward direction: a declared gate with no enforcement --------
    (
        "a criterion with no enforcement is accepted",
        "if entry is None:\n                problems.append(",
        "if False:\n                problems.append(",
    ),
    # --- the reverse direction: a *removal* from the roadmap --------------
    (
        "a gate removed from the roadmap is not reported",
        "for name in registry:\n            if name not in declared:",
        "for name in registry:\n            if False:",
    ),
    (
        "a registry milestone absent from the roadmap is not reported",
        "if milestone not in milestones:\n            problems.append(",
        "if False:\n            problems.append(",
    ),
    # --- enforcement existence: the check that caught the invented names --
    (
        "a missing checker script counts as enforcement",
        'if kind == "checker":\n        return (root / enforcement).is_file()',
        'if kind == "checker":\n        return True',
    ),
    (
        "a missing CI step counts as enforcement",
        'if kind == "ci_step":\n        return enforcement in ci_step_names(root / ".github" / "workflows" / "ci.yml")',
        'if kind == "ci_step":\n        return True',
    ),
    (
        "a missing test file counts as enforcement",
        "path = root / \"crates\" / crate / relative\n    if not path.is_file():\n        return False",
        "path = root / \"crates\" / crate / relative\n    if not path.is_file():\n        return True",
    ),
    (
        "a module entry matches a bare name rather than a declaration",
        'return re.search(rf"\\bfn\\s+{re.escape(function)}\\s*\\(", source) is not None',
        "return function in source",
    ),
    (
        "a module entry ignores the function name entirely",
        'return re.search(rf"\\bfn\\s+{re.escape(function)}\\s*\\(", source) is not None',
        "return True",
    ),
    (
        "a malformed module reference is accepted",
        'if len(parts) != 2 or ":" not in parts[0]:',
        "if False:",
    ),
    (
        "an unknown enforcement kind is accepted",
        '    fail(f"unknown enforcement kind {kind!r}")',
        "    return True",
    ),
    # --- sign-off gates: the ones a program must not pretend to settle ----
    (
        "a sign-off with no authority counts as enforced",
        "return bool(enforcement.strip())",
        "return True",
    ),
    # --- CI step names: read back, not assumed ---------------------------
    (
        "CI step names are not read from the workflow",
        "return {\n        match.group(1).strip()\n        for match in re.finditer(r\"^\\s*-?\\s*name:\\s*(.+?)\\s*$\", text, re.M)\n    }",
        "return set()",
    ),
    (
        "a missing workflow yields no step names instead of failing",
        "except FileNotFoundError:\n        fail(f\"missing workflow: {workflow}\")",
        "except FileNotFoundError:\n        return set()",
    ),
    # --- roadmap parsing: the milestone boundary --------------------------
    (
        "the next milestone's gates are read as this milestone's",
        "end = starts[index + 1] if index + 1 < len(starts) else len(lines)",
        "end = len(lines)",
    ),
    (
        "a roadmap with no milestones yields an empty dict",
        'if not starts:\n        fail(f"{path}: no milestones found")',
        "if not starts:\n        return {}",
    ),
    (
        "a missing roadmap yields an empty dict",
        "except FileNotFoundError:\n        fail(f\"missing roadmap: {path}\")",
        "except FileNotFoundError:\n        return {}",
    ),
    (
        "inline list syntax is not parsed",
        "if inline.startswith(\"[\") and inline.endswith(\"]\"):\n                return [item.strip() for item in inline[1:-1].split(\",\") if item.strip()]",
        "if False:\n                return [item.strip() for item in inline[1:-1].split(\",\") if item.strip()]",
    ),
    # --- the report as a whole -------------------------------------------
    (
        "problems do not affect admissibility",
        '"roadmap_admissible": not problems,',
        '"roadmap_admissible": True,',
    ),
    (
        "the gate count is reported rather than derived",
        '"gates_covered": len(covered),',
        '"gates_covered": 55,',
    ),
    (
        "the signoff count is reported as zero",
        '"signoff_gates": len(signoffs),',
        '"signoff_gates": 0,',
    ),
    (
        "the signoff list is empty regardless of the report",
        'sorted(\n            (f"{item[\'milestone\']}:{item[\'gate\']}" for item in signoffs)\n        )',
        "[]",
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
        [sys.executable, str(ROOT / "scripts" / "test_roadmap_admissibility.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0, result.stdout + result.stderr


def main() -> int:
    original = TOOL.read_text(encoding="utf-8")
    baseline_failed, output = run_tests()
    if baseline_failed:
        print("FAIL: baseline roadmap-admissibility tests do not pass")
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
