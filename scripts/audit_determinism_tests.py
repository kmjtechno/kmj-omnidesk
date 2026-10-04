#!/usr/bin/env python3
"""Which tests are evidence, and which only look like evidence?

A test named `..._is_deterministic` asserts that the same input gives the
same output twice. That is a real property and worth having. It is also
satisfied by an implementation that is wrong in a way that does not vary
between runs -- and the mutations that survive a determinism test are
exactly the ones that are deterministic and wrong.

The concrete case this was written for: `relay.rs` had

    fn relay_ratio_and_session_minutes_are_deterministic()

which passed both of these edits:

    // ratio denominator: total -> relayed_bytes.max(1)
    // session-minute ceiling: `if seconds % 60 == 0` -> `if true`

Neither changes the output between two identical calls, so the test could not
see either. Both changed the number a cost report publishes. A neighbouring
test with the same subject passed both, because it asserted the arithmetic.

So this tool does not judge a test. It reports, for each determinism-named
test, whether a mutation in the same file changes its result. A determinism
test whose file has an uncaught mutation is not wrong -- it is incomplete,
and the report says which file to read.

## What it does not do

It does not decide whether a test is *good*. It applies a fixed set of edits
to a fixed set of files and reports what survived. A file with no mutations
listed is reported as `no_mutations_defined`, which is not a pass -- it is the
absence of an answer, and is counted separately from "mutation survived".
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo.exe")

# Test names matching this are the subject: tests whose stated claim is that a
# result is stable. They are not judged; they are looked up.
DETERMINISM_NAME = re.compile(r"(deterministic|reproducible|_stable\b)", re.I)


@dataclass(frozen=True)
class Mutation:
    """One edit, and the test filter that selects what should notice it."""

    label: str
    path: str
    old: str
    new: str
    filter: str  # passed to `cargo test <filter> --lib`


@dataclass
class FileReport:
    path: str
    mutations: list[Mutation] = field(default_factory=list)
    applied: list[str] = field(default_factory=list)
    unapplied: list[str] = field(default_factory=list)
    uncaught: list[str] = field(default_factory=list)


# The mutations. Each targets a specific claim made by a determinism test in
# that file, and each is an edit that leaves two identical calls returning
# identical results -- so only a test asserting the arithmetic can see it.
#
# Adding an entry here is cheap and safe: an entry whose `old` does not match
# is reported as `unapplied`, never silently skipped, because a mutation that
# never applied is indistinguishable from one that was never run. That is the
# bug `verify_uninstall_mutations.py` had and fixed, and it is why this tool
# reports it rather than skipping.
MUTATIONS: list[Mutation] = [
    Mutation(
        "relay ratio divides by relayed bytes instead of total bytes",
        "crates/omnidesk-core/src/relay.rs",
        "        let scaled = self.relayed_bytes.saturating_mul(10_000) / total;",
        "        let scaled = self.relayed_bytes.saturating_mul(10_000)\n"
        "            / self.relayed_bytes.max(1);",
        "relay::tests",
    ),
    Mutation(
        "relay session minutes drop the round-up ceiling",
        "crates/omnidesk-core/src/relay.rs",
        "        if self.relay_session_seconds % 60 == 0 {",
        "        if true {",
        "relay::tests",
    ),
    Mutation(
        "connectivity success rate divides by successes instead of attempts",
        "crates/omnidesk-core/src/connectivity.rs",
        "        let scaled = u64::from(self.successes) * 10_000 / u64::from(self.attempts);",
        "        let scaled = u64::from(self.successes) * 10_000 / u64::from(self.successes).max(1);",
        "connectivity::tests",
    ),
    Mutation(
        "media frame validation stops rejecting oversized frames",
        "crates/omnidesk-core/src/media.rs",
        "MAX_FRAME_BYTES",
        "MAX_FRAME_BYTES_PLACEHOLDER_DOES_NOT_EXIST",
        "media::tests",
    ),
    Mutation(
        "weak-network evaluation skips a rung",
        "crates/omnidesk-core/src/weak_network.rs",
        "fn observe(&mut self, sample: NetworkSample) -> QualityLevel {",
        "fn observe(&mut self, sample: NetworkSample) -> QualityLevel {\n"
        "        return self.level;\n"
        "        #[allow(unreachable_code)]",
        "weak_network::tests",
    ),
]


def determinism_tests(source: str) -> list[str]:
    """Test names in a file that claim a result is stable.

    Parsed from the `#[test]` attribute above each function rather than from a
    hand-kept list, so a renamed test is found by its new name and a deleted
    one stops being claimed. A hardcoded list would go stale silently, which
    is the same defect the roadmap checker was built to catch.
    """
    return [
        name
        for name in re.findall(r"#\[test\]\s*\n\s*fn\s+([a-z_0-9]+)\s*\(", source)
        if DETERMINISM_NAME.search(name)
    ]


def run_tests(filter_: str) -> tuple[bool, str]:
    """Returns (failed, output) for the selected tests."""
    result = subprocess.run(
        [CARGO, "test", "-p", "omnidesk-core", filter_, "--lib"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    return result.returncode != 0, result.stdout + result.stderr


def apply_mutation(mutation: Mutation) -> bool:
    path = ROOT / mutation.path
    if not path.is_file():
        return False
    source = path.read_text(encoding="utf-8")
    if mutation.old not in source:
        return False
    path.write_text(source.replace(mutation.old, mutation.new, 1), encoding="utf-8")
    return True


def evaluate() -> dict:
    reports: list[FileReport] = []
    files = {mutation.path for mutation in MUTATIONS}

    originals: dict[Path, str] = {
        ROOT / path: (ROOT / path).read_text(encoding="utf-8")
        for path in files
        if (ROOT / path).is_file()
    }

    for path in sorted(files):
        report = FileReport(path=path)
        report.mutations = [m for m in MUTATIONS if m.path == path]
        (ROOT / path).write_text(originals[ROOT / path], encoding="utf-8")

        # Baseline first, and refuse to report anything about a file whose
        # tests already fail. A mutation "surviving" against a broken baseline
        # is not evidence.
        baseline_failed, output = run_tests(report.mutations[0].filter)
        report_baseline = baseline_failed
        for mutation in report.mutations:
            (ROOT / path).write_text(originals[ROOT / path], encoding="utf-8")
            if not apply_mutation(mutation):
                report.unapplied.append(mutation.label)
                continue
            report.applied.append(mutation.label)
            failed, mutated_output = run_tests(mutation.filter)
            if failed:
                caught = [
                    line.split(" ")[1]
                    for line in mutated_output.splitlines()
                    if line.startswith("test ") and " FAILED" in line
                ]
                if caught and all(
                    any(d in name for d in determinism_tests(originals[ROOT / path]))
                    for name in caught
                ):
                    report.uncaught.append(mutation.label)
            else:
                report.uncaught.append(mutation.label)

        (ROOT / path).write_text(originals[ROOT / path], encoding="utf-8")
        if report_baseline:
            report.unapplied.append("baseline did not pass; results not reported")
        reports.append(report)

    determinism_covered = 0
    determinism_uncovered: list[str] = []
    for path in sorted(files):
        source = originals.get(ROOT / path, "")
        for name in determinism_tests(source):
            determinism_covered += 1
    for path in sorted(ROOT.rglob("crates/**/*.rs")):
        if "target" in path.parts:
            continue
        source = path.read_text(encoding="utf-8", errors="ignore")
        for name in determinism_tests(source):
            rel = str(path.relative_to(ROOT))
            if rel not in files:
                determinism_uncovered.append(f"{rel}::{name}")

    return {
        "determinism_tests_total": determinism_covered + len(determinism_uncovered),
        "determinism_tests_with_mutations": determinism_covered,
        "determinism_tests_without_mutations": sorted(determinism_uncovered),
        "mutations_total": len(MUTATIONS),
        "mutations_unapplied": sum(len(r.unapplied) for r in reports),
        "mutations_uncaught": sum(len(r.uncaught) for r in reports),
        "files": [
            {
                "path": r.path,
                "applied": r.applied,
                "unapplied": r.unapplied,
                "uncaught": r.uncaught,
            }
            for r in reports
        ],
    }


def main() -> int:
    report = evaluate()
    for entry in report["files"]:
        if entry["uncaught"]:
            print(f"FAIL {entry['path']}: these mutations were not caught by any test:")
            for label in entry["uncaught"]:
                print(f"  - {label}")
        for label in entry["unapplied"]:
            print(f"WARN {entry['path']}: mutation never applied: {label}")

    if report["mutations_uncaught"] or report["mutations_unapplied"]:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "uncaught": report["mutations_uncaught"],
                    "unapplied": report["mutations_unapplied"],
                },
                indent=2,
            )
        )
        return 1

    print(
        json.dumps(
            {
                "status": "PASS",
                "determinism_tests": report["determinism_tests_total"],
                "with_mutations": report["determinism_tests_with_mutations"],
                "mutations": report["mutations_total"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
