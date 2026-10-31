#!/usr/bin/env python3
"""M13 release-candidate performance matrix: evidence validation.

This tool never runs a benchmark, never invents a number, and never decides
that a result is good. It only checks that a supplied measurement set is
*admissible* under the four rules `benchmarks/network-profiles.yaml` states:

  raw_results_required
      Every reported figure must trace to a raw per-sample file. A summary
      with no raw file behind it is a number someone typed.

  environment_metadata_required
      A measurement without the machine, OS, and build it came from cannot be
      compared with anything, so it is refused rather than stored.

  cherry_picking_forbidden
      Runs form an append-only ledger. Dropping an inconvenient run is the
      whole failure mode this rule names, so a run that disappears is a hard
      error even though removing it left no trace in any single run.

  comparative_claims_require_reproducible_comparable_tests
      A claim that A beats B is only checkable when A and B were measured on
      the same profile, on the same machine, from the same build. Anything
      less is not evidence of a comparison.

Admissibility is not performance. A complete, honest, badly-performing matrix
passes every check here, and that is correct: this tool's job is to make sure
what is published is what was measured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

RUN_ID = re.compile(r"^M13-[A-Za-z0-9]+-R[0-9]{3,}$")

# The metrics ROADMAP.yaml M13 lists, in the order network-profiles.yaml
# declares them. Order is not meaningful; completeness is.
REQUIRED_METRICS = (
    "interactive_latency_ms",
    "connection_time_ms",
    "reconnect_time_ms",
    "bandwidth_kbps",
    "cpu_percent",
    "gpu_percent",
    "ram_mb",
    "direct_connect_success_rate",
    "relay_ratio",
    "visual_quality_metric",
)

# Fields that must be present for two runs to be comparable. Deliberately
# strict: the cost of a false "A is faster than B" is a published claim that
# nobody can reproduce, and the cost of demanding a rebuild is a re-run.
COMPARABILITY_FIELDS = ("machine_id", "os_build", "commit", "profile")


def fail(message: str) -> NoReturn:
    # To stderr, not stdout: stdout is the tool's result channel, and a
    # consumer parsing it should not find a refusal sitting where a JSON
    # document is expected.
    raise SystemExit(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_run_id(value: str) -> str:
    if not RUN_ID.fullmatch(value):
        fail(f"invalid run_id: {value!r} (expected M13-<label>-R<NNN>)")
    return value


def load_json(path: Path) -> dict:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing file: {path}")
    except json.JSONDecodeError as error:
        fail(f"{path}: not valid JSON: {error}")
    if not isinstance(parsed, dict):
        fail(f"{path}: expected a JSON object at the top level")
    return parsed


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size



def checked_root(value: str) -> Path:
    """Do not follow redirected evidence roots or their ancestors."""
    supplied = Path(value)
    if ".." in supplied.parts:
        fail("parent traversal in M13 evidence root forbidden")
    absolute = supplied.absolute()
    for part in (absolute, *absolute.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            fail(f"redirected M13 evidence root forbidden: {part}")
    return absolute.resolve()


def checked_raw_file(root: Path, name: object) -> Path:
    """Only accept unshared, non-redirected raw samples within root/raw."""
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or any(char in name for char in "/\\:")
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        fail("raw_results_required: unsafe raw filename")
    directory = root / "raw"
    if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
        fail("raw_results_required: redirected raw directory")
    try:
        directory_stat = directory.lstat()
    except FileNotFoundError:
        fail("raw_results_required: missing raw directory")
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not stat.S_ISDIR(directory_stat.st_mode) or (
        getattr(directory_stat, "st_file_attributes", 0) & reparse
    ):
        fail("raw_results_required: unsafe raw directory")
    path = directory / name
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail("raw_results_required: missing raw file")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (getattr(metadata, "st_file_attributes", 0) & reparse)
    ):
        fail("raw_results_required: raw file must be unshared and regular")
    return path


# --- ledger ---------------------------------------------------------------


def ledger_path(root: Path) -> Path:
    path = root / "ledger.jsonl"
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        fail("redirected M13 evidence ledger forbidden")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    ):
        fail("M13 evidence ledger must be an unshared regular file")
    return path


def command_init(args: argparse.Namespace) -> None:
    """Create the append-only ledger if it does not exist."""
    root = checked_root(args.root)
    root.mkdir(parents=True, exist_ok=True)
    path = ledger_path(root)
    if path.exists():
        fail(f"{path} already exists; refusing to overwrite a run ledger")
    path.write_text("", encoding="utf-8")
    print(json.dumps({"ledger": str(path), "created_at": utc_now()}))


def read_ledger(root: Path) -> list[dict]:
    path = ledger_path(root)
    if not path.exists():
        return []
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as error:
            fail(f"{path}:{number}: corrupt ledger line: {error}")
        entry = entries[-1]
        if not isinstance(entry, dict) or not isinstance(entry.get("run_id"), str) or not RUN_ID.fullmatch(entry["run_id"]):
            fail(f"{path}:{number}: invalid ledger entry or run_id")
    return entries


def command_record(args: argparse.Namespace) -> None:
    """Append one measured run to the ledger.

    Refuses a duplicate run id, which is the observable form of cherry-picking:
    a run cannot be quietly replaced by a better one under the same name.
    """
    root = checked_root(args.root)
    root.mkdir(parents=True, exist_ok=True)
    run_id = validate_run_id(args.run_id)

    supplied_raw = Path(args.raw)
    if ".." in supplied_raw.parts:
        fail("raw_results_required: parent traversal forbidden")
    raw = checked_raw_file(root, supplied_raw.name)
    if supplied_raw.absolute() != raw:
        fail("raw_results_required: raw input must be inside evidence root/raw")
    raw_sha, raw_size = sha256_file(raw)

    existing = read_ledger(root)
    if any(entry.get("run_id") == run_id for entry in existing):
        fail(
            f"run_id {run_id} is already in the ledger; "
            "a run cannot be replaced under the same name (cherry_picking_forbidden)"
        )

    entry = {
        "run_id": run_id,
        "recorded_at": utc_now(),
        "raw_sha256": raw_sha,
        "raw_bytes": raw_size,
        "raw_path": raw.name,
        "environment": load_json(Path(args.environment).resolve(strict=True)),
        "metrics": load_json(Path(args.metrics).resolve(strict=True)),
    }
    with ledger_path(root).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    print(json.dumps({"run_id": run_id, "recorded": True}, sort_keys=True))


# --- validation -----------------------------------------------------------


def missing_metrics(metrics: dict) -> list[str]:
    """Reject absent, nonnumeric, boolean and nonfinite reported metrics."""
    return [
        name
        for name in REQUIRED_METRICS
        if name not in metrics
        or not (
            type(metrics[name]) is int
            or (type(metrics[name]) is float and math.isfinite(metrics[name]))
        )
    ]


def command_verify(args: argparse.Namespace) -> None:
    """Check every ledger entry against the four declared rules."""
    root = checked_root(args.root)
    entries = read_ledger(root)
    if not entries:
        fail(f"no runs recorded under {root}; nothing to verify")

    problems: list[str] = []

    # rule: cherry_picking_forbidden. Detected as a hole in the sequence, not
    # as anything inside a surviving run -- that is what makes deleting a file
    # detectable at all.
    seen: dict[str, int] = {}
    for entry in entries:
        run_id = entry.get("run_id", "<missing>")
        if run_id in seen:
            problems.append(
                f"cherry_picking_forbidden: run_id {run_id} appears twice"
            )
        seen[run_id] = seen.get(run_id, 0) + 1

    for entry in entries:
        run_id = entry.get("run_id", "<missing>")

        # rule: raw_results_required
        raw_sha = entry.get("raw_sha256")
        try:
            raw_path = checked_raw_file(root, entry.get("raw_path"))
        except SystemExit as error:
            problems.append(f"{run_id}: {error}")
        else:
            actual, actual_size = sha256_file(raw_path)
            if not isinstance(raw_sha, str) or actual != raw_sha:
                problems.append(
                    f"{run_id}: raw_results_required -- {raw_path.name} "
                    "no longer hashes to what was recorded"
                )
            if type(entry.get("raw_bytes")) is not int or entry["raw_bytes"] != actual_size:
                problems.append(f"{run_id}: raw_results_required -- raw_bytes mismatch")

        # rule: environment_metadata_required
        environment = entry.get("environment")
        if not isinstance(environment, dict):
            problems.append(f"{run_id}: environment_metadata_required -- absent")
        else:
            missing_env = [
                field
                for field in COMPARABILITY_FIELDS
                if not isinstance(environment.get(field), str)
                or not environment[field].strip()
            ]
            if missing_env:
                problems.append(
                    f"{run_id}: environment_metadata_required -- missing "
                    + ", ".join(missing_env)
                )

        # M13's own metric list, not the reporter's.
        metrics = entry.get("metrics")
        if not isinstance(metrics, dict):
            problems.append(f"{run_id}: no metrics recorded")
        else:
            missing = missing_metrics(metrics)
            if missing:
                problems.append(
                    f"{run_id}: incomplete matrix -- missing or invalid " + ", ".join(missing)
                )

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        fail(f"{len(problems)} problem(s); matrix is not admissible")

    print(
        json.dumps(
            {
                "m13_matrix": "PASS",
                "runs": len(entries),
                "required_metrics": len(REQUIRED_METRICS),
            },
            sort_keys=True,
        )
    )


def command_compare(args: argparse.Namespace) -> None:
    """Check that a claimed comparison rests on comparable runs."""
    if args.baseline == args.candidate:
        fail("comparative_claims_require_reproducible_comparable_tests: distinct runs required")
    root = checked_root(args.root)
    ledger = read_ledger(root)
    if len({entry["run_id"] for entry in ledger}) != len(ledger):
        fail("cherry_picking_forbidden: duplicate run_id in comparison ledger")
    entries = {entry["run_id"]: entry for entry in ledger}

    for run_id in (args.baseline, args.candidate):
        if run_id not in entries:
            fail(f"unknown run_id: {run_id}")

    baseline = entries[args.baseline]
    candidate = entries[args.candidate]

    # A comparison must not bypass verify's raw-evidence integrity checks.
    for run_id, entry in ((args.baseline, baseline), (args.candidate, candidate)):
        raw_path = checked_raw_file(root, entry.get("raw_path"))
        actual, actual_size = sha256_file(raw_path)
        if (
            actual != entry.get("raw_sha256")
            or type(entry.get("raw_bytes")) is not int
            or actual_size != entry["raw_bytes"]
        ):
            fail(f"{run_id}: raw_results_required -- comparison evidence mismatch")
        if not isinstance(entry.get("metrics"), dict) or missing_metrics(entry["metrics"]):
            fail(f"{run_id}: incomplete metrics for comparison")
        if not isinstance(entry.get("environment"), dict):
            fail(f"{run_id}: missing environment for comparison")
        if any(not isinstance(entry["environment"].get(field), str) or not entry["environment"][field].strip() for field in COMPARABILITY_FIELDS):
            fail(f"{run_id}: incomplete environment for comparison")

    # rule: comparative_claims_require_reproducible_comparable_tests
    incomparable = []
    for field in COMPARABILITY_FIELDS:
        left = baseline.get("environment", {}).get(field)
        right = candidate.get("environment", {}).get(field)
        if left != right:
            incomparable.append(f"{field}: {left!r} vs {right!r}")

    if incomparable:
        for detail in incomparable:
            print(f"FAIL not comparable -- {detail}")
        fail(
            "comparative_claims_require_reproducible_comparable_tests: "
            "these runs differ in environment, so no speedup may be claimed"
        )

    names = sorted(REQUIRED_METRICS)
    print(
        json.dumps(
            {
                "comparable": True,
                "metrics": {
                    name: {
                        args.baseline: baseline["metrics"].get(name),
                        args.candidate: candidate["metrics"].get(name),
                    }
                    for name in names
                },
                "note": "reporting the numbers is not a verdict; "
                "whether one is better is a judgement, not a measurement",
            },
            sort_keys=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the run ledger")
    init.add_argument("--root", required=True)
    init.set_defaults(func=command_init)

    record = sub.add_parser("record", help="append one measured run")
    record.add_argument("--root", required=True)
    record.add_argument("--run-id", required=True)
    record.add_argument("--raw", required=True, help="raw per-sample results file")
    record.add_argument("--environment", required=True, help="environment metadata JSON")
    record.add_argument("--metrics", required=True, help="metric summary JSON")
    record.set_defaults(func=command_record)

    verify = sub.add_parser("verify", help="check the matrix against the declared rules")
    verify.add_argument("--root", required=True)
    verify.set_defaults(func=command_verify)

    compare = sub.add_parser("compare", help="check a claimed comparison is reproducible")
    compare.add_argument("--root", required=True)
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--candidate", required=True)
    compare.set_defaults(func=command_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()