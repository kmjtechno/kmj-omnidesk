#!/usr/bin/env python3
"""M5 relay-fallback evidence: does a claim rest on a real observation?

Until this tool existed, M5's three exit criteria and three security gates
were referenced nowhere in the repository. `relay.rs` implemented the policy,
but "the relay module has tests" is not the same as "the relay fallback was
observed working on a real transport", and the roadmap made no distinction
because nothing in the tree made it for it.

So this tool never decides whether M5 is done. It decides whether a *report*
claiming M5's gates are met is backed by observation records, and refuses the
report when it is not. The difference matters: M5's criteria need two NAT
networks, a relay operator, and a real session. This repository does not have
those. What it can do -- and what was missing -- is make the absence visible
instead of silent.

The three properties this exists to enforce:

  gate_coverage_both_directions
      Every exit criterion and security gate M5 declares must have a check
      here, and every check here must name a gate M5 still declares. Deleting
      a criterion from ROADMAP.yaml must leave a checker behind that nothing
      calls -- otherwise removing a security gate is a one-line edit nobody
      notices. Read the list back out of the roadmap; copying it would defeat
      the check.

  observation_required
      A gate may only be reported `observed` when it names observation records
      that exist, that hash to what the report says, and that come from a run
      whose evidence class the gate actually admits. A criterion cannot be
      satisfied by a unit test -- `forced_direct_failure_falls_back_to_relay`
      needs an actual direct-connect failure, and a test that simulates one is
      evidence about the code, not about the network.

  fail_closed_authorization
      `authorization_failure_is_fail_closed` is the one gate where a
      *missing* observation must not read as a pass. The other gates refuse
      on missing data; this one refuses on it too, and additionally refuses
      any report that cannot show the relay was exercised while unauthorized.
      A relay that was never asked to authorize anything has not failed
      closed; it has simply never been asked.

The evidence classes are what stop the same test output from satisfying every
gate. `transport_observed` needs a real relay over a real transport;
`code_observed` is satisfied by the unit-test binary and is explicitly *not*
enough for the three exit criteria. A report cannot promote a `code_observed`
record to `transport_observed` by naming the gate differently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

RUN_ID = re.compile(r"^M5-[A-Za-z0-9]+-R[0-9]{3,}$")

# The evidence classes a run may be recorded under, and what each one is
# allowed to establish.
#
# The split is the whole design. `code_observed` is cheap, always available,
# and honest about what it is -- so the gates that code can settle are
# settled. `transport_observed` requires a relay someone actually ran, which
# this repository has never done, so the gates that need one stay unsatisfiable
# until it does. What is not available is a class that lets a cheap record
# satisfy an expensive gate.
EVIDENCE_CLASSES = {
    "code_observed": (
        "Ran the relay module's own tests. Establishes code behaviour only; "
        "never satisfies an exit criterion."
    ),
    "transport_observed": (
        "A real relay was exercised over a real transport between two hosts. "
        "The only class that can satisfy an exit criterion."
    ),
    "link_forced_observed": (
        "Direct establishment was actively broken on a shaped link and the "
        "session continued over the relay. The only class that can satisfy "
        "forced_direct_failure_falls_back_to_relay."
    ),
}

# M5's exit criteria, in the order ROADMAP.yaml declares them.
EXIT_CRITERIA = (
    "forced_direct_failure_falls_back_to_relay",
    "end_to_end_confidentiality_preserved",
    "relay_utilization_measured",
)

# M5's security gates.
SECURITY_GATES = (
    "relay_cannot_decrypt_session_payload",
    "relay_cannot_grant_control_permission",
    "authorization_failure_is_fail_closed",
)

# Which evidence classes each exit criterion admits. The narrow list is the
# point: `end_to_end_confidentiality_preserved` admits `transport_observed`
# but not `link_forced_observed`, because a shaped link tells you nothing about
# what the relay could read. Each criterion therefore has its own answer
# rather than sharing one permissive default.
CRITERIA_EVIDENCE = {
    "forced_direct_failure_falls_back_to_relay": ("link_forced_observed",),
    "end_to_end_confidentiality_preserved": ("transport_observed",),
    "relay_utilization_measured": ("transport_observed", "link_forced_observed"),
}

# Which evidence classes each security gate admits. These are the gates that
# the relay's *interface* settles, so `code_observed` is admitted -- with the
# exception of the fail-closed gate, below.
#
# `authorization_failure_is_fail_closed` admits `code_observed` but carries a
# separate requirement: the run must record that the relay was actually asked
# to authorize something. See `check_fail_closed_authorization`.
GATE_EVIDENCE = {
    "relay_cannot_decrypt_session_payload": ("code_observed", "transport_observed"),
    "relay_cannot_grant_control_permission": ("code_observed", "transport_observed"),
    "authorization_failure_is_fail_closed": ("code_observed", "transport_observed"),
}

# A run whose class is `code_observed` must say it ran the real test binary,
# because that is the only thing the class means. Without it, a report could
# label a hand-written file `code_observed` and the class would carry no claim.
CODE_EVIDENCE_REQUIRED_PROBE = "relay::tests"


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_run_id(value: str) -> str:
    if not RUN_ID.fullmatch(value):
        fail(f"invalid run_id: {value!r} (expected M5-<label>-R<NNN>)")
    return value


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


# --- roadmap -------------------------------------------------------------


def m5_sections_from_roadmap(path: Path) -> tuple[list[str], list[str]]:
    """Read M5's exit criteria and security gates out of ROADMAP.yaml.

    Parsed rather than copied, for the reason `release_gate.py` does the same:
    a copy is not a check. The block is located by its `id: M5` marker and
    read until the next milestone, so a criterion added to the roadmap without
    a checker here fails instead of passing unnoticed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"missing roadmap: {path}")

    lines = text.splitlines()
    start = None
    for number, line in enumerate(lines):
        if re.match(r"^\s*-\s*id:\s*M5\s*$", line):
            start = number
            break
    if start is None:
        fail(f"{path}: no milestone with id M5")

    end = len(lines)
    for number in range(start + 1, len(lines)):
        if re.match(r"^\s*-\s*id:\s*M[A-Z0-9]+\s*$", lines[number]):
            end = number
            break

    def collect(key: str) -> list[str]:
        found: list[str] = []
        reading = False
        for line in lines[start:end]:
            stripped = line.strip()
            if re.match(rf"^{key}:", stripped):
                reading = True
                inline = stripped[len(key) + 1 :].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    return [
                        item.strip()
                        for item in inline[1:-1].split(",")
                        if item.strip()
                    ]
                continue
            if reading:
                if stripped.startswith("- "):
                    found.append(stripped[2:].strip())
                elif stripped and not stripped.startswith("#"):
                    reading = False
        return found

    return collect("exit_criteria"), collect("security_gates")


# --- ledger --------------------------------------------------------------


def ledger_path(root: Path) -> Path:
    return root / "ledger.jsonl"


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
    return entries


def load_json(path: Path, label: str) -> dict | None:
    """Load a required document, or return None.

    Returns rather than raises, deliberately. One unreadable observation file
    must fail *its* gate and let the others report: raising would abort the
    whole report, so a single missing file would hide whether the relay had
    been exercised at all -- turning a visible failure into a missing answer.
    The same reasoning is recorded in `release_gate.py`; both tools learned it
    from the same failure.
    """
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    del label
    return parsed


# --- checks --------------------------------------------------------------


def check_gate_coverage(
    exit_criteria: list[str], security_gates: list[str]
) -> list[str]:
    """Every declared gate needs a check, and every check needs a gate.

    Run in both directions. The second half is the one that is usually
    forgotten, and it is the one that catches a *removal*: deleting a
    criterion from the roadmap would otherwise leave a checker behind that no
    gate calls, which is a security requirement removed by editing a
    sentence.
    """
    problems: list[str] = []

    for criterion in exit_criteria:
        if criterion not in EXIT_CRITERIA:
            problems.append(
                f"gate coverage: exit criterion {criterion} has no check in m5_evidence.py"
            )
        elif criterion not in CRITERIA_EVIDENCE:
            problems.append(
                f"gate coverage: exit criterion {criterion} admits no evidence class"
            )

    for gate in security_gates:
        if gate not in SECURITY_GATES:
            problems.append(
                f"gate coverage: security gate {gate} has no check in m5_evidence.py"
            )
        elif gate not in GATE_EVIDENCE:
            problems.append(f"gate coverage: security gate {gate} admits no evidence class")

    for criterion in EXIT_CRITERIA:
        if criterion not in exit_criteria:
            problems.append(
                f"gate coverage: checker for {criterion} names a criterion M5 no longer declares"
            )

    for gate in SECURITY_GATES:
        if gate not in security_gates:
            problems.append(
                f"gate coverage: checker for {gate} names a gate M5 no longer declares"
            )

    return problems


def gate_runs(entries: list[dict], gate: str) -> list[dict]:
    return [
        entry
        for entry in entries
        if gate in (entry.get("gates_observed") or [])
    ]


def gate_satisfied(
    gate: str,
    entries: list[dict],
    raw_root: Path,
    is_criterion: bool,
) -> tuple[bool, list[str]]:
    """Whether `gate` is backed by an observation that still holds.

    Three refusals, and the second is the one that matters most: a run may
    name the gate, but if its evidence class is not one this gate admits, the
    gate is still unmet. That is what stops `code_observed` from quietly
    standing in for a relay nobody ran.
    """
    problems: list[str] = []
    admitted = (
        CRITERIA_EVIDENCE.get(gate, ()) if is_criterion else GATE_EVIDENCE.get(gate, ())
    )

    candidates = gate_runs(entries, gate)
    if not candidates:
        return False, [
            f"{gate}: no recorded run observes this gate"
        ]

    honoured = 0
    for entry in candidates:
        run_id = entry.get("run_id", "<missing>")
        evidence_class = entry.get("evidence_class")

        if evidence_class not in EVIDENCE_CLASSES:
            problems.append(f"{gate}: run {run_id} declares unknown evidence class {evidence_class!r}")
            continue

        if evidence_class not in admitted:
            problems.append(
                f"{gate}: run {run_id} is {evidence_class}, which does not establish this gate "
                f"(needs one of: {', '.join(admitted)})"
            )
            continue

        # Both sets must reach `honoured`, or a run with a deleted raw file or
        # a missing endpoint still counts as an observation and the gate reads
        # green off a `problems` list nobody acts on.
        #
        # The first version appended the integrity problems and discarded the
        # class errors entirely, so the refusal was reported and then ignored
        # -- a check wired to no outcome. Six tests failed on it, which is the
        # only reason it is not still there.
        integrity = entry_problems(entry, run_id, raw_root)
        class_errors = entry_class_errors(entry, run_id) or []

        problems.extend(integrity)
        problems.extend(class_errors)

        if not integrity and not class_errors:
            honoured += 1

    if honoured:
        return True, problems
    return False, problems or [f"{gate}: no admissible observation"]


def entry_problems(entry: dict, run_id: str, raw_root: Path) -> list[str]:
    """Whether the run's own evidence still hashes to what was recorded."""
    problems: list[str] = []

    digest = entry.get("raw_sha256")
    if not digest:
        return [f"{run_id}: no raw observation hashed"]

    name = str(entry.get("raw_path", ""))
    path = raw_root / name
    if not path.is_file():
        problems.append(f"{run_id}: raw observation {name} is gone")
        return problems

    actual, _ = sha256_file(path)
    if actual != digest:
        problems.append(f"{run_id}: raw observation {name} no longer hashes to what was recorded")

    return problems


def entry_class_errors(entry: dict, run_id: str) -> list[str] | None:
    """Class-specific requirements, or None when the entry is admissible.

    Split out from `entry_problems` because these are the checks a generic
    hash comparison cannot make: a `code_observed` run must say which test
    binary it ran, and a `transport_observed` run must name the two hosts the
    relay sat between. A digest alone proves a file is unchanged; it says
    nothing about whether the file said anything relevant.
    """
    evidence_class = entry.get("evidence_class")
    errors: list[str] = []

    if evidence_class == "code_observed":
        probe = entry.get("test_binary")
        if probe != CODE_EVIDENCE_REQUIRED_PROBE:
            errors.append(
                f"{run_id}: code_observed run must record test_binary "
                f"{CODE_EVIDENCE_REQUIRED_PROBE!r}, got {probe!r}"
            )

    if evidence_class in ("transport_observed", "link_forced_observed"):
        for field in ("relay_endpoint", "client_endpoint", "server_endpoint"):
            if not entry.get(field):
                errors.append(f"{run_id}: {evidence_class} run is missing {field}")

    if evidence_class == "link_forced_observed":
        impairment = entry.get("impairment")
        if not isinstance(impairment, dict):
            errors.append(f"{run_id}: link_forced_observed run must record how the link was broken")
        elif not impairment.get("method") or not impairment.get("applied_before_session"):
            errors.append(
                f"{run_id}: link_forced_observed run must record impairment.method and "
                "impairment.applied_before_session -- an impairment applied afterwards did not cause the failure"
            )

    return errors or None


def check_fail_closed_authorization(entries: list[dict], raw_root: Path) -> list[str]:
    """The gate that must not pass on absence.

    `authorization_failure_is_fail_closed` asks what happens when a relay is
    asked to forward something it may not. A run that never asked proves
    nothing -- not even that the check was skipped, only that nothing
    exercised it.

    So this does not simply look for a satisfying run. It first requires that
    the relay was exercised while unauthorized at all, and only then asks
    whether that exercise was refused. A report whose runs contain no
    unauthorized attempt gets an explicit refusal, because that absence is
    the finding.
    """
    problems: list[str] = []

    attempts = [
        entry
        for entry in entries
        if entry.get("unauthorized_attempted") is True
    ]
    if not attempts:
        return [
            "authorization_failure_is_fail_closed: no run recorded an unauthorized attempt; "
            "a relay that was never asked has not been shown to fail closed"
        ]

    refused = False
    for entry in attempts:
        run_id = entry.get("run_id", "<missing>")
        outcome = entry.get("unauthorized_outcome")
        if outcome is None:
            problems.append(f"{run_id}: unauthorized attempt records no outcome")
            continue
        if outcome == "refused":
            # Only a run whose observation is otherwise sound may claim the
            # relay refused. A refused unauthorized attempt on a run whose raw
            # file was deleted is a claim with nothing behind it, and counting
            # it is how this gate would read green on absent evidence.
            #
            # The gate's own satisfaction is still decided by `gate_satisfied`;
            # this only decides whether the attempt counts as a *refusal*.
            integrity = entry_problems(entry, run_id, raw_root)
            class_errors = entry_class_errors(entry, run_id) or []
            if integrity or class_errors:
                problems.extend(integrity)
                problems.extend(class_errors)
                continue
            refused = True
        else:
            problems.append(
                f"{run_id}: unauthorized attempt was {outcome!r} rather than refused -- "
                "authorization is not failing closed"
            )

    if not refused:
        problems.append(
            "authorization_failure_is_fail_closed: no recorded unauthorized attempt was refused"
        )

    return problems


def evaluate(root: Path, roadmap: Path) -> dict:
    """Build the report. Never raises on bad evidence -- it reports."""
    exit_criteria, security_gates = m5_sections_from_roadmap(roadmap)
    entries = read_ledger(root)
    raw_root = root / "raw"

    problems: list[str] = list(check_gate_coverage(exit_criteria, security_gates))

    if not entries:
        problems.append(f"no runs recorded under {root}; nothing was observed")

    gates: dict[str, dict] = {}
    for criterion in EXIT_CRITERIA:
        satisfied, gate_problems = gate_satisfied(
            criterion, entries, raw_root, is_criterion=True
        )
        problems.extend(gate_problems)
        gates[criterion] = {
            "kind": "exit_criterion",
            "status": "observed" if satisfied else "unmet",
            "admitted_evidence": list(CRITERIA_EVIDENCE.get(criterion, ())),
        }

    for gate in SECURITY_GATES:
        satisfied, gate_problems = gate_satisfied(
            gate, entries, raw_root, is_criterion=False
        )
        if gate == "authorization_failure_is_fail_closed":
            fail_closed = check_fail_closed_authorization(entries, raw_root)
            satisfied = satisfied and not fail_closed
            gate_problems = [*gate_problems, *fail_closed]
        problems.extend(gate_problems)
        gates[gate] = {
            "kind": "security_gate",
            "status": "observed" if satisfied else "unmet",
            "admitted_evidence": list(GATE_EVIDENCE.get(gate, ())),
        }

    unmet = [name for name, detail in gates.items() if detail["status"] != "observed"]

    return {
        "milestone": "M5",
        "generated_at": utc_now(),
        "runs": len(entries),
        "gates": gates,
        "unmet": unmet,
        "problems": problems,
        # Deliberately not "complete": M5's exit criteria need two NAT
        # networks and a real relay, and this repository has neither. Naming
        # the field `satisfied` would invite someone to read it as progress.
        "m5_satisfied": not problems,
    }


# --- commands ------------------------------------------------------------


def command_init(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = ledger_path(root)
    if path.exists():
        fail(f"{path} already exists; refusing to overwrite a run ledger")
    (root / "raw").mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    print(json.dumps({"ledger": str(path), "created_at": utc_now()}, sort_keys=True))


def command_record(args: argparse.Namespace) -> None:
    """Append one observed run.

    Refuses a duplicate run id. That is the observable form of the failure
    `cherry_picking_forbidden` names in M13: a bad run cannot be replaced by a
    good one under the same name, because the name is taken.
    """
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / "raw").mkdir(parents=True, exist_ok=True)
    run_id = validate_run_id(args.run_id)

    evidence_class = args.evidence_class
    if evidence_class not in EVIDENCE_CLASSES:
        fail(f"unknown evidence class {evidence_class!r}; expected one of {sorted(EVIDENCE_CLASSES)}")

    raw = Path(args.raw).resolve(strict=True)
    raw_name = f"{run_id}{raw.suffix or '.json'}"
    (root / "raw" / raw_name).write_bytes(raw.read_bytes())
    digest, size = sha256_file(root / "raw" / raw_name)

    gates = [gate for gate in (args.gate or []) if gate]
    known = set(EXIT_CRITERIA) | set(SECURITY_GATES)
    unknown = [gate for gate in gates if gate not in known]
    if unknown:
        fail(f"run names gates M5 does not declare: {', '.join(sorted(unknown))}")

    entry = {
        "run_id": run_id,
        "recorded_at": utc_now(),
        "evidence_class": evidence_class,
        "raw_sha256": digest,
        "raw_bytes": size,
        "raw_path": raw_name,
        "gates_observed": gates,
        "environment": load_json_or_empty(args.environment),
    }

    for field in ("test_binary", "relay_endpoint", "client_endpoint", "server_endpoint"):
        value = getattr(args, field, None)
        if value:
            entry[field] = value

    if args.impairment:
        impairment = load_json_or_empty(args.impairment)
        if impairment is None:
            fail(f"could not read impairment description: {args.impairment}")
        entry["impairment"] = impairment

    if args.unauthorized_attempted is not None:
        entry["unauthorized_attempted"] = args.unauthorized_attempted
    if args.unauthorized_outcome is not None:
        entry["unauthorized_outcome"] = args.unauthorized_outcome

    for entry_ in read_ledger(root):
        if entry_.get("run_id") == run_id:
            fail(f"run_id {run_id} is already in the ledger; a run cannot be replaced under the same name")

    with ledger_path(root).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    print(json.dumps({"run_id": run_id, "recorded": True}, sort_keys=True))


def load_json_or_empty(value: str | None) -> dict:
    if not value:
        return {}
    path = Path(value).resolve(strict=True)
    return load_json(path, str(path)) or {}


def command_verify(args: argparse.Namespace) -> None:
    report = evaluate(Path(args.root).resolve(), Path(args.roadmap).resolve())
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for problem in report["problems"]:
            print(f"FAIL {problem}")
    if not report["m5_satisfied"]:
        fail(f"{len(report['unmet'])} of M5's gates are unmet")
    print(json.dumps({"m5_evidence": "PASS", "runs": report["runs"]}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the observation ledger")
    init.add_argument("--root", required=True)
    init.set_defaults(func=command_init)

    record = sub.add_parser("record", help="append one observed run")
    record.add_argument("--root", required=True)
    record.add_argument("--run-id", required=True)
    record.add_argument("--evidence-class", required=True, choices=sorted(EVIDENCE_CLASSES))
    record.add_argument("--raw", required=True, help="the observation file itself")
    record.add_argument("--gate", action="append", help="gate this run observes (repeatable)")
    record.add_argument("--environment", help="environment metadata JSON")
    record.add_argument("--test-binary", help="test binary a code_observed run actually ran")
    record.add_argument("--relay-endpoint")
    record.add_argument("--client-endpoint")
    record.add_argument("--server-endpoint")
    record.add_argument("--impairment", help="JSON describing how the direct link was broken")
    record.add_argument("--unauthorized-attempted", action="store_true")
    record.add_argument("--unauthorized-outcome", choices=("refused", "forwarded", "unknown"))
    record.set_defaults(func=command_record)

    verify = sub.add_parser("verify", help="check M5's gates against recorded observation")
    verify.add_argument("--root", required=True)
    verify.add_argument("--roadmap", default="ROADMAP.yaml")
    verify.add_argument("--json", action="store_true", help="print the full report")
    verify.set_defaults(func=command_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
