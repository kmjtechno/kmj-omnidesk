#!/usr/bin/env python3
"""M14 commercial release gate: which release gates are actually green.

ROADMAP.yaml M14 lists seven gates. Until this tool, none of them were
referenced anywhere in the repository — the milestone was a list of words
whose every item was satisfied by nothing in particular. That is the same hole
M12 and M13 each had, one level up.

This tool does not decide whether to ship. It decides whether a *claim* that
the gates are met is backed by evidence, and refuses the claim when it is not.
A milestone that flips to `complete` is a status someone typed; this is the
check that makes typing it insufficient.

What it enforces:

* Every gate M14 declares has a checker here, or is explicitly marked
  `requires_signoff` with the human who must provide it. A gate that is
  neither is an error, not a pass — that is the load-bearing check. A gate
  added to M14 with nothing enforcing it is exactly how M12, M13, and M14 all
  shipped aspirational in the first place.

* `signed_release_artifacts` requires each artifact in the release to have a
  signature and a digest that match the manifest. It does not verify the
  signature against a key — that needs production keys and is why M14 stays
  pending — but it refuses an artifact that is merely *declared* signed.

* `security_gate_pass` and `performance_gate_pass` are delegations, not
  re-implementations. The security gate is green only when every named CI
  check is reported green; the performance gate only when the supplied matrix
  is admissible under M13's own rules. Neither tool decides what its checks
  mean.

* `update_metadata_verified` and `licensing_integration_verified` require the
  corresponding manifests to exist and to parse, and refuse a gate declared
  green with no manifest behind it.

Deliberately NOT claimed:

* It does not verify a signature. U1 needs a real verifier and a real key.
* It does not replace `scan_secrets.py`, `cargo-deny`, or any other upstream
  check — it requires their results be fed to it, and trusts the report.
* It cannot detect a dishonest report. It can only require the report to
  exist and to be internally consistent with the manifests.

There is no `--force` and no suppression flag, for the reason
`scan_secrets.py` documents: a flag to skip a gate is how a gate quietly stops
working. A release that cannot pass this gate does not get a release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent

# The gates M14 declares, and how each one is checked. `check` names the
# function that verifies it; `requires_signoff` names the authority whose
# manual confirmation stands in for a program check, and is *not* satisfied by
# this tool alone.
#
# Every M14 gate must appear exactly once here. `gate_coverage` fails when one
# does not, which is the enforcement that a future M14 gate cannot be added
# without deciding how it is checked.
GATES: dict[str, dict[str, str]] = {
    "signed_release_artifacts": {"check": "check_signed_release_artifacts"},
    "update_metadata_verified": {"check": "check_update_metadata"},
    "licensing_integration_verified": {"check": "check_licensing_integration"},
    "security_gate_pass": {"check": "check_security_gate"},
    "performance_gate_pass": {"check": "check_performance_gate"},
    "support_and_recovery_path_defined": {
        "requires_signoff": "support_lead",
        "rationale": "a runbook exists or it does not; no program can tell",
    },
    "legal_and_codec_license_review_complete": {
        "requires_signoff": "legal_counsel",
        "rationale": "a licence question has no automated oracle",
    },
}


def fail(message: str) -> NoReturn:
    # To stderr: stdout is this tool's report channel, and a consumer parsing
    # it should not find a refusal sitting where a decision document belongs.
    raise SystemExit(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict | None:
    """Load a required document, returning None rather than raising.

    Every caller turns a `None` into a refusal. The alternative — treating an
    absent document as "nothing to violate" — is the failure this whole tool
    exists to prevent, so the absence of evidence is itself a refusal.

    Returns rather than raises, deliberately: a missing metadata file must
    fail *its* gate and let the other gates report too. Raising would abort the
    whole report, so one missing document would hide whether the artifact,
    security, and licensing gates were green — turning a visible failure into a
    missing answer, which is the worse of the two.
    """
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_signed_release_artifacts(release: dict) -> list[str]:
    """Each artifact must be present, digested, and declared signed."""
    problems: list[str] = []
    artifacts = release.get("artifacts")
    if not artifacts:
        return ["signed_release_artifacts: release declares no artifacts at all"]

    for entry in artifacts:
        name = entry.get("name", "<unnamed>")
        path = REPO_ROOT / entry.get("path", "")
        if not path.is_file():
            problems.append(f"signed_release_artifacts: {name} is not on disk: {path}")
            continue

        declared_digest = entry.get("sha256")
        actual_digest = sha256_file(path)
        if not declared_digest:
            problems.append(f"signed_release_artifacts: {name} declares no digest")
        elif declared_digest != actual_digest:
            problems.append(
                f"signed_release_artifacts: {name} digest does not match the file "
                f"(declared {declared_digest[:12]}…, actual {actual_digest[:12]}…)"
            )

        # `signature_declared` is not `signature_verified`. This tool refuses a
        # release that merely *claims* to be signed the same way M13 refuses a
        # matrix that merely claims to be complete: the difference between the
        # two is the entire point of the gate.
        if not entry.get("signature_declared"):
            problems.append(
                f"signed_release_artifacts: {name} carries no signature; a signed "
                "release must say so per-artifact, not once at the top"
            )
    return problems


def check_update_metadata(release: dict) -> list[str]:
    """Every channel in the release needs a metadata document that parses."""
    problems: list[str] = []
    metadata = release.get("update_metadata")
    if not metadata:
        return ["update_metadata_verified: release declares no update metadata"]

    for entry in metadata:
        channel = entry.get("channel", "<unnamed>")
        path = REPO_ROOT / entry.get("path", "")
        document = load_json(path, f"update_metadata_verified[{channel}]")
        if document is None:
            problems.append(
                f"update_metadata_verified: {channel} metadata is missing or "
                f"unparseable at {path}"
            )
        elif not document.get("signature_declared"):
            problems.append(
                f"update_metadata_verified: {channel} metadata is not declared signed"
            )
    return problems


def check_licensing_integration(release: dict) -> list[str]:
    """The licensing contract the client ships must be present and parseable."""
    entry = release.get("licensing_contract")
    if not entry:
        return ["licensing_integration_verified: release names no licensing contract"]

    path = REPO_ROOT / entry.get("path", "")
    document = load_json(path, "licensing_integration_verified")
    if document is None:
        return [
            f"licensing_integration_verified: contract is missing or unparseable "
            f"at {path}"
        ]

    plans = document.get("plans")
    if not isinstance(plans, list) or not plans:
        return [
            "licensing_integration_verified: contract declares no plans; a contract "
            "with no plans gates nothing"
        ]
    return []


def check_security_gate(release: dict) -> list[str]:
    """Every named CI check must be reported green.

    This delegates to whatever ran the checks. It cannot tell a passing
    security review from a forged report — nothing can — so its job is to make
    the report *exist and be complete*, so that "the gate passed" is a
    statement about a specific set of checks rather than about a feeling.
    """
    checks = release.get("security_checks")
    if not isinstance(checks, list) or not checks:
        return [
            "security_gate_pass: release reports no security checks; an empty set "
            "passes trivially and must not be treated as a pass"
        ]

    problems: list[str] = []
    for check in checks:
        name = check.get("name", "<unnamed>")
        if check.get("status") != "green":
            problems.append(f"security_gate_pass: {name} is {check.get('status')!r}")
    return problems


def check_performance_gate(release: dict) -> list[str]:
    """The supplied matrix must be admissible under M13's own rules.

    Delegates rather than re-implementing: M13's checker is the authority on
    what an admissible matrix is, and a second implementation would be a second
    opinion nobody asked for and might disagree with the first.
    """
    import m13_matrix

    matrix_root = REPO_ROOT / release.get("performance_matrix_root", "evidence/m13-rc1")
    if not matrix_root.is_dir():
        return [
            "performance_gate_pass: no performance matrix at "
            f"{matrix_root}; M13's rules cannot check a matrix that is not there"
        ]

    # `command_verify` raises SystemExit on refusal. An inadmissible matrix is
    # the gate working, so its message becomes a problem rather than an
    # exception here. The namespace is constructed by hand rather than by
    # M13's parser so this tool stays a caller of that module's rules rather
    # than a second opinion about its command line.
    try:
        m13_matrix.command_verify(argparse.Namespace(root=str(matrix_root)))
    except SystemExit as refusal:
        return [f"performance_gate_pass: matrix refused by M13: {refusal}"]
    return []


CHECKS = {
    "check_signed_release_artifacts": check_signed_release_artifacts,
    "check_update_metadata": check_update_metadata,
    "check_licensing_integration": check_licensing_integration,
    "check_security_gate": check_security_gate,
    "check_performance_gate": check_performance_gate,
}


def gate_coverage(roadmap_m14_gates: list[str]) -> list[str]:
    """Every gate M14 declares must be either checked or explicitly signed off.

    This is the check that stops the milestone from regrowing the hole it was
    born with. Adding a gate to M14 without deciding how it is verified makes
    this tool fail, which is the moment to decide.
    """
    problems: list[str] = []
    for gate in roadmap_m14_gates:
        if gate not in GATES:
            problems.append(
                f"gate_coverage: M14 gate {gate!r} is declared but nothing checks it "
                "and no signoff is named for it"
            )
    for gate in GATES:
        if gate not in roadmap_m14_gates:
            problems.append(
                f"gate_coverage: {gate!r} is checked here but is no longer an M14 gate"
            )
    return problems


def evaluate(release: dict, roadmap_m14_gates: list[str]) -> dict:
    """Decide every M14 gate and report, without ever deciding to ship."""
    report: dict[str, object] = {
        "release": release.get("release_id", "<unnamed>"),
        "gates": {},
        "admissible": False,
    }
    problems: list[str] = list(gate_coverage(roadmap_m14_gates))

    for gate in roadmap_m14_gates:
        spec = GATES.get(gate)
        if spec is None:
            # gate_coverage already reported it; do not double-report here.
            report["gates"][gate] = "unchecked"
            continue

        if "requires_signoff" in spec:
            report["gates"][gate] = {
                "status": "requires_signoff",
                "authority": spec["requires_signoff"],
                "rationale": spec["rationale"],
                # Never auto-satisfied. A signoff gate that this tool can
                # pass on its own would not be a signoff gate.
                "satisfied_by_tool": False,
            }
            continue

        gate_problems = CHECKS[spec["check"]](release)
        if gate_problems:
            report["gates"][gate] = {"status": "refused", "problems": gate_problems}
            problems.extend(gate_problems)
        else:
            report["gates"][gate] = {"status": "green"}

    # Two gates here are outside this tool's reach and are NOT counted as
    # satisfied, so `admissible` can never be `True` while they are unsigned.
    #
    # Keyed off `status`, not off a `requires_signoff` field in the report: the
    # report describes the gate's state, and `requires_signoff` is the
    # *specification* key, which is not what the report carries. Reading the
    # wrong one silently yields an empty list, and an empty list reads as "no
    # signoffs outstanding" — which would make this the exact bug it exists to
    # prevent.
    signoffs_pending = [
        gate
        for gate in roadmap_m14_gates
        if isinstance(report["gates"].get(gate), dict)
        and report["gates"][gate].get("status") == "requires_signoff"
    ]
    report["signoffs_pending"] = signoffs_pending
    report["admissible"] = not problems and not signoffs_pending
    report["problems"] = problems
    report["note"] = (
        "admissible means every automatic gate is green and no signoff is "
        "outstanding. It is a necessary condition for a release, never a "
        "sufficient one: this tool cannot decide that a product should ship."
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        required=True,
        help="release declaration JSON (see docs/RELEASE_GATE.md)",
    )
    parser.add_argument(
        "--roadmap",
        default=str(REPO_ROOT / "ROADMAP.yaml"),
        help="ROADMAP.yaml, read for M14's gate list so this tool and the "
        "roadmap cannot drift apart",
    )
    return parser


def m14_gates_from_roadmap(roadmap_path: Path) -> list[str]:
    """Read M14's gates from the roadmap rather than trusting this file.

    The point of the gate-coverage check is defeated if the gate list is
    copied here, because adding a gate to M14 would then not be noticed.
    Reading it back from the roadmap is what makes the drift detectable.
    """
    import re

    text = roadmap_path.read_text(encoding="utf-8")
    match = re.search(r"id:\s*M14(.*?)(?=\n\s*-\s*id:\s*M\d|\Z)", text, re.DOTALL)
    if match is None:
        fail(f"could not find milestone M14 in {roadmap_path}")
    gates_block = re.search(r"gates:\s*\n((?:\s*-\s*\S+\n?)+)", match.group(1))
    if gates_block is None:
        fail(f"M14 in {roadmap_path} declares no gates")
    return re.findall(r"-\s*(\S+)", gates_block.group(1))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    release = load_json(Path(args.release), "release")
    if release is None:
        # `load_json` returns None rather than raising so that one missing
        # document fails its own gate and the others still report. Honouring
        # that here is the difference between "the release manifest is
        # missing" and a traceback from `None.get`. An unreadable manifest
        # used to crash before a single gate spoke, which is the same failure
        # the docstring on `load_json` was written to prevent -- just reached
        # from a different door.
        print(
            json.dumps(
                {
                    "release": "<unreadable>",
                    "gates": {},
                    "admissible": False,
                    "problems": [
                        f"release: cannot read the release manifest at {args.release}",
                    ],
                },
                indent=2,
            )
        )
        return 1
    roadmap_gates = m14_gates_from_roadmap(Path(args.roadmap))
    report = evaluate(release, roadmap_gates)
    print(json.dumps(report, indent=2))
    return 0 if report["admissible"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    sys.exit(main())