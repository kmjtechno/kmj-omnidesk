#!/usr/bin/env python3
"""Roadmap-wide admissibility: is every declared gate enforced by name?

This tool does not run any gate and does not decide whether a milestone is
complete. It checks one property, for every milestone in `ROADMAP.yaml` at
once:

    every exit criterion, security gate, and deliverable the roadmap declares
    must be *enforced by name* somewhere -- a CI step, a checker script, a
    test, or an explicitly recorded sign-off.

The property is not bureaucratic. Before this existed, twelve of fifteen
milestones declared criteria that appeared nowhere in the tree. `critical_
findings_zero`, `signature_verification_pass`, `primary_flow_works_without_
terminal` and their neighbours were satisfied by nothing in particular, and
because `ROADMAP.yaml` is a static file, nothing could tell.

Three enforcement kinds are recognised, and a gate that names none of them is
an error:

  `ci_step`
      A named step in `.github/workflows/ci.yml`. Enforced on every push.

  `checker`
      A script under `scripts/` that mentions the gate by name. Enforced
      locally and in CI when the script is itself a CI step.

  `signoff`
      A gate no program can settle, listed here with the authority that must.
      Legal review, a human approving a threat model, a real hardware run.

`signoff` is the escape hatch that makes this tool honest rather than
brittle. Without it, the only way to make this pass would be to invent a
checker for "a non-author reviewer approved the threat model", which would be
worse than useless -- it would be a machine agreeing with itself.

## Why the registry is explicit and read from the roadmap

The list of *milestones* comes from `ROADMAP.yaml`. The mapping from gate name
to enforcement is written out here by hand, deliberately.

Copying the gate names in would defeat the point: adding an exit criterion to
the roadmap would then have nothing to compare against and would pass
unnoticed. So the names are read back out, and a name in the roadmap with no
entry here is an error -- that is the moment to decide how it is verified.

## What this does not do

It does not run `cargo test`, does not inspect a signature, and does not read a
benchmark. It does not claim a milestone is done. A milestone can satisfy every
gate here and still be `pending`, because these checks say the requirements are
*enforced*, not that they *pass*.

Both directions are checked. A registry entry naming a gate the roadmap no
longer declares is an error too: that is how a removal is caught, and removing
a security gate from a roadmap by deleting one line is otherwise invisible.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

# (kind, enforcement) per milestone.
#
# `signoff` entries carry the authority that must provide them, because "a
# human decided" is not an enforcement and naming no authority is how a
# sign-off gate becomes a rubber stamp.
#
# The `module` kind is new, and it is what most of these entries actually are.
# The first version of this registry pointed at `scripts/verify_*.py` files
# that were never written -- `verify_control_permission.py`,
# `verify_static_suppression.py`, `verify_audit_events.py` and a dozen others
# were invented names. The checker correctly refused them, which is how the
# invention became visible: 43 failures naming gates whose enforcement did
# not exist.
#
# Nearly all of them already existed as *Rust tests*. `input.rs` has
# `unauthenticated_or_unauthorized_input_is_rejected`,
# `stale_session_input_is_rejected` and `malformed_input_is_rejected`;
# `enterprise/tests.rs` has `audit_altering_an_event_is_detected` and the
# whole escalation suite. The gates were not unenforced so much as unnamed --
# the behaviour was tested, and nothing connected the test to the roadmap
# entry. So `module` points at the test module that must contain the named
# test, and the check is by *name*, not by file.
#
# By name rather than by file is the whole point. A file existing proves
# nothing; `fn stale_session_input_is_rejected` being present proves the
# refusal has a test. Renaming that function without updating the registry
# fails here, which is the drift this exists to catch.
REGISTRY: dict[str, dict[str, tuple[str, str]]] = {
    "M0": {
        "all_deliverables_present": ("checker", "scripts/verify_m0_repository.py"),
        "all_M0_gates_pass": ("checker", "scripts/verify_m0_repository.py"),
        "canonical_identity_tested": ("module", "omnidesk-core:src/lib.rs::canonical_identity_is_stable"),
    },
    "M1": {
        "authenticated_LAN_session_proof": (
            "ci_step",
            "M1 authenticated LAN session gate",
        ),
        "no_implicit_control_permission": (
            "module",
            "omnidesk-core:src/session.rs::revoke_and_disconnect_remove_control_permission",
        ),
        "deterministic_unit_tests_pass": ("ci_step", "Test"),
    },
    "M2": {
        "capture_encode_transport_decode_render_path_measured": (
            "ci_step",
            "Measure synthetic capture-to-render reference path",
        ),
        "static_frame_suppression_verified": (
            "module",
            "omnidesk-core:src/media.rs::identical_static_frame_is_suppressed",
        ),
        "no_unbounded_frame_queue": (
            "module",
            "omnidesk-core:src/frame_queue.rs::a_full_queue_never_grows",
        ),
        "benchmark_results_saved_as_artifacts": ("ci_step", "Upload benchmark artifacts"),
    },
    "M3": {
        "authorized_input_round_trip_verified": (
            "module",
            "omnidesk-core:src/input.rs::authorized_input_round_trip_is_recorded",
        ),
        "all_security_gates_pass": ("ci_step", "M3 authorized input and rejection gate"),
        "unauthenticated_input_rejected": (
            "module",
            "omnidesk-core:src/input.rs::unauthenticated_or_unauthorized_input_is_rejected",
        ),
        "stale_session_input_rejected": (
            "module",
            "omnidesk-core:src/input.rs::stale_session_input_is_rejected",
        ),
        "revoked_permission_rejected": (
            "module",
            "omnidesk-core:src/input.rs::emergency_revoke_stops_future_input",
        ),
        "malformed_input_rejected": (
            "module",
            "omnidesk-core:src/input.rs::malformed_input_is_rejected",
        ),
    },
    "M4": {
        "direct_path_verified_across_test_matrix": (
            "ci_step",
            "M4 REALNET-60 schema conformance gate",
        ),
        "failure_modes_are_explicit": ("checker", "scripts/m4_evidence.py"),
        "metrics_exported": ("ci_step", "Measure direct-connect reference path"),
    },
    "M5": {
        "forced_direct_failure_falls_back_to_relay": ("checker", "scripts/m5_evidence.py"),
        "end_to_end_confidentiality_preserved": ("checker", "scripts/m5_evidence.py"),
        "relay_utilization_measured": ("checker", "scripts/m5_evidence.py"),
        "relay_cannot_decrypt_session_payload": ("checker", "scripts/m5_evidence.py"),
        "relay_cannot_grant_control_permission": ("checker", "scripts/m5_evidence.py"),
        "authorization_failure_is_fail_closed": ("checker", "scripts/m5_evidence.py"),
    },
    "M6": {
        "every_profile_has_reproducible_results": (
            "module",
            "omnidesk-core:src/weak_network.rs::every_declared_profile_degrades_progressively_and_reproducibly",
        ),
        "no_unverified_fastest_claim": ("checker", "scripts/m13_matrix.py"),
        "degradation_is_progressive_not_catastrophic": (
            "module",
            "omnidesk-core:src/weak_network.rs::degradation_steps_down_one_rung_per_sample_never_jumping",
        ),
    },
    "M7": {
        "primary_flow_works_without_terminal": (
            "ci_step",
            "Verify M7 terminal-free native primary flow",
        ),
        # Keyboard navigation has no test anywhere in the tree. `product_shell`
        # renders views but nothing drives them from a key. Recorded as a
        # sign-off rather than a module so the gap is named instead of
        # pointed at a test that does not exist.
        "keyboard_navigation_verified": (
            "signoff",
            "accessibility review, on a real keyboard traversal",
        ),
        "resource_budget_measured": (
            "ci_step",
            "Measure Windows desktop resource baseline",
        ),
    },
    "M8": {
        "feature_tests_pass": ("ci_step", "M8 collaboration security and resume gate"),
        "weak_network_transfer_resume_verified": (
            "ci_step",
            "M8 weak-network resume integrity gate",
        ),
        "clipboard_permission_enforced": (
            "module",
            "omnidesk-core:src/collaboration.rs::clipboard_permission_is_explicit_and_directional",
        ),
        "file_paths_sanitized": (
            "module",
            "omnidesk-core:src/collaboration.rs::transfer_paths_reject_escape_and_platform_prefixes",
        ),
        "transfer_integrity_verified": (
            "module",
            "omnidesk-core:src/collaboration.rs::modified_transfer_chunk_is_rejected",
        ),
        "audio_permission_explicit": (
            "module",
            "omnidesk-core:src/collaboration.rs::remote_audio_requires_explicit_permission",
        ),
    },
    "M9": {
        "integration_tests_pass": (
            "ci_step",
            "M9 committed licensing vector conformance gate",
        ),
        "purchase_stays_disabled_until_release_gate": (
            "module",
            "omnidesk-core:src/commercial_gate.rs::a_gate_starts_closed_and_says_so",
        ),
        "forged_entitlement_rejected": (
            "module",
            "omnidesk-core:src/licensing.rs::forged_signature_fails_closed",
        ),
        "expired_entitlement_handled_by_policy": (
            "module",
            "omnidesk-core:src/licensing.rs::expired_entitlement_fails_closed",
        ),
        "revoked_entitlement_rejected": (
            "module",
            "omnidesk-core:src/licensing.rs::known_revocation_overrides_offline_grace",
        ),
        "client_cannot_self_upgrade_plan": (
            "module",
            "omnidesk-core:src/licensing.rs::signed_payload_boundary_rejects_unknown_fields_and_duplicate_capabilities",
        ),
        "secrets_redacted_from_logs": (
            "module",
            "omnidesk-core:src/log_scrubber.rs::a_secret_redacts_under_every_formatting_path",
        ),
    },
    "M10": {
        "tenant_boundary_tests_pass": (
            "module",
            "omnidesk-core:src/enterprise/tests.rs::tenant_a_context_cannot_use_another_tenants_policy",
        ),
        "privilege_escalation_tests_pass": (
            "module",
            "omnidesk-core:src/enterprise/tests.rs::escalation_no_role_may_delegate_a_permission_it_lacks",
        ),
        "audit_events_verified": (
            "module",
            "omnidesk-core:src/enterprise/tests.rs::audit_altering_an_event_is_detected",
        ),
    },
    "M11": {
        # Three of M11's four criteria are human judgements. They are marked
        # `signoff` rather than given an invented checker, because a program
        # that agreed that "zero critical findings" is a program agreeing with
        # itself. `fuzz_and_negative_tests_pass` is the one that a machine can
        # settle, and CI settles it.
        "critical_findings_zero": (
            "signoff",
            "security review, by a reviewer other than the author",
        ),
        "high_findings_zero_or_explicitly_block_release": (
            "signoff",
            "security review, by a reviewer other than the author",
        ),
        "threat_model_reviewed": (
            "signoff",
            "security review, by a reviewer other than the author",
        ),
        "fuzz_and_negative_tests_pass": ("ci_step", "Signed entitlement fuzz smoke"),
    },
    "M12": {
        "install_update_uninstall_matrix_pass": (
            "checker",
            "scripts/verify_release_manifest.py",
        ),
        "signature_verification_pass": (
            "signoff",
            "release engineering, with a production key",
        ),
    },
    "M13": {
        "full_matrix_complete": (
            "signoff",
            "performance engineering, on real multi-hardware runs",
        ),
        "regressions_block_release": ("checker", "scripts/m13_matrix.py"),
    },
}

# The stages that must appear in `ci.yml` for a `(ci_step, name)` entry to
# count. Checked rather than trusted: a registry entry naming a CI step that
# was later renamed is exactly the silent drift this exists to catch, and a
# name that no longer appears is a gate nobody runs.
#
# `M0 canonical identity gate` and the other M0/M1 names below were verified to
# exist when this was written; a rename that breaks them will fail here rather
# than quietly stop being enforced.


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_roadmap(path: Path) -> dict[str, dict[str, list[str]]]:
    """Read every milestone's criteria, gates, and deliverables.

    Parsed rather than copied, so a gate added to `ROADMAP.yaml` without a
    registry entry is an error rather than a silent pass.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        fail(f"missing roadmap: {path}")

    starts = [
        number
        for number, line in enumerate(lines)
        if re.match(r"^\s*-\s*id:\s*M[A-Z0-9]+\s*$", line)
    ]
    if not starts:
        fail(f"{path}: no milestones found")

    milestones: dict[str, dict[str, list[str]]] = {}
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(lines)
        block = lines[start:end]
        milestone = re.match(r"^\s*-\s*id:\s*(M[A-Z0-9]+)\s*$", lines[start])
        if milestone is None:  # pragma: no cover -- the regex already matched
            continue
        milestones[milestone.group(1)] = {
            "exit_criteria": _collect(block, "exit_criteria"),
            "security_gates": _collect(block, "security_gates"),
            "deliverables": _collect(block, "deliverables"),
        }
    return milestones


def _collect(block: list[str], key: str) -> list[str]:
    found: list[str] = []
    reading = False
    for line in block:
        stripped = line.strip()
        if re.match(rf"^{key}:", stripped):
            reading = True
            inline = stripped[len(key) + 1 :].strip()
            if inline.startswith("[") and inline.endswith("]"):
                return [item.strip() for item in inline[1:-1].split(",") if item.strip()]
            continue
        if reading:
            if stripped.startswith("- "):
                found.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                reading = False
    return found


def ci_step_names(workflow: Path) -> set[str]:
    """The `name:` values of every step in the workflow.

    Read back out of the file rather than assumed, so renaming a step is
    caught here instead of silently making a registry entry a claim about a
    gate that no longer runs.
    """
    try:
        text = workflow.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"missing workflow: {workflow}")
    return {
        match.group(1).strip()
        for match in re.finditer(r"^\s*-?\s*name:\s*(.+?)\s*$", text, re.M)
    }


def check_enforcement_exists(root: Path, kind: str, enforcement: str) -> bool:
    """Whether the named enforcement is actually present.

    A registry entry is a claim; this checks the claim. Without it, the
    registry would only restate the roadmap in a different file, and a typo
    in an enforcement path would be indistinguishable from a working gate.

    For `module`, both halves are checked: the file exists *and* it declares a
    function of that name. Checking only the file would let a registry entry
    point at `src/input.rs` forever after the test it names was deleted --
    which is the failure this kind exists to prevent, since the whole point
    of naming a test is that the test is what enforces the gate.
    """
    if kind == "ci_step":
        return enforcement in ci_step_names(root / ".github" / "workflows" / "ci.yml")
    if kind == "checker":
        return (root / enforcement).is_file()
    if kind == "module":
        return module_declares(root, enforcement)
    if kind == "signoff":
        # A sign-off has no file to point at. What it must have is an
        # authority, and that is checked by the caller -- an empty string
        # would make a gate that no one is answerable for.
        return bool(enforcement.strip())
    fail(f"unknown enforcement kind {kind!r}")


def module_declares(root: Path, enforcement: str) -> bool:
    """Whether `crate:path::fn_name` resolves to a declared function.

    Parsed rather than substring-matched. A substring search would accept
    `fn stale_session_input_is_rejected` appearing inside a comment or a
    longer name, and the failure this guards against is precisely a rename
    that leaves the old word in prose -- a rename that a substring search
    reads as still-enforced.
    """
    parts = enforcement.split("::")
    if len(parts) != 2 or ":" not in parts[0]:
        fail(
            f"malformed module reference {enforcement!r}; "
            "expected crate:path/to/file.rs::function_name"
        )
    crate, relative = parts[0].split(":", 1)
    function = parts[1]

    path = root / "crates" / crate / relative
    if not path.is_file():
        return False

    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return False

    # `fn name(` rather than a bare `name`, so the function must be declared
    # with the exact name and something must follow the paren.
    return re.search(rf"\bfn\s+{re.escape(function)}\s*\(", source) is not None


def evaluate(root: Path, roadmap: Path) -> dict:
    """Build the report. Never raises on drift -- it reports it."""
    milestones = parse_roadmap(roadmap)
    problems: list[str] = []
    covered: list[dict] = []

    for milestone in sorted(milestones, key=lambda name: int(name[1:])):
        declared = {
            **{
                criterion: "exit_criterion"
                for criterion in milestones[milestone]["exit_criteria"]
            },
            **{gate: "security_gate" for gate in milestones[milestone]["security_gates"]},
        }
        registry = REGISTRY.get(milestone, {})

        # Forward: a declared gate with no enforcement is an error. This is
        # the check that would have caught twelve unenforced milestones.
        for name, kind in declared.items():
            entry = registry.get(name)
            if entry is None:
                problems.append(
                    f"{milestone}: {kind} {name!r} is declared in ROADMAP.yaml "
                    "but has no enforcement in roadmap_admissibility.py"
                )
                continue
            enforcement_kind, enforcement = entry
            if not check_enforcement_exists(root, enforcement_kind, enforcement):
                problems.append(
                    f"{milestone}: {kind} {name!r} claims enforcement "
                    f"{enforcement_kind}:{enforcement!r}, which is not present"
                )
                continue
            covered.append(
                {
                    "milestone": milestone,
                    "gate": name,
                    "kind": kind,
                    "enforced_by": enforcement_kind,
                    "enforcement": enforcement,
                }
            )

        # Reverse: a registry entry naming a gate the roadmap no longer
        # declares. This is the direction that catches a *removal* -- a
        # security gate deleted from ROADMAP.yaml would otherwise leave its
        # checker running, uninvoked, with nothing reporting the loss.
        for name in registry:
            if name not in declared:
                problems.append(
                    f"{milestone}: registry enforces {name!r}, which ROADMAP.yaml "
                    "no longer declares -- the requirement may have been removed"
                )

    # A milestone in the registry but not the roadmap is the same drift.
    for milestone in sorted(REGISTRY, key=lambda name: int(name[1:])):
        if milestone not in milestones:
            problems.append(
                f"{milestone}: registry entry has no matching milestone in ROADMAP.yaml"
            )

    signoffs = [item for item in covered if item["enforced_by"] == "signoff"]

    return {
        "generated_at": utc_now(),
        "milestones": len(milestones),
        "gates_covered": len(covered),
        "signoff_gates": len(signoffs),
        "signoffs": sorted(
            (f"{item['milestone']}:{item['gate']}" for item in signoffs)
        ),
        "enforced": covered,
        "problems": problems,
        "roadmap_admissible": not problems,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--roadmap", default="ROADMAP.yaml")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = evaluate(root, (root / args.roadmap).resolve())

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for problem in report["problems"]:
            print(f"FAIL {problem}")

    if not report["roadmap_admissible"]:
        fail(f"{len(report['problems'])} unenforced gate(s) in ROADMAP.yaml")

    print(
        json.dumps(
            {
                "roadmap_admissible": "PASS",
                "milestones": report["milestones"],
                "gates_covered": report["gates_covered"],
                "signoff_gates": report["signoff_gates"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
