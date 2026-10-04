#!/usr/bin/env python3
"""Tests for the roadmap-wide admissibility checker.

Each test names the single edit that would let an unenforced gate pass while
it is unenforced. A test that cannot be made to fail by one edit is not
pinning the behaviour it claims to.
"""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "roadmap_admissibility", ROOT / "scripts" / "roadmap_admissibility.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ra = load_tool()


class Fixture(unittest.TestCase):
    """A repository copy that outlives the call that built it.

    `TemporaryDirectory` + `addCleanup`, for the reason the M5 fixture carries
    the same note: a fixture whose lifetime is shorter than its own tests is a
    fixture that tests nothing.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "repo"
        self.root.mkdir(parents=True)
        # Copy everything the checker reads, rather than an enumerated list of
        # it. The first version copied eleven hand-picked files and five
        # tests failed for the wrong reason -- the registry names modules in
        # `collaboration.rs`, `licensing.rs`, `enterprise/tests.rs` and others
        # that were never copied, so the checker correctly reported those
        # gates unenforced against a tree that was merely incomplete.
        #
        # A fixture that assembles a partial repository tests the fixture as
        # much as the tool.
        for name in ("ROADMAP.yaml", "Cargo.toml", "SECURITY.md", "README.md", "LICENSE"):
            source = ROOT / name
            if source.is_file():
                shutil.copy2(source, self.root / name)
        for tree in ("crates", "docs", "scripts", ".github"):
            source = ROOT / tree
            if source.is_dir():
                shutil.copytree(
                    source, self.root / tree, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target", "__pycache__")
                )
        toolchain = ROOT / "rust-toolchain.toml"
        if toolchain.is_file():
            shutil.copy2(toolchain, self.root / "rust-toolchain.toml")

    def report(self) -> dict:
        return ra.evaluate(self.root, self.root / "ROADMAP.yaml")

    def write_roadmap(self, text: str) -> None:
        (self.root / "ROADMAP.yaml").write_text(text, encoding="utf-8")


class TestTheRealRoadmap(Fixture):
    """The check that matters: this repository, as it stands."""

    def test_every_declared_gate_is_enforced(self) -> None:
        """Mutation: `if entry is None:` -> `if False:` in the forward loop."""
        report = self.report()
        self.assertEqual(
            report["problems"], [], "the real roadmap must be fully enforced"
        )

    def test_the_real_roadmap_is_admissible(self) -> None:
        """Mutation: `"roadmap_admissible": not problems` -> `True`."""
        self.assertTrue(self.report()["roadmap_admissible"])

    def test_every_milestone_with_gates_is_covered(self) -> None:
        """Mutation: skip a milestone in the loop.

        Compared against the milestones that actually declare gates, not
        against a constant. M14 declares none in ROADMAP.yaml -- its seven
        gates live in `scripts/release_gate.py` -- so it contributes nothing to
        `enforced`, and a hardcoded 15 would be asserting that a milestone
        with no gates produces rows, which it does not.
        """
        report = self.report()
        milestones = {item["milestone"] for item in report["enforced"]}
        declared = {
            name
            for name, milestone in ra.parse_roadmap(self.root / "ROADMAP.yaml").items()
            if milestone["exit_criteria"] or milestone["security_gates"]
        }
        self.assertEqual(milestones, declared)
        self.assertGreaterEqual(len(milestones), 13)

    def test_the_gate_count_is_what_the_roadmap_declares(self) -> None:
        """Every roadmap gate must appear in the report, and no extras.

        Compared both ways on purpose. Asserting only `report == roadmap`
        passes while the tool under-reports *and* the roadmap over-declares,
        which is the one state in which a gate has quietly vanished.
        """
        report = self.report()
        declared = {
            (milestone, name)
            for milestone, spec in ra.parse_roadmap(self.root / "ROADMAP.yaml").items()
            for name in (*spec["exit_criteria"], *spec["security_gates"])
        }
        covered = {
            (item["milestone"], item["gate"]) for item in report["enforced"]
        }
        self.assertEqual(covered, declared)


class TestForwardDirection(Fixture):
    def test_a_criterion_with_no_enforcement_is_a_problem(self) -> None:
        """Mutation: `if entry is None: problems.append(...)` -> `if False:`."""
        original = ra.REGISTRY["M3"]["authorized_input_round_trip_verified"]
        ra.REGISTRY["M3"].pop("authorized_input_round_trip_verified")
        self.addCleanup(
            ra.REGISTRY["M3"].__setitem__, "authorized_input_round_trip_verified", original
        )
        report = self.report()
        self.assertTrue(
            any("authorized_input_round_trip_verified" in p for p in report["problems"])
        )

    def test_a_security_gate_with_no_enforcement_is_a_problem(self) -> None:
        """Mutation: the same edit in the gate branch."""
        original = ra.REGISTRY["M3"]["malformed_input_rejected"]
        ra.REGISTRY["M3"].pop("malformed_input_rejected")
        self.addCleanup(
            ra.REGISTRY["M3"].__setitem__, "malformed_input_rejected", original
        )
        report = self.report()
        self.assertTrue(any("malformed_input_rejected" in p for p in report["problems"]))

    def test_a_gate_pointing_at_a_missing_script_is_a_problem(self) -> None:
        """Mutation: drop the `checker` existence check.

        This is the failure that found the invented `scripts/verify_*.py`
        names: a registry entry naming a file that does not exist is a claim
        about a gate nobody runs.
        """
        self.assertTrue(
            ra.check_enforcement_exists(self.root, "checker", "scripts/nonexistent.py")
            is False
        )
        self.assertTrue(
            ra.check_enforcement_exists(
                self.root, "checker", "scripts/verify_m0_repository.py"
            )
        )

    def test_a_module_entry_requires_the_file_and_the_function(self) -> None:
        """Mutation: check only the file, ignoring the declared function name.

        The whole point of naming a test is that the test enforces the gate. A
        file-only check would accept a registry entry pointing at `input.rs`
        forever after `stale_session_input_is_rejected` was deleted.
        """
        good = "omnidesk-core:src/input.rs::stale_session_input_is_rejected"
        self.assertTrue(ra.check_enforcement_exists(self.root, "module", good))

        missing_fn = "omnidesk-core:src/input.rs::a_test_that_was_never_written"
        self.assertFalse(
            ra.check_enforcement_exists(self.root, "module", missing_fn)
        )

        missing_file = "omnidesk-core:src/no_such_file.rs::whatever"
        self.assertFalse(
            ra.check_enforcement_exists(self.root, "module", missing_file)
        )

    def test_a_module_entry_does_not_match_a_name_merely_mentioned(self) -> None:
        """Mutation: substring match instead of `fn name(`.

        A rename that leaves the old word in a comment or in a longer function
        name must not read as still-enforced. Checked against a file that does
        contain the word, but not as a declaration of that exact name.
        """
        path = self.root / "crates" / "omnidesk-core" / "src" / "probe.rs"
        path.write_text(
            "// the stale_session_input_is_rejected test used to live here\n"
            "fn stale_session_input_is_rejected_by_policy_v2() {}\n",
            encoding="utf-8",
        )
        reference = "omnidesk-core:src/probe.rs::stale_session_input_is_rejected"
        self.assertFalse(ra.check_enforcement_exists(self.root, "module", reference))

    def test_a_malformed_module_reference_is_refused(self) -> None:
        """Mutation: accept a reference with no `crate:path::fn` shape."""
        with self.assertRaises(SystemExit):
            ra.check_enforcement_exists(self.root, "module", "not-a-reference")

    def test_an_unknown_enforcement_kind_is_refused(self) -> None:
        """Mutation: `fail(f"unknown enforcement kind")` removed."""
        with self.assertRaises(SystemExit):
            ra.check_enforcement_exists(self.root, "wishful", "whatever")


class TestReverseDirection(Fixture):
    """The direction that catches a *removal*."""

    def test_a_gate_removed_from_the_roadmap_leaves_a_stray_registry_entry(self) -> None:
        """Mutation: `if name not in declared:` -> `if False:`."""
        text = (self.root / "ROADMAP.yaml").read_text(encoding="utf-8")
        self.write_roadmap(text.replace("      - malformed_input_rejected\n", ""))
        report = self.report()
        self.assertTrue(
            any("no longer declares" in p for p in report["problems"]),
            "deleting a security gate from the roadmap must be reported",
        )

    def test_a_registry_milestone_absent_from_the_roadmap_is_a_problem(self) -> None:
        """Mutation: drop the registry/roadmap cross-check."""
        self.write_roadmap("milestones:\n  - id: M0\n    status: complete\n")
        report = self.report()
        self.assertTrue(any("no matching milestone" in p for p in report["problems"]))


class TestSignoffGates(Fixture):
    def test_a_signoff_gate_requires_an_authority(self) -> None:
        """Mutation: `return bool(enforcement.strip())` -> `return True`.

        A sign-off with nobody answerable for it is a gate that nobody is
        holding, which is worse than an unimplemented one because it reads as
        handled.
        """
        self.assertFalse(ra.check_enforcement_exists(self.root, "signoff", "   "))
        self.assertTrue(ra.check_enforcement_exists(self.root, "signoff", "security review"))

    def test_the_report_lists_its_signoff_gates(self) -> None:
        """Mutation: `"signoff_gates": len(signoffs)` -> `0`."""
        report = self.report()
        self.assertGreater(report["signoff_gates"], 0)
        self.assertEqual(len(report["signoffs"]), report["signoff_gates"])

    def test_the_human_judgement_gates_are_not_given_an_invented_checker(self) -> None:
        """M11's criteria cannot be settled by a program.

        The mutation this guards against is registering
        `critical_findings_zero` against a script that the same repository
        wrote and will therefore agree with. It would make the gate pass.
        """
        for gate in (
            "critical_findings_zero",
            "high_findings_zero_or_explicitly_block_release",
            "threat_model_reviewed",
        ):
            kind, _ = ra.REGISTRY["M11"][gate]
            self.assertEqual(kind, "signoff", f"{gate} must remain a human judgement")


class TestRoadmapParsing(Fixture):
    def test_a_roadmap_with_no_milestones_is_refused(self) -> None:
        """Mutation: return an empty dict instead of failing."""
        self.write_roadmap("product:\n  name: X\n")
        with self.assertRaises(SystemExit):
            ra.parse_roadmap(self.root / "ROADMAP.yaml")

    def test_a_missing_roadmap_is_refused(self) -> None:
        """Mutation: return `{}` on FileNotFoundError."""
        with self.assertRaises(SystemExit):
            ra.parse_roadmap(self.root / "does_not_exist.yaml")

    def test_the_next_milestone_is_not_mistaken_for_this_ones(self) -> None:
        """Mutation: read the whole file rather than the milestone's block.

        M3 declares `malformed_input_rejected` and M5 does not. If the reader
        ran past M3's block into the next milestone, both would show the same
        list, and every downstream enforcement check would be reading a
        different milestone's requirements.
        """
        milestones = ra.parse_roadmap(self.root / "ROADMAP.yaml")
        self.assertIn("malformed_input_rejected", milestones["M3"]["security_gates"])
        self.assertNotIn("malformed_input_rejected", milestones["M5"]["security_gates"])
        self.assertIn(
            "authorization_failure_is_fail_closed", milestones["M5"]["security_gates"]
        )


class TestCiStepEnforcement(Fixture):
    def test_a_ci_step_name_must_exist_in_the_workflow(self) -> None:
        """Mutation: `return enforcement in ci_step_names(...)` -> `return True`.

        A registry entry naming a CI step that was later renamed is exactly
        the silent drift this catches: the gate stops running and nothing
        reports it.
        """
        self.assertTrue(
            ra.check_enforcement_exists(self.root, "ci_step", "M5 relay evidence admissibility gate")
        )
        self.assertFalse(
            ra.check_enforcement_exists(self.root, "ci_step", "A step that does not exist")
        )

    def test_the_workflow_step_names_are_read_from_the_file(self) -> None:
        """Mutation: hardcode the step-name list."""
        names = ra.ci_step_names(self.root / ".github" / "workflows" / "ci.yml")
        self.assertIn("M3 authorized input and rejection gate", names)
        self.assertIn("M1 authenticated LAN session gate", names)

    def test_a_missing_workflow_is_refused(self) -> None:
        """Mutation: return an empty set on FileNotFoundError."""
        with self.assertRaises(SystemExit):
            ra.ci_step_names(self.root / "no" / "such" / "workflow.yml")


class TestReportDerivation(Fixture):
    """Three survivors from the first mutation run, each a missing test."""

    def test_inline_list_syntax_is_parsed(self) -> None:
        """Mutation: `if inline.startswith("[")` -> `if False:`.

        `depends_on: [M4]` and friends are written inline. A reader that
        only handled block lists would return an empty list for every one of
        them, which is a silent wrong answer rather than an error.
        """
        block = [
            "  - id: M5",
            "    exit_criteria: [a_criterion, another_criterion]",
            "  - id: M6",
        ]
        self.assertEqual(
            ra._collect(block, "exit_criteria"),
            ["a_criterion", "another_criterion"],
        )

    def test_an_inline_list_of_one_is_parsed(self) -> None:
        """A single-element inline list is still a list.

        Without this, a one-item gate written inline would parse as empty and
        the gate would silently lose its only requirement.
        """
        block = ["  - id: M5", "    exit_criteria: [only_one]"]
        self.assertEqual(ra._collect(block, "exit_criteria"), ["only_one"])

    def test_a_bare_scalar_is_not_parsed_as_a_list(self) -> None:
        """`exit_criteria: some_string` is not `["some_string"]`."""
        block = ["  - id: M5", "    exit_criteria: not_a_list"]
        self.assertEqual(ra._collect(block, "exit_criteria"), [])

    def test_problems_must_make_the_roadmap_inadmissible(self) -> None:
        """Mutation: `"roadmap_admissible": not problems` -> `True`.

        The complement of `test_the_real_roadmap_is_admissible`: without a
        test that an *unclean* tree is inadmissible, a tool that reported
        every problem and always said PASS would pass both.
        """
        original = ra.REGISTRY["M3"]["malformed_input_rejected"]
        ra.REGISTRY["M3"].pop("malformed_input_rejected")
        self.addCleanup(
            ra.REGISTRY["M3"].__setitem__, "malformed_input_rejected", original
        )
        report = self.report()
        self.assertTrue(report["problems"], "precondition: problems exist")
        self.assertFalse(
            report["roadmap_admissible"],
            "a roadmap with unenforced gates must not be admissible",
        )

    def test_the_gate_count_is_derived_not_declared(self) -> None:
        """Mutation: `"gates_covered": len(covered)` -> a constant.

        Compared against the *registry*, not against the roadmap. The first
        version compared against the roadmap's own total, which is a useless
        comparison when nothing is broken: `len(covered)` and the roadmap
        total are equal exactly when the tool is working, so replacing the
        field with today's constant left the test green. Removing a registry
        entry makes the two disagree, which is the change that matters.
        """
        report = self.report()
        registry_total = sum(
            len(entries) for entries in ra.REGISTRY.values()
        )
        self.assertEqual(report["gates_covered"], registry_total)

        original = ra.REGISTRY["M3"]["malformed_input_rejected"]
        ra.REGISTRY["M3"].pop("malformed_input_rejected")
        self.addCleanup(
            ra.REGISTRY["M3"].__setitem__, "malformed_input_rejected", original
        )
        after = self.report()
        self.assertEqual(after["gates_covered"], registry_total - 1)


if __name__ == "__main__":
    unittest.main()
