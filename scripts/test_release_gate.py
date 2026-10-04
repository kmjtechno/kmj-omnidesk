"""M14 release-gate tests.

Every test names the single edit that would make it pass while the gate it
covers is broken. The ones that matter most are the negative-direction tests:
a suite that only confirms a *refusal* works would also pass against a tool
that refuses everything, which is the same failure as one that passes
everything.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_gate  # noqa: E402

M14_GATES = [
    "signed_release_artifacts",
    "update_metadata_verified",
    "licensing_integration_verified",
    "security_gate_pass",
    "performance_gate_pass",
    "support_and_recovery_path_defined",
    "legal_and_codec_license_review_complete",
]

# Gates that need no manifest on disk, so a fixture can satisfy them without a
# real release tree.
AUTOMATIC_ONLY = [
    "security_gate_pass",
]


class ReleaseFixture(unittest.TestCase):
    """A release tree that outlives the call that built it.

    The first version of this fixture built its files inside a
    `TemporaryDirectory` and returned the release dict from inside the `with`
    block, so the directory was cleaned up before any check ran. Six tests
    errored on missing files and three "passed" for the wrong reason. A fixture
    whose lifetime is shorter than its own tests is a fixture that tests
    nothing.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def a_complete_release(self) -> dict:
        """A release that satisfies every automatic gate it declares.

        Deliberately still *not* admissible: two signoff gates are outstanding
        by construction, because a test fixture cannot forge a legal review.
        """
        artifact = self.root / "omnidesk.exe"
        artifact.write_bytes(b"not a real binary")
        metadata = self.write("stable.json", json.dumps({"signature_declared": True}))
        contract = self.write("contract.json", json.dumps({"plans": ["pro", "enterprise"]}))

        return {
            "release_id": "test",
            "artifacts": [
                {
                    "name": "omnidesk.exe",
                    "path": str(artifact),
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "signature_declared": True,
                }
            ],
            "update_metadata": [{"channel": "stable", "path": str(metadata)}],
            "licensing_contract": {"path": str(contract)},
            "security_checks": [{"name": "cargo-deny", "status": "green"}],
        }


class ReleaseGateTests(ReleaseFixture):
    def output(self, result: subprocess.CompletedProcess) -> str:
        """Both channels.

        A refusal exits via `SystemExit`, so its message lands on stderr, while
        the report document is printed to stdout. A test asserting on only one
        of them passes or fails for reasons unrelated to the property.
        """
        return result.stdout + result.stderr

    # --- the gate-coverage check: M14's defining property ---------------

    def test_a_gate_with_no_checker_and_no_signoff_is_refused(self) -> None:
        """Mutation: drop the `gate not in GATES` branch.

        This is the check that stops M14 regrowing the hole it was born with.
        A gate added to the roadmap with nothing enforcing it must fail here,
        not pass quietly.
        """
        problems = release_gate.gate_coverage(M14_GATES + ["a_new_unenforced_gate"])

        self.assertTrue(any("a_new_unenforced_gate" in problem for problem in problems))

    def test_gate_coverage_requires_every_roadmap_gate_to_be_known(self) -> None:
        """Mutation: return an empty problem list from `gate_coverage`.

        A tool that checks nothing but reports success is worse than one that
        checks nothing, because it removes the reader's reason to distrust it.
        """
        self.assertEqual(release_gate.gate_coverage(M14_GATES), [])

    def test_gate_coverage_rejects_a_gate_dropped_from_the_roadmap(self) -> None:
        """Mutation: only check that every M14 gate is known, not the reverse.

        Without the reverse direction, deleting a gate from ROADMAP.yaml would
        leave a checker behind that no gate calls — a silent removal of a
        release requirement, which is exactly what the milestone is supposed to
        make impossible.
        """
        problems = release_gate.gate_coverage(M14_GATES[:-1])

        self.assertTrue(
            any(M14_GATES[-1] in problem for problem in problems),
            f"a gate checked here but dropped from the roadmap must be an error: {problems}",
        )

    # --- signed_release_artifacts ----------------------------------------

    def test_an_artifact_without_a_digest_is_refused(self) -> None:
        """Mutation: treat a missing digest as a match."""
        release = self.a_complete_release()
        release["artifacts"][0].pop("sha256")

        problems = release_gate.check_signed_release_artifacts(release)

        self.assertTrue(any("no digest" in problem for problem in problems))

    def test_an_artifact_whose_digest_was_edited_after_signing_is_refused(self) -> None:
        """Mutation: compare only the first N hex characters of the digest.

        A truncated comparison is the kind of weakening that passes review and
        fails in the field: the artifact changed, the release still certifies.

        The forged digest shares its first 12 characters with the real one, so
        a prefix comparison accepts it. An all-zeros digest does not — it fails
        a prefix comparison too, which made the first version of this test pass
        against the very mutation it was written for.
        """
        release = self.a_complete_release()
        real = release["artifacts"][0]["sha256"]
        release["artifacts"][0]["sha256"] = real[:12] + "f" * (len(real) - 12)

        problems = release_gate.check_signed_release_artifacts(release)

        self.assertTrue(any("does not match" in problem for problem in problems))

    def test_an_artifact_with_no_signature_is_refused(self) -> None:
        """Mutation: honour a release-level `signed: true` instead of a per-artifact one.

        The whole gate is about one artifact being unaccounted for. A release
        that says "these are signed, signed" and then ships an unsigned binary
        among them is the failure this check exists for.
        """
        release = self.a_complete_release()
        release["artifacts"][0].pop("signature_declared")
        release["signed"] = True

        problems = release_gate.check_signed_release_artifacts(release)

        self.assertTrue(any("no signature" in problem for problem in problems))

    def test_a_release_declaring_no_artifacts_is_refused(self) -> None:
        """Mutation: return `[]` for an empty artifact list.

        An empty set of artifacts is not a release; it is the absence of one.
        And it satisfies "every artifact is signed" vacuously, which is the
        shape of check that makes a gate quietly stop working.
        """
        release = self.a_complete_release()
        release["artifacts"] = []

        problems = release_gate.check_signed_release_artifacts(release)

        self.assertTrue(problems)

    def test_an_artifact_absent_from_disk_is_refused(self) -> None:
        """Mutation: skip artifacts whose path does not exist."""
        release = self.a_complete_release()
        release["artifacts"][0]["path"] = "/nonexistent/omnidesk.exe"

        problems = release_gate.check_signed_release_artifacts(release)

        self.assertTrue(any("not on disk" in problem for problem in problems))

    # --- update_metadata_verified ----------------------------------------

    def test_metadata_without_a_signature_is_refused(self) -> None:
        """Mutation: accept metadata that merely parses."""
        metadata = self.write("stable.json", json.dumps({"version": "1.0.0"}))
        release = {"update_metadata": [{"channel": "stable", "path": str(metadata)}]}

        problems = release_gate.check_update_metadata(release)

        self.assertTrue(any("not declared signed" in problem for problem in problems))

    def test_missing_metadata_document_is_refused_not_defaulted(self) -> None:
        """Mutation: treat an absent document as an empty one that passes.

        The absence of evidence is itself a refusal. Every other reading makes
        a gate pass precisely when it has nothing to check.
        """
        problems = release_gate.check_update_metadata(
            {"update_metadata": [{"channel": "stable", "path": "/nonexistent.json"}]}
        )

        self.assertTrue(any("missing or unparseable" in problem for problem in problems))

    def test_a_release_declaring_no_update_metadata_is_refused(self) -> None:
        """Mutation: return `[]` when no metadata is declared."""
        self.assertTrue(release_gate.check_update_metadata({}))

    # --- licensing_integration_verified ---------------------------------

    def test_a_licensing_contract_with_no_plans_is_refused(self) -> None:
        """Mutation: accept a contract that gates nothing."""
        contract = self.write("contract.json", json.dumps({"plans": []}))
        release = {"licensing_contract": {"path": str(contract)}}

        problems = release_gate.check_licensing_integration(release)

        self.assertTrue(problems)

    def test_a_release_naming_no_licensing_contract_is_refused(self) -> None:
        """Mutation: return `[]` when no contract is named."""
        self.assertTrue(release_gate.check_licensing_integration({}))

    def test_a_missing_licensing_contract_document_is_refused(self) -> None:
        """Mutation: return `[]` when the named contract is not on disk.

        Distinct from the two tests above, and it exists because the mutation
        harness reported this one as SURVIVED. Running it by hand confirmed the
        behaviour really did change — a missing contract went from refused to
        silently accepted — which meant the suite had no test covering this
        path at all, not that the mutation was equivalent.

        The report claims a gate is green while having read nothing, which is
        the specific failure this tool exists to prevent.
        """
        problems = release_gate.check_licensing_integration(
            {"licensing_contract": {"path": "/nonexistent/contract.json"}}
        )

        self.assertTrue(any("missing or unparseable" in problem for problem in problems))

    # --- security_gate_pass ----------------------------------------------

    def test_a_non_green_security_check_fails_the_gate(self) -> None:
        """Mutation: check only that `security_checks` is non-empty."""
        release = {"security_checks": [{"name": "cargo-deny", "status": "red"}]}

        problems = release_gate.check_security_gate(release)

        self.assertTrue(any("is 'red'" in problem for problem in problems))

    def test_an_empty_security_check_set_is_refused(self) -> None:
        """Mutation: return `[]` when no checks are reported.

        This is the check that cannot be quietly removed. An empty set of
        security checks passes "every check is green" vacuously, so a release
        that ran nothing at all would certify itself. This is the same shape as
        the empty-artifacts hole, and it is the most likely one to be written
        by accident.
        """
        self.assertTrue(release_gate.check_security_gate({}))
        self.assertTrue(release_gate.check_security_gate({"security_checks": []}))

    # --- performance_gate_pass (delegation) ------------------------------

    def test_a_missing_performance_matrix_is_refused(self) -> None:
        """Mutation: skip the performance gate when no matrix is supplied.

        M13's rules are what make a published number honest; skipping them
        because there is nothing to apply them to is the exact inversion.
        """
        problems = release_gate.check_performance_gate(
            {"performance_matrix_root": "nonexistent-matrix"}
        )

        self.assertTrue(any("no performance matrix" in problem for problem in problems))

    def test_a_matrix_that_m13_refuses_fails_the_performance_gate(self) -> None:
        """Mutation: swallow M13's refusal.

        The delegation is the part of this gate most likely to break quietly. A
        `try/except SystemExit: pass` around a refusal looks defensive, reads
        as error handling, and converts "the matrix is inadmissible" into "the
        gate passed" — which is the exact inversion, arriving through the most
        innocuous-looking code in the file.

        The matrix here is a real directory with an empty ledger, which is
        precisely what M13 refuses and nothing else would.
        """
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty, True)
        (empty / "ledger.jsonl").write_text("", encoding="utf-8")

        problems = release_gate.check_performance_gate(
            {"performance_matrix_root": str(empty)}
        )

        self.assertTrue(
            any("refused by M13" in problem for problem in problems),
            f"an inadmissible matrix must fail the gate, got {problems}",
        )

    # --- the report as a whole -------------------------------------------

    def test_a_release_is_never_admissible_while_a_signoff_is_outstanding(self) -> None:
        """Mutation: count a `requires_signoff` gate as satisfied.

        This is the most consequential mutation in the file. A signoff gate
        that the tool can satisfy on its own is not a signoff gate — it is a
        gate that rubber-stamps its own most important requirement, and the
        milestone it guards (commercial release) is the one where that matters
        most.

        Isolated onto a gate set with **no problems at all**, and one signoff
        gate among otherwise-checkable automatic gates. The first version used
        the full M14 gate list against a fixture that had no performance
        matrix, so `admissible` was already `False` for an unrelated reason —
        the test could not tell a signoff from a missing matrix, and the
        mutation `admissible = not problems` passed it.
        """
        gates = [
            "signed_release_artifacts",
            "update_metadata_verified",
            "licensing_integration_verified",
            "security_gate_pass",
            "legal_and_codec_license_review_complete",
        ]
        with unittest.mock.patch.dict(
            release_gate.GATES,
            {gate: release_gate.GATES[gate] for gate in gates},
            clear=True,
        ):
            report = release_gate.evaluate(self.a_complete_release(), gates)

        # The automatic gates are all green — otherwise this proves nothing.
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["signoffs_pending"], ["legal_and_codec_license_review_complete"])
        self.assertFalse(report["admissible"])

    def test_a_signoff_gate_is_never_marked_satisfied_by_the_tool(self) -> None:
        """Mutation: drop `satisfied_by_tool` from the signoff report."""
        report = release_gate.evaluate(self.a_complete_release(), M14_GATES)
        gate = report["gates"]["legal_and_codec_license_review_complete"]

        self.assertFalse(gate["satisfied_by_tool"])
        self.assertEqual(gate["status"], "requires_signoff")

    def test_an_unenforced_gate_makes_the_whole_report_inadmissible(self) -> None:
        """Mutation: report gate-coverage problems without failing the release.

        Isolated on purpose. With the full M14 gate list, `admissible` is
        already `False` because two signoffs are pending, so the assertion
        would pass whether or not the coverage problems were counted — the test
        could not tell the two behaviours apart, and would keep passing against
        exactly this mutation.

        `GATES` is narrowed to match the subset so the fixture is internally
        consistent. Left unpatched, `gate_coverage`'s reverse check correctly
        reports the omitted gates as no-longer-M14-gates, which would bury the
        one problem this test is about.
        """
        subset = [
            "signed_release_artifacts",
            "update_metadata_verified",
            "licensing_integration_verified",
            "security_gate_pass",
        ]
        with unittest.mock.patch.dict(
            release_gate.GATES,
            {gate: release_gate.GATES[gate] for gate in subset},
            clear=True,
        ):
            report = release_gate.evaluate(
                self.a_complete_release(), subset + ["unnoticed_gate"]
            )

        # The gate itself must be reported, and it must be the *only* problem:
        # anything else here would mean the assertion below proves nothing.
        self.assertEqual(report["gates"]["unnoticed_gate"], "unchecked")
        self.assertEqual(len(report["problems"]), 1, report["problems"])
        self.assertIn("unnoticed_gate", report["problems"][0])
        self.assertEqual(report["signoffs_pending"], [])
        self.assertFalse(report["admissible"])

    def test_a_release_over_only_checkable_gates_is_admissible(self) -> None:
        """The complement of the test above.

        Without this, "coverage problems are counted" and "the report is never
        admissible" would both be satisfied by a tool that refuses everything —
        and a mutation making `admissible` permanently `False` would pass every
        other test in this file.
        """
        subset = [
            "signed_release_artifacts",
            "update_metadata_verified",
            "licensing_integration_verified",
            "security_gate_pass",
        ]
        with unittest.mock.patch.dict(
            release_gate.GATES,
            {gate: release_gate.GATES[gate] for gate in subset},
            clear=True,
        ):
            report = release_gate.evaluate(self.a_complete_release(), subset)

        self.assertEqual(report["problems"], [])
        self.assertTrue(report["admissible"])

    def test_a_release_report_carries_every_roadmap_gate(self) -> None:
        """Mutation: report only the gates that happened to pass.

        A report that omits a refused gate reads, to anything scanning it
        quickly, like a report in which that gate did not exist.
        """
        report = release_gate.evaluate(self.a_complete_release(), M14_GATES)

        for gate in M14_GATES:
            self.assertIn(gate, report["gates"], f"{gate} missing from the report")

    def test_one_missing_document_does_not_hide_the_other_gates(self) -> None:
        """Mutation: raise on a missing manifest instead of returning a refusal.

        The first version raised `SystemExit` from `load_json`. One absent
        metadata file then aborted the entire report, so a release with a
        broken metadata document and, say, an unsigned artifact produced *no*
        report at all — the artifact problem became invisible rather than
        refused. Each gate has to fail on its own so the others still report.
        """
        release = self.a_complete_release()
        release["update_metadata"] = [
            {"channel": "stable", "path": "/nonexistent/stable.json"}
        ]
        # Break a second, unrelated gate so its status is distinguishable.
        release["artifacts"][0].pop("signature_declared")

        report = release_gate.evaluate(release, M14_GATES)

        self.assertEqual(
            report["gates"]["update_metadata_verified"]["status"], "refused"
        )
        self.assertEqual(report["gates"]["signed_release_artifacts"]["status"], "refused")
        self.assertFalse(report["admissible"])


class CommandLineTests(ReleaseFixture):
    def test_the_cli_exits_nonzero_on_an_incomplete_release(self) -> None:
        """Mutation: always exit 0, printing the report regardless.

        A release tool that exits 0 while refusing is a release tool nobody
        has to read, which is the same as no tool.
        """
        release = self.a_complete_release()
        release["security_checks"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            path.write_text(json.dumps(release), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "release_gate.py"),
                    "--release",
                    str(path),
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_roadmap_gate_list_is_read_from_the_roadmap(self) -> None:
        """Mutation: hard-code the gate list in the tool.

        The point of the gate-coverage check is defeated if the list is copied
        into the tool, because adding a gate to ROADMAP.yaml would then go
        unnoticed. Reading it back is what makes drift detectable.
        """
        roadmap_gates = release_gate.m14_gates_from_roadmap(REPO_ROOT / "ROADMAP.yaml")

        self.assertEqual(sorted(roadmap_gates), sorted(M14_GATES))

    def test_the_roadmap_gate_list_is_not_hardcoded_to_pass_vacously(self) -> None:
        """Mutation: return an empty list when parsing fails.

        An empty gate list makes every check vacuously satisfied and every
        report empty — both look like success. A parser that cannot find M14
        must fail loudly.
        """
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "ROADMAP.yaml"
            empty.write_text("milestones: []\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                release_gate.m14_gates_from_roadmap(empty)


if __name__ == "__main__":
    unittest.main(verbosity=2)