#!/usr/bin/env python3
"""Tests for the M5 relay-evidence tool.

Every test names the single edit that would let the gate pass while it is
broken. A test that cannot be made to fail by one edit is not pinning the
behaviour it claims to.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "m5_evidence", ROOT / "scripts" / "m5_evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m5 = load_tool()

EXIT = "forced_direct_failure_falls_back_to_relay"
CONF = "end_to_end_confidentiality_preserved"
UTIL = "relay_utilization_measured"
DECRYPT = "relay_cannot_decrypt_session_payload"
CONTROL = "relay_cannot_grant_control_permission"
FAILCLOSED = "authorization_failure_is_fail_closed"

ROADMAP = """milestones:
  - id: M5
    name: Encrypted relay fallback
    status: pending
    exit_criteria:
      - {exit}
      - {conf}
      - {util}
    security_gates:
      - {decrypt}
      - {control}
      - {failclosed}
  - id: M6
    exit_criteria:
      - something_else
""".format(exit=EXIT, conf=CONF, util=UTIL, decrypt=DECRYPT, control=CONTROL, failclosed=FAILCLOSED)


class Fixture(unittest.TestCase):
    """An evidence tree that outlives the call that built it.

    The M14 suite's first version built its files inside a
    `TemporaryDirectory` and returned from inside the block, so the directory
    was cleaned up before any check ran and six tests errored on missing files
    while three passed for the wrong reason. A fixture whose lifetime is
    shorter than its own tests is a fixture that tests nothing.
    """

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "evidence"
        (self.root / "raw").mkdir(parents=True)
        self.roadmap = Path(self.directory.name) / "ROADMAP.yaml"
        self.roadmap.write_text(ROADMAP, encoding="utf-8")
        (self.root / "ledger.jsonl").write_text("", encoding="utf-8")

    def raw(self, name: str, content: str = '{"observed": true}') -> str:
        path = self.root / "raw" / f"{name}.json"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def entry(self, run_id: str, **overrides) -> dict:
        import hashlib

        content = overrides.pop("content", '{"observed": true}')
        path = self.root / "raw" / f"{run_id}.json"
        path.write_text(content, encoding="utf-8")
        entry = {
            "run_id": run_id,
            "recorded_at": "2026-01-01T00:00:00Z",
            "raw_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "raw_bytes": len(content),
            "raw_path": f"{run_id}.json",
            "environment": {"machine_id": "m1", "os_build": "linux", "commit": "abc123"},
        }
        entry.update(overrides)
        return entry

    def append(self, *entries: dict) -> None:
        with (self.root / "ledger.jsonl").open("a", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def code_run(self, run_id: str = "M5-CODE-R001", **overrides) -> dict:
        entry = self.entry(
            run_id,
            evidence_class="code_observed",
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            gates_observed=[DECRYPT, CONTROL],
        )
        entry.update(overrides)
        return entry

    def transport_run(self, run_id: str = "M5-TRANS-R001", **overrides) -> dict:
        entry = self.entry(
            run_id,
            evidence_class="transport_observed",
            relay_endpoint="relay.example:4433",
            client_endpoint="10.0.0.1:9000",
            server_endpoint="10.0.0.2:9000",
            gates_observed=[CONF, UTIL, DECRYPT, CONTROL],
        )
        entry.update(overrides)
        return entry

    def report(self) -> dict:
        return m5.evaluate(self.root, self.roadmap)


class TestRoadmapParsing(Fixture):
    """Mutation: return a hardcoded list instead of reading the roadmap."""

    def test_the_exit_criteria_are_read_from_the_roadmap(self) -> None:
        criteria, gates = m5.m5_sections_from_roadmap(self.roadmap)
        self.assertEqual(criteria, [EXIT, CONF, UTIL])
        self.assertEqual(gates, [DECRYPT, CONTROL, FAILCLOSED])

    def test_the_next_milestones_list_is_not_mistaken_for_this_ones(self) -> None:
        # `something_else` belongs to M6. Reading past M5's block would make a
        # criterion appear that no checker exists for.
        criteria, gates = m5.m5_sections_from_roadmap(self.roadmap)
        self.assertNotIn("something_else", criteria)
        self.assertNotIn("something_else", gates)

    def test_a_roadmap_without_m5_is_refused_rather_than_read_as_empty(self) -> None:
        """Mutation: return empty lists when the milestone is not found."""
        path = Path(self.directory.name) / "empty.yaml"
        path.write_text("milestones:\n  - id: M6\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            m5.m5_sections_from_roadmap(path)


class TestGateCoverage(Fixture):
    """The rule that stops M5 regrowing the hole it was born with."""

    # Both directions must be pinned independently, and each test names only
    # the gate it is about. The first version of these tests added an unknown
    # gate to the forward direction while the reverse direction also fired
    # (the unknown gate is trivially "not in EXIT_CRITERIA", so the reverse
    # check reported it too), which meant both mutations that disabled the
    # forward check still passed -- the assertion was satisfied by a
    # different check reporting the same name.
    #
    # Each test below therefore asserts on a *specific* message fragment that
    # only its own direction can produce.

    def test_an_unenforced_exit_criterion_is_a_problem(self) -> None:
        """Mutation: `if False: problems.append(...)` in the criteria loop."""
        problems = m5.check_gate_coverage([EXIT, CONF, UTIL, "a_new_criterion"], [DECRYPT, CONTROL, FAILCLOSED])
        forward = [
            problem
            for problem in problems
            if "a_new_criterion" in problem and "has no check" in problem
        ]
        self.assertTrue(
            forward,
            f"the forward direction must report the unenforced criterion; got {problems}",
        )

    def test_an_unenforced_security_gate_is_a_problem(self) -> None:
        """Mutation: `if False: problems.append(...)` in the gate loop."""
        problems = m5.check_gate_coverage([EXIT, CONF, UTIL], [DECRYPT, CONTROL, FAILCLOSED, "a_new_gate"])
        forward = [
            problem
            for problem in problems
            if "a_new_gate" in problem and "has no check" in problem
        ]
        self.assertTrue(
            forward,
            f"the forward direction must report the unenforced gate; got {problems}",
        )

    def test_a_criterion_dropped_from_the_roadmap_leaves_a_stray_checker(self) -> None:
        """Mutation: drop the reverse direction of the coverage check.

        This is the direction that catches a *removal*. Deleting a security
        gate from ROADMAP.yaml is one line; without this, the checker for it
        would simply go on running, uninvoked, and the gate would be gone.
        """
        problems = m5.check_gate_coverage([EXIT, CONF], [DECRYPT, CONTROL, FAILCLOSED])
        self.assertTrue(any(UTIL in problem and "no longer declares" in problem for problem in problems))

    def test_a_gate_dropped_from_the_roadmap_leaves_a_stray_checker(self) -> None:
        """Mutation: drop the reverse direction of the coverage check."""
        problems = m5.check_gate_coverage([EXIT, CONF, UTIL], [DECRYPT, CONTROL])
        self.assertTrue(any(FAILCLOSED in problem and "no longer declares" in problem for problem in problems))

    def test_the_real_roadmap_has_full_coverage(self) -> None:
        """Mutation: any false positive in the coverage check."""
        criteria, gates = m5.m5_sections_from_roadmap(ROOT / "ROADMAP.yaml")
        self.assertEqual(m5.check_gate_coverage(criteria, gates), [])

    def test_coverage_problems_are_surfaced_in_the_report(self) -> None:
        """Mutation: `problems: list[str] = list(check_gate_coverage(...))` -> `[]`."""
        self.roadmap.write_text(
            ROADMAP.replace(f"      - {UTIL}\n", ""), encoding="utf-8"
        )
        report = self.report()
        self.assertFalse(report["m5_satisfied"])
        self.assertTrue(any("no longer declares" in problem for problem in report["problems"]))


class TestNoRunsRecorded(Fixture):
    def test_an_empty_ledger_refuses(self) -> None:
        """Mutation: drop the `if not entries` problem."""
        report = self.report()
        self.assertFalse(report["m5_satisfied"])
        self.assertTrue(any("no runs recorded" in problem for problem in report["problems"]))

    def test_an_empty_ledger_marks_every_gate_unmet(self) -> None:
        self.assertEqual(len(self.report()["unmet"]), 6)


class TestEvidenceClassDiscipline(Fixture):
    """The property that keeps a cheap observation from standing in for an expensive one."""

    def test_a_code_run_cannot_satisfy_an_exit_criterion(self) -> None:
        """Mutation: drop the `evidence_class not in admitted` refusal.

        This is the central claim of the tool. M5's exit criteria need a real
        relay on a real network; if `code_observed` could satisfy them, the
        exit criteria would be satisfiable by running `cargo test`, which is
        exactly the equivalence the tool exists to prevent.
        """
        run = self.code_run(gates_observed=[EXIT, CONF, UTIL])
        self.append(run)
        report = self.report()
        for criterion in (EXIT, CONF, UTIL):
            self.assertEqual(report["gates"][criterion]["status"], "unmet")
            self.assertTrue(
                any(
                    "does not establish this gate" in problem
                    for problem in report["problems"]
                ),
                f"{criterion} should refuse a code_observed run",
            )

    def test_a_code_run_can_satisfy_the_interface_security_gates(self) -> None:
        """The complement: the tool must not be vacuously refusing everything."""
        self.append(self.code_run())
        report = self.report()
        self.assertEqual(report["gates"][DECRYPT]["status"], "observed")
        self.assertEqual(report["gates"][CONTROL]["status"], "observed")

    def test_a_forced_link_run_cannot_establish_confidentiality(self) -> None:
        """Mutation: widen CRITERIA_EVIDENCE[CONF] to admit link_forced_observed.

        A shaped link says nothing about what the relay could read, so the two
        criteria answer different questions and must not share a class list.
        """
        run = self.entry(
            "M5-FORCED-R001",
            evidence_class="link_forced_observed",
            relay_endpoint="relay.example:4433",
            client_endpoint="10.0.0.1:9000",
            server_endpoint="10.0.0.2:9000",
            impairment={"method": "iptables DROP", "applied_before_session": True},
            gates_observed=[CONF],
        )
        self.append(run)
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")

    def test_a_transport_run_does_establish_confidentiality_and_utilization(self) -> None:
        self.append(self.transport_run())
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "observed")
        self.assertEqual(report["gates"][UTIL]["status"], "observed")

    def test_an_unknown_evidence_class_is_refused(self) -> None:
        """Mutation: drop the `evidence_class not in EVIDENCE_CLASSES` check."""
        self.append(self.entry("M5-FAKE-R001", evidence_class="believed", gates_observed=[CONF]))
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")
        self.assertTrue(any("unknown evidence class" in problem for problem in report["problems"]))


class TestEvidenceIntegrity(Fixture):
    def test_a_deleted_raw_observation_fails_its_gate(self) -> None:
        """Mutation: drop the `if not path.is_file()` refusal."""
        entry = self.transport_run()
        self.append(entry)
        (self.root / "raw" / "M5-TRANS-R001.json").unlink()
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")
        self.assertTrue(any("is gone" in problem for problem in report["problems"]))

    def test_a_tampered_raw_observation_fails_its_gate(self) -> None:
        """Mutation: drop the `actual != digest` refusal, or truncate it.

        The mutation here shares its first twelve characters with the real
        digest, so a truncated comparison accepts it and only a full one
        refuses. An all-zeros forgery would fail both and would prove nothing.
        """
        entry = self.transport_run()
        self.append(entry)
        real = entry["raw_sha256"]
        entry["raw_sha256"] = real[:12] + "0" * 52
        self.root.joinpath("ledger.jsonl").write_text(
            json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8"
        )
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")
        self.assertTrue(any("no longer hashes" in problem for problem in report["problems"]))

    def test_a_run_with_no_digest_is_refused(self) -> None:
        """Mutation: drop the `if not digest` refusal."""
        entry = self.transport_run()
        del entry["raw_sha256"]
        self.append(entry)
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")

    def test_a_code_run_must_name_the_test_binary_it_ran(self) -> None:
        """Mutation: drop the CODE_EVIDENCE_REQUIRED_PROBE requirement.

        Without this, `code_observed` is a label anyone can attach to any
        file, and the class stops constraining anything.
        """
        self.append(self.entry("M5-CODE-R001", evidence_class="code_observed", gates_observed=[DECRYPT]))
        report = self.report()
        self.assertEqual(report["gates"][DECRYPT]["status"], "unmet")
        self.assertTrue(any("test_binary" in problem for problem in report["problems"]))

    def test_a_transport_run_must_name_its_endpoints(self) -> None:
        """Mutation: drop the `relay_endpoint` check for transport runs."""
        self.append(
            self.entry(
                "M5-TRANS-R001",
                evidence_class="transport_observed",
                gates_observed=[CONF],
            )
        )
        report = self.report()
        self.assertEqual(report["gates"][CONF]["status"], "unmet")
        self.assertTrue(any("relay_endpoint" in problem for problem in report["problems"]))

    def test_a_forced_link_run_must_record_how_the_link_was_broken(self) -> None:
        """Mutation: drop the `impairment.method` requirement.

        `forced_direct_failure_falls_back_to_relay` is the criterion most
        easily faked -- an impairment applied *after* the session establishes
        proves nothing about fallback. Hence `applied_before_session`.
        """
        self.append(
            self.entry(
                "M5-FORCED-R001",
                evidence_class="link_forced_observed",
                relay_endpoint="relay.example:4433",
                client_endpoint="10.0.0.1:9000",
                server_endpoint="10.0.0.2:9000",
                impairment={"method": "iptables DROP", "applied_before_session": False},
                gates_observed=[EXIT],
            )
        )
        report = self.report()
        self.assertEqual(report["gates"][EXIT]["status"], "unmet")

    def test_an_impairment_missing_entirely_is_refused(self) -> None:
        self.append(
            self.entry(
                "M5-FORCED-R001",
                evidence_class="link_forced_observed",
                relay_endpoint="relay.example:4433",
                client_endpoint="10.0.0.1:9000",
                server_endpoint="10.0.0.2:9000",
                gates_observed=[EXIT],
            )
        )
        report = self.report()
        self.assertEqual(report["gates"][EXIT]["status"], "unmet")

    def test_a_link_forced_run_cannot_satisfy_a_security_gate_without_endpoints(self) -> None:
        self.append(
            self.entry(
                "M5-FORCED-R001",
                evidence_class="link_forced_observed",
                impairment={"method": "x", "applied_before_session": True},
                gates_observed=[DECRYPT],
            )
        )
        report = self.report()
        self.assertEqual(report["gates"][DECRYPT]["status"], "unmet")


class TestFailClosed(Fixture):
    """The gate that must not pass on absence."""

    def test_a_report_with_no_unauthorized_attempt_refuses(self) -> None:
        """Mutation: `if not attempts: return []`.

        This is the mutation the whole check exists for. A relay that was
        never asked to authorize anything has not failed closed; it has
        simply never been asked, and returning clean here is how a report
        would claim the property on no evidence at all.
        """
        self.append(self.code_run())
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "unmet")
        self.assertTrue(
            any("no run recorded an unauthorized attempt" in problem for problem in report["problems"])
        )

    def test_a_forwarded_unauthorized_attempt_is_reported_as_a_failure(self) -> None:
        """Mutation: accept `outcome == 'forwarded'`."""
        run = self.code_run(
            unauthorized_attempted=True,
            unauthorized_outcome="forwarded",
        )
        self.append(run)
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "unmet")
        self.assertTrue(any("rather than refused" in problem for problem in report["problems"]))

    def test_a_refused_unauthorized_attempt_satisfies_the_gate(self) -> None:
        """The complement: without it, `return []` would also pass."""
        run = self.code_run(
            gates_observed=[DECRYPT, CONTROL, FAILCLOSED],
            unauthorized_attempted=True,
            unauthorized_outcome="refused",
        )
        self.append(run)
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "observed")

    def test_an_attempt_recording_no_outcome_is_refused(self) -> None:
        """Mutation: treat a missing outcome as a refusal."""
        self.append(self.code_run(unauthorized_attempted=True))
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "unmet")
        self.assertTrue(any("records no outcome" in problem for problem in report["problems"]))

    def test_a_refusal_on_a_tampered_run_does_not_satisfy_the_gate(self) -> None:
        """Mutation: `if integrity or class_errors:` -> `if False:`.

        A run whose observation no longer hashes to what was recorded has
        nothing behind it, so its claim that the relay refused is a claim
        about a file that may since have been replaced. Counting it is how
        this gate would go green on an unbacked assertion -- which is the
        exact shape of defect the tool exists to refuse, appearing inside the
        tool.

        This test was missing rather than wrong: the behaviour was already
        correct, and the mutation survived because nothing exercised it.
        """
        run = self.code_run(
            gates_observed=[DECRYPT, CONTROL, FAILCLOSED],
            unauthorized_attempted=True,
            unauthorized_outcome="refused",
        )
        run["raw_sha256"] = "0" * 64
        self.append(run)
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "unmet")
        self.assertTrue(any("no recorded unauthorized attempt was refused" in problem for problem in report["problems"]))

    def test_an_unauthorized_flag_left_false_does_not_count_as_an_attempt(self) -> None:
        """Mutation: count `unauthorized_outcome` without `unauthorized_attempted`.

        A run that records `unauthorized_attempted: false` alongside a
        `refused` outcome would otherwise satisfy the gate while stating that
        no attempt was made.
        """
        self.append(
            self.code_run(unauthorized_attempted=False, unauthorized_outcome="refused")
        )
        report = self.report()
        self.assertEqual(report["gates"][FAILCLOSED]["status"], "unmet")


class TestReportShape(Fixture):
    def test_a_run_observing_no_gates_is_refused(self) -> None:
        """Mutation: drop the `if not candidates` refusal.

        Without it, every gate would read as satisfied by the mere existence
        of a ledger -- an empty set is not a pass.
        """
        self.append(self.code_run(gates_observed=[]))
        report = self.report()
        self.assertEqual(len(report["unmet"]), 6)

    def test_the_report_is_never_labelled_satisfied_while_a_gate_is_unmet(self) -> None:
        """Mutation: `m5_satisfied` computed from something other than problems."""
        self.append(self.code_run())
        report = self.report()
        self.assertTrue(report["unmet"])
        self.assertFalse(report["m5_satisfied"])

    def test_a_run_observing_every_gate_with_admissible_evidence_satisfies_the_report(self) -> None:
        """The complement, and the reason the complement matters.

        Without it, a tool that refused every report forever would pass every
        other test in this file -- including the two above.
        """
        self.append(
            self.transport_run(
                unauthorized_attempted=True,
                unauthorized_outcome="refused",
                gates_observed=[CONF, UTIL, DECRYPT, CONTROL, FAILCLOSED],
            ),
            self.entry(
                "M5-FORCED-R001",
                evidence_class="link_forced_observed",
                relay_endpoint="relay.example:4433",
                client_endpoint="10.0.0.1:9000",
                server_endpoint="10.0.0.2:9000",
                impairment={"method": "iptables DROP", "applied_before_session": True},
                gates_observed=[EXIT],
            ),
        )
        report = self.report()
        self.assertEqual(report["unmet"], [])
        self.assertTrue(report["m5_satisfied"], report["problems"])

    def test_every_declared_gate_appears_in_the_report(self) -> None:
        """Mutation: omit a gate from the report's `gates` dict."""
        report = self.report()
        for name in m5.EXIT_CRITERIA + m5.SECURITY_GATES:
            self.assertIn(name, report["gates"])

    def test_a_gate_that_m14_also_names_is_not_reused(self) -> None:
        """M5's gates and M14's `security_gate_pass` are different things.

        A checker that treated one as the other would let M14's green release
        review stand in for an observed relay run.
        """
        self.assertNotIn("security_gate_pass", m5.SECURITY_GATES)
        self.assertNotIn("security_gate_pass", m5.EXIT_CRITERIA)


class TestRecording(Fixture):
    def test_a_duplicate_run_id_is_refused(self) -> None:
        """Mutation: drop the duplicate-run_id refusal."""
        import argparse

        run = self.code_run()
        self.append(run)
        args = argparse.Namespace(
            root=str(self.root),
            run_id="M5-CODE-R001",
            evidence_class="code_observed",
            raw=self.raw("obs"),
            gate=[DECRYPT],
            environment=None,
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            relay_endpoint=None,
            client_endpoint=None,
            server_endpoint=None,
            impairment=None,
            unauthorized_attempted=None,
            unauthorized_outcome=None,
        )
        with self.assertRaises(SystemExit):
            m5.command_record(args)

    def test_recording_a_gate_m5_does_not_declare_is_refused(self) -> None:
        """Mutation: drop the `unknown` gate refusal."""
        import argparse

        args = argparse.Namespace(
            root=str(self.root),
            run_id="M5-NEW-R001",
            evidence_class="code_observed",
            raw=self.raw("obs"),
            gate=["a_gate_from_nowhere"],
            environment=None,
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            relay_endpoint=None,
            client_endpoint=None,
            server_endpoint=None,
            impairment=None,
            unauthorized_attempted=None,
            unauthorized_outcome=None,
        )
        with self.assertRaises(SystemExit):
            m5.command_record(args)

    def test_an_unknown_evidence_class_is_refused_at_record_time(self) -> None:
        """Mutation: drop the EVIDENCE_CLASSES check in command_record."""
        import argparse

        args = argparse.Namespace(
            root=str(self.root),
            run_id="M5-NEW-R001",
            evidence_class="believed",
            raw=self.raw("obs"),
            gate=[DECRYPT],
            environment=None,
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            relay_endpoint=None,
            client_endpoint=None,
            server_endpoint=None,
            impairment=None,
            unauthorized_attempted=None,
            unauthorized_outcome=None,
        )
        with self.assertRaises(SystemExit):
            m5.command_record(args)

    def test_an_invalid_run_id_is_refused(self) -> None:
        """Mutation: drop `validate_run_id` from command_record."""
        self.assertIsNone(m5.RUN_ID.fullmatch("not-a-run-id"))
        self.assertIsNotNone(m5.RUN_ID.fullmatch("M5-CODE-R001"))

    def test_recording_with_an_invalid_run_id_raises(self) -> None:
        """Mutation: `run_id = validate_run_id(args.run_id)` -> `run_id = args.run_id`.

        The test above only proves the *regex* rejects a bad id. That is not
        the same as proving `record` calls it -- removing the call leaves the
        regex test green while a malformed id walks straight into the ledger,
        where `gate_runs` will later match it against a real gate name. So the
        call is exercised here, not just the pattern it calls.

        This was a missing test rather than a broken tool: the mutation
        survived because nothing ran `record` with a bad id.
        """
        import argparse

        args = argparse.Namespace(
            root=str(self.root),
            run_id="not-a-run-id",
            evidence_class="code_observed",
            raw=self.raw("obs"),
            gate=[DECRYPT],
            environment=None,
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            relay_endpoint=None,
            client_endpoint=None,
            server_endpoint=None,
            impairment=None,
            unauthorized_attempted=None,
            unauthorized_outcome=None,
        )
        with self.assertRaises(SystemExit):
            m5.command_record(args)
        self.assertEqual(m5.read_ledger(self.root), [])

    def test_the_recorded_run_is_readable_by_verify(self) -> None:
        """Mutation: write a ledger entry `verify` cannot re-read.

        The two commands are only meaningful together: `record` proves an
        observation happened, `verify` decides whether it counts. If the entry
        written here were missing the hash, verify would refuse its own output.
        """
        import argparse

        args = argparse.Namespace(
            root=str(self.root),
            run_id="M5-CODE-R001",
            evidence_class="code_observed",
            raw=self.raw("obs"),
            gate=[DECRYPT, CONTROL],
            environment=None,
            test_binary=m5.CODE_EVIDENCE_REQUIRED_PROBE,
            relay_endpoint=None,
            client_endpoint=None,
            server_endpoint=None,
            impairment=None,
            unauthorized_attempted=None,
            unauthorized_outcome="refused",
        )
        args.unauthorized_attempted = True
        m5.command_record(args)
        entries = m5.read_ledger(self.root)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["evidence_class"], "code_observed")
        self.assertIn("raw_sha256", entries[0])
        self.assertIsNone(m5.entry_class_errors(entries[0], "M5-CODE-R001"))


if __name__ == "__main__":
    unittest.main()
