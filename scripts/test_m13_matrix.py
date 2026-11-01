#!/usr/bin/env python3
"""M13 performance-matrix admissibility tests.

Each test names the single edit that would make it pass while the property is
broken, because a validator that cannot be shown to catch its own failure is
not evidence of anything.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("m13_matrix.py")

FULL_METRICS = {
    "interactive_latency_ms": 42.0,
    "connection_time_ms": 193.0,
    "reconnect_time_ms": 59.0,
    "bandwidth_kbps": 18432.0,
    "cpu_percent": 6.2,
    "gpu_percent": 0.0,
    "ram_mb": 41.5,
    "direct_connect_success_rate": 100.0,
    "relay_ratio": 0.0,
    "visual_quality_metric": 0.93,
}

ENVIRONMENT = {
    "machine_id": "bench-01",
    "os_build": "windows-10-0.19045",
    "commit": "78f3abd",
    "profile": "office_good",
}


class MatrixToolTests(unittest.TestCase):
    def run_tool(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(result.stdout or result.stderr)
        return result

    def output(self, result) -> str:
        """Both channels.

        A refusal exits via `SystemExit`, so its message lands on stderr, while
        `verify`'s per-problem lines are printed to stdout. A test asserting on
        only one of them passes or fails for reasons unrelated to the property.
        """
        return result.stdout + result.stderr

    def make_run(self, root: Path, run_id: str, **overrides):
        """Write a raw file, environment, and metrics, then record the run."""
        raw = root / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        samples = root / f"{run_id}.samples.jsonl"
        samples.write_text(
            "".join(json.dumps({"i": i, "latency_ms": 40 + i}) + "\n" for i in range(5)),
            encoding="utf-8",
        )

        environment = dict(ENVIRONMENT)
        environment.update(overrides.pop("environment", {}))
        metrics = dict(FULL_METRICS)
        metrics.update(overrides.pop("metrics", {}))

        env_path = root / f"{run_id}.env.json"
        env_path.write_text(json.dumps(environment), encoding="utf-8")
        metrics_path = root / f"{run_id}.metrics.json"
        metrics_path.write_text(json.dumps(metrics), encoding="utf-8")

        # The tool reads --raw by absolute path but stores only the basename,
        # and verify re-reads it from <root>/raw. Keep both honest by copying.
        stored = raw / samples.name
        stored.write_text(samples.read_text(encoding="utf-8"), encoding="utf-8")

        self.run_tool(
            "record",
            "--root", str(root),
            "--run-id", run_id,
            "--raw", str(stored),
            "--environment", str(env_path),
            "--metrics", str(metrics_path),
            **overrides,
        )

    def init_ledger(self, root: Path):
        self.run_tool("init", "--root", str(root))

    # --- the four declared rules ------------------------------------------

    def test_a_complete_honest_matrix_verifies(self):
        """Mutation: none -- this is the positive control every other test
        is measured against. If this fails, the failures elsewhere mean
        nothing."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            result = self.run_tool("verify", "--root", str(root))
            self.assertIn('"m13_matrix": "PASS"', result.stdout)

    def test_a_missing_metric_is_refused(self):
        """Mutation: delete `missing_metrics()` from `command_verify`."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001", metrics={"ram_mb": None})
            ledger = root / "ledger.jsonl"
            lines = ledger.read_text(encoding="utf-8").splitlines()
            entry = json.loads(lines[0])
            del entry["metrics"]["gpu_percent"]
            ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gpu_percent", self.output(result))

    def test_raw_results_are_required(self):
        """Mutation: drop the `raw_path.is_file()` check from `command_verify`."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            (root / "raw" / "M13-office-R001.samples.jsonl").unlink()

            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw_results_required", self.output(result))

    def test_an_edited_raw_file_is_refused(self):
        """Mutation: remove the `actual != raw_sha` comparison.

        This is the one that matters. An unhashed raw file is a summary
        wearing a raw file's name; a *replaced* one is a summary that was
        captured honestly and then improved.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            raw.write_text('{"i": 0, "latency_ms": 3}\n', encoding="utf-8")

            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no longer hashes", self.output(result))

    def test_environment_metadata_is_required(self):
        """Mutation: drop the environment loop from `command_verify`."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            ledger = root / "ledger.jsonl"
            entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
            del entry["environment"]["machine_id"]
            ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")

            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("environment_metadata_required", self.output(result))

    def test_replacing_a_run_under_the_same_name_is_refused(self):
        """Mutation: delete the duplicate-run_id check from `command_record`.

        This is `cherry_picking_forbidden` in the form it actually takes:
        not deleting a run, but replacing it with a better one under a name
        the reviewer has already seen.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            result = self.run_tool(
                "record",
                "--root", str(root),
                "--run-id", "M13-office-R001",
                "--raw", str(root / "raw" / "M13-office-R001.samples.jsonl"),
                "--environment", str(root / "M13-office-R001.env.json"),
                "--metrics", str(root / "M13-office-R001.metrics.json"),
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cherry_picking_forbidden", self.output(result))

    # --- comparative claims ------------------------------------------------

    def test_a_comparison_across_machines_is_refused(self):
        """Mutation: remove the `incomparable` loop from `command_compare`.

        Without this, "47 ms vs 42 ms" reads as a 10% improvement when the
        two numbers came from different hardware entirely.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(
                root, "M13-office-R002", environment={"machine_id": "bench-02"}
            )

            result = self.run_tool(
                "compare",
                "--root", str(root),
                "--baseline", "M13-office-R001",
                "--candidate", "M13-office-R002",
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine_id", self.output(result))

    def test_a_comparison_across_profiles_is_refused(self):
        """Mutation: drop "profile" from COMPARABILITY_FIELDS.

        Comparing `office_good` against `severe` and calling it a regression
        is the single easiest false claim this matrix could produce.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(
                root, "M13-office-R002", environment={"profile": "severe"}
            )

            result = self.run_tool(
                "compare",
                "--root", str(root),
                "--baseline", "M13-office-R001",
                "--candidate", "M13-office-R002",
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("profile", self.output(result))

    def test_a_comparable_comparison_reports_both_sides(self):
        """Mutation: make `command_compare` print only the candidate's numbers.

        A comparison tool that shows one side is an advertising tool.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(
                root, "M13-office-R002", metrics={"interactive_latency_ms": 51.0}
            )

            result = self.run_tool(
                "compare",
                "--root", str(root),
                "--baseline", "M13-office-R001",
                "--candidate", "M13-office-R002",
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["comparable"])
            latency = payload["metrics"]["interactive_latency_ms"]
            self.assertEqual(latency["M13-office-R001"], 42.0)
            self.assertEqual(latency["M13-office-R002"], 51.0)

    # --- input validation --------------------------------------------------

    def test_rejects_an_invalid_run_id(self):
        """Mutation: make `validate_run_id` return its argument."""
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_tool(
                "init", "--root", temp, "--run-id", "not-a-run", ok=False
            )
            self.assertNotEqual(result.returncode, 0)

    def test_verify_refuses_an_empty_matrix(self):
        """Mutation: return `PASS` from `command_verify` when there are no runs.

        An empty matrix is not a matrix. Passing it would let the tool be run
        before any measurement exists and report success.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("nothing to verify", self.output(result))


    def test_raw_path_traversal_refused_even_with_matching_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            ledger = root / "ledger.jsonl"
            entry = json.loads(ledger.read_text(encoding="utf-8"))
            entry["raw_path"] = "../M13-office-R001.samples.jsonl"
            ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe raw filename", self.output(result))

    def test_raw_size_forgery_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            ledger = root / "ledger.jsonl"
            entry = json.loads(ledger.read_text(encoding="utf-8"))
            entry["raw_bytes"] += 1
            ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw_bytes mismatch", self.output(result))

    def test_raw_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            raw.unlink()
            try:
                raw.symlink_to(root / "M13-office-R001.samples.jsonl")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink unavailable: {error}")
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unshared and regular", self.output(result))

    def test_raw_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            try:
                import os
                os.link(raw, root / "shared.jsonl")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"hardlink unavailable: {error}")
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unshared and regular", self.output(result))

    def test_compare_refuses_tampered_raw_and_duplicate_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            args = ("compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            raw.write_text('{"latency_ms": 1}\n', encoding="utf-8")
            result = self.run_tool(*args, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("comparison evidence mismatch", self.output(result))
            ledger = root / "ledger.jsonl"
            lines = ledger.read_text(encoding="utf-8").splitlines()
            ledger.write_text("\n".join(lines + [lines[0]]) + "\n", encoding="utf-8")
            result = self.run_tool(*args, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate run_id", self.output(result))

    def test_record_refuses_external_raw(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            sample = root / "external.jsonl"
            sample.write_text('{"latency_ms": 42}\n', encoding="utf-8")
            environment = root / "env.json"
            environment.write_text(json.dumps(ENVIRONMENT), encoding="utf-8")
            metrics = root / "metrics.json"
            metrics.write_text(json.dumps(FULL_METRICS), encoding="utf-8")
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R001",
                "--raw", str(sample), "--environment", str(environment),
                "--metrics", str(metrics), ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw_results_required", self.output(result))
            self.assertEqual((root / "ledger.jsonl").read_text(), "")



    def test_redirected_ledger_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            ledger = root / "ledger.jsonl"
            outside = root / "other-ledger.jsonl"
            outside.write_text("", encoding="utf-8")
            ledger.unlink()
            try:
                ledger.symlink_to(outside)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink unavailable: {error}")
            result = self.run_tool("verify", "--root", str(root), ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("redirected M13 evidence ledger", self.output(result))




    def test_nonnumeric_or_nonfinite_metrics_refused_by_verify_and_compare(self):
        for value in (None, True, "42", float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001", metrics={"interactive_latency_ms": value})
                self.make_run(root, "M13-office-R002")
                verified = self.run_tool("verify", "--root", str(root), ok=False)
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn("interactive_latency_ms", self.output(verified))
                compared = self.run_tool(
                    "compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002", ok=False,
                )
                self.assertNotEqual(compared.returncode, 0)
                self.assertIn("incomplete metrics", self.output(compared))

    def test_invalid_environment_types_refused_by_verify_and_compare(self):
        for field, value in (("machine_id", 42), ("profile", []), ("os_build", "  ")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001", environment={field: value})
                self.make_run(root, "M13-office-R002")
                verified = self.run_tool("verify", "--root", str(root), ok=False)
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn(field, self.output(verified))
                compared = self.run_tool(
                    "compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002", ok=False,
                )
                self.assertNotEqual(compared.returncode, 0)
                self.assertIn("incomplete environment", self.output(compared))

    def test_self_comparison_is_not_independent_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            result = self.run_tool(
                "compare", "--root", str(root),
                "--baseline", "M13-office-R001",
                "--candidate", "M13-office-R001", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("distinct runs required", self.output(result))


    def test_negative_metric_values_refused_by_verify_and_compare(self):
        # Negative durations, usage, rates and scores cannot be measurements.
        for field in (
            "interactive_latency_ms", "bandwidth_kbps", "cpu_percent",
            "ram_mb", "direct_connect_success_rate", "relay_ratio",
            "visual_quality_metric",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001", metrics={field: -0.5})
                self.make_run(root, "M13-office-R002")
                verified = self.run_tool("verify", "--root", str(root), ok=False)
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn(field, self.output(verified))
                compared = self.run_tool(
                    "compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002", ok=False,
                )
                self.assertNotEqual(compared.returncode, 0)
                self.assertIn("incomplete metrics", self.output(compared))


    def test_impossible_percentage_and_ratio_values_refused(self):
        # Valid finite numbers are still impossible measurements if out of range.
        for field, value in (
            ("cpu_percent", 100.1),
            ("gpu_percent", 101),
            ("direct_connect_success_rate", 101),
            ("relay_ratio", 1.01),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001", metrics={field: value})
                self.make_run(root, "M13-office-R002")
                verified = self.run_tool("verify", "--root", str(root), ok=False)
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn(field, self.output(verified))
                compared = self.run_tool(
                    "compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002", ok=False,
                )
                self.assertNotEqual(compared.returncode, 0)
                self.assertIn("incomplete metrics", self.output(compared))

    def test_percentage_and_ratio_upper_boundaries_are_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001", metrics={
                "cpu_percent": 100, "gpu_percent": 100,
                "direct_connect_success_rate": 100, "relay_ratio": 1,
            })
            self.make_run(root, "M13-office-R002")
            verified = self.run_tool("verify", "--root", str(root))
            self.assertIn('"m13_matrix": "PASS"', verified.stdout)
            compared = self.run_tool(
                "compare", "--root", str(root),
                "--baseline", "M13-office-R001",
                "--candidate", "M13-office-R002",
            )
            self.assertTrue(json.loads(compared.stdout)["comparable"])


    def test_missing_middle_run_number_refuses_verify_and_compare(self):
        # Deleting R002 must not make R001 versus R003 look admissible.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            for run_id in ("M13-office-R001", "M13-office-R002", "M13-office-R003"):
                self.make_run(root, run_id)
            ledger = root / "ledger.jsonl"
            lines = ledger.read_text(encoding="utf-8").splitlines()
            ledger.write_text("\n".join((lines[0], lines[2])) + "\n", encoding="utf-8")
            for command in (
                ("verify", "--root", str(root)),
                ("compare", "--root", str(root), "--baseline",
                 "M13-office-R001", "--candidate", "M13-office-R003"),
            ):
                result = self.run_tool(*command, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cherry_picking_forbidden", self.output(result))

    def test_reordered_run_numbers_refuse_verify_and_compare(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            ledger = root / "ledger.jsonl"
            lines = ledger.read_text(encoding="utf-8").splitlines()
            ledger.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
            for command in (
                ("verify", "--root", str(root)),
                ("compare", "--root", str(root), "--baseline",
                 "M13-office-R001", "--candidate", "M13-office-R002"),
            ):
                result = self.run_tool(*command, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ledger order", self.output(result))

    def test_record_refuses_skipping_next_run_number(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            # Use a distinct, valid sample so this test reaches the sequence
            # guard rather than the independent duplicate-raw guard.
            next_raw = root / "raw" / "M13-office-R003.samples.jsonl"
            next_raw.write_text('{"i": 0, "latency_ms": 50}\n', encoding="utf-8")
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R003",
                "--raw", str(next_raw),
                "--environment", str(root / "M13-office-R001.env.json"),
                "--metrics", str(root / "M13-office-R001.metrics.json"),
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected R002", self.output(result))
            self.assertEqual(len((root / "ledger.jsonl").read_text().splitlines()), 1)



    def test_record_refuses_empty_raw_sample_file(self):
        # A zero-byte file is not per-sample benchmark evidence.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            raw_dir = root / "raw"
            raw_dir.mkdir()
            raw = raw_dir / "M13-office-R001.samples.jsonl"
            raw.write_bytes(b"")
            env = root / "env.json"
            env.write_text(json.dumps(ENVIRONMENT), encoding="utf-8")
            metrics = root / "metrics.json"
            metrics.write_text(json.dumps(FULL_METRICS), encoding="utf-8")
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R001",
                "--raw", str(raw), "--environment", str(env),
                "--metrics", str(metrics), ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("empty raw sample file", self.output(result))
            self.assertEqual((root / "ledger.jsonl").read_text(), "")

    def test_empty_raw_with_matching_hash_and_size_refuses_verify_compare(self):
        # Forged metadata must not turn zero observations into a valid run.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            raw.write_bytes(b"")
            ledger = root / "ledger.jsonl"
            entries = [json.loads(line) for line in ledger.read_text().splitlines()]
            entries[0]["raw_sha256"] = hashlib.sha256(b"").hexdigest()
            entries[0]["raw_bytes"] = 0
            ledger.write_text(
                "".join(json.dumps(entry) + "\n" for entry in entries),
                encoding="utf-8",
            )
            for args in (
                ("verify", "--root", str(root)),
                ("compare", "--root", str(root),
                 "--baseline", "M13-office-R001",
                 "--candidate", "M13-office-R002"),
            ):
                result = self.run_tool(*args, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("empty raw sample file", self.output(result))


    def test_compare_rejects_invalid_unselected_ledger_run(self):
        # A clean R001/R002 pair cannot hide a corrupted R003 in the same
        # evidence ledger. The entire matrix must remain admissible.
        for defect in ("raw", "metrics", "environment"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                for ordinal in (1, 2, 3):
                    self.make_run(root, f"M13-office-R{ordinal:03d}")
                args = (
                    "compare", "--root", str(root),
                    "--baseline", "M13-office-R001",
                    "--candidate", "M13-office-R002",
                )
                self.assertTrue(json.loads(self.run_tool(*args).stdout)["comparable"])
                if defect == "raw":
                    raw = root / "raw" / "M13-office-R003.samples.jsonl"
                    raw.write_text('{"i": 0, "latency_ms": 1}\n', encoding="utf-8")
                else:
                    ledger = root / "ledger.jsonl"
                    entries = [json.loads(line) for line in ledger.read_text().splitlines()]
                    if defect == "metrics":
                        entries[2]["metrics"]["ram_mb"] = None
                    else:
                        entries[2]["environment"]["machine_id"] = ""
                    ledger.write_text(
                        "".join(json.dumps(entry) + "\n" for entry in entries),
                        encoding="utf-8",
                    )
                result = self.run_tool(*args, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("full ledger inadmissible", self.output(result))


    def test_record_refuses_append_after_prior_raw_tampering(self):
        # A later run must not bury a replaced or deleted prior raw sample.
        for defect in ("tampered", "missing"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001")
                ledger = root / "ledger.jsonl"
                raw = root / "raw" / "M13-office-R001.samples.jsonl"
                if defect == "tampered":
                    raw.write_text('{"i": 0, "latency_ms": 1}\n', encoding="utf-8")
                else:
                    raw.unlink()
                next_raw = root / "raw" / "M13-office-R002.samples.jsonl"
                next_raw.write_text('{"i": 0, "latency_ms": 50}\n', encoding="utf-8")
                original = ledger.read_bytes()
                result = self.run_tool(
                    "record", "--root", str(root), "--run-id", "M13-office-R002",
                    "--raw", str(next_raw),
                    "--environment", str(root / "M13-office-R001.env.json"),
                    "--metrics", str(root / "M13-office-R001.metrics.json"),
                    ok=False,
                )
                self.assertNotEqual(result.returncode, 0)
                expected = ("existing raw evidence inadmissible"
                            if defect == "tampered" else "raw_results_required")
                self.assertIn(expected, self.output(result))
                self.assertEqual(ledger.read_bytes(), original)


    def test_record_refuses_reusing_existing_raw_sample_for_new_run(self):
        # Two run IDs cannot cite the same physical sample as independent runs.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            ledger = root / "ledger.jsonl"
            before = ledger.read_bytes()
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R002",
                "--raw", str(root / "raw" / "M13-office-R001.samples.jsonl"),
                "--environment", str(root / "M13-office-R001.env.json"),
                "--metrics", str(root / "M13-office-R001.metrics.json"),
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw sample already assigned", self.output(result))
            self.assertEqual(ledger.read_bytes(), before)

    def test_verify_and_compare_refuse_reused_raw_path_in_ledger(self):
        # A forged ledger may reuse an intact file with matching SHA and size.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            ledger = root / "ledger.jsonl"
            entries = [json.loads(line) for line in ledger.read_text().splitlines()]
            entries[1]["raw_path"] = entries[0]["raw_path"]
            # Both helpers generated the same raw bytes, so the old validator
            # accepted this as a valid independent comparison.
            self.assertEqual(entries[0]["raw_sha256"], entries[1]["raw_sha256"])
            ledger.write_text(
                "".join(json.dumps(entry) + "\n" for entry in entries),
                encoding="utf-8",
            )
            for args in (
                ("verify", "--root", str(root)),
                ("compare", "--root", str(root),
                 "--baseline", "M13-office-R001",
                 "--candidate", "M13-office-R002"),
            ):
                result = self.run_tool(*args, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("raw sample already used", self.output(result))



    def test_record_refuses_non_jsonl_raw_even_when_nonempty(self):
        # Hashing arbitrary bytes does not establish per-sample observations.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            raw_dir = root / "raw"
            raw_dir.mkdir()
            raw = raw_dir / "M13-office-R001.samples.jsonl"
            raw.write_text("not a JSONL observation\n", encoding="utf-8")
            env = root / "env.json"
            env.write_text(json.dumps(ENVIRONMENT), encoding="utf-8")
            metrics = root / "metrics.json"
            metrics.write_text(json.dumps(FULL_METRICS), encoding="utf-8")
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R001",
                "--raw", str(raw), "--environment", str(env),
                "--metrics", str(metrics), ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid JSONL sample line", self.output(result))
            self.assertEqual((root / "ledger.jsonl").read_text(), "")

    def test_forged_hash_cannot_validate_non_jsonl_samples(self):
        # Even matching SHA-256/byte counts cannot authenticate bad JSONL.
        for payload, reason in (
            (b"[]\n", "invalid JSONL sample object"),
            (b"{}\n", "invalid JSONL sample object"),
            (b'{"latency_ms": NaN}\n', "invalid JSONL sample object"),
            (b'{"latency_ms": 1e999}\n', "invalid JSONL sample object"),
            (b'{"i": 1}\n\n', "blank JSONL sample line"),
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                self.make_run(root, "M13-office-R001")
                self.make_run(root, "M13-office-R002")
                raw = root / "raw" / "M13-office-R001.samples.jsonl"
                raw.write_bytes(payload)
                ledger = root / "ledger.jsonl"
                entries = [json.loads(line) for line in ledger.read_text().splitlines()]
                entries[0]["raw_sha256"] = hashlib.sha256(payload).hexdigest()
                entries[0]["raw_bytes"] = len(payload)
                ledger.write_text(
                    "".join(json.dumps(entry) + "\n" for entry in entries),
                    encoding="utf-8",
                )
                for args in (
                    ("verify", "--root", str(root)),
                    ("compare", "--root", str(root),
                     "--baseline", "M13-office-R001",
                     "--candidate", "M13-office-R002"),
                ):
                    result = self.run_tool(*args, ok=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, self.output(result))

    def test_record_refuses_prior_raw_with_forged_matching_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            first = root / "raw" / "M13-office-R001.samples.jsonl"
            payload = b"not-json\n"
            first.write_bytes(payload)
            ledger = root / "ledger.jsonl"
            entry = json.loads(ledger.read_text())
            entry["raw_sha256"] = hashlib.sha256(payload).hexdigest()
            entry["raw_bytes"] = len(payload)
            ledger.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            before = ledger.read_bytes()
            next_raw = root / "raw" / "M13-office-R002.samples.jsonl"
            next_raw.write_text('{"i": 1}\n', encoding="utf-8")
            result = self.run_tool(
                "record", "--root", str(root), "--run-id", "M13-office-R002",
                "--raw", str(next_raw),
                "--environment", str(root / "M13-office-R001.env.json"),
                "--metrics", str(root / "M13-office-R001.metrics.json"),
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid JSONL sample line", self.output(result))
            self.assertEqual(ledger.read_bytes(), before)


    def test_record_refuses_duplicate_jsonl_object_keys(self):
        # Contradictory duplicate keys, including nested keys, are not raw evidence.
        for payload in (
            '{"latency_ms": 42, "latency_ms": 1}\n',
            '{"sample": {"latency_ms": 42, "latency_ms": 1}}\n',
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.init_ledger(root)
                raw_dir = root / "raw"
                raw_dir.mkdir()
                raw = raw_dir / "M13-office-R001.samples.jsonl"
                raw.write_text(payload, encoding="utf-8")
                env = root / "env.json"
                env.write_text(json.dumps(ENVIRONMENT), encoding="utf-8")
                metrics = root / "metrics.json"
                metrics.write_text(json.dumps(FULL_METRICS), encoding="utf-8")
                result = self.run_tool(
                    "record", "--root", str(root), "--run-id", "M13-office-R001",
                    "--raw", str(raw), "--environment", str(env),
                    "--metrics", str(metrics), ok=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("duplicate JSON key", self.output(result))
                self.assertEqual((root / "ledger.jsonl").read_text(), "")

    def test_verify_compare_refuse_duplicate_jsonl_keys_with_matching_hash(self):
        # A forged matching digest/size cannot make ambiguous JSON admissible.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.init_ledger(root)
            self.make_run(root, "M13-office-R001")
            self.make_run(root, "M13-office-R002")
            raw = root / "raw" / "M13-office-R001.samples.jsonl"
            payload = b'{"i": 0, "latency_ms": 42, "latency_ms": 1}\n'
            raw.write_bytes(payload)
            ledger = root / "ledger.jsonl"
            entries = [json.loads(line) for line in ledger.read_text().splitlines()]
            entries[0]["raw_sha256"] = hashlib.sha256(payload).hexdigest()
            entries[0]["raw_bytes"] = len(payload)
            ledger.write_text(
                "".join(json.dumps(entry) + "\n" for entry in entries),
                encoding="utf-8",
            )
            for args in (
                ("verify", "--root", str(root)),
                ("compare", "--root", str(root),
                 "--baseline", "M13-office-R001",
                 "--candidate", "M13-office-R002"),
            ):
                result = self.run_tool(*args, ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("duplicate JSON key", self.output(result))


if __name__ == "__main__":
    unittest.main()