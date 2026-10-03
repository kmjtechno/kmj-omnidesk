#!/usr/bin/env python3
"""M13 performance-matrix admissibility tests.

Each test names the single edit that would make it pass while the property is
broken, because a validator that cannot be shown to catch its own failure is
not evidence of anything.
"""

from __future__ import annotations

import json
import subprocess
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
            ["python3", str(SCRIPT), *args],
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


if __name__ == "__main__":
    unittest.main()