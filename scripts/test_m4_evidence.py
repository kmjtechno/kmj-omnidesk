#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("m4_evidence.py")


class EvidenceToolTests(unittest.TestCase):
    def run_tool(self, *args, ok=True):
        result = subprocess.run(
            ["python3", str(SCRIPT), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(result.stderr or result.stdout)
        return result

    def test_prepare_run_and_artifact_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_tool("prepare-run", "--root", temp, "--run-id", "M4-T1-R01")
            artifact = root / "runs" / "M4-T1-R01" / "events.jsonl"
            artifact.write_text('{"event":"candidate"}\n', encoding="utf-8")
            result = self.run_tool(
                "artifact",
                "--root", temp,
                "--file", str(artifact),
                "--artifact-id", "artifact-M4-T1-R01-events",
                "--run-id", "M4-T1-R01",
                "--kind", "EVENT_LOG",
                "--content-type", "application/jsonl",
                "--component", "omnidesk-agent",
                "--version", "0.0.1",
                "--created-at", "2026-09-29T13:00:00Z",
            )
            entry = json.loads(result.stdout)
            expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertEqual(entry["sha256"], expected)
            self.assertEqual(entry["size_bytes"], artifact.stat().st_size)
            self.assertEqual(entry["relative_path"], "runs/M4-T1-R01/events.jsonl")
            self.assertTrue(entry["immutable"])

    def test_rejects_invalid_run_id(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_tool(
                "prepare-run", "--root", temp, "--run-id", "fake-run", ok=False
            )
            self.assertNotEqual(result.returncode, 0)

    def test_checksums_are_sorted_and_exclude_checksum_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "b.txt").write_text("b", encoding="utf-8")
            (root / "a.txt").write_text("a", encoding="utf-8")
            (root / "checksums.sha256").write_text("old", encoding="utf-8")
            result = self.run_tool("checksums", "--root", temp)
            lines = result.stdout.strip().splitlines()
            self.assertEqual([line.split("  ", 1)[1] for line in lines], ["a.txt", "b.txt"])

    def test_rejects_artifact_outside_root(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.NamedTemporaryFile() as outside:
            result = self.run_tool(
                "artifact",
                "--root", temp,
                "--file", outside.name,
                "--artifact-id", "x",
                "--run-id", "M4-T1-R01",
                "--kind", "EVENT_LOG",
                "--content-type", "application/jsonl",
                "--component", "agent",
                "--version", "1",
                ok=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
