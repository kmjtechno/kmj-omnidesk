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

    def test_checksums_rejects_symlinked_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "real"
            actual.mkdir()
            (actual / "events.jsonl").write_text("real bytes\\n", encoding="utf-8")
            linked = root / "linked"
            try:
                linked.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            result = self.run_tool("checksums", "--root", temp, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink forbidden", result.stderr)

    def test_checksums_rejects_symlinked_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "real.txt"
            actual.write_text("real bytes\\n", encoding="utf-8")
            linked = root / "linked.txt"
            try:
                linked.symlink_to(actual)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"file symlinks unavailable: {error}")
            result = self.run_tool("checksums", "--root", temp, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink forbidden", result.stderr)

    def test_checksums_rejects_non_regular_fifo(self):
        import os

        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unsupported on this platform")
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "evidence.pipe"
            try:
                os.mkfifo(fifo)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"FIFO creation unavailable: {error}")
            result = self.run_tool("checksums", "--root", temp, ok=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-regular evidence path", result.stderr)

    def test_symlinked_package_root_rejected_for_all_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            actual = base / "actual"
            actual.mkdir()
            linked = base / "linked"
            try:
                linked.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            artifact = actual / "runs" / "M4-T1-R01" / "events.jsonl"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("observed\\n", encoding="utf-8")
            commands = [
                ("prepare-run", "--root", str(linked), "--run-id", "M4-T2-R01"),
                ("checksums", "--root", str(linked)),
                (
                    "artifact", "--root", str(linked), "--file",
                    str(linked / "runs" / "M4-T1-R01" / "events.jsonl"),
                    "--artifact-id", "root-link", "--run-id", "M4-T1-R01",
                    "--kind", "EVENT_LOG", "--content-type", "application/jsonl",
                    "--component", "agent", "--version", "1",
                ),
            ]
            before = artifact.read_bytes()
            for command in commands:
                with self.subTest(command=command[0]):
                    result = self.run_tool(*command, ok=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("symlinked evidence root path", result.stderr)
            self.assertFalse((actual / "runs" / "M4-T2-R01").exists())
            self.assertEqual(artifact.read_bytes(), before)

    def test_symlinked_parent_and_parent_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            root = linked_parent / "evidence"
            result = self.run_tool(
                "prepare-run", "--root", str(root), "--run-id", "M4-T1-R01",
                ok=False,
            )
            self.assertIn("symlinked evidence root path", result.stderr)
            self.assertFalse((real_parent / "evidence").exists())

            traversed = base / "safe" / ".." / "actual"
            result = self.run_tool("checksums", "--root", str(traversed), ok=False)
            self.assertIn("parent traversal in evidence root", result.stderr)

    def test_prepare_run_rejects_redirected_runs_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            package = base / "package"
            package.mkdir()
            outside = base / "outside"
            outside.mkdir()
            redirected = package / "runs"
            try:
                redirected.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            result = self.run_tool(
                "prepare-run", "--root", str(package),
                "--run-id", "M4-T1-R01", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("redirected runs directory forbidden", result.stderr)
            self.assertFalse((outside / "M4-T1-R01").exists())
            self.assertEqual(list(outside.iterdir()), [])

    def test_prepare_run_rejects_non_directory_runs_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "runs").write_text("owner data", encoding="utf-8")
            result = self.run_tool(
                "prepare-run", "--root", temp,
                "--run-id", "M4-T1-R01", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("runs path is not a directory", result.stderr)
            self.assertEqual((root / "runs").read_text(encoding="utf-8"), "owner data")

    def test_rejects_cross_run_artifact_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run_a = root / "runs" / "M4-T1-R01"
            run_b = root / "runs" / "M4-T2-R01"
            run_a.mkdir(parents=True)
            run_b.mkdir(parents=True)
            artifact = run_a / "events.jsonl"
            artifact.write_text('{"event":"real-observation"}\n', encoding="utf-8")
            result = self.run_tool(
                "artifact", "--root", temp, "--file", str(artifact),
                "--artifact-id", "artifact-a", "--run-id", "M4-T2-R01",
                "--kind", "EVENT_LOG", "--content-type", "application/jsonl",
                "--component", "agent", "--version", "1", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("declared run directory", result.stderr)

    def test_rejects_package_level_artifact_with_run_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "summary.json"
            artifact.write_text("{}", encoding="utf-8")
            result = self.run_tool(
                "artifact", "--root", temp, "--file", str(artifact),
                "--artifact-id", "summary", "--run-id", "M4-T1-R01",
                "--kind", "SUMMARY", "--content-type", "application/json",
                "--component", "agent", "--version", "1", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("declared run directory", result.stderr)

    def test_rejects_directory_as_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp) / "runs" / "M4-T1-R01"
            run_dir.mkdir(parents=True)
            result = self.run_tool(
                "artifact", "--root", temp, "--file", str(run_dir),
                "--artifact-id", "directory", "--run-id", "M4-T1-R01",
                "--kind", "OTHER", "--content-type", "application/octet-stream",
                "--component", "agent", "--version", "1", ok=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regular file", result.stderr)

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
