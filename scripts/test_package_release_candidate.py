#!/usr/bin/env python3
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("package_release_candidate.py")


class ReleaseCandidatePackagingTests(unittest.TestCase):
    def run_packager(self, binary: Path, output: Path, version: str = "0.0.1"):
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--binary",
                str(binary),
                "--output",
                str(output),
                "--version",
                version,
                "--platform",
                "windows",
                "--arch",
                "x86_64",
                "--channel",
                "beta",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_bundle_is_explicitly_unsigned_and_non_publishable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.write_bytes(b"omnidesk-test-binary")
            result = self.run_packager(binary, root / "out")
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(result.stdout)["manifest"]
            self.assertEqual(manifest["release_state"], "UNSIGNED_CANDIDATE")
            self.assertFalse(manifest["publishable"])
            self.assertFalse(manifest["signature_declared"])
            self.assertFalse(manifest["artifacts"][0]["signature_declared"])

    def test_same_input_produces_same_bundle_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.write_bytes(b"stable-bytes")
            first = json.loads(self.run_packager(binary, root / "first").stdout)
            second = json.loads(self.run_packager(binary, root / "second").stdout)
            self.assertEqual(first["bundle_sha256"], second["bundle_sha256"])

    def test_archive_contains_only_expected_candidate_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.write_bytes(b"binary")
            out = root / "out"
            payload = json.loads(self.run_packager(binary, out).stdout)
            with zipfile.ZipFile(out / payload["bundle"]) as archive:
                names = sorted(archive.namelist())
            self.assertEqual(
                names,
                [
                    "kmj-omnidesk-0.0.1-windows-x86_64/omnidesk-desktop.exe",
                    "kmj-omnidesk-0.0.1-windows-x86_64/release-candidate-manifest.json",
                ],
            )

    def test_unsafe_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.write_bytes(b"binary")
            result = self.run_packager(binary, root / "out", "../escape")
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
