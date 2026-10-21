#!/usr/bin/env python3
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("package_release_candidate.py")


class ReleaseCandidatePackagingTests(unittest.TestCase):
    def run_packager(
        self, binary: Path, output: Path, version: str = "0.0.1",
        platform: str = "windows", arch: str = "x86_64",
    ):
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
                platform,
                "--arch",
                arch,
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

    def test_path_traversal_segments_are_rejected_without_deleting_other_folders(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.write_bytes(b"binary")
            victim = root / "victim"
            victim.mkdir()
            sentinel = victim / "keep-me.txt"
            sentinel.write_text("never delete", encoding="utf-8")
            for overrides in (
                {"arch": "a/../../victim"},
                {"platform": "a/../../victim"},
                {"arch": "..\\\\victim"},
                {"platform": ""},
            ):
                with self.subTest(overrides=overrides):
                    result = self.run_packager(binary, root / "out", **overrides)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(sentinel.read_text(encoding="utf-8"), "never delete")

    def test_binary_in_staging_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            staging = root / "out" / "kmj-omnidesk-0.0.1-windows-x86_64"
            staging.mkdir(parents=True)
            binary = staging / "omnidesk-desktop.exe"
            binary.write_bytes(b"original")
            result = self.run_packager(binary, root / "out")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(binary.read_bytes(), b"original")

    def test_empty_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "omnidesk-desktop.exe"
            binary.touch()
            result = self.run_packager(binary, root / "out")
            self.assertNotEqual(result.returncode, 0)



    def test_nsis_customer_installer_is_interactive_with_silent_ci_fallback(self):
        installer = (
            Path(__file__).resolve().parents[1]
            / "packaging"
            / "windows"
            / "KMJ-OmniDesk.nsi"
        ).read_text(encoding="utf-8")
        self.assertIn('!include "MUI2.nsh"', installer)
        self.assertIn("SilentInstall normal", installer)
        self.assertIn("SilentUnInstall normal", installer)
        self.assertIn("!insertmacro MUI_PAGE_WELCOME", installer)
        self.assertIn("!insertmacro MUI_PAGE_DIRECTORY", installer)
        self.assertIn("!insertmacro MUI_PAGE_INSTFILES", installer)
        self.assertIn("!insertmacro MUI_UNPAGE_CONFIRM", installer)
        self.assertIn("!insertmacro MUI_UNPAGE_INSTFILES", installer)
        self.assertIn('!define APP_VERSION "0.0.1"', installer)
        self.assertIn('"DisplayVersion" "${APP_VERSION}"', installer)
        self.assertIn('CreateShortCut "$SMPROGRAMS\\KMJ OmniDesk.lnk"', installer)
        self.assertIn('Delete "$SMPROGRAMS\\KMJ OmniDesk.lnk"', installer)
        # Current Windows CI deliberately exercises /S install *and* uninstall.
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Start-Process -FilePath $outputExe -ArgumentList '/S'", workflow)
        self.assertIn("Start-Process -FilePath $uninstaller -ArgumentList '/S'", workflow)

    def test_manual_release_workflow_treats_untrusted_inputs_as_data(self):
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "release-candidate.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("KMJ_RC_VERSION: ${{ inputs.version }}", workflow)
        self.assertIn("KMJ_RC_CHANNEL: ${{ inputs.channel }}", workflow)
        self.assertIn('--version "$env:KMJ_RC_VERSION"', workflow)
        self.assertIn('--channel "$env:KMJ_RC_CHANNEL"', workflow)
        self.assertNotIn("--version '${{ inputs.version }}'", workflow)
        self.assertNotIn("--channel '${{ inputs.channel }}'", workflow)



if __name__ == "__main__":
    unittest.main()
