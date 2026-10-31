#!/usr/bin/env python3
"""Tests for `verify_release_manifest.py`.

Every rule in that script is tested with a manifest that *satisfies* it and a
manifest that *violates* it. A rule with only a passing case cannot fail, and a
check that cannot fail is not a gate -- the same defect the M8 resume gate had.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_release_manifest import (  # noqa: E402
    Manifest,
    check_artifacts,
    check_channel,
    check_downgrade,
    check_minimum_client,
    check_platform,
    check_signature_declared,
    check_uninstall_cleanup,
    load_manifest,
    verify,
)

PAYLOAD = b"omnidesk-release-payload"


def rules(violations) -> set[str]:
    return {violation.rule for violation in violations}


def good_manifest(**overrides) -> Manifest:
    """A manifest that satisfies every rule, before any override."""
    values = {
        "version": 5,
        "channel": "stable",
        "platform": "windows-x86_64",
        "minimum_client_version": 4,
        "artifacts": {},
        "signature_verified_by": "cosign-release",
        "cleanup": {
            "windows-x86_64": [
                "OmniDeskUpdateTask",
                "OmniDeskUpdaterService",
            ]
        },
    }
    values.update(overrides)
    return Manifest(**values)


class TestDowngrade(unittest.TestCase):
    """U3: an update must be strictly newer."""

    def test_a_newer_version_is_accepted(self):
        self.assertEqual(check_downgrade(good_manifest(version=6), 5), [])

    def test_the_same_version_is_refused(self):
        violations = check_downgrade(good_manifest(version=5), 5)
        self.assertEqual(rules(violations), {"U3"})

    def test_an_older_version_is_refused(self):
        violations = check_downgrade(good_manifest(version=4), 5)
        self.assertEqual(rules(violations), {"U3"})


class TestChannel(unittest.TestCase):
    """U5: a client only accepts its own pinned channel."""

    def test_the_matching_channel_is_accepted(self):
        self.assertEqual(check_channel(good_manifest(channel="stable"), "stable"), [])
        self.assertEqual(check_channel(good_manifest(channel="beta"), "beta"), [])

    def test_a_stable_client_refuses_a_beta_manifest(self):
        violations = check_channel(good_manifest(channel="beta"), "stable")
        self.assertEqual(rules(violations), {"U5"})

    def test_a_beta_client_refuses_a_stable_manifest(self):
        violations = check_channel(good_manifest(channel="stable"), "beta")
        self.assertEqual(rules(violations), {"U5"})

    def test_an_unknown_channel_is_refused(self):
        violations = check_channel(good_manifest(channel="nightly"), "stable")
        self.assertEqual(rules(violations), {"U5"})


class TestPlatform(unittest.TestCase):
    """U5: a client only accepts artifacts for its own platform."""

    def test_the_matching_platform_is_accepted(self):
        self.assertEqual(
            check_platform(good_manifest(platform="linux-aarch64"), "linux-aarch64"), []
        )

    def test_a_windows_client_refuses_a_macos_manifest(self):
        violations = check_platform(
            good_manifest(platform="macos-aarch64"), "windows-x86_64"
        )
        self.assertEqual(rules(violations), {"U5"})

    def test_an_unknown_platform_is_refused(self):
        violations = check_platform(good_manifest(platform="solaris"), "windows-x86_64")
        self.assertEqual(rules(violations), {"U5"})


class TestMinimumClient(unittest.TestCase):
    """U4: a client below the manifest's floor is not offered the update."""

    def test_a_client_above_the_floor_is_accepted(self):
        self.assertEqual(check_minimum_client(good_manifest(), 5), [])

    def test_a_client_below_the_floor_is_refused(self):
        violations = check_minimum_client(
            good_manifest(minimum_client_version=9), 5
        )
        self.assertEqual(rules(violations), {"U4"})


class TestSignatureDeclared(unittest.TestCase):
    """This script does not verify signatures and must not pretend to."""

    def test_an_unsigned_manifest_is_refused(self):
        violations = check_signature_declared(
            good_manifest(signature_verified_by=None)
        )
        self.assertEqual(rules(violations), {"U1"})

    def test_an_empty_declaration_is_refused(self):
        violations = check_signature_declared(good_manifest(signature_verified_by=""))
        self.assertEqual(rules(violations), {"U1"})

    def test_a_declared_verifier_is_accepted(self):
        self.assertEqual(check_signature_declared(good_manifest()), [])


class TestArtifacts(unittest.TestCase):
    """U4: a listed artifact must exist and match its digest."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.artifacts = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, data: bytes = PAYLOAD) -> str:
        (self.artifacts / name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def test_a_matching_digest_is_accepted(self):
        digest = self.write("app.exe")
        self.assertEqual(
            check_artifacts(good_manifest(artifacts={"app.exe": digest}), self.artifacts),
            [],
        )

    def test_no_artifacts_is_not_a_valid_release(self):
        violations = check_artifacts(good_manifest(), self.artifacts)
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("no artifacts", str(violations[0]))

    def test_unsafe_paths_are_refused_even_when_the_external_file_matches(self):
        outside = self.artifacts.parent / (self.artifacts.name + "-outside.exe")
        outside.write_bytes(PAYLOAD)
        self.addCleanup(outside.unlink, missing_ok=True)
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        for name in (
            "../" + outside.name,
            str(outside),
            r"..\escape.exe",
            r"C:\escape.exe",
            "nested/app.exe",
            "app.exe:alternate",
            ".hidden.exe",
            "trailing.",
        ):
            with self.subTest(name=name):
                violations = check_artifacts(
                    good_manifest(artifacts={name: digest}), self.artifacts
                )
                self.assertEqual(rules(violations), {"U4"})
                self.assertIn("unsafe artifact filename", str(violations[0]))

    def test_windows_reserved_device_names_are_refused_before_file_access(self):
        # These names can be created on Linux CI but cannot be safely used as
        # Windows release artifacts, even when an extension is appended.
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        for name in (
            "CON", "con.exe", "PRN.txt", "AUX", "NUL.exe",
            "COM1.exe", "com9.bin", "LPT1.exe", "lpt9.log",
        ):
            with self.subTest(name=name):
                violations = check_artifacts(
                    good_manifest(artifacts={name: digest}), self.artifacts
                )
                self.assertEqual(rules(violations), {"U4"})
                self.assertIn("reserved Windows device name", str(violations[0]))

    def test_windows_case_insensitive_artifact_collisions_fail_closed(self):
        # Check before filesystem access, including on a Linux CI host where
        # the colliding files could exist as distinct regular files.
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        for first, second in (
            ("OmniDesk.exe", "omnidesk.EXE"),
            ("APP.exe", "app.exe"),
            ("a.BIN", "A.bin"),
        ):
            with self.subTest(first=first, second=second):
                violations = check_artifacts(
                    good_manifest(artifacts={first: digest, second: digest}),
                    self.artifacts,
                )
                self.assertEqual(rules(violations), {"U4"})
                self.assertEqual(len(violations), 1)
                self.assertIn("ambiguous Windows artifact filenames", str(violations[0]))

    def test_linux_distinct_case_artifact_names_remain_valid(self):
        if os.name == "nt":
            self.skipTest("case-distinct filenames cannot be reliably created on Windows")
        first = "OmniDesk.bin"
        second = "omnidesk.BIN"
        digest = self.write(first)
        self.write(second)
        self.assertEqual(
            check_artifacts(
                good_manifest(
                    platform="linux-x86_64",
                    artifacts={first: digest, second: digest},
                ),
                self.artifacts,
            ),
            [],
        )

    def test_linux_artifact_name_con_remains_valid(self):
        if os.name == "nt":
            self.skipTest("Windows cannot create a regular file named CON")
        digest = self.write("CON")
        self.assertEqual(
            check_artifacts(
                good_manifest(platform="linux-x86_64", artifacts={"CON": digest}),
                self.artifacts,
            ),
            [],
        )

    def test_symlink_to_external_payload_is_refused(self):
        external = self.artifacts.parent / (self.artifacts.name + "-linked.exe")
        external.write_bytes(PAYLOAD)
        self.addCleanup(external.unlink, missing_ok=True)
        link = self.artifacts / "app.exe"
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not supported by this environment")
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": hashlib.sha256(PAYLOAD).hexdigest()}),
            self.artifacts,
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("symbolic link", str(violations[0]))

    def test_symlinked_artifact_directory_and_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as external_dir:
            external = Path(external_dir)
            (external / "app.exe").write_bytes(PAYLOAD)
            nested = external / "nested"
            nested.mkdir()
            (nested / "app.exe").write_bytes(PAYLOAD)
            redirected = self.artifacts / "redirected"
            try:
                redirected.symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            manifest = good_manifest(
                artifacts={"app.exe": hashlib.sha256(PAYLOAD).hexdigest()}
            )
            before = (external / "app.exe").read_bytes()
            for selected in (redirected, redirected / "nested"):
                with self.subTest(selected=selected):
                    violations = check_artifacts(manifest, selected)
                    self.assertEqual(rules(violations), {"U4"})
                    self.assertIn("redirected artifact directory", str(violations[0]))
            self.assertEqual((external / "app.exe").read_bytes(), before)

    def test_artifact_directory_parent_traversal_is_refused(self):
        digest = self.write("app.exe")
        (self.artifacts / "empty").mkdir()
        selected = self.artifacts / "empty" / ".."
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": digest}), selected
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("parent traversal", str(violations[0]))

    def test_artifact_directory_must_be_a_directory(self):
        digest = self.write("app.exe")
        not_directory = self.artifacts / "not-a-directory"
        not_directory.write_text("owner data", encoding="utf-8")
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": digest}), not_directory
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("not an existing directory", str(violations[0]))
        self.assertEqual(not_directory.read_text(encoding="utf-8"), "owner data")

    def test_hardlinked_external_payload_is_refused_without_modifying_it(self):
        external = self.artifacts.parent / (self.artifacts.name + "-hardlink-source.exe")
        external.write_bytes(PAYLOAD)
        self.addCleanup(external.unlink, missing_ok=True)
        artifact = self.artifacts / "app.exe"
        try:
            artifact.hardlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("hard links are unavailable on this filesystem")
        self.assertGreater(artifact.stat().st_nlink, 1)
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": hashlib.sha256(PAYLOAD).hexdigest()}),
            self.artifacts,
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("hard links", str(violations[0]))
        self.assertEqual(external.read_bytes(), PAYLOAD)

    def test_same_bytes_replacement_between_inspection_and_open_is_refused(self):
        # Matching content is not enough: a replaced inode must not attest
        # the release artifact that was inspected before opening.
        digest = self.write("app.exe")
        artifact = self.artifacts / "app.exe"
        replacement = self.artifacts / "replacement.tmp"
        replacement.write_bytes(PAYLOAD)
        original_open = os.open
        swapped = False

        def replace_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path) == artifact and not swapped:
                swapped = True
                os.replace(replacement, artifact)
            return original_open(path, flags, *args, **kwargs)

        with patch("verify_release_manifest.os.open", side_effect=replace_before_open):
            violations = check_artifacts(
                good_manifest(artifacts={"app.exe": digest}), self.artifacts
            )
        self.assertTrue(swapped)
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("changed between inspection and open", str(violations[0]))
        self.assertEqual(artifact.read_bytes(), PAYLOAD)

    def test_matching_bytes_in_swapped_artifact_directory_are_refused(self):
        # Replacing an admitted directory with another ordinary directory
        # containing the SAME bytes must not attest the substituted package.
        digest = self.write("app.exe")
        artifact = self.artifacts / "app.exe"
        original_open = os.open
        swapped = False
        with tempfile.TemporaryDirectory() as other_parent:
            replacement = Path(other_parent) / "replacement"
            replacement.mkdir()
            (replacement / "app.exe").write_bytes(PAYLOAD)
            saved = self.artifacts.with_name(self.artifacts.name + "-saved")
            self.assertFalse(saved.exists())

            def swap_before_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path) == artifact and not swapped:
                    self.artifacts.rename(saved)
                    try:
                        replacement.rename(self.artifacts)
                    except OSError:
                        saved.rename(self.artifacts)
                        raise
                    swapped = True
                return original_open(path, flags, *args, **kwargs)

            try:
                with patch("verify_release_manifest.os.open", side_effect=swap_before_open):
                    violations = check_artifacts(
                        good_manifest(artifacts={"app.exe": digest}), self.artifacts
                    )
            finally:
                if swapped:
                    self.artifacts.rename(replacement)
                    saved.rename(self.artifacts)
            self.assertTrue(swapped)
            self.assertEqual(rules(violations), {"U4"})
            # The per-file identity guard may reject the swap before the
            # directory identity guard runs. Either is a fail-closed result.
            self.assertRegex(
                str(violations[0]),
                r"changed between inspection and open|artifact directory changed",
            )
            self.assertEqual((self.artifacts / "app.exe").read_bytes(), PAYLOAD)
            self.assertEqual((replacement / "app.exe").read_bytes(), PAYLOAD)

    def test_malformed_digest_is_refused(self):
        self.write("app.exe")
        for digest in ("", "abc", "F" * 64, 123, None):
            with self.subTest(digest=digest):
                violations = check_artifacts(
                    good_manifest(artifacts={"app.exe": digest}), self.artifacts
                )
                self.assertEqual(rules(violations), {"U4"})
                self.assertIn("invalid SHA-256", str(violations[0]))

    def test_a_missing_artifact_is_refused(self):
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": "0" * 64}), self.artifacts
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("not present", str(violations[0]))

    def test_a_digest_mismatch_is_refused(self):
        self.write("app.exe")
        violations = check_artifacts(
            good_manifest(artifacts={"app.exe": "f" * 64}), self.artifacts
        )
        self.assertEqual(rules(violations), {"U4"})
        self.assertIn("mismatch", str(violations[0]))

    def test_tampering_after_signing_is_caught(self):
        digest = self.write("app.exe")
        manifest = good_manifest(artifacts={"app.exe": digest})
        self.assertEqual(check_artifacts(manifest, self.artifacts), [])

        (self.artifacts / "app.exe").write_bytes(PAYLOAD + b"!")

        violations = check_artifacts(manifest, self.artifacts)
        self.assertEqual(rules(violations), {"U4"})


class TestUninstallCleanup(unittest.TestCase):
    """U8: nothing that can install or launch survives uninstall."""

    def test_a_complete_cleanup_is_accepted(self):
        self.assertEqual(check_uninstall_cleanup(good_manifest()), [])

    def test_no_cleanup_at_all_is_refused(self):
        violations = check_uninstall_cleanup(good_manifest(cleanup={}))
        self.assertEqual(rules(violations), {"U8"})

    def test_an_empty_platform_cleanup_is_refused(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"windows-x86_64": []})
        )
        self.assertEqual(rules(violations), {"U8"})

    def test_cleanup_for_another_platform_cannot_attest_this_build(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"linux-x86_64": ["OmniDeskUpdaterService"]})
        )
        self.assertEqual(rules(violations), {"U8"})
        self.assertIn("omits manifest platform", str(violations[0]))

    def test_multi_platform_cleanup_must_include_current_platform(self):
        manifest = good_manifest(
            cleanup={
                "linux-x86_64": ["OmniDeskUpdaterService"],
                "windows-aarch64": ["OmniDeskUpdateTask"],
            }
        )
        self.assertEqual(rules(check_uninstall_cleanup(manifest)), {"U8"})
        manifest.cleanup["windows-x86_64"] = ["OmniDeskUpdateTask"]
        self.assertEqual(check_uninstall_cleanup(manifest), [])

    def test_nonstring_manifest_platform_fails_closed(self):
        violations = check_uninstall_cleanup(
            good_manifest(platform=["windows-x86_64"], cleanup={"windows-x86_64": ["OmniDeskUpdateTask"]})
        )
        self.assertEqual(rules(violations), {"U8"})

    def test_an_updater_scheduled_task_is_named_as_removable(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"windows-x86_64": ["OmniDeskUpdateTask"]})
        )
        self.assertEqual(violations, [])

    def test_a_cleanup_naming_no_runnable_entry_is_refused(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"windows-x86_64": ["omnidesk.exe"]})
        )
        self.assertEqual(rules(violations), {"U8"})

    def test_a_bare_path_is_refused_because_paths_are_handled_separately(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"windows-x86_64": ["C:\\Program Files\\OmniDesk"]})
        )
        self.assertEqual(rules(violations), {"U8"})
        self.assertIn("bare path", str(violations[0]))

    def test_an_unknown_platform_in_cleanup_is_refused(self):
        violations = check_uninstall_cleanup(
            good_manifest(cleanup={"atari-st": ["OmniDeskUpdateTask"]})
        )
        self.assertEqual(rules(violations), {"U8"})


class TestLoadManifest(unittest.TestCase):
    """A malformed manifest is a hard failure, never a partial load."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, data: dict) -> Path:
        path = self.dir / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_a_complete_manifest_loads(self):
        path = self.write(
            {
                "version": 3,
                "channel": "beta",
                "platform": "linux-x86_64",
                "minimum_client_version": 2,
                "artifacts": {"app": "abc"},
                "signature_verified_by": "cosign",
                "cleanup": {"linux-x86_64": ["omnidesk-update.service"]},
            }
        )
        manifest = load_manifest(path)
        self.assertEqual(manifest.version, 3)
        self.assertEqual(manifest.artifacts, {"app": "abc"})

    def test_duplicate_json_keys_are_rejected_at_every_depth(self):
        # Python's default json.loads silently keeps the final duplicate.
        # Release metadata must not admit two interpretations of a key.
        base = (
            '{"version":1,"channel":"stable","platform":"windows-x86_64",'
            '"minimum_client_version":1}'
        )
        cases = (
            (
                "top-level",
                base.replace('"version":1', '"version":1,"version":2', 1),
                "version",
            ),
            (
                "artifact digest",
                base[:-1] + ',"artifacts":{"app.exe":"bad","app.exe":"good"}}',
                "app.exe",
            ),
            (
                "cleanup entries",
                base[:-1]
                + ',"cleanup":{"windows-x86_64":[],"windows-x86_64":["OmniDeskUpdateTask"]}}',
                "windows-x86_64",
            ),
        )
        path = self.dir / "manifest.json"
        for case, content, key in cases:
            with self.subTest(case=case):
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError, f"duplicate JSON key '{key}'"
                ):
                    load_manifest(path)

    def test_a_missing_required_key_is_rejected(self):
        path = self.write({"version": 1, "channel": "stable", "platform": "linux-x86_64"})
        with self.assertRaises(ValueError) as context:
            load_manifest(path)
        self.assertIn("minimum_client_version", str(context.exception))

    def test_a_zero_version_is_rejected(self):
        path = self.write(
            {
                "version": 0,
                "channel": "stable",
                "platform": "linux-x86_64",
                "minimum_client_version": 1,
            }
        )
        with self.assertRaises(ValueError):
            load_manifest(path)

    def test_a_boolean_version_is_rejected(self):
        # `True` is an int in Python. Accepting it would make version 1 mean
        # "true", which is a pleasant way to ship a downgrade guard that does
        # not work.
        path = self.write(
            {
                "version": True,
                "channel": "stable",
                "platform": "linux-x86_64",
                "minimum_client_version": 1,
            }
        )
        with self.assertRaises(ValueError):
            load_manifest(path)

    def test_a_top_level_array_is_rejected_cleanly(self):
        path = self.dir / "manifest.json"
        path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            load_manifest(path)

    def test_invalid_cleanup_shape_is_rejected_cleanly(self):
        base = {
            "version": 1,
            "channel": "stable",
            "platform": "linux-x86_64",
            "minimum_client_version": 1,
        }
        for bad in (["task"], {"linux-x86_64": "task"}, {"linux-x86_64": [9]}):
            with self.subTest(cleanup=bad):
                with self.assertRaisesRegex(ValueError, "cleanup"):
                    load_manifest(self.write({**base, "cleanup": bad}))

    def test_nonstring_verifier_is_rejected_cleanly(self):
        path = self.write(
            {
                "version": 1,
                "channel": "stable",
                "platform": "linux-x86_64",
                "minimum_client_version": 1,
                "signature_verified_by": ["self"],
            }
        )
        with self.assertRaisesRegex(ValueError, "signature_verified_by"):
            load_manifest(path)

    def test_non_object_artifacts_are_rejected(self):
        path = self.write(
            {
                "version": 1,
                "channel": "stable",
                "platform": "linux-x86_64",
                "minimum_client_version": 1,
                "artifacts": ["a", "b"],
            }
        )
        with self.assertRaises(ValueError):
            load_manifest(path)


class TestVerifyComposition(unittest.TestCase):
    """The combined gate must surface every violation, not stop at the first."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.artifacts = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_a_good_manifest_passes(self):
        (self.artifacts / "app.exe").write_bytes(PAYLOAD)
        valid = good_manifest(
            artifacts={"app.exe": hashlib.sha256(PAYLOAD).hexdigest()}
        )
        self.assertEqual(
            verify(
                valid,
                client_version=4,
                client_channel="stable",
                client_platform="windows-x86_64",
                artifacts_dir=self.artifacts,
            ),
            [],
        )

    def test_every_violation_is_reported_at_once(self):
        manifest = good_manifest(
            version=2,
            channel="beta",
            platform="macos-x86_64",
            minimum_client_version=99,
            signature_verified_by=None,
            artifacts={"app.exe": "0" * 64},
            cleanup={"windows-x86_64": ["omnidesk.exe"]},
        )
        violations = verify(
            manifest,
            client_version=5,
            client_channel="stable",
            client_platform="windows-x86_64",
            artifacts_dir=self.artifacts,
        )
        # A gate that reports one failure at a time makes fixing a release
        # take one CI run per mistake.
        self.assertEqual(rules(violations), {"U1", "U3", "U4", "U5", "U8"})
        self.assertGreaterEqual(len(violations), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)