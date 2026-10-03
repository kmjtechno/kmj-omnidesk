#!/usr/bin/env python3
"""Tests for `verify_release_manifest.py`.

Every rule in that script is tested with a manifest that *satisfies* it and a
manifest that *violates* it. A rule with only a passing case cannot fail, and a
check that cannot fail is not a gate -- the same defect the M8 resume gate had.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(
            verify(
                good_manifest(),
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