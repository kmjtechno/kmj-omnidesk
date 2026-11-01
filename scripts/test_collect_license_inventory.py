#!/usr/bin/env python3
"""Fail-closed regression tests for truthful Cargo.lock license inventory."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_license_inventory import (
    build_license_inventory,
    check_for_viral_copyleft,
    parse_cargo_lock,
    parse_deny_toml_licenses,
)


class TestLicenseInventory(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.lock = self.root / "Cargo.lock"
        self.deny = self.root / "deny.toml"
        self.lock.write_text(
            'version = 4\n[[package]]\nname = "pkg-a"\nversion = "1.0.0"\n'
            'source = "registry+https://example.invalid/index"\n'
            '[[package]]\nname = "pkg-b"\nversion = "2.1.0"\n',
            encoding="utf-8",
        )
        self.deny.write_text(
            '[licenses]\nallow = ["MIT", "Apache-2.0", "MPL-2.0"]\n'
            '[[licenses.clarify]]\nname = "pkg-b"\nexpression = "MPL-2.0"\n',
            encoding="utf-8",
        )

    def test_lockfile_identity_not_license(self) -> None:
        packages = parse_cargo_lock(self.lock)
        self.assertEqual(len(packages), 2)
        self.assertNotIn("license", packages[0])
        self.assertEqual(packages[1]["source"], "")

    def test_deny_policy_is_not_inventory(self) -> None:
        policy = parse_deny_toml_licenses(self.deny)
        self.assertIn("MIT", policy["allow"])
        self.assertEqual(policy["clarifications"]["pkg-b"], "MPL-2.0")

    def test_unknown_license_not_assumed_permissive(self) -> None:
        inv = build_license_inventory(self.lock, self.deny)
        self.assertFalse(inv["license_audit_complete"])
        self.assertTrue(inv["requires_independent_cargo_deny"])
        self.assertEqual(inv["unknown_license_count"], 1)
        self.assertIsNone(inv["packages"][0]["license"])
        self.assertEqual(inv["packages"][0]["license_status"], "unknown")
        self.assertEqual(inv["packages"][1]["license_status"], "policy_clarification_only")
        self.assertEqual(inv["total_third_party"], 1)

    def test_explicit_prohibited_policy_rejected(self) -> None:
        self.deny.write_text(
            '[licenses]\nallow = ["MIT"]\n'
            '[[licenses.clarify]]\nname = "pkg-b"\nexpression = "GPL-3.0-only"\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            build_license_inventory(self.lock, self.deny)

    def test_prohibited_spdx_detection(self) -> None:
        for expression in ("GPL-3.0-only", "AGPL-3.0", "LGPL-2.1-or-later", "SSPL-1.0"):
            self.assertTrue(check_for_viral_copyleft(expression))
        for expression in ("MIT OR Apache-2.0", "MPL-2.0", "BSD-3-Clause"):
            self.assertFalse(check_for_viral_copyleft(expression))

    def test_prohibited_license_in_allow_policy_rejected(self) -> None:
        for prohibited in ("GPL-3.0-only", "AGPL-3.0-or-later", "LGPL-2.1-only", "SSPL-1.0"):
            with self.subTest(prohibited=prohibited):
                self.deny.write_text(
                    '[licenses]\nallow = ["MIT", "' + prohibited + '"]\n',
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "Prohibited licenses.allow"):
                    parse_deny_toml_licenses(self.deny)

    def test_empty_license_allow_policy_rejected(self) -> None:
        self.deny.write_text('[licenses]\nallow = []\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty licenses.allow"):
            parse_deny_toml_licenses(self.deny)

    def test_duplicate_allow_policy_rejected_without_masking_good_entries(self) -> None:
        self.deny.write_text(
            '[licenses]\nallow = ["MIT", "Apache-2.0", " mit "]\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Duplicate licenses.allow"):
            parse_deny_toml_licenses(self.deny)

    def test_permissive_allow_policy_still_accepted(self) -> None:
        policy = parse_deny_toml_licenses(self.deny)
        self.assertEqual(policy["allow"], ["MIT", "Apache-2.0", "MPL-2.0"])

    def test_duplicate_package_rejected(self) -> None:
        self.lock.write_text(
            '[[package]]\nname = "x"\nversion = "1"\n'
            '[[package]]\nname = "x"\nversion = "1"\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            parse_cargo_lock(self.lock)

    def test_duplicate_clarification_rejected(self) -> None:
        self.deny.write_text(
            '[licenses]\nallow = ["MIT"]\n'
            '[[licenses.clarify]]\nname = "pkg-b"\nexpression = "MIT"\n'
            '[[licenses.clarify]]\nname = "pkg-b"\nexpression = "MIT"\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            parse_deny_toml_licenses(self.deny)

    def test_repo_inventory_structural_check(self) -> None:
        repo = Path(__file__).resolve().parent.parent
        inv = build_license_inventory(repo / "Cargo.lock", repo / "deny.toml")
        self.assertGreater(inv["total_packages"], 50)
        self.assertIn("MIT", inv["allowed_licenses"])
        self.assertFalse(inv["license_audit_complete"])


if __name__ == "__main__":
    unittest.main()
