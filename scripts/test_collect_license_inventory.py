#!/usr/bin/env python3
"""Unit tests for collect_license_inventory.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from collect_license_inventory import (
    build_license_inventory,
    check_for_viral_copyleft,
    parse_cargo_lock,
    parse_deny_toml_licenses,
)


class TestLicenseInventory(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_parse_cargo_lock(self) -> None:
        lock = self.root / "Cargo.lock"
        lock.write_text(
            """
[[package]]
name = "pkg-a"
version = "1.0.0"

[[package]]
name = "pkg-b"
version = "2.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
        )
        pkgs = parse_cargo_lock(lock)
        self.assertEqual(len(pkgs), 2)
        self.assertEqual(pkgs[0]["name"], "pkg-a")
        self.assertEqual(pkgs[1]["version"], "2.1.0")

    def test_parse_deny_toml(self) -> None:
        deny = self.root / "deny.toml"
        deny.write_text(
            """
[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "MPL-2.0",
]

[[licenses.clarify]]
name = "ring"
expression = "MIT AND ISC AND OpenSSL"
"""
        )
        policy = parse_deny_toml_licenses(deny)
        self.assertIn("MIT", policy["allow"])
        self.assertIn("MPL-2.0", policy["allow"])
        self.assertEqual(policy["clarifications"].get("ring"), "MIT AND ISC AND OpenSSL")

    def test_viral_copyleft_detected(self) -> None:
        self.assertTrue(check_for_viral_copyleft("GPL-3.0-only"))
        self.assertTrue(check_for_viral_copyleft("AGPL-3.0"))
        self.assertTrue(check_for_viral_copyleft("LGPL-2.1-or-later"))
        self.assertFalse(check_for_viral_copyleft("MIT OR Apache-2.0"))
        self.assertFalse(check_for_viral_copyleft("MPL-2.0"))
        self.assertFalse(check_for_viral_copyleft("BSD-3-Clause"))

    def test_build_inventory_rejects_gpl(self) -> None:
        lock = self.root / "Cargo.lock"
        lock.write_text('[[package]]\nname = "gpl-pkg"\nversion = "1.0.0"\n')
        deny = self.root / "deny.toml"
        deny.write_text(
            """
[licenses]
allow = ["MIT"]
[[licenses.clarify]]
name = "gpl-pkg"
expression = "GPL-3.0-only"
"""
        )
        with self.assertRaises(ValueError):
            build_license_inventory(lock, deny)

    def test_repo_inventory_passes(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        lock = repo_root / "Cargo.lock"
        deny = repo_root / "deny.toml"
        inventory = build_license_inventory(lock, deny)
        self.assertGreater(inventory["total_packages"], 50)
        self.assertIn("MIT", inventory["allowed_licenses"])


if __name__ == "__main__":
    unittest.main()
