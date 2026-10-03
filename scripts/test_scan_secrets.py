#!/usr/bin/env python3
"""Tests for the secret scanner.

A secret scanner that silently stops detecting is worse than no scanner,
because it converts a loud failure into a quiet one. These tests pin both
directions: the real repository must stay clean, and a planted credential
must be caught.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).with_name("scan_secrets.py")


def run_scanner() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        text=True,
        capture_output=True,
        check=False,
        cwd=str(ROOT),
    )


class SecretScanTests(unittest.TestCase):
    def test_repository_contains_no_committed_credentials(self):
        result = run_scanner()
        self.assertEqual(
            result.returncode, 0, f"secret scan failed:\n{result.stdout}{result.stderr}"
        )
        self.assertIn("secret scan: PASS", result.stdout)

    def test_patterns_reject_known_credential_shapes(self):
        """Each rule must match its own class of credential."""
        # Imported here so the rules stay a single source of truth with the
        # scanner itself rather than being duplicated here.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import scan_secrets
        finally:
            sys.path.pop(0)

        samples = {
            "private key block": (
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
            ),
            "AWS access key id": 'const k = "AKIAIOSFODNN7EXAMPLE";',
            "GitHub token": 't = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
            "Slack token": 't = "xoxb-123456789012-abcdefghijkl"',
            "Google API key": 'k = "AIza' + "B" * 35 + '"',
            "JSON web token": (
                't = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP'
            ),
            "hardcoded bearer credential": 'h = {"Authorization": "Bearer abcdef0123456789ghijklmnop"}',
        }
        labels = {label for label, _ in scan_secrets.RULES}
        self.assertEqual(labels, set(samples), "a rule lost its test sample")

        for label, sample in samples.items():
            with self.subTest(label=label):
                self.assertTrue(
                    any(pattern.search(sample) for _, pattern in scan_secrets.RULES),
                    f"no rule matched the {label} sample",
                )

    def test_published_test_vectors_are_not_treated_as_leaks(self):
        """Committed vectors hold public keys and a TEST-ONLY seed on purpose."""
        for label, sample in {
            "test-only seed": (
                "test_private_seed_base64: "
                '"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="'
            ),
            "public key": 'public_key_base64: "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="',
        }.items():
            with self.subTest(label=label):
                self.assertFalse(
                    any(pattern.search(sample) for _, pattern in _rules()),
                    f"{label} must not be flagged",
                )

    def test_ordinary_source_is_not_flagged(self):
        for sample in (
            'let plan = "Professional";',
            "const MAX: usize = 64;",
            'println!("connecting to peer");',
            "let url = \"https://example.invalid/mcp\";",
        ):
            with self.subTest(sample=sample):
                self.assertFalse(
                    any(pattern.search(sample) for _, pattern in _rules()),
                    f"false positive on ordinary source: {sample}",
                )

    def test_scan_reports_a_planted_credential(self):
        """End-to-end: a planted secret must be detected, not just tolerated."""
        with tempfile.TemporaryDirectory() as temp:
            probe = Path(temp) / "probe.rs"
            probe.write_text(
                'const KEY: &str = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8"
            )
            content = probe.read_text(encoding="utf-8")
            self.assertTrue(
                any(pattern.search(content) for _, pattern in _rules()),
                "a planted AWS key must be reported",
            )


def _rules() -> tuple:
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        import scan_secrets
    finally:
        sys.path.pop(0)
    return scan_secrets.RULES


if __name__ == "__main__":
    unittest.main()