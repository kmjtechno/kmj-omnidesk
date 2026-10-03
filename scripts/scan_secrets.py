#!/usr/bin/env python3
"""Fails the build when a credential-shaped string is committed.

SECURITY.md already forbids production credentials, signing keys and client
master secrets in this repository, but that rule was previously stated
policy with nothing enforcing it. This script makes it a gate.

Design notes:

* Detection is deliberately conservative about *where* a pattern counts.
  Protocol test vectors legitimately contain public keys, a published
  TEST-ONLY private seed, and placeholder identifiers, so those paths are
  excluded rather than the whole pattern being weakened.
* Any match fails the run. There is no allowlist suppression flag, because a
  suppression flag is how secret scanners quietly stop working.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Paths that hold published test material. These are reviewed and public by
# design; excluding them keeps the scanner from flagging the very vectors the
# licensing conformance gate depends on.
EXCLUDED_PREFIXES = (
    "protocol/licensing/test-vectors/",
    "fuzz/corpus/",
    "fuzz/artifacts/",
    "fuzz/target/",
    "target/",
)

# (compiled pattern, label). Each pattern targets a specific secret class
# rather than a generic "long string", which would be unusable.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key block",
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ),
    (
        "AWS access key id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "Slack token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "JSON web token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "hardcoded bearer credential",
        re.compile(r"[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}"),
    ),
)

SCANNED_SUFFIXES = {
    ".rs",
    ".py",
    ".js",
    ".ts",
    ".json",
    ".sh",
    ".yml",
    ".yaml",
    ".toml",
    ".md",
    ".env",
    ".txt",
}

# Files whose whole purpose is to contain credential-shaped samples.
SKIPPED_NAMES = {"scan_secrets.py", "test_scan_secrets.py"}


def is_excluded(relative: Path) -> bool:
    posix = relative.as_posix()
    return any(posix.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def iter_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if is_excluded(relative) or relative.name in SKIPPED_NAMES:
            continue
        if path.suffix.lower() in SCANNED_SUFFIXES or path.name.startswith(".env"):
            files.append(path)
    return sorted(files)


def main() -> int:
    findings: list[str] = []
    for path in iter_files():
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Binary or unreadable files are out of scope for a text scan.
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            for label, pattern in RULES:
                if pattern.search(line):
                    relative = path.relative_to(ROOT).as_posix()
                    findings.append(f"{relative}:{line_number}: {label}")
    if findings:
        print("secret scan: FAILED", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nRemove the credential and rotate it if it was ever real. "
            "Do not add a suppression flag.",
            file=sys.stderr,
        )
        return 1
    print("secret scan: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())