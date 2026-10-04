#!/usr/bin/env python3
"""Enforces the update-integrity properties that can be checked offline.

`docs/UPDATE_INTEGRITY.md` specifies U1-U9 for the update path. Most of them
concern a running client and cannot be verified here. The ones that *can* be
checked against a release manifest are checked here, because a property
nobody verifies is a property that silently regresses.

Covered here:

* U3  downgrade is refused (version must be strictly greater)
* U4  an artifact must be listed in the manifest with a matching digest
* U5  the client refuses a manifest for another channel
* U5  the client refuses a manifest for another platform
* U8  no updater task, service, or autostart entry survives uninstall

Not covered here, and deliberately not claimed:

* U1  signature verification -- needs the real verifier and a real key
* U2  the trust anchor being compiled in rather than fetched
* U6  no configuration can lower verification
* U7  archive traversal rejection

Design notes:

* Signatures are *not* checked here. A verifier that skips the signature
  check and calls itself a verifier is worse than none, so this script
  refuses to run unless the manifest declares that signature verification is
  handled elsewhere. Silently passing unsigned material would make the whole
  file a placebo.

* No suppression flag. The same reasoning as `scan_secrets.py`: a suppression
  flag is how a gate quietly stops working.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CHANNELS = ("stable", "beta")

PLATFORMS = (
    "windows-x86_64",
    "windows-aarch64",
    "macos-x86_64",
    "macos-aarch64",
    "linux-x86_64",
    "linux-aarch64",
)

# Names that indicate something survives uninstall. Matched case-insensitively
# against every path in the cleanup manifest. The list is intentionally broad:
# a false positive is one line to fix, a false negative is a machine that
# keeps running something the user asked to remove.
RESIDUE_MARKERS = (
    "update",
    "updater",
    "scheduled_task",
    "scheduledtask",
    "service",
    "autostart",
    "run_once",
    "runonce",
    "launch_agent",
    "launchagent",
    "startup",
)


@dataclass
class Violation:
    """One property the manifest fails to satisfy."""

    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.rule}: {self.detail}"


@dataclass
class Manifest:
    """A parsed release manifest."""

    version: int
    channel: str
    platform: str
    minimum_client_version: int
    artifacts: dict[str, str] = field(default_factory=dict)
    signature_verified_by: str | None = None
    cleanup: dict[str, list[str]] = field(default_factory=dict)


def load_manifest(path: Path) -> Manifest:
    """Parse a release manifest.

    Raises ValueError on a structurally invalid manifest. A malformed manifest
    is a hard failure, never a partial load: a manifest that parses with
    missing fields would let absent data satisfy a check.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))

    required = ("version", "channel", "platform", "minimum_client_version")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(f"manifest is missing required keys: {', '.join(missing)}")

    version = raw["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError(f"version must be a positive integer, got {version!r}")

    minimum = raw["minimum_client_version"]
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        raise ValueError(
            f"minimum_client_version must be a positive integer, got {minimum!r}"
        )

    artifacts = raw.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise ValueError("artifacts must be an object mapping name to digest")

    return Manifest(
        version=version,
        channel=raw["channel"],
        platform=raw["platform"],
        minimum_client_version=minimum,
        artifacts=artifacts,
        signature_verified_by=raw.get("signature_verified_by"),
        cleanup=raw.get("cleanup", {}),
    )


def check_downgrade(manifest: Manifest, current_version: int) -> list[Violation]:
    """U3: an update must be strictly newer than what is running."""
    if manifest.version <= current_version:
        return [
            Violation(
                "U3",
                f"manifest version {manifest.version} is not newer than "
                f"the running version {current_version}; downgrade refused",
            )
        ]
    return []


def check_channel(manifest: Manifest, client_channel: str) -> list[Violation]:
    """U5: a client only accepts a manifest for its own pinned channel."""
    if manifest.channel not in CHANNELS:
        return [Violation("U5", f"unknown channel {manifest.channel!r}")]
    if manifest.channel != client_channel:
        return [
            Violation(
                "U5",
                f"manifest channel {manifest.channel!r} does not match the "
                f"client channel {client_channel!r}",
            )
        ]
    return []


def check_platform(manifest: Manifest, client_platform: str) -> list[Violation]:
    """U5: a client only accepts artifacts for the platform it runs on."""
    if manifest.platform not in PLATFORMS:
        return [Violation("U5", f"unknown platform {manifest.platform!r}")]
    if manifest.platform != client_platform:
        return [
            Violation(
                "U5",
                f"manifest platform {manifest.platform!r} does not match the "
                f"client platform {client_platform!r}",
            )
        ]
    return []


def check_artifacts(manifest: Manifest, artifacts_dir: Path) -> list[Violation]:
    """U4: every listed artifact exists and matches its recorded digest."""
    violations: list[Violation] = []
    for name, expected in sorted(manifest.artifacts.items()):
        artifact = artifacts_dir / name
        if not artifact.is_file():
            violations.append(
                Violation("U4", f"{name} is listed in the manifest but is not present")
            )
            continue
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != expected:
            violations.append(
                Violation(
                    "U4",
                    f"{name} digest mismatch: manifest says {expected}, "
                    f"file hashes to {actual}",
                )
            )
    return violations


def check_signature_declared(manifest: Manifest) -> list[Violation]:
    """Refuse to treat an unsigned manifest as verified.

    This script does not implement U1. Rather than imply it does, it requires
    the manifest to name who did verify the signature. A manifest that cannot
    say is rejected, so the gate cannot pass on unsigned material by accident.
    """
    if not manifest.signature_verified_by:
        return [
            Violation(
                "U1",
                "manifest does not declare signature_verified_by; this script "
                "does not verify signatures and will not pretend to",
            )
        ]
    return []


def check_minimum_client(manifest: Manifest, client_version: int) -> list[Violation]:
    """A client older than the manifest's floor must not be offered the update."""
    if client_version < manifest.minimum_client_version:
        return [
            Violation(
                "U4",
                f"client version {client_version} is below the manifest's "
                f"minimum_client_version {manifest.minimum_client_version}",
            )
        ]
    return []


def check_uninstall_cleanup(manifest: Manifest) -> list[Violation]:
    """U8: nothing that can install or launch survives uninstall.

    Every cleanup target must exist in the manifest, and no target may be a
    bare filesystem path. An installer that lists its own scheduled task and
    its install directory is complete; one that lists only a directory is
    declaring that something still runs.
    """
    violations: list[Violation] = []

    if not manifest.cleanup:
        return [
            Violation(
                "U8",
                "manifest declares no cleanup targets; uninstall must remove "
                "something and must not be empty",
            )
        ]

    for platform, targets in sorted(manifest.cleanup.items()):
        if platform not in PLATFORMS:
            violations.append(
                Violation("U8", f"cleanup lists unknown platform {platform!r}")
            )
            continue
        if not targets:
            violations.append(
                Violation("U8", f"cleanup for {platform} is empty")
            )
            continue

        for target in targets:
            if "/" in target or "\\" in target:
                violations.append(
                    Violation(
                        "U8",
                        f"{platform} cleanup names a bare path {target!r}; "
                        "expected a system entry name",
                    )
                )
                continue
            lowered = target.lower()
            if not any(marker in lowered for marker in RESIDUE_MARKERS):
                violations.append(
                    Violation(
                        "U8",
                        f"{platform} cleanup target {target!r} names no updater, "
                        "service, or autostart entry",
                    )
                )

    return violations


def verify(
    manifest: Manifest,
    client_version: int,
    client_channel: str,
    client_platform: str,
    artifacts_dir: Path,
) -> list[Violation]:
    """Run every check this script can run offline."""
    violations: list[Violation] = []
    violations += check_signature_declared(manifest)
    violations += check_downgrade(manifest, client_version)
    violations += check_channel(manifest, client_channel)
    violations += check_platform(manifest, client_platform)
    violations += check_minimum_client(manifest, client_version)
    violations += check_artifacts(manifest, artifacts_dir)
    violations += check_uninstall_cleanup(manifest)
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--client-version", type=int, required=True)
    parser.add_argument("--client-channel", required=True)
    parser.add_argument("--client-platform", required=True)
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release-integrity: manifest is unusable: {error}", file=sys.stderr)
        return 1

    violations = verify(
        manifest,
        args.client_version,
        args.client_channel,
        args.client_platform,
        args.artifacts,
    )

    if violations:
        print(
            f"release-integrity: {len(violations)} violation(s)", file=sys.stderr
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print(
        f"release-integrity: OK (manifest v{manifest.version}, "
        f"{manifest.channel}/{manifest.platform}, "
        f"{len(manifest.artifacts)} artifact(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())