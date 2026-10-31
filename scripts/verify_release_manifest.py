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
import os
import re
import stat
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
# Windows DOS device names remain reserved even with ordinary extensions.
# The release verifier runs on multiple hosts, so reject these for Windows
# manifests *before* consulting the host filesystem (Linux can create them).
WINDOWS_RESERVED_ARTIFACT_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


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


def _reject_duplicate_manifest_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse ambiguous JSON keys, including inside artifacts and cleanup."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"manifest contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_manifest(path: Path) -> Manifest:
    """Parse a release manifest.

    Raises ValueError on a structurally invalid manifest. A malformed manifest
    is a hard failure, never a partial load: a manifest that parses with
    missing fields would let absent data satisfy a check.
    """
    raw = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_manifest_keys,
    )
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")

    # If this is a candidate bundle wrapper with {"manifest": {...}}, unwrap it.
    if "manifest" in raw and isinstance(raw["manifest"], dict) and (
        "version" in raw["manifest"] or "version_code" in raw["manifest"]
    ):
        raw = raw["manifest"]

    platform = raw.get("platform")
    if "target_platform" in raw and isinstance(raw["target_platform"], str):
        if raw["target_platform"] in PLATFORMS:
            platform = raw["target_platform"]
    elif isinstance(platform, str) and platform not in PLATFORMS and "arch" in raw:
        combo = f"{platform}-{raw['arch']}"
        if combo in PLATFORMS:
            platform = combo

    if "version" not in raw and "version_code" not in raw:
        raise ValueError("manifest is missing required keys: version")
    for key in ("channel", "minimum_client_version"):
        if key not in raw:
            raise ValueError(f"manifest is missing required keys: {key}")
    if platform is None:
        raise ValueError("manifest is missing required keys: platform")

    version_raw = (
        raw.get("version_code")
        if isinstance(raw.get("version_code"), int) and not isinstance(raw.get("version_code"), bool)
        else raw.get("version")
    )
    if isinstance(version_raw, str):
        try:
            version = int(version_raw)
        except ValueError:
            parts = version_raw.split("-")[0].split(".")
            if len(parts) >= 1 and all(p.isdigit() for p in parts):
                ints = [int(p) for p in parts]
                if len(ints) == 3:
                    version = ints[0] * 10000 + ints[1] * 100 + ints[2]
                elif len(ints) == 1:
                    version = ints[0]
                else:
                    version = ints[0] * 100 + ints[1]
            else:
                raise ValueError(
                    f"version must be a positive integer or valid semver, got {version_raw!r}"
                )
    elif isinstance(version_raw, int) and not isinstance(version_raw, bool):
        version = version_raw
    else:
        raise ValueError(f"version must be a positive integer, got {version_raw!r}")

    if version < 1:
        raise ValueError(f"version must be a positive integer, got {version!r}")

    minimum = raw["minimum_client_version"]
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        raise ValueError(
            f"minimum_client_version must be a positive integer, got {minimum!r}"
        )

    raw_artifacts = raw.get("artifacts", {})
    if isinstance(raw_artifacts, list):
        artifacts: dict[str, str] = {}
        for entry in raw_artifacts:
            if not isinstance(entry, dict) or "name" not in entry or "sha256" not in entry:
                raise ValueError(
                    "artifacts list entries must be objects with name and sha256"
                )
            name = entry["name"]
            if not isinstance(name, str):
                raise ValueError(f"artifact name must be a string, got {name!r}")
            if name in artifacts:
                raise ValueError(f"duplicate artifact name {name!r}")
            digest = entry["sha256"]
            if not isinstance(digest, str):
                raise ValueError(f"artifact sha256 must be a string, got {digest!r}")
            artifacts[name] = digest
    elif isinstance(raw_artifacts, dict):
        artifacts = raw_artifacts
    else:
        raise ValueError(
            "artifacts must be an object mapping name to digest or list of artifact objects"
        )

    cleanup = raw.get("cleanup", {})
    if not isinstance(cleanup, dict) or any(
        not isinstance(plat, str)
        or not isinstance(targets, list)
        or any(not isinstance(target, str) for target in targets)
        for plat, targets in cleanup.items()
    ):
        raise ValueError("cleanup must map platforms to lists of entry names")

    verifier = raw.get("signature_verified_by")
    if verifier is not None and not isinstance(verifier, str):
        raise ValueError("signature_verified_by must be a string when present")

    return Manifest(
        version=version,
        channel=raw["channel"],
        platform=platform,
        minimum_client_version=minimum,
        artifacts=artifacts,
        signature_verified_by=verifier,
        cleanup=cleanup,
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
    """U4: require real, explicitly named artifacts with verified SHA-256 digests.

    Artifact names are single safe filenames, not paths. Refusing absolute paths,
    traversal, separators, and symlinks prevents a manifest from using files
    outside the selected artifact directory as supposed release evidence.
    """
    violations: list[Violation] = []
    if not manifest.artifacts:
        return [Violation("U4", "release manifest lists no artifacts")]

    # Windows filesystems are ordinarily case-insensitive. Two distinct JSON
    # keys can therefore refer to one installed filename even if a Linux
    # verifier sees two separate files. Reject ambiguity before file access.
    if isinstance(manifest.platform, str) and manifest.platform.startswith("windows-"):
        seen_windows_names: dict[str, str] = {}
        for name in manifest.artifacts:
            if not isinstance(name, str):
                continue
            folded = name.casefold()
            previous = seen_windows_names.get(folded)
            if previous is not None:
                return [
                    Violation(
                        "U4",
                        f"ambiguous Windows artifact filenames {previous!r} and {name!r}",
                    )
                ]
            seen_windows_names[folded] = name

    # Reject a redirected *directory*, not only redirected artifact files.
    # Otherwise a valid digest in a symlinked artifact directory can attest
    # an unrelated tree. Check before resolving any supplied path.
    if ".." in artifacts_dir.parts:
        return [Violation("U4", "artifact directory parent traversal is forbidden")]
    selected = artifacts_dir.absolute()
    if not selected.is_dir():
        return [Violation("U4", "artifact directory is not an existing directory")]
    # Snapshot every ancestor's identity. Checking reparse flags only once
    # permits a directory to be replaced after preflight but before file open.
    # Recheck after hashing; this detects persistent substitutions without
    # claiming race-free directory handles on Windows.
    directory_components = []
    for component in (selected, *selected.parents):
        try:
            metadata = component.lstat()
            reparse = bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            is_junction = getattr(component, "is_junction", lambda: False)
            if component.is_symlink() or is_junction() or reparse:
                return [
                    Violation("U4", f"redirected artifact directory component: {component}")
                ]
            if not stat.S_ISDIR(metadata.st_mode):
                return [Violation("U4", f"artifact directory component is not a directory: {component}")]
            directory_components.append((component, metadata.st_dev, metadata.st_ino))
        except OSError as error:
            return [
                Violation("U4", f"cannot inspect artifact directory component {component}: {error}")
            ]

    for name, expected in sorted(
        manifest.artifacts.items(), key=lambda item: str(item[0])
    ):
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
            or name.endswith(".")
        ):
            violations.append(
                Violation("U4", f"unsafe artifact filename {name!r}")
            )
            continue
        if (
            isinstance(manifest.platform, str)
            and manifest.platform.startswith("windows-")
            and name.split(".", 1)[0].upper() in WINDOWS_RESERVED_ARTIFACT_STEMS
        ):
            violations.append(
                Violation("U4", f"{name} is a reserved Windows device name")
            )
            continue
        if not isinstance(expected, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected
        ):
            violations.append(
                Violation("U4", f"{name} has an invalid SHA-256 digest")
            )
            continue

        artifact = selected / name
        # lstat, unlike is_file(), does not follow the final path component.
        # Refuse Windows reparse files and multiply-linked files as well as
        # POSIX symlinks. A release artifact must be an unshared regular file.
        try:
            metadata = artifact.lstat()
        except FileNotFoundError:
            violations.append(
                Violation("U4", f"{name} is listed in the manifest but is not present")
            )
            continue
        except OSError as error:
            violations.append(Violation("U4", f"{name} cannot be inspected: {error}"))
            continue
        reparse = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        if stat.S_ISLNK(metadata.st_mode) or reparse:
            violations.append(
                Violation("U4", f"{name} is a symbolic link or reparse point, not a release artifact")
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            violations.append(Violation("U4", f"{name} is not a regular release artifact"))
            continue
        if metadata.st_nlink != 1:
            violations.append(
                Violation("U4", f"{name} has {metadata.st_nlink} hard links; release artifacts must be unshared")
            )
            continue

        digest = hashlib.sha256()
        try:
            # Open without following the final symlink where supported. O_NONBLOCK
            # prevents a swapped-in FIFO from hanging the release verifier.
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(artifact, flags)
            with os.fdopen(descriptor, "rb") as handle:
                opened = os.fstat(handle.fileno())
                # Bind the bytes being hashed to the exact file inspected by
                # lstat, not merely a pathname an attacker may have replaced.
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or bool(
                        getattr(opened, "st_file_attributes", 0)
                        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                    )
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                ):
                    violations.append(
                        Violation("U4", f"{name} changed between inspection and open")
                    )
                    continue
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                after_read = os.fstat(handle.fileno())
                if (
                    after_read.st_size != opened.st_size
                    or after_read.st_mtime_ns != opened.st_mtime_ns
                    or after_read.st_ctime_ns != opened.st_ctime_ns
                ):
                    violations.append(
                        Violation("U4", f"{name} changed while being hashed")
                    )
                    continue
            # Detect a rename or path substitution during the read. This is
            # defense in depth, not a claim of race-free Windows directory IO.
            after_path = artifact.lstat()
            if (
                after_path.st_dev != opened.st_dev
                or after_path.st_ino != opened.st_ino
                or not stat.S_ISREG(after_path.st_mode)
                or after_path.st_nlink != 1
                or bool(
                    getattr(after_path, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
            ):
                violations.append(
                    Violation("U4", f"{name} changed after opening for hashing")
                )
                continue
            # A swapped directory containing identical artifact bytes is not
            # the tree that was admitted by the original provenance preflight.
            directory_changed = False
            for component, original_dev, original_ino in directory_components:
                current = component.lstat()
                current_reparse = bool(
                    getattr(current, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or current_reparse
                    or component.is_symlink()
                    or getattr(component, "is_junction", lambda: False)()
                    or current.st_dev != original_dev
                    or current.st_ino != original_ino
                ):
                    directory_changed = True
                    break
            if directory_changed:
                violations.append(
                    Violation("U4", f"{name} artifact directory changed during verification")
                )
                continue
        except OSError as error:
            violations.append(
                Violation("U4", f"{name} cannot be read: {error}")
            )
            continue
        actual = digest.hexdigest()
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
    if not isinstance(manifest.signature_verified_by, str) or not manifest.signature_verified_by.strip():
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

    # Cleanup for another architecture cannot prove that this build's updater
    # and autostart entries are removed. The manifest platform must be covered.
    if not isinstance(manifest.platform, str) or manifest.platform not in manifest.cleanup:
        violations.append(
            Violation("U8", f"cleanup omits manifest platform {manifest.platform!r}")
        )

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
    pre_signing: bool = False,
) -> list[Violation]:
    """Run every check this script can run offline."""
    violations: list[Violation] = []
    if not pre_signing:
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
    parser.add_argument(
        "--pre-signing",
        action="store_true",
        help="verify all pre-signing integrity properties on unsigned candidates (defers U1 signature check)",
    )
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
        pre_signing=args.pre_signing,
    )

    if violations:
        print(
            f"release-integrity: {len(violations)} violation(s)", file=sys.stderr
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    mode_label = "PRE-SIGNING OK (signature check deferred)" if args.pre_signing else "OK"
    print(
        f"release-integrity: {mode_label} (manifest v{manifest.version}, "
        f"{manifest.channel}/{manifest.platform}, "
        f"{len(manifest.artifacts)} artifact(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())