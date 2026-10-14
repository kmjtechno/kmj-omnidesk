#!/usr/bin/env python3
"""Build a deterministic unsigned KMJ OmniDesk release-candidate bundle.

This script never signs or publishes a release. It packages already-built bytes,
records their digest, and marks the result UNSIGNED_CANDIDATE so downstream
release gates cannot confuse CI packaging evidence with a production release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(value: str, label: str) -> str:
    """Reject directory separators, traversal, shell controls, and ambiguous labels."""
    if not SAFE_COMPONENT.fullmatch(value) or value.endswith("."):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def safe_version(value: str) -> str:
    return safe_component(value, "version")


def build(args: argparse.Namespace) -> dict:
    binary = Path(args.binary).resolve(strict=True)
    version = safe_version(args.version)
    platform = safe_component(args.platform, "platform")
    arch = safe_component(args.arch, "arch")
    if not binary.is_file() or binary.stat().st_size == 0:
        raise ValueError("binary must be a non-empty regular file")
    if platform == "windows" and binary.suffix.lower() != ".exe":
        raise ValueError("Windows release candidate must use an .exe binary")

    output = Path(args.output).resolve()
    bundle_name = f"kmj-omnidesk-{version}-{platform}-{arch}"
    staging = output / bundle_name
    # Never delete the source payload when rebuilding the same candidate.
    if binary.is_relative_to(staging):
        raise ValueError("binary cannot be inside the candidate staging directory")
    output.mkdir(parents=True, exist_ok=True)
    if staging.exists():
        if staging.is_symlink() or not staging.is_dir():
            raise ValueError("candidate staging path must be a real directory")
        shutil.rmtree(staging)
    staging.mkdir()

    packaged_binary = staging / binary.name
    shutil.copy2(binary, packaged_binary)

    manifest = {
        "schema_version": 1,
        "product_id": "KMJ_OMNIDESK",
        "product_slug": "kmj-omnidesk",
        "version": version,
        "channel": args.channel,
        "platform": platform,
        "arch": arch,
        "release_state": "UNSIGNED_CANDIDATE",
        "publishable": False,
        "signature_declared": False,
        "artifacts": [
            {
                "name": packaged_binary.name,
                "sha256": sha256(packaged_binary),
                "size_bytes": packaged_binary.stat().st_size,
                "signature_declared": False,
            }
        ],
    }
    manifest_path = staging / "release-candidate-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    archive = output / f"{bundle_name}.zip"
    if archive.exists():
        archive.unlink()

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_dir():
                continue
            relative = Path(bundle_name) / path.relative_to(staging)
            info = zipfile.ZipInfo(relative.as_posix(), FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, path.read_bytes())

    result = {
        "bundle": archive.name,
        "bundle_sha256": sha256(archive),
        "bundle_size_bytes": archive.stat().st_size,
        "manifest": manifest,
    }
    (output / f"{bundle_name}.bundle.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--binary", required=True)
    value.add_argument("--output", required=True)
    value.add_argument("--version", required=True)
    value.add_argument("--platform", default="windows")
    value.add_argument("--arch", default="x86_64")
    value.add_argument("--channel", choices=["stable", "beta"], default="beta")
    return value


def main() -> None:
    args = parser().parse_args()
    result = build(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
