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
import shutil
import zipfile
from pathlib import Path

FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def safe_version(value: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if not value or any(char not in allowed for char in value):
        raise ValueError("version contains unsupported characters")
    return value


def build(args: argparse.Namespace) -> dict:
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    version = safe_version(args.version)
    bundle_name = f"kmj-omnidesk-{version}-{args.platform}-{args.arch}"
    staging = output / bundle_name
    if staging.exists():
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
        "platform": args.platform,
        "arch": args.arch,
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
