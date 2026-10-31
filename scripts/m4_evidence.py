#!/usr/bin/env python3
"""M4 REALNET-60 evidence collection helpers.

This tool never manufactures run outcomes. It only prepares run directories,
hashes real files, emits strict artifact entries, and produces package checksums.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

RUN_ID = re.compile(r"^M4-T[1-6]-R[0-9]{2,}$")
KINDS = {
    "RUN_JSON",
    "EVENT_LOG",
    "CANDIDATE_LOG",
    "NETWORK_DIAGNOSTIC",
    "CONTROL_PROBE",
    "RECONNECT_LOG",
    "BUILD_METADATA",
    "SUMMARY",
    "CSV",
    "OTHER",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def validate_run_id(value: str) -> str:
    if not RUN_ID.fullmatch(value):
        fail(f"invalid run_id: {value}")
    return value


def safe_relative(root: Path, file_path: Path) -> tuple[Path, Path]:
    root = root.resolve()
    if file_path.is_symlink():
        fail("symlink artifacts are forbidden")
    resolved = file_path.resolve(strict=True)
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        fail("artifact escapes package root")
    if ".." in relative.parts:
        fail("artifact path traversal is forbidden")
    return resolved, relative


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def checked_evidence_root(value: str) -> Path:
    """Refuse redirected package roots before reading or creating evidence.

    resolve() alone follows a supplied root symlink (or a symlinked ancestor),
    which could make an external tree look like this run's evidence package.
    """
    supplied = Path(value)
    if ".." in supplied.parts:
        fail("parent traversal in evidence root forbidden")
    absolute = supplied.absolute()
    for component in (absolute, *absolute.parents):
        is_junction = getattr(component, "is_junction", lambda: False)
        if component.is_symlink() or is_junction():
            fail(f"symlinked evidence root path forbidden: {component}")
    return absolute.resolve()


def command_prepare_run(args: argparse.Namespace) -> None:
    run_id = validate_run_id(args.run_id)
    root = checked_evidence_root(args.root)
    # A clean package root does not make a redirected child safe. Without
    # this check, a pre-existing runs/ symlink or Windows junction sends
    # prepare-run's mkdir outside the evidence package.
    runs_root = root / "runs"
    is_junction = getattr(runs_root, "is_junction", lambda: False)
    if runs_root.is_symlink() or is_junction():
        fail(f"redirected runs directory forbidden: {runs_root}")
    if runs_root.exists() and not runs_root.is_dir():
        fail(f"runs path is not a directory: {runs_root}")
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    print(run_dir)


def command_artifact(args: argparse.Namespace) -> None:
    run_id = validate_run_id(args.run_id)
    if args.kind not in KINDS:
        fail(f"unsupported artifact kind: {args.kind}")
    root = checked_evidence_root(args.root)
    resolved, relative = safe_relative(root, Path(args.file))
    # A run-scoped artifact must actually belong to the named run. Merely
    # hashing a file elsewhere in the package lets a manifest claim that an
    # unrelated run supplied the observation. Global artifacts use run_id=null
    # in the manifest and are not produced by this run-scoped subcommand.
    # Check the object type first: a run directory itself is not a valid
    # artifact, even when it is the declared run directory.
    if not resolved.is_file():
        fail("artifact must be a regular file")
    if len(relative.parts) < 3 or relative.parts[:2] != ("runs", run_id):
        fail("artifact is not inside its declared run directory")
    checksum, size = sha256_file(resolved)
    created_at = args.created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entry = {
        "artifact_id": args.artifact_id,
        "run_id": run_id,
        "kind": args.kind,
        "relative_path": relative.as_posix(),
        "content_type": args.content_type,
        "size_bytes": size,
        "sha256": checksum,
        "created_at": created_at,
        "producer": {"component": args.component, "version": args.version},
        "immutable": True,
    }
    print(json.dumps(entry, indent=2, sort_keys=True))


def command_checksums(args: argparse.Namespace) -> None:
    root = checked_evidence_root(args.root)
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        # Check links *before* directories: is_dir() follows directory
        # symlinks and otherwise silently omits them from the package digest.
        if path.is_symlink():
            fail(f"symlink forbidden: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"non-regular evidence path forbidden: {path}")
        relative = path.resolve(strict=True).relative_to(root)
        if relative.as_posix() == "checksums.sha256":
            continue
        digest, _ = sha256_file(path)
        rows.append(f"{digest}  {relative.as_posix()}")
    print("\n".join(rows))


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="KMJ OmniDesk M4 REALNET-60 evidence helper")
    sub = value.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare-run", help="create a clean run evidence directory")
    prepare.add_argument("--root", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.set_defaults(func=command_prepare_run)

    artifact = sub.add_parser("artifact", help="hash a real artifact and emit its manifest entry")
    artifact.add_argument("--root", required=True)
    artifact.add_argument("--file", required=True)
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--run-id", required=True)
    artifact.add_argument("--kind", required=True, choices=sorted(KINDS))
    artifact.add_argument("--content-type", required=True)
    artifact.add_argument("--component", required=True)
    artifact.add_argument("--version", required=True)
    artifact.add_argument("--created-at")
    artifact.set_defaults(func=command_artifact)

    checksums = sub.add_parser("checksums", help="emit deterministic SHA-256 package checksum lines")
    checksums.add_argument("--root", required=True)
    checksums.set_defaults(func=command_checksums)
    return value


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
