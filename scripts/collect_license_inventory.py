#!/usr/bin/env python3
"""Generate a lockfile/package inventory without inventing third-party licenses.

Cargo.lock contains package identities, not SPDX licenses.  deny.toml contains
policy and selected clarifications, not a complete upstream license inventory.
The independent cargo-deny CI action performs actual license policy evaluation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROHIBITED = re.compile(r"(?<![A-Za-z0-9])(?:AGPL|GPL|LGPL|SSPL)(?:[-. ]|$)", re.I)


def parse_cargo_lock(lock_path: Path) -> list[dict[str, str]]:
    if not lock_path.is_file():
        raise FileNotFoundError(f"Cargo.lock not found: {lock_path}")
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo.lock contains no package entries")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            raise ValueError("Invalid Cargo.lock package entry")
        name, version, source = pkg.get("name"), pkg.get("version"), pkg.get("source", "")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError("Cargo.lock package lacks name or version")
        if not isinstance(source, str):
            raise ValueError("Cargo.lock package source is invalid")
        key = (name, version, source)
        if key in seen:
            raise ValueError(f"Duplicate Cargo.lock package identity: {name} {version}")
        seen.add(key)
        result.append({"name": name, "version": version, "source": source})
    return result


def parse_deny_toml_licenses(deny_path: Path) -> dict[str, object]:
    if not deny_path.is_file():
        raise FileNotFoundError(f"deny.toml not found: {deny_path}")
    data = tomllib.loads(deny_path.read_text(encoding="utf-8"))
    licenses = data.get("licenses")
    if not isinstance(licenses, dict) or not isinstance(licenses.get("allow"), list):
        raise ValueError("deny.toml lacks licenses.allow policy")
    allowed = licenses["allow"]
    if not all(isinstance(x, str) and x for x in allowed):
        raise ValueError("Invalid licenses.allow policy")
    clarifications: dict[str, str] = {}
    for item in licenses.get("clarify", []):
        if not isinstance(item, dict):
            raise ValueError("Invalid license clarification")
        name, expression = item.get("name"), item.get("expression")
        if not isinstance(name, str) or not name or not isinstance(expression, str) or not expression:
            raise ValueError("Incomplete license clarification")
        if name in clarifications:
            raise ValueError(f"Duplicate license clarification: {name}")
        clarifications[name] = expression
    return {"allow": allowed, "clarifications": clarifications}


def check_for_viral_copyleft(license_str: str) -> list[str]:
    return [license_str] if PROHIBITED.search(license_str) else []


def build_license_inventory(lock_path: Path, deny_path: Path) -> dict[str, object]:
    packages = parse_cargo_lock(lock_path)
    policy = parse_deny_toml_licenses(deny_path)
    clarifications = policy["clarifications"]
    assert isinstance(clarifications, dict)
    entries: list[dict[str, object]] = []
    unverified = 0
    for pkg in packages:
        # Clarifications are operator policy assertions, not independent
        # verification of a crate's upstream SPDX license.
        expression = clarifications.get(pkg["name"])
        if expression is not None and check_for_viral_copyleft(expression):
            raise ValueError(f"Prohibited license policy clarification for {pkg['name']}")
        if expression is None:
            unverified += 1
        entries.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "source": pkg["source"],
            "license": expression,  # null when Cargo.lock has no license evidence
            "license_status": "policy_clarification_only" if expression else "unknown",
        })
    return {
        "product": "KMJ OmniDesk",
        "total_packages": len(entries),
        "total_third_party": sum(bool(p["source"]) for p in packages),
        "license_source": "deny.toml clarifications only; Cargo.lock has no SPDX metadata",
        "license_audit_complete": False,
        "unknown_license_count": unverified,
        "requires_independent_cargo_deny": True,
        "allowed_licenses": policy["allow"],
        "packages": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Honest Cargo.lock identity inventory")
    parser.add_argument("--cargo-lock", type=Path, default=REPO_ROOT / "Cargo.lock")
    parser.add_argument("--deny-toml", type=Path, default=REPO_ROOT / "deny.toml")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="Validate inventory structure; cargo-deny separately audits licenses")
    args = parser.parse_args()
    try:
        inventory = build_license_inventory(args.cargo_lock, args.deny_toml)
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        print(
            f"Lockfile inventory: {inventory['total_packages']} packages; "
            f"{inventory['unknown_license_count']} without license metadata. "
            "NOT a license clearance; run independent cargo-deny and legal review."
        )
        return 0
    except (OSError, ValueError, TypeError, tomllib.TOMLDecodeError) as exc:
        print(f"Lockfile inventory FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
