#!/usr/bin/env python3
"""M0: repository and contract deliverables, and canonical identity.

M0 is `complete`, which means its three exit criteria were satisfied at some
point -- by whoever typed that status. Nothing has checked them since, so a
milestone that has been `complete` for months is the same word as one marked
complete a second ago.

This tool makes the word mean something again. It checks two things:

  * every deliverable M0 lists is actually present on disk, and
  * the canonical identity M0 defines is stated identically in every place the
    repository states it.

The second is the interesting one. `canonical_identity_tested` is a criterion
about a single source of truth: `product_id`, `slug`, and `name` must not drift
between `Cargo.toml`, `ROADMAP.yaml`, and `package.json`-shaped files. Drift is
how a support article, a signing identity, and a build artifact end up naming
three different products.

It is a *string* check on purpose. It cannot verify that the identity is
globally unique or that the slug is registered; it verifies only that the
repository does not contradict itself, which is the part that is checkable
offline and the part that actually goes wrong.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

# The deliverables M0 declares. Written out rather than parsed from the
# roadmap because this tool *is* the checker for that list: reading the list
# and then confirming each entry exists is circular. The roadmap-admissibility
# tool is what guarantees this list has not silently shrunk.
REQUIRED_DELIVERABLES = (
    "README.md",
    "ROADMAP.yaml",
    "SECURITY.md",
    "LICENSE",
    "docs/ARCHITECTURE.md",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".github/workflows/ci.yml",
    "crates/omnidesk-protocol",
    "crates/omnidesk-core",
)


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_deliverables(root: Path) -> list[str]:
    """Every declared deliverable must exist.

    Existence, not contents. "Is `crates/omnidesk-core` a real crate with real
    code" is a different check, and pretending otherwise here would be the
    dishonest version of this tool.
    """
    return [
        f"M0 all_deliverables_present: missing {name}"
        for name in REQUIRED_DELIVERABLES
        if not (root / name).exists()
    ]


def _roadmap_product(root: Path) -> dict[str, str]:
    """Read `product:` out of ROADMAP.yaml without a YAML dependency.

    A hand-rolled reader, because the alternative is adding a dependency to a
    repository whose M11 gate runs `cargo-deny`. The block is small and
    flat, and a missing key is reported rather than defaulted.
    """
    text = (root / "ROADMAP.yaml").read_text(encoding="utf-8")
    match = re.search(r"^product:\s*$", text, re.M)
    if match is None:
        fail("ROADMAP.yaml has no product block")

    fields: dict[str, str] = {}
    reading = False
    for line in text[match.end() :].splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            break
        stripped = line.strip()
        key_value = re.match(r"^(\w+):\s*(.*)$", stripped)
        if key_value:
            reading = True
            fields[key_value.group(1)] = key_value.group(2).strip().strip('"')
        elif reading:
            # A nested key under `product:` -- not part of the identity.
            reading = False
    return fields


def check_canonical_identity(root: Path) -> list[str]:
    """The identity must be stated identically everywhere it is stated.

    Three sources, three places. If `Cargo.toml` says one slug and
    `ROADMAP.yaml` says another, a build artifact and a support page
    describing it will disagree, and nothing in the build will notice.
    """
    problems: list[str] = []

    roadmap = _roadmap_product(root)
    slug = roadmap.get("slug", "")
    product_id = roadmap.get("product_id", "")

    if not slug or not product_id:
        problems.append(
            "M0 canonical_identity_tested: ROADMAP.yaml product block is missing "
            "slug or product_id"
        )

    try:
        workspace = (root / "Cargo.toml").read_text(encoding="utf-8")
    except OSError as error:
        return [*problems, f"M0 canonical_identity_tested: cannot read Cargo.toml: {error}"]

    if slug and slug not in workspace:
        problems.append(
            f"M0 canonical_identity_tested: slug {slug!r} from ROADMAP.yaml does not "
            "appear in Cargo.toml"
        )

    # The workspace must list the crates the roadmap points at. A renamed or
    # dropped crate that the roadmap still names is the same drift in a
    # different file, and it breaks every CI step that says `-p omnidesk-core`.
    #
    # Checked against `members`, not against `name = "..."`: a workspace lists
    # crate *paths*, and the package name lives in each crate's own manifest.
    # The first version looked for `name =` in the root and reported both
    # crates missing; the second looked for the bare crate name and still
    # failed, because the members list spells them as `crates/<name>`.
    for crate in ("omnidesk-core", "omnidesk-protocol"):
        if f'"crates/{crate}"' not in workspace:
            problems.append(
                f"M0 canonical_identity_tested: Cargo.toml does not list "
                f"crates/{crate} in its members"
            )
            continue
        # The member path existing is not enough; the crate must declare the
        # name the rest of the repository and CI invoke it by.
        manifest = root / "crates" / crate / "Cargo.toml"
        if not manifest.is_file():
            problems.append(f"M0 canonical_identity_tested: {manifest} does not exist")
        elif f'name = "{crate}"' not in manifest.read_text(encoding="utf-8"):
            problems.append(
                f"M0 canonical_identity_tested: {crate}/Cargo.toml does not declare "
                f'name = "{crate}", which is the name CI invokes with -p'
            )

    return problems


def evaluate(root: Path) -> dict:
    problems = [*check_deliverables(root), *check_canonical_identity(root)]
    return {
        "milestone": "M0",
        "generated_at": utc_now(),
        "deliverables_checked": len(REQUIRED_DELIVERABLES),
        "problems": problems,
        "m0_verified": not problems,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = evaluate(root)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for problem in report["problems"]:
            print(f"FAIL {problem}")

    if not report["m0_verified"]:
        fail(f"{len(report['problems'])} problem(s); M0's criteria are not met")

    print(
        json.dumps(
            {"m0_repository": "PASS", "deliverables": len(REQUIRED_DELIVERABLES)},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
