#!/usr/bin/env python3
"""Public check-shaped functions that nothing in the tree calls.

A `pub fn` with no caller and no test is not dead code by itself -- it can be
public API this workspace does not consume yet. What this reports is the
narrower case: functions whose *names* say they are checks (`is_*`, `validate`,
`reject`, `parse`, ...) and that nothing exercises.

Three real findings came out of running this by hand, and each was a
different kind of defect:

* `Permission::is_administrative` was documented as the mechanism that
  refuses self-escalation and was wired to nothing. The escalation rule is
  `Role::may_delegate`. Wiring the documented one in would have looked like
  closing the hole and would have stopped the only role that may legitimately
  delegate. A docstring claiming a check that does not exist is worse than no
  docstring, because it stops the next reader from looking.
* `DeviceTrust::is_managed` has no production caller. `ENTERPRISE_CONTROLS.md`
  records why: managed deployment has a direction and no deployment client.
  A documented limitation is not a gap -- but it was untested, so nothing
  would have noticed if `managed` had quietly become a trust input.
* `sha256_hex` had neither caller nor test, behind a docstring asserting what
  it computed.

## It does not fail the build

A candidate here is not a defect by itself, and the list changes as the crate
grows. It is a reading list. `test_find_unreferenced_checks.py` proves the
scanner sees what it claims to see; CI prints the list without gating on it,
because a tool that cries wolf gets ignored on the entries that are real.

One scanner bug is worth recording, because this project has been bitten by
its exact shape twice. The first version excluded a file's own text when
counting uses, so `reject_unexpected_executable` -- defined *and* called in
`update_path.rs` -- was reported as unreferenced. A check wired to no outcome
and a check wired to the wrong outcome both look like "nothing calls this",
and both are wrong answers from a tool that appears to be working.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "crates" / "omnidesk-core"

PUB_FN = re.compile(r"^\s*pub\s+(?:const\s+|async\s+|unsafe\s+)*fn\s+([a-z_0-9]+)")
TRAIT_FN = re.compile(r"^\s*fn\s+([a-z_0-9]+)\s*\(")

# Names that read like a check.
CHECKISH = re.compile(
    r"^(is_|has_|should_|can_|validate|verify|check|reject|refuse|parse|"
    r"sanitize|bounds?|clamp|expires?|allows?|permits?)",
    re.I,
)

# Derived or structural. Not checks, and their absence of callers is not news.
BORING = {"new", "default", "drop", "clone", "fmt", "into", "iter", "as_ref"}


def haystacks() -> list[Path]:
    files = [p for p in (CRATE / "src").rglob("*.rs") if "target" not in p.parts]
    tests = CRATE / "tests"
    if tests.is_dir():
        files += sorted(tests.glob("*.rs"))
    examples = CRATE / "examples"
    if examples.is_dir():
        files += sorted(examples.glob("*.rs"))
    return files


def candidates() -> list[dict[str, str]]:
    texts: dict[Path, str] = {}
    for path in haystacks():
        try:
            texts[path] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

    found: list[dict[str, str]] = []
    for path, text in texts.items():
        if path.name.endswith("tests.rs"):
            continue
        defined = set(PUB_FN.findall(text)) | set(TRAIT_FN.findall(text))
        if not defined:
            continue

        # This file's own text with its definition lines removed, so a use in
        # the same file still counts. Excluding the whole file is the bug
        # described in the module docstring.
        self_text = "\n".join(
            line
            for line in text.splitlines()
            if not PUB_FN.match(line) and not TRAIT_FN.match(line)
        )
        elsewhere = "\n".join(t for p, t in texts.items() if p != path)

        for name in sorted(defined):
            if name in BORING or not CHECKISH.match(name):
                continue
            pattern = rf"\b{re.escape(name)}\s*[(:<!]"
            uses = len(re.findall(pattern, elsewhere)) + len(
                re.findall(pattern, self_text)
            )
            if uses == 0:
                rel = path.relative_to(ROOT).as_posix()
                found.append({"path": rel, "name": name})
    return found


def main() -> int:
    found = candidates()
    print(
        json.dumps(
            {"unreferenced_checks": len(found), "entries": found}, indent=2
        )
    )
    if found:
        print(
            f"\n{len(found)} check-shaped function(s) with no caller and no test.",
            "\nThis is a reading list, not a failure: see the module docstring",
            "\nfor the three defects it found and why it is not a build gate.",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())