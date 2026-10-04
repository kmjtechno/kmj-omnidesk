#!/usr/bin/env python3
"""Proves `find_unreferenced_checks.py` sees what it claims to see.

The scanner's job is to report functions nothing calls. Its failure mode is
the dangerous kind: reporting a function that *is* called makes it look like
a tool that works, and the next real finding gets discounted along with the
noise.

So the suite below is mostly about the ways it was wrong.

## Naming the file

The biggest gap was structural: a function called only in its own file. The
first version excluded the defining file from its use count, which is right
for "does another module call this" and wrong for "does anything call this".
It reported `reject_unexpected_executable` -- defined and called two hundred
lines apart in `update_path.rs` -- as unreferenced. The probe name is built
at run time so this file never supplies the string it searches for.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    """Import the scanner with `scripts/` on the path.

    The name is assembled so this file does not contain the literal it is
    testing for.
    """
    target = ROOT / "scripts" / ("find_unreferenced_" + "checks.py")
    spec = importlib.util.spec_from_file_location("unreferenced_scanner", target)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f"cannot load {target}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scanner = _load()


class TestScannerSeesItsOwnTree(unittest.TestCase):
    def test_a_function_this_suite_calls_is_not_reported(self):
        """The named function is used by the test tree, so it is not a gap."""
        names = {entry["name"] for entry in scanner.candidates()}
        self.assertNotIn(
            "verify_and_parse",
            names,
            "verify_and_parse is called from update_path tests; reporting it "
            "means the scanner cannot count uses",
        )

    def test_every_real_candidate_has_been_resolved(self):
        """The list is empty.

        Not "the remaining ones look fine" -- empty. Each of the three the
        scanner found was resolved: `is_administrative` and `is_managed` by
        tests, `sha256_hex` in an earlier pass. A non-empty list here would
        mean this suite had stopped being read.
        """
        found = scanner.candidates()
        self.assertEqual(
            found,
            [],
            "unreferenced checks have appeared:\n"
            + "\n".join(f"  {e['path']}::{e['name']}" for e in found),
        )


class TestScannerCountsSameFileUses(unittest.TestCase):
    """The bug that reported a called function as uncalled."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _scanner_for(self, root: Path):
        """A scanner instance pointed at a synthetic crate."""
        scanner.ROOT = root
        scanner.CRATE = root / "crates" / "omnidesk-core"
        return scanner

    def test_a_function_called_in_its_own_file_is_not_reported(self):
        src = self.root / "crates" / "omnidesk-core" / "src"
        src.mkdir(parents=True)
        module = src / ("probe_" + "unreferenced_check.rs")
        module.write_text(
            "pub fn validate_thing() -> bool {\n"
            "    true\n"
            "}\n"
            "\n"
            "pub fn caller() -> bool {\n"
            "    validate_thing()\n"
            "}\n",
            encoding="utf-8",
        )
        found = self._scanner_for(self.root).candidates()
        self.assertEqual(found, [], "a same-file call must count")

    def test_a_function_nothing_calls_is_reported(self):
        src = self.root / "crates" / "omnidesk-core" / "src"
        src.mkdir(parents=True)
        module = src / ("probe_" + "unreferenced_check.rs")
        module.write_text(
            "pub fn verify_thing() -> bool {\n    true\n}\n",
            encoding="utf-8",
        )
        found = self._scanner_for(self.root).candidates()
        self.assertEqual(
            [e["name"] for e in found],
            ["verify_thing"],
            "an uncalled check must be reported",
        )

    def test_a_call_from_a_test_file_counts(self):
        src = self.root / "crates" / "omnidesk-core" / "src"
        src.mkdir(parents=True)
        (src / ("probe_" + "unreferenced_check.rs")).write_text(
            "pub fn verify_thing() -> bool {\n    true\n}\n", encoding="utf-8"
        )
        tests = self.root / "crates" / "omnidesk-core" / "tests"
        tests.mkdir(parents=True)
        (tests / "probe_test.rs").write_text(
            "fn t() { assert!(super::verify_thing()); }\n", encoding="utf-8"
        )
        found = self._scanner_for(self.root).candidates()
        self.assertEqual(found, [], "a test call must count as a use")

    def test_a_function_named_like_a_check_is_in_scope_and_one_that_is_not_is_not(self):
        src = self.root / "crates" / "omnidesk-core" / "src"
        src.mkdir(parents=True)
        (src / ("probe_" + "unreferenced_check.rs")).write_text(
            "pub fn is_trustworthy() -> bool {\n    true\n}\n"
            "pub fn helper_name() -> bool {\n    true\n}\n",
            encoding="utf-8",
        )
        found = self._scanner_for(self.root).candidates()
        self.assertEqual(
            [e["name"] for e in found],
            ["is_trustworthy"],
            "only check-shaped names belong in the reading list",
        )


class TestScannerExitsCleanOnRealTree(unittest.TestCase):
    def test_main_reports_zero_and_exits_zero(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = scanner.main()
        self.assertEqual(code, 0)
        self.assertIn('"unreferenced_checks": 0', buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)