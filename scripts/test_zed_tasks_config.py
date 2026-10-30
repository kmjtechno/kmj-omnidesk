#!/usr/bin/env python3
"""Negative checks for fixed explicit Zed QA tasks."""
import copy
import json
import unittest
from check_zed_tasks_config import validate

BASE = [
    {
        "label": label,
        "command": "cargo.exe",
        "args": args,
        "cwd": "$ZED_WORKTREE_ROOT",
        "save": "none",
        "allow_concurrent_runs": False,
        "use_new_terminal": False,
    }
    for label, args in zip(
        ("KMJ OmniDesk · Rust format check",
         "KMJ OmniDesk · Rust Clippy (locked)",
         "KMJ OmniDesk · Rust tests (locked)"),
        (["fmt", "--all", "--", "--check"],
         ["clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
         ["test", "--locked", "--workspace", "--all-targets", "--all-features"]),
    )
]

class ZedTaskTests(unittest.TestCase):
    def test_good(self):
        self.assertTrue(validate(json.dumps(BASE)))

    def test_deny_unsafe_variants(self):
        changes = [
            (0, "command", "powershell.exe"),
            (0, "hooks", ["create_worktree"]),
            (1, "args", ["clippy", "--workspace"]),
            (2, "cwd", "C:\\"),
            (2, "allow_concurrent_runs", True),
            (2, "save", "all"),
            (2, "env", {"TOKEN": "not-allowed"}),
        ]
        for index, field, value in changes:
            with self.subTest(field=field, index=index):
                tasks = copy.deepcopy(BASE)
                tasks[index][field] = value
                with self.assertRaises(ValueError):
                    validate(json.dumps(tasks))

    def test_deny_extra_task(self):
        with self.assertRaises(ValueError):
            validate(json.dumps(BASE + [BASE[0]]))

    def test_deny_duplicate_json_field(self):
        with self.assertRaises(ValueError):
            validate('[{"command":"cargo.exe","command":"cmd.exe"}]')

if __name__ == "__main__":
    unittest.main()
