#!/usr/bin/env python3
"""Fail-closed static contract for explicit user-run Zed Rust QA tasks."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARGS = (
    ["fmt", "--all", "--", "--check"],
    ["clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
    ["test", "--locked", "--workspace", "--all-targets", "--all-features"],
)
LABELS = (
    "KMJ OmniDesk · Rust format check",
    "KMJ OmniDesk · Rust Clippy (locked)",
    "KMJ OmniDesk · Rust tests (locked)",
)

def unique_keys(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate task field")
        result[k] = v
    return result

def validate(raw):
    tasks = json.loads(raw, object_pairs_hook=unique_keys)
    if not isinstance(tasks, list) or len(tasks) != 3:
        raise ValueError("expected exactly three explicit QA tasks")
    for idx, task in enumerate(tasks):
        expected = {
            "label": LABELS[idx],
            "command": "cargo.exe",
            "args": ARGS[idx],
            "cwd": "$ZED_WORKTREE_ROOT",
            "save": "none",
            "allow_concurrent_runs": False,
            "use_new_terminal": False,
        }
        if type(task) is not dict or task != expected:
            raise ValueError(f"task {idx + 1} differs from reviewed QA allowlist")
    return True

if __name__ == "__main__":
    validate((ROOT / ".zed" / "tasks.json").read_text(encoding="utf-8"))
    print("ZED_RUST_QA_TASKS=PASS_STATIC_ONLY")
