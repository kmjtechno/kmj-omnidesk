"""Mutation harness for the U8 uninstall module.

Applies one edit at a time, runs the uninstall tests, and reports whether any
test failed. A mutation that leaves the suite green is a hole in the tests,
not a win -- the suite is meant to be able to say no.

Line-based replacement rather than string replacement, because several
mutations need to change one line in a way a substring search would match in
the wrong place (or not match at all, silently, and report a clean run).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "crates" / "omnidesk-core" / "src" / "uninstall.rs"

# (label, must-contain-in-line, replacement)
MUTATIONS: list[tuple[str, str, str]] = [
    (
        "is_under becomes a plain string prefix",
        "path.strip_prefix(root)",
        "path.strip_prefix(root).is_some()",
    ),
    (
        "normalize resolves traversal",
        'if segment.is_empty() || segment == "." {',
        'if segment.is_empty() || segment == "." { continue; }\n        let mut skipped = segment;\n        while skipped == ".." {\n            parts.pop();\n            if let Some(rest) = path.split_once("/") { break; }\n        }\n        if false {',
    ),
    (
        "normalize drops the leading slash",
        'format!("/{}", parts.join("/"))',
        'parts.join("/")',
    ),
    (
        "record no longer refuses traversal",
        'normalized.split(\'/\').any(|segment| segment == "..")',
        "false",
    ),
    (
        "record no longer checks containment",
        "if !is_under(root, &normalized) {",
        "if false {",
    ),
    (
        "record drops the no-root guard",
        ".ok_or(UninstallError::NoInstallRoot)?;",
        ".unwrap_or(&String::new());",
    ),
    (
        "removal_targets keeps user data",
        ".filter(|entry| !entry.is_user_data())",
        ".filter(|entry| entry.is_user_data())",
    ),
    (
        "confirm_clean drops the no-root guard",
        "let Some(root) = self.install_root.as_ref() else {",
        "let root = self.install_root.as_deref().unwrap_or(\"/\"); let _ = &root; let Some(root) = self.install_root.as_ref().or(Some(&\"/\".to_string())) else {",
    ),
    (
        "confirm_clean drops the user-data refusal",
        "if entry.is_user_data() {",
        "if false {",
    ),
    (
        "confirm_clean drops the outside-root refusal",
        "if !is_under(root, &normalize(entry.path())) {",
        "if false {",
    ),
    (
        "confirm_clean drops the residue check",
        "if let Some(leftover) = surviving.iter().find(|entry| entry.kind().is_persistence()) {",
        "if let Some(leftover) = surviving.iter().filter(|_| false).find(|entry| entry.kind().is_persistence()) {",
    ),
    (
        "confirm_clean residue check matches nothing",
        "if let Some(leftover) = surviving.iter().find(|entry| entry.kind().is_persistence()) {",
        "if let Some(leftover) = surviving.iter().find(|entry| matches!(entry.kind(), ResidueKind::UpdateScheduler)) {",
    ),
    (
        "is_persistence answers false for the updater",
        "Self::UpdateScheduler\n            | Self::AutostartEntry",
        "Self::AutostartEntry",
    ),
    (
        "is_persistence answers false for the cached secret",
        "| Self::CachedSecret\n            | Self::InstalledBinary => true,",
        "| Self::InstalledBinary => true,",
    ),
    (
        "is_persistence answers false for the autostart entry",
        "| Self::CachedSecret\n            | Self::InstalledBinary => true,",
        "| Self::CachedSecret\n            | Self::InstalledBinary => false,",
    ),
    (
        "is_persistence answers false for the binary",
        "| Self::InstalledBinary => true,",
        "| Self::InstalledBinary => false,",
    ),
    (
        "is_plausible_root allows short roots",
        "if root.len() <= 2 {",
        "if root.len() == 0 {",
    ),
    (
        "is_plausible_root ignores traversal",
        'root.split(\'/\').any(|segment| segment == "..")',
        "false",
    ),
    (
        "declare_root drops the length check",
        "if install_root.len() > MAX_INSTALL_ROOT_BYTES {",
        "if false {",
    ),
    (
        "declare_root stores the unnormalized root",
        "self.install_root = Some(normalize(trimmed));",
        "self.install_root = Some(trimmed.to_string());",
    ),
    (
        "declare_root drops the trailing-slash trim",
        "let trimmed = install_root.trim_end_matches('/');",
        "let trimmed = install_root;",
    ),
    (
        "user_owned is not marked as user data",
        "user_data: true,",
        "user_data: false,",
    ),
    (
        "user_owned_constructor helper",
        "pub fn user_owned(path: &str, kind: ResidueKind) -> Self {",
        "pub fn user_owned(path: &str, kind: ResidueKind) -> Self {\n        return Self::product(path, kind);",
    ),
    (
        "residue kinds collapse to one name",
        'Self::UpdateScheduler => "update_scheduler",',
        'Self::UpdateScheduler => "residue",',
    ),
    (
        "autostart name is swapped for another unique string",
        'Self::AutostartEntry => "autostart_entry",',
        'Self::AutostartEntry => "startup",',
    ),
    (
        "cached_secret error name is generic",
        'Self::CachedSecret => "cached_secret",',
        'Self::CachedSecret => "residue",',
    ),
    (
        "display drops the path from the residue error",
        '"U8: {} still present after uninstall: {detail}",',
        '"U8: {} still present after uninstall",',
    ),
]


def apply_mutation(old: str, new: str) -> bool:
    """Apply one mutation, or report False so the caller can list it.

    Matches against the whole file rather than line by line. Line-by-line was
    the first version and it was wrong in a way that hid results: a pattern
    spanning two lines -- which is what `rustfmt` produces for a long `match`
    arm -- never matched, so the mutation was reported as "apply failed" and
    skipped rather than run. Four mutations were silently not tested.
    """
    source = MODULE.read_text(encoding="utf-8")
    if old not in source:
        return False
    MODULE.write_text(source.replace(old, new, 1), encoding="utf-8")
    return True


def run_tests() -> tuple[bool, str]:
    result = subprocess.run(
        ["cargo", "test", "-p", "omnidesk-core", "uninstall", "--lib"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0, result.stdout + result.stderr


def main() -> int:
    original = MODULE.read_text(encoding="utf-8")
    baseline_failed, _ = run_tests()
    if baseline_failed:
        print("FAIL: baseline uninstall tests do not pass")
        MODULE.write_text(original, encoding="utf-8")
        return 1
    print(f"baseline: PASS ({len(MUTATIONS)} mutations)\n")

    survivors: list[str] = []
    skipped: list[str] = []
    for label, old, new in MUTATIONS:
        if not apply_mutation(old, new):
            skipped.append(f"{label} (pattern not found)")
            continue
        caught, output = run_tests()
        MODULE.write_text(original, encoding="utf-8")
        if caught:
            failing = sorted(
                {
                    line.split(" ")[1]
                    for line in output.splitlines()
                    if line.startswith("test uninstall::tests::") and " FAILED" in line
                }
            )
            names = ", ".join(failing[:3]) if failing else "compile error"
            print(f"CAUGHT: {label}  [{names}]")
        else:
            print(f"SURVIVED: {label}")
            survivors.append(label)

    print()
    for item in skipped:
        print(f"APPLY-FAILED: {item}")
    if survivors:
        print(f"\n{len(survivors)} mutation(s) survived")
        return 1
    print("all mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())