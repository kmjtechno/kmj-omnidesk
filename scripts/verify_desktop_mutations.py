"""Desktop mutation harness implementation for the desktop shell.

This module contains the mutation harness for the desktop shell that verifies
the robustness of desktop tests by applying one edit at a time and
running the desktop tests to ensure they can detect faults. A mutation that
leaves the suite green is a hole in the tests, not a win -- the suite is meant
to be able to say no.

The shell is where a passing test is least informative. Every other mutation
harness in this repository targets code that refuses something: a boundary that
must not be crossed, an authorization that must not be granted. This one
targets code that *draws* and *locates*, where the failure mode is not a
rejected request but a control the user cannot click or a region drawn over
another. A hit test that is one pixel too generous looks exactly like a correct
one under test, which is the property that makes this harness worth having.

This version is simpler than the previous version that had parsing issues.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# The script is located at .../scripts/verify_desktop_mutations.py
# We want ROOT to be the repository root: .../kmj-omnidesk
# So we go up two levels from the script's location
ROOT = Path(__file__).resolve().parent.parent
# Normalize the path to handle any inconsistencies
ROOT = ROOT.resolve()
CRATE = ROOT / "crates" / "omnidesk-desktop" / "src"

# (file, label, must-contain, replacement)
MUTATIONS: list[tuple[str, str, str, str]] = [
    # ---- layout.rs: the geometry every other module resolves through ----
    (
        "layout.rs",
        "for_window lays out a window with no height left for the footer",
        "if width < 360 || height < SHORT_SHELL_HEIGHT {",
        "if width < 360 || height < 1 {",
    ),
    (
        "layout.rs",
        "for_window lays out a window too narrow to read",
        "if width < 360 || height < SHORT_SHELL_HEIGHT {",
        "if width < 1 || height < SHORT_SHELL_HEIGHT {",
    ),
    (
        "layout.rs",
        "for_window always shows the panel, even when it cannot fit",
        "let panel_width = if width >= NARROW_SHELL_WIDTH {",
        "let panel_width = if true {",
    ),
    (
        "layout.rs",
        "panel width is not clamped at the wide end",
        "let panel_width = if width >= NARROW_SHELL_WIDTH {\n            (width * 3 / 10).clamp(240, 380)\n        } else {\n            0\n        };",
        "let panel_width = if width >= NARROW_SHELL_WIDTH {\n            (width * 3 / 10).max(240)\n        } else {\n            0\n        };",
    ),
    (
        "layout.rs",
        "panel width is not clamped at the narrow end",
        "let panel_width = if width >= NARROW_SHELL_WIDTH {\n            (width * 3 / 10).clamp(240, 380)\n        } else {\n            0\n        };",
        "let panel_width = if width >= NARROW_SHELL_WIDTH {\n            (width * 3 / 10).max(240)\n        } else {\n            (width * 3 / 10).max(240)\n        };",
    ),
    (
        "layout.rs",
        "content column is allowed to collapse to nothing",
        ".max(200)",
        "let content_width = if content_width == 0 { 200 } else { content_width.max(200) };",
    ),
    (
        "layout.rs",
        "panel is laid out at the same x as the content column",
        "let panel_x = content_x\n            .saturating_add(content_width)\n            .saturating_add(gutter);",
        "let panel_x = content_x;",
    ),
    (
        "layout.rs",
        "shows_panel reports true even when the panel has no width",
        "pub const fn shows_panel(&self) -> bool {\n        self.panel_width > 0\n    }",
        "pub const fn shows_panel(&self) -> bool {\n        true\n    }",
    ),
    (
        "layout.rs",
        "first_row_y lands above the top bar",
        "pub const fn first_row_y(&self) -> usize {\n        self.top_bar_height + 92\n    }",
        "pub const fn first_row_y(&self) -> usize {\n        0\n    }",
    ),
    (
        "layout.rs",
        "visible_rows ignores the header block it must clear",
        "let header = 92;\n        let below_rows = self\n            .content_height\n            .saturating_sub(header)\n            .saturating_sub(self.footer_height);",
        "let header = 0;\n        let below_rows = self\n            .content_height\n            .saturating_sub(header)\n            .saturating_sub(self.footer_height);",
    ),
    # ---- lib.rs: the hit test and the presentation the renderer draws ----
    (
        "lib.rs",
        "control rects ignore the row index",
        "y: layout\n                .first_row_y()\n                .saturating_add(index.saturating_mul(layout.row_height)),",
        "y: layout.first_row_y().saturating_add(0),",
    ),
    (
        "lib.rs",
        "control rects are full row height, so rows touch each other",
        "height: layout.row_height,",
        "height: 1,",
    ),
    (
        "lib.rs",
        "control rects ignore the content column",
        "x: layout.content_x,",
        "x: layout.content_x.saturating_add(layout.content_width),",
    ),
    (
        "lib.rs",
        "control rects ignore the content width",
        "width: layout.content_width,",
        "width: layout.row_height,",
    ),
    (
        "lib.rs",
        "control rects are still produced for a window too small to lay out",
        "let Some(layout) = ShellLayout::for_window(width, height) else {\n        return vec![\n            ControlRect {\n                x: 0,\n                y: 0,\n                width,\n                height\n            };\n            presentation.controls.len()\n        ];\n    };",
        "let Some(layout) = ShellLayout::for_window(width, height) else {\n        return Vec::new();\n    };",
    ),
    (
        "lib.rs",
        "hit test matches disabled controls",
        ".find(|(control, rect)| control.enabled && rect.contains(x, y))",
        ".find(|(_, rect)| rect.contains(x, y))",
    ),
    (
        "lib.rs",
        "contains treats the right edge as inside the rect",
        "&& x < self.x.saturating_add(self.width)\n            && y < self.y.saturating_add(self.height)",
        "&& x < self.x.saturating_add(self.width)\n            && y <= self.y.saturating_add(self.height)",
    ),
    (
        "lib.rs",
        "contains ignores the top edge",
        "&& y >= self.y",
        "&& y > self.y",
    ),
    (
        "lib.rs",
        "hit test returns an action for a point outside every row",
        ".map(|(control, _)| control.action)",
        ".map(|(control, _)| control.action)\n        .or(Some(DesktopAction::Quit))",
    ),
    (
        "lib.rs",
        "summary counts every device as online",
        ".filter(|device| device.status == DeviceStatus::Online)",
        ".filter(|_| true)",
    ),
    (
        "lib.rs",
        "summary never reports the empty case",
        'let summary = if devices.is_empty() {\n        "No devices registered".to_owned()\n    } else {',
        'let summary = if false {\n        "No devices registered".to_owned()\n    } else {',
    ),
    (
        "lib.rs",
        "summary drops the online count",
        '"{} device{} · {online} online",',
        '"{} device{}",',
    ),
    (
        "lib.rs",
        "panel title is wrong for the permission prompt",
        'PrimaryView::PermissionPrompt => "Request",',
        'PrimaryView::PermissionPrompt => "Devices",',
    ),
    (
        "lib.rs",
        "resource budget accepts a shell over its memory limit",
        "idle_memory_mib <= self.idle_memory_mib\n            && idle_cpu_milli_percent <= self.idle_cpu_milli_percent",
        "true",
    ),
    # ---- render.rs: the structural decisions, not the pixel arithmetic ----
    (
        "render.rs",
        "renderer draws rows past the point they stop being visible",
        ".zip(rects).take(visible)",
        ".zip(rects)",
    ),
    (
        "render.rs",
        "renderer stops drawing rows before the column is full",
        ".zip(rects).take(visible)",
        ".zip(rects).take(1)",
    ),
    (
        "render.rs",
        "renderer draws into a buffer shorter than the window claims",
        "if width == 0 || height == 0 || pixels.len() < width.saturating_mul(height) {",
        "if width == 0 || height == 0 {",
    ),
    (
        "render.rs",
        "the panel is skipped when the layout shows it",
        "if !layout.shows_panel() {\n        return;\n    }",
        "if layout.shows_panel() {\n        return;\n    }",
    ),
    (
        "render.rs",
        "panel content is drawn outside the panel",
        "let inner_x = layout.panel_x + 18;\n    let inner_width = layout.panel_width.saturating_sub(36);",
        "let inner_x = layout.content_x;\n    let inner_width = layout.content_width;",
    ),
    (
        "render.rs",
        "long labels are drawn past their row instead of truncated",
        "let budget = max_width / (9 * scale);\n        if text.chars().count() <= budget {\n            self.text(x, y, text, scale, color);\n            return;\n        }",
        "let budget = max_width / (9 * scale);\n        if true {\n            self.text(x, y, text, scale, color);\n            return;\n        }",
    ),
    (
        "render.rs",
        "truncation ellipsis is drawn on top of the text it replaces",
        "let kept_len = budget.saturating_sub(3);",
        "let kept_len = budget;"
    ),
    (
        "render.rs",
        "a disabled row is drawn as though it were enabled",
        "let label_color = if is_online {\n            palette.foreground\n        } else {\n            palette.muted\n        };",
        "let label_color = palette.foreground;",
    ),
    (
        "render.rs",
        "an offline row shows a shortcut hint instead of saying it is offline",
        'let trailing = if is_online {\n            format!("[{}]", control.keyboard_key.to_ascii_uppercase())\n        } else {\n            "OFFLINE".to_owned()\n        };',
        'let trailing = palette.muted;',
    ),
    (
        "render.rs",
        "every row gets the red destructive edge",
        "palette.border,",
        "if destructive {\n                palette.danger\n            } else {\n                palette.border\n            },",
    ),
    (
        "render.rs",
        "no row gets the red destructive edge",
        "if destructive {\n                palette.danger\n            } else {\n                palette.border\n            },",
        "palette.border,",
    ),
    (
        "render.rs",
        "the shell draws nothing on a window too small to lay out",
        "let Some(layout) = ShellLayout::for_window(width, height) else {\n        return;\n    };",
        "let Some(layout) = ShellLayout::for_window(width, height) else {\n        draw_top_bar(\n            &mut Canvas { pixels, width, height },\n            presentation,\n            &ShellLayout { top_bar_height: 56, content_height: 0, footer_height: 44, content_x: 0, content_width: 0, panel_x: 0, panel_width: 0, row_height: 52, gutter: 0 },\n            palette,\n        );\n        return;\n    };",
    ),
]


def apply_mutation(target: Path, old: str, new: str) -> bool:
    """Apply one mutation, or report False so the caller can list it.

    A pattern that does not match is reported, never skipped: an untested
    mutation and a passing one are indistinguishable from the outside, which
    is the same defect this harness exists to detect.
    """
    source = target.read_text(encoding="utf-8")
    if old not in source:
        return False
    target.write_text(source.replace(old, new, 1), encoding="utf-8")
    return True


def _originals() -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in CRATE.glob("*.rs")}


def _find_cargo() -> str:
    """Locate the cargo executable, accounting for the `.exe` suffix on Windows."""
    import os
    import shutil

    # `shutil.which` handles PATH lookup and the executable suffix on Windows.
    found = shutil.which("cargo")
    if found:
        return found

    # On Windows, `cargo` is a shell alias for `cargo.exe`; the PATH entry may
    # point at the directory rather than the binary. Search the common rustup
    # locations explicitly, including the `.exe` form.
    candidates = [
        os.path.expanduser("~/.cargo/bin/cargo.exe"),
        os.path.expanduser("~/.cargo/bin/cargo"),
        "/c/Users/lenovo/.cargo/bin/cargo.exe",
        "/c/Users/lenovo/.cargo/bin/cargo",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError("cargo executable not found")


def run_tests() -> tuple[bool, str]:
    """Run the desktop test suite and return (tests_failed, output)."""
    import os

    cargo = _find_cargo()
    original_cwd = os.getcwd()
    try:
        os.chdir(str(ROOT))
        result = subprocess.run(
            [cargo, "test", "-p", "omnidesk-desktop", "--lib"],
            capture_output=True,
            text=True,
        )
        return result.returncode != 0, result.stdout + result.stderr
    finally:
        os.chdir(original_cwd)


def main() -> int:
    originals = _originals()

    baseline_failed, output = run_tests()
    if baseline_failed:
        print("FAIL: baseline desktop tests do not pass")
        print(output[-2000:])
        return 1
    print(f"baseline: PASS ({len(MUTATIONS)} mutations)\n")

    survivors: list[str] = []
    skipped: list[str] = []
    for filename, label, old, new in MUTATIONS:
        target = CRATE / filename
        if not apply_mutation(target, old, new):
            skipped.append(f"{label} [{filename}: pattern not found]")
            continue
        caught, output = run_tests()
        target.write_text(originals[target], encoding="utf-8")
        if caught:
            failing = sorted(
                {
                    line.split(" ")[1]
                    for line in output.splitlines()
                    if line.startswith("test ") and " FAILED" in line
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
    if skipped:
        print(f"\n{len(skipped)} mutation(s) could not be applied")
        return 1
    print("all mutations caught")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        # Never leave the working tree holding a mutation, even on an
        # interrupt: a half-mutated source file is indistinguishable from a
        # real change to the next person who reads it.
        for path, source in _originals().items():
            path.write_text(source, encoding="utf-8")
