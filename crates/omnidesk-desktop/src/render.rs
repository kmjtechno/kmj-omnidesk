use font8x8::{BASIC_FONTS, UnicodeFonts};

use crate::{LockedDashboardLayout, PresentationModel, ShellLayout, control_rects_for};

#[must_use]
pub const fn packed_rgb(rgb: [u8; 3]) -> u32 {
    (rgb[0] as u32) << 16 | (rgb[1] as u32) << 8 | rgb[2] as u32
}

struct Canvas<'a> {
    pixels: &'a mut [u32],
    width: usize,
    height: usize,
}

impl Canvas<'_> {
    fn fill_rect(&mut self, x: usize, y: usize, rect_width: usize, rect_height: usize, color: u32) {
        let max_x = x.saturating_add(rect_width).min(self.width);
        let max_y = y.saturating_add(rect_height).min(self.height);
        for py in y.min(self.height)..max_y {
            let row = py * self.width;
            for px in x.min(self.width)..max_x {
                self.pixels[row + px] = color;
            }
        }
    }

    /// A hairline separator. Drawn as a filled rectangle because the canvas
    /// has no per-pixel alpha, so a 1px line is a 1px fill.
    fn h_line(&mut self, x: usize, y: usize, line_width: usize, color: u32) {
        self.fill_rect(x, y, line_width, 1, color);
    }

    fn stroke_rect(
        &mut self,
        x: usize,
        y: usize,
        rect_width: usize,
        rect_height: usize,
        thickness: usize,
        color: u32,
    ) {
        self.fill_rect(x, y, rect_width, thickness, color);
        self.fill_rect(
            x,
            y.saturating_add(rect_height.saturating_sub(thickness)),
            rect_width,
            thickness,
            color,
        );
        self.fill_rect(x, y, thickness, rect_height, color);
        self.fill_rect(
            x.saturating_add(rect_width.saturating_sub(thickness)),
            y,
            thickness,
            rect_height,
            color,
        );
    }

    /// Pixel width `text` occupies at `scale`.
    fn text_width(text: &str, scale: usize) -> usize {
        text.chars().count().saturating_mul(9).saturating_mul(scale)
    }

    /// Draws `text`, truncating with an ellipsis when it would run past
    /// `max_width`.
    ///
    /// A label drawn past its row's edge is drawn over the neighbouring
    /// region, which reads as a rendering fault rather than as a long name.
    fn text_clipped(
        &mut self,
        x: usize,
        y: usize,
        text: &str,
        scale: usize,
        max_width: usize,
        color: u32,
    ) {
        if max_width == 0 {
            return;
        }
        let budget = max_width / (9 * scale);
        if text.chars().count() <= budget {
            self.text(x, y, text, scale, color);
            return;
        }
        if budget <= 3 {
            return;
        }
        let kept: String = text.chars().take(budget - 3).collect();
        let kept_width = Self::text_width(&kept, scale);
        self.text(x, y, &kept, scale, color);
        self.text(x + kept_width, y, "...", scale, color);
    }

    /// Right-aligned text, used for status values and shortcut hints.
    fn text_right(&mut self, right_edge: usize, y: usize, text: &str, scale: usize, color: u32) {
        let width = Self::text_width(text, scale);
        self.text(right_edge.saturating_sub(width), y, text, scale, color);
    }

    fn text(&mut self, x: usize, y: usize, text: &str, scale: usize, color: u32) {
        let mut cursor_x = x;
        for character in text.chars() {
            let glyph_character = character.to_ascii_uppercase();
            if let Some(glyph) = BASIC_FONTS.get(glyph_character) {
                for (row, bits) in glyph.iter().enumerate() {
                    for column in 0..8 {
                        if bits & (1 << column) != 0 {
                            self.fill_rect(
                                cursor_x + column * scale,
                                y + row * scale,
                                scale,
                                scale,
                                color,
                            );
                        }
                    }
                }
            }
            cursor_x = cursor_x.saturating_add(9 * scale);
        }
    }

    /// A filled status dot: online devices get accent, offline get muted.
    fn dot(&mut self, cx: usize, cy: usize, radius: usize, color: u32) {
        let diameter = radius.saturating_mul(2);
        // The offset from the centre is taken with `abs_diff`, so no cast to a
        // signed type is needed and the subtraction cannot wrap. Comparing
        // squared distances keeps the loop in `usize` throughout.
        let radius_sq = radius.saturating_mul(radius);
        for dy in 0..diameter {
            for dx in 0..diameter {
                let ox = dx.abs_diff(radius);
                let oy = dy.abs_diff(radius);
                if ox.saturating_mul(ox).saturating_add(oy.saturating_mul(oy)) <= radius_sq {
                    self.fill_rect(
                        cx.saturating_sub(radius).saturating_add(dx),
                        cy.saturating_sub(radius).saturating_add(dy),
                        1,
                        1,
                        color,
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    surface: u32,
    foreground: u32,
    accent: u32,
    danger: u32,
    muted: u32,
    border: u32,
}

const fn palette_for(visual: crate::VisualSystem) -> Palette {
    Palette {
        background: packed_rgb(visual.background_rgb),
        surface: packed_rgb(visual.surface_rgb),
        foreground: packed_rgb(visual.foreground_rgb),
        accent: packed_rgb(visual.accent_rgb),
        danger: packed_rgb(visual.danger_rgb),
        muted: packed_rgb(visual.muted_rgb),
        border: packed_rgb(visual.border_rgb),
    }
}

fn draw_top_bar(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    let bar = layout.top_bar_height;

    // Title on the left, status pill on the right. The red is spent here on
    // the status dot only -- enough to read the shell's state at a glance
    // without tinting the chrome.
    // At compact widths a 2x title intersects the status pill. Use a
    // measured one-line title and clip the secondary label to the viewport.
    let title_scale = if canvas.width < 480 { 1 } else { 2 };
    canvas.text(
        layout.content_x,
        (bar / 2).saturating_sub(9),
        presentation.title,
        title_scale,
        palette.foreground,
    );
    canvas.text_clipped(
        layout.content_x,
        (bar / 2).saturating_add(13),
        "KMJ TECHNO  /  SECURE REMOTE ACCESS",
        1,
        canvas
            .width
            .saturating_sub(layout.content_x + layout.gutter),
        palette.muted,
    );

    let status_width = Canvas::text_width(presentation.status, 1);
    let pill_right = layout
        .content_x
        .saturating_add(layout.content_width)
        .saturating_add(if layout.shows_panel() {
            layout.gutter + layout.panel_width
        } else {
            0
        });
    let pill_x = pill_right.saturating_sub(status_width + 22);
    canvas.fill_rect(
        pill_x,
        (bar / 2).saturating_sub(11),
        status_width + 22,
        22,
        palette.surface,
    );
    canvas.stroke_rect(
        pill_x,
        (bar / 2).saturating_sub(11),
        status_width + 22,
        22,
        1,
        palette.border,
    );
    canvas.dot(pill_x + 11, bar / 2, 3, palette.accent);
    canvas.text(
        pill_x + 20,
        (bar / 2).saturating_sub(4),
        presentation.status,
        1,
        palette.foreground,
    );

    canvas.h_line(0, bar.saturating_sub(1), canvas.width, palette.border);
}

fn draw_content_header(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    let y = layout.top_bar_height + layout.gutter;
    canvas.text(
        layout.content_x,
        y,
        presentation.panel_title,
        2,
        palette.foreground,
    );
    canvas.text(
        layout.content_x,
        y.saturating_add(28),
        &presentation.summary,
        1,
        palette.muted,
    );
}

fn draw_quick_connect(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    let x = layout.content_x;
    let y = layout.top_bar_height + 76;
    let width = layout.content_width;
    let height = 138;

    canvas.fill_rect(x, y, width, height, palette.surface);
    canvas.stroke_rect(x, y, width, height, 1, palette.border);
    canvas.fill_rect(x, y, 3, height, palette.accent);

    let inner_x = x + 22;
    let inner_y = y + 18;
    canvas.text(inner_x, inner_y, "YOUR OMNIDESK ID", 1, palette.muted);
    canvas.text(inner_x, inner_y + 24, "NOT ASSIGNED", 2, palette.foreground);
    let split_x = x + width / 2;
    let identity_width = if width >= 560 {
        split_x.saturating_sub(inner_x + 12)
    } else {
        width.saturating_sub(44)
    };
    canvas.text_clipped(
        inner_x,
        inner_y + 54,
        "Identity appears only after secure device registration.",
        1,
        identity_width,
        palette.muted,
    );

    if width >= 560 {
        canvas.fill_rect(split_x, y + 18, 1, height - 36, palette.border);
        let remote_x = split_x + 22;
        let remote_width = x + width - remote_x - 22;

        canvas.text(remote_x, inner_y, "REMOTE DEVICE ID", 1, palette.muted);
        canvas.fill_rect(remote_x, inner_y + 24, remote_width, 34, palette.background);
        canvas.stroke_rect(remote_x, inner_y + 24, remote_width, 34, 1, palette.border);
        canvas.text_clipped(
            remote_x + 12,
            inner_y + 36,
            "SELECT A REGISTERED DEVICE BELOW",
            1,
            remote_width.saturating_sub(24),
            palette.muted,
        );

        let button_width = remote_width.min(156);
        canvas.fill_rect(
            remote_x,
            inner_y + 72,
            button_width,
            30,
            if presentation.controls.iter().any(|control| control.enabled) {
                palette.accent
            } else {
                palette.border
            },
        );
        canvas.text(
            remote_x + 16,
            inner_y + 83,
            "CONNECT",
            1,
            palette.foreground,
        );
        let message_x = remote_x + button_width + 12;
        canvas.text_clipped(
            message_x,
            inner_y + 83,
            "Use an online device",
            1,
            x.saturating_add(width).saturating_sub(message_x + 12),
            palette.muted,
        );
    } else {
        canvas.text_clipped(
            inner_x,
            inner_y + 82,
            "REMOTE DEVICE: SELECT AN ONLINE DEVICE BELOW",
            1,
            width.saturating_sub(44),
            palette.muted,
        );
    }
}

/// Whether an action destroys something the user would have to re-establish.
///
/// Denying a request and ending a live session are both destructive, and
/// marking them is the one place the second red earns its keep: a user
/// confirming "Deny" should not have to read it to know it ends something.
const fn is_destructive(action: crate::DesktopAction) -> bool {
    matches!(
        action,
        crate::DesktopAction::DenyPermission | crate::DesktopAction::Disconnect
    )
}

fn draw_controls(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    let rects = control_rects_for(presentation, canvas.width, canvas.height);
    let visible = layout.visible_rows();

    for (control, rect) in presentation.controls.iter().zip(rects).take(visible) {
        let is_online = control.enabled;
        let destructive = is_destructive(control.action);
        canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, palette.surface);

        // A red left edge on every enabled row brought back the "everything
        // is red" problem, so the enabled cue is a dot and the border is the
        // neutral hairline -- except on a destructive action, which gets the
        // red edge because that is the one thing the colour must warn about.
        canvas.fill_rect(
            rect.x,
            rect.y,
            1,
            rect.height,
            if destructive {
                palette.danger
            } else {
                palette.border
            },
        );
        canvas.dot(
            rect.x + 22,
            rect.y + rect.height / 2,
            4,
            if is_online {
                palette.accent
            } else {
                palette.muted
            },
        );

        // Reserve enough space for the actual trailing status string before
        // rendering the device label. A fixed 96px inset was insufficient for
        // "UNAVAILABLE", which collided with the label on narrow windows.
        let trailing = if is_online {
            format!("[{}]", control.keyboard_key.to_ascii_uppercase())
        } else if matches!(control.action, crate::DesktopAction::ConnectDevice(_)) {
            "OFFLINE".to_owned()
        } else {
            "UNAVAILABLE".to_owned()
        };
        let label_color = if is_online {
            palette.foreground
        } else {
            palette.muted
        };
        let trailing_width = Canvas::text_width(&trailing, 1);
        canvas.text_clipped(
            rect.x + 40,
            rect.y + 12,
            &control.label,
            1,
            rect.width.saturating_sub(40 + trailing_width + 24),
            label_color,
        );
        canvas.text_right(
            rect.x + rect.width - 14,
            rect.y + 12,
            &trailing,
            1,
            palette.muted,
        );
        canvas.h_line(
            rect.x + 1,
            rect.y + rect.height.saturating_sub(1),
            rect.width.saturating_sub(2),
            palette.border,
        );
    }

    if presentation.controls.is_empty() {
        // An empty list drawn as nothing at all reads as a failed render. The
        // empty state says what is missing and what would fill it, so a
        // viewer can tell the difference between "no devices yet" and "the
        // app is broken".
        let empty_y = layout.first_row_y().saturating_add(8);
        canvas.text(
            layout.content_x,
            empty_y,
            "NO DEVICES REGISTERED",
            1,
            palette.muted,
        );
        canvas.text(
            layout.content_x,
            empty_y.saturating_add(24),
            "A device appears here once it has paired with this account.",
            1,
            palette.muted,
        );
    }
}

fn draw_panel(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    if !layout.shows_panel() {
        return;
    }

    let panel_y = layout.top_bar_height + layout.gutter;
    let panel_height = layout.content_height.saturating_sub(layout.gutter * 2);

    canvas.fill_rect(
        layout.panel_x,
        panel_y,
        layout.panel_width,
        panel_height,
        palette.surface,
    );
    canvas.stroke_rect(
        layout.panel_x,
        panel_y,
        layout.panel_width,
        panel_height,
        1,
        palette.border,
    );

    let inner_x = layout.panel_x + 18;
    let inner_width = layout.panel_width.saturating_sub(36);

    canvas.text(inner_x, panel_y + 18, "DETAILS", 1, palette.muted);
    canvas.h_line(inner_x, panel_y + 36, inner_width, palette.border);

    let mut row_y = panel_y + 52;
    for detail in &presentation.details {
        canvas.text_clipped(inner_x, row_y, detail, 1, inner_width, palette.foreground);
        row_y = row_y.saturating_add(26);
    }
}

fn draw_footer(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &ShellLayout,
    palette: Palette,
) {
    let y = canvas.height.saturating_sub(layout.footer_height);
    canvas.h_line(0, y, canvas.width, palette.border);

    // Footer shortcuts must never collide with right-aligned status text.
    let shortcut_text = if canvas.width < 540 {
        "TAB / ENTER / ESC"
    } else {
        "TAB CYCLE   ENTER SELECT   ESC BACK"
    };
    let status_width = Canvas::text_width(presentation.status, 1);
    canvas.text_clipped(
        layout.content_x,
        y + 16,
        shortcut_text,
        1,
        layout.content_width.saturating_sub(status_width + 28),
        palette.muted,
    );
    canvas.text_right(
        layout.content_x + layout.content_width,
        y + 16,
        presentation.status,
        1,
        palette.muted,
    );
}

// Real, product-derived four-column canvas for the exact owner-locked
// 1419x611 desktop application reference. No demo wallpaper, manufactured
// devices, or fabricated connection metrics may be rendered here.
const VERIFIED_GREEN: u32 = 0x1f_da_78;

fn locked_frame(
    canvas: &mut Canvas<'_>,
    left: usize,
    top: usize,
    width: usize,
    height: usize,
    palette: Palette,
) {
    canvas.fill_rect(left, top, width, height, palette.surface);
    canvas.stroke_rect(left, top, width, height, 1, palette.border);
}

fn locked_label(
    canvas: &mut Canvas<'_>,
    x: usize,
    y: usize,
    width: usize,
    label: &str,
    color: u32,
) {
    canvas.text_clipped(x, y, label, 1, width, color);
}

fn draw_locked_header(canvas: &mut Canvas<'_>, layout: &LockedDashboardLayout, p: Palette) {
    // Header: branding, search affordance and account utilities, as in lock.
    canvas.fill_rect(0, 0, canvas.width, layout.top_bar_height, p.surface);
    canvas.fill_rect(0, 0, canvas.width, 2, p.accent);
    canvas.h_line(0, layout.top_bar_height - 1, canvas.width, p.border);
    canvas.text(17, 21, "KMJ", 2, p.accent);
    canvas.text(85, 21, "OMNIDESK", 2, p.foreground);
    canvas.text(85, 45, "SECURE  /  ACCESSIBLE  /  EVERYWHERE", 1, p.muted);

    let search_x = canvas.width / 3;
    let search_w = canvas.width / 3;
    canvas.fill_rect(search_x, 15, search_w, 37, p.background);
    canvas.stroke_rect(search_x, 15, search_w, 37, 1, p.border);
    locked_label(
        canvas,
        search_x + 14,
        29,
        search_w.saturating_sub(28),
        "SEARCH UNAVAILABLE UNTIL DEVICE SYNC",
        p.muted,
    );
    locked_label(
        canvas,
        canvas.width.saturating_sub(194),
        29,
        180,
        "SETTINGS   HELP",
        p.muted,
    );
}

fn draw_locked_navigation(canvas: &mut Canvas<'_>, layout: &LockedDashboardLayout, p: Palette) {
    let nav = layout.navigation;
    let nav_labels = [
        "DEVICES",
        "CONNECTIONS",
        "FILE TRANSFER",
        "REMOTE ACTIONS",
        "AUTOMATION",
        "SECURITY",
        "SETTINGS",
    ];
    for (index, label) in nav_labels.iter().enumerate() {
        let y = nav.y + 9 + index * 44;
        let enabled = index == 0;
        if enabled {
            canvas.fill_rect(nav.x + 6, y, nav.width - 12, 36, p.accent);
            canvas.stroke_rect(nav.x + 6, y, nav.width - 12, 36, 1, p.danger);
        }
        locked_label(
            canvas,
            nav.x + 18,
            y + 13,
            nav.width.saturating_sub(32),
            label,
            if enabled { p.foreground } else { p.muted },
        );
    }
    let nav_bottom = nav.y + nav.height;
    canvas.fill_rect(nav.x + 9, nav_bottom - 69, nav.width - 18, 56, p.background);
    canvas.stroke_rect(nav.x + 9, nav_bottom - 69, nav.width - 18, 56, 1, p.border);
    canvas.dot(nav.x + 22, nav_bottom - 47, 4, p.muted);
    locked_label(
        canvas,
        nav.x + 32,
        nav_bottom - 51,
        nav.width.saturating_sub(48),
        "DISCONNECTED",
        p.foreground,
    );
    locked_label(
        canvas,
        nav.x + 17,
        nav_bottom - 28,
        nav.width.saturating_sub(28),
        "LOCAL DEVICE",
        p.muted,
    );
}

fn draw_locked_devices(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let devices = layout.devices;
    // Device directory stays empty until an authoritative pairing service
    // provides real DeviceSummary records; never copy fake peers from mockup.
    locked_label(
        canvas,
        devices.x + 14,
        devices.y + 21,
        devices.width - 28,
        "DEVICES",
        p.foreground,
    );
    canvas.fill_rect(
        devices.x + 10,
        devices.y + 60,
        devices.width - 20,
        1,
        p.border,
    );
    locked_label(
        canvas,
        devices.x + 15,
        devices.y + 75,
        devices.width - 26,
        "ALL      ONLINE      OFFLINE",
        p.muted,
    );
    let device_controls =
        if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices {
            presentation.controls.len()
        } else {
            0
        };
    if device_controls == 0 || !presentation.controls.iter().any(|control| control.enabled) {
        locked_label(
            canvas,
            devices.x + 14,
            devices.y + 112,
            devices.width - 28,
            "NO ONLINE DEVICE AVAILABLE",
            p.muted,
        );
        locked_label(
            canvas,
            devices.x + 14,
            devices.y + 136,
            devices.width - 28,
            "PAIR A TRUSTED DEVICE FIRST",
            p.muted,
        );
    }
    if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices {
        for (index, control) in presentation.controls.iter().enumerate() {
            let rect = layout.device_row(index);
            if rect.y + rect.height >= devices.y + devices.height - 12 {
                break;
            }
            canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, p.background);
            canvas.stroke_rect(rect.x, rect.y, rect.width, rect.height, 1, p.border);
            canvas.dot(
                rect.x + 14,
                rect.y + rect.height / 2,
                4,
                if control.enabled {
                    VERIFIED_GREEN
                } else {
                    p.muted
                },
            );
            locked_label(
                canvas,
                rect.x + 28,
                rect.y + 18,
                rect.width.saturating_sub(44),
                &control.label,
                if control.enabled {
                    p.foreground
                } else {
                    p.muted
                },
            );
        }
    }
}

fn draw_locked_remote_view(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let viewer = layout.viewer;
    // Remote canvas. A legitimate remote video frame must come from the
    // authenticated frame decoder, never from a screenshot of the reference.
    locked_label(
        canvas,
        viewer.x + 13,
        viewer.y + 22,
        viewer.width - 26,
        presentation.panel_title,
        p.foreground,
    );
    locked_label(
        canvas,
        viewer.x + 13,
        viewer.y + 43,
        viewer.width - 26,
        presentation.status,
        p.muted,
    );
    let screen = layout.remote_screen;
    canvas.fill_rect(
        screen.x,
        screen.y,
        screen.width,
        screen.height,
        p.background,
    );
    canvas.stroke_rect(screen.x, screen.y, screen.width, screen.height, 1, p.border);
    canvas.fill_rect(screen.x + 1, screen.y + 1, screen.width - 2, 3, p.border);
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 22,
        screen.width - 44,
        "REMOTE DESKTOP",
        p.foreground,
    );
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 48,
        screen.width - 44,
        "NO AUTHENTICATED REMOTE VIDEO",
        p.muted,
    );
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 73,
        screen.width - 44,
        "CONNECT TO A VERIFIED DEVICE TO START",
        p.muted,
    );
}

fn draw_locked_session_tiles(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let screen = layout.remote_screen;
    // Keyboard/device controls only become clickable in their real shell state.
    let toolbar = layout.session_toolbar;
    let offline_labels = [
        "SEND KEYS",
        "CLIPBOARD",
        "FILE TRANSFER",
        "SHELL",
        "CAPTURE",
        "MORE",
    ];
    let active_session =
        presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Session;
    let prompt =
        presentation.primary_view == omnidesk_core::product_shell::PrimaryView::PermissionPrompt;
    if prompt {
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 107,
            screen.width - 44,
            "APPROVE LOCAL PERMISSION?",
            p.foreground,
        );
        for (index, control) in presentation.controls.iter().enumerate() {
            let rect = layout.permission_button(index);
            canvas.fill_rect(
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                if index == 0 { p.accent } else { p.border },
            );
            locked_label(
                canvas,
                rect.x + 12,
                rect.y + 19,
                rect.width - 24,
                &control.label,
                p.foreground,
            );
        }
    }
    if active_session {
        for (index, control) in presentation.controls.iter().enumerate() {
            let rect = layout.session_button(index, presentation.controls.len());
            canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, p.border);
            canvas.stroke_rect(rect.x, rect.y, rect.width, rect.height, 1, p.muted);
            locked_label(
                canvas,
                rect.x + 6,
                rect.y + 18,
                rect.width.saturating_sub(12),
                &control.label,
                p.foreground,
            );
        }
    } else {
        let tile_width = toolbar.width / offline_labels.len();
        for (index, label) in offline_labels.iter().enumerate() {
            let x = toolbar.x + index * tile_width + 3;
            let width = tile_width.saturating_sub(6);
            canvas.fill_rect(x, toolbar.y + 5, width, toolbar.height - 10, p.background);
            canvas.stroke_rect(x, toolbar.y + 5, width, toolbar.height - 10, 1, p.border);
            locked_label(
                canvas,
                x + 5,
                toolbar.y + 22,
                width.saturating_sub(10),
                label,
                p.muted,
            );
        }
    }
}

fn draw_locked_details(
    canvas: &mut Canvas<'_>,
    p: Palette,
    info_x: usize,
    info_w: usize,
    details_y: usize,
) {
    locked_label(
        canvas,
        info_x,
        details_y + 18,
        info_w,
        "SESSION DETAILS",
        p.foreground,
    );
    for (index, text) in [
        "Duration        --",
        "Resolution      --",
        "Frame rate      --",
        "Bandwidth       --",
        "Codec           --",
        "Encryption      --",
    ]
    .iter()
    .enumerate()
    {
        locked_label(
            canvas,
            info_x,
            details_y + 45 + index * 22,
            info_w,
            text,
            p.muted,
        );
    }
}

fn draw_locked_action_buttons(
    canvas: &mut Canvas<'_>,
    p: Palette,
    info_x: usize,
    info_w: usize,
    actions_y: usize,
) {
    locked_label(
        canvas,
        info_x,
        actions_y + 16,
        info_w,
        "ACTIONS  /  UNAVAILABLE",
        p.foreground,
    );
    for (index, text) in ["FILE TRANSFER", "REMOTE REBOOT", "CLIPBOARD", "UNATTENDED"]
        .iter()
        .enumerate()
    {
        let columns = 2;
        let cell_w = info_w / columns;
        let x = info_x + index % columns * cell_w + 2;
        let y = actions_y + 37 + index / columns * 37;
        let button_width = cell_w.saturating_sub(8);
        canvas.fill_rect(x, y, button_width, 31, p.background);
        canvas.stroke_rect(x, y, button_width, 31, 1, p.border);
        locked_label(
            canvas,
            x + 5,
            y + 12,
            button_width.saturating_sub(10),
            text,
            p.muted,
        );
    }}

fn draw_locked_inspector(canvas: &mut Canvas<'_>, layout: &LockedDashboardLayout, p: Palette) {
    let inspector = layout.inspector;
    // Right cards. Values remain unavailable until verified by transport.
    let first = inspector.height * 36 / 100;
    let second = inspector.height * 35 / 100;
    let status_y = inspector.y + 5;
    let details_y = status_y + first + 6;
    let actions_y = details_y + second + 6;
    locked_frame(
        canvas,
        inspector.x + 6,
        status_y,
        inspector.width - 12,
        first,
        p,
    );
    locked_frame(
        canvas,
        inspector.x + 6,
        details_y,
        inspector.width - 12,
        second,
        p,
    );
    locked_frame(
        canvas,
        inspector.x + 6,
        actions_y,
        inspector.width - 12,
        inspector.y + inspector.height - actions_y - 5,
        p,
    );
    let info_x = inspector.x + 20;
    let info_w = inspector.width.saturating_sub(40);
    locked_label(
        canvas,
        info_x,
        status_y + 18,
        info_w,
        "CONNECTION STATUS",
        p.foreground,
    );
    canvas.dot(info_x + 5, status_y + 47, 4, p.muted);
    locked_label(
        canvas,
        info_x + 17,
        status_y + 43,
        info_w - 17,
        "NO VERIFIED CONNECTION",
        p.muted,
    );
    for (index, text) in [
        "Path: unavailable",
        "Latency: unavailable",
        "Relay: not verified",
    ]
    .iter()
    .enumerate()
    {
        locked_label(
            canvas,
            info_x,
            status_y + 72 + index * 25,
            info_w,
            text,
            p.muted,
        );
    }
    draw_locked_details(canvas, p, info_x, info_w, details_y);
    draw_locked_action_buttons(canvas, p, info_x, info_w, actions_y);
}

fn draw_locked_dashboard(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    draw_locked_header(canvas, layout, p);
    for rect in [
        layout.navigation,
        layout.devices,
        layout.viewer,
        layout.inspector,
    ] {
        locked_frame(canvas, rect.x, rect.y, rect.width, rect.height, p);
    }
    draw_locked_navigation(canvas, layout, p);
    draw_locked_devices(canvas, presentation, layout, p);
    draw_locked_remote_view(canvas, presentation, layout, p);
    draw_locked_session_tiles(canvas, presentation, layout, p);
    draw_locked_inspector(canvas, layout, p);
}

/// Draws the current truthful product-shell presentation into an RGB software buffer.
///
/// The renderer is deliberately static/event-driven: it draws only the state supplied by
/// `PresentationModel` and never invents devices, sessions, or online state.
pub fn render_shell(
    pixels: &mut [u32],
    width: usize,
    height: usize,
    presentation: &PresentationModel,
) {
    if width == 0 || height == 0 || pixels.len() < width.saturating_mul(height) {
        return;
    }

    let palette = palette_for(presentation.visual);

    pixels[..width * height].fill(palette.background);
    let Some(layout) = ShellLayout::for_window(width, height) else {
        return;
    };

    let mut canvas = Canvas {
        pixels,
        width,
        height,
    };
    if let Some(locked) = LockedDashboardLayout::for_window(width, height) {
        draw_locked_dashboard(&mut canvas, presentation, &locked, palette);
        return;
    }
    draw_top_bar(&mut canvas, presentation, &layout, palette);
    draw_content_header(&mut canvas, presentation, &layout, palette);
    draw_quick_connect(&mut canvas, presentation, &layout, palette);
    draw_controls(&mut canvas, presentation, &layout, palette);
    draw_panel(&mut canvas, presentation, &layout, palette);
    draw_footer(&mut canvas, presentation, &layout, palette);
}

#[cfg(test)]
mod tests {
    use omnidesk_core::product_shell::ProductShell;

    use super::*;
    use crate::{VisualSystem, presentation_for};

    #[test]
    fn renderer_uses_locked_black_red_visual_tokens() {
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        let mut pixels = vec![0_u32; 1200 * 800];

        render_shell(&mut pixels, 1200, 800, &presentation);

        let visual = VisualSystem::kmj_black_red();
        let background = packed_rgb(visual.background_rgb);
        let surface = packed_rgb(visual.surface_rgb);
        let foreground = packed_rgb(visual.foreground_rgb);
        let accent = packed_rgb(visual.accent_rgb);
        let muted = packed_rgb(visual.muted_rgb);
        let border = packed_rgb(visual.border_rgb);

        for color in [background, surface, foreground, accent, muted, border] {
            assert!(pixels.contains(&color), "colour {color:#010x} never drawn");
        }
    }

    #[test]
    fn quick_connect_identity_caption_stays_in_its_own_column() {
        let width = 1200;
        let height = 800;
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        let mut pixels = vec![0_u32; width * height];
        render_shell(&mut pixels, width, height, &presentation);
        let layout = ShellLayout::for_window(width, height).expect("wide layout");
        assert!(layout.content_width >= 560);
        let split_x = layout.content_x + layout.content_width / 2;
        let caption_y = layout.top_bar_height + 76 + 18 + 54;
        let text_color = packed_rgb(presentation.visual.muted_rgb);
        // Only the identity caption occupies this band: the remote input
        // above it and connect CTA below it must remain visually independent.
        for y in caption_y..caption_y + 8 {
            for x in split_x..layout.content_x + layout.content_width {
                assert_ne!(
                    pixels[y * width + x],
                    text_color,
                    "identity caption crosses into remote device field at ({x},{y})"
                );
            }
        }
    }

    #[test]
    fn renderer_is_safe_for_zero_or_short_buffers() {
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        let mut pixels = vec![7_u32; 4];

        render_shell(&mut pixels, 0, 0, &presentation);
        assert_eq!(pixels, vec![7_u32; 4]);

        render_shell(&mut pixels, 100, 100, &presentation);
        assert_eq!(pixels, vec![7_u32; 4]);
    }

    #[test]
    fn every_window_size_renders_without_panicking() {
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        for (width, height) in [
            (0, 0),
            (1, 1),
            (320, 240),
            (360, 220),
            (700, 800),
            (1200, 800),
            (1920, 1080),
            (2560, 1440),
        ] {
            let mut pixels = vec![0_u32; width * height];
            render_shell(&mut pixels, width, height, &presentation);
        }
    }

    #[test]
    fn a_window_too_small_to_lay_out_is_left_blank_rather_than_corrupted() {
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        let mut pixels = vec![0_u32; 300 * 200];
        render_shell(&mut pixels, 300, 200, &presentation);
        // Only the background fill should be present -- no partial chrome.
        let background = packed_rgb(presentation.visual.background_rgb);
        assert!(pixels.iter().all(|pixel| *pixel == background));
    }

    #[test]
    fn a_long_device_label_is_truncated_rather_than_drawn_over_its_neighbour() {
        let mut presentation = presentation_for(&ProductShell::new());
        presentation.controls = vec![crate::ShellControl {
            label: "A-very-long-device-name-that-cannot-possibly-fit-in-the-column".to_owned(),
            action: crate::DesktopAction::FocusDevices,
            keyboard_key: '1',
            role: crate::AccessibleRole::Button,
            enabled: true,
        }];
        let mut pixels = vec![0_u32; 960 * 800];
        render_shell(&mut pixels, 960, 800, &presentation);

        // The panel starts at panel_x; nothing of the row may land there.
        let Some(layout) = ShellLayout::for_window(960, 800) else {
            panic!("layout should resolve at 960x800");
        };
        let Some(rect) = crate::control_rects_for(&presentation, 960, 800)
            .first()
            .copied()
        else {
            panic!("expected a control rect");
        };
        let row_y = rect.y;
        for y in row_y..row_y + rect.height {
            for x in layout.panel_x..layout.panel_x + layout.panel_width {
                let pixel = pixels[y * 960 + x];
                assert_ne!(
                    pixel,
                    packed_rgb(presentation.visual.foreground_rgb),
                    "label overflowed into the panel at ({x},{y})"
                );
            }
        }
    }
}
