use ab_glyph::{Font, FontArc, PxScale, ScaleFont, point};
use font8x8::{BASIC_FONTS, UnicodeFonts};
use std::sync::OnceLock;

use crate::{
    LockedDashboardLayout, PresentationModel, ShellLayout, brand::official_kmj_mark,
    control_rects_for,
};

#[must_use]
pub const fn packed_rgb(rgb: [u8; 3]) -> u32 {
    (rgb[0] as u32) << 16 | (rgb[1] as u32) << 8 | rgb[2] as u32
}

// Read fonts supplied by the operating system: the product does not bundle,
// upload, copy, or redistribute proprietary Windows font files. The existing
// tiny pixel-font renderer remains a deterministic fallback for minimal hosts.
fn native_ui_font() -> Option<&'static FontArc> {
    static FONT: OnceLock<Option<FontArc>> = OnceLock::new();
    FONT.get_or_init(|| {
        #[cfg(windows)]
        let paths: &[&str] = &[
            r"C:\Windows\Fonts\segoeui.ttf",
            r"C:\Windows\Fonts\arial.ttf",
        ];
        #[cfg(target_os = "macos")]
        let paths: &[&str] = &[
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial.ttf",
        ];
        #[cfg(all(not(windows), not(target_os = "macos")))]
        let paths: &[&str] = &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
        ];
        paths.iter().find_map(|path| {
            std::fs::read(path)
                .ok()
                .and_then(|data| FontArc::try_from_vec(data).ok())
        })
    })
    .as_ref()
}

const fn native_text_size(scale: usize) -> f32 {
    if scale >= 2 { 22.0 } else { 16.0 }
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

    fn image_rgba(
        &mut self,
        destination: (usize, usize, usize, usize),
        source_size: (usize, usize),
        rgba: &[u8],
    ) {
        let (x, y, width, height) = destination;
        let (source_width, source_height) = source_size;
        if width == 0
            || height == 0
            || source_width == 0
            || source_height == 0
            || rgba.len() < source_width.saturating_mul(source_height).saturating_mul(4)
        {
            return;
        }

        for dy in 0..height {
            let sy = dy.saturating_mul(source_height) / height;
            for dx in 0..width {
                let sx = dx.saturating_mul(source_width) / width;
                let source_index = sy
                    .saturating_mul(source_width)
                    .saturating_add(sx)
                    .saturating_mul(4);
                let red = u32::from(rgba[source_index]);
                let green = u32::from(rgba[source_index + 1]);
                let blue = u32::from(rgba[source_index + 2]);
                let alpha = f32::from(rgba[source_index + 3]) / 255.0;
                let color = (red << 16) | (green << 8) | blue;
                self.blend_coverage(
                    i32::try_from(x.saturating_add(dx)).unwrap_or(i32::MAX),
                    i32::try_from(y.saturating_add(dy)).unwrap_or(i32::MAX),
                    color,
                    alpha,
                );
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

    // Glyph advances are finite, screen-bounded float values; usize only
    // records the conservative rounded pixel extent for clipping.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn text_width(text: &str, scale: usize) -> usize {
        if let Some(font) = native_ui_font() {
            let scaled = font.as_scaled(PxScale::from(native_text_size(scale)));
            let sum: f32 = text
                .chars()
                .map(|c| scaled.h_advance(scaled.glyph_id(c)))
                .sum();
            return sum.ceil() as usize;
        }
        text.chars().count().saturating_mul(9).saturating_mul(scale)
    }

    /// Clip text to its real font advances rather than dividing by a fixed
    /// bitmap-cell width. Reserve ellipsis width to protect neighboring cards.
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
        if Self::text_width(text, scale) <= max_width {
            self.text(x, y, text, scale, color);
            return;
        }
        let ellipsis = "...";
        let dots_width = Self::text_width(ellipsis, scale);
        if dots_width >= max_width {
            return;
        }
        let mut kept = String::new();
        for c in text.chars() {
            kept.push(c);
            if Self::text_width(&kept, scale).saturating_add(dots_width) > max_width {
                kept.pop();
                break;
            }
        }
        let used_width = Self::text_width(&kept, scale);
        self.text(x, y, &kept, scale, color);
        self.text(x.saturating_add(used_width), y, ellipsis, scale, color);
    }

    fn text_right(&mut self, right_edge: usize, y: usize, text: &str, scale: usize, color: u32) {
        let width = Self::text_width(text, scale);
        self.text(right_edge.saturating_sub(width), y, text, scale, color);
    }

    // The alpha fraction is clamped to [0,1] before converting to the
    // exact 8-bit channel range used for deterministic pixel compositing.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn blend_coverage(&mut self, x: i32, y: i32, color: u32, coverage: f32) {
        let (Ok(x), Ok(y)) = (usize::try_from(x), usize::try_from(y)) else {
            return;
        };
        if x >= self.width || y >= self.height {
            return;
        }
        let alpha = (coverage.clamp(0.0, 1.0) * 255.0).round() as u32;
        if alpha == 0 {
            return;
        }
        let background = self.pixels[y * self.width + x];
        let inverse = 255 - alpha;
        let mut blended = 0_u32;
        for shift in [0_u32, 8, 16] {
            let foreground = (color >> shift) & 0xff;
            let behind = (background >> shift) & 0xff;
            let mix = (foreground * alpha + behind * inverse + 127) / 255;
            blended |= mix << shift;
        }
        self.pixels[y * self.width + x] = blended;
    }

    // Font APIs use f32 coordinates and signed raster bounds. The viewport
    // clips all pixel writes, and the glyph API bounds each local delta.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap
    )]
    fn text(&mut self, x: usize, y: usize, text: &str, scale: usize, color: u32) {
        if let Some(font) = native_ui_font() {
            let px = PxScale::from(native_text_size(scale));
            let scaled = font.as_scaled(px);
            let mut cursor_x = x as f32;
            let baseline = y as f32 + scaled.ascent();
            for character in text.chars() {
                let id = scaled.glyph_id(character);
                let glyph = id.with_scale_and_position(px, point(cursor_x, baseline));
                if let Some(outline) = font.outline_glyph(glyph) {
                    let bounds = outline.px_bounds();
                    let left = bounds.min.x as i32;
                    let top = bounds.min.y as i32;
                    outline.draw(|dx, dy, coverage| {
                        self.blend_coverage(
                            left.saturating_add(dx as i32),
                            top.saturating_add(dy as i32),
                            color,
                            coverage,
                        );
                    });
                }
                cursor_x += scaled.h_advance(id);
            }
            return;
        }
        let mut cursor_x = x;
        for character in text.chars() {
            if let Some(glyph) = BASIC_FONTS.get(character) {
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
    // The narrow shell keeps the same single official brand mark as the
    // wide dashboard; it never draws a second mark in content cards.
    if let Some(mark) = official_kmj_mark() {
        canvas.image_rgba(
            (layout.content_x, 13, 38, 38),
            (
                usize::try_from(mark.width).unwrap_or(0),
                usize::try_from(mark.height).unwrap_or(0),
            ),
            &mark.rgba,
        );
    }
    let title_x = layout.content_x.saturating_add(47);
    let title_scale = if canvas.width < 480 { 1 } else { 2 };
    let title = if canvas.width < 480 {
        "OmniDesk"
    } else {
        presentation.title
    };
    canvas.text(
        title_x,
        (bar / 2).saturating_sub(9),
        title,
        title_scale,
        palette.foreground,
    );
    canvas.text_clipped(
        title_x,
        (bar / 2).saturating_add(13),
        "KMJ TECHNO",
        1,
        canvas
            .width
            .saturating_sub(title_x.saturating_add(layout.gutter)),
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
        } else if matches!(control.action, crate::DesktopAction::ConnectDevice(_, _)) {
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

fn draw_locked_header(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    // Header: branding, search affordance and account utilities, as in lock.
    canvas.fill_rect(0, 0, canvas.width, layout.top_bar_height, p.surface);
    canvas.fill_rect(0, 0, canvas.width, 2, p.accent);
    canvas.h_line(0, layout.top_bar_height - 1, canvas.width, p.border);
    if let Some(mark) = official_kmj_mark() {
        canvas.image_rgba(
            (14, 12, 44, 44),
            (
                usize::try_from(mark.width).unwrap_or(0),
                usize::try_from(mark.height).unwrap_or(0),
            ),
            &mark.rgba,
        );
    }
    // One approved KMJ mark and one company wordmark per window. OmniDesk
    // is the product label, not an additional copy of the brand logo.
    canvas.text(70, 19, "KMJ TECHNO", 2, p.foreground);
    canvas.text(70, 45, "INNOVATE | BUILD | SCALE", 1, p.muted);
    locked_label(canvas, 295, 20, 155, "OmniDesk", p.foreground);
    locked_label(canvas, 295, 44, 155, "Remote Access", p.muted);

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

    let settings_rect = layout.settings_button_rect(canvas.width);
    let help_rect = layout.help_button_rect(canvas.width);
    let settings_color = if presentation.nav_tab == omnidesk_core::product_shell::NavTab::Settings {
        p.accent
    } else {
        p.muted
    };
    let help_color = if presentation.help_open {
        p.accent
    } else {
        p.muted
    };
    locked_label(
        canvas,
        settings_rect.x,
        29,
        settings_rect.width,
        "SETTINGS",
        settings_color,
    );
    locked_label(canvas, help_rect.x, 29, help_rect.width, "HELP", help_color);
}

fn draw_locked_nav_icon(canvas: &mut Canvas<'_>, index: usize, x: usize, y: usize, color: u32) {
    // Low-overdraw monochrome vector-style icons; no external font/icon
    // dependency or fabricated online/connection state.
    match index {
        0 => {
            canvas.stroke_rect(x, y, 16, 12, 1, color);
            canvas.fill_rect(x + 7, y + 12, 2, 3, color);
            canvas.fill_rect(x + 4, y + 15, 8, 1, color);
        }
        1 => {
            canvas.stroke_rect(x, y + 4, 10, 8, 1, color);
            canvas.stroke_rect(x + 7, y, 10, 8, 1, color);
        }
        2 => {
            canvas.stroke_rect(x + 2, y, 12, 16, 1, color);
            canvas.fill_rect(x + 5, y + 6, 6, 1, color);
        }
        3 => {
            for dy in [0, 8] {
                for dx in [0, 8] {
                    canvas.stroke_rect(x + dx, y + dy, 6, 6, 1, color);
                }
            }
        }
        4 => {
            canvas.stroke_rect(x + 2, y + 2, 12, 12, 1, color);
            canvas.dot(x + 8, y + 8, 3, color);
        }
        5 => {
            canvas.stroke_rect(x + 3, y, 10, 13, 1, color);
            canvas.fill_rect(x + 7, y + 8, 2, 5, color);
        }
        _ => {
            canvas.dot(x + 8, y + 8, 7, color);
            canvas.dot(x + 8, y + 8, 3, 0x0e_11_14);
        }
    }
}

fn draw_locked_navigation(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let nav = layout.navigation;
    let nav_labels = [
        "Devices",
        "Connections",
        "File Transfer",
        "Remote Actions",
        "Automation",
        "Security",
        "Settings",
    ];
    let nav_tabs = [
        omnidesk_core::product_shell::NavTab::Devices,
        omnidesk_core::product_shell::NavTab::Connections,
        omnidesk_core::product_shell::NavTab::FileTransfer,
        omnidesk_core::product_shell::NavTab::RemoteActions,
        omnidesk_core::product_shell::NavTab::Automation,
        omnidesk_core::product_shell::NavTab::Security,
        omnidesk_core::product_shell::NavTab::Settings,
    ];
    for (index, label) in nav_labels.iter().enumerate() {
        let rect = layout.nav_tab_rect(index);
        let active = nav_tabs[index] == presentation.nav_tab;
        if active {
            // The premium lock uses a red selection marker, not a glowing
            // destructive-looking border around every selected nav row.
            canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, 0x52_13_27);
            canvas.stroke_rect(rect.x, rect.y, rect.width, rect.height, 1, p.border);
            canvas.fill_rect(rect.x, rect.y, 3, rect.height, p.accent);
        }
        let item_color = if active { p.foreground } else { p.muted };
        draw_locked_nav_icon(canvas, index, rect.x + 7, rect.y + 10, item_color);
        locked_label(
            canvas,
            rect.x + 29,
            rect.y + 13,
            rect.width.saturating_sub(34),
            label,
            item_color,
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
        "Disconnected",
        p.foreground,
    );
    locked_label(
        canvas,
        nav.x + 17,
        nav_bottom - 28,
        nav.width.saturating_sub(28),
        "Local device",
        p.muted,
    );
}

fn draw_locked_device_rows(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let devices = layout.devices;
    let all_color = if presentation.device_filter == omnidesk_core::product_shell::DeviceFilter::All
    {
        p.foreground
    } else {
        p.muted
    };
    let online_color =
        if presentation.device_filter == omnidesk_core::product_shell::DeviceFilter::Online {
            p.foreground
        } else {
            p.muted
        };
    let offline_color =
        if presentation.device_filter == omnidesk_core::product_shell::DeviceFilter::Offline {
            p.foreground
        } else {
            p.muted
        };

    locked_label(canvas, devices.x + 15, devices.y + 75, 45, "ALL", all_color);
    locked_label(
        canvas,
        devices.x + 68,
        devices.y + 75,
        65,
        "ONLINE",
        online_color,
    );
    locked_label(
        canvas,
        devices.x + 140,
        devices.y + 75,
        70,
        "OFFLINE",
        offline_color,
    );

    let empty_directory = presentation.controls.len() == 1
        && matches!(
            presentation.controls[0].action,
            crate::DesktopAction::FocusDevices
        )
        && !presentation.controls[0].enabled;
    if empty_directory {
        locked_label(
            canvas,
            devices.x + 14,
            devices.y + 112,
            devices.width - 28,
            "No online device available",
            p.muted,
        );
        locked_label(
            canvas,
            devices.x + 14,
            devices.y + 136,
            devices.width - 28,
            "Pair a trusted device first",
            p.muted,
        );
    }
    if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices {
        for (index, control) in presentation.controls.iter().enumerate() {
            if matches!(control.action, crate::DesktopAction::FocusDevices) && !control.enabled {
                continue;
            }
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

fn draw_locked_secondary_tab(
    canvas: &mut Canvas<'_>,
    nav_tab: omnidesk_core::product_shell::NavTab,
    devices_x: usize,
    devices_y: usize,
    devices_width: usize,
    p: Palette,
) {
    let (line1, line2) = match nav_tab {
        omnidesk_core::product_shell::NavTab::Connections => (
            "No active connections",
            "Pair or connect a peer to view active sessions",
        ),
        omnidesk_core::product_shell::NavTab::FileTransfer => (
            "No active transfer session",
            "Connect to a device to send or receive files",
        ),
        omnidesk_core::product_shell::NavTab::RemoteActions => (
            "Select a device",
            "Remote actions require an active connection",
        ),
        omnidesk_core::product_shell::NavTab::Automation => (
            "No scheduled tasks",
            "Automations run on paired host devices",
        ),
        omnidesk_core::product_shell::NavTab::Security => {
            ("Security status", "Transport security not verified")
        }
        omnidesk_core::product_shell::NavTab::Settings => {
            ("Settings view", "Default display quality: Balanced")
        }
        omnidesk_core::product_shell::NavTab::Devices => ("Unavailable", "No data"),
    };
    locked_label(
        canvas,
        devices_x + 14,
        devices_y + 80,
        devices_width - 28,
        line1,
        p.foreground,
    );
    locked_label(
        canvas,
        devices_x + 14,
        devices_y + 105,
        devices_width - 28,
        line2,
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
    let nav_tab = presentation.nav_tab;
    let col_title = match nav_tab {
        omnidesk_core::product_shell::NavTab::Devices => "Devices",
        omnidesk_core::product_shell::NavTab::Connections => "Connections",
        omnidesk_core::product_shell::NavTab::FileTransfer => "File Transfer",
        omnidesk_core::product_shell::NavTab::RemoteActions => "Remote Actions",
        omnidesk_core::product_shell::NavTab::Automation => "Automation",
        omnidesk_core::product_shell::NavTab::Security => "Security",
        omnidesk_core::product_shell::NavTab::Settings => "Settings",
    };

    locked_label(
        canvas,
        devices.x + 14,
        devices.y + 21,
        devices.width - 28,
        col_title,
        p.foreground,
    );
    canvas.fill_rect(
        devices.x + 10,
        devices.y + 60,
        devices.width - 20,
        1,
        p.border,
    );

    if nav_tab == omnidesk_core::product_shell::NavTab::Devices {
        draw_locked_device_rows(canvas, presentation, layout, p);
    } else {
        draw_locked_secondary_tab(canvas, nav_tab, devices.x, devices.y, devices.width, p);
    }
}

fn draw_locked_your_id_card(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let your_id_card = layout.your_id_card_rect();
    canvas.fill_rect(
        your_id_card.x,
        your_id_card.y,
        your_id_card.width,
        your_id_card.height,
        p.surface,
    );
    canvas.stroke_rect(
        your_id_card.x,
        your_id_card.y,
        your_id_card.width,
        your_id_card.height,
        1,
        p.border,
    );
    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 14,
        your_id_card.width.saturating_sub(32),
        "THIS DESKTOP  ·  YOUR ID",
        p.muted,
    );

    let id_str = if presentation.local_device_id.is_empty() {
        "NOT INITIALIZED"
    } else {
        &presentation.local_device_id
    };
    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 50,
        your_id_card.width.saturating_sub(140),
        id_str,
        p.foreground,
    );

    let copy_btn = layout.your_id_copy_btn_rect();
    canvas.fill_rect(
        copy_btn.x,
        copy_btn.y,
        copy_btn.width,
        copy_btn.height,
        p.border,
    );
    canvas.stroke_rect(
        copy_btn.x,
        copy_btn.y,
        copy_btn.width,
        copy_btn.height,
        1,
        p.muted,
    );
    locked_label(
        canvas,
        copy_btn.x + 14,
        copy_btn.y + 10,
        copy_btn.width.saturating_sub(28),
        "COPY ID",
        p.foreground,
    );
}

fn draw_locked_remote_id_input(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    input_rect: crate::layout::DashboardRect,
    p: Palette,
) {
    canvas.fill_rect(
        input_rect.x,
        input_rect.y,
        input_rect.width,
        input_rect.height,
        p.background,
    );
    let input_border_color = if presentation.remote_id_focused {
        p.accent
    } else {
        p.border
    };
    canvas.stroke_rect(
        input_rect.x,
        input_rect.y,
        input_rect.width,
        input_rect.height,
        if presentation.remote_id_focused { 2 } else { 1 },
        input_border_color,
    );

    if presentation.remote_id_input.is_empty() {
        if presentation.remote_id_focused {
            locked_label(
                canvas,
                input_rect.x + 12,
                input_rect.y + 11,
                input_rect.width.saturating_sub(24),
                "|",
                p.accent,
            );
        } else {
            locked_label(
                canvas,
                input_rect.x + 12,
                input_rect.y + 11,
                input_rect.width.saturating_sub(24),
                "e.g. 123-456-789",
                p.muted,
            );
        }
    } else {
        let display_text = if presentation.remote_id_focused {
            format!("{}|", presentation.remote_id_input)
        } else {
            presentation.remote_id_input.clone()
        };
        locked_label(
            canvas,
            input_rect.x + 12,
            input_rect.y + 11,
            input_rect.width.saturating_sub(24),
            &display_text,
            p.foreground,
        );
    }
}

fn draw_locked_remote_id_card(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let remote_id_card = layout.remote_id_card_rect();
    canvas.fill_rect(
        remote_id_card.x,
        remote_id_card.y,
        remote_id_card.width,
        remote_id_card.height,
        p.surface,
    );
    canvas.stroke_rect(
        remote_id_card.x,
        remote_id_card.y,
        remote_id_card.width,
        remote_id_card.height,
        1,
        p.border,
    );
    locked_label(
        canvas,
        remote_id_card.x + 16,
        remote_id_card.y + 14,
        remote_id_card.width.saturating_sub(32),
        "CONNECT TO REMOTE DEVICE",
        p.muted,
    );

    draw_locked_remote_id_input(canvas, presentation, layout.remote_id_input_rect(), p);

    let connect_btn = layout.remote_id_connect_btn_rect();
    let connect_enabled = !presentation.remote_id_input.is_empty();
    canvas.fill_rect(
        connect_btn.x,
        connect_btn.y,
        connect_btn.width,
        connect_btn.height,
        if connect_enabled { p.accent } else { p.border },
    );
    canvas.stroke_rect(
        connect_btn.x,
        connect_btn.y,
        connect_btn.width,
        connect_btn.height,
        1,
        if connect_enabled { p.accent } else { p.border },
    );
    locked_label(
        canvas,
        connect_btn.x + 18,
        connect_btn.y + 11,
        connect_btn.width.saturating_sub(36),
        "CONNECT",
        if connect_enabled {
            p.foreground
        } else {
            p.muted
        },
    );
}

fn draw_locked_dual_role_cards(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    draw_locked_your_id_card(canvas, presentation, layout, p);
    draw_locked_remote_id_card(canvas, presentation, layout, p);

    let screen = layout.remote_screen;
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 248,
        screen.width.saturating_sub(44),
        "Remote access requires verified peer identity and explicit permission",
        p.muted,
    );
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

    if presentation.help_open {
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 22,
            screen.width - 44,
            "KMJ OmniDesk Help & Shortcuts",
            p.foreground,
        );
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 48,
            screen.width - 44,
            "Navigation: [D] Devices, [C] Connections, [F] File Transfer",
            p.muted,
        );
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 73,
            screen.width - 44,
            "Management: [M] Automation, [S] Security, [O] Settings",
            p.muted,
        );
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 98,
            screen.width - 44,
            "Session: [1] Data Saver, [2] Balanced, [3] High, [X] Disconnect",
            p.muted,
        );
        locked_label(
            canvas,
            screen.x + 22,
            screen.y + 123,
            screen.width - 44,
            "Click HELP again to close",
            p.accent,
        );
    } else {
        draw_locked_dual_role_cards(canvas, presentation, layout, p);
    }
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
        "Send Keys",
        "Clipboard",
        "File Transfer",
        "Remote Shell",
        "Screenshot",
        "More",
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
        "Session Details",
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
        "Actions  /  Unavailable",
        p.foreground,
    );
    for (index, text) in ["File Transfer", "Remote Reboot", "Clipboard", "Unattended"]
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
    }
}

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
        "Connection Status",
        p.foreground,
    );
    canvas.dot(info_x + 5, status_y + 47, 4, p.muted);
    locked_label(
        canvas,
        info_x + 17,
        status_y + 43,
        info_w - 17,
        "No verified connection",
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

// Enterprise Premium V7: real native software rendering, not a flattened
// screenshot. Inputs and hitboxes share PremiumDashboardLayout.
fn premium_panel(
    canvas: &mut Canvas<'_>,
    rect: crate::layout::DashboardRect,
    p: Palette,
    accent: bool,
) {
    canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, p.surface);
    canvas.stroke_rect(
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        1,
        if accent { 0x80_24_43 } else { p.border },
    );
    if accent {
        canvas.fill_rect(rect.x + 1, rect.y + 1, rect.width.saturating_sub(2), 2, 0x73_1b_37);
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn premium_orbit(
    canvas: &mut Canvas<'_>,
    cx: usize,
    cy: usize,
    rx: usize,
    ry: usize,
    color: u32,
) {
    const STEPS: usize = 240;
    for step in 0..STEPS {
        let angle = step as f32 * std::f32::consts::TAU / STEPS as f32;
        let fx = cx as f32 + rx as f32 * angle.cos();
        let fy = cy as f32 + ry as f32 * angle.sin();
        if fx >= 0.0 && fy >= 0.0 {
            canvas.fill_rect(fx.round() as usize, fy.round() as usize, 2, 2, color);
        }
    }
}

fn draw_premium_dashboard(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &crate::PremiumDashboardLayout,
    p: Palette,
) {
    use omnidesk_core::product_shell::{NavTab, PrimaryView};

    // Top chrome: exactly one official brand mark + company wordmark.
    canvas.fill_rect(0, 0, canvas.width, layout.header_height, 0x0b_0d_17);
    canvas.h_line(0, layout.header_height - 1, canvas.width, 0x6e_17_34);
    if let Some(mark) = official_kmj_mark() {
        canvas.image_rgba(
            (22, 11, 48, 48),
            (
                usize::try_from(mark.width).unwrap_or(0),
                usize::try_from(mark.height).unwrap_or(0),
            ),
            &mark.rgba,
        );
    }
    canvas.text(77, 15, "KMJ TECHNO", 2, p.foreground);
    canvas.text(79, 44, "INNOVATE | BUILD | SCALE", 1, p.muted);
    canvas.fill_rect(296, 16, 1, 40, p.accent);
    canvas.text(326, 19, "OmniDesk", 2, p.foreground);
    canvas.fill_rect(458, 22, 96, 28, 0x85_12_2d);
    canvas.stroke_rect(458, 22, 96, 28, 1, p.accent);
    locked_label(canvas, 471, 29, 78, "Enterprise", p.foreground);
    locked_label(
        canvas,
        582,
        30,
        canvas.width.saturating_sub(860),
        "Unified Remote Access & Support Platform",
        p.muted,
    );
    locked_label(
        canvas,
        canvas.width.saturating_sub(203),
        29,
        192,
        "HELP    SETTINGS",
        p.muted,
    );

    // Left rail: six existing destinations are backed by real shell state.
    let nav = layout.navigation;
    canvas.fill_rect(nav.x, nav.y, nav.width, nav.height, 0x0d_11_19);
    canvas.fill_rect(nav.width.saturating_sub(1), nav.y, 1, nav.height, p.border);
    let nav_labels = [
        "Dashboard",
        "Remote Access",
        "My Devices",
        "Sessions",
        "File Transfer",
        "Multi-Monitor",
        "Collaboration",
        "Security & Access",
        "Users & Teams",
        "Licensing",
        "Reports & Logs",
        "Settings",
    ];
    for (i, label) in nav_labels.iter().enumerate() {
        let rect = layout.nav_row(i);
        let selected = match presentation.nav_tab {
            NavTab::Devices => i == 0,
            NavTab::Connections => i == 3,
            NavTab::FileTransfer => i == 4,
            NavTab::Security => i == 7,
            NavTab::Settings => i == 11,
            _ => false,
        };
        let available = matches!(i, 0 | 1 | 2 | 3 | 4 | 7 | 11);
        if selected {
            canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, 0x7d_16_30);
            canvas.fill_rect(rect.x, rect.y, 3, rect.height, p.accent);
        }
        canvas.stroke_rect(
            rect.x + 16,
            rect.y + 11,
            16,
            13,
            1,
            if selected { p.foreground } else { p.muted },
        );
        locked_label(
            canvas,
            rect.x + 50,
            rect.y + 12,
            rect.width.saturating_sub(61),
            label,
            if selected {
                p.foreground
            } else if available {
                0xcb_cf_da
            } else {
                0x77_7e_8c
            },
        );
    }
    locked_label(
        canvas,
        nav.x + 20,
        nav.y + nav.height.saturating_sub(25),
        nav.width.saturating_sub(40),
        "Pre-alpha  |  Not released",
        p.muted,
    );

    // Hero: abstract network art cannot be mistaken for live connectivity.
    let hero = layout.hero;
    canvas.fill_rect(hero.x, hero.y, hero.width, hero.height, 0x12_0d_19);
    canvas.fill_rect(hero.x, hero.y + hero.height - 2, hero.width, 2, 0x9b_11_35);
    canvas.text(hero.x + 20, hero.y + 26, "KMJ OmniDesk", 3, p.foreground);
    locked_label(
        canvas,
        hero.x + 22,
        hero.y + 78,
        hero.width.saturating_sub(44),
        "Secure Remote Access  |  Support  |  Manage  |  Collaborate",
        0xdc_d6_e0,
    );
    let globe_x = hero.x + hero.width.saturating_sub(205);
    let globe_y = hero.y + 83;
    premium_orbit(canvas, globe_x, globe_y, 141, 63, 0xa7_1b_46);
    premium_orbit(canvas, globe_x, globe_y, 72, 63, 0x5d_27_48);
    premium_orbit(canvas, globe_x, globe_y, 33, 63, 0x51_2a_47);
    premium_orbit(canvas, globe_x, globe_y, 141, 29, 0xcb_1b_4c);
    premium_orbit(canvas, globe_x, globe_y, 169, 37, p.accent);
    for (dx, dy) in [(-80_i32, -36_i32), (36, -51), (104, -12), (-30, 48)] {
        let px = i32::try_from(globe_x).unwrap_or(i32::MAX).saturating_add(dx);
        let py = i32::try_from(globe_y).unwrap_or(i32::MAX).saturating_add(dy);
        if let (Ok(x), Ok(y)) = (usize::try_from(px), usize::try_from(py)) {
            canvas.dot(x, y, 3, p.accent);
        }
    }

    let share = layout.share;
    let connect = layout.connect;
    for rect in [share, connect] {
        premium_panel(canvas, rect, p, true);
    }
    locked_label(
        canvas,
        share.x + 21,
        share.y + 22,
        share.width.saturating_sub(42),
        "THIS DEVICE  /  SHARE ACCESS",
        p.foreground,
    );
    locked_label(
        canvas,
        share.x + 21,
        share.y + 49,
        share.width.saturating_sub(42),
        "Allow another person to access this computer",
        p.muted,
    );
    locked_label(
        canvas,
        share.x + 21,
        share.y + 76,
        share.width.saturating_sub(42),
        "YOUR DEVICE ID",
        0xdd_e0_e8,
    );
    canvas.fill_rect(share.x + 19, share.y + 91, share.width.saturating_sub(38), 38, 0x19_20_2e);
    canvas.stroke_rect(share.x + 19, share.y + 91, share.width.saturating_sub(38), 38, 1, 0x58_5d_6b);
    locked_label(
        canvas,
        share.x + 31,
        share.y + 104,
        share.width.saturating_sub(147),
        if presentation.local_device_id.is_empty() {
            "NOT INITIALIZED"
        } else {
            &presentation.local_device_id
        },
        p.foreground,
    );
    let copy = layout.local_id_copy();
    canvas.fill_rect(copy.x, copy.y, copy.width, copy.height, p.border);
    locked_label(
        canvas,
        copy.x + 7,
        copy.y + 13,
        copy.width.saturating_sub(14),
        if presentation.local_device_id.is_empty() {
            "NO ID"
        } else {
            "COPY ID"
        },
        if presentation.local_device_id.is_empty() {
            p.muted
        } else {
            p.foreground
        },
    );
    locked_label(
        canvas,
        share.x + 21,
        share.y + 150,
        share.width.saturating_sub(42),
        "TEMPORARY SESSION PASSWORD",
        0xdd_e0_e8,
    );
    canvas.fill_rect(share.x + 19, share.y + 166, share.width.saturating_sub(38), 37, 0x15_19_26);
    canvas.stroke_rect(share.x + 19, share.y + 166, share.width.saturating_sub(38), 37, 1, p.border);
    locked_label(
        canvas,
        share.x + 33,
        share.y + 179,
        share.width.saturating_sub(66),
        "Not configured  /  host password unavailable",
        p.muted,
    );

    if presentation.primary_view == PrimaryView::PermissionPrompt {
        locked_label(
            canvas,
            share.x + 21,
            share.y + 212,
            share.width.saturating_sub(42),
            "INCOMING PEER: VERIFY BEFORE APPROVING",
            p.foreground,
        );
        for (i, control) in presentation.controls.iter().enumerate() {
            let rect = layout.permission_button(i);
            canvas.fill_rect(
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                if i == 0 { p.accent } else { p.border },
            );
            locked_label(
                canvas,
                rect.x + 13,
                rect.y + 13,
                rect.width.saturating_sub(26),
                if i == 0 { "ALLOW" } else { "DENY" },
                p.foreground,
            );
            let _ = control;
        }
    } else {
        canvas.fill_rect(share.x + 23, share.y + 225, 38, 21, 0x4b_4e_5b);
        canvas.dot(share.x + 34, share.y + 235, 7, p.muted);
        locked_label(
            canvas,
            share.x + 77,
            share.y + 231,
            share.width.saturating_sub(90),
            "Allow remote control  /  Not configured",
            p.muted,
        );
    }

    locked_label(
        canvas,
        connect.x + 20,
        connect.y + 22,
        connect.width.saturating_sub(40),
        "CONNECT TO REMOTE DEVICE",
        p.foreground,
    );
    locked_label(
        canvas,
        connect.x + 20,
        connect.y + 49,
        connect.width.saturating_sub(40),
        "Access a trusted peer with explicit permission",
        p.muted,
    );
    locked_label(
        canvas,
        connect.x + 20,
        connect.y + 76,
        connect.width.saturating_sub(40),
        "REMOTE DEVICE ID",
        0xdd_e0_e8,
    );
    let input = layout.remote_id_input();
    canvas.fill_rect(input.x, input.y, input.width, input.height, 0x19_20_2e);
    canvas.stroke_rect(
        input.x,
        input.y,
        input.width,
        input.height,
        if presentation.remote_id_focused { 2 } else { 1 },
        if presentation.remote_id_focused {
            p.accent
        } else {
            0x58_5d_6b
        },
    );
    locked_label(
        canvas,
        input.x + 13,
        input.y + 12,
        input.width.saturating_sub(26),
        if presentation.remote_id_input.is_empty() {
            "Enter remote device ID"
        } else {
            &presentation.remote_id_input
        },
        if presentation.remote_id_input.is_empty() {
            p.muted
        } else {
            p.foreground
        },
    );
    locked_label(
        canvas,
        connect.x + 20,
        connect.y + 150,
        connect.width.saturating_sub(40),
        "SESSION PASSWORD",
        0xdd_e0_e8,
    );
    canvas.fill_rect(connect.x + 19, connect.y + 166, connect.width.saturating_sub(38), 37, 0x15_19_26);
    canvas.stroke_rect(connect.x + 19, connect.y + 166, connect.width.saturating_sub(38), 37, 1, p.border);
    locked_label(
        canvas,
        connect.x + 33,
        connect.y + 179,
        connect.width.saturating_sub(66),
        "Password sign-in not yet available",
        p.muted,
    );
    let button = layout.remote_connect_button();
    let ready = !presentation.remote_id_input.is_empty();
    canvas.fill_rect(
        button.x,
        button.y,
        button.width,
        button.height,
        if ready { p.accent } else { 0x60_20_33 },
    );
    canvas.stroke_rect(button.x, button.y, button.width, button.height, 1, 0xe0_29_4b);
    locked_label(
        canvas,
        button.x + 15,
        button.y + 14,
        button.width.saturating_sub(30),
        "CONNECT TRUSTED PEER",
        if ready { p.foreground } else { 0xbc_b4_c1 },
    );

    // Seven capability tiles. In a verified session, the available session
    // controls replace the decorative tiles, using the same hit geometry.
    let feature = layout.features;
    let labels = [
        "Remote Control",
        "File Transfer",
        "Multi-Monitor",
        "Audio & Voice",
        "Clipboard Sync",
        "Session Record",
        "Unattended",
    ];
    if presentation.primary_view == PrimaryView::Session {
        for (i, control) in presentation.controls.iter().enumerate() {
            let rect = layout.session_button(i, presentation.controls.len());
            premium_panel(canvas, rect, p, i == presentation.controls.len().saturating_sub(1));
            locked_label(
                canvas,
                rect.x + 8,
                rect.y + 26,
                rect.width.saturating_sub(16),
                &control.label,
                p.foreground,
            );
        }
    } else {
        let tile_width = feature.width / labels.len();
        for (i, label) in labels.iter().enumerate() {
            let rect = crate::layout::DashboardRect {
                x: feature.x + i * tile_width + 3,
                y: feature.y,
                width: tile_width.saturating_sub(6),
                height: feature.height,
            };
            premium_panel(canvas, rect, p, i == 0);
            canvas.stroke_rect(rect.x + rect.width / 2 - 10, rect.y + 14, 20, 16, 1, p.muted);
            locked_label(
                canvas,
                rect.x + 9,
                rect.y + 56,
                rect.width.saturating_sub(18),
                label,
                if i == 0 { p.foreground } else { p.muted },
            );
        }
    }

    // Device names originate from real shell directory entries only.
    let devices = layout.devices;
    let sessions = layout.sessions;
    premium_panel(canvas, devices, p, false);
    premium_panel(canvas, sessions, p, false);
    locked_label(
        canvas,
        devices.x + 19,
        devices.y + 20,
        devices.width.saturating_sub(38),
        "MY DEVICES",
        p.foreground,
    );
    locked_label(
        canvas,
        sessions.x + 19,
        sessions.y + 20,
        sessions.width.saturating_sub(38),
        "RECENT SESSIONS",
        p.foreground,
    );
    if presentation.nav_tab == NavTab::Devices && presentation.primary_view == PrimaryView::Devices {
        let mut rendered = 0;
        for (i, control) in presentation.controls.iter().take(3).enumerate() {
            if !control.enabled {
                continue;
            }
            let rect = layout.device_row(i);
            canvas.h_line(rect.x, rect.y + rect.height, rect.width, p.border);
            canvas.dot(
                rect.x + 12,
                rect.y + 15,
                4,
                VERIFIED_GREEN,
            );
            locked_label(
                canvas,
                rect.x + 27,
                rect.y + 9,
                rect.width.saturating_sub(33),
                &control.label,
                p.foreground,
            );
            rendered += 1;
        }
        if rendered == 0 {
            locked_label(
                canvas,
                devices.x + 19,
                devices.y + 90,
                devices.width.saturating_sub(38),
                "No verified online devices",
                p.muted,
            );
        }
    } else {
        locked_label(
            canvas,
            devices.x + 19,
            devices.y + 90,
            devices.width.saturating_sub(38),
            "Select Dashboard to view devices",
            p.muted,
        );
    }
    locked_label(
        canvas,
        sessions.x + 19,
        sessions.y + 90,
        sessions.width.saturating_sub(38),
        "No verified session history available",
        p.muted,
    );

    // Right inspector: never fabricate entitlement, security, relay or latency.
    let license = layout.license;
    let health = layout.health;
    let quick = layout.quick_actions;
    for rect in [license, health, quick] {
        premium_panel(canvas, rect, p, false);
    }
    locked_label(canvas, license.x + 18, license.y + 23, license.width - 36, "ENTERPRISE LICENSE", p.foreground);
    locked_label(canvas, license.x + 18, license.y + 56, license.width - 36, "Not verified by KMJ Main Platform", p.muted);
    locked_label(canvas, license.x + 18, license.y + 101, license.width - 36, "Seats                     Unavailable", p.muted);
    canvas.fill_rect(license.x + 18, license.y + 139, license.width - 36, 7, p.border);
    locked_label(canvas, license.x + 18, license.y + 171, license.width - 36, "Valid until                            --", p.muted);

    locked_label(canvas, health.x + 18, health.y + 21, health.width - 36, "SYSTEM STATUS", p.foreground);
    for (i, status) in [
        "App shell           Pre-alpha",
        "Transport           Not verified",
        "Relay path          Not established",
        "Encryption          No active session",
    ].iter().enumerate() {
        canvas.dot(health.x + 23, health.y + 61 + i * 31, 3, p.muted);
        locked_label(
            canvas,
            health.x + 38,
            health.y + 56 + i * 31,
            health.width.saturating_sub(56),
            status,
            p.muted,
        );
    }
    locked_label(canvas, quick.x + 18, quick.y + 21, quick.width - 36, "QUICK ACTIONS", p.foreground);
    let quick_actions = [
        "New Session",
        "Wake on LAN",
        "Remote CMD",
        "Send File",
        "Get Logs",
        "Invite User",
    ];
    for (i, action) in quick_actions.iter().enumerate() {
        let columns = 3;
        let cell_width = (quick.width - 32) / columns;
        let x = quick.x + 17 + (i % columns) * cell_width;
        let y = quick.y + 63 + (i / columns) * 96;
        canvas.fill_rect(x + 2, y, cell_width.saturating_sub(8), 83, 0x17_1a_27);
        canvas.stroke_rect(x + 2, y, cell_width.saturating_sub(8), 83, 1, p.border);
        locked_label(
            canvas,
            x + 7,
            y + 44,
            cell_width.saturating_sub(18),
            action,
            p.muted,
        );
    }

    // Footer never turns unverified demo values into operational badges.
    let footer = layout.footer;
    canvas.h_line(footer.x, footer.y, footer.width, p.border);
    canvas.dot(footer.x + 24, footer.y + 21, 4, p.muted);
    locked_label(
        canvas,
        footer.x + 38,
        footer.y + 15,
        footer.width.saturating_sub(340),
        "No verified remote session   |   Connection path unavailable",
        p.muted,
    );
    locked_label(
        canvas,
        footer.x + footer.width.saturating_sub(240),
        footer.y + 15,
        226,
        "KMJ OmniDesk  /  PRE-ALPHA",
        p.muted,
    );
}

fn draw_locked_dashboard(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    draw_locked_header(canvas, presentation, layout, p);
    for rect in [
        layout.navigation,
        layout.devices,
        layout.viewer,
        layout.inspector,
    ] {
        locked_frame(canvas, rect.x, rect.y, rect.width, rect.height, p);
    }
    draw_locked_navigation(canvas, presentation, layout, p);
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
    if let Some(premium) = crate::PremiumDashboardLayout::for_window(width, height) {
        draw_premium_dashboard(&mut canvas, presentation, &premium, palette);
        return;
    }
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
    fn locked_design_preserves_lowercase_typography() {
        let mut lower_pixels = vec![0_u32; 16 * 12];
        let mut upper_pixels = vec![0_u32; 16 * 12];
        Canvas {
            pixels: &mut lower_pixels,
            width: 16,
            height: 12,
        }
        .text(0, 0, "a", 1, 0x00_ff_ff);
        Canvas {
            pixels: &mut upper_pixels,
            width: 16,
            height: 12,
        }
        .text(0, 0, "A", 1, 0x00_ff_ff);
        assert_ne!(
            lower_pixels, upper_pixels,
            "lowercase navigation must remain lowercase"
        );
    }

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
        // Quick-connect belongs to the compact fallback. At >=1180px the
        // locked four-column dashboard intentionally replaces this view.
        let width = 960;
        let height = 800;
        let shell = ProductShell::new();
        let presentation = presentation_for(&shell);
        let mut pixels = vec![0_u32; width * height];
        render_shell(&mut pixels, width, height, &presentation);
        let layout = ShellLayout::for_window(width, height).expect("compact layout");
        assert!(LockedDashboardLayout::for_window(width, height).is_none());
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
    fn locked_empty_directory_is_not_covered_by_a_disabled_placeholder_row() {
        let model = presentation_for(&ProductShell::new());
        let width = 1419;
        let height = 611;
        let layout = LockedDashboardLayout::for_window(width, height).unwrap();
        let mut pixels = vec![0_u32; width * height];
        render_shell(&mut pixels, width, height, &model);

        // The placeholder must not paint a dark row behind the empty-state
        // prompt. A genuine peer row begins at the same y-position.
        let x = layout.devices.x + 9;
        let y = layout.device_row(0).y + 20;
        assert_eq!(
            pixels[y * width + x],
            packed_rgb(model.visual.surface_rgb),
            "the fake placeholder row obscured the truthful empty-state text"
        );
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
