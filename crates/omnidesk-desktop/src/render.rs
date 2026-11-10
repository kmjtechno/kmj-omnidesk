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
    canvas.text(70, 19, "KMJ TECHNO", 2, p.foreground);
    canvas.text(
        70,
        45,
        "OMNIDESK  /  INNOVATE  |  BUILD  |  SCALE",
        1,
        p.muted,
    );

    let search_x = canvas.width / 3;
    let search_w = canvas.width / 3;
    canvas.fill_rect(search_x, 15, search_w, 37, p.background);
    canvas.stroke_rect(search_x, 15, search_w, 37, 1, p.border);
    locked_label(
        canvas,
        search_x + 14,
        29,
        search_w.saturating_sub(28),
        "SECURE REMOTE ACCESS  /  ONE APP, EVERY DESK",
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
        "Remote Access",
        "Sessions",
        "File Transfer",
        "Remote Actions",
        "Automation",
        "Security Center",
        "Preferences",
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
    locked_label(
        canvas,
        nav.x + 14,
        nav.y + 12,
        nav.width.saturating_sub(28),
        "WORKSPACE",
        p.muted,
    );
    for (index, label) in nav_labels.iter().enumerate() {
        let rect = layout.nav_tab_rect(index);
        let active = nav_tabs[index] == presentation.nav_tab;
        if active {
            canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, p.accent);
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
        presentation.status,
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
    let area = layout.devices;
    let filter = presentation.device_filter;
    for (index, (label, active)) in [
        ("ALL", filter == omnidesk_core::product_shell::DeviceFilter::All),
        ("ONLINE", filter == omnidesk_core::product_shell::DeviceFilter::Online),
        ("OFFLINE", filter == omnidesk_core::product_shell::DeviceFilter::Offline),
    ]
    .iter()
    .enumerate()
    {
        let rect = match index {
            0 => layout.filter_all_rect(),
            1 => layout.filter_online_rect(),
            _ => layout.filter_offline_rect(),
        };
        locked_label(
            canvas,
            rect.x,
            rect.y,
            rect.width,
            label,
            if *active { p.foreground } else { p.muted },
        );
    }
    let empty = presentation.controls.iter().all(|control| !control.enabled);
    if empty {
        locked_label(
            canvas,
            area.x + 14,
            area.y + 53,
            area.width.saturating_sub(28),
            "No enrolled devices. Use Remote ID to request verified access.",
            p.muted,
        );
        return;
    }
    for (index, control) in presentation.controls.iter().take(3).enumerate() {
        let rect = layout.device_row(index);
        if !control.enabled {
            continue;
        }
        canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, p.background);
        canvas.stroke_rect(rect.x, rect.y, rect.width, rect.height, 1, p.border);
        canvas.dot(rect.x + 11, rect.y + 21, 4, VERIFIED_GREEN);
        locked_label(
            canvas,
            rect.x + 24,
            rect.y + 18,
            rect.width.saturating_sub(32),
            &control.label,
            p.foreground,
        );
    }
}

fn draw_locked_devices(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let area = layout.devices;
    canvas.fill_rect(area.x, area.y, area.width, area.height, p.surface);
    canvas.stroke_rect(area.x, area.y, area.width, area.height, 1, p.border);
    locked_label(
        canvas,
        area.x + 14,
        area.y + 12,
        area.width.saturating_sub(28),
        "TRUSTED DEVICES",
        p.foreground,
    );
    if presentation.nav_tab == omnidesk_core::product_shell::NavTab::Devices {
        draw_locked_device_rows(canvas, presentation, layout, p);
    } else {
        let status = match presentation.nav_tab {
            omnidesk_core::product_shell::NavTab::Connections => {
                "Sessions require a verified peer"
            }
            omnidesk_core::product_shell::NavTab::FileTransfer => {
                "File transfer requires an authorized session"
            }
            omnidesk_core::product_shell::NavTab::RemoteActions => {
                "Remote actions require scoped permission"
            }
            omnidesk_core::product_shell::NavTab::Automation => "No verified automation session",
            omnidesk_core::product_shell::NavTab::Security => {
                "Peer identity must be verified before control"
            }
            omnidesk_core::product_shell::NavTab::Settings => "Local session settings",
            omnidesk_core::product_shell::NavTab::Devices => "No device selected",
        };
        locked_label(
            canvas,
            area.x + 14,
            area.y + 53,
            area.width.saturating_sub(28),
            status,
            p.muted,
        );
    }
}

#[allow(clippy::too_many_lines)]
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
    canvas.fill_rect(
        your_id_card.x + 1,
        your_id_card.y + 1,
        your_id_card.width.saturating_sub(2),
        2,
        p.border,
    );
    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 14,
        your_id_card.width.saturating_sub(32),
        "02  /  SHARE THIS DEVICE",
        p.accent,
    );
    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 30,
        your_id_card.width.saturating_sub(32),
        "Your ID & password",
        p.foreground,
    );

    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 41,
        your_id_card.width.saturating_sub(145),
        "YOUR DEVICE ID",
        p.muted,
    );
    let id_str = if presentation.local_device_id.is_empty() {
        "KMJ-..."
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

    // Real host session password lifecycle display
    let password = layout.your_password_status_rect();
    canvas.h_line(
        password.x,
        password.y.saturating_sub(12),
        password.width,
        p.border,
    );
    locked_label(
        canvas,
        password.x,
        password.y,
        password.width,
        &format!("YOUR PASSWORD: {}", presentation.local_password_display),
        p.foreground,
    );

    let rev_btn = layout.your_password_reveal_btn_rect();
    canvas.stroke_rect(
        rev_btn.x,
        rev_btn.y,
        rev_btn.width,
        rev_btn.height,
        1,
        p.border,
    );
    locked_label(
        canvas,
        rev_btn.x + 8,
        rev_btn.y + 4,
        rev_btn.width.saturating_sub(16),
        if presentation.local_password_revealed {
            "HIDE"
        } else {
            "SHOW"
        },
        p.muted,
    );

    let cp_btn = layout.your_password_copy_btn_rect();
    canvas.stroke_rect(cp_btn.x, cp_btn.y, cp_btn.width, cp_btn.height, 1, p.border);
    locked_label(
        canvas,
        cp_btn.x + 8,
        cp_btn.y + 4,
        cp_btn.width.saturating_sub(16),
        "COPY",
        p.muted,
    );

    let rot_btn = layout.your_password_rotate_btn_rect();
    canvas.stroke_rect(
        rot_btn.x,
        rot_btn.y,
        rot_btn.width,
        rot_btn.height,
        1,
        p.border,
    );
    locked_label(
        canvas,
        rot_btn.x + 8,
        rot_btn.y + 4,
        rot_btn.width.saturating_sub(16),
        "NEW",
        p.muted,
    );
    locked_label(
        canvas,
        your_id_card.x + 16,
        your_id_card.y + 159,
        your_id_card.width.saturating_sub(32),
        if presentation.local_password_display == "NOT CONFIGURED" {
            "Generate a temporary password to share this device"
        } else {
            "Secure access still requires verified transport and permission"
        },
        p.muted,
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

#[allow(clippy::too_many_lines)]
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
    canvas.fill_rect(
        remote_id_card.x + 1,
        remote_id_card.y + 1,
        remote_id_card.width.saturating_sub(2),
        2,
        p.accent,
    );
    locked_label(
        canvas,
        remote_id_card.x + 16,
        remote_id_card.y + 14,
        remote_id_card.width.saturating_sub(32),
        "01  /  TAKE CONTROL",
        p.accent,
    );
    locked_label(
        canvas,
        remote_id_card.x + 16,
        remote_id_card.y + 29,
        remote_id_card.width.saturating_sub(32),
        "Connect to another desktop",
        p.foreground,
    );

    // Explicit field captions match the locked V5 connection workflow.
    locked_label(
        canvas,
        remote_id_card.x + 16,
        remote_id_card.y + 40,
        remote_id_card.width.saturating_sub(32),
        "REMOTE ID",
        p.muted,
    );
    draw_locked_remote_id_input(canvas, presentation, layout.remote_id_input_rect(), p);

    let connect_btn = layout.remote_id_connect_btn_rect();
    let connect_enabled = !presentation.remote_id_input.is_empty()
        && !presentation.remote_password_input_masked.is_empty();
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
        "CONNECT SECURELY",
        if connect_enabled {
            p.foreground
        } else {
            p.muted
        },
    );
    locked_label(
        canvas,
        remote_id_card.x + 16,
        remote_id_card.y + if layout.compact_height() { 82 } else { 88 },
        remote_id_card.width.saturating_sub(32),
        "SESSION PASSWORD",
        p.muted,
    );
    // Remote session password input
    let password = layout.remote_password_status_rect();
    canvas.fill_rect(
        password.x,
        password.y,
        password.width,
        password.height,
        p.background,
    );
    let pw_border_color = if presentation.remote_password_focused {
        p.accent
    } else {
        p.border
    };
    canvas.stroke_rect(
        password.x,
        password.y,
        password.width,
        password.height,
        if presentation.remote_password_focused {
            2
        } else {
            1
        },
        pw_border_color,
    );
    if presentation.remote_password_input_masked.is_empty() {
        locked_label(
            canvas,
            password.x + 10,
            password.y + 11,
            password.width.saturating_sub(20),
            if presentation.remote_password_focused {
                "|"
            } else {
                "Enter session password"
            },
            if presentation.remote_password_focused {
                p.accent
            } else {
                p.muted
            },
        );
    } else {
        let text = if presentation.remote_password_focused {
            format!("{}|", presentation.remote_password_input_masked)
        } else {
            presentation.remote_password_input_masked.clone()
        };
        locked_label(
            canvas,
            password.x + 10,
            password.y + 11,
            password.width.saturating_sub(20),
            &text,
            p.foreground,
        );
    }
}

fn draw_locked_dual_role_cards(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    // The approved V5 first screen always leads with the two concrete
    // workflows. A separate remote-display stage follows them at every
    // supported desktop size, including compact-height 1419x611.
    draw_locked_remote_id_card(canvas, presentation, layout, p);
    draw_locked_your_id_card(canvas, presentation, layout, p);

    let stage = layout.remote_stage_rect();
    canvas.fill_rect(stage.x, stage.y, stage.width, stage.height, p.background);
    canvas.stroke_rect(stage.x, stage.y, stage.width, stage.height, 1, p.border);
    canvas.fill_rect(
        stage.x + 1,
        stage.y + 1,
        stage.width.saturating_sub(2),
        31,
        p.surface,
    );
    canvas.dot(stage.x + 16, stage.y + 16, 3, p.accent);
    canvas.dot(stage.x + 28, stage.y + 16, 3, p.border);
    canvas.dot(stage.x + 40, stage.y + 16, 3, p.border);
    locked_label(
        canvas,
        stage.x + 54,
        stage.y + 12,
        stage.width.saturating_sub(72),
        "REMOTE DISPLAY  /  NO VERIFIED CONNECTION",
        p.foreground,
    );

    // A premium empty state, not a simulated remote screenshot and never
    // a fabricated connected status. Keep the viewport useful at 600px.
    if stage.height >= 175 {
        let icon_x = stage.x + stage.width / 2;
        let icon_y = stage.y + (stage.height / 2).saturating_sub(21);
        canvas.stroke_rect(
            icon_x.saturating_sub(20),
            icon_y.saturating_sub(19),
            40,
            29,
            2,
            p.border,
        );
        canvas.fill_rect(icon_x.saturating_sub(2), icon_y + 11, 4, 8, p.border);
        canvas.h_line(icon_x.saturating_sub(12), icon_y + 20, 24, p.border);
        locked_label(
            canvas,
            stage.x + 18,
            icon_y + 35,
            stage.width.saturating_sub(36),
            "Your remote screen starts here",
            p.foreground,
        );
        locked_label(
            canvas,
            stage.x + 18,
            icon_y + 60,
            stage.width.saturating_sub(36),
            "Enter a device ID and password; remote control needs verified access.",
            p.muted,
        );
    } else {
        locked_label(
            canvas,
            stage.x + 18,
            stage.y + 49,
            stage.width.saturating_sub(36),
            "Your remote screen starts here",
            p.foreground,
        );
        locked_label(
            canvas,
            stage.x + 18,
            stage.y + 71,
            stage.width.saturating_sub(36),
            "Requires authenticated transport and target permission",
            p.muted,
        );
    }
}

/// V5 sidebar pages must not all render the same Remote Access form.
///
/// The source of truth for these states remains ProductShell. These are
/// dedicated, clearly labelled feature views, not fake device data or
/// actionable features that require a verified remote connection.
fn draw_locked_feature_page(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    use omnidesk_core::product_shell::NavTab;

    let (category, heading, explanation, cards) = match presentation.nav_tab {
        NavTab::Connections => (
            "SESSION MANAGEMENT",
            "Sessions & history",
            "Every remote session must have verified identity and explicit access.",
            [
                ("ACTIVE SESSION", "None verified"),
                ("CONNECTION HISTORY", "No verified sessions to show"),
                ("ACCESS PERMISSIONS", "Granted only after secure verification"),
            ],
        ),
        NavTab::FileTransfer => (
            "SECURE TRANSFER",
            "File transfer",
            "Send and receive files only within an authorized encrypted session.",
            [
                ("TRANSFER QUEUE", "No active transfers"),
                ("RECENT ACTIVITY", "No verified transfer records"),
                ("ACCESS CONTROL", "Remote file access unavailable offline"),
            ],
        ),
        NavTab::RemoteActions => (
            "REMOTE OPERATIONS",
            "Remote actions",
            "Keyboard, clipboard and device actions are permission-gated.",
            [
                ("KEYBOARD & MOUSE", "Requires verified remote control"),
                ("CLIPBOARD", "Synchronization unavailable offline"),
                ("SYSTEM ACTIONS", "Explicit authorization required"),
            ],
        ),
        NavTab::Automation => (
            "AUTOMATION WORKSPACE",
            "Automation",
            "Unattended work must be separately approved and access-scoped.",
            [
                ("ACTIVE TASKS", "No verified remote tasks"),
                ("UNATTENDED ACCESS", "Not authorized in this session"),
                ("SECURITY POLICY", "No automatic elevation of privilege"),
            ],
        ),
        NavTab::Security => (
            "TRUST & ACCESS",
            "Security center",
            "Peer verification, session passwords and explicit permissions.",
            [
                ("PEER IDENTITY", "Authenticated transport required"),
                ("SESSION PASSWORD", "Configure in your device panel"),
                ("REMOTE PERMISSIONS", "Fail closed until authorized"),
            ],
        ),
        NavTab::Settings => (
            "WORKSPACE SETTINGS",
            "Preferences",
            "Customize your local experience without relaxing security.",
            [
                ("DISPLAY QUALITY", "Configurable after session verification"),
                ("ACCESSIBILITY", "Keyboard and screen reader enabled"),
                ("NETWORK", "No secure remote channel established"),
            ],
        ),
        NavTab::Devices => return,
    };
    let frame = layout.remote_screen;
    canvas.fill_rect(frame.x, frame.y, frame.width, frame.height, p.background);
    canvas.stroke_rect(frame.x, frame.y, frame.width, frame.height, 1, p.border);
    canvas.fill_rect(frame.x + 1, frame.y + 1, frame.width.saturating_sub(2), 38, p.surface);
    canvas.fill_rect(frame.x + 1, frame.y + 1, 3, 38, p.accent);
    locked_label(
        canvas, frame.x + 18, frame.y + 14,
        frame.width.saturating_sub(36), category, p.accent,
    );
    canvas.text_clipped(
        frame.x + 18, frame.y + 60, heading, 2,
        frame.width.saturating_sub(36), p.foreground,
    );
    locked_label(
        canvas, frame.x + 18, frame.y + 105,
        frame.width.saturating_sub(36), explanation, p.muted,
    );
    let gap = 10;
    let gutter = 18;
    let width = frame.width.saturating_sub(gutter * 2 + gap * 2) / 3;
    let tile_height = if layout.compact_height() { 92 } else { 132 };
    for (index, (title, message)) in cards.iter().enumerate() {
        let x = frame.x + gutter + index * (width + gap);
        let y = frame.y + 145;
        canvas.fill_rect(x, y, width, tile_height, p.surface);
        canvas.stroke_rect(x, y, width, tile_height, 1, p.border);
        canvas.fill_rect(x + 11, y + 13, 3, 12, p.accent);
        locked_label(
            canvas, x + 23, y + 15,
            width.saturating_sub(32), title, p.foreground,
        );
        locked_label(
            canvas, x + 12, y + 48,
            width.saturating_sub(24), message, p.muted,
        );
    }
    if frame.height > 350 {
        canvas.h_line(
            frame.x + gutter,
            frame.y + 145 + tile_height + 24,
            frame.width.saturating_sub(gutter * 2),
            p.border,
        );
        locked_label(
            canvas, frame.x + gutter, frame.y + 145 + tile_height + 46,
            frame.width.saturating_sub(gutter * 2),
            "No remote operation is available until identity, transport and permissions are verified.",
            p.muted,
        );
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
        viewer.x + 18,
        viewer.y + 13,
        viewer.width.saturating_sub(36),
        "KMJ TECHNO  /  OMNIDESK  /  ACCESS DESK",
        p.muted,
    );
    let page_title = match presentation.nav_tab {
        omnidesk_core::product_shell::NavTab::Devices => "Remote control, reimagined.",
        omnidesk_core::product_shell::NavTab::Connections => "Sessions & history",
        omnidesk_core::product_shell::NavTab::FileTransfer => "File transfer",
        omnidesk_core::product_shell::NavTab::RemoteActions => "Remote actions",
        omnidesk_core::product_shell::NavTab::Automation => "Automation",
        omnidesk_core::product_shell::NavTab::Security => "Security center",
        omnidesk_core::product_shell::NavTab::Settings => "Preferences",
    };
    canvas.text_clipped(
        viewer.x + 18,
        viewer.y + 35,
        page_title,
        2,
        viewer.width.saturating_sub(36),
        p.foreground,
    );
    locked_label(
        canvas,
        viewer.x + 18,
        viewer.y + if layout.compact_height() { 51 } else { 66 },
        viewer.width.saturating_sub(36),
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

    if !matches!(
        presentation.nav_tab,
        omnidesk_core::product_shell::NavTab::Devices
    ) && presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices
        && !presentation.help_open
    {
        draw_locked_feature_page(canvas, presentation, layout, p);
    } else if presentation.help_open {
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
    } else if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Session {
        draw_locked_remote_workspace(canvas, presentation, layout, p);
    } else {
        draw_locked_dual_role_cards(canvas, presentation, layout, p);
    }
}

fn draw_locked_remote_workspace(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    // ProductShell permission state alone cannot prove transport video, FPS,
    // codec, cipher or round-trip latency. Only display verified facts.
    let screen = layout.remote_screen;
    canvas.fill_rect(screen.x, screen.y, screen.width, screen.height, p.background);
    canvas.stroke_rect(screen.x, screen.y, screen.width, screen.height, 1, p.border);
    canvas.fill_rect(screen.x, screen.y, screen.width, 35, p.surface);
    locked_label(
        canvas,
        screen.x + 16,
        screen.y + 12,
        screen.width.saturating_sub(32),
        "REMOTE DISPLAY  /  FRAME STREAM NOT VERIFIED",
        p.foreground,
    );

    let detail = presentation
        .details
        .iter()
        .find(|item| item.starts_with("Device:"))
        .map_or("No verified peer metadata", String::as_str);
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 68,
        screen.width.saturating_sub(44),
        detail,
        p.foreground,
    );
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 96,
        screen.width.saturating_sub(44),
        "Session permission does not establish an authenticated video stream.",
        p.muted,
    );
    locked_label(
        canvas,
        screen.x + 22,
        screen.y + 122,
        screen.width.saturating_sub(44),
        "Waiting for authenticated transport, frame decoder and peer consent.",
        p.muted,
    );

    let bar = layout.session_toolbar_rect();
    canvas.fill_rect(bar.x, bar.y, bar.width, bar.height, p.surface);
    canvas.stroke_rect(bar.x, bar.y, bar.width, bar.height, 1, p.border);
    let labels = [
        if presentation.remote_input_enabled { "INPUT ON" } else { "INPUT OFF" },
        "MONITORS",
        if presentation.clipboard_sync_enabled { "CLIP ON" } else { "CLIP OFF" },
        "FILES",
        if presentation.fullscreen_enabled { "EXIT FULL" } else { "FULLSCREEN" },
        "DISCONNECT",
    ];
    for (index, label) in labels.iter().enumerate() {
        let rect = layout.session_tool_btn_rect(index);
        canvas.fill_rect(
            rect.x, rect.y, rect.width, rect.height,
            if index == 5 { p.accent } else { p.border },
        );
        locked_label(
            canvas,
            rect.x + 8,
            rect.y + 12,
            rect.width.saturating_sub(16),
            label,
            p.foreground,
        );
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

fn draw_locked_inspector(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
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
        match presentation.primary_view {
            omnidesk_core::product_shell::PrimaryView::Devices => "No verified connection",
            omnidesk_core::product_shell::PrimaryView::PermissionPrompt => "Permission pending",
            omnidesk_core::product_shell::PrimaryView::Session => "Transport still unverified",
        },
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
    draw_locked_header(canvas, presentation, layout, p);
    for rect in [layout.navigation, layout.viewer] {
        locked_frame(canvas, rect.x, rect.y, rect.width, rect.height, p);
    }
    if layout.inspector.width > 0 {
        let rect = layout.inspector;
        locked_frame(canvas, rect.x, rect.y, rect.width, rect.height, p);
    }
    draw_locked_navigation(canvas, presentation, layout, p);
    draw_locked_remote_view(canvas, presentation, layout, p);
    draw_locked_session_tiles(canvas, presentation, layout, p);
    draw_locked_devices(canvas, presentation, layout, p);
    if layout.inspector.width > 0 {
        draw_locked_inspector(canvas, presentation, layout, p);
    }
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
    fn v5_offline_password_slots_are_neutral_and_never_show_fake_secrets() {
        let presentation = presentation_for(&ProductShell::new());
        let width = 1419;
        let height = 611;
        let layout = LockedDashboardLayout::for_window(width, height).unwrap();
        let mut pixels = vec![0_u32; width * height];
        render_shell(&mut pixels, width, height, &presentation);
        let own = layout.your_password_status_rect();
        let remote = layout.remote_password_status_rect();
        let border = packed_rgb(presentation.visual.border_rgb);
        assert_eq!(pixels[remote.y * width + remote.x], border);
        let connect = layout.remote_id_card_rect();
        if layout.access_cards_wide() {
            assert_eq!(own.y, connect.y);
            assert!(own.x >= connect.x + connect.width);
        } else {
            assert!(own.y + own.height <= connect.y);
        }
        assert!(
            remote.y + remote.height
                <= layout.remote_id_card_rect().y + layout.remote_id_card_rect().height
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
        let x = layout.devices.x + 3;
        let y = layout.device_row(0).y + 20;
        assert_eq!(
            pixels[y * width + x],
            packed_rgb(model.visual.surface_rgb),
            "a disabled placeholder must not paint a fake device tile"
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
