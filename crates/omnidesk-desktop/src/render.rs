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

    fn v_line(&mut self, x: usize, y: usize, line_height: usize, color: u32) {
        if x >= self.width {
            return;
        }
        let max_y = y.saturating_add(line_height).min(self.height);
        for py in y..max_y {
            self.pixels[py * self.width + x] = color;
        }
    }

    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    fn rounded_panel(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        r: usize,
        bg: u32,
        border: u32,
    ) {
        if w < 2 || h < 2 {
            return;
        }
        let r = r.min(w / 2).min(h / 2);
        self.fill_rect(x + r, y, w.saturating_sub(r * 2), h, bg);
        self.fill_rect(x, y + r, r, h.saturating_sub(r * 2), bg);
        self.fill_rect(x + w - r, y + r, r, h.saturating_sub(r * 2), bg);
        self.h_line(x + r, y, w.saturating_sub(r * 2), border);
        self.h_line(x + r, y + h - 1, w.saturating_sub(r * 2), border);
        self.v_line(x, y + r, h.saturating_sub(r * 2), border);
        self.v_line(x + w - 1, y + r, h.saturating_sub(r * 2), border);
    }

    #[allow(
        clippy::many_single_char_names,
        clippy::too_many_arguments,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::suboptimal_flops
    )]
    fn rounded_gradient_panel(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        top_color: u32,
        bottom_color: u32,
        border: u32,
    ) {
        if w < 2 || h < 2 {
            return;
        }
        let tr = (top_color >> 16) & 0xff;
        let tg = (top_color >> 8) & 0xff;
        let tb = top_color & 0xff;
        let br = (bottom_color >> 16) & 0xff;
        let bg = (bottom_color >> 8) & 0xff;
        let bb = bottom_color & 0xff;

        for row in 0..h {
            let py = y + row;
            if py >= self.height {
                break;
            }
            let frac = row as f32 / h.max(1) as f32;
            let cr = (tr as f32 * (1.0 - frac) + br as f32 * frac) as u32;
            let cg = (tg as f32 * (1.0 - frac) + bg as f32 * frac) as u32;
            let cb = (tb as f32 * (1.0 - frac) + bb as f32 * frac) as u32;
            let c = (cr << 16) | (cg << 8) | cb;
            self.h_line(x, py, w, c);
        }
        self.stroke_rect(x, y, w, h, 1, border);
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

// Enterprise Premium V7 native rendering; owner screenshot parity remains subject to QA.
fn premium_panel(
    canvas: &mut Canvas<'_>,
    rect: crate::layout::DashboardRect,
    p: Palette,
    accent: bool,
) {
    canvas.rounded_panel(
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        10,
        0x14_17_24,
        if accent { 0x9e_19_35 } else { p.border },
    );
    if accent {
        canvas.rounded_panel(
            rect.x + 1,
            rect.y + 1,
            rect.width.saturating_sub(2),
            rect.height.saturating_sub(2),
            9,
            0x14_17_24,
            0x5a_14_25,
        );
    }
}

fn draw_home_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 5, y + 1, 4, 2, color);
    canvas.fill_rect(x + 3, y + 3, 8, 2, color);
    canvas.fill_rect(x + 1, y + 5, 12, 2, color);
    canvas.fill_rect(x + 2, y + 7, 10, 6, color);
    canvas.fill_rect(x + 5, y + 9, 4, 4, 0x14_17_24);
}

fn draw_monitor_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, w: usize, h: usize, color: u32) {
    canvas.stroke_rect(x, y, w, h, 1, color);
    let neck_h = 2.min(h);
    let neck_x = x + w / 2;
    canvas.fill_rect(neck_x.saturating_sub(1), y + h, 2, neck_h, color);
    let base_w = (w / 2).max(4);
    canvas.h_line(
        neck_x.saturating_sub(base_w / 2),
        y + h + neck_h,
        base_w,
        color,
    );
}

fn draw_devices_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y, 13, 9, 1, color);
    canvas.h_line(x - 1, y + 9, 15, color);
}

fn draw_dual_monitors_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 3, 9, 7, 1, color);
    canvas.stroke_rect(x + 5, y, 9, 7, 1, color);
}

fn draw_folder_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x, y + 2, 5, 2, color);
    canvas.fill_rect(x, y + 4, 14, 8, color);
    canvas.fill_rect(x + 2, y + 6, 10, 5, 0x14_17_22);
}

fn draw_layers_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 3, y, 10, 7, 1, color);
    canvas.stroke_rect(x, y + 4, 10, 7, 1, color);
}

fn draw_users_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 5, y + 3, 3, color);
    canvas.fill_rect(x + 1, y + 7, 8, 5, color);
    canvas.dot(x + 10, y + 4, 2, color);
    canvas.fill_rect(x + 9, y + 7, 4, 4, color);
}

fn draw_shield_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.h_line(x + 1, y, 10, color);
    canvas.fill_rect(x, y + 1, 1, 6, color);
    canvas.fill_rect(x + 11, y + 1, 1, 6, color);
    canvas.fill_rect(x + 1, y + 7, 2, 2, color);
    canvas.fill_rect(x + 9, y + 7, 2, 2, color);
    canvas.fill_rect(x + 3, y + 9, 2, 2, color);
    canvas.fill_rect(x + 7, y + 9, 2, 2, color);
    canvas.fill_rect(x + 5, y + 11, 2, 2, color);
    canvas.dot(x + 6, y + 5, 2, color);
}

fn draw_id_card_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 1, 14, 10, 1, color);
    canvas.dot(x + 4, y + 5, 2, color);
    canvas.h_line(x + 8, y + 4, 4, color);
    canvas.h_line(x + 8, y + 7, 4, color);
}

fn draw_lock_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 2, y, 8, 6, 1, color);
    canvas.fill_rect(x, y + 5, 12, 8, color);
    canvas.fill_rect(x + 5, y + 7, 2, 3, 0x0009_0d16);
}

fn draw_key_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 1, 6, 6, 1, color);
    canvas.h_line(x + 5, y + 4, 7, color);
    canvas.v_line(x + 9, y + 4, 3, color);
    canvas.v_line(x + 11, y + 4, 2, color);
}

fn draw_chart_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 1, y + 7, 2, 5, color);
    canvas.fill_rect(x + 5, y + 4, 2, 8, color);
    canvas.fill_rect(x + 9, y + 1, 2, 11, color);
}

fn draw_gear_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 6, 4, color);
    canvas.dot(x + 6, y + 6, 2, 0x0d_11_19);
    canvas.fill_rect(x + 5, y, 2, 12, color);
    canvas.fill_rect(x, y + 5, 12, 2, color);
}

fn draw_link_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 2, 6, 6, 1, color);
    canvas.stroke_rect(x + 5, y + 4, 6, 6, 1, color);
    canvas.h_line(x + 4, y + 5, 3, color);
}

fn draw_copy_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 3, y, 8, 9, 1, color);
    canvas.stroke_rect(x, y + 3, 8, 9, 1, color);
}

fn draw_refresh_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 6, 5, color);
    canvas.dot(x + 6, y + 6, 3, 0x0b_12_19);
    canvas.fill_rect(x + 6, y + 1, 4, 2, color);
    canvas.fill_rect(x + 2, y + 9, 4, 2, color);
}

fn draw_eye_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.h_line(x + 2, y + 2, 8, color);
    canvas.h_line(x + 2, y + 8, 8, color);
    canvas.v_line(x + 1, y + 3, 5, color);
    canvas.v_line(x + 10, y + 3, 5, color);
    canvas.dot(x + 6, y + 5, 2, color);
}

fn draw_paste_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 1, y + 2, 10, 11, 1, color);
    canvas.fill_rect(x + 3, y, 6, 3, color);
}

fn draw_bell_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 4, y + 1, 4, 2, color);
    canvas.fill_rect(x + 2, y + 3, 8, 6, color);
    canvas.fill_rect(x, y + 9, 12, 2, color);
    canvas.fill_rect(x + 5, y + 11, 2, 2, color);
}

fn draw_help_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 6, 6, color);
    canvas.dot(x + 6, y + 6, 4, 0x0b_0d_17);
    canvas.fill_rect(x + 5, y + 3, 3, 2, color);
    canvas.fill_rect(x + 6, y + 5, 2, 2, color);
    canvas.dot(x + 6, y + 9, 1, color);
}

fn draw_window_controls(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.h_line(x, y + 10, 8, color);
    canvas.stroke_rect(x + 16, y + 3, 8, 8, 1, color);
    for d in 0..8 {
        canvas.fill_rect(x + 32 + d, y + 3 + d, 1, 1, color);
        canvas.fill_rect(x + 39 - d, y + 3 + d, 1, 1, color);
    }
}

fn draw_waveform_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 1, y + 5, 2, 4, color);
    canvas.fill_rect(x + 4, y + 2, 2, 10, color);
    canvas.fill_rect(x + 7, y, 2, 14, color);
    canvas.fill_rect(x + 10, y + 3, 2, 8, color);
    canvas.fill_rect(x + 13, y + 6, 2, 2, color);
}

fn draw_clipboard_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 1, y + 2, 11, 12, 1, color);
    canvas.fill_rect(x + 3, y, 7, 3, color);
    canvas.h_line(x + 4, y + 6, 5, color);
    canvas.h_line(x + 4, y + 9, 5, color);
}

fn draw_record_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 6, 6, color);
    canvas.dot(x + 6, y + 6, 4, 0x14_17_24);
    canvas.dot(x + 6, y + 6, 2, 0xf7_19_3b);
}

fn draw_infinity_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 3, 6, 6, 1, color);
    canvas.stroke_rect(x + 6, y + 3, 6, 6, 1, color);
}

fn draw_windows_logo(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x, y, 5, 5, color);
    canvas.fill_rect(x + 7, y, 5, 5, color);
    canvas.fill_rect(x, y + 7, 5, 5, color);
    canvas.fill_rect(x + 7, y + 7, 5, 5, color);
}

fn draw_ubuntu_logo(canvas: &mut Canvas<'_>, x: usize, y: usize) {
    canvas.dot(x + 6, y + 6, 6, 0xe9_54_20);
    canvas.dot(x + 6, y + 6, 3, 0x14_17_24);
    canvas.dot(x + 2, y + 4, 2, 0xff_ff_ff);
}

fn draw_crown_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 1, y + 7, 10, 2, color);
    canvas.fill_rect(x, y + 3, 2, 5, color);
    canvas.fill_rect(x + 5, y + 1, 2, 7, color);
    canvas.fill_rect(x + 10, y + 3, 2, 5, color);
}

fn draw_award_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 5, 5, color);
    canvas.dot(x + 6, y + 5, 3, 0x14_17_24);
    canvas.fill_rect(x + 3, y + 10, 2, 4, color);
    canvas.fill_rect(x + 7, y + 10, 2, 4, color);
}

fn draw_heartbeat_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.h_line(x, y + 5, 3, color);
    canvas.v_line(x + 3, y + 2, 6, color);
    canvas.v_line(x + 6, y, 10, color);
    canvas.v_line(x + 8, y + 4, 4, color);
    canvas.h_line(x + 8, y + 5, 4, color);
}

fn draw_lightning_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x + 4, y, 4, 4, color);
    canvas.fill_rect(x + 2, y + 4, 6, 2, color);
    canvas.fill_rect(x, y + 6, 5, 6, color);
}

fn draw_power_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 6, 6, color);
    canvas.dot(x + 6, y + 6, 4, 0x17_1a_27);
    canvas.v_line(x + 6, y + 1, 5, color);
}

fn draw_terminal_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x, y + 1, 14, 11, 1, color);
    canvas.fill_rect(x + 3, y + 4, 2, 1, color);
    canvas.fill_rect(x + 4, y + 5, 2, 1, color);
    canvas.fill_rect(x + 3, y + 6, 2, 1, color);
    canvas.h_line(x + 7, y + 8, 4, color);
}

fn draw_upload_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.h_line(x + 1, y + 10, 12, color);
    canvas.v_line(x + 7, y + 2, 7, color);
    canvas.fill_rect(x + 5, y + 4, 2, 1, color);
    canvas.fill_rect(x + 8, y + 4, 2, 1, color);
}

fn draw_document_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.stroke_rect(x + 1, y + 1, 10, 12, 1, color);
    canvas.h_line(x + 3, y + 4, 6, color);
    canvas.h_line(x + 3, y + 7, 6, color);
    canvas.h_line(x + 3, y + 10, 4, color);
}

fn draw_user_plus_icon(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 4, y + 4, 3, color);
    canvas.fill_rect(x + 1, y + 8, 7, 4, color);
    canvas.v_line(x + 11, y + 4, 5, color);
    canvas.h_line(x + 9, y + 6, 5, color);
}

fn draw_signal_bars(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.fill_rect(x, y + 8, 2, 4, color);
    canvas.fill_rect(x + 3, y + 5, 2, 7, color);
    canvas.fill_rect(x + 6, y + 2, 2, 10, color);
    canvas.fill_rect(x + 9, y, 2, 12, color);
}

fn draw_cloud_check(canvas: &mut Canvas<'_>, x: usize, y: usize, color: u32) {
    canvas.dot(x + 6, y + 5, 4, color);
    canvas.fill_rect(x + 2, y + 6, 10, 3, color);
    canvas.h_line(x + 4, y + 7, 4, 0x14_17_24);
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops
)]
fn premium_orbit(canvas: &mut Canvas<'_>, cx: usize, cy: usize, rx: usize, ry: usize, color: u32) {
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

#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::suboptimal_flops,
    clippy::match_same_arms
)]
fn draw_premium_dashboard(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &crate::PremiumDashboardLayout,
    p: Palette,
) {
    use omnidesk_core::product_shell::NavTab;

    canvas.pixels.fill(p.background);

    // 1. Top Chrome Header
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
    canvas.text(318, 19, "OmniDesk", 2, p.foreground);
    canvas.text(410, 17, "TM", 1, 0x99_a3_b3);
    canvas.rounded_panel(435, 22, 92, 26, 6, 0x85_12_2d, p.accent);
    canvas.text(449, 28, "Enterprise", 1, p.foreground);
    locked_label(
        canvas,
        545,
        30,
        canvas.width.saturating_sub(840),
        "Unified Remote Access & Support Platform",
        0xa0_ab_bc,
    );

    // Top Right Icons: Bell, Help, Settings, Window Controls
    let right_ctrl_x = canvas.width.saturating_sub(180);
    draw_bell_icon(canvas, right_ctrl_x, 26, 0xcb_d2_df);
    canvas.dot(right_ctrl_x + 10, 24, 3, 0xf7_19_3b);
    draw_help_icon(canvas, right_ctrl_x + 28, 25, 0xcb_d2_df);
    draw_gear_icon(canvas, right_ctrl_x + 56, 25, 0xcb_d2_df);
    // Native Windows titlebar already owns minimize/maximize/close.
    // Never paint fake window controls that cannot receive real clicks.

    // 2. Left Navigation Rail
    let nav = layout.navigation;
    canvas.fill_rect(nav.x, nav.y, nav.width, nav.height, p.surface);
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
            NavTab::Connections => i == 3,
            NavTab::FileTransfer => i == 4,
            NavTab::Security => i == 7,
            NavTab::Settings => i == 11,
            _ => i == 0,
        };
        let available = matches!(i, 0 | 1 | 2 | 3 | 4 | 7 | 11);
        if selected {
            canvas.rounded_gradient_panel(
                rect.x + 8,
                rect.y,
                rect.width.saturating_sub(16),
                rect.height,
                0xed_12_36,
                0x94_07_20,
                0xf0_35_52,
            );
        }

        let icon_color = if selected { p.foreground } else { p.muted };
        let icon_x = rect.x + 18;
        let icon_y = rect.y + 11;
        match i {
            0 => draw_home_icon(canvas, icon_x, icon_y, icon_color),
            1 => draw_monitor_icon(canvas, icon_x, icon_y, 13, 9, icon_color),
            2 => draw_devices_icon(canvas, icon_x, icon_y, icon_color),
            3 => draw_layers_icon(canvas, icon_x, icon_y, icon_color),
            4 => draw_folder_icon(canvas, icon_x, icon_y, icon_color),
            5 => draw_dual_monitors_icon(canvas, icon_x, icon_y, icon_color),
            6 => draw_users_icon(canvas, icon_x, icon_y, icon_color),
            7 => draw_shield_icon(canvas, icon_x, icon_y, icon_color),
            8 => draw_id_card_icon(canvas, icon_x, icon_y, icon_color),
            9 => draw_key_icon(canvas, icon_x, icon_y, icon_color),
            10 => draw_chart_icon(canvas, icon_x, icon_y, icon_color),
            _ => draw_gear_icon(canvas, icon_x, icon_y, icon_color),
        }

        locked_label(
            canvas,
            rect.x + 46,
            rect.y + 12,
            rect.width.saturating_sub(80),
            label,
            if selected {
                p.foreground
            } else if available {
                0xd0_d5_e2
            } else {
                0x85_8d_9e
            },
        );

        if i == 6 {
            // "New" badge on Collaboration
            canvas.rounded_panel(
                rect.x + rect.width.saturating_sub(44),
                rect.y + 11,
                28,
                16,
                4,
                0xed_12_36,
                0xf0_40_55,
            );
            canvas.text(
                rect.x + rect.width.saturating_sub(39),
                rect.y + 13,
                "New",
                1,
                p.foreground,
            );
        }
    }
    locked_label(
        canvas,
        nav.x + 20,
        nav.y + nav.height.saturating_sub(25),
        nav.width.saturating_sub(40),
        "PRE-ALPHA | V7",
        0x78_82_94,
    );

    // 3. Hero Banner
    let hero = layout.hero;
    canvas.rounded_panel(
        hero.x,
        hero.y,
        hero.width,
        hero.height,
        12,
        0x0f_13_1e,
        0x3d_14_25,
    );
    canvas.text(hero.x + 22, hero.y + 24, "KMJ", 3, 0xff_20_4e);
    canvas.text(hero.x + 92, hero.y + 24, "OmniDesk", 3, p.foreground);
    canvas.text(hero.x + 236, hero.y + 22, "TM", 1, 0x90_9a_ac);
    locked_label(
        canvas,
        hero.x + 24,
        hero.y + 76,
        hero.width.saturating_sub(44),
        "Secure Remote Access  ·  Support  ·  Manage  ·  Collaborate",
        0xc5_cb_d8,
    );

    // Red orbital globe background + 3D monitor outline
    let globe_x = hero.x + hero.width.saturating_sub(190);
    let globe_y = hero.y + 78;
    premium_orbit(canvas, globe_x, globe_y, 130, 56, 0xa7_1b_46);
    premium_orbit(canvas, globe_x, globe_y, 65, 56, 0x5d_27_48);
    premium_orbit(canvas, globe_x, globe_y, 130, 26, 0xcb_1b_4c);
    premium_orbit(canvas, globe_x, globe_y, 150, 33, p.accent);
    for (dx, dy) in [(-70_i32, -30_i32), (32, -44), (95, -10), (-25, 40)] {
        let px = i32::try_from(globe_x)
            .unwrap_or(i32::MAX)
            .saturating_add(dx);
        let py = i32::try_from(globe_y)
            .unwrap_or(i32::MAX)
            .saturating_add(dy);
        if let (Ok(x), Ok(y)) = (usize::try_from(px), usize::try_from(py)) {
            canvas.dot(x, y, 3, p.accent);
        }
    }
    // Monitor and Laptop wireframes in hero
    let mon_x = hero.x + hero.width.saturating_sub(140);
    let mon_y = hero.y + 30;
    canvas.rounded_panel(mon_x, mon_y, 90, 56, 6, 0x14_17_24, 0xf7_19_3b);
    draw_monitor_icon(canvas, mon_x + 36, mon_y + 18, 18, 13, 0xf7_19_3b);
    let lap_x = mon_x.saturating_sub(55);
    let lap_y = mon_y + 22;
    canvas.rounded_panel(lap_x, lap_y, 65, 42, 4, 0x11_15_20, 0xd0_18_38);
    draw_monitor_icon(canvas, lap_x + 24, lap_y + 12, 14, 10, 0xd0_18_38);

    // 4. Two Primary Cards: "This Device" and "Connect to Remote Device"
    let share = layout.share;
    let connect = layout.connect;
    for rect in [share, connect] {
        premium_panel(canvas, rect, p, true);
    }

    // Card 1: This Device (Share Access)
    canvas.rounded_panel(
        share.x + 20,
        share.y + 20,
        36,
        36,
        8,
        0x42_14_22,
        0x8a_1e_35,
    );
    draw_monitor_icon(canvas, share.x + 29, share.y + 30, 18, 12, 0xff_30_55);
    canvas.text(
        share.x + 66,
        share.y + 20,
        "This Device (Share Access)",
        1,
        p.foreground,
    );
    canvas.text_clipped(
        share.x + 66,
        share.y + 38,
        "Allow others to securely connect to this device.",
        1,
        share.width.saturating_sub(76),
        0x90_9a_ac,
    );

    canvas.text(share.x + 20, share.y + 70, "Your Device ID", 1, 0xd0_d6_e3);
    let id_box_w = share.width.saturating_sub(40);
    canvas.rounded_panel(
        share.x + 20,
        share.y + 88,
        id_box_w,
        42,
        8,
        0x0b_12_19,
        0x28_38_4a,
    );
    let local_id_formatted = if presentation.local_device_id.is_empty() {
        "Not initialized"
    } else {
        &presentation.local_device_id
    };
    canvas.text(
        share.x + 34,
        share.y + 100,
        local_id_formatted,
        2,
        p.foreground,
    );
    let copy = layout.local_id_copy();
    canvas.rounded_panel(copy.x, share.y + 94, 34, 30, 6, 0x16_20_2d, 0x3d_4e_63);
    draw_copy_icon(canvas, copy.x + 10, share.y + 101, 0xcb_d2_df);

    canvas.text(
        share.x + 20,
        share.y + 144,
        "Session Password",
        1,
        0xd0_d6_e3,
    );
    canvas.rounded_panel(
        share.x + 20,
        share.y + 160,
        id_box_w,
        42,
        8,
        0x0b_12_19,
        0x28_38_4a,
    );
    // This release does NOT have a temporary-password lifecycle.
    // Never render a fake masked password or an enabled sharing switch.
    canvas.text_clipped(
        share.x + 32,
        share.y + 174,
        "Password access not configured",
        1,
        id_box_w.saturating_sub(54),
        0x9e_a7_b8,
    );
    canvas.rounded_panel(
        share.x + 20,
        share.y + 218,
        38,
        20,
        10,
        0x41_46_54,
        0x56_5c_6d,
    );
    canvas.dot(share.x + 30, share.y + 228, 7, 0xb1_b8_c5);
    canvas.text(
        share.x + 68,
        share.y + 216,
        "Allow remote control",
        1,
        0xc0_c6_d4,
    );
    canvas.text_clipped(
        share.x + 68,
        share.y + 234,
        "Unavailable until secure host password is implemented",
        1,
        share.width.saturating_sub(78),
        0x8a_95_a6,
    );

    // Card 2: Connect to Remote Device
    canvas.rounded_panel(
        connect.x + 20,
        connect.y + 20,
        36,
        36,
        8,
        0x42_14_22,
        0x8a_1e_35,
    );
    draw_link_icon(canvas, connect.x + 30, connect.y + 31, 0xff_30_55);
    canvas.text(
        connect.x + 66,
        connect.y + 20,
        "Connect to Remote Device",
        1,
        p.foreground,
    );
    canvas.text_clipped(
        connect.x + 66,
        connect.y + 38,
        "Access and control a remote device securely.",
        1,
        connect.width.saturating_sub(76),
        0x90_9a_ac,
    );

    canvas.text(
        connect.x + 20,
        connect.y + 70,
        "Remote Device ID",
        1,
        0xd0_d6_e3,
    );
    let connect_box_w = connect.width.saturating_sub(40);
    let _input = layout.remote_id_input();
    canvas.rounded_panel(
        connect.x + 20,
        connect.y + 88,
        connect_box_w,
        42,
        8,
        0x0b_12_19,
        if presentation.remote_id_focused {
            p.accent
        } else {
            0x28_38_4a
        },
    );
    let input_text = if presentation.remote_id_input.is_empty() {
        "Enter device ID (e.g. 734 281 905)"
    } else {
        &presentation.remote_id_input
    };
    canvas.text_clipped(
        connect.x + 32,
        connect.y + 102,
        input_text,
        1,
        connect_box_w.saturating_sub(60),
        if presentation.remote_id_input.is_empty() {
            0x72_7d_8e
        } else {
            p.foreground
        },
    );
    canvas.h_line(
        connect.x + connect_box_w - 36,
        connect.y + 105,
        5,
        0x90_9a_ac,
    );
    draw_paste_icon(
        canvas,
        connect.x + connect_box_w - 18,
        connect.y + 101,
        0xcb_d2_df,
    );

    canvas.text(connect.x + 20, connect.y + 144, "Password", 1, 0xd0_d6_e3);
    canvas.rounded_panel(
        connect.x + 20,
        connect.y + 160,
        connect_box_w,
        42,
        8,
        0x0b_12_19,
        0x28_38_4a,
    );
    canvas.text_clipped(
        connect.x + 32,
        connect.y + 174,
        "Password authentication not implemented",
        1,
        connect_box_w.saturating_sub(40),
        0x8a_95_a6,
    );
    draw_eye_icon(
        canvas,
        connect.x + connect_box_w - 20,
        connect.y + 175,
        0xcb_d2_df,
    );

    // Password-based Connect Securely remains disabled until an audited
    // password proof and matching host verifier are integrated end-to-end.
    let button = layout.remote_connect_button();
    canvas.rounded_panel(
        button.x,
        button.y,
        button.width,
        button.height,
        8,
        0x5e_20_35,
        0x72_31_4a,
    );
    canvas.text_clipped(
        button.x + 18,
        button.y + 12,
        "CONNECT SECURELY  (UNAVAILABLE)",
        1,
        button.width.saturating_sub(36),
        0xd1_c6_ce,
    );

    // 5. Seven Capability Action Tiles
    let feature = layout.features;
    let tiles = [
        ("Remote Control", "Full device access"),
        ("File Transfer", "Send & receive files"),
        ("Multi-Monitor", "View multiple displays"),
        ("Audio & Voice", "Remote audio & call"),
        ("Clipboard Sync", "Copy & paste securely"),
        ("Session Record", "Record & replay"),
        ("Unattended Access", "Always available"),
    ];
    let tile_width = feature.width / tiles.len();
    for (i, (title, subtitle)) in tiles.iter().enumerate() {
        let rect = crate::layout::DashboardRect {
            x: feature.x + i * tile_width + 2,
            y: feature.y,
            width: tile_width.saturating_sub(4),
            height: feature.height,
        };
        let is_active = i == 0;
        canvas.rounded_panel(
            rect.x,
            rect.y,
            rect.width,
            rect.height,
            8,
            0x14_17_24,
            if is_active { 0xed_18_3b } else { 0x25_29_3b },
        );
        if is_active {
            canvas.fill_rect(
                rect.x + 1,
                rect.y + 1,
                rect.width.saturating_sub(2),
                2,
                0xed_18_3b,
            );
        }
        let icon_x = rect.x + rect.width / 2 - 7;
        let icon_y = rect.y + 12;
        let icon_col = if is_active { 0xff_30_55 } else { 0xa0_ab_bc };
        match i {
            0 => draw_monitor_icon(canvas, icon_x, icon_y, 14, 10, icon_col),
            1 => draw_folder_icon(canvas, icon_x, icon_y, icon_col),
            2 => draw_dual_monitors_icon(canvas, icon_x, icon_y, icon_col),
            3 => draw_waveform_icon(canvas, icon_x, icon_y, icon_col),
            4 => draw_clipboard_icon(canvas, icon_x, icon_y, icon_col),
            5 => draw_record_icon(canvas, icon_x, icon_y, icon_col),
            _ => draw_infinity_icon(canvas, icon_x, icon_y, icon_col),
        }
        canvas.text(
            rect.x + 8,
            rect.y + 44,
            title,
            1,
            if is_active { p.foreground } else { 0xd5_db_e6 },
        );
        canvas.text_clipped(
            rect.x + 8,
            rect.y + 64,
            subtitle,
            1,
            rect.width.saturating_sub(16),
            0x85_8f_a1,
        );
    }

    // 6. Lower Cards: My Devices and Recent Sessions
    let devices = layout.devices;
    let sessions = layout.sessions;
    premium_panel(canvas, devices, p, false);
    premium_panel(canvas, sessions, p, false);

    // Directory is populated only by actual product-shell state; no sample
    // Windows/Linux devices and no fabricated online badges or history.
    draw_monitor_icon(canvas, devices.x + 20, devices.y + 20, 15, 11, 0xff_30_55);
    canvas.text(
        devices.x + 44,
        devices.y + 18,
        "My Devices",
        1,
        p.foreground,
    );
    let visible_devices = presentation
        .controls
        .iter()
        .enumerate()
        .filter(|(_, control)| matches!(control.action, crate::DesktopAction::ConnectDevice(..)))
        .take(3);
    let mut any_device = false;
    for (i, control) in visible_devices {
        any_device = true;
        let rect = layout.device_row(i);
        canvas.h_line(rect.x, rect.y + rect.height, rect.width, 0x22_27_38);
        draw_monitor_icon(canvas, rect.x + 7, rect.y + 11, 14, 10, 0x9a_a8_ba);
        canvas.text_clipped(
            rect.x + 33,
            rect.y + 10,
            &control.label,
            1,
            rect.width.saturating_sub(47),
            if control.enabled { p.foreground } else { 0x96_9e_ae },
        );
    }
    if !any_device {
        canvas.text(
            devices.x + 24,
            devices.y + 92,
            "No registered or verified online devices",
            1,
            p.muted,
        );
    }
    canvas.dot(sessions.x + 26, sessions.y + 26, 5, 0xf7_19_3b);
    canvas.text(sessions.x + 44, sessions.y + 18, "Recent Sessions", 1, p.foreground);
    canvas.text_clipped(
        sessions.x + 24,
        sessions.y + 92,
        "No verified session history available",
        1,
        sessions.width.saturating_sub(48),
        p.muted,
    );

    // 7. Right Column: License, System Status, Quick Actions
    let license = layout.license;
    let health = layout.health;
    let quick = layout.quick_actions;
    for rect in [license, health, quick] {
        premium_panel(canvas, rect, p, false);
    }

    // Entitlement and health are not provided by this renderer. Until
    // authenticated runtime probes exist all badges must remain neutral.
    draw_award_icon(canvas, license.x + 18, license.y + 20, 0xf5_a6_23);
    canvas.text(license.x + 42, license.y + 18, "Enterprise License", 1, p.foreground);
    canvas.rounded_panel(
        license.x + license.width.saturating_sub(89),
        license.y + 18, 75, 20, 5, 0x29_2f_3f, 0x47_50_62,
    );
    canvas.text(
        license.x + license.width.saturating_sub(82),
        license.y + 21, "Unverified", 1, 0xbd_c3_cf,
    );
    canvas.text_clipped(
        license.x + 18, license.y + 51,
        "No signed entitlement status loaded",
        1, license.width.saturating_sub(36), p.muted,
    );
    canvas.text(license.x + 18, license.y + 89, "Seats", 1, 0xd0_d6_e3);
    canvas.text_right(license.x + license.width - 22, license.y + 89, "Unavailable", 1, p.muted);
    canvas.rounded_panel(
        license.x + 18, license.y + 110,
        license.width.saturating_sub(36), 8, 4, 0x1b_22_32, 0x2a_36_4c,
    );
    canvas.text(license.x + 18, license.y + 143, "Valid until", 1, 0xd0_d6_e3);
    canvas.text_right(license.x + license.width - 22, license.y + 143, "--", 1, p.muted);
    canvas.rounded_panel(
        license.x + 18, license.y + 171,
        license.width.saturating_sub(36), 33, 6, 0x18_1c_2b, 0x34_3c_52,
    );
    canvas.text_clipped(
        license.x + 37, license.y + 179, "Manage license (unavailable)", 1,
        license.width.saturating_sub(65), p.muted,
    );

    draw_heartbeat_icon(canvas, health.x + 18, health.y + 20, 0xf7_19_3b);
    canvas.text(health.x + 40, health.y + 18, "System Status", 1, p.foreground);
    let health_rows = [
        ("App shell", "Pre-alpha"),
        ("Relay Network", "Not verified"),
        ("Session Encryption", "No session"),
        ("NAT Traversal", "Not verified"),
    ];
    for (i, (item, state)) in health_rows.iter().enumerate() {
        let y = health.y + 54 + i * 32;
        canvas.dot(health.x + 23, y + 8, 3, 0x8a_92_a2);
        canvas.text_clipped(health.x + 35, y + 2, item, 1, 168, 0xd0_d6_e3);
        canvas.text_right(health.x + health.width - 14, y + 2, state, 1, 0x94_9e_ae);
    }

    // Quick Actions
    draw_lightning_icon(canvas, quick.x + 18, quick.y + 18, 0xf7_19_3b);
    canvas.text(quick.x + 40, quick.y + 16, "Quick Actions", 1, p.foreground);
    let quick_actions = [
        "New Session",
        "Wake on LAN",
        "Remote CMD",
        "Send File",
        "Get Logs",
        "Invite User",
    ];
    let columns = 3;
    let cell_width = (quick.width - 32) / columns;
    for (i, action) in quick_actions.iter().enumerate() {
        let col = i % columns;
        let row = i / columns;
        let x = quick.x + 16 + col * cell_width;
        let y = quick.y + 48 + row * 82;
        let cell_w = cell_width.saturating_sub(8);
        canvas.rounded_panel(x, y, cell_w, 72, 6, 0x18_1c_2b, 0x2e_38_4e);
        let icon_x = x + cell_w / 2 - 7;
        let icon_y = y + 14;
        match i {
            0 => draw_monitor_icon(canvas, icon_x, icon_y, 14, 10, 0xf7_19_3b),
            1 => draw_power_icon(canvas, icon_x, icon_y, 0xf7_19_3b),
            2 => draw_terminal_icon(canvas, icon_x, icon_y, 0x42_99_e1),
            3 => draw_upload_icon(canvas, icon_x, icon_y, 0x48_bb_78),
            4 => draw_document_icon(canvas, icon_x, icon_y, 0xa0_ae_c0),
            _ => draw_user_plus_icon(canvas, icon_x, icon_y, 0x38_b2_ac),
        }
        canvas.text_clipped(
            x + 4,
            y + 46,
            action,
            1,
            cell_w.saturating_sub(8),
            p.foreground,
        );
    }

    // No fabricated relay health, encryption algorithm, latency or service
    // status. These values may become green only after measured verification.
    let footer = layout.footer;
    canvas.fill_rect(footer.x, footer.y, footer.width, footer.height, 0x09_0d_16);
    canvas.h_line(footer.x, footer.y, footer.width, 0x22_27_38);
    canvas.dot(footer.x + 22, footer.y + 22, 4, 0x9a_a2_b2);
    canvas.text(
        footer.x + 36, footer.y + 16,
        "No verified remote session", 1, 0xd0_d6_e3,
    );
    canvas.text(
        footer.x + 285, footer.y + 16,
        "Transport: not established", 1, 0x9d_a7_b7,
    );
    canvas.text(
        footer.x + 528, footer.y + 16,
        "Security: unverified", 1, 0x9d_a7_b7,
    );
    canvas.text_right(
        footer.x + footer.width.saturating_sub(18),
        footer.y + 16, "KMJ OmniDesk  /  PRE-ALPHA", 1, 0x9d_a7_b7,
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
