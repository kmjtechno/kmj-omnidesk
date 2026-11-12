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
    if scale >= 3 {
        34.0
    } else if scale == 2 {
        22.0
    } else {
        16.0
    }
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

    /// A compact rounded panel primitive for the owner-locked V5 card
    /// language. Rectangular borders were the main source of the old,
    /// box-heavy appearance in the native screenshot.
    fn rounded_fill(
        &mut self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
        radius: usize,
        color: u32,
    ) {
        if width == 0 || height == 0 {
            return;
        }
        let radius = radius.min(width / 2).min(height / 2);
        if radius == 0 {
            self.fill_rect(x, y, width, height, color);
            return;
        }
        self.fill_rect(x, y + radius, width, height - radius * 2, color);
        for row in 0..radius {
            // Three-step antialias-free corner: soft enough at 1x/125% DPI
            // without any downloaded textures, dependencies or GPU effects.
            let inset = if row < radius / 4 {
                radius / 2
            } else if row < radius / 2 {
                radius / 4
            } else {
                1
            };
            self.fill_rect(
                x + inset, y + row, width.saturating_sub(inset * 2), 1, color,
            );
            self.fill_rect(
                x + inset, y + height - row - 1,
                width.saturating_sub(inset * 2), 1, color,
            );
        }
    }

    fn rounded_panel(
        &mut self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
        radius: usize,
        background: u32,
        border: u32,
    ) {
        self.rounded_fill(x, y, width, height, radius, border);
        if width >= 3 && height >= 3 {
            self.rounded_fill(
                x + 1, y + 1, width - 2, height - 2,
                radius.saturating_sub(1), background,
            );
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
    canvas.fill_rect(0, 0, canvas.width, layout.top_bar_height, p.background);
    canvas.h_line(0, layout.top_bar_height - 1, canvas.width, p.border);
    if let Some(mark) = official_kmj_mark() {
        canvas.image_rgba(
            (26, 17, 40, 40),
            (
                usize::try_from(mark.width).unwrap_or(0),
                usize::try_from(mark.height).unwrap_or(0),
            ),
            &mark.rgba,
        );
    }
    canvas.text(73, 20, "KMJ TECHNO", 1, p.foreground);
    canvas.text(73, 42, "INNOVATE  |  BUILD  |  SCALE", 1, p.muted);

    // Hide the decorative command strip on compact windows: it is not
    // searchable yet and must never overlap the KMJ TECHNO wordmark.
    if canvas.width >= 1024 {
        let search_x = layout.remote_screen.x + 155;
        let search_w = (canvas.width * 23 / 100).clamp(270, 365);
        canvas.rounded_panel(
            search_x, 18, search_w, 37, 9, p.background, p.border,
        );
        locked_label(
            canvas,
            search_x + 14,
            29,
            search_w.saturating_sub(28),
            "OMNIDESK  /  REMOTE WORKSPACE",
            p.muted,
        );
    }

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
    // Minimal native glyphs for the owner-locked six navigation destinations.
    // Their visual location and labels are shared by pointer and AccessKit.
    match index {
        0 => {
            // Remote access: desktop monitor.
            canvas.stroke_rect(x, y, 16, 11, 1, color);
            canvas.fill_rect(x + 7, y + 11, 2, 3, color);
            canvas.h_line(x + 4, y + 14, 8, color);
        }
        1 => {
            // Trusted devices: two overlapping verified computers.
            canvas.stroke_rect(x, y + 4, 11, 8, 1, color);
            canvas.stroke_rect(x + 6, y, 11, 8, 1, color);
        }
        2 => {
            // Sessions: clock face and hands.
            canvas.dot(x + 8, y + 8, 7, color);
            canvas.dot(x + 8, y + 8, 5, 0x0e_11_14);
            canvas.fill_rect(x + 8, y + 4, 1, 5, color);
            canvas.h_line(x + 8, y + 8, 4, color);
        }
        3 => {
            // File transfer: document with a transfer arrow.
            canvas.stroke_rect(x + 3, y, 10, 15, 1, color);
            canvas.h_line(x + 5, y + 5, 6, color);
            canvas.h_line(x + 5, y + 8, 4, color);
            canvas.fill_rect(x + 12, y + 11, 5, 1, color);
        }
        4 => {
            // Security: shield with an identity mark.
            canvas.stroke_rect(x + 3, y, 11, 13, 1, color);
            canvas.dot(x + 8, y + 6, 2, color);
            canvas.fill_rect(x + 7, y + 10, 3, 2, color);
        }
        _ => {
            // Preferences: settings dial.
            canvas.dot(x + 8, y + 8, 7, color);
            canvas.dot(x + 8, y + 8, 4, 0x0e_11_14);
            canvas.dot(x + 8, y + 8, 2, color);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn draw_locked_navigation(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let nav = layout.navigation;
    let nav_labels = [
        "Remote access",
        "Trusted devices",
        "Sessions",
        "File transfer",
        "Security center",
        "Preferences",
    ];
    let nav_tabs = [
        omnidesk_core::product_shell::NavTab::Devices,
        omnidesk_core::product_shell::NavTab::TrustedDevices,
        omnidesk_core::product_shell::NavTab::Connections,
        omnidesk_core::product_shell::NavTab::FileTransfer,
        omnidesk_core::product_shell::NavTab::Security,
        omnidesk_core::product_shell::NavTab::Settings,
    ];
    locked_label(
        canvas,
        nav.x + 14,
        nav.y + 26,
        nav.width.saturating_sub(28),
        "WORKSPACE",
        p.muted,
    );
    // The owner's locked V5 reference has a distinct Protection section.
    let compact_rail = nav.width < 120;
    canvas.h_line(
        nav.x + 14,
        nav.y + 255,
        nav.width.saturating_sub(28),
        p.border,
    );
    if !compact_rail {
        locked_label(
            canvas,
            nav.x + 14,
            nav.y + 273,
            nav.width.saturating_sub(28),
            "PROTECTION",
            p.muted,
        );
    }
    for (index, label) in nav_labels.iter().enumerate() {
        let rect = layout.nav_tab_rect(index);
        let active = nav_tabs[index] == presentation.nav_tab;
        if active {
            canvas.rounded_fill(rect.x, rect.y, rect.width, rect.height, 9, p.accent);
        }
        let item_color = if active { p.foreground } else { p.muted };
        let compact_rail = nav.width < 120;
        let icon_x = if compact_rail {
            rect.x + rect.width.saturating_sub(16) / 2
        } else {
            rect.x + 15
        };
        draw_locked_nav_icon(canvas, index, icon_x, rect.y + 10, item_color);
        if !compact_rail {
            locked_label(
                canvas,
                rect.x + 44,
                rect.y + 14,
                rect.width.saturating_sub(50),
                label,
                item_color,
            );
        }
    }
    let nav_bottom = nav.y + nav.height;
    canvas.rounded_panel(
        nav.x + 9,
        nav_bottom - 69,
        nav.width.saturating_sub(18),
        56,
        9,
        p.background,
        p.border,
    );
    if nav.width < 120 {
        canvas.dot(nav.x + nav.width / 2, nav_bottom - 40, 5, p.muted);
        locked_label(
            canvas,
            nav.x + 12,
            nav_bottom - 24,
            nav.width.saturating_sub(24),
            "LOCAL",
            p.muted,
        );
    } else {
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
        (
            "ALL",
            filter == omnidesk_core::product_shell::DeviceFilter::All,
        ),
        (
            "ONLINE",
            filter == omnidesk_core::product_shell::DeviceFilter::Online,
        ),
        (
            "OFFLINE",
            filter == omnidesk_core::product_shell::DeviceFilter::Offline,
        ),
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
            omnidesk_core::product_shell::NavTab::TrustedDevices => {
                "Manage only enrolled trusted peers"
            }
            omnidesk_core::product_shell::NavTab::Connections => "Sessions require a verified peer",
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
    let card = layout.your_id_card_rect();
    canvas.rounded_panel(card.x, card.y, card.width, card.height, 14, p.surface, p.border);
    // Approved V5 has icon + title hierarchy, not three overlapping labels.
    canvas.rounded_panel(card.x + 24, card.y + 24, 40, 40, 10, p.background, p.border);
    canvas.stroke_rect(card.x + 36, card.y + 36, 17, 14, 1, p.muted);
    locked_label(canvas, card.x + 76, card.y + 26, card.width.saturating_sub(100),
        "02  /  SHARE THIS DESK", p.muted);
    locked_label(canvas, card.x + 76, card.y + 48, card.width.saturating_sub(100),
        "Your ID & password", p.foreground);

    locked_label(canvas, card.x + 24, card.y + 94, card.width.saturating_sub(48),
        "Your OmniDesk ID", p.foreground);
    let id_row_x = card.x + 24;
    let id_row_y = card.y + 111;
    let id_row_width = card.width.saturating_sub(48);
    canvas.rounded_panel(
        id_row_x, id_row_y, id_row_width, 50, 9, p.background, p.border,
    );
    let id_text = if presentation.local_device_id.is_empty() {
        "Not assigned"
    } else {
        &presentation.local_device_id
    };
    canvas.text_clipped(
        id_row_x + 13, id_row_y + 17, id_text, 1,
        id_row_width.saturating_sub(132), p.foreground,
    );
    let copy_id = layout.your_id_copy_btn_rect();
    canvas.rounded_panel(
        copy_id.x, copy_id.y, copy_id.width, copy_id.height, 7, p.border, p.muted,
    );
    locked_label(canvas, copy_id.x + 15, copy_id.y + 11,
        copy_id.width.saturating_sub(28), "Copy ID", p.foreground);

    let caption = layout.your_password_status_rect();
    locked_label(canvas, caption.x, caption.y, caption.width, "Your password", p.foreground);
    let field = layout.your_password_field_rect();
    canvas.rounded_panel(
        field.x, field.y, field.width, field.height, 9, p.background, p.border,
    );
    canvas.text_clipped(
        field.x + 12, field.y + 13,
        &presentation.local_password_display,
        1, field.width.saturating_sub(65),
        if presentation.local_password_display == "NOT CONFIGURED" {
            p.muted
        } else {
            p.foreground
        },
    );
    let has_password = presentation.local_password_display != "NOT CONFIGURED";
    let show = layout.your_password_reveal_btn_rect();
    canvas.rounded_panel(
        show.x, show.y, show.width, show.height, 6,
        p.background, p.border,
    );
    locked_label(canvas, show.x + 3, show.y + 10,
        show.width.saturating_sub(6),
        if presentation.local_password_revealed { "HIDE" } else { "SHOW" },
        if has_password { p.foreground } else { p.muted });
    let copy = layout.your_password_copy_btn_rect();
    canvas.rounded_panel(copy.x, copy.y, copy.width, copy.height,
        8, p.border, p.muted);
    locked_label(canvas, copy.x + 24, copy.y + 15,
        copy.width.saturating_sub(40), "Copy",
        if has_password { p.foreground } else { p.muted });

    canvas.dot(card.x + 30, card.y + 301, 4, p.muted);
    locked_label(canvas, card.x + 41, card.y + 294,
        card.width.saturating_sub(220),
        "Unattended access: OFF", p.muted);
    let rotate = layout.your_password_rotate_btn_rect();
    canvas.rounded_panel(rotate.x, rotate.y, rotate.width, rotate.height,
        7, p.background, p.border);
    locked_label(canvas, rotate.x + 11, rotate.y + 9,
        rotate.width.saturating_sub(18), "New password", p.foreground);
    locked_label(canvas, card.x + 24, card.y + 330,
        card.width.saturating_sub(48),
        "Credentials are local; verified encrypted access is required.", p.muted);
}

fn draw_locked_remote_id_input(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    input_rect: crate::layout::DashboardRect,
    p: Palette,
) {
    let input_border_color = if presentation.remote_id_focused {
        p.accent
    } else {
        p.border
    };
    canvas.rounded_panel(
        input_rect.x, input_rect.y, input_rect.width, input_rect.height,
        9, p.background, input_border_color,
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
    let card = layout.remote_id_card_rect();
    canvas.rounded_panel(card.x, card.y, card.width, card.height, 14, p.surface, p.border);
    canvas.rounded_panel(card.x + 24, card.y + 24, 40, 40, 10, p.background, p.accent);
    canvas.stroke_rect(card.x + 35, card.y + 36, 18, 13, 1, p.accent);
    locked_label(canvas, card.x + 76, card.y + 26,
        card.width.saturating_sub(100), "01  /  TAKE CONTROL", p.accent);
    locked_label(canvas, card.x + 76, card.y + 48,
        card.width.saturating_sub(100), "Connect to another desktop", p.foreground);

    locked_label(canvas, card.x + 24, card.y + 94,
        card.width.saturating_sub(48), "Remote device ID", p.foreground);
    draw_locked_remote_id_input(canvas, presentation, layout.remote_id_input_rect(), p);

    locked_label(canvas, card.x + 24, card.y + 174,
        card.width.saturating_sub(48), "Session password", p.foreground);
    let field = layout.remote_password_status_rect();
    canvas.rounded_panel(
        field.x, field.y, field.width, field.height, 9,
        p.background,
        if presentation.remote_password_focused { p.accent } else { p.border },
    );
    let placeholder = presentation.remote_password_display.is_empty();
    let value = if placeholder {
        "Enter remote password"
    } else {
        &presentation.remote_password_display
    };
    canvas.text_clipped(
        field.x + 13, field.y + 14, value, 1,
        field.width.saturating_sub(76),
        if placeholder { p.muted } else { p.foreground },
    );
    let show = layout.remote_password_reveal_btn_rect();
    canvas.rounded_panel(
        show.x, show.y, show.width, show.height, 6,
        p.background, p.border,
    );
    locked_label(canvas, show.x + 7, show.y + 10,
        show.width.saturating_sub(12),
        if presentation.remote_password_revealed { "HIDE" } else { "SHOW" },
        if placeholder { p.muted } else { p.foreground });

    let connect = layout.remote_id_connect_btn_rect();
    let ready = presentation.remote_access_form_ready;
    canvas.rounded_panel(
        connect.x, connect.y, connect.width, connect.height, 9,
        if ready { p.accent } else { p.border },
        if ready { p.accent } else { p.border },
    );
    locked_label(
        canvas, connect.x + 17, connect.y + 14,
        connect.width.saturating_sub(25), "Connect securely",
        if ready { p.foreground } else { p.muted },
    );
    locked_label(
        canvas, connect.x + connect.width + 12, connect.y + 8,
        card.width.saturating_sub(connect.width + 64),
        "Requires a verified peer and an allowed session.", p.muted,
    );
    canvas.dot(card.x + 30, card.y + 335, 4, p.accent);
    locked_label(canvas, card.x + 42, card.y + 329,
        card.width.saturating_sub(65),
        "ID locates the device; password and permission must be verified.",
        p.muted);
}

fn draw_locked_dual_role_cards(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    draw_locked_remote_id_card(canvas, presentation, layout, p);
    draw_locked_your_id_card(canvas, presentation, layout, p);

    let stage = layout.remote_stage_rect();
    // A labelled stage below the cards, not a 200px inset trapped inside
    // a compressed outer card. Its title and subtitle are visible on the
    // approved 1024x768 fold, while the document scrolls below it.
    locked_label(canvas, stage.x, stage.y.saturating_sub(54),
        stage.width, "Remote display", p.foreground);
    locked_label(canvas, stage.x, stage.y.saturating_sub(30),
        stage.width,
        "Your full-control workspace comes alive after a verified connection.",
        p.muted);
    canvas.rounded_panel(
        stage.x, stage.y, stage.width, stage.height,
        14, p.background, p.border,
    );
    canvas.fill_rect(
        stage.x + 1, stage.y + 1, stage.width.saturating_sub(2), 45,
        p.surface,
    );
    for (index, color) in [p.accent, p.muted, p.border].iter().enumerate() {
        canvas.dot(stage.x + 20 + index * 11, stage.y + 23, 3, *color);
    }
    locked_label(canvas, stage.x + 57, stage.y + 16,
        stage.width.saturating_sub(76),
        "Remote screen  /  No session", p.foreground);
    canvas.h_line(stage.x + 1, stage.y + 46,
        stage.width.saturating_sub(2), p.border);

    // This is a genuine disconnected state, not a fictional remote image,
    // frame rate, codec, encryption metric or authorized input stream.
    let center_x = stage.x + stage.width / 2;
    let center_y = stage.y + 126;
    canvas.rounded_panel(
        center_x.saturating_sub(27), center_y.saturating_sub(20),
        54, 54, 14, p.surface, p.border,
    );
    canvas.stroke_rect(
        center_x.saturating_sub(12), center_y.saturating_sub(4),
        24, 19, 2, p.accent,
    );
    canvas.fill_rect(center_x.saturating_sub(1), center_y + 15, 2, 6, p.accent);
    canvas.h_line(center_x.saturating_sub(7), center_y + 21, 14, p.accent);
    let main_label = "Your remote screen starts here";
    let label_width = Canvas::text_width(main_label, 2);
    canvas.text_clipped(
        center_x.saturating_sub(label_width / 2),
        stage.y + 184, main_label, 2,
        stage.width.saturating_sub(36), p.foreground,
    );
    let detail = "Enter a device ID and password above. A real desktop appears only after secure verification.";
    let detail_width = Canvas::text_width(detail, 1);
    canvas.text_clipped(
        center_x.saturating_sub(detail_width / 2),
        stage.y + 218, detail, 1,
        stage.width.saturating_sub(36), p.muted,
    );
    locked_label(
        canvas, center_x.saturating_sub(110), stage.y + 263,
        220, "No authenticated connection", p.muted,
    );
}

/// Actual enrolled device directory, never fictional demo peers.
///
/// The control list is derived from the current `ProductShell` device catalog,
/// with enabled = online, and its rectangles are shared with pointer/a11y
/// activation. No "connected" badge is shown before verification.
fn draw_locked_trusted_devices_page(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let frame = layout.remote_screen;
    canvas.fill_rect(frame.x, frame.y, frame.width, frame.height, p.background);
    canvas.stroke_rect(frame.x, frame.y, frame.width, frame.height, 1, p.border);
    canvas.fill_rect(
        frame.x + 1,
        frame.y + 1,
        frame.width.saturating_sub(2),
        38,
        p.surface,
    );
    canvas.fill_rect(frame.x + 1, frame.y + 1, 3, 38, p.accent);
    locked_label(
        canvas,
        frame.x + 18,
        frame.y + 14,
        frame.width.saturating_sub(36),
        "TRUSTED DEVICES",
        p.accent,
    );
    canvas.text_clipped(
        frame.x + 18,
        frame.y + 56,
        "Your computers",
        2,
        frame.width.saturating_sub(36),
        p.foreground,
    );
    locked_label(
        canvas,
        frame.x + 18,
        frame.y + 102,
        frame.width.saturating_sub(36),
        "Only enrolled device identities appear here. Access still requires authorization.",
        p.muted,
    );

    let mut shown = 0;
    for (index, control) in presentation.controls.iter().enumerate().take(9) {
        if !matches!(control.action, crate::DesktopAction::ConnectDevice(_, _)) {
            continue;
        }
        let tile = layout.trusted_device_tile_rect(index);
        canvas.fill_rect(tile.x, tile.y, tile.width, tile.height, p.surface);
        canvas.stroke_rect(tile.x, tile.y, tile.width, tile.height, 1, p.border);
        canvas.dot(
            tile.x + 13,
            tile.y + 20,
            4,
            if control.enabled {
                VERIFIED_GREEN
            } else {
                p.muted
            },
        );
        locked_label(
            canvas,
            tile.x + 24,
            tile.y + 15,
            tile.width.saturating_sub(32),
            &control.label,
            p.foreground,
        );
        shown += 1;
    }
    if shown == 0 {
        locked_label(
            canvas,
            frame.x + 22,
            frame.y + 170,
            frame.width.saturating_sub(44),
            "No trusted devices enrolled. Connect to a verified device first.",
            p.muted,
        );
    }
}

/// V5 sidebar pages must not all render the same Remote Access form.
///
/// The source of truth for these states remains `ProductShell`. These are
/// dedicated, clearly labelled feature views, not fake device data or
/// actionable features that require a verified remote connection.
#[allow(clippy::too_many_lines)]
fn draw_locked_feature_page(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    use omnidesk_core::product_shell::NavTab;

    // These counts and names originate from ProductShell's local records,
    // not a hardcoded "empty" dashboard. None imply verified delivery.
    let transfer_count = format!("{} local transfer record(s)", presentation.transfer_record_count);
    let latest_transfer_name = presentation
        .latest_transfer_filename
        .as_deref()
        .unwrap_or("No transfer recorded");
    let latest_transfer_status = presentation
        .latest_transfer_status
        .as_deref()
        .unwrap_or("No transfer status");
    let local_audit_count = format!("{} local security event(s)", presentation.local_audit_event_count);

    let (category, heading, explanation, cards) = match presentation.nav_tab {
        NavTab::Connections => (
            "SESSION MANAGEMENT",
            "Sessions & history",
            "Every remote session must have verified identity and explicit access.",
            [
                ("ACTIVE SESSION", "None verified"),
                ("CONNECTION HISTORY", "No verified sessions to show"),
                (
                    "ACCESS PERMISSIONS",
                    "Granted only after secure verification",
                ),
            ],
        ),
        NavTab::FileTransfer => (
            "LOCAL TRANSFER RECORDS",
            "File transfer",
            "Recorded local queue status; network delivery is not verified.",
            [
                ("TRANSFER RECORDS", transfer_count.as_str()),
                ("LATEST FILE", latest_transfer_name),
                ("LOCAL STATUS", latest_transfer_status),
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
            "Peer verification, local audit records and access permissions.",
            [
                ("PEER IDENTITY", "Authenticated transport required"),
                ("LOCAL AUDIT LOG", local_audit_count.as_str()),
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
        NavTab::TrustedDevices | NavTab::Devices => return,
    };
    let frame = layout.remote_screen;
    canvas.fill_rect(frame.x, frame.y, frame.width, frame.height, p.background);
    canvas.stroke_rect(frame.x, frame.y, frame.width, frame.height, 1, p.border);
    canvas.fill_rect(
        frame.x + 1,
        frame.y + 1,
        frame.width.saturating_sub(2),
        38,
        p.surface,
    );
    canvas.fill_rect(frame.x + 1, frame.y + 1, 3, 38, p.accent);
    locked_label(
        canvas,
        frame.x + 18,
        frame.y + 14,
        frame.width.saturating_sub(36),
        category,
        p.accent,
    );
    canvas.text_clipped(
        frame.x + 18,
        frame.y + 60,
        heading,
        2,
        frame.width.saturating_sub(36),
        p.foreground,
    );
    locked_label(
        canvas,
        frame.x + 18,
        frame.y + 105,
        frame.width.saturating_sub(36),
        explanation,
        p.muted,
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
            canvas,
            x + 23,
            y + 15,
            width.saturating_sub(32),
            title,
            p.foreground,
        );
        locked_label(
            canvas,
            x + 12,
            y + 48,
            width.saturating_sub(24),
            message,
            p.muted,
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
            canvas,
            frame.x + gutter,
            frame.y + 145 + tile_height + 46,
            frame.width.saturating_sub(gutter * 2),
            "No remote operation is available until identity, transport and permissions are verified.",
            p.muted,
        );
    }
}

#[allow(clippy::too_many_lines)]
fn draw_locked_remote_view(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let viewer = layout.viewer;
    let screen = layout.remote_screen;
    locked_label(
        canvas,
        screen.x,
        viewer.y + 28,
        screen.width,
        "KMJ TECHNO   >   OMNIDESK   >   ACCESS DESK",
        p.muted,
    );
    use omnidesk_core::product_shell::NavTab;
    if presentation.nav_tab == NavTab::Devices {
        let prefix = "Remote control,";
        let prefix_width = Canvas::text_width(prefix, 3);
        canvas.text_clipped(
            screen.x, viewer.y + 58, prefix, 3, screen.width, p.foreground,
        );
        canvas.text_clipped(
            screen.x + prefix_width + 8, viewer.y + 58,
            "reimagined.", 3,
            screen.width.saturating_sub(prefix_width + 8), p.accent,
        );
        locked_label(
            canvas, screen.x, viewer.y + 109, screen.width,
            "One beautifully focused workspace to connect, collaborate and manage your computers securely.",
            p.muted,
        );
    } else {
        let title = match presentation.nav_tab {
            NavTab::TrustedDevices => "Trusted devices",
            NavTab::Connections => "Sessions & history",
            NavTab::FileTransfer => "File transfer",
            NavTab::RemoteActions => "Remote actions",
            NavTab::Automation => "Automation",
            NavTab::Security => "Security center",
            NavTab::Settings => "Preferences",
            NavTab::Devices => unreachable!(),
        };
        canvas.text_clipped(
            screen.x, viewer.y + 58, title, 3, screen.width, p.foreground,
        );
        locked_label(
            canvas, screen.x, viewer.y + 109, screen.width,
            "Your secure workspace. Operations require verified access and scoped permissions.",
            p.muted,
        );
    }
    // The approved first fold has no frame around the whole middle area:
    // only the two workflow cards and Remote Display are bordered.
    if presentation.nav_tab != omnidesk_core::product_shell::NavTab::Devices
        || presentation.help_open
        || presentation.primary_view != omnidesk_core::product_shell::PrimaryView::Devices
    {
        canvas.rounded_panel(
            screen.x, screen.y, screen.width, screen.height,
            12, p.background, p.border,
        );
    }

    if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices
        && !presentation.help_open
        && presentation.nav_tab == omnidesk_core::product_shell::NavTab::TrustedDevices
    {
        draw_locked_trusted_devices_page(canvas, presentation, layout, p);
    } else if presentation.primary_view == omnidesk_core::product_shell::PrimaryView::Devices
        && !presentation.help_open
        && presentation.nav_tab != omnidesk_core::product_shell::NavTab::Devices
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
    canvas.fill_rect(
        screen.x,
        screen.y,
        screen.width,
        screen.height,
        p.background,
    );
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
        if presentation.remote_input_enabled {
            "INPUT ON"
        } else {
            "INPUT OFF"
        },
        "MONITORS",
        if presentation.clipboard_sync_enabled {
            "CLIP ON"
        } else {
            "CLIP OFF"
        },
        "FILES",
        if presentation.fullscreen_enabled {
            "EXIT FULL"
        } else {
            "FULLSCREEN"
        },
        "DISCONNECT",
    ];
    for (index, label) in labels.iter().enumerate() {
        let rect = layout.session_tool_btn_rect(index);
        canvas.fill_rect(
            rect.x,
            rect.y,
            rect.width,
            rect.height,
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

/// Only show fields actually established by the live transport. Do not
/// substitute hard-coded FPS, bitrate or cipher labels in the disconnected UI.
fn draw_locked_details(
    canvas: &mut Canvas<'_>,
    p: Palette,
    info_x: usize,
    info_w: usize,
    details_y: usize,
) {
    for (index, text) in [
        "Remote computer    --",
        "Transport          Unavailable",
        "Round-trip delay   --",
        "Encryption         Not established",
    ]
    .iter()
    .enumerate()
    {
        locked_label(
            canvas,
            info_x,
            details_y + index * 23,
            info_w,
            text,
            p.muted,
        );
    }
}

/// These session actions are intentionally disabled until a real encrypted
/// peer transport, target consent and active session are independently proven.
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
        "SESSION TOOLS  /  LOCKED",
        p.foreground,
    );
    for (index, text) in ["Remote Input", "File Transfer", "Monitors", "Clipboard"]
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

#[allow(clippy::too_many_lines)]
fn draw_locked_inspector(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    let inspector = layout.inspector;
    // Match the locked V5 right rail: connection status, session tools,
    // then verification checklist. All three fit compact 611px windows.
    let first = inspector.height * 44 / 100;
    let second = inspector.height * 25 / 100;
    let status_y = inspector.y + 5;
    let actions_y = status_y + first + 6;
    let verification_y = actions_y + second + 6;
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
        actions_y,
        inspector.width - 12,
        second,
        p,
    );
    locked_frame(
        canvas,
        inspector.x + 6,
        verification_y,
        inspector.width - 12,
        inspector.y + inspector.height - verification_y - 5,
        p,
    );
    let info_x = inspector.x + 20;
    let info_w = inspector.width.saturating_sub(40);
    locked_label(
        canvas,
        info_x,
        status_y + 18,
        info_w,
        "SESSION INSPECTOR",
        p.foreground,
    );
    locked_label(
        canvas,
        info_x,
        status_y + 37,
        info_w,
        "Connection status",
        p.muted,
    );
    canvas.dot(info_x + 7, status_y + 67, 6, p.muted);
    locked_label(
        canvas,
        info_x + 22,
        status_y + 62,
        info_w.saturating_sub(22),
        match presentation.primary_view {
            omnidesk_core::product_shell::PrimaryView::Devices => "Not connected",
            omnidesk_core::product_shell::PrimaryView::PermissionPrompt => "Permission pending",
            omnidesk_core::product_shell::PrimaryView::Session => "Transport unverified",
        },
        p.foreground,
    );
    locked_label(
        canvas,
        info_x,
        status_y + 94,
        info_w,
        "Waiting for verified remote access",
        p.muted,
    );
    canvas.h_line(info_x, status_y + 119, info_w, p.border);
    draw_locked_details(canvas, p, info_x, info_w, status_y + 139);
    draw_locked_action_buttons(canvas, p, info_x, info_w, actions_y);

    locked_label(
        canvas,
        info_x,
        verification_y + 16,
        info_w,
        "VERIFICATION CHECKLIST",
        p.foreground,
    );
    for (index, (title, status)) in [
        ("Peer identity", "Awaiting cryptographic proof"),
        ("Session authorization", "Target permission required"),
        ("Screen availability", "No desktop stream received"),
    ]
    .iter()
    .enumerate()
    {
        let y = verification_y + 41 + index * 36;
        canvas.dot(info_x + 6, y + 5, 4, p.muted);
        locked_label(
            canvas,
            info_x + 18,
            y,
            info_w.saturating_sub(18),
            title,
            p.foreground,
        );
        locked_label(
            canvas,
            info_x + 18,
            y + 14,
            info_w.saturating_sub(18),
            status,
            p.muted,
        );
    }
}

/// Preserve the approved V5 fold at every height. Only the center
/// workspace scrolls; the KMJ header, left rail and session inspector stay
/// fixed. Rendering is event-driven so the temporary ~5 MB RGB buffer is
/// allocated only on a frame request, not by a continuous animation loop.
fn draw_locked_dashboard(
    canvas: &mut Canvas<'_>,
    presentation: &PresentationModel,
    layout: &LockedDashboardLayout,
    p: Palette,
) {
    draw_locked_header(canvas, presentation, layout, p);
    locked_frame(
        canvas,
        layout.navigation.x, layout.navigation.y,
        layout.navigation.width, layout.navigation.height, p,
    );
    draw_locked_navigation(canvas, presentation, layout, p);

    if layout.inspector.width > 0 {
        draw_locked_inspector(canvas, presentation, layout, p);
    }

    let virtual_height = LockedDashboardLayout::CONTENT_HEIGHT.max(canvas.height);
    let Some(virtual_layout) = LockedDashboardLayout::for_window(canvas.width, virtual_height)
    else {
        return;
    };
    let mut content_pixels = vec![p.background; canvas.width.saturating_mul(virtual_height)];
    let mut content_canvas = Canvas {
        pixels: &mut content_pixels,
        width: canvas.width,
        height: virtual_height,
    };
    draw_locked_remote_view(&mut content_canvas, presentation, &virtual_layout, p);
    draw_locked_session_tiles(&mut content_canvas, presentation, &virtual_layout, p);
    draw_locked_devices(&mut content_canvas, presentation, &virtual_layout, p);

    let left = layout.viewer.x;
    let right = left.saturating_add(layout.viewer.width).min(canvas.width);
    let top = layout.viewer.y;
    let bottom = top.saturating_add(layout.viewer.height).min(canvas.height);
    let scroll = presentation
        .workspace_scroll_y
        .min(LockedDashboardLayout::max_scroll_y(canvas.height));
    if right > left {
        for visible_y in top..bottom {
            let document_y = visible_y.saturating_add(scroll);
            if document_y >= virtual_height {
                break;
            }
            let start = visible_y * canvas.width + left;
            let source = document_y * canvas.width + left;
            canvas.pixels[start..start + (right - left)]
                .copy_from_slice(&content_pixels[source..source + (right - left)]);
        }
    }
    // Subtle viewport scroll cue; not a fake session metric.
    if LockedDashboardLayout::max_scroll_y(canvas.height) > 0 && right > left + 10 {
        let track_height = bottom.saturating_sub(top);
        let handle_height = (track_height * track_height / virtual_height).max(28);
        let max_scroll = LockedDashboardLayout::max_scroll_y(canvas.height);
        let handle_top = top + (track_height.saturating_sub(handle_height)) * scroll / max_scroll;
        canvas.fill_rect(right - 5, top, 2, track_height, p.border);
        canvas.fill_rect(right - 6, handle_top, 4, handle_height, p.muted);
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
        // V5 input fields have rounded corners; sample the top-center
        // hairline rather than the transparent top-left corner pixel.
        assert_eq!(pixels[remote.y * width + remote.x + remote.width / 2], border);
        let own_card = layout.your_id_card_rect();
        let connect_card = layout.remote_id_card_rect();
        if layout.access_cards_wide() {
            assert_eq!(own_card.y, connect_card.y);
            assert!(own_card.x >= connect_card.x + connect_card.width);
        } else {
            assert!(own_card.y + own_card.height <= connect_card.y);
        }
        assert!(own.y >= own_card.y);
        assert!(own.y + own.height <= own_card.y + own_card.height);
        assert!(
            remote.y + remote.height
                <= layout.remote_id_card_rect().y + layout.remote_id_card_rect().height
        );
    }

    #[test]
    fn v5_remote_display_stage_is_drawn_on_all_supported_compact_desktops() {
        let border = packed_rgb(VisualSystem::kmj_black_red().border_rgb);
        for (width, height) in [
            (800, 600),
            (960, 640),
            (1024, 768),
            (1308, 777),
            (1419, 611),
            (1920, 1080),
        ] {
            let layout = LockedDashboardLayout::for_window(width, height).unwrap();
            let stage = layout.remote_stage_rect();
            let mut shell = ProductShell::new();
            // Scroll stage into the physical viewport; the document layout
            // retains its exact reference coordinates at every window size.
            let requested = stage.y.saturating_sub(height / 2);
            let scroll = requested.min(LockedDashboardLayout::max_scroll_y(height));
            shell.set_workspace_scroll_y(scroll);
            let mut pixels = vec![0_u32; width * height];
            render_shell(&mut pixels, width, height, &presentation_for(&shell));
            let visible_y = stage.y.saturating_sub(scroll);
            assert!(visible_y < height);
            assert_eq!(
                pixels[visible_y * width + stage.x + stage.width / 2],
                border,
                "missing V5 Remote Display stage border at {width}x{height}"
            );
            assert!(stage.height >= 315);
        }
    }

    #[test]
    fn v5_trusted_devices_has_its_own_native_screen() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, NavTab};

        let width = 1419;
        let height = 611;
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "verified-peer".to_owned(),
            display_name: "Real trusted workstation".to_owned(),
            status: DeviceStatus::Online,
        }]);
        let mut remote_access = vec![0_u32; width * height];
        render_shell(&mut remote_access, width, height, &presentation_for(&shell));
        shell.set_nav_tab(NavTab::TrustedDevices);
        let mut trusted = vec![0_u32; width * height];
        render_shell(&mut trusted, width, height, &presentation_for(&shell));
        assert_ne!(remote_access, trusted);
        let tile = LockedDashboardLayout::for_window(width, height)
            .unwrap()
            .trusted_device_tile_rect(0);
        assert_eq!(
            trusted[tile.y * width + tile.x],
            packed_rgb(presentation_for(&shell).visual.border_rgb)
        );
    }

    #[test]
    fn v5_transfer_and_security_pages_react_to_real_local_records() {
        use omnidesk_core::product_shell::{FileTransferItem, NavTab};

        let width = 1419;
        let height = 800;
        let mut shell = ProductShell::new();

        shell.set_nav_tab(NavTab::FileTransfer);
        let mut empty_transfer = vec![0_u32; width * height];
        render_shell(
            &mut empty_transfer,
            width,
            height,
            &presentation_for(&shell),
        );
        shell.add_file_transfer(FileTransferItem {
            id: "local-item".into(),
            filename: "document.pdf".into(),
            size_bytes: 1024,
            progress_percent: 17,
            status: "Queued".into(),
        });
        let mut actual_transfer = vec![0_u32; width * height];
        render_shell(
            &mut actual_transfer,
            width,
            height,
            &presentation_for(&shell),
        );
        assert_ne!(actual_transfer, empty_transfer);

        shell.set_nav_tab(NavTab::Security);
        let mut empty_security = vec![0_u32; width * height];
        render_shell(
            &mut empty_security,
            width,
            height,
            &presentation_for(&shell),
        );
        shell.add_audit_event("local-attempt", "Denied pending verification", 10);
        let mut actual_security = vec![0_u32; width * height];
        render_shell(
            &mut actual_security,
            width,
            height,
            &presentation_for(&shell),
        );
        assert_ne!(actual_security, empty_security);
    }

    #[test]
    fn v5_sidebar_pages_are_visually_distinct_from_remote_access() {
        use omnidesk_core::product_shell::NavTab;

        let mut shell = ProductShell::new();
        let width = 1419;
        let height = 611;
        let mut access = vec![0_u32; width * height];
        render_shell(&mut access, width, height, &presentation_for(&shell));

        for tab in [
            NavTab::Connections,
            NavTab::FileTransfer,
            NavTab::RemoteActions,
            NavTab::Automation,
            NavTab::Security,
            NavTab::Settings,
        ] {
            shell.set_nav_tab(tab);
            let mut pixels = vec![0_u32; width * height];
            render_shell(&mut pixels, width, height, &presentation_for(&shell));
            assert_ne!(
                pixels, access,
                "V5 {tab:?} page must not be a copy of the Remote Access form"
            );
        }
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
        // The legacy layout remains only for windows narrower than 800px.
        // V5 owns compact desktop widths without the old dashboard layout.
        let width = 700;
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
        let mut pixels = vec![0_u32; 760 * 800];
        render_shell(&mut pixels, 760, 800, &presentation);

        // The panel starts at panel_x; nothing of the row may land there.
        let Some(layout) = ShellLayout::for_window(760, 800) else {
            panic!("layout should resolve at 760x800");
        };
        let Some(rect) = crate::control_rects_for(&presentation, 760, 800)
            .first()
            .copied()
        else {
            panic!("expected a control rect");
        };
        let row_y = rect.y;
        for y in row_y..row_y + rect.height {
            for x in layout.panel_x..layout.panel_x + layout.panel_width {
                let pixel = pixels[y * 760 + x];
                assert_ne!(
                    pixel,
                    packed_rgb(presentation.visual.foreground_rgb),
                    "label overflowed into the panel at ({x},{y})"
                );
            }
        }
    }
}
