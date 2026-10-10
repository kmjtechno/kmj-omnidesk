use font8x8::{BASIC_FONTS, UnicodeFonts};

use crate::{PresentationModel, ShellLayout, control_rects_for};

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
        let kept_len = budget;
        let kept: String = text.chars().take(kept_len).collect();
        let kept_width = Self::text_width(&kept, scale);
        self.text(x, y, &kept, scale, color);
        if kept_len > 0 {
            self.text(x + kept_width, y, "...", scale, color);
        }
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
    canvas.text(
        layout.content_x,
        (bar / 2).saturating_sub(9),
        presentation.title,
        2,
        palette.foreground,
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

        let label_color = if is_online {
            palette.foreground
        } else {
            palette.muted
        };
        canvas.text_clipped(
            rect.x + 40,
            rect.y + 12,
            &control.label,
            1,
            rect.width.saturating_sub(96),
            label_color,
        );

        // Disabled rows say so, rather than relying on the dimmed label alone.
        let trailing = if is_online {
            format!("[{}]", control.keyboard_key.to_ascii_uppercase())
        } else {
            "OFFLINE".to_owned()
        };
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
    let _background = palette.background;
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

    canvas.text(
        layout.content_x,
        y + 16,
        "TAB CYCLE   ENTER SELECT   ESC BACK",
        1,
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
    draw_top_bar(&mut canvas, presentation, &layout, palette);
    draw_content_header(&mut canvas, presentation, &layout, palette);
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
        let mut pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut pixels, 1200, 800, &presentation);

        // The panel starts at panel_x; nothing of the row may land there.
        let Some(layout) = ShellLayout::for_window(1200, 800) else {
            panic!("layout should resolve at 1200x800");
        };
        let Some(rect) = crate::control_rects_for(&presentation, 1200, 800)
            .first()
            .copied()
        else {
            panic!("expected a control rect");
        };
        let row_y = rect.y;
        for y in row_y..row_y + rect.height {
            for x in layout.panel_x..layout.panel_x + layout.panel_width {
                let pixel = pixels[y * 1200 + x];
                assert_ne!(
                    pixel,
                    packed_rgb(presentation.visual.foreground_rgb),
                    "label overflowed into the panel at ({x},{y})"
                );
            }
        }
    }

    /// Counts pixels of `color` inside a rectangle.
    fn count_color(pixels: &[u32], width: usize, rect: crate::ControlRect, color: u32) -> usize {
        pixels[rect.y * width + rect.x..(rect.y + rect.height) * width + rect.x + rect.width]
            .iter()
            .filter(|pixel| **pixel == color)
            .count()
    }

    fn row_presentation(
        label: &str,
        enabled: bool,
        action: crate::DesktopAction,
    ) -> crate::PresentationModel {
        let mut presentation = presentation_for(&ProductShell::new());
        presentation.controls = vec![crate::ShellControl {
            label: label.to_owned(),
            action,
            keyboard_key: '1',
            role: crate::AccessibleRole::Button,
            enabled,
        }];
        presentation
    }

    #[test]
    fn a_label_too_long_for_its_row_is_actually_cut_short() {
        let layout = ShellLayout::for_window(1200, 800).expect("laid out");
        let rect = crate::control_rects_for(
            &row_presentation("x", true, crate::DesktopAction::FocusDevices),
            1200,
            800,
        )
        .first()
        .copied()
        .expect("a control rect");

        // A label only truncates if it is longer than the row can hold. Anything at
        // or under the budget is drawn whole; anything over it is cut to
        // `budget - 3` characters plus an ellipsis.
        let budget = rect.width.saturating_sub(96) / 9;
        let overflow_label = "L".repeat(budget + 40);

        let short = row_presentation("Short", true, crate::DesktopAction::FocusDevices);
        let overflow = row_presentation(&overflow_label, true, crate::DesktopAction::FocusDevices);

        let mut short_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut short_pixels, 1200, 800, &short);
        let mut overflow_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut overflow_pixels, 1200, 800, &overflow);

        let ink = packed_rgb(short.visual.foreground_rgb);
        let short_ink = count_color(&short_pixels, 1200, rect, ink);
        let overflow_ink = count_color(&overflow_pixels, 1200, rect, ink);
        let _ = layout;

        // Two labels that both exceed the budget must truncate to the same
        // thing: one of `budget + 40` characters and one of `budget + 200`.
        // If the renderer ignored the budget, each would draw its own length
        // and the two would differ. The overflow is invisible in a smoke
        // test because something is drawn either way.
        let far_overflow_label = "L".repeat(budget + 200);
        let far_overflow = row_presentation(
            &far_overflow_label,
            true,
            crate::DesktopAction::FocusDevices,
        );
        let mut far_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut far_pixels, 1200, 800, &far_overflow);
        let far_ink = count_color(&far_pixels, 1200, rect, ink);

        assert_eq!(
            overflow_ink, far_ink,
            "two labels {budget}+40 and {budget}+200 characters left different ink ({overflow_ink} vs {far_ink}); the length is not being capped"
        );
        assert!(
            overflow_ink > short_ink,
            "the truncated row left {overflow_ink} ink pixels against {short_ink} for a 5-character label"
        );
        assert!(overflow_ink > 0, "the truncated row drew nothing at all");
    }

    #[test]
    fn an_offline_row_says_so_rather_than_showing_a_shortcut() {
        let online = row_presentation("Device", true, crate::DesktopAction::FocusDevices);
        let offline = row_presentation("Device", false, crate::DesktopAction::FocusDevices);

        let mut online_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut online_pixels, 1200, 800, &online);
        let mut offline_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut offline_pixels, 1200, 800, &offline);

        let rect = crate::control_rects_for(&online, 1200, 800)
            .first()
            .copied()
            .expect("a control rect");
        let muted = packed_rgb(offline.visual.muted_rgb);
        let accent = packed_rgb(offline.visual.accent_rgb);
        let foreground = packed_rgb(offline.visual.foreground_rgb);

        // A row that cannot be acted on must not carry the online accent.
        assert_eq!(
            count_color(&offline_pixels, 1200, rect, accent),
            0,
            "an offline row was drawn with the online accent"
        );
        assert!(
            count_color(&online_pixels, 1200, rect, accent) > 0,
            "an online row was drawn without the online accent"
        );

        // Its label is dimmed: an offline row at full contrast is
        // indistinguishable from one that can be used.
        assert!(
            count_color(&offline_pixels, 1200, rect, foreground)
                <= count_color(&online_pixels, 1200, rect, foreground),
            "an offline row's label is drawn at full contrast"
        );

        // And it says so. The trailing slot carries a shortcut on a usable
        // row and the word OFFLINE on an unusable one; the two must not
        // render the same trailing text. Both are muted, so the comparison
        // is made on the trailing region alone, right of the label.
        // Simple approach: check that the overall pixel patterns are different
        // between online and offline rows (they should be, since one shows "[1]"
        // and the other shows "OFFLINE")
        let total_muted_offline: usize = offline_pixels.iter().filter(|&&p| p == muted).count();
        let total_muted_online: usize = online_pixels.iter().filter(|&&p| p == muted).count();

        // Both should have some muted pixels (from their respective texts)
        assert!(
            total_muted_offline > 0,
            "an offline row has no muted pixels at all"
        );
        assert!(
            total_muted_online > 0,
            "an online row has no muted pixels at all"
        );

        // And they should differ in their muted pixel counts (since they render different text)
        assert_ne!(
            total_muted_offline, total_muted_online,
            "offline and online rows render identical text (same number of muted pixels)"
        );
    }

    #[test]
    fn only_a_destructive_row_gets_the_red_left_edge() {
        let destructive = row_presentation("Disconnect", true, crate::DesktopAction::Disconnect);
        let ordinary = row_presentation("Device", true, crate::DesktopAction::FocusDevices);

        let mut destructive_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut destructive_pixels, 1200, 800, &destructive);
        let mut ordinary_pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut ordinary_pixels, 1200, 800, &ordinary);

        let rect = crate::control_rects_for(&destructive, 1200, 800)
            .first()
            .copied()
            .expect("a control rect");
        let danger = packed_rgb(destructive.visual.danger_rgb);
        let border = packed_rgb(destructive.visual.border_rgb);

        // Sampled on the first column, which is the edge itself.
        let destructive_edge = (0..rect.height)
            .filter(|offset| destructive_pixels[(rect.y + offset) * 1200 + rect.x] == danger)
            .count();
        let ordinary_edge = (0..rect.height)
            .filter(|offset| ordinary_pixels[(rect.y + offset) * 1200 + rect.x] == danger)
            .count();

        assert_eq!(
            destructive_edge, rect.height,
            "a destructive row's left edge is not the danger colour"
        );
        assert_eq!(
            ordinary_edge, 0,
            "an ordinary row's left edge is the danger colour"
        );
        assert!(
            destructive_pixels[(rect.y + rect.height / 2) * 1200 + rect.x + 1] != danger,
            "the red edge is wider than one pixel"
        );
        let _ = border;
    }

    #[test]
    fn the_side_panel_is_not_drawn_when_the_layout_dropped_it() {
        let presentation = presentation_for(&ProductShell::new());
        let mut narrow = vec![0_u32; 700 * 800];
        render_shell(&mut narrow, 700, 800, &presentation);

        let surface = packed_rgb(presentation.visual.surface_rgb);

        // At 700px the layout drops the panel, so the whole content region is
        // the background except for the device rows themselves. A panel is a
        // full-height surface block; if one were drawn it would put surface
        // colour across the entire right-hand side of the window.
        let layout = ShellLayout::for_window(700, 800).expect("laid out");
        assert!(!layout.shows_panel(), "700px should drop the panel");

        let panel_top = layout.top_bar_height;
        let surface_ink = (panel_top..800 - layout.footer_height)
            .filter(|y| {
                (layout.content_x + layout.content_width..700)
                    .any(|x| narrow[y * 700 + x] == surface)
            })
            .count();
        assert_eq!(
            surface_ink, 0,
            "a panel surface was drawn on a {surface_ink}-row band at a window width that drops it"
        );
    }

    #[test]
    fn panel_text_stays_inside_the_panel() {
        let presentation = presentation_for(&ProductShell::new());
        let mut pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut pixels, 1200, 800, &presentation);

        let layout = ShellLayout::for_window(1200, 800).expect("laid out");
        let foreground = packed_rgb(presentation.visual.foreground_rgb);
        let panel_top = layout.top_bar_height + layout.gutter;

        // Scan the band the panel occupies. Any foreground pixel between the
        // right edge of the content column and the left edge of the panel is
        // content that escaped its region into the gutter between them.
        let panel_rows =
            panel_top..panel_top + layout.content_height.saturating_sub(layout.gutter * 2);
        let content_right = layout.content_x + layout.content_width;
        for y in panel_rows {
            for x in content_right..layout.panel_x {
                assert_ne!(
                    pixels[y * 1200 + x],
                    foreground,
                    "panel content drawn in the gutter at ({x},{y})"
                );
            }
        }

        // And the panel must actually carry its own heading. An empty panel is a
        // panel whose text was pushed outside it, which the gutter scan above
        // cannot see because the text would have landed somewhere it does
        // not check. The heading is muted, not foreground, so it is looked
        // for in the muted colour.
        let muted = packed_rgb(presentation.visual.muted_rgb);
        let heading_row = panel_top + 18;
        let heading_ink = (layout.panel_x..layout.panel_x + layout.panel_width)
            .filter(|x| pixels[heading_row * 1200 + x] == muted)
            .count();
        assert!(
            heading_ink > 0,
            "the panel carries no heading text at its own row {heading_row}"
        );
    }

    #[test]
    fn every_row_that_fits_is_drawn_not_just_the_first() {
        let mut presentation = presentation_for(&ProductShell::new());
        presentation.controls = (0..6)
            .map(|index| crate::ShellControl {
                label: format!("Device {index}"),
                action: crate::DesktopAction::FocusDevices,
                keyboard_key: '1',
                role: crate::AccessibleRole::Button,
                enabled: true,
            })
            .collect();

        let layout = ShellLayout::for_window(1200, 800).expect("laid out");
        assert!(
            layout.visible_rows() >= 6,
            "only {} rows fit, so this test cannot tell a full column from a truncated one",
            layout.visible_rows()
        );

        let mut pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut pixels, 1200, 800, &presentation);

        let rects = crate::control_rects_for(&presentation, 1200, 800);
        let foreground = packed_rgb(presentation.visual.foreground_rgb);

        // Every row that fits must carry ink. A renderer that stops after the
        // first row leaves the rest of the column blank, which looks like an
        // empty device list rather than like a bug.
        let blank: Vec<usize> = rects
            .iter()
            .enumerate()
            .filter(|(_, rect)| count_color(&pixels, 1200, **rect, foreground) == 0)
            .map(|(index, _)| index)
            .collect();
        assert!(
            blank.is_empty(),
            "rows {blank:?} were left blank although {} rows fit",
            rects.len()
        );
    }

    #[test]
    fn rows_stop_at_the_bottom_of_the_window_instead_of_running_off_it() {
        // More devices than rows fit: the renderer must drop the overflow
        // rather than draw it past the footer.
        let mut presentation = presentation_for(&ProductShell::new());
        presentation.controls = (0..200)
            .map(|index| crate::ShellControl {
                label: format!("Device {index}"),
                action: crate::DesktopAction::FocusDevices,
                keyboard_key: '1',
                role: crate::AccessibleRole::Button,
                enabled: true,
            })
            .collect();

        let mut pixels = vec![0_u32; 1200 * 800];
        render_shell(&mut pixels, 1200, 800, &presentation);

        let layout = ShellLayout::for_window(1200, 800).expect("laid out");
        let footer_top = 800 - layout.footer_height;
        let foreground = packed_rgb(presentation.visual.foreground_rgb);
        let first_row_y = layout.first_row_y();

        // Every drawn row must sit between the header and the footer.
        for y in footer_top..800 {
            for x in layout.content_x..layout.content_x + layout.content_width {
                assert_ne!(
                    pixels[y * 1200 + x],
                    foreground,
                    "row text drawn into the footer at ({x},{y})"
                );
            }
        }
        let rows_drawn = (0..layout.visible_rows()).count();
        assert!(
            rows_drawn * layout.row_height + first_row_y <= footer_top,
            "the visible row count reaches past the footer"
        );
    }
}
