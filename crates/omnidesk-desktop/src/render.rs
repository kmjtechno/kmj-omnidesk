use font8x8::{BASIC_FONTS, UnicodeFonts};

use crate::{PresentationModel, control_rects_for};

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
}

#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    surface: u32,
    foreground: u32,
    accent: u32,
    danger: u32,
}

fn draw_navigation(canvas: &mut Canvas<'_>, presentation: &PresentationModel, palette: Palette) {
    let rail_width = 176.min(canvas.width);
    canvas.fill_rect(0, 0, rail_width, canvas.height, palette.surface);
    canvas.fill_rect(0, 0, 6.min(canvas.width), canvas.height, palette.accent);
    canvas.text(22, 22, presentation.title, 2, palette.foreground);
    canvas.text(22, 56, presentation.status, 1, palette.accent);
}

fn draw_controls(canvas: &mut Canvas<'_>, presentation: &PresentationModel, palette: Palette) {
    if canvas.width <= 208 || canvas.height <= 64 {
        return;
    }

    let panel_x = 192;
    let panel_y = 32;
    let panel_width = canvas.width.saturating_sub(216);
    let panel_height = canvas.height.saturating_sub(64);

    canvas.fill_rect(panel_x, panel_y, panel_width, panel_height, palette.surface);
    canvas.stroke_rect(
        panel_x,
        panel_y,
        panel_width,
        panel_height,
        1,
        palette.accent,
    );
    canvas.text(
        panel_x + 22,
        panel_y + 20,
        "SECURITY STATE",
        1,
        palette.foreground,
    );
    canvas.text(
        panel_x + 22,
        panel_y + 42,
        presentation.status,
        1,
        palette.accent,
    );

    let mut detail_y = panel_y + 68;
    for detail in &presentation.details {
        canvas.text(panel_x + 22, detail_y, detail, 1, palette.foreground);
        detail_y = detail_y.saturating_add(18);
    }

    let rects = control_rects_for(presentation, canvas.width, canvas.height);
    for (control, rect) in presentation.controls.iter().zip(rects) {
        canvas.fill_rect(rect.x, rect.y, rect.width, rect.height, palette.background);
        canvas.stroke_rect(
            rect.x,
            rect.y,
            rect.width,
            rect.height,
            2,
            if control.enabled {
                palette.accent
            } else {
                palette.danger
            },
        );
        canvas.text(
            rect.x + 14,
            rect.y + 12,
            &control.label,
            1,
            if control.enabled {
                palette.foreground
            } else {
                palette.danger
            },
        );

        let shortcut = format!("[{}]", control.keyboard_key.to_ascii_uppercase());
        let shortcut_x = rect
            .x
            .saturating_add(rect.width)
            .saturating_sub(shortcut.len() * 9 + 14);
        canvas.text(shortcut_x, rect.y + 12, &shortcut, 1, palette.danger);
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

    let visual = presentation.visual;
    let palette = Palette {
        background: packed_rgb(visual.background_rgb),
        surface: packed_rgb(visual.surface_rgb),
        foreground: packed_rgb(visual.foreground_rgb),
        accent: packed_rgb(visual.accent_rgb),
        danger: packed_rgb(visual.danger_rgb),
    };

    pixels[..width * height].fill(palette.background);
    let mut canvas = Canvas {
        pixels,
        width,
        height,
    };
    draw_navigation(&mut canvas, presentation, palette);
    draw_controls(&mut canvas, presentation, palette);
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
        let mut pixels = vec![0_u32; 480 * 260];

        render_shell(&mut pixels, 480, 260, &presentation);

        let visual = VisualSystem::kmj_black_red();
        let background = packed_rgb(visual.background_rgb);
        let surface = packed_rgb(visual.surface_rgb);
        let foreground = packed_rgb(visual.foreground_rgb);
        let accent = packed_rgb(visual.accent_rgb);

        assert!(pixels.contains(&background));
        assert!(pixels.contains(&surface));
        assert!(pixels.contains(&foreground));
        assert!(pixels.contains(&accent));
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
}
