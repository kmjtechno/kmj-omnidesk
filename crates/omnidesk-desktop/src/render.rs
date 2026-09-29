use font8x8::{BASIC_FONTS, UnicodeFonts};

use crate::PresentationModel;

#[must_use]
pub const fn packed_rgb(rgb: [u8; 3]) -> u32 {
    (rgb[0] as u32) << 16 | (rgb[1] as u32) << 8 | rgb[2] as u32
}

fn fill_rect(
    pixels: &mut [u32],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    rect_width: usize,
    rect_height: usize,
    color: u32,
) {
    let max_x = x.saturating_add(rect_width).min(width);
    let max_y = y.saturating_add(rect_height).min(height);
    for py in y.min(height)..max_y {
        let row = py * width;
        for px in x.min(width)..max_x {
            pixels[row + px] = color;
        }
    }
}

fn stroke_rect(
    pixels: &mut [u32],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    rect_width: usize,
    rect_height: usize,
    thickness: usize,
    color: u32,
) {
    fill_rect(pixels, width, height, x, y, rect_width, thickness, color);
    fill_rect(
        pixels,
        width,
        height,
        x,
        y.saturating_add(rect_height.saturating_sub(thickness)),
        rect_width,
        thickness,
        color,
    );
    fill_rect(pixels, width, height, x, y, thickness, rect_height, color);
    fill_rect(
        pixels,
        width,
        height,
        x.saturating_add(rect_width.saturating_sub(thickness)),
        y,
        thickness,
        rect_height,
        color,
    );
}

fn draw_text(
    pixels: &mut [u32],
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    text: &str,
    scale: usize,
    color: u32,
) {
    let mut cursor_x = x;
    for character in text.chars() {
        let glyph_character = character.to_ascii_uppercase();
        if let Some(glyph) = BASIC_FONTS.get(glyph_character) {
            for (row, bits) in glyph.iter().enumerate() {
                for column in 0..8 {
                    if bits & (1 << column) != 0 {
                        fill_rect(
                            pixels,
                            width,
                            height,
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

/// Draws the current truthful product-shell presentation into an RGB software buffer.
///
/// The renderer is deliberately static/event-driven: it draws only the state supplied by
/// PresentationModel and never invents devices, sessions, or online state.
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
    let background = packed_rgb(visual.background_rgb);
    let surface = packed_rgb(visual.surface_rgb);
    let foreground = packed_rgb(visual.foreground_rgb);
    let accent = packed_rgb(visual.accent_rgb);
    let danger = packed_rgb(visual.danger_rgb);

    pixels[..width * height].fill(background);

    let rail_width = 176.min(width);
    fill_rect(pixels, width, height, 0, 0, rail_width, height, surface);
    fill_rect(pixels, width, height, 0, 0, 6.min(width), height, accent);

    draw_text(
        pixels,
        width,
        height,
        22,
        22,
        presentation.title,
        2,
        foreground,
    );
    draw_text(
        pixels,
        width,
        height,
        22,
        56,
        presentation.status,
        1,
        accent,
    );

    if width > 208 && height > 64 {
        let panel_x = 192;
        let panel_y = 32;
        let panel_width = width.saturating_sub(216);
        let panel_height = height.saturating_sub(64);
        fill_rect(
            pixels,
            width,
            height,
            panel_x,
            panel_y,
            panel_width,
            panel_height,
            surface,
        );
        stroke_rect(
            pixels,
            width,
            height,
            panel_x,
            panel_y,
            panel_width,
            panel_height,
            1,
            accent,
        );

        draw_text(
            pixels,
            width,
            height,
            panel_x + 22,
            panel_y + 20,
            "SECURITY STATE",
            1,
            foreground,
        );
        draw_text(
            pixels,
            width,
            height,
            panel_x + 22,
            panel_y + 42,
            presentation.status,
            1,
            accent,
        );

        let mut control_y = panel_y + 84;
        for control in &presentation.controls {
            let card_width = panel_width.saturating_sub(44);
            fill_rect(
                pixels,
                width,
                height,
                panel_x + 22,
                control_y,
                card_width,
                48,
                background,
            );
            stroke_rect(
                pixels,
                width,
                height,
                panel_x + 22,
                control_y,
                card_width,
                48,
                2,
                accent,
            );
            draw_text(
                pixels,
                width,
                height,
                panel_x + 36,
                control_y + 12,
                control.label,
                1,
                foreground,
            );

            let shortcut = format!("[{}]", control.keyboard_key.to_ascii_uppercase());
            let shortcut_x = panel_x
                .saturating_add(panel_width)
                .saturating_sub(22 + shortcut.len() * 9 + 14);
            draw_text(
                pixels,
                width,
                height,
                shortcut_x,
                control_y + 12,
                &shortcut,
                1,
                danger,
            );
            control_y = control_y.saturating_add(62);
        }
    }
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
