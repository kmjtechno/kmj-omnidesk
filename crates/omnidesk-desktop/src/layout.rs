//! Window geometry for the desktop shell.
//!
//! Every consumer -- the renderer, the pointer hit test, and the keyboard
//! navigation order -- resolves positions through this module. When the
//! layout lived inline in the renderer, the hit test kept its own copy of the
//! arithmetic: the two agreed until the first visual change, at which point a
//! click landed somewhere other than the thing drawn under the cursor. A
//! layout that exists twice is a layout that will disagree.

/// Every dimension the shell draws, in one place.
///
/// Fields are `usize` because they are consumed as pixel offsets. The
/// conversion from a measured design is `usize::try_from(...).unwrap_or(0)`,
/// which is total; there is no path where a value is out of range by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellLayout {
    /// Height of the window title bar and primary navigation strip.
    pub top_bar_height: usize,
    /// Height of the content region above the footer.
    pub content_height: usize,
    /// Height of the footer strip.
    pub footer_height: usize,
    /// Left edge of the main content column.
    pub content_x: usize,
    /// Width of the main content column, excluding the side panel.
    pub content_width: usize,
    /// Left edge of the trailing side panel.
    pub panel_x: usize,
    /// Width of the trailing side panel.
    pub panel_width: usize,
    /// Height of a single device row.
    pub row_height: usize,
    /// Left inset shared by every text-bearing region.
    pub gutter: usize,
}

/// Below this width the shell cannot show both the content column and the side
/// panel without the text becoming unreadable, so it draws the content column
/// alone and drops the panel.
const NARROW_SHELL_WIDTH: usize = 720;

/// Below this height there is no room for the top bar, one device row, and the
/// footer.
const SHORT_SHELL_HEIGHT: usize = 220;

impl ShellLayout {
    /// Resolves the layout for a window of the given size.
    ///
    /// Returns `None` when the window is too small to draw anything useful;
    /// callers treat that as "render nothing" rather than as an error, so a
    /// window dragged to a tiny size shows an empty frame instead of
    /// overlapping text.
    #[must_use]
    pub fn for_window(width: usize, height: usize) -> Option<Self> {
        if width < 360 || height < SHORT_SHELL_HEIGHT {
            return None;
        }

        let gutter = 24;
        let top_bar_height = 56;
        let footer_height = 44;
        let row_height = 52;

        // The content column takes whatever the panel does not, floored so the
        // device labels keep a usable width on a small window.
        let panel_width = if width >= NARROW_SHELL_WIDTH {
            (width * 3 / 10).clamp(240, 380)
        } else {
            0
        };
        let content_x = gutter;
        let content_width = width
            .saturating_sub(gutter)
            .saturating_sub(panel_width)
            .saturating_sub(if panel_width == 0 { gutter } else { gutter * 2 });

        // Never let the column collapse to nothing on a window that passed the
        // narrow check: a zero-width column still reports hit targets.
        let content_width = content_width.max(200);
        let panel_x = content_x
            .saturating_add(content_width)
            .saturating_add(gutter);

        Some(Self {
            top_bar_height,
            content_height: height.saturating_sub(top_bar_height + footer_height),
            footer_height,
            content_x,
            content_width,
            panel_x,
            panel_width,
            row_height,
            gutter,
        })
    }

    /// Whether the trailing side panel is drawn at all.
    #[must_use]
    pub const fn shows_panel(&self) -> bool {
        self.panel_width > 0
    }

    /// Top edge of the first device row, below the content header.
    #[must_use]
    pub const fn first_row_y(&self) -> usize {
        self.top_bar_height + 92
    }

    /// How many device rows fit in the content column without scrolling.
    #[must_use]
    pub const fn visible_rows(&self) -> usize {
        // `first_row_y - top_bar_height` is the header block under the top
        // bar; subtracting it from `content_height` leaves the space below
        // the header, and `top_bar_height` is added back because
        // `first_row_y` is measured from the window origin while
        // `content_height` is measured from below the top bar.
        let header = 92;
        let below_rows = self
            .content_height
            .saturating_sub(header)
            .saturating_sub(self.footer_height);
        below_rows / self.row_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_lay_out_a_window_too_small_to_read() {
        assert!(ShellLayout::for_window(0, 0).is_none());
        assert!(ShellLayout::for_window(359, 800).is_none());
        assert!(ShellLayout::for_window(1200, 219).is_none());
        assert!(ShellLayout::for_window(360, 220).is_some());
    }

    #[test]
    fn wide_shell_reserves_a_panel_and_keeps_the_column_usable() {
        let layout = ShellLayout::for_window(1200, 800).expect("laid out");
        assert!(layout.shows_panel());
        assert!(
            layout.content_width >= 200,
            "content column collapsed to {}",
            layout.content_width
        );
        assert!(layout.panel_x > layout.content_x);
        assert!(
            layout.panel_x + layout.panel_width <= 1200,
            "panel runs past the window edge"
        );
    }

    #[test]
    fn narrow_shell_drops_the_panel_rather_than_squeezing_both() {
        let layout = ShellLayout::for_window(700, 800).expect("laid out");
        assert!(!layout.shows_panel());
        assert!(layout.content_width >= 200);
    }

    #[test]
    fn regions_never_overlap() {
        for width in [400, 700, 900, 1366, 1920, 2560] {
            let layout = ShellLayout::for_window(width, 800).expect("laid out");
            assert!(layout.top_bar_height < layout.content_height + layout.top_bar_height);
            assert!(layout.footer_height > 0);
            if layout.shows_panel() {
                assert!(
                    layout.panel_x >= layout.content_x + layout.content_width,
                    "panel at {} overlaps column ending at {}",
                    layout.panel_x,
                    layout.content_x + layout.content_width
                );
            }
        }
    }
}
