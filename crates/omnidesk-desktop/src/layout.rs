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

        let gutter = 28;
        let top_bar_height = 68;
        let footer_height = 42;
        let row_height = 58;

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
        self.top_bar_height + 246
    }

    /// How many device rows fit in the content column without scrolling.
    #[must_use]
    pub const fn visible_rows(&self) -> usize {
        // content_height already excludes the footer. Subtracting it again
        // would hide a device row even when that row fully fits above it.
        let header = self.first_row_y().saturating_sub(self.top_bar_height);
        self.content_height.saturating_sub(header) / self.row_height
    }
}

/// Initial desktop size fitted to the available physical monitor.
///
/// Winit's initial size is in logical pixels. A 1280 logical-pixel window
/// does not fit on a 1024-pixel hosted display, and `PrintWindow` can then
/// capture an unpainted right-hand region rather than the inspector. Leave
/// physical room for non-client borders, a taskbar, and OS window placement.
/// This affects only the initial window size; normal user resizing remains
/// available and the narrow shell is the explicit responsive fallback.
#[must_use]
pub fn initial_window_inner_size(monitor: Option<(u32, u32, f64)>) -> (f64, f64) {
    const PREFERRED_WIDTH: f64 = 1280.0;
    const PREFERRED_HEIGHT: f64 = 720.0;
    let Some((physical_width, physical_height, scale_factor)) = monitor else {
        return (PREFERRED_WIDTH, PREFERRED_HEIGHT);
    };
    if !scale_factor.is_finite() || scale_factor <= 0.0 {
        return (PREFERRED_WIDTH, PREFERRED_HEIGHT);
    }

    let usable_width = f64::from(physical_width.saturating_sub(56));
    let usable_height = f64::from(physical_height.saturating_sub(84));
    (
        (usable_width / scale_factor).clamp(360.0, PREFERRED_WIDTH),
        (usable_height / scale_factor).clamp(220.0, PREFERRED_HEIGHT),
    )
}

/// Place a new native window just inside its monitor, not at an arbitrary
/// OS-chosen offset. A window can be smaller than the display yet still
/// extend beyond its right and bottom boundaries after default placement.
#[must_use]
pub const fn initial_window_origin(monitor_left: i32, monitor_top: i32) -> (i32, i32) {
    (
        monitor_left.saturating_add(8),
        monitor_top.saturating_add(8),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_window_placement_keeps_its_monitor_origin() {
        assert_eq!(initial_window_origin(0, 0), (8, 8));
        assert_eq!(initial_window_origin(-1920, 0), (-1912, 8));
        assert_eq!(
            initial_window_origin(i32::MAX, i32::MAX),
            (i32::MAX, i32::MAX)
        );
    }

    #[test]
    fn initial_window_fits_a_small_physical_monitor() {
        let (width, height) = initial_window_inner_size(Some((1024, 768, 1.0)));
        assert_eq!((width, height), (968.0, 684.0));
        assert!(width + 56.0 <= 1024.0);
        assert!(height + 84.0 <= 768.0);
        // A small monitor uses the compact fallback rather than clipping the
        // locked four-column dashboard beyond the visible screen.
        assert!(LockedDashboardLayout::for_window(968, 684).is_none());
        assert!(ShellLayout::for_window(968, 684).is_some());
    }

    #[test]
    fn initial_window_respects_dpi_and_preferred_desktop_size() {
        assert_eq!(initial_window_inner_size(None), (1280.0, 720.0));
        assert_eq!(
            initial_window_inner_size(Some((1920, 1080, 1.0))),
            (1280.0, 720.0)
        );
        assert_eq!(
            initial_window_inner_size(Some((1024, 768, 1.25))),
            (774.4, 547.2)
        );
        let (width, height) = initial_window_inner_size(Some((2560, 1440, 2.0)));
        assert_eq!((width, height), (1252.0, 678.0));
        assert!(width.mul_add(2.0, 56.0) <= 2560.0);
        assert!(height.mul_add(2.0, 84.0) <= 1440.0);
    }

    #[test]
    fn invalid_monitor_scale_does_not_break_native_startup() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                initial_window_inner_size(Some((1024, 768, scale))),
                (1280.0, 720.0)
            );
        }
    }

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
    fn compact_shell_shows_every_full_row_above_the_footer() {
        let layout = ShellLayout::for_window(700, 800).expect("laid out");
        assert_eq!(layout.first_row_y(), 314);
        // 800 - 42 (footer) - 314 (first row) = 444 pixels: seven full
        // 58-pixel rows fit. The old double-footer subtraction showed six.
        assert_eq!(layout.visible_rows(), 7);
        assert_eq!(
            layout.first_row_y() + layout.visible_rows() * layout.row_height,
            720
        );
    }

    #[test]
    fn compact_visible_row_count_is_maximal_without_footer_overlap() {
        for height in [220, 300, 371, 372, 400, 600, 800, 1080] {
            let layout = ShellLayout::for_window(700, height).expect("laid out");
            let content_bottom = layout.top_bar_height + layout.content_height;
            let first = layout.first_row_y();
            let count = layout.visible_rows();
            if content_bottom < first {
                assert_eq!(count, 0);
                continue;
            }
            let rows_bottom = first + count * layout.row_height;
            assert!(rows_bottom <= content_bottom);
            assert!(content_bottom - rows_bottom < layout.row_height);
        }
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

/// Pixel-space rectangle shared by the visual and input layers of the locked
/// four-column dashboard. Draw and hit-test code must not duplicate offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DashboardRect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

impl DashboardRect {
    #[must_use]
    pub const fn contains(self, x: usize, y: usize) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x.saturating_add(self.width)
            && y < self.y.saturating_add(self.height)
    }
}

/// Canonical 1419x611 user-approved visual reference:
/// nav | devices | remote workspace | status inspector.
///
/// Below the minimum readable dashboard size the existing compact shell
/// is used. This is a deliberate responsive fallback, not clipped columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedDashboardLayout {
    pub top_bar_height: usize,
    pub navigation: DashboardRect,
    pub devices: DashboardRect,
    pub viewer: DashboardRect,
    pub inspector: DashboardRect,
    pub remote_screen: DashboardRect,
    pub session_toolbar: DashboardRect,
    pub first_device_row_y: usize,
    pub device_row_step: usize,
}

impl LockedDashboardLayout {
    #[must_use]
    pub fn for_window(width: usize, height: usize) -> Option<Self> {
        if width < 1180 || height < 600 {
            return None;
        }
        let top = 70;
        let navigation_width = (width / 100 * 12).clamp(160, 198);
        let devices_width = (width / 100 * 19).clamp(238, 315);
        let inspector_width = (width / 100 * 20).clamp(254, 320);
        let nav = DashboardRect {
            x: 4,
            y: top + 4,
            width: navigation_width,
            height: height - top - 10,
        };
        let devices = DashboardRect {
            x: nav.x + nav.width + 6,
            y: nav.y,
            width: devices_width,
            height: nav.height,
        };
        let inspector = DashboardRect {
            x: width - inspector_width - 6,
            y: nav.y,
            width: inspector_width,
            height: nav.height,
        };
        let viewer_x = devices.x + devices.width + 6;
        let viewer_width = inspector.x.saturating_sub(viewer_x + 6);
        if viewer_width < 350 {
            return None;
        }
        let viewer = DashboardRect {
            x: viewer_x,
            y: nav.y,
            width: viewer_width,
            height: nav.height,
        };
        let toolbar_y = viewer.y + viewer.height - 76;
        let remote_screen = DashboardRect {
            x: viewer.x + 10,
            y: viewer.y + 62,
            width: viewer.width - 20,
            height: viewer.height.saturating_sub(150),
        };
        let session_toolbar = DashboardRect {
            x: viewer.x + 10,
            y: toolbar_y,
            width: viewer.width - 20,
            height: 58,
        };
        Some(Self {
            top_bar_height: top,
            navigation: nav,
            devices,
            viewer,
            inspector,
            remote_screen,
            session_toolbar,
            first_device_row_y: devices.y + 93,
            device_row_step: 55,
        })
    }

    #[must_use]
    pub const fn device_row(&self, index: usize) -> DashboardRect {
        DashboardRect {
            x: self.devices.x + 8,
            y: self.first_device_row_y + index.saturating_mul(self.device_row_step),
            width: self.devices.width.saturating_sub(16),
            height: 49,
        }
    }

    #[must_use]
    pub fn permission_button(&self, index: usize) -> DashboardRect {
        DashboardRect {
            x: self.remote_screen.x + 18,
            y: self.remote_screen.y + 125 + index.saturating_mul(62),
            width: self.remote_screen.width.saturating_sub(36).min(240),
            height: 48,
        }
    }

    #[must_use]
    pub fn session_button(&self, index: usize, count: usize) -> DashboardRect {
        let count = count.max(1);
        let item_width = self.session_toolbar.width / count;
        DashboardRect {
            x: self.session_toolbar.x + index.saturating_mul(item_width) + 3,
            y: self.session_toolbar.y + 5,
            width: item_width.saturating_sub(6),
            height: self.session_toolbar.height - 10,
        }
    }
}

#[cfg(test)]
mod locked_dashboard_tests {
    use super::*;

    #[test]
    fn matches_locked_four_column_hierarchy() {
        let l = LockedDashboardLayout::for_window(1419, 611).unwrap();
        assert!(l.navigation.x + l.navigation.width < l.devices.x);
        assert!(l.devices.x + l.devices.width < l.viewer.x);
        assert!(l.viewer.x + l.viewer.width < l.inspector.x);
        assert!(l.inspector.x + l.inspector.width <= 1419);
        assert!(l.remote_screen.y >= l.viewer.y);
        assert!(l.session_toolbar.y > l.remote_screen.y + l.remote_screen.height);
    }

    #[test]
    fn compact_windows_fall_back_instead_of_overlapping_panels() {
        assert!(LockedDashboardLayout::for_window(960, 640).is_none());
        assert!(LockedDashboardLayout::for_window(1419, 560).is_none());
        for (width, height) in [
            (1180, 600),
            (1200, 800),
            (1419, 611),
            (1920, 1080),
            (2560, 1440),
        ] {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            assert!(l.viewer.width >= 350);
            assert!(l.inspector.x + l.inspector.width <= width);
            assert!(
                l.device_row(0)
                    .contains(l.device_row(0).x, l.device_row(0).y)
            );
            assert!(!l.device_row(0).contains(l.navigation.x, l.device_row(0).y));
        }
    }
}
