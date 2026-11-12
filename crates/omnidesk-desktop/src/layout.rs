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

/// Keep a newly opened native window within the target monitor.
///
/// A window smaller than a display can still extend off-screen when the
/// operating system chooses a large initial position offset.
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
        // V5 fits a 1024x768 physical monitor with the responsive 3-column layout
        // (compact nav rail, wide remote workspace, collapsed inspector).
        assert!(LockedDashboardLayout::for_window(968, 684).is_some());
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
        if width < 800 || height < 600 {
            return None;
        }
        // V5 canonical fold: 75px branded header, fixed navigation and a
        // SCROLLABLE central content canvas. Never shrink 363px workflow
        // cards into the former 173px mini-panels on short Windows screens.
        let top = 75;
        // Match the actual locked HTML breakpoints, not a guessed 1450px
        // threshold. At the owner's 1309x777 screenshot the inspector must
        // collapse so the two credential cards can breathe.
        let navigation_width = if width <= 1020 { 78 } else { 200 };
        let inspector_width = if width <= 1510 {
            0
        } else {
            (width * 18 / 100).clamp(294, 315)
        };
        let nav = DashboardRect {
            x: 12,
            y: top,
            width: navigation_width,
            height: height.saturating_sub(top),
        };
        let inspector = DashboardRect {
            x: width.saturating_sub(inspector_width),
            y: top,
            width: inspector_width,
            height: nav.height,
        };
        let viewer_x = nav.x + nav.width + 16;
        let viewer_width = inspector.x.saturating_sub(viewer_x + 16);
        if viewer_width < 640 {
            return None;
        }
        let viewer = DashboardRect {
            x: viewer_x,
            y: top,
            width: viewer_width,
            height: nav.height,
        };
        // These are CONTENT positions, not positions squeezed into one
        // short viewport. The host scrolls this center column only.
        let remote_screen = DashboardRect {
            // The approved HTML adds four pixels of padding when the
            // Session Inspector is present, and two pixels of vertical
            // breathing room on medium-width Windows desktops.
            x: viewer.x + if inspector_width > 0 { 25 } else { 21 },
            y: viewer.y
                + if inspector_width > 0 {
                    133
                } else if width >= 1200 {
                    125
                } else {
                    123
                },
            width: viewer
                .width
                .saturating_sub(if inspector_width > 0 { 37 } else { 33 }),
            height: 788,
        };
        let devices = DashboardRect {
            x: remote_screen.x,
            y: remote_screen.y + 810,
            width: remote_screen.width,
            height: 85,
        };
        let session_toolbar = DashboardRect {
            x: remote_screen.x,
            y: devices.y + 100,
            width: remote_screen.width,
            height: 56,
        };
        Some(Self {
            top_bar_height: top,
            navigation: nav,
            devices,
            viewer,
            inspector,
            remote_screen,
            session_toolbar,
            first_device_row_y: devices.y + 34,
            device_row_step: 55,
        })
    }

    /// Full document height of the scrollable V5 center column.
    pub const CONTENT_HEIGHT: usize = 1240;

    /// Maximum possible vertical scroll for a physical Windows viewport.
    #[must_use]
    pub const fn max_scroll_y(window_height: usize) -> usize {
        Self::CONTENT_HEIGHT.saturating_sub(window_height)
    }

    #[must_use]
    pub const fn device_row(&self, index: usize) -> DashboardRect {
        let tile_width = self.devices.width.saturating_sub(28) / 3;
        DashboardRect {
            x: self.devices.x + 10 + (index % 3) * (tile_width + 4),
            y: self.first_device_row_y + (index / 3) * self.device_row_step,
            width: tile_width,
            height: if self.compact_height() { 30 } else { 45 },
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

    #[must_use]
    pub const fn nav_tab_rect(&self, index: usize) -> DashboardRect {
        DashboardRect {
            x: self.navigation.x,
            y: self.navigation.y + 50 + index.saturating_mul(44) + if index >= 4 { 80 } else { 0 },
            width: self.navigation.width,
            height: 42,
        }
    }

    /// Positions verified-device tiles on the separate Trusted Devices page.
    /// The same rectangles are shared by rendering, pointer hit tests and
    /// assistive technology; the Remote Access quick strip is unaffected.
    #[must_use]
    pub const fn trusted_device_tile_rect(&self, index: usize) -> DashboardRect {
        let frame = self.remote_screen;
        let gutter = 18;
        let gap = 10;
        let columns = 3;
        let tile_width = frame.width.saturating_sub(gutter * 2 + gap * 2) / columns;
        DashboardRect {
            x: frame.x + gutter + (index % columns) * (tile_width + gap),
            y: frame.y + 146 + (index / columns) * 57,
            width: tile_width,
            height: 48,
        }
    }

    #[must_use]
    pub const fn filter_all_rect(&self) -> DashboardRect {
        DashboardRect {
            x: self.devices.x + 175,
            y: self.devices.y + 9,
            width: 45,
            height: 22,
        }
    }

    #[must_use]
    pub const fn filter_online_rect(&self) -> DashboardRect {
        DashboardRect {
            x: self.devices.x + 228,
            y: self.devices.y + 9,
            width: 65,
            height: 22,
        }
    }

    #[must_use]
    pub const fn filter_offline_rect(&self) -> DashboardRect {
        DashboardRect {
            x: self.devices.x + 302,
            y: self.devices.y + 9,
            width: 70,
            height: 22,
        }
    }

    #[must_use]
    pub const fn settings_button_rect(&self, window_width: usize) -> DashboardRect {
        DashboardRect {
            x: window_width.saturating_sub(194),
            y: 20,
            width: 90,
            height: 30,
        }
    }

    /// Compact-height windows keep the remote-display stage visible.
    #[must_use]
    pub const fn compact_height(&self) -> bool {
        self.viewer.height < 700
    }

    /// A separate video/stage area below Connect and Share cards.
    #[must_use]
    pub const fn remote_stage_rect(&self) -> DashboardRect {
        let offset = 462;
        DashboardRect {
            x: self.remote_screen.x,
            y: self.remote_screen.y + offset,
            width: self.remote_screen.width,
            height: 315,
        }
    }

    /// Show separate share/connect panels side by side when there is enough
    /// actual viewer width, retaining the stacked layout on smaller desktops.
    #[must_use]
    pub const fn access_cards_wide(&self) -> bool {
        self.remote_screen.width >= 640
    }

    #[must_use]
    pub const fn your_id_card_rect(&self) -> DashboardRect {
        let screen = self.remote_screen;
        let gap = 16;
        let available = screen.width.saturating_sub(gap);
        let connect_width = available * 52 / 100;
        DashboardRect {
            x: if self.access_cards_wide() {
                screen.x + connect_width + gap
            } else {
                screen.x
            },
            y: if self.access_cards_wide() {
                screen.y + 18
            } else {
                screen.y + 18 + 363 + 16
            },
            width: if self.access_cards_wide() {
                available.saturating_sub(connect_width)
            } else {
                screen.width
            },
            height: 363,
        }
    }

    #[must_use]
    pub const fn your_id_copy_btn_rect(&self) -> DashboardRect {
        let card = self.your_id_card_rect();
        DashboardRect {
            x: card.x + card.width.saturating_sub(117),
            y: card.y + 118,
            width: 98,
            height: 36,
        }
    }

    #[must_use]
    pub const fn your_password_status_rect(&self) -> DashboardRect {
        let card = self.your_id_card_rect();
        DashboardRect {
            x: card.x + 24,
            y: card.y + 172,
            width: card.width.saturating_sub(48),
            height: 20,
        }
    }

    /// Dedicated credential input, separate from its caption and footer.
    #[must_use]
    pub const fn your_password_field_rect(&self) -> DashboardRect {
        let card = self.your_id_card_rect();
        DashboardRect {
            x: card.x + 24,
            y: card.y + 198,
            width: card.width.saturating_sub(158),
            height: 44,
        }
    }

    #[must_use]
    pub const fn your_password_reveal_btn_rect(&self) -> DashboardRect {
        let field = self.your_password_field_rect();
        DashboardRect {
            x: field.x + field.width.saturating_sub(42),
            y: field.y + 4,
            width: 38,
            height: 36,
        }
    }

    #[must_use]
    pub const fn your_password_copy_btn_rect(&self) -> DashboardRect {
        let field = self.your_password_field_rect();
        DashboardRect {
            x: field.x + field.width + 8,
            y: field.y,
            width: 96,
            height: field.height,
        }
    }

    #[must_use]
    pub const fn your_password_rotate_btn_rect(&self) -> DashboardRect {
        let card = self.your_id_card_rect();
        DashboardRect {
            x: card.x + card.width.saturating_sub(170),
            y: card.y + 285,
            width: 146,
            height: 32,
        }
    }

    #[must_use]
    pub const fn remote_id_card_rect(&self) -> DashboardRect {
        let screen = self.remote_screen;
        DashboardRect {
            x: screen.x,
            y: screen.y + 18,
            width: if self.access_cards_wide() {
                screen.width.saturating_sub(16) * 52 / 100
            } else {
                screen.width
            },
            height: 363,
        }
    }

    #[must_use]
    pub const fn remote_id_input_rect(&self) -> DashboardRect {
        let card = self.remote_id_card_rect();
        DashboardRect {
            x: card.x + 24,
            y: card.y + 111,
            width: card.width.saturating_sub(48),
            height: 44,
        }
    }

    #[must_use]
    pub const fn remote_id_connect_btn_rect(&self) -> DashboardRect {
        let card = self.remote_id_card_rect();
        DashboardRect {
            x: card.x + 24,
            y: card.y + 252,
            width: 176,
            height: 44,
        }
    }

    #[must_use]
    pub const fn remote_password_status_rect(&self) -> DashboardRect {
        let card = self.remote_id_card_rect();
        DashboardRect {
            x: card.x + 24,
            y: card.y + 191,
            width: card.width.saturating_sub(48),
            height: 44,
        }
    }

    #[must_use]
    pub const fn remote_password_reveal_btn_rect(&self) -> DashboardRect {
        let field = self.remote_password_status_rect();
        DashboardRect {
            x: field.x + field.width.saturating_sub(51),
            y: field.y + 3,
            width: 47,
            height: field.height.saturating_sub(6),
        }
    }

    #[must_use]
    pub const fn session_toolbar_rect(&self) -> DashboardRect {
        DashboardRect {
            x: self.remote_screen.x + 16,
            y: self.remote_screen.y + 12,
            width: self.remote_screen.width.saturating_sub(32),
            height: 40,
        }
    }

    #[must_use]
    pub const fn session_tool_btn_rect(&self, index: usize) -> DashboardRect {
        let bar = self.session_toolbar_rect();
        let btn_w = 95;
        DashboardRect {
            x: bar.x + 10 + index * (btn_w + 8),
            y: bar.y + 4,
            width: btn_w,
            height: 32,
        }
    }

    #[must_use]
    pub const fn help_button_rect(&self, window_width: usize) -> DashboardRect {
        DashboardRect {
            x: window_width.saturating_sub(100),
            y: 20,
            width: 80,
            height: 30,
        }
    }
}

#[cfg(test)]
mod locked_dashboard_tests {
    use super::*;

    #[test]
    fn approved_v5_reference_coordinates_are_locked_at_three_viewports() {
        // Matched against the approved V5 HTML reference's real DOM boxes,
        // not an unapproved redesign or the outdated 173px native screenshot.
        let scenarios = [
            // screen width, height, x, card y, connect width, share x,
            // share width, stage y, stage x
            (1024, 768, 249, 216, 380, 645, 351, 660, 249),
            (1308, 777, 249, 218, 527, 792, 488, 662, 249),
            (1600, 920, 253, 226, 524, 793, 485, 670, 253),
        ];
        for (
            width,
            height,
            card_x,
            card_y,
            connect_width,
            share_x,
            share_width,
            stage_y,
            stage_x,
        ) in scenarios
        {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            let connect = l.remote_id_card_rect();
            let share = l.your_id_card_rect();
            let stage = l.remote_stage_rect();
            assert_eq!(
                (connect.x, connect.y, connect.width, connect.height),
                (card_x, card_y, connect_width, 363)
            );
            assert_eq!(
                (share.x, share.y, share.width, share.height),
                (share_x, card_y, share_width, 363)
            );
            assert_eq!((stage.x, stage.y), (stage_x, stage_y));
            assert_eq!(stage.height, 315);
            assert_eq!(
                l.inspector.width == 0,
                width <= 1510,
                "inspector must collapse on 1308px compact Windows desktop"
            );
            assert!(LockedDashboardLayout::max_scroll_y(height) > 0);
        }
    }

    #[test]
    fn v5_layout_uses_three_primary_columns() {
        let l = LockedDashboardLayout::for_window(1419, 611).unwrap();
        assert!(l.navigation.x + l.navigation.width < l.viewer.x);
        assert!(l.viewer.x + l.viewer.width < l.inspector.x);
        assert!(l.devices.x >= l.viewer.x);
        assert!(l.devices.x + l.devices.width <= l.viewer.x + l.viewer.width);
        assert!(l.inspector.x + l.inspector.width <= 1419);
        assert!(l.remote_screen.y >= l.viewer.y);
        assert!(l.session_toolbar.y > l.remote_screen.y + l.remote_screen.height);
    }

    #[test]
    fn compact_windows_fall_back_and_laptops_hide_the_inspector() {
        assert!(LockedDashboardLayout::for_window(760, 640).is_none());
        assert!(LockedDashboardLayout::for_window(960, 640).is_some());
        assert!(LockedDashboardLayout::for_window(1419, 560).is_none());
        assert_eq!(
            LockedDashboardLayout::for_window(1024, 768)
                .unwrap()
                .inspector
                .width,
            0
        );
        assert_eq!(
            LockedDashboardLayout::for_window(960, 640)
                .unwrap()
                .navigation
                .width,
            78
        );
        for (width, height) in [
            (800, 600),
            (960, 640),
            (1024, 768),
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

    #[test]
    fn locked_html_breakpoints_match_owner_screenshot_and_inspector_fold() {
        for (width, height, expected_nav, inspector_visible) in [
            (960, 640, 78, false),
            (1020, 768, 78, false),
            (1021, 768, 200, false),
            (1309, 777, 200, false),
            (1419, 611, 200, false),
            (1450, 900, 200, false),
            (1510, 900, 200, false),
            (1511, 900, 200, true),
            (1920, 777, 200, true),
            (1920, 1080, 200, true),
        ] {
            let layout = LockedDashboardLayout::for_window(width, height)
                .expect("V5 owner-locked breakpoint");
            assert_eq!(layout.navigation.width, expected_nav, "{width}x{height}");
            assert_eq!(
                layout.inspector.width > 0,
                inspector_visible,
                "{width}x{height}"
            );
            let connect = layout.remote_id_card_rect();
            let share = layout.your_id_card_rect();
            assert!(connect.x + connect.width <= share.x, "{width}x{height}");
            assert!(share.x + share.width <= layout.viewer.x + layout.viewer.width);
            let input = layout.remote_id_input_rect();
            let password = layout.remote_password_status_rect();
            let connect_button = layout.remote_id_connect_btn_rect();
            assert!(input.y + input.height <= password.y);
            assert!(password.y + password.height <= connect_button.y);
            assert!(connect_button.y + connect_button.height < connect.y + connect.height);
        }
    }

    #[test]
    fn v5_password_status_rows_are_visible_without_overlapping_remote_id() {
        for (width, height) in [(1180, 600), (1419, 611), (1920, 1080)] {
            let layout = LockedDashboardLayout::for_window(width, height).unwrap();
            let own = layout.your_id_card_rect();
            let own_status = layout.your_password_status_rect();
            let remote = layout.remote_id_card_rect();
            let remote_status = layout.remote_password_status_rect();
            let connect = layout.remote_id_connect_btn_rect();
            assert!(own_status.y >= own.y);
            assert!(own_status.y + own_status.height <= own.y + own.height);
            if layout.access_cards_wide() {
                assert_eq!(remote.y, own.y);
                assert!(own.x >= remote.x + remote.width);
            } else {
                assert!(remote.y >= own.y + own.height);
            }
            assert!(remote_status.y >= remote.y);
            assert!(remote_status.y + remote_status.height <= remote.y + remote.height);
            assert!(connect.y >= remote_status.y + remote_status.height);
            assert!(
                remote.y + remote.height <= layout.remote_screen.y + layout.remote_screen.height
            );
        }
    }

    #[test]
    fn v5_compact_form_has_nonoverlapping_credential_fields() {
        for (width, height) in [(800, 600), (960, 640), (1180, 600), (1419, 611)] {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            let id = l.remote_id_input_rect();
            let password = l.remote_password_status_rect();
            let connect = l.remote_id_connect_btn_rect();
            assert!(l.compact_height());
            assert!(id.y + id.height + 10 <= password.y);
            assert!(password.y + password.height + 10 <= connect.y);
        }
    }

    #[test]
    fn v5_remote_password_reveal_is_bounded_inside_the_input_field() {
        for (width, height) in [(800, 600), (960, 640), (1419, 611), (1920, 1080)] {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            let field = l.remote_password_status_rect();
            let reveal = l.remote_password_reveal_btn_rect();
            assert!(reveal.x > field.x);
            assert!(reveal.y >= field.y);
            assert!(reveal.x + reveal.width <= field.x + field.width);
            assert!(reveal.y + reveal.height <= field.y + field.height);
        }
    }

    #[test]
    fn v5_password_actions_never_cover_password_text_or_leave_share_card() {
        for (w, h) in [(1180, 600), (1419, 611), (1920, 1080)] {
            let layout = LockedDashboardLayout::for_window(w, h).unwrap();
            let card = layout.your_id_card_rect();
            let label = layout.your_password_status_rect();
            for btn in [
                layout.your_password_reveal_btn_rect(),
                layout.your_password_copy_btn_rect(),
                layout.your_password_rotate_btn_rect(),
            ] {
                assert!(btn.y >= label.y + label.height);
                assert!(btn.x >= card.x);
                assert!(btn.y + btn.height <= card.y + card.height);
                assert!(btn.x + btn.width <= card.x + card.width);
            }
        }
    }

    #[test]
    fn v5_locked_sidebar_has_four_workspace_and_two_protection_items() {
        for (width, height) in [(800, 600), (1419, 611), (1920, 1080)] {
            let layout = LockedDashboardLayout::for_window(width, height).unwrap();
            let fourth = layout.nav_tab_rect(3);
            let protection = layout.nav_tab_rect(4);
            let settings = layout.nav_tab_rect(5);
            assert!(protection.y >= fourth.y + fourth.height + 30);
            assert!(settings.y >= protection.y + protection.height);
            assert!(
                settings.y + settings.height < layout.navigation.y + layout.navigation.height - 69
            );
            for i in 0..9 {
                let tile = layout.trusted_device_tile_rect(i);
                assert!(tile.x >= layout.remote_screen.x);
                assert!(tile.x + tile.width <= layout.remote_screen.x + layout.remote_screen.width);
                assert!(
                    tile.y + tile.height <= layout.remote_screen.y + layout.remote_screen.height
                );
            }
        }
    }

    #[test]
    fn v5_icon_rail_keeps_cards_and_stage_visible_on_small_windows() {
        for (width, height) in [(800, 600), (960, 640)] {
            let layout = LockedDashboardLayout::for_window(width, height).unwrap();
            assert_eq!(layout.navigation.width, 78);
            assert!(layout.viewer.width >= 640);
            assert!(layout.access_cards_wide());
            assert!(layout.remote_stage_rect().height >= 95);
            assert!(layout.remote_stage_rect().x >= layout.viewer.x);
        }
    }

    #[test]
    fn v5_locked_remote_stage_is_visible_on_compact_and_large_windows() {
        for (width, height) in [(1024, 768), (1180, 600), (1419, 611), (1920, 1080)] {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            let stage = l.remote_stage_rect();
            let own = l.your_id_card_rect();
            let connect = l.remote_id_card_rect();
            assert!(
                stage.height >= 95,
                "remote stage hidden at {width}x{height}"
            );
            assert!(stage.y >= own.y + own.height);
            assert!(stage.y >= connect.y + connect.height);
            assert!(stage.y + stage.height <= l.remote_screen.y + l.remote_screen.height);
            assert!(stage.y + stage.height < l.devices.y);
            assert!(l.devices.y + l.devices.height < l.session_toolbar.y);
        }
    }

    #[test]
    fn dual_role_cards_geometry_inside_remote_screen() {
        for (width, height) in [(1180, 600), (1419, 611), (1920, 1080), (2560, 1440)] {
            let l = LockedDashboardLayout::for_window(width, height).unwrap();
            let screen = l.remote_screen;
            let your_id = l.your_id_card_rect();
            let copy_btn = l.your_id_copy_btn_rect();
            let remote_id = l.remote_id_card_rect();
            let input = l.remote_id_input_rect();
            let connect_btn = l.remote_id_connect_btn_rect();

            // Both cards are within remote_screen bounds
            assert!(your_id.x >= screen.x);
            assert!(your_id.y >= screen.y);
            assert!(your_id.x + your_id.width <= screen.x + screen.width);
            assert!(your_id.y + your_id.height <= screen.y + screen.height);

            assert!(remote_id.x >= screen.x);
            assert!(remote_id.y >= screen.y);
            assert!(remote_id.x + remote_id.width <= screen.x + screen.width);
            assert!(remote_id.y + remote_id.height <= screen.y + screen.height);

            // Wider workspaces keep share/connect side by side; compact
            // workspaces retain a collision-free vertical flow.
            if l.access_cards_wide() {
                assert_eq!(remote_id.y, your_id.y);
                assert!(your_id.x >= remote_id.x + remote_id.width);
            } else {
                assert!(remote_id.y >= your_id.y + your_id.height);
            }

            // Copy button is inside Your ID card
            assert!(copy_btn.x >= your_id.x);
            assert!(copy_btn.y >= your_id.y);
            assert!(copy_btn.x + copy_btn.width <= your_id.x + your_id.width);
            assert!(copy_btn.y + copy_btn.height <= your_id.y + your_id.height);

            // Input and Connect button are inside Remote ID card
            assert!(input.x >= remote_id.x);
            assert!(input.y >= remote_id.y);
            assert!(input.x + input.width <= remote_id.x + remote_id.width);
            assert!(input.y + input.height <= remote_id.y + remote_id.height);

            assert!(connect_btn.x >= remote_id.x);
            assert!(connect_btn.y >= remote_id.y);
            assert!(connect_btn.x + connect_btn.width <= remote_id.x + remote_id.width);
            assert!(connect_btn.y + connect_btn.height <= remote_id.y + remote_id.height);

            // The form flows from ID, to password, to connect without
            // overlapping interactive targets.
            let password = l.remote_password_status_rect();
            assert!(password.y >= input.y + input.height);
            assert!(connect_btn.y >= password.y + password.height);
        }
    }
}
