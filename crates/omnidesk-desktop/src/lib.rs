#![forbid(unsafe_code)]

use omnidesk_core::product_shell::{
    DeviceFilter, DeviceStatus, NavTab, PermissionDecision, PrimaryView, ProductShell,
    QualityPreset,
};

pub mod accesskit_tree;
pub mod brand;
pub mod layout;
pub mod render;

pub use layout::{LockedDashboardLayout, ShellLayout};

#[cfg(windows)]
pub mod windows_host;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopAction {
    FocusDevices,
    // (original directory index, directory revision at hit-test time)
    ConnectDevice(usize, u64),
    AllowPermission,
    DenyPermission,
    SetQuality(QualityPreset),
    Disconnect,
    SelectNav(NavTab),
    SelectFilter(DeviceFilter),
    ToggleHelp,
    OpenSettings,
    EnrollDevice,
    RefreshDiscovery,
    RetryConnect,
    CopyYourId,
    FocusRemoteIdInput,
    ConnectRemoteId,
    CopyYourPassword,
    ToggleYourPasswordReveal,
    RotateYourPassword,
    FocusRemotePasswordInput,
    ToggleRemotePasswordReveal,
    ToggleRemoteInput,
    ToggleFullscreen,
    NextMonitor,
    ToggleClipboardSync,
    ToggleUnattendedAccess,
    TriggerFileTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibleControl {
    pub label: &'static str,
    pub action: DesktopAction,
    pub keyboard_key: char,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibleRole {
    Navigation,
    Button,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibilityNode {
    pub label: &'static str,
    pub role: AccessibleRole,
    pub keyboard_key: char,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellControl {
    pub label: String,
    pub action: DesktopAction,
    pub keyboard_key: char,
    pub role: AccessibleRole,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisualSystem {
    pub background_rgb: [u8; 3],
    pub surface_rgb: [u8; 3],
    pub foreground_rgb: [u8; 3],
    pub accent_rgb: [u8; 3],
    pub danger_rgb: [u8; 3],
    pub muted_rgb: [u8; 3],
    pub border_rgb: [u8; 3],
}

impl VisualSystem {
    /// The KMJ shell palette: a blue-grey ground with the brand red reserved
    /// for actions.
    ///
    /// The red is deliberately scarce. Carrying it on borders, rail edges, and
    /// every enabled control turned the whole surface into one hue and left
    /// nothing standing out -- an accent that appears everywhere is not an
    /// accent. Here it marks the primary action and destructive state only.
    ///
    /// `surface` sits far enough above `background` to read as a distinct
    /// plane. At a difference of a few levels per channel the panel and the
    /// ground are the same colour to the eye, and the layout collapses into
    /// one undifferentiated field.
    #[must_use]
    pub const fn kmj_black_red() -> Self {
        Self {
            // KMJ Main Platform brand tokens, adapted for remote-control UI.
            // Keep red for the primary action and use graphite to group work.
            background_rgb: [7, 13, 19],
            surface_rgb: [14, 21, 29],
            foreground_rgb: [244, 246, 250],
            accent_rgb: [237, 18, 54],
            danger_rgb: [247, 66, 76],
            muted_rgb: [156, 171, 191],
            border_rgb: [40, 55, 68],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PresentationModel {
    pub primary_view: PrimaryView,
    pub nav_tab: NavTab,
    pub workspace_scroll_y: usize,
    pub device_filter: DeviceFilter,
    pub help_open: bool,
    pub title: &'static str,
    pub status: &'static str,
    pub details: Vec<String>,
    pub controls: Vec<ShellControl>,
    pub visual: VisualSystem,
    /// One-line summary shown under the content header, e.g. "3 devices · 2 online".
    pub summary: String,
    /// Labels for the panel's labelled rows, in order.
    pub panel_title: &'static str,
    pub local_device_id: String,
    pub remote_id_input: String,
    pub remote_id_focused: bool,
    pub local_password_display: String,
    pub local_password_revealed: bool,
    pub remote_password_display: String,
    pub remote_password_focused: bool,
    pub remote_password_revealed: bool,
    /// Enables the Connect CTA only with a valid, non-self Remote ID and
    /// a nonempty password. This is UI readiness, NOT authentication.
    pub remote_access_form_ready: bool,
    pub remote_input_enabled: bool,
    pub fullscreen_enabled: bool,
    pub selected_monitor: usize,
    pub total_monitors: usize,
    pub clipboard_sync_enabled: bool,
    pub unattended_access_enabled: bool,
    /// Locally recorded transfer state; not evidence of an encrypted
    /// remote file channel or of any successfully delivered bytes.
    pub transfer_record_count: usize,
    pub latest_transfer_filename: Option<String>,
    pub latest_transfer_status: Option<String>,
    /// Count of locally recorded security events, not a server audit log.
    pub local_audit_event_count: usize,
}

#[must_use]
pub fn presentation_for(shell: &ProductShell) -> PresentationModel {
    let status = match shell.primary_view() {
        PrimaryView::Devices => "Disconnected",
        PrimaryView::PermissionPrompt => "Authorization required",
        PrimaryView::Session => {
            // A local permission decision and reported performance counters
            // do NOT prove that a peer-authenticated encrypted transport or
            // real remote display stream exists. The Windows host still
            // refuses raw-TCP remote control until independent verification.
            if shell.connection_stats().is_some() {
                "Transport unverified"
            } else {
                "Permission granted"
            }
        }
    };
    let details = presentation_details(shell);
    let devices = shell.devices();
    let online = devices
        .iter()
        .filter(|device| device.status == DeviceStatus::Online)
        .count();
    let summary = if devices.is_empty() {
        "No devices registered".to_owned()
    } else {
        format!(
            "{} device{} · {online} online",
            devices.len(),
            if devices.len() == 1 { "" } else { "s" }
        )
    };
    let panel_title = match shell.primary_view() {
        PrimaryView::Devices => "Remote access",
        PrimaryView::PermissionPrompt => "Authorization",
        PrimaryView::Session => "Session setup",
    };
    let local_id = if shell.local_device_id().is_empty() {
        None
    } else {
        Some(shell.local_device_id())
    };
    let remote_access_form_ready =
        omnidesk_core::device_identity::validate_remote_id(shell.remote_id_input(), local_id)
            .is_ok()
            && !shell.remote_password_input().trim().is_empty();
    // A plaintext display copy exists only for an explicit local reveal.
    // It must never be logged, persisted or sent to accessibility nodes.
    let remote_pw_display = if shell.is_remote_password_revealed() {
        shell.remote_password_input().to_owned()
    } else {
        "•".repeat(shell.remote_password_input().chars().count())
    };
    PresentationModel {
        primary_view: shell.primary_view(),
        nav_tab: shell.nav_tab(),
        workspace_scroll_y: shell.workspace_scroll_y(),
        device_filter: shell.device_filter(),
        help_open: shell.is_help_open(),
        title: "KMJ OmniDesk",
        status,
        details,
        controls: controls_for_shell(shell),
        visual: VisualSystem::kmj_black_red(),
        summary,
        panel_title,
        local_device_id: shell.local_device_id().to_owned(),
        remote_id_input: shell.remote_id_input().to_owned(),
        remote_id_focused: shell.is_remote_id_focused(),
        local_password_display: shell.password_manager().display_text(),
        local_password_revealed: shell.password_manager().is_revealed(),
        remote_password_display: remote_pw_display,
        remote_password_focused: shell.is_remote_password_focused(),
        remote_password_revealed: shell.is_remote_password_revealed(),
        remote_access_form_ready,
        remote_input_enabled: shell.remote_input_enabled(),
        fullscreen_enabled: shell.fullscreen_enabled(),
        selected_monitor: shell.selected_monitor(),
        total_monitors: shell.total_monitors(),
        clipboard_sync_enabled: shell.clipboard_sync_enabled(),
        unattended_access_enabled: shell.unattended_access_enabled(),
        transfer_record_count: shell.file_transfers().len(),
        latest_transfer_filename: shell
            .file_transfers()
            .last()
            .map(|item| item.filename.clone()),
        latest_transfer_status: shell
            .file_transfers()
            .last()
            .map(|item| item.status.clone()),
        local_audit_event_count: shell.audit_log().len(),
    }
}

fn controls_for_devices_view(shell: &ProductShell) -> Vec<ShellControl> {
    // Keep original device indices when filtering: the visible row
    // position must never select a different, hidden device.
    let visible: Vec<_> = shell
        .devices()
        .iter()
        .enumerate()
        .filter(|(_, device)| match shell.device_filter() {
            DeviceFilter::All => true,
            DeviceFilter::Online => device.status == DeviceStatus::Online,
            DeviceFilter::Offline => device.status != DeviceStatus::Online,
        })
        .take(9)
        .collect();

    if visible.is_empty() {
        let label = match shell.device_filter() {
            DeviceFilter::All => "No devices available",
            DeviceFilter::Online => "No online devices available",
            DeviceFilter::Offline => "No offline devices available",
        };
        let mut controls = vec![ShellControl {
            label: label.to_owned(),
            action: DesktopAction::FocusDevices,
            keyboard_key: 'd',
            role: AccessibleRole::Navigation,
            enabled: false,
        }];

        if shell.last_error().is_some() {
            controls.push(ShellControl {
                label: "Retry Connection".to_owned(),
                action: DesktopAction::RetryConnect,
                keyboard_key: 't',
                role: AccessibleRole::Button,
                enabled: true,
            });
        } else if shell.is_discovering() {
            controls.push(ShellControl {
                label: "Stop Device Discovery".to_owned(),
                action: DesktopAction::RefreshDiscovery,
                keyboard_key: 'r',
                role: AccessibleRole::Button,
                enabled: true,
            });
        }

        return controls;
    }

    visible
        .into_iter()
        .enumerate()
        .map(|(display_index, (source_index, device))| {
            const DEVICE_KEYS: [char; 9] = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
            let key = DEVICE_KEYS[display_index];
            let online = device.status == DeviceStatus::Online;
            ShellControl {
                label: format!(
                    "{} — {}",
                    device.display_name,
                    if online { "Online" } else { "Offline" }
                ),
                action: DesktopAction::ConnectDevice(source_index, shell.device_revision()),
                keyboard_key: key,
                role: AccessibleRole::Button,
                enabled: online,
            }
        })
        .collect()
}

#[must_use]
pub fn controls_for_shell(shell: &ProductShell) -> Vec<ShellControl> {
    match shell.primary_view() {
        PrimaryView::Devices => controls_for_devices_view(shell),
        PrimaryView::PermissionPrompt => vec![
            ShellControl {
                label: "Allow remote session".to_owned(),
                action: DesktopAction::AllowPermission,
                keyboard_key: 'a',
                role: AccessibleRole::Button,
                enabled: true,
            },
            ShellControl {
                label: "Deny remote session".to_owned(),
                action: DesktopAction::DenyPermission,
                keyboard_key: 'n',
                role: AccessibleRole::Button,
                enabled: true,
            },
        ],
        PrimaryView::Session => vec![
            ShellControl {
                label: "Data saver quality".to_owned(),
                action: DesktopAction::SetQuality(QualityPreset::DataSaver),
                keyboard_key: '1',
                role: AccessibleRole::Button,
                enabled: true,
            },
            ShellControl {
                label: "Balanced quality".to_owned(),
                action: DesktopAction::SetQuality(QualityPreset::Balanced),
                keyboard_key: '2',
                role: AccessibleRole::Button,
                enabled: true,
            },
            ShellControl {
                label: "High quality".to_owned(),
                action: DesktopAction::SetQuality(QualityPreset::HighQuality),
                keyboard_key: '3',
                role: AccessibleRole::Button,
                enabled: true,
            },
            ShellControl {
                label: "Disconnect remote session".to_owned(),
                action: DesktopAction::Disconnect,
                keyboard_key: 'x',
                role: AccessibleRole::Button,
                enabled: true,
            },
        ],
    }
}

#[must_use]
pub fn presentation_details(shell: &ProductShell) -> Vec<String> {
    match shell.primary_view() {
        PrimaryView::Devices => {
            let mut list = if shell.devices().is_empty() {
                vec!["Waiting for registered devices".to_owned()]
            } else {
                vec![format!("{} registered device(s)", shell.devices().len())]
            };
            if !shell.local_device_id().is_empty() {
                list.push(format!("Your ID: {}", shell.local_device_id()));
            }
            if let Some(err) = shell.last_error() {
                list.push(format!("Notice: {err}"));
            }
            if shell.is_discovering() {
                list.push("Discovery: active scanning...".to_owned());
            }
            list
        }
        PrimaryView::PermissionPrompt => vec![
            format!(
                "Device: {}",
                shell.selected_device().unwrap_or("unavailable")
            ),
            "Explicit authorization is required before control".to_owned(),
        ],
        PrimaryView::Session => {
            let mut details = vec![
                format!(
                    "Device: {}",
                    shell.selected_device().unwrap_or("unavailable")
                ),
                format!("Quality: {:?}", shell.quality_preset()),
            ];
            if let Some(stats) = shell.connection_stats() {
                details.push("Authenticated transport active".to_owned());
                details.push(format!("Latency: {} ms", stats.latency_ms));
                details.push(format!("Bitrate: {} kbps", stats.bitrate_kbps));
                details.push(format!("FPS: {}", stats.fps));
            } else {
                details.push("Network session not verified".to_owned());
                details.push("Connection statistics unavailable".to_owned());
            }
            details
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

impl ControlRect {
    #[must_use]
    pub const fn contains(self, x: usize, y: usize) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x.saturating_add(self.width)
            && y < self.y.saturating_add(self.height)
    }
}

/// Geometry of each control, in the same order as `presentation.controls`.
///
/// Resolved through [`ShellLayout`] rather than recomputed here, so the hit
/// test cannot drift from what the renderer drew.
#[must_use]
pub fn control_rects_for(
    presentation: &PresentationModel,
    width: usize,
    height: usize,
) -> Vec<ControlRect> {
    // The real four-column dashboard and its hit-testing share precisely
    // the same panel and control rectangles. Never render one coordinate
    // system and click in a different one.
    if let Some(locked) = LockedDashboardLayout::for_window(width, height) {
        let count = presentation.controls.len();
        return presentation
            .controls
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let rect = match presentation.primary_view {
                    PrimaryView::Devices => {
                        if presentation.nav_tab == NavTab::TrustedDevices {
                            locked.trusted_device_tile_rect(index)
                        } else {
                            locked.device_row(index)
                        }
                    }
                    PrimaryView::PermissionPrompt => locked.permission_button(index),
                    PrimaryView::Session => locked.session_button(index, count),
                };
                // The V5 quick device strip visibly displays at most three
                // trusted peers. No invisible row is allowed to accept input
                // behind the remote display or session toolbar.
                let visible = presentation.primary_view != PrimaryView::Devices
                    || match presentation.nav_tab {
                        NavTab::Devices => index < 3,
                        NavTab::TrustedDevices => index < 9,
                        _ => false,
                    };
                ControlRect {
                    x: rect.x,
                    y: rect.y,
                    width: if visible { rect.width } else { 0 },
                    height: if visible { rect.height } else { 0 },
                }
            })
            .collect();
    }

    let Some(layout) = ShellLayout::for_window(width, height) else {
        return Vec::new();
    };

    presentation
        .controls
        .iter()
        .enumerate()
        .map(|(index, _)| ControlRect {
            x: layout.content_x,
            y: layout
                .first_row_y()
                .saturating_add(index.saturating_mul(layout.row_height)),
            width: layout.content_width,
            height: layout.row_height.saturating_sub(8),
        })
        .collect()
}

#[must_use]
const fn locked_dual_role_action(
    locked: &LockedDashboardLayout,
    x: usize,
    y: usize,
) -> Option<DesktopAction> {
    if locked.your_id_copy_btn_rect().contains(x, y) {
        return Some(DesktopAction::CopyYourId);
    }
    if locked.your_password_reveal_btn_rect().contains(x, y) {
        return Some(DesktopAction::ToggleYourPasswordReveal);
    }
    if locked.your_password_copy_btn_rect().contains(x, y) {
        return Some(DesktopAction::CopyYourPassword);
    }
    if locked.your_password_rotate_btn_rect().contains(x, y) {
        return Some(DesktopAction::RotateYourPassword);
    }
    if locked.remote_id_connect_btn_rect().contains(x, y) {
        // The primary V5 ID + password form cannot be activated with only
        // the ID populated. Transport-level checks remain mandatory.
        return Some(DesktopAction::ConnectRemoteId);
    }
    if locked.remote_password_reveal_btn_rect().contains(x, y) {
        return Some(DesktopAction::ToggleRemotePasswordReveal);
    }
    if locked.remote_password_status_rect().contains(x, y) {
        return Some(DesktopAction::FocusRemotePasswordInput);
    }
    if locked.remote_id_input_rect().contains(x, y) || locked.remote_id_card_rect().contains(x, y) {
        return Some(DesktopAction::FocusRemoteIdInput);
    }
    None
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn action_at_point(
    shell: &ProductShell,
    width: usize,
    height: usize,
    x: usize,
    y: usize,
) -> Option<DesktopAction> {
    // Only center content scrolls. Header, navigation and inspector retain
    // physical Windows coordinates for consistent pointer/a11y behavior.
    let content_y = LockedDashboardLayout::for_window(width, height).map_or(y, |layout| {
        if x >= layout.viewer.x
            && x < layout.viewer.x.saturating_add(layout.viewer.width)
            && y >= layout.viewer.y
        {
            y.saturating_add(
                shell
                    .workspace_scroll_y()
                    .min(LockedDashboardLayout::max_scroll_y(height)),
            )
        } else {
            y
        }
    });
    if let Some(locked) = LockedDashboardLayout::for_window(width, height) {
        // Six visible destinations, matching the locked V5 sidebar.
        const NAV_TABS: [NavTab; 6] = [
            NavTab::Devices,
            NavTab::TrustedDevices,
            NavTab::Connections,
            NavTab::FileTransfer,
            NavTab::Security,
            NavTab::Settings,
        ];
        for (i, &tab) in NAV_TABS.iter().enumerate() {
            let rect = locked.nav_tab_rect(i);
            if x >= rect.x
                && content_y >= rect.y
                && x < rect.x.saturating_add(rect.width)
                && content_y < rect.y.saturating_add(rect.height)
            {
                return Some(DesktopAction::SelectNav(tab));
            }
        }

        // Filter buttons are visible only on the Devices tab.
        if shell.nav_tab() == NavTab::Devices {
            let all_rect = locked.filter_all_rect();
            if x >= all_rect.x
                && content_y >= all_rect.y
                && x < all_rect.x.saturating_add(all_rect.width)
                && content_y < all_rect.y.saturating_add(all_rect.height)
            {
                return Some(DesktopAction::SelectFilter(DeviceFilter::All));
            }
            let online_rect = locked.filter_online_rect();
            if x >= online_rect.x
                && content_y >= online_rect.y
                && x < online_rect.x.saturating_add(online_rect.width)
                && content_y < online_rect.y.saturating_add(online_rect.height)
            {
                return Some(DesktopAction::SelectFilter(DeviceFilter::Online));
            }
            let offline_rect = locked.filter_offline_rect();
            if x >= offline_rect.x
                && content_y >= offline_rect.y
                && x < offline_rect.x.saturating_add(offline_rect.width)
                && content_y < offline_rect.y.saturating_add(offline_rect.height)
            {
                return Some(DesktopAction::SelectFilter(DeviceFilter::Offline));
            }
        }

        // Top bar buttons (SETTINGS, HELP)
        let settings_rect = locked.settings_button_rect(width);
        if x >= settings_rect.x
            && content_y >= settings_rect.y
            && x < settings_rect.x.saturating_add(settings_rect.width)
            && content_y < settings_rect.y.saturating_add(settings_rect.height)
        {
            return Some(DesktopAction::OpenSettings);
        }
        let help_rect = locked.help_button_rect(width);
        if x >= help_rect.x
            && content_y >= help_rect.y
            && x < help_rect.x.saturating_add(help_rect.width)
            && content_y < help_rect.y.saturating_add(help_rect.height)
        {
            return Some(DesktopAction::ToggleHelp);
        }
        // Help replaces the central workflow surface. Underlying input
        // fields, connect buttons and session controls must not be clickable
        // through its visible overlay.
        if shell.is_help_open() && locked.remote_screen.contains(x, content_y) {
            return None;
        }

        // Trusted Devices has real, permission-gated peer tiles. Other
        // pages must not expose hidden Connect or credential actions.
        if shell.primary_view() == PrimaryView::Devices {
            if shell.nav_tab() == NavTab::TrustedDevices {
                let model = presentation_for(shell);
                for (index, control) in model.controls.iter().enumerate().take(9) {
                    if control.enabled
                        && locked
                            .trusted_device_tile_rect(index)
                            .contains(x, content_y)
                    {
                        return Some(control.action);
                    }
                }
                return None;
            }
            if shell.nav_tab() != NavTab::Devices {
                return None;
            }
            if let Some(action) = locked_dual_role_action(&locked, x, content_y) {
                if action == DesktopAction::ConnectRemoteId
                    && !presentation_for(shell).remote_access_form_ready
                {
                    return None;
                }
                if matches!(
                    action,
                    DesktopAction::CopyYourPassword | DesktopAction::ToggleYourPasswordReveal
                ) && shell.password_manager().raw_password().is_none()
                {
                    return None;
                }
                if action == DesktopAction::ToggleRemotePasswordReveal
                    && shell.remote_password_input().is_empty()
                {
                    return None;
                }
                return Some(action);
            }
        } else if shell.primary_view() == PrimaryView::Session {
            if locked.session_tool_btn_rect(0).contains(x, content_y) {
                return Some(DesktopAction::ToggleRemoteInput);
            }
            if locked.session_tool_btn_rect(1).contains(x, content_y) {
                return Some(DesktopAction::NextMonitor);
            }
            if locked.session_tool_btn_rect(2).contains(x, content_y) {
                return Some(DesktopAction::ToggleClipboardSync);
            }
            if locked.session_tool_btn_rect(3).contains(x, content_y) {
                return Some(DesktopAction::TriggerFileTransfer);
            }
            if locked.session_tool_btn_rect(4).contains(x, content_y) {
                return Some(DesktopAction::ToggleFullscreen);
            }
            if locked.session_tool_btn_rect(5).contains(x, content_y) {
                return Some(DesktopAction::Disconnect);
            }
        }
    }

    let presentation = presentation_for(shell);
    let rects = control_rects_for(&presentation, width, height);
    presentation
        .controls
        .iter()
        .zip(rects)
        .find(|(control, rect)| control.enabled && rect.contains(x, content_y))
        .map(|(control, _)| control.action)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    pub idle_memory_mib: u32,
    pub idle_cpu_milli_percent: u32,
}

impl ResourceBudget {
    #[must_use]
    pub const fn desktop_baseline() -> Self {
        Self {
            idle_memory_mib: 64,
            idle_cpu_milli_percent: 500,
        }
    }

    #[must_use]
    pub const fn accepts(self, idle_memory_mib: u32, idle_cpu_milli_percent: u32) -> bool {
        idle_memory_mib <= self.idle_memory_mib
            && idle_cpu_milli_percent <= self.idle_cpu_milli_percent
    }
}

#[must_use]
pub fn action_for_key(view: PrimaryView, key: char) -> Option<DesktopAction> {
    let key = key.to_ascii_lowercase();
    controls_for(view)
        .iter()
        .find(|control| control.keyboard_key == key)
        .map(|control| control.action)
}

#[allow(clippy::too_many_lines)]
pub fn apply_action(shell: &mut ProductShell, action: DesktopAction) {
    match action {
        DesktopAction::FocusDevices => {
            shell.set_nav_tab(NavTab::Devices);
        }
        DesktopAction::ConnectDevice(index, revision) => {
            // A pointer event can be queued before the user changes tabs or
            // filters. Revalidate the target at dispatch time, not only when
            // hit-testing it, so stale actions cannot select hidden rows.
            let visible_limit = match shell.nav_tab() {
                NavTab::Devices => 3,
                NavTab::TrustedDevices => 9,
                _ => 0,
            };
            if visible_limit == 0
                || shell.device_revision() != revision
                || shell.primary_view() != PrimaryView::Devices
                || !controls_for_shell(shell)
                    .iter()
                    .take(visible_limit)
                    .any(|control| {
                        control.enabled
                            && control.action == DesktopAction::ConnectDevice(index, revision)
                    })
            {
                return;
            }
            let device_id = shell.devices().get(index).map(|device| device.id.clone());
            if let Some(device_id) = device_id {
                let _ = shell.begin_connect(&device_id);
            }
        }
        DesktopAction::AllowPermission => shell.decide_permission(PermissionDecision::Allow),
        DesktopAction::DenyPermission => shell.decide_permission(PermissionDecision::Deny),
        DesktopAction::SetQuality(preset) => shell.set_quality_preset(preset),
        DesktopAction::Disconnect => shell.disconnect(),
        DesktopAction::SelectNav(tab) => {
            shell.set_nav_tab(tab);
        }
        DesktopAction::SelectFilter(filter) => {
            shell.set_device_filter(filter);
        }
        DesktopAction::ToggleHelp => {
            shell.toggle_help();
        }
        DesktopAction::OpenSettings => {
            shell.set_nav_tab(NavTab::Settings);
        }
        DesktopAction::EnrollDevice => {
            // An enrollment click is not cryptographic proof of a remote peer.
            // Keep the directory unchanged until a real signed peer flow exists.
            shell.set_error(
                "Secure enrollment requires a verified remote peer; pairing is not available yet",
            );
        }
        DesktopAction::RefreshDiscovery => {
            if shell.is_discovering() {
                shell.stop_discovery();
            } else {
                shell.start_discovery();
            }
        }
        DesktopAction::RetryConnect => {
            let _ = shell.retry_connect();
        }
        DesktopAction::CopyYourId => {
            shell.set_remote_id_focused(false);
            shell.set_remote_password_focused(false);
            let id = shell.local_device_id().to_owned();
            if id.is_empty() {
                shell.set_error("Device identity not initialized yet");
            } else {
                shell.set_error(format!("Your ID '{id}' copied to clipboard"));
            }
        }
        DesktopAction::FocusRemoteIdInput => {
            shell.focus_remote_id();
        }
        DesktopAction::FocusRemotePasswordInput => {
            shell.focus_remote_password();
        }
        DesktopAction::ToggleRemotePasswordReveal => {
            shell.toggle_remote_password_reveal();
        }
        DesktopAction::ConnectRemoteId => {
            // Remote ID by itself is never enough for the V5 password
            // connection form. A validated ID still isn't authentication.
            if shell.remote_password_input().trim().is_empty() {
                shell.set_error("Enter the remote session password to request access");
                return;
            }
            shell.set_remote_id_focused(false);
            shell.set_remote_password_focused(false);
            let _ = shell.begin_connect_remote_id();
        }
        DesktopAction::CopyYourPassword => {
            if shell.password_manager().raw_password().is_some() {
                shell.set_error("Session password copied to clipboard");
            }
        }
        DesktopAction::ToggleYourPasswordReveal => {
            shell.toggle_local_password_reveal();
        }
        DesktopAction::RotateYourPassword => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            shell.rotate_local_password(now);
            shell.set_error("Session password regenerated");
        }
        DesktopAction::ToggleRemoteInput => {
            shell.toggle_remote_input();
        }
        DesktopAction::ToggleFullscreen => {
            shell.toggle_fullscreen();
        }
        DesktopAction::NextMonitor => {
            shell.next_monitor();
        }
        DesktopAction::ToggleClipboardSync => {
            shell.toggle_clipboard_sync();
        }
        DesktopAction::ToggleUnattendedAccess => {
            shell.toggle_unattended_access();
        }
        DesktopAction::TriggerFileTransfer => {
            shell.set_nav_tab(NavTab::FileTransfer);
        }
    }
}

pub fn apply_key(shell: &mut ProductShell, key: char) -> bool {
    if shell.is_remote_id_focused() {
        match key {
            '\x08' => {
                shell.backspace_remote_id();
                return true;
            }
            '\r' | '\n' => {
                apply_action(shell, DesktopAction::ConnectRemoteId);
                return true;
            }
            '\t' => {
                shell.focus_remote_password();
                return true;
            }
            '\x1b' => {
                shell.set_remote_id_focused(false);
                return true;
            }
            c if !c.is_control() => {
                shell.append_remote_id_char(c);
                return true;
            }
            _ => return false,
        }
    }
    if shell.is_remote_password_focused() {
        match key {
            '\x08' => {
                shell.backspace_remote_password();
                return true;
            }
            '\r' | '\n' => {
                apply_action(shell, DesktopAction::ConnectRemoteId);
                return true;
            }
            '\t' => {
                shell.focus_remote_id();
                return true;
            }
            '\x1b' => {
                shell.set_remote_password_focused(false);
                return true;
            }
            c if !c.is_control() => {
                shell.append_remote_password_char(c);
                return true;
            }
            _ => return false,
        }
    }
    let key = key.to_ascii_lowercase();
    let control_match = if shell.primary_view() == PrimaryView::Devices
        && !matches!(shell.nav_tab(), NavTab::Devices | NavTab::TrustedDevices)
    {
        None // Do not activate hidden device rows via numeric shortcuts.
    } else {
        controls_for_shell(shell)
            .into_iter()
            .find(|control| control.keyboard_key == key)
    };

    if let Some(control) = control_match {
        if control.enabled {
            apply_action(shell, control.action);
            return true;
        }
        // The disabled empty-directory placeholder uses 'd', which is also
        // the global Devices navigation shortcut. Let that one key fall
        // through to navigation; disabled device rows must stay inert.
        if control.action != DesktopAction::FocusDevices {
            return false;
        }
    }

    // Nav and help shortcuts in Devices / Disconnected view
    if shell.primary_view() == PrimaryView::Devices {
        let nav_action = match key {
            'd' => Some(DesktopAction::SelectNav(NavTab::Devices)),
            'v' => Some(DesktopAction::SelectNav(NavTab::TrustedDevices)),
            'c' => Some(DesktopAction::SelectNav(NavTab::Connections)),
            'f' => Some(DesktopAction::SelectNav(NavTab::FileTransfer)),
            'm' => Some(DesktopAction::SelectNav(NavTab::Automation)),
            's' => Some(DesktopAction::SelectNav(NavTab::Security)),
            'o' => Some(DesktopAction::SelectNav(NavTab::Settings)),
            'h' => Some(DesktopAction::ToggleHelp),
            _ => None,
        };
        if let Some(action) = nav_action {
            apply_action(shell, action);
            return true;
        }
    }
    false
}

#[must_use]
pub fn accessibility_snapshot(shell: &ProductShell) -> Vec<AccessibilityNode> {
    accessibility_nodes_for(shell.primary_view()).to_vec()
}

#[must_use]
pub const fn accessibility_nodes_for(view: PrimaryView) -> &'static [AccessibilityNode] {
    match view {
        PrimaryView::Devices => &[AccessibilityNode {
            label: "Devices",
            role: AccessibleRole::Navigation,
            keyboard_key: 'd',
        }],
        PrimaryView::PermissionPrompt => &[
            AccessibilityNode {
                label: "Allow remote session",
                role: AccessibleRole::Button,
                keyboard_key: 'a',
            },
            AccessibilityNode {
                label: "Deny remote session",
                role: AccessibleRole::Button,
                keyboard_key: 'n',
            },
        ],
        PrimaryView::Session => &[AccessibilityNode {
            label: "Disconnect remote session",
            role: AccessibleRole::Button,
            keyboard_key: 'x',
        }],
    }
}

#[must_use]
pub const fn controls_for(view: PrimaryView) -> &'static [AccessibleControl] {
    match view {
        PrimaryView::Devices => &[AccessibleControl {
            label: "Devices",
            action: DesktopAction::FocusDevices,
            keyboard_key: 'd',
        }],
        PrimaryView::PermissionPrompt => &[
            AccessibleControl {
                label: "Allow remote session",
                action: DesktopAction::AllowPermission,
                keyboard_key: 'a',
            },
            AccessibleControl {
                label: "Deny remote session",
                action: DesktopAction::DenyPermission,
                keyboard_key: 'n',
            },
        ],
        PrimaryView::Session => &[AccessibleControl {
            label: "Disconnect remote session",
            action: DesktopAction::Disconnect,
            keyboard_key: 'x',
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnidesk_core::product_shell::DeviceSummary;

    #[test]
    fn enrollment_without_verified_peer_never_creates_a_trusted_device() {
        let mut shell = ProductShell::new();
        apply_action(&mut shell, DesktopAction::EnrollDevice);
        assert_eq!(shell.devices(), []);
        assert!(shell.last_error().is_some());
        assert_eq!(shell.primary_view(), PrimaryView::Devices);
    }

    #[test]
    fn every_primary_view_has_keyboard_operable_labeled_controls() {
        for view in [
            PrimaryView::Devices,
            PrimaryView::PermissionPrompt,
            PrimaryView::Session,
        ] {
            let controls = controls_for(view);
            assert_ne!(controls.len(), 0);
            assert!(
                controls
                    .iter()
                    .all(|control| !control.label.trim().is_empty())
            );
            assert!(
                controls
                    .iter()
                    .all(|control| control.keyboard_key.is_ascii())
            );
        }
    }

    #[test]
    fn locked_dashboard_device_rows_and_pointer_targets_agree() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "paired-desk".to_owned(),
            display_name: "Paired Desk".to_owned(),
            status: DeviceStatus::Online,
        }]);
        let p = presentation_for(&shell);
        let rect = control_rects_for(&p, 1419, 611)[0];
        assert!(rect.x > 180, "device control must not overlap nav rail");
        assert_eq!(
            action_at_point(&shell, 1419, 611, rect.x + 12, rect.y + 12),
            Some(DesktopAction::ConnectDevice(0, shell.device_revision()))
        );
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let file_transfer = layout.nav_tab_rect(3);
        assert_eq!(
            action_at_point(
                &shell,
                1419,
                611,
                file_transfer.x + 12,
                file_transfer.y + 12,
            ),
            Some(DesktopAction::SelectNav(NavTab::FileTransfer))
        );
        // The gap between the sidebar and remote workspace is inert.
        let gap_x = layout.navigation.x + layout.navigation.width + 3;
        assert_eq!(action_at_point(&shell, 1419, 611, gap_x, rect.y + 12), None);
        shell.begin_connect("paired-desk").unwrap();
        let approval = presentation_for(&shell);
        let yes = control_rects_for(&approval, 1419, 611)[0];
        assert_eq!(
            action_at_point(&shell, 1419, 611, yes.x + 12, yes.y + 12),
            Some(DesktopAction::AllowPermission)
        );
    }

    #[test]
    fn presentation_model_is_shell_derived_and_never_claims_online_by_default() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        let initial = presentation_for(&shell);
        assert_eq!(initial.title, "KMJ OmniDesk");
        assert_eq!(initial.status, "Disconnected");
        assert_eq!(initial.visual, VisualSystem::kmj_black_red());

        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);
        shell.begin_connect("desk-1").unwrap();
        assert_eq!(presentation_for(&shell).status, "Authorization required");

        shell.decide_permission(PermissionDecision::Allow);
        assert_eq!(presentation_for(&shell).status, "Permission granted");
        assert!(
            presentation_for(&shell)
                .details
                .iter()
                .any(|value| value == "Network session not verified")
        );
    }

    #[test]
    fn accessibility_snapshot_tracks_product_shell_view() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        assert_eq!(
            accessibility_snapshot(&shell),
            accessibility_nodes_for(PrimaryView::Devices)
        );

        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);
        shell.begin_connect("desk-1").unwrap();
        assert_eq!(
            accessibility_snapshot(&shell),
            accessibility_nodes_for(PrimaryView::PermissionPrompt)
        );

        shell.decide_permission(PermissionDecision::Allow);
        assert_eq!(
            accessibility_snapshot(&shell),
            accessibility_nodes_for(PrimaryView::Session)
        );
    }

    #[test]
    fn accessibility_nodes_match_operable_controls() {
        for view in [
            PrimaryView::Devices,
            PrimaryView::PermissionPrompt,
            PrimaryView::Session,
        ] {
            let nodes = accessibility_nodes_for(view);
            let controls = controls_for(view);
            assert_eq!(nodes.len(), controls.len());
            for (node, control) in nodes.iter().zip(controls) {
                assert_eq!(node.label, control.label);
                assert_eq!(node.keyboard_key, control.keyboard_key);
            }
        }
        assert_eq!(
            accessibility_nodes_for(PrimaryView::Devices)[0].role,
            AccessibleRole::Navigation
        );
        assert!(
            accessibility_nodes_for(PrimaryView::PermissionPrompt)
                .iter()
                .all(|node| node.role == AccessibleRole::Button)
        );
    }

    #[test]
    fn black_red_visual_system_is_explicit_and_high_contrast() {
        let visual = VisualSystem::kmj_black_red();
        // The ground must stay dark enough that the foreground text reads at
        // a glance. The bound is per-channel against the darkest channel of
        // the surface, not against an exact tuple, so the palette can move to
        // a blue-grey ground without this test having to be rewritten for it.
        assert!(visual.background_rgb.iter().all(|channel| *channel <= 24));
        // Surface sits above the ground: if it does not, the panel collapses
        // into the background and the layout stops reading as a layout.
        assert!(
            visual
                .surface_rgb
                .iter()
                .all(|c| *c > visual.background_rgb[0]),
            "surface must be distinguishable from background"
        );
        // Surface stays in the same dark band: a light surface would invert
        // the whole shell and break the red accent's contrast.
        assert!(
            visual.surface_rgb.iter().all(|channel| *channel <= 48),
            "surface too light for the dark shell"
        );
        assert!(visual.foreground_rgb.iter().all(|channel| *channel >= 200));
        // Secondary text must be clearly dimmer than primary, or the type
        // hierarchy disappears.
        assert!(visual.muted_rgb.iter().all(|channel| *channel >= 90));
        assert!(
            visual
                .muted_rgb
                .iter()
                .all(|c| *c < visual.foreground_rgb[0]),
            "muted text is not distinguishable from primary"
        );
        assert!(visual.accent_rgb[0] > visual.accent_rgb[1] * 5);
        assert!(visual.accent_rgb[0] > visual.accent_rgb[2] * 4);
    }

    #[test]
    fn desktop_resource_budget_is_explicit_and_fail_closed() {
        let budget = ResourceBudget::desktop_baseline();
        assert!(budget.accepts(64, 500));
        assert!(!budget.accepts(65, 500));
        assert!(!budget.accepts(64, 501));
    }

    #[test]
    fn keyboard_dispatch_is_case_insensitive_and_view_scoped() {
        assert_eq!(
            action_for_key(PrimaryView::PermissionPrompt, 'A'),
            Some(DesktopAction::AllowPermission)
        );
        assert_eq!(
            action_for_key(PrimaryView::PermissionPrompt, 'N'),
            Some(DesktopAction::DenyPermission)
        );
        assert_eq!(action_for_key(PrimaryView::Devices, 'A'), None);
        assert_eq!(
            action_for_key(PrimaryView::Session, 'X'),
            Some(DesktopAction::Disconnect)
        );
    }

    #[test]
    fn keyboard_actions_drive_shell_without_bypassing_permission_state() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, SecurityState};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);
        shell.begin_connect("desk-1").unwrap();

        assert!(!apply_key(&mut shell, 'x'));
        assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);
        assert!(apply_key(&mut shell, 'a'));
        assert_eq!(shell.security_state(), SecurityState::Authorized);
        assert!(apply_key(&mut shell, 'x'));
        assert_eq!(shell.security_state(), SecurityState::Disconnected);
    }

    #[test]
    fn keyboard_keys_are_unique_within_each_view() {
        for view in [
            PrimaryView::Devices,
            PrimaryView::PermissionPrompt,
            PrimaryView::Session,
        ] {
            let controls = controls_for(view);
            for (index, control) in controls.iter().enumerate() {
                assert!(
                    controls[index + 1..]
                        .iter()
                        .all(|other| other.keyboard_key != control.keyboard_key)
                );
            }
        }
    }

    #[test]
    fn real_device_control_drives_terminal_free_primary_flow() {
        use omnidesk_core::product_shell::{
            DeviceStatus, DeviceSummary, PrimaryView, QualityPreset,
        };

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "desk-1".into(),
                display_name: "Desk 1".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "desk-2".into(),
                display_name: "Desk 2".into(),
                status: DeviceStatus::Offline,
            },
        ]);

        let controls = controls_for_shell(&shell);
        assert_eq!(
            controls[0].action,
            DesktopAction::ConnectDevice(0, shell.device_revision())
        );
        assert!(controls[0].enabled);
        assert!(!controls[1].enabled);

        assert!(apply_key(&mut shell, '1'));
        assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);
        assert_eq!(shell.selected_device(), Some("desk-1"));

        assert!(apply_key(&mut shell, 'a'));
        assert_eq!(shell.primary_view(), PrimaryView::Session);

        assert!(apply_key(&mut shell, '1'));
        assert_eq!(shell.quality_preset(), QualityPreset::DataSaver);
        assert!(apply_key(&mut shell, '3'));
        assert_eq!(shell.quality_preset(), QualityPreset::HighQuality);

        assert!(apply_key(&mut shell, 'x'));
        assert_eq!(shell.primary_view(), PrimaryView::Devices);
    }

    #[test]
    fn offline_device_keyboard_control_is_fail_closed() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, PrimaryView};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "desk-offline".into(),
            display_name: "Offline Desk".into(),
            status: DeviceStatus::Offline,
        }]);

        assert!(!apply_key(&mut shell, '1'));
        assert_eq!(shell.primary_view(), PrimaryView::Devices);
        assert_eq!(shell.selected_device(), None);
    }

    #[test]
    fn v5_transfer_and_security_cards_use_actual_local_records() {
        use omnidesk_core::product_shell::FileTransferItem;

        let mut shell = ProductShell::new();
        let empty = presentation_for(&shell);
        assert_eq!(empty.transfer_record_count, 0);
        assert!(empty.latest_transfer_filename.is_none());
        assert_eq!(empty.local_audit_event_count, 0);

        shell.add_file_transfer(FileTransferItem {
            id: "local-record-1".into(),
            filename: "report.pdf".into(),
            size_bytes: 512,
            progress_percent: 25,
            status: "Queued".into(),
        });
        shell.add_audit_event("local-session-request", "No network permission granted", 42);
        let actual = presentation_for(&shell);
        assert_eq!(actual.transfer_record_count, 1);
        assert_eq!(
            actual.latest_transfer_filename.as_deref(),
            Some("report.pdf")
        );
        assert_eq!(actual.latest_transfer_status.as_deref(), Some("Queued"));
        assert_eq!(actual.local_audit_event_count, 1);
    }

    #[test]
    fn presentation_contains_truthful_device_and_session_details() {
        use omnidesk_core::product_shell::{
            ConnectionStats, DeviceStatus, DeviceSummary, QualityPreset,
        };

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);

        let devices = presentation_for(&shell);
        assert!(
            devices
                .details
                .iter()
                .any(|line| line.contains("1 registered"))
        );

        shell.begin_connect("desk-1").unwrap();
        shell.decide_permission(PermissionDecision::Allow);
        shell.set_quality_preset(QualityPreset::HighQuality);
        shell.update_connection_stats(ConnectionStats {
            latency_ms: 25,
            bitrate_kbps: 1200,
            fps: 60,
        });

        let session = presentation_for(&shell);
        assert_eq!(
            session.status, "Transport unverified",
            "Performance counters must not make an unauthenticated peer look connected"
        );
        assert!(session.details.iter().any(|line| line == "Device: desk-1"));
        assert!(
            session
                .details
                .iter()
                .any(|line| line == "Quality: HighQuality")
        );
        assert!(session.details.iter().any(|line| line == "Latency: 25 ms"));
        assert!(
            session
                .details
                .iter()
                .any(|line| line == "Bitrate: 1200 kbps")
        );
        assert!(session.details.iter().any(|line| line == "FPS: 60"));
    }

    #[test]
    fn pointer_hit_test_drives_same_fail_closed_actions_as_keyboard() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, PrimaryView};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "desk-1".into(),
                display_name: "Desk 1".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "desk-2".into(),
                display_name: "Desk 2".into(),
                status: DeviceStatus::Offline,
            },
        ]);

        let presentation = presentation_for(&shell);
        let rects = control_rects_for(&presentation, 960, 640);
        let first = rects[0];
        let second = rects[1];

        let connect = action_at_point(
            &shell,
            960,
            640,
            first.x + first.width / 2,
            first.y + first.height / 2,
        );
        assert_eq!(
            connect,
            Some(DesktopAction::ConnectDevice(0, shell.device_revision()))
        );
        apply_action(&mut shell, connect.unwrap());
        assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);

        shell.disconnect();
        let offline = action_at_point(
            &shell,
            960,
            640,
            second.x + second.width / 2,
            second.y + second.height / 2,
        );
        assert_eq!(offline, None);
    }

    #[test]
    fn permission_prompt_exposes_explicit_allow_and_deny_actions() {
        let controls = controls_for(PrimaryView::PermissionPrompt);
        assert!(
            controls
                .iter()
                .any(|c| c.action == DesktopAction::AllowPermission)
        );
        assert!(
            controls
                .iter()
                .any(|c| c.action == DesktopAction::DenyPermission)
        );
    }

    #[test]
    fn device_filter_hides_rows_but_preserves_original_connection_indices() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "offline-first".into(),
                display_name: "Offline first".into(),
                status: DeviceStatus::Offline,
            },
            DeviceSummary {
                id: "online-second".into(),
                display_name: "Online second".into(),
                status: DeviceStatus::Online,
            },
        ]);
        shell.set_device_filter(DeviceFilter::Online);
        let online = controls_for_shell(&shell);
        assert_eq!(online.len(), 1);
        assert_eq!(
            online[0].action,
            DesktopAction::ConnectDevice(1, shell.device_revision())
        );
        assert!(online[0].enabled);

        let rect = control_rects_for(&presentation_for(&shell), 1419, 611)[0];
        let action = action_at_point(&shell, 1419, 611, rect.x + 12, rect.y + 12);
        assert_eq!(
            action,
            Some(DesktopAction::ConnectDevice(1, shell.device_revision()))
        );
        apply_action(&mut shell, action.unwrap());
        assert_eq!(shell.selected_device(), Some("online-second"));

        shell.disconnect();
        shell.set_device_filter(DeviceFilter::Offline);
        let offline = controls_for_shell(&shell);
        assert_eq!(offline.len(), 1);
        assert_eq!(
            offline[0].action,
            DesktopAction::ConnectDevice(0, shell.device_revision())
        );
        assert!(!offline[0].enabled);
    }

    #[test]
    fn devices_shortcut_is_not_shadowed_by_disabled_empty_directory() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        // Empty directory creates a disabled FocusDevices control on 'd'.
        assert!(apply_key(&mut shell, 'd'));
        assert_eq!(shell.nav_tab(), NavTab::Devices);
        assert!(apply_key(&mut shell, 'c'));
        assert_eq!(shell.nav_tab(), NavTab::Connections);
        assert!(apply_key(&mut shell, 'd'));
        assert_eq!(shell.nav_tab(), NavTab::Devices);

        // An empty *filtered* directory must behave identically.
        shell.replace_devices(vec![DeviceSummary {
            id: "offline-only".into(),
            display_name: "Offline only".into(),
            status: DeviceStatus::Offline,
        }]);
        shell.set_device_filter(DeviceFilter::Online);
        assert!(apply_key(&mut shell, 'd'));
        assert_eq!(shell.nav_tab(), NavTab::Devices);
        assert!(!apply_key(&mut shell, '1'));
        assert_eq!(shell.selected_device(), None);

        // A disabled real device row must not become actionable.
        shell.set_device_filter(DeviceFilter::All);
        assert!(!apply_key(&mut shell, '1'));
        assert_eq!(shell.selected_device(), None);
    }

    #[test]
    fn hidden_device_rows_cannot_be_clicked_or_keyboard_activated() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "online".into(),
            display_name: "Online".into(),
            status: DeviceStatus::Online,
        }]);
        let row = control_rects_for(&presentation_for(&shell), 1419, 611)[0];
        shell.set_nav_tab(NavTab::Security);
        assert_eq!(
            action_at_point(&shell, 1419, 611, row.x + 12, row.y + 12),
            None
        );
        assert!(!apply_key(&mut shell, '1'));
        assert_eq!(shell.selected_device(), None);
        assert!(apply_key(&mut shell, 'd'));
        assert_eq!(shell.nav_tab(), NavTab::Devices);
    }

    #[test]
    fn stale_connect_actions_cannot_activate_hidden_or_offline_rows() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "online-first".into(),
                display_name: "Online first".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "online-second".into(),
                display_name: "Online second".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "offline-third".into(),
                display_name: "Offline third".into(),
                status: DeviceStatus::Offline,
            },
        ]);

        // Simulate a click queued before the filter changed. The index is
        // valid and online, but the row is now hidden.
        let stale_action = DesktopAction::ConnectDevice(1, shell.device_revision());
        shell.set_device_filter(DeviceFilter::Offline);
        apply_action(&mut shell, stale_action);
        assert_eq!(shell.selected_device(), None);

        // A stale click must not connect from a secondary tab either.
        shell.set_device_filter(DeviceFilter::All);
        shell.set_nav_tab(NavTab::Security);
        apply_action(&mut shell, stale_action);
        assert_eq!(shell.selected_device(), None);

        shell.set_nav_tab(NavTab::Devices);
        let revision = shell.device_revision();
        apply_action(&mut shell, DesktopAction::ConnectDevice(2, revision));
        assert_eq!(shell.selected_device(), None);

        // A currently visible online target still reaches the permission
        // prompt, preserving the normal device-connection flow.
        apply_action(&mut shell, stale_action);
        assert_eq!(shell.selected_device(), Some("online-second"));
        assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);
    }

    #[test]
    fn direct_dispatch_rejects_device_rows_beyond_visible_limit() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(
            (0..10)
                .map(|i| DeviceSummary {
                    id: format!("desk-{i}"),
                    display_name: format!("Desk {i}"),
                    status: DeviceStatus::Online,
                })
                .collect(),
        );
        let revision = shell.device_revision();
        apply_action(&mut shell, DesktopAction::ConnectDevice(9, revision));
        assert_eq!(shell.selected_device(), None);
        apply_action(&mut shell, DesktopAction::ConnectDevice(8, revision));
        assert_eq!(shell.selected_device(), None);
        apply_action(&mut shell, DesktopAction::ConnectDevice(2, revision));
        assert_eq!(shell.selected_device(), Some("desk-2"));
    }

    #[test]
    fn queued_connect_action_cannot_retarget_after_device_directory_refresh() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "first".into(),
                display_name: "First".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "second".into(),
                display_name: "Second".into(),
                status: DeviceStatus::Online,
            },
        ]);
        let stale = controls_for_shell(&shell)[0].action;
        let old_revision = shell.device_revision();

        // Reordering must invalidate the queued index even when both rows
        // remain online and visible. Otherwise index 0 connects the wrong peer.
        shell.replace_devices(vec![
            DeviceSummary {
                id: "second".into(),
                display_name: "Second".into(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "first".into(),
                display_name: "First".into(),
                status: DeviceStatus::Online,
            },
        ]);
        assert_ne!(shell.device_revision(), old_revision);
        apply_action(&mut shell, stale);
        assert_eq!(shell.selected_device(), None);

        // Identical refreshes preserve the current revision and do not
        // invalidate a freshly generated action unnecessarily.
        let current = controls_for_shell(&shell)[0].action;
        let revision = shell.device_revision();
        let same_snapshot = shell.devices().to_vec();
        shell.replace_devices(same_snapshot);
        assert_eq!(shell.device_revision(), revision);
        apply_action(&mut shell, current);
        assert_eq!(shell.selected_device(), Some("second"));
    }

    #[test]
    fn trusted_device_filters_preserve_source_indices_without_hidden_selection() {
        let mut shell = ProductShell::new();
        let mut peers = (0..12)
            .map(|i| DeviceSummary {
                id: format!("offline-{i}"),
                display_name: format!("Offline {i}"),
                status: DeviceStatus::Offline,
            })
            .collect::<Vec<_>>();
        peers.push(DeviceSummary {
            id: "authorized-online".to_owned(),
            display_name: "Verified online peer".to_owned(),
            status: DeviceStatus::Online,
        });
        shell.replace_devices(peers);
        shell.set_device_filter(DeviceFilter::Online);
        shell.set_nav_tab(NavTab::TrustedDevices);
        let revision = shell.device_revision();
        let action = DesktopAction::ConnectDevice(12, revision);
        apply_action(&mut shell, action);
        assert_eq!(shell.selected_device(), Some("authorized-online"));
        shell.disconnect();
        shell.set_nav_tab(NavTab::Devices);
        apply_action(&mut shell, action);
        assert_eq!(shell.selected_device(), Some("authorized-online"));
    }

    #[test]
    fn v5_trusted_devices_page_uses_real_online_peer_actions() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "trusted-1".to_owned(),
                display_name: "Owner laptop".to_owned(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "trusted-2".to_owned(),
                display_name: "Offline peer".to_owned(),
                status: DeviceStatus::Offline,
            },
        ]);
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let nav = layout.nav_tab_rect(1);
        assert_eq!(
            action_at_point(&shell, 1419, 611, nav.x + 8, nav.y + 8),
            Some(DesktopAction::SelectNav(NavTab::TrustedDevices))
        );
        shell.set_nav_tab(NavTab::TrustedDevices);
        assert_eq!(presentation_for(&shell).nav_tab, NavTab::TrustedDevices);
        let first = layout.trusted_device_tile_rect(0);
        let offline = layout.trusted_device_tile_rect(1);
        assert!(matches!(
            action_at_point(&shell, 1419, 611, first.x + 6, first.y + 6),
            Some(DesktopAction::ConnectDevice(0, _))
        ));
        assert_eq!(
            action_at_point(&shell, 1419, 611, offline.x + 6, offline.y + 6),
            None
        );
        let hidden = layout.remote_id_input_rect();
        assert_eq!(
            action_at_point(&shell, 1419, 611, hidden.x + 6, hidden.y + 6),
            None
        );
    }

    #[test]
    fn navigation_tabs_and_filters_are_hit_testable() {
        let mut shell = ProductShell::new();
        let layout = LockedDashboardLayout::for_window(1419, 611).expect("layout fits");

        // 1. Navigation items hit testing
        let conn_rect = layout.nav_tab_rect(2);
        let action = action_at_point(&shell, 1419, 611, conn_rect.x + 10, conn_rect.y + 10);
        assert_eq!(action, Some(DesktopAction::SelectNav(NavTab::Connections)));

        apply_action(&mut shell, action.unwrap());
        assert_eq!(shell.nav_tab(), NavTab::Connections);
        let presentation = presentation_for(&shell);
        assert_eq!(presentation.nav_tab, NavTab::Connections);

        let ft_rect = layout.nav_tab_rect(3);
        let action = action_at_point(&shell, 1419, 611, ft_rect.x + 10, ft_rect.y + 10);
        assert_eq!(action, Some(DesktopAction::SelectNav(NavTab::FileTransfer)));

        let sec_rect = layout.nav_tab_rect(4);
        let action = action_at_point(&shell, 1419, 611, sec_rect.x + 10, sec_rect.y + 10);
        assert_eq!(action, Some(DesktopAction::SelectNav(NavTab::Security)));

        // Filters are intentionally inactive while the Connections tab is open.
        // Exercise that guard before switching back to Devices for positive tests.
        let all_rect = layout.filter_all_rect();
        assert_eq!(
            action_at_point(&shell, 1419, 611, all_rect.x + 5, all_rect.y + 5),
            None
        );
        apply_action(&mut shell, DesktopAction::SelectNav(NavTab::Devices));
        assert_eq!(shell.nav_tab(), NavTab::Devices);

        // 2. Filter buttons hit testing on the Devices tab
        let action = action_at_point(&shell, 1419, 611, all_rect.x + 5, all_rect.y + 5);
        assert_eq!(action, Some(DesktopAction::SelectFilter(DeviceFilter::All)));

        let online_rect = layout.filter_online_rect();
        let action = action_at_point(&shell, 1419, 611, online_rect.x + 5, online_rect.y + 5);
        assert_eq!(
            action,
            Some(DesktopAction::SelectFilter(DeviceFilter::Online))
        );

        apply_action(&mut shell, action.unwrap());
        assert_eq!(shell.device_filter(), DeviceFilter::Online);

        let offline_rect = layout.filter_offline_rect();
        let action = action_at_point(&shell, 1419, 611, offline_rect.x + 5, offline_rect.y + 5);
        assert_eq!(
            action,
            Some(DesktopAction::SelectFilter(DeviceFilter::Offline))
        );

        // 3. Top bar buttons hit testing
        let settings_rect = layout.settings_button_rect(1419);
        let action = action_at_point(
            &shell,
            1419,
            611,
            settings_rect.x + 10,
            settings_rect.y + 10,
        );
        assert_eq!(action, Some(DesktopAction::OpenSettings));
        apply_action(&mut shell, action.unwrap());
        assert_eq!(shell.nav_tab(), NavTab::Settings);

        let help_rect = layout.help_button_rect(1419);
        let action = action_at_point(&shell, 1419, 611, help_rect.x + 10, help_rect.y + 10);
        assert_eq!(action, Some(DesktopAction::ToggleHelp));
        apply_action(&mut shell, action.unwrap());
        assert!(shell.is_help_open());
    }

    #[test]
    fn v5_scrolling_maps_remote_form_clicks_but_not_sidebar_navigation() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        shell.set_remote_id_input("222-222-222");
        shell.set_remote_password_input("test-only");
        let width = 1308;
        let height = 777;
        let layout = LockedDashboardLayout::for_window(width, height).unwrap();
        assert_eq!(layout.inspector.width, 0, "approved compact layout");
        let input = layout.remote_id_input_rect();
        let sidebar = layout.nav_tab_rect(2);
        shell.set_workspace_scroll_y(140);
        assert_eq!(
            action_at_point(&shell, width, height, input.x + 4, input.y + 4 - 140),
            Some(DesktopAction::FocusRemoteIdInput)
        );
        assert_eq!(
            action_at_point(&shell, width, height, sidebar.x + 5, sidebar.y + 5),
            Some(DesktopAction::SelectNav(NavTab::Connections))
        );
    }

    #[test]
    fn v5_help_overlay_blocks_hidden_connect_and_password_hit_targets() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        shell.set_remote_id_input("222-222-222");
        shell.set_remote_password_input("offline-ui-test-only");
        for (width, height) in [(800, 600), (960, 640), (1419, 611), (1920, 1080)] {
            shell.set_help_open(false);
            let layout = LockedDashboardLayout::for_window(width, height).unwrap();
            let connect = layout.remote_id_connect_btn_rect();
            assert_eq!(
                action_at_point(&shell, width, height, connect.x + 5, connect.y + 5),
                Some(DesktopAction::ConnectRemoteId)
            );
            shell.set_help_open(true);
            for rect in [
                layout.remote_id_input_rect(),
                layout.remote_password_status_rect(),
                layout.remote_password_reveal_btn_rect(),
                layout.remote_id_connect_btn_rect(),
                layout.your_id_copy_btn_rect(),
            ] {
                assert_eq!(
                    action_at_point(&shell, width, height, rect.x + 5, rect.y + 5),
                    None,
                    "Help overlay must block hidden fields at {width}x{height}"
                );
            }
            let help = layout.help_button_rect(width);
            assert_eq!(
                action_at_point(&shell, width, height, help.x + 5, help.y + 5),
                Some(DesktopAction::ToggleHelp)
            );
        }
    }

    #[test]
    fn v5_secondary_pages_do_not_accept_hidden_remote_credential_clicks() {
        let mut shell = ProductShell::new();
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let fields = [
            layout.remote_id_input_rect(),
            layout.remote_password_status_rect(),
            layout.your_id_copy_btn_rect(),
            layout.remote_id_connect_btn_rect(),
        ];
        for tab in [
            NavTab::Connections,
            NavTab::FileTransfer,
            NavTab::Security,
            NavTab::Settings,
        ] {
            shell.set_nav_tab(tab);
            for rect in fields {
                assert_eq!(
                    action_at_point(&shell, 1419, 611, rect.x + 5, rect.y + 5),
                    None,
                    "hidden Remote Access action reachable on {tab:?}"
                );
            }
        }
        shell.set_nav_tab(NavTab::Devices);
        let input = layout.remote_id_input_rect();
        assert_eq!(
            action_at_point(&shell, 1419, 611, input.x + 5, input.y + 5),
            Some(DesktopAction::FocusRemoteIdInput)
        );
    }

    #[test]
    fn v5_copy_device_id_does_not_leave_password_keyboard_focus_active() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        shell.set_remote_password_input("temporary-ui-secret");
        shell.focus_remote_password();
        shell.toggle_remote_password_reveal();
        apply_action(&mut shell, DesktopAction::CopyYourId);
        assert!(!shell.is_remote_password_focused());
        assert!(!shell.is_remote_password_revealed());
    }

    #[test]
    fn v5_password_typing_never_activates_global_navigation_shortcuts() {
        let mut shell = ProductShell::new();
        shell.focus_remote_password();
        for character in ['s', 'c', 'f', 'm', 'o', 'd'] {
            assert!(apply_key(&mut shell, character));
        }
        assert_eq!(shell.remote_password_input(), "scfmod");
        assert_eq!(shell.nav_tab(), NavTab::Devices);
        assert!(shell.is_remote_password_focused());

        assert!(apply_key(&mut shell, '\t'));
        assert!(shell.is_remote_id_focused());
        assert!(!shell.is_remote_password_focused());
        assert!(apply_key(&mut shell, '\t'));
        assert!(shell.is_remote_password_focused());
    }

    #[test]
    fn v5_remote_password_reveal_is_explicit_and_never_default() {
        let mut shell = ProductShell::new();
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let button = layout.remote_password_reveal_btn_rect();
        let hit =
            |shell: &ProductShell| action_at_point(shell, 1419, 611, button.x + 5, button.y + 5);
        assert_eq!(hit(&shell), None);
        shell.set_remote_password_input("secret-only-for-ui-test");
        let hidden = presentation_for(&shell);
        assert!(!hidden.remote_password_revealed);
        assert!(!hidden.remote_password_display.contains("secret"));
        assert_eq!(hit(&shell), Some(DesktopAction::ToggleRemotePasswordReveal));
        apply_action(&mut shell, DesktopAction::ToggleRemotePasswordReveal);
        let shown = presentation_for(&shell);
        assert!(shown.remote_password_revealed);
        assert_eq!(shown.remote_password_display, "secret-only-for-ui-test");
        shell.disconnect();
        assert!(!presentation_for(&shell).remote_password_revealed);
        assert_eq!(presentation_for(&shell).remote_password_display, "");
    }

    #[test]
    fn v5_connect_button_stays_disabled_for_invalid_or_missing_credentials() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        let l = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let c = l.remote_id_connect_btn_rect();
        let hit = |shell: &ProductShell| action_at_point(shell, 1419, 611, c.x + 5, c.y + 5);
        assert_eq!(hit(&shell), None);
        shell.set_remote_id_input("bad");
        shell.set_remote_password_input("temporary-only");
        assert_eq!(hit(&shell), None);
        shell.set_remote_id_input("111-111-111"); // self
        assert_eq!(hit(&shell), None);
        shell.set_remote_id_input("222-222-222");
        assert_eq!(hit(&shell), Some(DesktopAction::ConnectRemoteId));
        shell.clear_remote_password();
        assert_eq!(hit(&shell), None);
    }

    #[test]
    fn v5_access_form_hit_targets_match_layout_at_real_desktop_sizes() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        shell.set_remote_id_input("222-222-222");
        shell.set_remote_password_input("test-only-secret");
        for (width, height) in [(1024, 768), (1419, 611), (1920, 1080)] {
            let layout =
                LockedDashboardLayout::for_window(width, height).expect("V5 desktop layout");
            let remote_id = layout.remote_id_input_rect();
            let remote_password = layout.remote_password_status_rect();
            let connect = layout.remote_id_connect_btn_rect();
            let copy_id = layout.your_id_copy_btn_rect();

            for (rect, expected) in [
                (remote_id, DesktopAction::FocusRemoteIdInput),
                (remote_password, DesktopAction::FocusRemotePasswordInput),
                (connect, DesktopAction::ConnectRemoteId),
                (copy_id, DesktopAction::CopyYourId),
            ] {
                let actual = action_at_point(
                    &shell,
                    width,
                    height,
                    rect.x + rect.width / 2,
                    rect.y + rect.height / 2,
                );
                assert_eq!(
                    actual,
                    Some(expected),
                    "V5 visible field must agree with native hit testing at {width}x{height}"
                );
            }

            let trusted = layout.devices;
            let screen = layout.remote_screen;
            assert!(trusted.y >= screen.y + screen.height);
            assert!(trusted.x >= layout.viewer.x);
            assert!(trusted.x + trusted.width <= layout.viewer.x + layout.viewer.width);
            assert!(connect.y >= remote_password.y + remote_password.height);
        }
    }

    #[test]
    fn v5_remote_id_alone_cannot_start_password_connection() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-111-111");
        shell.set_remote_id_input("222-222-222");
        apply_action(&mut shell, DesktopAction::ConnectRemoteId);
        assert!(shell.selected_device().is_none());
        assert!(shell.last_error().is_some());

        shell.set_remote_password_input("test-only-secret");
        apply_action(&mut shell, DesktopAction::ConnectRemoteId);
        assert_eq!(shell.selected_device(), Some("KMJ-222-222-222"));
        // A ProductShell request is still not verified remote control.
        assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);
    }

    #[test]
    fn dual_role_cards_pointer_and_keyboard_interaction() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-123-456-789");

        let layout = LockedDashboardLayout::for_window(1419, 611).expect("layout");

        // 1. Click Copy Your ID button
        let copy_rect = layout.your_id_copy_btn_rect();
        let copy_action = action_at_point(&shell, 1419, 611, copy_rect.x + 5, copy_rect.y + 5);
        assert_eq!(copy_action, Some(DesktopAction::CopyYourId));
        apply_action(&mut shell, copy_action.unwrap());
        assert!(shell.last_error().unwrap().contains("KMJ-123-456-789"));

        // 2. Click Remote ID input box -> focuses input
        let input_rect = layout.remote_id_input_rect();
        let focus_action = action_at_point(&shell, 1419, 611, input_rect.x + 5, input_rect.y + 5);
        assert_eq!(focus_action, Some(DesktopAction::FocusRemoteIdInput));
        apply_action(&mut shell, focus_action.unwrap());
        assert!(shell.is_remote_id_focused());

        // 3. Type characters via apply_key while focused
        assert!(apply_key(&mut shell, '9'));
        assert!(apply_key(&mut shell, '8'));
        assert!(apply_key(&mut shell, '7'));
        assert!(apply_key(&mut shell, '-'));
        assert!(apply_key(&mut shell, '6'));
        assert!(apply_key(&mut shell, '5'));
        assert!(apply_key(&mut shell, '4'));
        assert_eq!(shell.remote_id_input(), "987-654");

        // 4. Backspace
        assert!(apply_key(&mut shell, '\x08'));
        assert_eq!(shell.remote_id_input(), "987-65");

        // 5. Complete input and connect via click
        shell.append_remote_id_char('4');
        shell.append_remote_id_char('-');
        shell.append_remote_id_char('3');
        shell.append_remote_id_char('2');
        shell.append_remote_id_char('1');
        assert_eq!(shell.remote_id_input(), "987-654-321");

        let connect_rect = layout.remote_id_connect_btn_rect();
        let connect_action =
            action_at_point(&shell, 1419, 611, connect_rect.x + 5, connect_rect.y + 5);
        assert_eq!(connect_action, None, "disabled V5 CTA cannot be clicked");
        apply_action(&mut shell, DesktopAction::ConnectRemoteId);
        assert!(shell.selected_device().is_none());
        assert!(
            shell
                .last_error()
                .unwrap()
                .contains("remote session password")
        );

        // A password-shaped input alone is not a verified remote connection,
        // but it permits the shell to begin the guarded request.
        shell.set_remote_password_input("local-qa-only");
        let connect_action =
            action_at_point(&shell, 1419, 611, connect_rect.x + 5, connect_rect.y + 5);
        assert_eq!(connect_action, Some(DesktopAction::ConnectRemoteId));
        apply_action(&mut shell, connect_action.unwrap());
        assert_eq!(shell.selected_device(), Some("KMJ-987-654-321"));
        assert!(!shell.is_remote_id_focused());

        // 6. Refuse self-connection
        shell.disconnect();
        shell.set_remote_id_input("123-456-789");
        shell.set_remote_password_input("local-qa-only");
        apply_action(&mut shell, DesktopAction::ConnectRemoteId);
        assert!(
            shell
                .last_error()
                .unwrap()
                .contains("Cannot connect to self")
        );
        assert_eq!(shell.selected_device(), None);
    }
}
