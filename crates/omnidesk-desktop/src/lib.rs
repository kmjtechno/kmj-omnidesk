#![forbid(unsafe_code)]

use omnidesk_core::product_shell::{
    DeviceStatus, PermissionDecision, PrimaryView, ProductShell, QualityPreset,
};

pub mod accesskit_tree;
pub mod render;

#[cfg(windows)]
pub mod windows_host;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopAction {
    FocusDevices,
    ConnectDevice(usize),
    AllowPermission,
    DenyPermission,
    SetQuality(QualityPreset),
    Disconnect,
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
}

impl VisualSystem {
    #[must_use]
    pub const fn kmj_black_red() -> Self {
        Self {
            background_rgb: [8, 8, 10],
            surface_rgb: [18, 18, 22],
            foreground_rgb: [245, 245, 247],
            accent_rgb: [220, 24, 40],
            danger_rgb: [255, 59, 48],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationModel {
    pub title: &'static str,
    pub status: &'static str,
    pub details: Vec<String>,
    pub controls: Vec<ShellControl>,
    pub visual: VisualSystem,
}

#[must_use]
pub fn presentation_for(shell: &ProductShell) -> PresentationModel {
    let status = match shell.primary_view() {
        PrimaryView::Devices => "Disconnected",
        PrimaryView::PermissionPrompt => "Authorization required",
        PrimaryView::Session => "Secure session active",
    };
    let details = presentation_details(shell);
    PresentationModel {
        title: "KMJ OmniDesk",
        status,
        details,
        controls: controls_for_shell(shell),
        visual: VisualSystem::kmj_black_red(),
    }
}

#[must_use]
pub fn controls_for_shell(shell: &ProductShell) -> Vec<ShellControl> {
    match shell.primary_view() {
        PrimaryView::Devices => {
            if shell.devices().is_empty() {
                return vec![ShellControl {
                    label: "No devices available".to_owned(),
                    action: DesktopAction::FocusDevices,
                    keyboard_key: 'd',
                    role: AccessibleRole::Navigation,
                    enabled: false,
                }];
            }

            shell
                .devices()
                .iter()
                .take(9)
                .enumerate()
                .map(|(index, device)| {
                    let key =
                        char::from_digit(u32::try_from(index + 1).expect("device key index"), 10)
                            .expect("device key digit");
                    let online = device.status == DeviceStatus::Online;
                    ShellControl {
                        label: format!(
                            "{} — {}",
                            device.display_name,
                            if online { "Online" } else { "Offline" }
                        ),
                        action: DesktopAction::ConnectDevice(index),
                        keyboard_key: key,
                        role: AccessibleRole::Button,
                        enabled: online,
                    }
                })
                .collect()
        }
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
            if shell.devices().is_empty() {
                vec!["Waiting for registered devices".to_owned()]
            } else {
                vec![format!("{} registered device(s)", shell.devices().len())]
            }
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
                details.push(format!("Latency: {} ms", stats.latency_ms));
                details.push(format!("Bitrate: {} kbps", stats.bitrate_kbps));
                details.push(format!("FPS: {}", stats.fps));
            } else {
                details.push("Connection statistics unavailable".to_owned());
            }
            details
        }
    }
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

pub fn apply_action(shell: &mut ProductShell, action: DesktopAction) {
    match action {
        DesktopAction::FocusDevices => {}
        DesktopAction::ConnectDevice(index) => {
            let device_id = shell.devices().get(index).map(|device| device.id.clone());
            if let Some(device_id) = device_id {
                let _ = shell.begin_connect(&device_id);
            }
        }
        DesktopAction::AllowPermission => shell.decide_permission(PermissionDecision::Allow),
        DesktopAction::DenyPermission => shell.decide_permission(PermissionDecision::Deny),
        DesktopAction::SetQuality(preset) => shell.set_quality_preset(preset),
        DesktopAction::Disconnect => shell.disconnect(),
    }
}

pub fn apply_key(shell: &mut ProductShell, key: char) -> bool {
    let key = key.to_ascii_lowercase();
    let Some(control) = controls_for_shell(shell)
        .into_iter()
        .find(|control| control.enabled && control.keyboard_key == key)
    else {
        return false;
    };
    apply_action(shell, control.action);
    true
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

    #[test]
    fn every_primary_view_has_keyboard_operable_labeled_controls() {
        for view in [
            PrimaryView::Devices,
            PrimaryView::PermissionPrompt,
            PrimaryView::Session,
        ] {
            let controls = controls_for(view);
            assert!(!controls.is_empty());
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
        assert_eq!(presentation_for(&shell).status, "Secure session active");
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
        assert!(visual.background_rgb.iter().all(|channel| *channel <= 16));
        assert!(visual.surface_rgb.iter().all(|channel| *channel <= 32));
        assert!(visual.foreground_rgb.iter().all(|channel| *channel >= 240));
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
        assert_eq!(controls[0].action, DesktopAction::ConnectDevice(0));
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
}
