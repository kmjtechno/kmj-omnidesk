#![forbid(unsafe_code)]

use omnidesk_core::product_shell::{PermissionDecision, PrimaryView, ProductShell};

#[cfg(windows)]
pub mod windows_host;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopAction {
    FocusDevices,
    AllowPermission,
    DenyPermission,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibleControl {
    pub label: &'static str,
    pub action: DesktopAction,
    pub keyboard_key: char,
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
        DesktopAction::AllowPermission => shell.decide_permission(PermissionDecision::Allow),
        DesktopAction::DenyPermission => shell.decide_permission(PermissionDecision::Deny),
        DesktopAction::Disconnect => shell.disconnect(),
    }
}

pub fn apply_key(shell: &mut ProductShell, key: char) -> bool {
    let Some(action) = action_for_key(shell.primary_view(), key) else {
        return false;
    };
    apply_action(shell, action);
    true
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
