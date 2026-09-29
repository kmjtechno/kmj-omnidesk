#![forbid(unsafe_code)]

use omnidesk_core::product_shell::PrimaryView;

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
            assert!(controls.iter().all(|control| !control.label.trim().is_empty()));
            assert!(controls.iter().all(|control| control.keyboard_key.is_ascii()));
        }
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
        assert!(controls.iter().any(|c| c.action == DesktopAction::AllowPermission));
        assert!(controls.iter().any(|c| c.action == DesktopAction::DenyPermission));
    }
}
