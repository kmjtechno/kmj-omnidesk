use accesskit::{Action, Node, NodeId, Rect, Role, TreeId, TreeInfo, TreeUpdate};
use omnidesk_core::product_shell::{NavTab, PrimaryView, ProductShell};

use crate::{
    DesktopAction, control_rects_for, controls_for_shell,
    layout::{DashboardRect, LockedDashboardLayout},
    presentation_for,
};

pub const ROOT_NODE_ID: NodeId = NodeId(0);

fn control_node_id(index: usize) -> NodeId {
    NodeId(u64::try_from(index + 1).expect("control index fits u64"))
}

/// Control IDs for V5's native task-focused fields. Device-list items keep
/// the existing low IDs, while these remain stable as the directory changes.
const V5_REMOTE_ID_NODE: NodeId = NodeId(10_001);
const V5_REMOTE_PASSWORD_NODE: NodeId = NodeId(10_002);
const V5_CONNECT_NODE: NodeId = NodeId(10_003);
const V5_COPY_ID_NODE: NodeId = NodeId(10_004);
const V5_SHOW_PASSWORD_NODE: NodeId = NodeId(10_005);
const V5_COPY_PASSWORD_NODE: NodeId = NodeId(10_006);
const V5_ROTATE_PASSWORD_NODE: NodeId = NodeId(10_007);
const V5_REMOTE_REVEAL_NODE: NodeId = NodeId(10_008);
const V5_NAV_FIRST_NODE: u64 = 11_001;
const V5_SETTINGS_NODE: NodeId = NodeId(12_001);
const V5_HELP_NODE: NodeId = NodeId(12_002);

const V5_NAV_TABS: [NavTab; 6] = [
    NavTab::Devices,
    NavTab::TrustedDevices,
    NavTab::Connections,
    NavTab::FileTransfer,
    NavTab::Security,
    NavTab::Settings,
];

#[must_use]
pub fn desktop_action_for_node(shell: &ProductShell, node_id: NodeId) -> Option<DesktopAction> {
    // Always-visible top-bar actions remain operable when Help replaces
    // the central content. They never reveal credential values.
    match node_id {
        V5_SETTINGS_NODE => return Some(DesktopAction::OpenSettings),
        V5_HELP_NODE => return Some(DesktopAction::ToggleHelp),
        _ => {}
    }
    if let Some(index) = node_id.0.checked_sub(V5_NAV_FIRST_NODE) {
        if let Some(tab) = V5_NAV_TABS.get(usize::try_from(index).ok()?) {
            return Some(DesktopAction::SelectNav(*tab));
        }
    }
    if shell.primary_view() == PrimaryView::Devices
        && shell.nav_tab() == NavTab::Devices
        && !shell.is_help_open()
    {
        if (node_id == V5_REMOTE_REVEAL_NODE && shell.remote_password_input().is_empty())
            || (node_id == V5_CONNECT_NODE && !presentation_for(shell).remote_access_form_ready)
            || (matches!(node_id, V5_SHOW_PASSWORD_NODE | V5_COPY_PASSWORD_NODE)
                && shell.password_manager().raw_password().is_none())
        {
            return None;
        }
        let form_action = match node_id {
            V5_REMOTE_ID_NODE => Some(DesktopAction::FocusRemoteIdInput),
            V5_REMOTE_PASSWORD_NODE => Some(DesktopAction::FocusRemotePasswordInput),
            V5_REMOTE_REVEAL_NODE => Some(DesktopAction::ToggleRemotePasswordReveal),
            V5_CONNECT_NODE => Some(DesktopAction::ConnectRemoteId),
            V5_COPY_ID_NODE => Some(DesktopAction::CopyYourId),
            V5_SHOW_PASSWORD_NODE => Some(DesktopAction::ToggleYourPasswordReveal),
            V5_COPY_PASSWORD_NODE => Some(DesktopAction::CopyYourPassword),
            V5_ROTATE_PASSWORD_NODE => Some(DesktopAction::RotateYourPassword),
            _ => None,
        };
        if form_action.is_some() {
            return form_action;
        }
    }

    controls_for_shell(shell)
        .into_iter()
        .enumerate()
        .find(|(index, control)| {
            // A11y activation must never bypass pointer hit-testing's
            // three-visible-tile limit or a secondary tab's hidden directory.
            let visible = shell.primary_view() != PrimaryView::Devices
                || match shell.nav_tab() {
                    NavTab::Devices => *index < 3,
                    NavTab::TrustedDevices => *index < 9,
                    _ => false,
                };
            visible && control.enabled && control_node_id(*index) == node_id
        })
        .map(|(_, control)| control.action)
}

fn accessibility_coordinate(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn dashboard_bounds_scrolled(rect: DashboardRect, scroll_y: usize) -> Rect {
    let dy = accessibility_coordinate(scroll_y);
    Rect {
        x0: accessibility_coordinate(rect.x),
        y0: accessibility_coordinate(rect.y) - dy,
        x1: accessibility_coordinate(rect.x.saturating_add(rect.width)),
        y1: accessibility_coordinate(rect.y.saturating_add(rect.height)) - dy,
    }
}

fn dashboard_bounds(rect: DashboardRect) -> Rect {
    Rect {
        x0: accessibility_coordinate(rect.x),
        y0: accessibility_coordinate(rect.y),
        x1: accessibility_coordinate(rect.x.saturating_add(rect.width)),
        y1: accessibility_coordinate(rect.y.saturating_add(rect.height)),
    }
}

fn control_bounds(shell: &ProductShell, index: usize, width: usize, height: usize) -> Rect {
    let presentation = presentation_for(shell);
    let rect = control_rects_for(&presentation, width, height)
        .get(index)
        .copied()
        .unwrap_or(crate::ControlRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        });
    let scroll = if LockedDashboardLayout::for_window(width, height).is_some() {
        shell.workspace_scroll_y()
            .min(LockedDashboardLayout::max_scroll_y(height))
    } else {
        0
    };
    dashboard_bounds_scrolled(
        DashboardRect {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
        },
        scroll,
    )
}

/// Builds a complete AccessKit tree from the authoritative product-shell state.
#[must_use]
pub fn build_accesskit_tree(shell: &ProductShell) -> TreeUpdate {
    build_accesskit_tree_with_focus(shell, None)
}

/// Builds the same complete tree while honoring a valid platform-requested focus node.
#[must_use]
pub fn build_accesskit_tree_with_focus(
    shell: &ProductShell,
    requested_focus: Option<NodeId>,
) -> TreeUpdate {
    // Legacy offscreen compatibility wrapper. The real Windows host always
    // uses build_accesskit_tree_at_size with its measured window dimensions.
    build_accesskit_tree_at_size(shell, requested_focus, 760, 640)
}

/// Builds the accessibility tree using the actual physical window size.
///
/// This geometry must match the native renderer and pointer hit-testing.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_accesskit_tree_at_size(
    shell: &ProductShell,
    requested_focus: Option<NodeId>,
    width: usize,
    height: usize,
) -> TreeUpdate {
    let presentation = presentation_for(shell);
    let controls = controls_for_shell(shell);
    let mut child_ids = Vec::with_capacity(controls.len());
    let mut nodes = Vec::with_capacity(controls.len() + 1);

    for (index, control) in controls.iter().enumerate() {
        if shell.primary_view() == PrimaryView::Devices {
            let visible = match shell.nav_tab() {
                NavTab::Devices => index < 3,
                NavTab::TrustedDevices => index < 9,
                _ => false,
            };
            if !visible {
                continue;
            }
        }
        let id = control_node_id(index);
        child_ids.push(id);

        let mut node = Node::new(Role::Button);
        node.set_label(&control.label);
        node.set_bounds(control_bounds(shell, index, width, height));
        node.add_action(Action::Focus);
        if control.enabled {
            node.add_action(Action::Click);
        } else {
            node.set_disabled();
        }
        nodes.push((id, node));
    }

    if let Some(layout) = LockedDashboardLayout::for_window(width, height) {
        for (id, name, rect) in [
            (
                V5_SETTINGS_NODE,
                "Open preferences",
                layout.settings_button_rect(width),
            ),
            (
                V5_HELP_NODE,
                "Open or close Help",
                layout.help_button_rect(width),
            ),
        ] {
            let mut node = Node::new(Role::Button);
            node.set_label(name);
            node.set_bounds(dashboard_bounds(rect));
            node.add_action(Action::Focus);
            node.add_action(Action::Click);
            child_ids.push(id);
            nodes.push((id, node));
        }
    }

    // Native V5 sidebar is a keyboard/screen-reader navigation region.
    // Keep the same tab order and rectangles as the renderer and hit tester.
    if let Some(layout) = LockedDashboardLayout::for_window(width, height) {
        for (index, label) in [
            "Remote access",
            "Trusted devices",
            "Sessions",
            "File transfer",
            "Security center",
            "Preferences",
        ]
        .iter()
        .enumerate()
        {
            let id = NodeId(V5_NAV_FIRST_NODE + u64::try_from(index).unwrap_or(0));
            let mut node = Node::new(Role::Button);
            node.set_label(*label);
            node.set_bounds(dashboard_bounds(layout.nav_tab_rect(index)));
            node.add_action(Action::Focus);
            node.add_action(Action::Click);
            child_ids.push(id);
            nodes.push((id, node));
        }
    }

    // Expose the actual V5 fields to screen readers, without ever storing
    // or announcing either local or remote password contents in node values.
    if shell.primary_view() == PrimaryView::Devices
        && shell.nav_tab() == NavTab::Devices
        && !shell.is_help_open()
    {
        if let Some(layout) = LockedDashboardLayout::for_window(width, height) {
            let fields = [
                (
                    V5_REMOTE_ID_NODE,
                    Role::TextInput,
                    "Remote device ID",
                    layout.remote_id_input_rect(),
                ),
                (
                    V5_REMOTE_PASSWORD_NODE,
                    Role::PasswordInput,
                    "Remote session password",
                    layout.remote_password_status_rect(),
                ),
                (
                    V5_REMOTE_REVEAL_NODE,
                    Role::Button,
                    "Show or hide remote session password",
                    layout.remote_password_reveal_btn_rect(),
                ),
                (
                    V5_CONNECT_NODE,
                    Role::Button,
                    "Connect securely",
                    layout.remote_id_connect_btn_rect(),
                ),
                (
                    V5_COPY_ID_NODE,
                    Role::Button,
                    "Copy your device ID",
                    layout.your_id_copy_btn_rect(),
                ),
                (
                    V5_SHOW_PASSWORD_NODE,
                    Role::Button,
                    "Show or hide your password",
                    layout.your_password_reveal_btn_rect(),
                ),
                (
                    V5_COPY_PASSWORD_NODE,
                    Role::Button,
                    "Copy your password",
                    layout.your_password_copy_btn_rect(),
                ),
                (
                    V5_ROTATE_PASSWORD_NODE,
                    Role::Button,
                    "Generate new device password",
                    layout.your_password_rotate_btn_rect(),
                ),
            ];
            for (id, role, label, bounds) in fields {
                let mut node = Node::new(role);
                node.set_label(label);
                node.set_bounds(dashboard_bounds_scrolled(
                    bounds,
                    shell.workspace_scroll_y()
                        .min(LockedDashboardLayout::max_scroll_y(height)),
                ));
                node.add_action(Action::Focus);
                let enabled = match id {
                    V5_REMOTE_REVEAL_NODE => !shell.remote_password_input().is_empty(),
                    V5_CONNECT_NODE => presentation.remote_access_form_ready,
                    V5_SHOW_PASSWORD_NODE | V5_COPY_PASSWORD_NODE => {
                        shell.password_manager().raw_password().is_some()
                    }
                    _ => true,
                };
                if enabled {
                    node.add_action(Action::Click);
                } else {
                    node.set_disabled();
                }
                child_ids.push(id);
                nodes.push((id, node));
            }
        }
    }

    let mut root = Node::new(Role::Window);
    root.set_label(format!("{} — {}", presentation.title, presentation.status));
    root.set_bounds(Rect {
        x0: 0.0,
        y0: 0.0,
        x1: accessibility_coordinate(width),
        y1: accessibility_coordinate(height),
    });
    root.set_children(child_ids.clone());
    nodes.insert(0, (ROOT_NODE_ID, root));

    let default_focus = if shell.is_help_open() && child_ids.contains(&V5_HELP_NODE) {
        V5_HELP_NODE
    } else if child_ids.contains(&V5_REMOTE_ID_NODE) {
        V5_REMOTE_ID_NODE
    } else {
        child_ids.first().copied().unwrap_or(ROOT_NODE_ID)
    };
    let focus = requested_focus
        .filter(|id| *id == ROOT_NODE_ID || child_ids.contains(id))
        .unwrap_or(default_focus);

    TreeUpdate {
        nodes,
        tree: Some(TreeInfo::new(ROOT_NODE_ID)),
        tree_id: TreeId::ROOT,
        focus,
    }
}

#[cfg(test)]
mod tests {
    use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};

    use super::*;

    #[test]
    fn default_tree_exposes_truthful_window_and_devices_control() {
        let shell = ProductShell::new();
        let update = build_accesskit_tree(&shell);

        assert_eq!(update.nodes.len(), 2);
        assert_eq!(update.focus, NodeId(1));
        assert!(update.tree.is_some());
        assert_eq!(desktop_action_for_node(&shell, NodeId(1)), None);
        assert_eq!(desktop_action_for_node(&shell, NodeId(2)), None);
        assert!(update.nodes[1].1.is_disabled());
    }

    #[test]
    fn requested_focus_is_kept_only_when_node_exists() {
        let shell = ProductShell::new();
        let valid = build_accesskit_tree_with_focus(&shell, Some(NodeId(1)));
        assert_eq!(valid.focus, NodeId(1));

        let invalid = build_accesskit_tree_with_focus(&shell, Some(NodeId(99)));
        assert_eq!(invalid.focus, NodeId(1));
    }

    #[test]
    fn v5_accessibility_bounds_follow_center_scroll_but_not_header() {
        let mut shell = ProductShell::new();
        let width = 1308;
        let height = 777;
        shell.set_workspace_scroll_y(120);
        let layout = LockedDashboardLayout::for_window(width, height).unwrap();
        let tree = build_accesskit_tree_at_size(&shell, None, width, height);
        let (_, field) = tree.nodes.iter()
            .find(|(id, _)| *id == V5_REMOTE_ID_NODE).unwrap();
        let expected = dashboard_bounds_scrolled(layout.remote_id_input_rect(), 120);
        assert_eq!(field.bounds(), Some(expected));
        let (_, navigation) = tree.nodes.iter()
            .find(|(id, _)| *id == NodeId(V5_NAV_FIRST_NODE)).unwrap();
        assert_eq!(navigation.bounds(), Some(dashboard_bounds(layout.nav_tab_rect(0))));
    }

    #[test]
    fn v5_accessibility_uses_actual_window_geometry_and_hides_overflow_rows() {
        let mut shell = ProductShell::new();
        shell.replace_devices(
            (0..5)
                .map(|i| DeviceSummary {
                    id: format!("peer-{i}"),
                    display_name: format!("Peer {i}"),
                    status: DeviceStatus::Online,
                })
                .collect(),
        );
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        // Root + at most three visible trusted-device tiles.
        assert_eq!(tree.nodes.len(), 20);
        assert_eq!(tree.focus, V5_REMOTE_ID_NODE);
        assert_eq!(
            tree.nodes[0].1.bounds(),
            Some(Rect {
                x0: 0.0,
                y0: 0.0,
                x1: 1419.0,
                y1: 611.0,
            })
        );
        assert_eq!(desktop_action_for_node(&shell, NodeId(4)), None);
        assert_eq!(desktop_action_for_node(&shell, NodeId(5)), None);

        // A11y activation on a secondary tab cannot select hidden peers.
        shell.set_nav_tab(NavTab::Security);
        assert_eq!(desktop_action_for_node(&shell, NodeId(1)), None);
    }

    #[test]
    fn v5_topbar_help_and_settings_are_accessible_and_hit_aligned() {
        let mut shell = ProductShell::new();
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        for (id, expected_action, rect) in [
            (
                V5_SETTINGS_NODE,
                DesktopAction::OpenSettings,
                layout.settings_button_rect(1419),
            ),
            (
                V5_HELP_NODE,
                DesktopAction::ToggleHelp,
                layout.help_button_rect(1419),
            ),
        ] {
            let (_, node) = tree.nodes.iter().find(|(nid, _)| *nid == id).unwrap();
            assert_eq!(desktop_action_for_node(&shell, id), Some(expected_action));
            assert_eq!(node.bounds(), Some(dashboard_bounds(rect)));
        }
        shell.set_help_open(true);
        let help_tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        assert_eq!(help_tree.focus, V5_HELP_NODE);
        assert_eq!(
            desktop_action_for_node(&shell, V5_HELP_NODE),
            Some(DesktopAction::ToggleHelp)
        );
    }

    #[test]
    fn v5_help_overlay_removes_invisible_credential_nodes_and_actions() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("ui-test-only");
        shell.set_help_open(true);
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        assert!(
            !tree
                .nodes
                .iter()
                .any(|(id, _)| *id == V5_REMOTE_PASSWORD_NODE)
        );
        assert!(!tree.nodes.iter().any(|(id, _)| *id == V5_CONNECT_NODE));
        assert_eq!(
            desktop_action_for_node(&shell, V5_REMOTE_PASSWORD_NODE),
            None
        );
        assert_eq!(desktop_action_for_node(&shell, V5_CONNECT_NODE), None);
    }

    #[test]
    fn v5_accessibility_omits_credential_nodes_on_secondary_pages() {
        let mut shell = ProductShell::new();
        shell.set_nav_tab(NavTab::Security);
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        assert!(
            !tree
                .nodes
                .iter()
                .any(|(id, _)| *id == V5_REMOTE_PASSWORD_NODE)
        );
        assert!(!tree.nodes.iter().any(|(id, _)| *id == V5_CONNECT_NODE));
        assert_eq!(
            desktop_action_for_node(&shell, V5_REMOTE_PASSWORD_NODE),
            None
        );
        assert_eq!(desktop_action_for_node(&shell, V5_COPY_ID_NODE), None);
        assert_eq!(
            desktop_action_for_node(&shell, NodeId(V5_NAV_FIRST_NODE + 4)),
            Some(DesktopAction::SelectNav(NavTab::Security))
        );
    }

    #[test]
    fn trusted_devices_accessibility_matches_real_on_screen_peers() {
        use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary};
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            DeviceSummary {
                id: "trusted-a".to_owned(),
                display_name: "Verified peer A".to_owned(),
                status: DeviceStatus::Online,
            },
            DeviceSummary {
                id: "trusted-b".to_owned(),
                display_name: "Offline peer B".to_owned(),
                status: DeviceStatus::Offline,
            },
        ]);
        shell.set_nav_tab(NavTab::TrustedDevices);
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        let layout = LockedDashboardLayout::for_window(1419, 611).unwrap();
        let (_, first) = tree.nodes.iter().find(|(id, _)| *id == NodeId(1)).unwrap();
        let (_, second) = tree.nodes.iter().find(|(id, _)| *id == NodeId(2)).unwrap();
        assert_eq!(
            first.bounds(),
            Some(dashboard_bounds(layout.trusted_device_tile_rect(0)))
        );
        assert!(!first.is_disabled());
        assert!(second.is_disabled());
        assert_eq!(desktop_action_for_node(&shell, NodeId(2)), None);
        assert!(matches!(
            desktop_action_for_node(&shell, NodeId(1)),
            Some(DesktopAction::ConnectDevice(0, _))
        ));
    }

    #[test]
    fn v5_sidebar_accessibility_actions_match_native_tabs() {
        let shell = ProductShell::new();
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        let nav_node = NodeId(V5_NAV_FIRST_NODE + 4);
        assert!(tree.nodes.iter().any(|(id, _)| *id == nav_node));
        assert_eq!(
            desktop_action_for_node(&shell, nav_node),
            Some(DesktopAction::SelectNav(NavTab::Security))
        );
        assert_eq!(
            desktop_action_for_node(&shell, NodeId(V5_NAV_FIRST_NODE + 99)),
            None
        );
    }

    #[test]
    fn v5_remote_password_reveal_node_never_contains_the_secret() {
        let mut shell = ProductShell::new();
        let empty = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        let (_, disabled) = empty
            .nodes
            .iter()
            .find(|(id, _)| *id == V5_REMOTE_REVEAL_NODE)
            .unwrap();
        assert!(disabled.is_disabled());
        assert_eq!(desktop_action_for_node(&shell, V5_REMOTE_REVEAL_NODE), None);

        shell.set_remote_password_input("do-not-leak-to-screen-reader");
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);
        let (_, show) = tree
            .nodes
            .iter()
            .find(|(id, _)| *id == V5_REMOTE_REVEAL_NODE)
            .unwrap();
        assert!(!show.is_disabled());
        assert_eq!(show.value(), None);
        assert_eq!(
            desktop_action_for_node(&shell, V5_REMOTE_REVEAL_NODE),
            Some(DesktopAction::ToggleRemotePasswordReveal)
        );
    }

    #[test]
    fn v5_accessibility_exposes_password_role_without_secret_value() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("do-not-expose-this");
        let tree = build_accesskit_tree_at_size(&shell, None, 1419, 611);

        let (_, password_node) = tree
            .nodes
            .iter()
            .find(|(id, _)| *id == V5_REMOTE_PASSWORD_NODE)
            .expect("V5 password node");
        assert_eq!(password_node.role(), Role::PasswordInput);
        assert_eq!(password_node.label(), Some("Remote session password"));
        assert_eq!(password_node.value(), None);

        assert_eq!(
            desktop_action_for_node(&shell, V5_REMOTE_PASSWORD_NODE),
            Some(DesktopAction::FocusRemotePasswordInput)
        );
        // Without a valid remote ID, Connect is disabled fail-closed.
        assert_eq!(desktop_action_for_node(&shell, V5_CONNECT_NODE), None);

        // With valid ID and password, Connect action is operable.
        shell.set_remote_id_input("KMJ-123-456-789");
        assert_eq!(
            desktop_action_for_node(&shell, V5_CONNECT_NODE),
            Some(DesktopAction::ConnectRemoteId)
        );
        assert_eq!(desktop_action_for_node(&shell, NodeId(99_999)), None);
    }

    #[test]
    fn online_device_is_exposed_as_clickable_connect_action() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);

        let update = build_accesskit_tree(&shell);
        assert_eq!(update.nodes.len(), 2);
        assert_eq!(
            desktop_action_for_node(&shell, NodeId(1)),
            Some(DesktopAction::ConnectDevice(0, shell.device_revision()))
        );
        assert!(!update.nodes[1].1.is_disabled());
    }

    #[test]
    fn permission_view_maps_accessibility_nodes_to_existing_actions() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "desk-1".into(),
            display_name: "Desk 1".into(),
            status: DeviceStatus::Online,
        }]);
        shell.begin_connect("desk-1").unwrap();

        let update = build_accesskit_tree(&shell);
        assert_eq!(update.nodes.len(), 3);
        assert_eq!(
            desktop_action_for_node(&shell, NodeId(1)),
            Some(DesktopAction::AllowPermission)
        );
        assert_eq!(
            desktop_action_for_node(&shell, NodeId(2)),
            Some(DesktopAction::DenyPermission)
        );
    }
}
