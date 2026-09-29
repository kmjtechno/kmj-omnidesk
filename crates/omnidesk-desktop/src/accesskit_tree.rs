use accesskit::{Action, Node, NodeId, Rect, Role, TreeId, TreeInfo, TreeUpdate};
use omnidesk_core::product_shell::ProductShell;

use crate::{DesktopAction, controls_for_shell, presentation_for};

pub const ROOT_NODE_ID: NodeId = NodeId(0);

fn control_node_id(index: usize) -> NodeId {
    NodeId(u64::try_from(index + 1).expect("control index fits u64"))
}

#[must_use]
pub fn desktop_action_for_node(shell: &ProductShell, node_id: NodeId) -> Option<DesktopAction> {
    controls_for_shell(shell)
        .into_iter()
        .enumerate()
        .find(|(index, control)| control.enabled && control_node_id(*index) == node_id)
        .map(|(_, control)| control.action)
}

fn control_bounds(index: usize) -> Rect {
    let row = f64::from(u32::try_from(index).expect("control index fits u32"));
    let y0 = row.mul_add(62.0, 116.0);
    Rect {
        x0: 214.0,
        y0,
        x1: 910.0,
        y1: y0 + 48.0,
    }
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
    let presentation = presentation_for(shell);
    let controls = controls_for_shell(shell);
    let mut child_ids = Vec::with_capacity(controls.len());
    let mut nodes = Vec::with_capacity(controls.len() + 1);

    for (index, control) in controls.iter().enumerate() {
        let id = control_node_id(index);
        child_ids.push(id);

        let mut node = Node::new(Role::Button);
        node.set_label(&control.label);
        node.set_bounds(control_bounds(index));
        node.add_action(Action::Focus);
        if control.enabled {
            node.add_action(Action::Click);
        }
        nodes.push((id, node));
    }

    let mut root = Node::new(Role::Window);
    root.set_label(format!("{} — {}", presentation.title, presentation.status));
    root.set_bounds(Rect {
        x0: 0.0,
        y0: 0.0,
        x1: 960.0,
        y1: 640.0,
    });
    root.set_children(child_ids.clone());
    nodes.insert(0, (ROOT_NODE_ID, root));

    let default_focus = child_ids.first().copied().unwrap_or(ROOT_NODE_ID);
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
            Some(DesktopAction::ConnectDevice(0))
        );
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
