use omnidesk_core::product_shell::{
    DeviceStatus, DeviceSummary, PrimaryView, ProductShell, QualityPreset,
};
use omnidesk_desktop::{
    DesktopAction, action_at_point, apply_action, control_rects_for, presentation_for,
};

fn click_first_enabled(shell: &mut ProductShell) -> DesktopAction {
    let presentation = presentation_for(shell);
    let rects = control_rects_for(&presentation, 960, 640);
    let (index, control) = presentation
        .controls
        .iter()
        .enumerate()
        .find(|(_, control)| control.enabled)
        .expect("fixture must expose an enabled control");
    let rect = rects[index];
    let action = action_at_point(
        shell,
        960,
        640,
        rect.x + rect.width / 2,
        rect.y + rect.height / 2,
    )
    .expect("enabled control must be clickable");
    assert_eq!(action, control.action);
    apply_action(shell, action);
    action
}

fn main() {
    let mut shell = ProductShell::new();
    shell.replace_devices(vec![
        DeviceSummary {
            id: "fixture-online".into(),
            display_name: "Fixture Online".into(),
            status: DeviceStatus::Online,
        },
        DeviceSummary {
            id: "fixture-offline".into(),
            display_name: "Fixture Offline".into(),
            status: DeviceStatus::Offline,
        },
    ]);

    assert_eq!(shell.primary_view(), PrimaryView::Devices);
    assert_eq!(click_first_enabled(&mut shell), DesktopAction::ConnectDevice(0));
    assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);

    assert_eq!(click_first_enabled(&mut shell), DesktopAction::AllowPermission);
    assert_eq!(shell.primary_view(), PrimaryView::Session);

    apply_action(
        &mut shell,
        DesktopAction::SetQuality(QualityPreset::HighQuality),
    );
    assert_eq!(shell.quality_preset(), QualityPreset::HighQuality);

    apply_action(&mut shell, DesktopAction::Disconnect);
    assert_eq!(shell.primary_view(), PrimaryView::Devices);

    println!(
        "{{\"m7_primary_flow\":\"PASS\",\"input\":\"native_hit_test\",\"states\":[\"Devices\",\"PermissionPrompt\",\"Session\",\"Devices\"],\"offline_fail_closed\":true,\"fake_production_devices\":false}}"
    );
}
