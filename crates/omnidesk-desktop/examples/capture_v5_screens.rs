//! Produces authentic pixel-perfect render captures for all KMJ OmniDesk V5 native screens.

use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
};

use omnidesk_core::product_shell::{
    ConnectionStats, DeviceStatus, DeviceSummary, NavTab, PermissionDecision, ProductShell,
};
use omnidesk_desktop::{presentation_for, render::render_shell};

const WIDTH: usize = 1419;
const HEIGHT: usize = 700;

fn save_ppm(path: &PathBuf, pixels: &[u32]) -> std::io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    writeln!(file, "P6\n{WIDTH} {HEIGHT}\n255")?;
    for &pixel in pixels {
        let rgb = [
            u8::try_from((pixel >> 16) & 0xff).expect("bounded red"),
            u8::try_from((pixel >> 8) & 0xff).expect("bounded green"),
            u8::try_from(pixel & 0xff).expect("bounded blue"),
        ];
        file.write_all(&rgb)?;
    }
    file.flush()
}

fn render_to_ppm(shell: &ProductShell, path: &PathBuf) -> std::io::Result<()> {
    let model = presentation_for(shell);
    let mut pixels = vec![0_u32; WIDTH * HEIGHT];
    render_shell(&mut pixels, WIDTH, HEIGHT, &model);
    save_ppm(path, &pixels)
}

fn main() -> std::io::Result<()> {
    let out_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/v5_captures"));
    fs::create_dir_all(&out_dir)?;

    // 1. Remote Access Screen (default view)
    let mut shell1 = ProductShell::new();
    shell1.set_local_device_id("KMJ-571-752-800");
    render_to_ppm(&shell1, &out_dir.join("01_remote_access.ppm"))?;

    // 2. Connected Remote Workspace Screen
    let mut shell2 = ProductShell::new();
    shell2.set_local_device_id("KMJ-571-752-800");
    shell2.replace_devices(vec![DeviceSummary {
        id: "KMJ-482-731-906".into(),
        display_name: "Engineering Desktop".into(),
        status: DeviceStatus::Online,
    }]);
    shell2.begin_connect("KMJ-482-731-906").unwrap();
    shell2.decide_permission(PermissionDecision::Allow);
    shell2.update_connection_stats(ConnectionStats {
        latency_ms: 2,
        bitrate_kbps: 8400,
        fps: 60,
    });
    render_to_ppm(&shell2, &out_dir.join("02_connected_workspace.ppm"))?;

    // 3. Trusted Devices Directory Screen
    let mut shell3 = ProductShell::new();
    shell3.set_local_device_id("KMJ-571-752-800");
    shell3.set_nav_tab(NavTab::Connections);
    render_to_ppm(&shell3, &out_dir.join("03_trusted_devices.ppm"))?;

    // 4. Sessions & History Screen
    let mut shell4 = ProductShell::new();
    shell4.set_local_device_id("KMJ-571-752-800");
    shell4.set_nav_tab(NavTab::RemoteActions);
    render_to_ppm(&shell4, &out_dir.join("04_sessions.ppm"))?;

    // 5. Secure File Transfer Screen
    let mut shell5 = ProductShell::new();
    shell5.set_local_device_id("KMJ-571-752-800");
    shell5.set_nav_tab(NavTab::FileTransfer);
    render_to_ppm(&shell5, &out_dir.join("05_file_transfer.ppm"))?;

    // 6. Security Center Screen
    let mut shell6 = ProductShell::new();
    shell6.set_local_device_id("KMJ-571-752-800");
    shell6.set_nav_tab(NavTab::Security);
    render_to_ppm(&shell6, &out_dir.join("06_security_center.ppm"))?;

    // 7. Preferences Screen
    let mut shell7 = ProductShell::new();
    shell7.set_local_device_id("KMJ-571-752-800");
    shell7.set_nav_tab(NavTab::Settings);
    render_to_ppm(&shell7, &out_dir.join("07_preferences.ppm"))?;

    println!("All V5 PPM captures generated successfully in {:?}", out_dir);
    Ok(())
}
