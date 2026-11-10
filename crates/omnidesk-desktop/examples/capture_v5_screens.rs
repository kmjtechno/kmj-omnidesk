//! Render-only receipts for the approved KMJ OmniDesk V5 native UI.
//!
//! These are deterministic pixel-buffer captures, NOT screenshots from a
//! running Windows app and NOT evidence of real remote network sessions.
//! Do not fabricate connection statistics or a "Connected" mock session.
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use omnidesk_core::product_shell::{NavTab, ProductShell};
use omnidesk_desktop::{presentation_for, render::render_shell};

fn save_ppm(path: &Path, pixels: &[u32], width: usize, height: usize) -> io::Result<()> {
    let mut file = BufWriter::new(File::create(path)?);
    writeln!(file, "P6\n{width} {height}\n255")?;
    for &pixel in pixels {
        let rgb = [
            u8::try_from((pixel >> 16) & 0xff).expect("red channel"),
            u8::try_from((pixel >> 8) & 0xff).expect("green channel"),
            u8::try_from(pixel & 0xff).expect("blue channel"),
        ];
        file.write_all(&rgb)?;
    }
    file.flush()
}

fn render_to_ppm(
    shell: &ProductShell,
    out_dir: &Path,
    filename: &str,
    width: usize,
    height: usize,
) -> io::Result<()> {
    let model = presentation_for(shell);
    let mut pixels = vec![0_u32; width * height];
    render_shell(&mut pixels, width, height, &model);
    save_ppm(&out_dir.join(filename), &pixels, width, height)
}

fn main() -> io::Result<()> {
    let out_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/v5_captures"));
    fs::create_dir_all(&out_dir)?;

    let mut shell = ProductShell::new();
    // Illustrative, non-operational ID used only for offline renderer QA.
    shell.set_local_device_id("KMJ-000-000-000");

    // The locked design must retain Connect + Share + Remote Display at
    // typical compact and full-size desktop resolutions.
    for (name, width, height) in [
        ("01_remote_access_compact.ppm", 1419, 611),
        ("02_remote_access_laptop.ppm", 1280, 800),
        ("03_remote_access_wide.ppm", 1920, 1080),
    ] {
        render_to_ppm(&shell, &out_dir, name, width, height)?;
    }

    for (name, tab) in [
        ("04_sessions.ppm", NavTab::Connections),
        ("05_file_transfer.ppm", NavTab::FileTransfer),
        ("06_remote_actions.ppm", NavTab::RemoteActions),
        ("07_automation.ppm", NavTab::Automation),
        ("08_security_center.ppm", NavTab::Security),
        ("09_preferences.ppm", NavTab::Settings),
    ] {
        shell.set_nav_tab(tab);
        render_to_ppm(&shell, &out_dir, name, 1419, 800)?;
    }

    let mut receipt = BufWriter::new(File::create(out_dir.join("RECEIPT.txt"))?);
    writeln!(receipt, "KMJ_OMNIDESK_V5_CAPTURE_TYPE=OFFLINE_NATIVE_RENDER_BUFFER")?;
    writeln!(receipt, "VERIFIED_NETWORK_SESSION=NO")?;
    writeln!(receipt, "CONNECTED_DESKTOP_CAPTURE=NO")?;
    writeln!(receipt, "WINDOWS_EXE_SCREENSHOT=NO")?;
    writeln!(receipt, "SCREEN_COUNT=9")?;
    writeln!(receipt, "BROWSER_MOCKUP=NO")?;
    receipt.flush()?;
    println!("V5 offline Rust renderer captures: {}", out_dir.display());
    Ok(())
}
