//! Render-only receipts for the approved KMJ `OmniDesk` V5 native UI.
//!
//! PNG captures come directly from the Rust software renderer; these are
//! NOT Windows desktop captures, live network streams or connected sessions.
//! No test credentials, passwords or session metrics are written to images.
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use omnidesk_core::product_shell::{NavTab, ProductShell};
use omnidesk_desktop::{presentation_for, render::render_shell};

fn save_png(path: &Path, pixels: &[u32], width: usize, height: usize) -> io::Result<()> {
    let width_u32 = u32::try_from(width).map_err(io::Error::other)?;
    let height_u32 = u32::try_from(height).map_err(io::Error::other)?;
    let mut raw_rgb = Vec::with_capacity(pixels.len() * 3);
    for &pixel in pixels {
        raw_rgb.push(u8::try_from((pixel >> 16) & 0xff).expect("red"));
        raw_rgb.push(u8::try_from((pixel >> 8) & 0xff).expect("green"));
        raw_rgb.push(u8::try_from(pixel & 0xff).expect("blue"));
    }
    image::save_buffer_with_format(
        path,
        &raw_rgb,
        width_u32,
        height_u32,
        image::ColorType::Rgb8,
        image::ImageFormat::Png,
    )
    .map_err(io::Error::other)
}

fn render_to_png(
    shell: &ProductShell,
    out_dir: &Path,
    filename: &str,
    width: usize,
    height: usize,
) -> io::Result<()> {
    let model = presentation_for(shell);
    let mut pixels = vec![0_u32; width * height];
    render_shell(&mut pixels, width, height, &model);
    save_png(&out_dir.join(filename), &pixels, width, height)
}

fn main() -> io::Result<()> {
    let out_dir = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("target/v5_captures"), PathBuf::from);
    fs::create_dir_all(&out_dir)?;

    let mut shell = ProductShell::new();
    // Illustrative, non-operational ID used only for offline renderer QA.
    shell.set_local_device_id("KMJ-000-000-000");

    // The locked design must retain Connect + Share + Remote Display at
    // typical compact and full-size desktop resolutions.
    for (name, width, height) in [
        ("01_remote_access_small.png", 800, 600),
        ("02_remote_access_iconrail.png", 960, 640),
        ("04_remote_access_1024.png", 1024, 768),
        ("03_remote_access_compact.png", 1419, 611),
        ("10_remote_access_laptop.png", 1280, 800),
        // Exact size of the owner's 2026-11-12 screenshot, to detect
        // inspector and Connect/Share overlap regressions on the real fold.
        ("12_owner_screenshot_1309.png", 1309, 777),
        ("11_remote_access_wide.png", 1920, 1080),
    ] {
        render_to_png(&shell, &out_dir, name, width, height)?;
    }

    // Match the six *visible* destinations of the approved V5 design.
    for (name, tab) in [
        ("06_trusted_devices.png", NavTab::TrustedDevices),
        ("07_sessions.png", NavTab::Connections),
        ("08_file_transfer.png", NavTab::FileTransfer),
        ("09_security_center.png", NavTab::Security),
        ("10_preferences.png", NavTab::Settings),
    ] {
        shell.set_nav_tab(tab);
        render_to_png(&shell, &out_dir, name, 1419, 800)?;
    }
    shell.set_nav_tab(NavTab::TrustedDevices);
    render_to_png(&shell, &out_dir, "11_trusted_compact.png", 960, 640)?;

    let mut receipt = BufWriter::new(File::create(out_dir.join("RECEIPT.txt"))?);
    writeln!(
        receipt,
        "KMJ_OMNIDESK_V5_CAPTURE_TYPE=OFFLINE_NATIVE_RENDER_BUFFER_PNG"
    )?;
    writeln!(receipt, "VERIFIED_NETWORK_SESSION=NO")?;
    writeln!(receipt, "CONNECTED_DESKTOP_CAPTURE=NO")?;
    writeln!(receipt, "WINDOWS_EXE_SCREENSHOT=NO")?;
    writeln!(receipt, "SCREEN_COUNT=13")?;
    writeln!(receipt, "BROWSER_MOCKUP=NO")?;
    receipt.flush()?;
    println!(
        "V5 offline Rust renderer PNG captures: {}",
        out_dir.display()
    );
    Ok(())
}
