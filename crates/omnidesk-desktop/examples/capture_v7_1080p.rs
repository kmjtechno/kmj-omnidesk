use omnidesk_core::product_shell::ProductShell;
use omnidesk_desktop::{presentation_for, render::render_shell};
use std::{
    fs::File,
    io::{BufWriter, Write},
};

const WIDTH: usize = 1920;
const HEIGHT: usize = 1040;

fn main() -> std::io::Result<()> {
    let mut shell = ProductShell::new();
    shell.set_local_device_id("734 281 905");
    let model = presentation_for(&shell);
    let mut pixels = vec![0_u32; WIDTH * HEIGHT];
    render_shell(&mut pixels, WIDTH, HEIGHT, &model);

    let output_path = r"C:\Users\KMJ TECHNO\.gemini\antigravity\brain\6ed02b16-26b1-4f9d-9b39-e3cbe2b17e88\scratch\v7_1080p.ppm";
    let mut output = BufWriter::new(File::create(output_path)?);
    writeln!(output, "P6\n{WIDTH} {HEIGHT}\n255")?;
    for pixel in pixels {
        let rgb = [
            ((pixel >> 16) & 0xff) as u8,
            ((pixel >> 8) & 0xff) as u8,
            (pixel & 0xff) as u8,
        ];
        output.write_all(&rgb)?;
    }
    output.flush()?;
    println!("Rendered 1920x1040 successfully");
    Ok(())
}
