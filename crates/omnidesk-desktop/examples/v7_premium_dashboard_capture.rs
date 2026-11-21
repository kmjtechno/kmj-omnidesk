//! Export the exact owner-approved V7 native Rust renderer artboard
//! (1672 × 941), as a deterministic disconnected-state PPM frame.
//!
//! This is not a remote session, not a native Windows window screenshot,
//! and not evidence of final visual equivalence with the approved PNG.

use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use omnidesk_core::product_shell::ProductShell;
use omnidesk_desktop::{presentation_for, render::render_shell};

const WIDTH: usize = 1672;
const HEIGHT: usize = 941;

fn main() -> io::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path required"))?;

    let shell = ProductShell::new();
    let model = presentation_for(&shell);
    let mut pixels = vec![0_u32; WIDTH * HEIGHT];
    render_shell(&mut pixels, WIDTH, HEIGHT, &model);

    let mut output = BufWriter::new(File::create(output)?);
    writeln!(output, "P6\n{WIDTH} {HEIGHT}\n255")?;
    for pixel in pixels {
        let rgb = [
            u8::try_from((pixel >> 16) & 0xff).expect("bounded red"),
            u8::try_from((pixel >> 8) & 0xff).expect("bounded green"),
            u8::try_from(pixel & 0xff).expect("bounded blue"),
        ];
        output.write_all(&rgb)?;
    }
    output.flush()
}
