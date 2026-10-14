//! Produces authentic renderer pixels for the exact owner-locked 1419x611
//! desktop design frame. This is a deterministic disconnected EMPTY STATE,
//! NOT an actual remote session or an interactive native window capture.

use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use omnidesk_core::product_shell::ProductShell;
use omnidesk_desktop::{presentation_for, render::render_shell};

const WIDTH: usize = 1419;
const HEIGHT: usize = 611;

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
