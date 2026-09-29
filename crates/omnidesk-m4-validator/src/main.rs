use omnidesk_m4_validator::{Manifest, Outcome, validate};
use std::{env, fs, path::Path};

fn main() {
    let mut args = env::args().skip(1);
    let Some(manifest_path) = args.next() else {
        eprintln!("usage: omnidesk-m4-validator <manifest.json> [package-root]");
        std::process::exit(4);
    };
    let bytes = match fs::read(&manifest_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(4)
        }
    };
    let manifest: Manifest = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(3)
        }
    };
    let root = args.next();
    let report = validate(&manifest, root.as_deref().map(Path::new));
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serialization")
    );
    let code = match report.result {
        Outcome::ValidM4Pass => 0,
        Outcome::ValidM4Fail => 2,
        Outcome::InvalidManifest => 3,
    };
    std::process::exit(code);
}
