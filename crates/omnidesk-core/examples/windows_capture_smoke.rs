#[cfg(windows)]
fn main() {
    use std::time::Instant;

    use omnidesk_core::{media::CaptureAdapter, windows_capture::WindowsDesktopCapture};

    let mut capture = WindowsDesktopCapture;
    let started = Instant::now();
    let frame = capture.capture().expect("Windows desktop capture");
    println!(
        "{{\"schema_version\":1,\"kind\":\"windows_desktop_capture_smoke\",\"width\":{},\"height\":{},\"stride\":{},\"bytes\":{},\"elapsed_ms\":{}}}",
        frame.width(),
        frame.height(),
        frame.stride(),
        frame.data().len(),
        started.elapsed().as_millis()
    );
}

#[cfg(not(windows))]
fn main() {
    println!(
        "{{\"schema_version\":1,\"kind\":\"windows_desktop_capture_smoke\",\"status\":\"not_windows\"}}"
    );
}
