fn main() {
    let shell = crate::ProductShell::new();
    let presentation = crate::presentation_for(&shell);
    println!("Summary: '{:?}'", presentation.summary);
    println!("Length: {}", presentation.summary.len());
    println!("Bytes: {:?}", presentation.summary.as_bytes());
    println!("Devices: {}", shell.devices().len());
    println!("Online: {}", shell.devices().iter().filter(|d| d.status == crate::DeviceStatus::Online).count());
}