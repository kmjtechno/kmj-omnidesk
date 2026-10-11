fn main() {
    let shell = crate::ProductShell::new();
    let devices = shell.devices();
    println!("Devices: {:?}", devices);
    println!("Devices len: {}", devices.len());
    println!("Devices is_empty: {}", devices.is_empty());
    let online = devices
        .iter()
        .filter(|device| device.status == crate::DeviceStatus::Online)
        .count();
    println!("Online count: {}", online);
}