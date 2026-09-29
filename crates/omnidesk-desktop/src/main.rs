#[cfg(windows)]
fn main() -> windows::core::Result<()> {
    omnidesk_desktop::windows_host::run()
}

#[cfg(not(windows))]
fn main() {
    use omnidesk_core::product_shell::ProductShell;
    use omnidesk_desktop::controls_for;

    let shell = ProductShell::new();
    println!("KMJ OmniDesk Desktop");
    for control in controls_for(shell.primary_view()) {
        println!("[{}] {}", control.keyboard_key, control.label);
    }
}
