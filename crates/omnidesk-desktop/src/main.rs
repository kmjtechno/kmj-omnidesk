use omnidesk_core::product_shell::{PrimaryView, ProductShell};
use omnidesk_desktop::controls_for;

fn main() {
    let shell = ProductShell::new();
    println!("KMJ OmniDesk Desktop");
    for control in controls_for(shell.primary_view()) {
        println!("[{}] {}", control.keyboard_key, control.label);
    }
}
