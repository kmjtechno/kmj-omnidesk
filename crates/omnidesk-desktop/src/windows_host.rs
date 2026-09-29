#![cfg(windows)]

use omnidesk_core::product_shell::ProductShell;
use winit::{
    application::ApplicationHandler,
    event::{ElementState, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop},
    window::{Window, WindowAttributes, WindowId},
};

use crate::{AccessibilityNode, accessibility_snapshot, apply_key};

struct DesktopHost {
    window: Option<Window>,
    shell: ProductShell,
    accessibility: Vec<AccessibilityNode>,
}

impl Default for DesktopHost {
    fn default() -> Self {
        let shell = ProductShell::new();
        let accessibility = accessibility_snapshot(&shell);
        Self {
            window: None,
            shell,
            accessibility,
        }
    }
}

impl ApplicationHandler for DesktopHost {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_none() {
            let attributes = WindowAttributes::default()
                .with_title("KMJ OmniDesk")
                .with_inner_size(winit::dpi::LogicalSize::new(960.0, 640.0));
            self.window = Some(
                event_loop
                    .create_window(attributes)
                    .expect("native desktop window creation must succeed"),
            );
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                if let Some(text) = event.text {
                    if let Some(key) = text.chars().next() {
                        if apply_key(&mut self.shell, key) {
                            self.accessibility = accessibility_snapshot(&self.shell);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Runs the safe native Windows host for the M7 desktop shell.
///
/// # Errors
///
/// Returns the event-loop error when the native host cannot start or run.
pub fn run() -> Result<(), winit::error::EventLoopError> {
    let event_loop = EventLoop::new()?;
    event_loop.run_app(&mut DesktopHost::default())
}
