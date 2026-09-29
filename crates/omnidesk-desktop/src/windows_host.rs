#![cfg(windows)]

use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop},
    window::{Window, WindowAttributes, WindowId},
};

#[derive(Default)]
struct DesktopHost {
    window: Option<Window>,
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
        if matches!(event, WindowEvent::CloseRequested) {
            event_loop.exit();
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
