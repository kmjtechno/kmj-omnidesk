#![cfg(windows)]

use std::{num::NonZeroU32, sync::Arc};

use omnidesk_core::product_shell::ProductShell;
use softbuffer::{Context, Surface};
use winit::{
    application::ApplicationHandler,
    event::{ElementState, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, OwnedDisplayHandle},
    window::{Window, WindowAttributes, WindowId},
};

use crate::{
    AccessibilityNode, accessibility_snapshot, apply_key, presentation_for, render::render_shell,
};

struct DesktopHost {
    // Drop the surface before the window and context that provide its handles.
    surface: Option<Surface<OwnedDisplayHandle, Arc<Window>>>,
    window: Option<Arc<Window>>,
    context: Context<OwnedDisplayHandle>,
    shell: ProductShell,
    accessibility: Vec<AccessibilityNode>,
}

impl DesktopHost {
    fn new(context: Context<OwnedDisplayHandle>) -> Self {
        let shell = ProductShell::new();
        let accessibility = accessibility_snapshot(&shell);
        Self {
            surface: None,
            window: None,
            context,
            shell,
            accessibility,
        }
    }

    fn refresh_presentation(&mut self) {
        self.accessibility = accessibility_snapshot(&self.shell);
        if let Some(window) = self.window.as_ref() {
            let presentation = presentation_for(&self.shell);
            window.set_title(&format!("{} — {}", presentation.title, presentation.status));
            window.request_redraw();
        }
    }

    fn redraw(&mut self) {
        let Some(window) = self.window.as_ref() else {
            return;
        };
        let Some(surface) = self.surface.as_mut() else {
            return;
        };
        let size = window.inner_size();
        let Some(width) = NonZeroU32::new(size.width) else {
            return;
        };
        let Some(height) = NonZeroU32::new(size.height) else {
            return;
        };

        surface
            .resize(width, height)
            .expect("native render surface resize must succeed");
        let presentation = presentation_for(&self.shell);
        let mut buffer = surface
            .buffer_mut()
            .expect("native render buffer acquisition must succeed");
        render_shell(
            &mut buffer,
            usize::try_from(width.get()).expect("window width fits usize"),
            usize::try_from(height.get()).expect("window height fits usize"),
            &presentation,
        );
        buffer
            .present()
            .expect("native render buffer presentation must succeed");
    }
}

impl ApplicationHandler for DesktopHost {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_none() {
            let presentation = presentation_for(&self.shell);
            let title = format!("{} — {}", presentation.title, presentation.status);
            let attributes = WindowAttributes::default()
                .with_title(title)
                .with_inner_size(winit::dpi::LogicalSize::new(960.0, 640.0));
            let window = Arc::new(
                event_loop
                    .create_window(attributes)
                    .expect("native desktop window creation must succeed"),
            );
            let surface = Surface::new(&self.context, Arc::clone(&window))
                .expect("native render surface creation must succeed");
            window.request_redraw();
            self.surface = Some(surface);
            self.window = Some(window);
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
            WindowEvent::RedrawRequested => self.redraw(),
            WindowEvent::Resized(_) => {
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                if let Some(text) = event.text {
                    if let Some(key) = text.chars().next() {
                        if apply_key(&mut self.shell, key) {
                            self.refresh_presentation();
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
    let context = Context::new(event_loop.owned_display_handle())
        .expect("native render context creation must succeed");
    event_loop.run_app(&mut DesktopHost::new(context))
}
