#![cfg(windows)]

use std::{num::NonZeroU32, sync::Arc};

use accesskit::{Action, NodeId};
use accesskit_winit::{Adapter, Event as AccessKitEvent, WindowEvent as AccessKitWindowEvent};
use omnidesk_core::product_shell::ProductShell;
use softbuffer::{Context, Surface};
use winit::{
    application::ApplicationHandler,
    event::{ElementState, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy, OwnedDisplayHandle},
    window::{Window, WindowAttributes, WindowId},
};

use crate::{
    AccessibilityNode, accessibility_snapshot,
    accesskit_tree::{build_accesskit_tree_with_focus, desktop_action_for_node},
    apply_action, apply_key, presentation_for,
    render::render_shell,
};

struct DesktopHost {
    // Drop platform adapters/surfaces before the window and context that provide their handles.
    surface: Option<Surface<OwnedDisplayHandle, Arc<Window>>>,
    adapter: Option<Adapter>,
    window: Option<Arc<Window>>,
    context: Context<OwnedDisplayHandle>,
    event_loop_proxy: EventLoopProxy<AccessKitEvent>,
    shell: ProductShell,
    accessibility: Vec<AccessibilityNode>,
    accessibility_focus: Option<NodeId>,
}

impl DesktopHost {
    fn new(
        context: Context<OwnedDisplayHandle>,
        event_loop_proxy: EventLoopProxy<AccessKitEvent>,
    ) -> Self {
        let shell = ProductShell::new();
        let accessibility = accessibility_snapshot(&shell);
        Self {
            surface: None,
            adapter: None,
            window: None,
            context,
            event_loop_proxy,
            shell,
            accessibility,
            accessibility_focus: None,
        }
    }

    fn update_accessibility_tree(&mut self) {
        let update = build_accesskit_tree_with_focus(&self.shell, self.accessibility_focus);
        if let Some(adapter) = self.adapter.as_mut() {
            adapter.update_if_active(|| update);
        }
    }

    fn refresh_presentation(&mut self) {
        self.accessibility = accessibility_snapshot(&self.shell);
        if self
            .accessibility_focus
            .is_some_and(|id| desktop_action_for_node(&self.shell, id).is_none())
        {
            self.accessibility_focus = None;
        }
        self.update_accessibility_tree();

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

    fn handle_accesskit_action(&mut self, request: accesskit::ActionRequest) {
        match request.action {
            Action::Focus => {
                if desktop_action_for_node(&self.shell, request.target_node).is_some() {
                    self.accessibility_focus = Some(request.target_node);
                    self.update_accessibility_tree();
                }
            }
            Action::Click => {
                if let Some(action) = desktop_action_for_node(&self.shell, request.target_node) {
                    apply_action(&mut self.shell, action);
                    self.accessibility_focus = None;
                    self.refresh_presentation();
                }
            }
            _ => {}
        }
    }
}

impl ApplicationHandler<AccessKitEvent> for DesktopHost {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_none() {
            let presentation = presentation_for(&self.shell);
            let title = format!("{} — {}", presentation.title, presentation.status);
            let attributes = WindowAttributes::default()
                .with_title(title)
                .with_visible(false)
                .with_inner_size(winit::dpi::LogicalSize::new(960.0, 640.0));
            let window = Arc::new(
                event_loop
                    .create_window(attributes)
                    .expect("native desktop window creation must succeed"),
            );
            let surface = Surface::new(&self.context, Arc::clone(&window))
                .expect("native render surface creation must succeed");
            let adapter =
                Adapter::with_event_loop_proxy(event_loop, &window, self.event_loop_proxy.clone());
            window.set_visible(true);
            window.request_redraw();

            self.surface = Some(surface);
            self.adapter = Some(adapter);
            self.window = Some(window);
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        if let (Some(adapter), Some(window)) = (self.adapter.as_mut(), self.window.as_ref()) {
            adapter.process_event(window, &event);
        }

        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => self.redraw(),
            WindowEvent::Resized(_) => {
                self.update_accessibility_tree();
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                if let Some(text) = event.text {
                    if let Some(key) = text.chars().next() {
                        if apply_key(&mut self.shell, key) {
                            self.accessibility_focus = None;
                            self.refresh_presentation();
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: AccessKitEvent) {
        match event.window_event {
            AccessKitWindowEvent::InitialTreeRequested => self.update_accessibility_tree(),
            AccessKitWindowEvent::ActionRequested(request) => {
                self.handle_accesskit_action(request);
            }
            AccessKitWindowEvent::AccessibilityDeactivated => {
                self.accessibility_focus = None;
            }
        }
    }
}

/// Runs the safe native Windows host for the M7 desktop shell.
///
/// # Errors
///
/// Returns the event-loop error when the native host cannot start or run.
pub fn run() -> Result<(), winit::error::EventLoopError> {
    let event_loop = EventLoop::<AccessKitEvent>::with_user_event().build()?;
    let context = Context::new(event_loop.owned_display_handle())
        .expect("native render context creation must succeed");
    let event_loop_proxy = event_loop.create_proxy();
    event_loop.run_app(&mut DesktopHost::new(context, event_loop_proxy))
}
