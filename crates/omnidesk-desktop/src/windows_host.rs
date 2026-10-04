#![cfg(windows)]

use std::{num::NonZeroU32, sync::Arc};

use accesskit::{Action, NodeId};
use accesskit_winit::{Adapter, Event as AccessKitEvent, WindowEvent as AccessKitWindowEvent};
use omnidesk_core::product_shell::ProductShell;
use softbuffer::{Context, Surface};
use winit::{
    application::ApplicationHandler,
    event::{ElementState, MouseButton, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy, OwnedDisplayHandle},
    window::{Window, WindowAttributes, WindowId},
};

use crate::{
    AccessibilityNode, accessibility_snapshot,
    accesskit_tree::{build_accesskit_tree_with_focus, desktop_action_for_node},
    action_at_point, apply_action, apply_key, presentation_for,
    render::render_shell,
};

/// Converts a window-logical coordinate to whole pixels.
///
/// Winit can report sub-pixel or out-of-range cursor positions (negative
/// when a drag leaves the window, and fractional under DPI scaling). A bare
/// `as usize` cast saturates negatives to `0` and truncates toward zero,
/// which silently remaps a pointer to the wrong control. This keeps the
/// value in range instead, so hit testing stays fail-closed.
// `value` is proven finite and non-negative by the guard below, then clamped
// to `MAX_PIXEL_CEILING`, so the cast is in range by construction.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "non-finite and negative coordinates are rejected before the cast"
)]
fn to_pixel(value: f64) -> Option<usize> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    // Clamping in `f64` before the single conversion keeps this total for
    // every finite input without depending on `TryFrom<f64>`, which std
    // does not provide.
    Some(value.floor().min(MAX_PIXEL_CEILING) as usize)
}

/// Largest pixel offset the native host will ever hit-test against, as the
/// integer the pointer hit test consumes. Test-only; the runtime path
/// clamps against [`MAX_PIXEL_CEILING`].
#[cfg(test)]
const MAX_PIXEL_OFFSET: usize = u32::MAX as usize;

/// Same bound expressed as `f64`, so clamping can happen before conversion.
const MAX_PIXEL_CEILING: f64 = u32::MAX as f64;

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
    cursor_position: Option<(usize, usize)>,
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
            cursor_position: None,
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

    fn handle_accesskit_action(&mut self, request: &accesskit::ActionRequest) {
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
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor_position = match (to_pixel(position.x), to_pixel(position.y)) {
                    (Some(x), Some(y)) => Some((x, y)),
                    _ => None,
                };
            }
            WindowEvent::MouseInput {
                state: ElementState::Pressed,
                button: MouseButton::Left,
                ..
            } => {
                if let (Some((x, y)), Some(window)) = (self.cursor_position, self.window.as_ref()) {
                    let size = window.inner_size();
                    if let Some(action) = action_at_point(
                        &self.shell,
                        usize::try_from(size.width).unwrap_or(usize::MAX),
                        usize::try_from(size.height).unwrap_or(usize::MAX),
                        x,
                        y,
                    ) {
                        apply_action(&mut self.shell, action);
                        self.accessibility_focus = None;
                        self.refresh_presentation();
                    }
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
                self.handle_accesskit_action(&request);
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
///
/// # Panics
///
/// Panics when no usable graphics context can be created for the host
/// window. This is a startup-only precondition: a missing or unusable
/// display/GPU context is not a recoverable session state, so failing
/// loudly at launch is preferred over running a shell that cannot render.
pub fn run() -> Result<(), winit::error::EventLoopError> {
    let event_loop = EventLoop::<AccessKitEvent>::with_user_event().build()?;
    let context = Context::new(event_loop.owned_display_handle())
        .expect("native render context creation must succeed");
    let event_loop_proxy = event_loop.create_proxy();
    event_loop.run_app(&mut DesktopHost::new(context, event_loop_proxy))
}

#[cfg(test)]
mod tests {
    use super::{MAX_PIXEL_OFFSET, to_pixel};

    #[test]
    fn whole_pixel_coordinates_pass_through_unchanged() {
        assert_eq!(to_pixel(0.0), Some(0));
        assert_eq!(to_pixel(1.0), Some(1));
        assert_eq!(to_pixel(960.0), Some(960));
    }

    #[test]
    fn fractional_coordinates_floor_to_the_pixel_below() {
        // A bare `as usize` cast truncates toward zero; 12.7 must not be
        // reported as pixel 12 being the hit target.
        assert_eq!(to_pixel(12.7), Some(12));
        assert_eq!(to_pixel(12.999), Some(12));
        assert_eq!(to_pixel(0.5), Some(0));
    }

    #[test]
    fn negative_coordinates_are_rejected_not_clamped_to_origin() {
        // `(-4.0f64) as usize` saturates to 0, which would remap a drag that
        // left the window onto the top-left control. Rejecting keeps
        // hit testing fail-closed.
        assert_eq!(to_pixel(-4.0), None);
        assert_eq!(to_pixel(-0.5), None);
        assert_eq!(to_pixel(f64::NEG_INFINITY), None);
    }

    #[test]
    fn non_finite_coordinates_are_rejected() {
        assert_eq!(to_pixel(f64::NAN), None);
        assert_eq!(to_pixel(f64::INFINITY), None);
        assert_eq!(to_pixel(f64::NEG_INFINITY), None);
    }

    #[test]
    fn huge_coordinates_clamp_instead_of_wrapping() {
        assert_eq!(to_pixel(f64::MAX), Some(MAX_PIXEL_OFFSET));
        assert_eq!(to_pixel(1e30), Some(MAX_PIXEL_OFFSET));
    }
}
