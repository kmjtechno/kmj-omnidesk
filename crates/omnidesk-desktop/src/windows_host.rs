#![cfg(windows)]

use std::{num::NonZeroU32, path::PathBuf, sync::Arc};

use accesskit::{Action, NodeId};
use accesskit_winit::{Adapter, Event as AccessKitEvent, WindowEvent as AccessKitWindowEvent};
use omnidesk_core::{
    device_enrollment::EnrollmentCoordinator,
    product_shell::{DeviceStatus, ProductShell},
    transport::LoopbackTransport,
    transport_adapter::TransportSessionAdapter,
    trusted_device_store::TrustedDeviceStore,
};
use softbuffer::{Context, Surface};
use winit::{
    application::ApplicationHandler,
    event::{ElementState, MouseButton, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy, OwnedDisplayHandle},
    window::{Icon, Window, WindowAttributes, WindowId},
};

use crate::{
    AccessibilityNode, DesktopAction, accessibility_snapshot,
    accesskit_tree::{build_accesskit_tree_with_focus, desktop_action_for_node},
    action_at_point, apply_action, apply_key,
    brand::official_kmj_mark,
    controls_for_shell,
    layout::{initial_window_inner_size, initial_window_origin},
    presentation_for,
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

/// A visible local permission prompt must not be confused with an authenticated
/// network session. Until a real peer transport is wired, reject every path
/// that could elevate an unverified device to session authorization.
fn refuse_unverified_session_action(
    shell: &mut ProductShell,
    has_authorized_transport: bool,
    action: DesktopAction,
) -> bool {
    if matches!(
        action,
        DesktopAction::ConnectDevice(..)
            | DesktopAction::RetryConnect
            | DesktopAction::AllowPermission
    ) {
        if has_authorized_transport {
            return false;
        }
        shell.disconnect();
        shell.set_error(
            "Remote connection unavailable: authenticated peer transport is not established",
        );
        return true;
    }
    false
}

struct DesktopHost {
    // Drop platform adapters/surfaces before the window and context that provide their handles.
    surface: Option<Surface<OwnedDisplayHandle, Arc<Window>>>,
    adapter: Option<Adapter>,
    window: Option<Arc<Window>>,
    context: Context<OwnedDisplayHandle>,
    event_loop_proxy: EventLoopProxy<AccessKitEvent>,
    shell: ProductShell,
    enrollment_coordinator: EnrollmentCoordinator,
    _store_path: PathBuf,
    session_adapter: Option<TransportSessionAdapter<LoopbackTransport>>,
    accessibility: Vec<AccessibilityNode>,
    accessibility_focus: Option<NodeId>,
    cursor_position: Option<(usize, usize)>,
}

impl DesktopHost {
    fn new(
        context: Context<OwnedDisplayHandle>,
        event_loop_proxy: EventLoopProxy<AccessKitEvent>,
    ) -> Self {
        let store_path = std::env::var_os("LOCALAPPDATA")
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("KMJ-OmniDesk")
            .join("trusted_devices.json");
        let mut shell = ProductShell::new();
        let store = match TrustedDeviceStore::load_from_path(&store_path) {
            Ok(store) => store,
            Err(err) => {
                // Never silently accept a damaged trust store or overwrite it.
                shell.set_error(format!("Trusted device store unavailable: {err}"));
                TrustedDeviceStore::new()
            }
        };
        if !store.is_empty() {
            // A persisted status is not proof of a live authenticated peer.
            let mut devices = store.to_device_summaries();
            for device in &mut devices {
                device.status = DeviceStatus::Offline;
            }
            shell.replace_devices(devices);
        }
        let accessibility = accessibility_snapshot(&shell);
        Self {
            surface: None,
            adapter: None,
            window: None,
            context,
            event_loop_proxy,
            shell,
            enrollment_coordinator: EnrollmentCoordinator::new(),
            _store_path: store_path,
            session_adapter: None,
            accessibility,
            accessibility_focus: None,
            cursor_position: None,
        }
    }

    fn handle_enroll_device(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        match self.enrollment_coordinator.create_challenge(now) {
            Ok(challenge) => {
                let hex_prefix = format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    challenge.nonce[0], challenge.nonce[1], challenge.nonce[2], challenge.nonce[3]
                );
                self.shell.set_error(format!(
                    "Enrollment challenge issued ({hex_prefix}... expires in 300s); awaiting peer signature"
                ));
            }
            Err(err) => {
                self.shell
                    .set_error(format!("Enrollment challenge failed: {err}"));
            }
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
                    let has_auth = self
                        .session_adapter
                        .as_ref()
                        .is_some_and(TransportSessionAdapter::is_control_authorized);
                    if action == DesktopAction::EnrollDevice {
                        self.handle_enroll_device();
                    } else if !refuse_unverified_session_action(&mut self.shell, has_auth, action) {
                        apply_action(&mut self.shell, action);
                    }
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
            let window_icon = official_kmj_mark()
                .and_then(|mark| Icon::from_rgba(mark.rgba.clone(), mark.width, mark.height).ok());
            let monitor = event_loop
                .primary_monitor()
                .or_else(|| event_loop.available_monitors().next());
            let initial_size = monitor.as_ref().map(|monitor| {
                let size = monitor.size();
                (size.width, size.height, monitor.scale_factor())
            });
            let (inner_width, inner_height) = initial_window_inner_size(initial_size);
            let attributes = WindowAttributes::default()
                .with_title(title)
                .with_visible(false)
                .with_window_icon(window_icon)
                .with_inner_size(winit::dpi::LogicalSize::new(inner_width, inner_height));
            // Physical initial placement is as important as inner-size
            // fitting: hosted desktops can default to (156,156) on a
            // 1024x768 display and crop an otherwise well-sized window.
            let attributes = if let Some(monitor) = monitor {
                let position = monitor.position();
                let (left, top) = initial_window_origin(position.x, position.y);
                attributes.with_position(winit::dpi::PhysicalPosition::new(left, top))
            } else {
                attributes
            };
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
                        let has_auth = self
                            .session_adapter
                            .as_ref()
                            .is_some_and(TransportSessionAdapter::is_control_authorized);
                        if action == DesktopAction::EnrollDevice {
                            self.handle_enroll_device();
                        } else if !refuse_unverified_session_action(
                            &mut self.shell,
                            has_auth,
                            action,
                        ) {
                            apply_action(&mut self.shell, action);
                        }
                        self.accessibility_focus = None;
                        self.refresh_presentation();
                    }
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                if let Some(text) = event.text {
                    if let Some(key) = text.chars().next() {
                        let selected_action = controls_for_shell(&self.shell)
                            .into_iter()
                            .find(|control| {
                                control.enabled && control.keyboard_key == key.to_ascii_lowercase()
                            })
                            .map(|control| control.action);
                        let has_auth = self
                            .session_adapter
                            .as_ref()
                            .is_some_and(TransportSessionAdapter::is_control_authorized);
                        if selected_action == Some(DesktopAction::EnrollDevice) {
                            self.handle_enroll_device();
                            self.accessibility_focus = None;
                            self.refresh_presentation();
                        } else if selected_action.is_some_and(|action| {
                            refuse_unverified_session_action(&mut self.shell, has_auth, action)
                        }) || apply_key(&mut self.shell, key)
                        {
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
    use super::{MAX_PIXEL_OFFSET, refuse_unverified_session_action, to_pixel};
    use crate::DesktopAction;
    use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, PrimaryView, ProductShell};

    #[test]
    fn unverified_online_device_cannot_enter_session_by_click_or_retry() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "unverified-peer".to_owned(),
            display_name: "Unverified peer".to_owned(),
            status: DeviceStatus::Online,
        }]);
        let revision = shell.device_revision();
        for action in [
            DesktopAction::ConnectDevice(0, revision),
            DesktopAction::RetryConnect,
            DesktopAction::AllowPermission,
        ] {
            assert!(refuse_unverified_session_action(&mut shell, false, action));
            assert_eq!(shell.primary_view(), PrimaryView::Devices);
            assert!(shell.selected_device().is_none());
            assert!(shell.last_error().is_some());
        }
    }

    #[test]
    fn authorized_transport_permits_session_actions() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "verified-peer".to_owned(),
            display_name: "Verified peer".to_owned(),
            status: DeviceStatus::Offline,
        }]);
        let revision = shell.device_revision();
        for action in [
            DesktopAction::ConnectDevice(0, revision),
            DesktopAction::RetryConnect,
            DesktopAction::AllowPermission,
        ] {
            assert!(!refuse_unverified_session_action(&mut shell, true, action));
        }
    }

    #[test]
    fn non_session_navigation_is_not_blocked() {
        let mut shell = ProductShell::new();
        assert!(!refuse_unverified_session_action(
            &mut shell,
            false,
            DesktopAction::ToggleHelp
        ));
        assert!(shell.last_error().is_none());
    }

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
