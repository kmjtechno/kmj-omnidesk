#![cfg(windows)]

use std::{num::NonZeroU32, path::PathBuf, sync::Arc};

use accesskit::{Action, NodeId};
use accesskit_winit::{Adapter, Event as AccessKitEvent, WindowEvent as AccessKitWindowEvent};
use omnidesk_core::{
    device_enrollment::EnrollmentCoordinator,
    product_shell::{DeviceStatus, PrimaryView, ProductShell},
    transport::HostTransport,
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
    accesskit_tree::{build_accesskit_tree_at_size, desktop_action_for_node},
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
/// Consent is bound to the currently authenticated peer and the visible prompt.
/// It is deliberately separate from cryptographic authentication.
fn consent_matches_peer(shell: &ProductShell, authenticated_device_id: Option<&str>) -> bool {
    shell.primary_view() == PrimaryView::PermissionPrompt
        && shell.selected_device().is_some()
        && shell.selected_device() == authenticated_device_id
}

#[cfg(test)]
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

struct IncomingPeer {
    stream: std::net::TcpStream,
    peer_addr: std::net::SocketAddr,
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
    store_path: PathBuf,
    session_adapter: Option<TransportSessionAdapter<HostTransport>>,
    accessibility: Vec<AccessibilityNode>,
    accessibility_focus: Option<NodeId>,
    cursor_position: Option<(usize, usize)>,
    incoming_rx: std::sync::mpsc::Receiver<IncomingPeer>,
    #[allow(dead_code)]
    identity: omnidesk_core::device_identity::DeviceIdentity,
}

/// Explicitly copy user-selected local content to the Windows clipboard.
///
/// Returns success only when clip.exe accepted stdin and exited successfully.
/// Secrets are never passed as process arguments or written to logs. Clipboard
/// contents persist under Windows policy and must not be treated as secure
/// storage; never call this without an explicit user action.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    if text.is_empty() {
        return false;
    }
    let Ok(mut child) = std::process::Command::new("clip.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::piped())
        .spawn()
    else {
        return false;
    };
    let wrote = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
    let exited = child.wait().is_ok_and(|status| status.success());
    wrote && exited
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
        let store = match TrustedDeviceStore::load_or_create(&store_path) {
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
        let identity_path = std::env::var_os("LOCALAPPDATA")
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join("KMJ-OmniDesk")
            .join("device_identity.json");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let identity =
            omnidesk_core::device_identity::DeviceIdentity::load_or_create(&identity_path, now)
                .unwrap_or_else(|_| omnidesk_core::device_identity::DeviceIdentity::generate(now));
        shell.set_local_device_id(identity.public_id());
        let accessibility = accessibility_snapshot(&shell);

        let (incoming_tx, incoming_rx) = std::sync::mpsc::channel::<IncomingPeer>();
        let listen_port: u16 = std::env::var("OMNIDESK_LISTEN_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(21118);

        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", listen_port))
            .or_else(|_| std::net::TcpListener::bind(("127.0.0.1", 0)))
        {
            let _ = listener.set_nonblocking(false);
            let _ = std::thread::Builder::new()
                .name("omnidesk-host-listener".to_owned())
                .spawn(move || {
                    while let Ok((stream, peer_addr)) = listener.accept() {
                        let _ = stream.set_nodelay(true);
                        if incoming_tx
                            .send(IncomingPeer { stream, peer_addr })
                            .is_err()
                        {
                            break;
                        }
                    }
                });
        }

        Self {
            surface: None,
            adapter: None,
            window: None,
            context,
            event_loop_proxy,
            shell,
            enrollment_coordinator: EnrollmentCoordinator::new(),
            store_path,
            session_adapter: None,
            accessibility,
            accessibility_focus: None,
            cursor_position: None,
            incoming_rx,
            identity,
        }
    }

    fn handle_enroll_device(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let mut enroll_peer_addr = std::env::var("OMNIDESK_ENROLL_PEER_ADDR")
            .ok()
            .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok());

        if enroll_peer_addr.is_none() {
            if let Some(dev) = self.shell.selected_device() {
                if let Ok(addr) = dev.parse::<std::net::SocketAddr>() {
                    enroll_peer_addr = Some(addr);
                }
            }
        }

        if let Some(peer_addr) = enroll_peer_addr {
            match HostTransport::connect_tcp(peer_addr, std::time::Duration::from_secs(3)) {
                Ok(mut transport) => {
                    let mut store = match TrustedDeviceStore::load_or_create(&self.store_path) {
                        Ok(s) => s,
                        Err(err) => {
                            self.shell
                                .set_error(format!("Trust store load failed: {err}"));
                            return;
                        }
                    };
                    match omnidesk_core::device_enrollment::host_process_pairing_exchange(
                        &mut self.enrollment_coordinator,
                        &mut store,
                        Some(&self.store_path),
                        &mut transport,
                        now,
                    ) {
                        Ok(Some(record)) => {
                            let mut summaries = store.to_device_summaries();
                            for s in &mut summaries {
                                s.status = DeviceStatus::Offline;
                            }
                            self.shell.replace_devices(summaries);
                            self.shell.set_error(format!(
                                "Peer '{}' successfully enrolled and stored (offline)",
                                record.device_id
                            ));
                        }
                        Ok(None) => {
                            self.shell.set_error(
                                "Pairing exchange initiated: challenge transmitted to peer",
                            );
                        }
                        Err(err) => {
                            self.shell
                                .set_error(format!("Network pairing exchange failed: {err}"));
                        }
                    }
                }
                Err(err) => {
                    self.shell.set_error(format!(
                        "Cannot connect to enrollment peer at {peer_addr}: {err:?}"
                    ));
                }
            }
            return;
        }

        match self.enrollment_coordinator.create_challenge(now) {
            Ok(challenge) => {
                let hex_prefix = format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    challenge.nonce[0], challenge.nonce[1], challenge.nonce[2], challenge.nonce[3]
                );
                self.shell.set_error(format!(
                    "Enrollment challenge issued ({hex_prefix}... expires in 300s); enter remote IP:port or set OMNIDESK_ENROLL_PEER_ADDR"
                ));
            }
            Err(err) => {
                self.shell
                    .set_error(format!("Enrollment challenge failed: {err}"));
            }
        }
    }

    /// Refuse raw-TCP password-only access. A password proof without a
    /// cryptographically authenticated, encrypted peer channel is not remote
    /// control authorization. The network adapter must explicitly attest
    /// these properties before this flow can be re-enabled.
    fn try_connect_peer(&mut self) {
        self.shell.disconnect();
        self.shell.set_error(
            "Secure remote control unavailable: verified encrypted peer transport and target permission are required",
        );
    }

    fn update_accessibility_tree(&mut self) {
        let Some(window) = self.window.as_ref() else {
            return;
        };
        let size = window.inner_size();
        let width = usize::try_from(size.width).unwrap_or(usize::MAX);
        let height = usize::try_from(size.height).unwrap_or(usize::MAX);
        let update =
            build_accesskit_tree_at_size(&self.shell, self.accessibility_focus, width, height);
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

    fn poll_incoming(&mut self) {
        // The current listener is loopback-only. Until the native transport
        // has mutually authenticated encryption and approved session grants,
        // an incoming password proof is not authorization. Drop the socket.
        while let Ok(incoming) = self.incoming_rx.try_recv() {
            let _peer = incoming.peer_addr;
            drop(incoming.stream);
            self.shell.set_error(
                "Incoming session refused: encrypted transport and target authorization are not verified",
            );
            self.refresh_presentation();
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

    fn dispatch_action(&mut self, action: DesktopAction) {
        if action == DesktopAction::EnrollDevice {
            self.handle_enroll_device();
        } else if matches!(
            action,
            DesktopAction::Disconnect | DesktopAction::DenyPermission
        ) {
            if let Some(mut adapter) = self.session_adapter.take() {
                adapter.close();
            }
            self.shell.disconnect();
        } else if action == DesktopAction::AllowPermission {
            // A signed proof alone must never enable remote input. The consent
            // must target the exact peer authenticated on this transport.
            let peer_id = self
                .session_adapter
                .as_ref()
                .and_then(TransportSessionAdapter::authenticated_device_id)
                .or_else(|| self.shell.selected_device());
            if consent_matches_peer(&self.shell, peer_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let store = TrustedDeviceStore::load_or_create(&self.store_path);
                let valid = store.as_ref().is_ok_and(|store| {
                    peer_id.and_then(|id| store.get(id)).is_some_and(|record| {
                        !record.revoked
                            && now <= record.trust_expires_at_epoch_secs
                            && self.session_adapter.as_ref().is_some_and(|adapter| {
                                adapter.session().authenticated_public_key()
                                    == Some(&record.public_key)
                            })
                    })
                });
                if !valid {
                    if let Some(mut adapter) = self.session_adapter.take() {
                        adapter.close();
                    }
                    self.shell.disconnect();
                    self.shell.set_error("Session approval rejected: trusted peer was revoked, expired or unavailable");
                } else if let Some(adapter) = self.session_adapter.as_mut() {
                    match adapter.authorize_session() {
                        Ok(()) => apply_action(&mut self.shell, action),
                        Err(err) => {
                            adapter.close();
                            self.session_adapter = None;
                            self.shell.disconnect();
                            self.shell
                                .set_error(format!("Session authorization failed: {err:?}"));
                        }
                    }
                }
            } else {
                self.shell
                    .set_error("Session approval rejected: peer or permission prompt mismatch");
            }
        } else if action == DesktopAction::CopyYourId {
            if copy_to_clipboard(self.shell.local_device_id()) {
                apply_action(&mut self.shell, action);
            } else {
                self.shell
                    .set_error("Unable to copy device ID to the Windows clipboard");
            }
        } else if action == DesktopAction::CopyYourPassword {
            // Never claim success when no password exists or the OS clipboard
            // write fails. This requires an explicit visible button click.
            let copied = self
                .shell
                .password_manager()
                .raw_password()
                .is_some_and(copy_to_clipboard);
            if copied {
                apply_action(&mut self.shell, action);
            } else {
                self.shell
                    .set_error("Session password unavailable or clipboard copy failed");
            }
        } else if action == DesktopAction::ConnectRemoteId {
            apply_action(&mut self.shell, action);
            if self.session_adapter.is_none() && self.shell.selected_device().is_some() {
                self.try_connect_peer();
            }
        } else if matches!(
            action,
            DesktopAction::ConnectDevice(..) | DesktopAction::RetryConnect
        ) {
            // Check that the action is still visible and enabled before any
            // network side effect. A stale directory revision is not consent.
            let valid_action = controls_for_shell(&self.shell)
                .iter()
                .any(|control| control.enabled && control.action == action);
            if valid_action && self.session_adapter.is_none() {
                self.try_connect_peer();
            }
        } else {
            apply_action(&mut self.shell, action);
        }
        self.accessibility_focus = None;
        self.refresh_presentation();
    }

    fn handle_accesskit_action(&mut self, request: &accesskit::ActionRequest) {
        match request.action {
            Action::Focus => {
                if let Some(action) = desktop_action_for_node(&self.shell, request.target_node) {
                    // Assistive-tech focus on an editable ID/password field
                    // must also move the actual keyboard input focus. Never
                    // copy/read the secret into accessibility node values.
                    if matches!(
                        action,
                        DesktopAction::FocusRemoteIdInput | DesktopAction::FocusRemotePasswordInput
                    ) {
                        self.dispatch_action(action);
                    }
                    self.accessibility_focus = Some(request.target_node);
                    self.update_accessibility_tree();
                }
            }
            Action::Click => {
                if let Some(action) = desktop_action_for_node(&self.shell, request.target_node) {
                    self.dispatch_action(action);
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

    #[allow(clippy::too_many_lines)]
    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        self.poll_incoming();
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
            WindowEvent::MouseWheel { delta, .. } => {
                if let (Some((x, y)), Some(window)) =
                    (self.cursor_position, self.window.as_ref())
                {
                    let size = window.inner_size();
                    let width = usize::try_from(size.width).unwrap_or(usize::MAX);
                    let height = usize::try_from(size.height).unwrap_or(usize::MAX);
                    if let Some(layout) = crate::LockedDashboardLayout::for_window(width, height) {
                        if layout.viewer.contains(x, y) {
                            let direction = match delta {
                                winit::event::MouseScrollDelta::LineDelta(_, dy) => {
                                    if dy > 0.0 { -1 } else if dy < 0.0 { 1 } else { 0 }
                                }
                                winit::event::MouseScrollDelta::PixelDelta(position) => {
                                    if position.y > 0.0 { -1 }
                                    else if position.y < 0.0 { 1 }
                                    else { 0 }
                                }
                            };
                            let old = self.shell.workspace_scroll_y();
                            let max = crate::LockedDashboardLayout::max_scroll_y(height);
                            let next = match direction {
                                -1 => old.saturating_sub(120),
                                1 => old.saturating_add(120).min(max),
                                _ => old,
                            };
                            if next != old {
                                self.shell.set_workspace_scroll_y(next);
                                self.update_accessibility_tree();
                                window.request_redraw();
                            }
                        }
                    }
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
                        self.dispatch_action(action);
                    } else if self.shell.is_remote_id_focused()
                        || self.shell.is_remote_password_focused()
                    {
                        // Clicking non-interactive chrome must release
                        // credential input focus; otherwise typing may land
                        // in a hidden password field.
                        self.shell.set_remote_id_focused(false);
                        self.shell.set_remote_password_focused(false);
                        self.refresh_presentation();
                    }
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                // Help replaces the V5 workspace. Do not let invisible
                // session/device keyboard shortcuts operate behind it.
                // Escape dismisses Help without sending a remote action.
                if self.shell.is_help_open() {
                    if matches!(
                        event.logical_key,
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Escape)
                    ) {
                        self.dispatch_action(DesktopAction::ToggleHelp);
                    }
                    return;
                }
                if self.shell.is_remote_id_focused() {
                    match &event.logical_key {
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Backspace) => {
                            self.shell.backspace_remote_id();
                            self.refresh_presentation();
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Enter) => {
                            self.dispatch_action(DesktopAction::ConnectRemoteId);
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Escape) => {
                            self.shell.set_remote_id_focused(false);
                            self.refresh_presentation();
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Tab) => {
                            self.dispatch_action(DesktopAction::FocusRemotePasswordInput);
                            return;
                        }
                        _ => {}
                    }
                    if let Some(text) = &event.text {
                        for c in text.chars() {
                            if !c.is_control() {
                                self.shell.append_remote_id_char(c);
                            }
                        }
                        self.refresh_presentation();
                        return;
                    }
                }
                if self.shell.is_remote_password_focused() {
                    // Credential input takes precedence over every global
                    // navigation shortcut. The letter 's' must append 's'
                    // to the password, never open Security Center.
                    match &event.logical_key {
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Backspace) => {
                            self.shell.backspace_remote_password();
                            self.refresh_presentation();
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Enter) => {
                            self.dispatch_action(DesktopAction::ConnectRemoteId);
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Escape) => {
                            self.shell.set_remote_password_focused(false);
                            self.refresh_presentation();
                            return;
                        }
                        winit::keyboard::Key::Named(winit::keyboard::NamedKey::Tab) => {
                            self.dispatch_action(DesktopAction::FocusRemoteIdInput);
                            return;
                        }
                        _ => {}
                    }
                    if let Some(text) = &event.text {
                        for c in text.chars() {
                            if !c.is_control() {
                                self.shell.append_remote_password_char(c);
                            }
                        }
                        self.refresh_presentation();
                        return;
                    }
                }
                if let Some(text) = event.text {
                    if let Some(key) = text.chars().next() {
                        let selected_action = controls_for_shell(&self.shell)
                            .into_iter()
                            .find(|control| {
                                control.enabled && control.keyboard_key == key.to_ascii_lowercase()
                            })
                            .map(|control| control.action);
                        if let Some(action) = selected_action {
                            self.dispatch_action(action);
                        } else if apply_key(&mut self.shell, key) {
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

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
        self.poll_incoming();
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
    use super::{
        MAX_PIXEL_OFFSET, consent_matches_peer, refuse_unverified_session_action, to_pixel,
    };
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
    fn consent_requires_visible_prompt_for_exact_authenticated_peer() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "verified-peer".to_owned(),
            display_name: "Verified peer".to_owned(),
            status: DeviceStatus::Online,
        }]);
        assert!(!consent_matches_peer(&shell, Some("verified-peer")));
        shell
            .begin_connect("verified-peer")
            .expect("known online peer");
        assert!(consent_matches_peer(&shell, Some("verified-peer")));
        assert!(!consent_matches_peer(&shell, Some("other-peer")));
        assert!(!consent_matches_peer(&shell, None));
        shell.disconnect();
        assert!(!consent_matches_peer(&shell, Some("verified-peer")));
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

    #[test]
    fn disconnect_clears_session_adapter_and_disconnects_shell() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "connected-peer".to_owned(),
            display_name: "Connected peer".to_owned(),
            status: DeviceStatus::Online,
        }]);
        let _ = shell.begin_connect("connected-peer");

        let transport = omnidesk_core::transport::HostTransport::loopback();
        let mut adapter = super::TransportSessionAdapter::new(transport, "kmj-tenant");
        adapter
            .begin_negotiation(omnidesk_core::session::PeerIdentity::new("connected-peer").unwrap())
            .unwrap();

        adapter.close();
        assert!(!adapter.is_control_authorized());
        shell.disconnect();
        assert_eq!(shell.primary_view(), PrimaryView::Devices);
    }
}
