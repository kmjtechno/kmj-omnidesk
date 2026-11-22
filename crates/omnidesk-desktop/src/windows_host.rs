#![cfg(windows)]

use std::{
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
};

use accesskit::{Action, NodeId};
use accesskit_winit::{Adapter, Event as AccessKitEvent, WindowEvent as AccessKitWindowEvent};
use omnidesk_core::{
    attended_proof_wire::{client_prove_attended_password, host_verify_attended_password},
    device_enrollment::EnrollmentCoordinator,
    device_identity::DeviceIdentity,
    noise_encrypted_transport::UnauthenticatedNoiseChannel,
    product_shell::{DeviceStatus, PrimaryView, ProductShell},
    transport::{HostTransport, Transport},
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
    action_at_point, action_for_key, apply_action,
    brand::official_kmj_mark,
    controls_for_shell,
    layout::{PremiumViewportFit, V7_ART_WIDTH, initial_window_inner_size, initial_window_origin},
    presentation_for,
    render::render_shell,
};

// The owner's V7 reference has a custom 70px header and *no second*
// Windows title bar. On screens that fit the locked artboard, the header
// hosts real OS minimize/maximize/close and drag actions. Smaller monitors
// retain native OS decorations so the compact UI always remains operable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PremiumCaptionAction {
    Drag,
    Minimize,
    Maximize,
    Close,
}

// P0 #182: the current TCP identity challenge is NOT an encrypted host
// password proof. Keep attended authorization disabled until a reviewed
// identity/session-bound, replay-safe encrypted proof receipt exists.
// Never replace this guard with "password input is nonempty".
const ATTENDED_PASSWORD_PROOF_TRANSPORT_READY: bool = false;

// Compile-time refusal: an unaudited change enabling native remote control
// fails test compilation rather than silently skipping the gate.
#[cfg(test)]
const _: () = assert!(!ATTENDED_PASSWORD_PROOF_TRANSPORT_READY);

// Pre-release operator opt-in for authentication QA only. Unlike the future
// remote-control listener, this accepts only explicit loopback/RFC1918/ULA
// addresses and ALWAYS closes after verifying the password; no mouse/screen
// or application session can be authorized by this mode.
fn secure_proof_diagnostic_enabled() -> bool {
    std::env::var("OMNIDESK_AUTH_PROBE_ONLY").as_deref() == Ok("1")
}

fn allowed_proof_diagnostic_bind(value: &str) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};
    let address: SocketAddr = value.parse().ok()?;
    if address.port() == 0 {
        return None;
    }
    let local = match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    };
    local.then_some(address)
}

fn secure_proof_diagnostic_bind() -> Option<std::net::SocketAddr> {
    if !secure_proof_diagnostic_enabled() {
        return None;
    }
    let value =
        std::env::var("OMNIDESK_AUTH_PROBE_BIND").unwrap_or_else(|_| "127.0.0.1:21118".to_owned());
    allowed_proof_diagnostic_bind(&value)
}

// Winit window attributes use logical sizes; rendering and mouse hitboxes
// use *physical* client pixels. On a 200%-DPI P520 monitor the approved
// 1672x941 native artboard can fit physically even though its logical width
// is below 1280. Decide borderless startup in physical coordinates.
fn premium_frameless_on_monitor(
    logical_width: f64,
    logical_height: f64,
    scale_factor: f64,
) -> bool {
    let scale = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor
    } else {
        1.0
    };
    logical_width * scale >= 1280.0 && logical_height * scale >= 720.0
}

fn premium_caption_action(
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    frameless: bool,
) -> Option<PremiumCaptionAction> {
    if !frameless {
        return None;
    }
    // The rendered titlebar moves when the locked artboard is fitted into
    // a non-16:9 window. Use the same inverse transform as remote-control
    // hit testing so OS actions never drift into credentials or badges.
    let (art_width, art_x, art_y) = if let Some(fit) = PremiumViewportFit::for_window(width, height)
    {
        let (source_x, source_y) = fit.artboard_point(x, y)?;
        (V7_ART_WIDTH, source_x, source_y)
    } else {
        (width, x, y)
    };
    if art_y >= 70 || art_width < 600 {
        return None;
    }
    if (art_width.saturating_sub(80)..art_width.saturating_sub(20)).contains(&art_x) {
        Some(PremiumCaptionAction::Close)
    } else if (art_width.saturating_sub(136)..art_width.saturating_sub(80)).contains(&art_x) {
        Some(PremiumCaptionAction::Maximize)
    } else if (art_width.saturating_sub(192)..art_width.saturating_sub(136)).contains(&art_x) {
        Some(PremiumCaptionAction::Minimize)
    } else if art_x < art_width.saturating_sub(450) {
        Some(PremiumCaptionAction::Drag)
    } else {
        None
    }
}

fn perform_premium_caption(
    window: &Window,
    event_loop: &ActiveEventLoop,
    action: PremiumCaptionAction,
) {
    match action {
        PremiumCaptionAction::Drag => {
            let _ = window.drag_window();
        }
        PremiumCaptionAction::Minimize => window.set_minimized(true),
        PremiumCaptionAction::Maximize => window.set_maximized(!window.is_maximized()),
        PremiumCaptionAction::Close => event_loop.exit(),
    }
}

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

// Visible local consent is necessary but does not authorize remote input unless
// the current transport has an authenticated identity whose trust record is valid.
fn verified_consent_for_authenticated_trust(
    shell: &ProductShell,
    authenticated_device_id: Option<&str>,
    trusted_record_verified: bool,
) -> bool {
    consent_matches_peer(shell, authenticated_device_id) && trusted_record_verified
}

// All three checks are independent: verified peer trust, visible local consent,
// and a host-attested temporary password proof. The current transport does
// not produce the last receipt, so physical remote control remains closed.
fn verified_attended_session_authorization(
    shell: &ProductShell,
    authenticated_device_id: Option<&str>,
    trusted_record_verified: bool,
    password_proof_verified: bool,
) -> bool {
    verified_consent_for_authenticated_trust(
        shell,
        authenticated_device_id,
        trusted_record_verified,
    ) && password_proof_verified
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

// Host proof runs off the GUI thread. A single active job serialises password
// guesses: its updated manager (including failed-attempt lockout) must be
// restored BEFORE the next queued incoming peer may be processed.
struct InboundProofRequest {
    stream: std::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    identity: DeviceIdentity,
    store: TrustedDeviceStore,
    manager: omnidesk_core::password_auth::HostPasswordManager,
    tenant: String,
}

struct InboundProofOutcome {
    manager: omnidesk_core::password_auth::HostPasswordManager,
    result: Result<(), String>,
    peer_addr: std::net::SocketAddr,
}

struct InboundProofJob {
    result_rx: Receiver<InboundProofOutcome>,
    cancelled: Arc<AtomicBool>,
    original_generation: (u64, u64),
}

impl Drop for InboundProofJob {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl InboundProofJob {
    fn launch(request: InboundProofRequest) -> std::io::Result<Self> {
        let original_generation = request.manager.approval_generation();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (tx, result_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("omnidesk-inbound-auth-probe".to_owned())
            .spawn(move || {
                let InboundProofRequest {
                    stream,
                    peer_addr,
                    identity,
                    store,
                    mut manager,
                    tenant,
                } = request;
                let result = if worker_cancelled.load(Ordering::Acquire) {
                    Err("Host cancelled before inbound handshake".to_owned())
                } else {
                    match HostTransport::from_tcp_stream(stream) {
                        Ok(transport) => match UnauthenticatedNoiseChannel::accept(transport) {
                            Ok(mut encrypted) => {
                                let verified = if worker_cancelled.load(Ordering::Acquire) {
                                    Err("Host cancelled during Noise handshake".to_owned())
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map_or(0, |duration| duration.as_secs());
                                    host_verify_attended_password(
                                        &mut encrypted,
                                        &identity,
                                        &store,
                                        &mut manager,
                                        &tenant,
                                        now,
                                    )
                                    .map_err(|err| format!("{err:?}"))
                                };
                                encrypted.close();
                                verified
                            }
                            Err(err) => Err(format!("Noise handshake failed: {err:?}")),
                        },
                        Err(err) => Err(format!("Incoming TCP transport rejected: {err:?}")),
                    }
                };
                // No session/capability/transport returned, only a redacted
                // result and updated lockout state for the host GUI.
                let _ = tx.send(InboundProofOutcome {
                    manager,
                    result,
                    peer_addr,
                });
            })?;
        Ok(Self {
            result_rx,
            cancelled,
            original_generation,
        })
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

// Build the outbound request on the GUI thread, then move it into exactly
// one bounded worker. Secrets are never included in Debug/status messages.
struct OutboundProofRequest {
    address: std::net::SocketAddr,
    expected_host_id: String,
    identity: DeviceIdentity,
    store: TrustedDeviceStore,
    tenant: String,
    password: String,
    now: u64,
}

/// One in-flight, password-only diagnostic. It MUST NOT carry a control
/// capability or be used to display a remote-control permission prompt.
struct OutboundProofJob {
    result_rx: Receiver<Result<(), String>>,
    cancelled: Arc<AtomicBool>,
    operator_cancelled: bool,
}

impl Drop for OutboundProofJob {
    fn drop(&mut self) {
        // Closing the UI must not leave a queued future password attempt.
        self.cancelled.store(true, Ordering::Release);
    }
}

impl OutboundProofJob {
    fn launch(request: OutboundProofRequest) -> std::io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (tx, result_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("omnidesk-outbound-auth-probe".to_owned())
            .spawn(move || {
                let OutboundProofRequest {
                    address,
                    expected_host_id,
                    identity,
                    store,
                    tenant,
                    password,
                    now,
                } = request;
                let result = if worker_cancelled.load(Ordering::Acquire) {
                    Err("Operator cancelled before connect".to_owned())
                } else {
                    match HostTransport::connect_tcp(address, std::time::Duration::from_secs(2)) {
                        Ok(transport) => match UnauthenticatedNoiseChannel::connect(transport) {
                            Ok(mut encrypted) => {
                                // Refuse to send the password proof if the
                                // operator cancelled during Noise negotiation.
                                let verified = if worker_cancelled.load(Ordering::Acquire) {
                                    Err("Operator cancelled during Noise handshake".to_owned())
                                } else {
                                    client_prove_attended_password(
                                        &mut encrypted,
                                        &identity,
                                        &store,
                                        &expected_host_id,
                                        &tenant,
                                        &password,
                                        now,
                                    )
                                    .map_err(|err| format!("{err:?}"))
                                };
                                encrypted.close();
                                verified
                            }
                            Err(err) => Err(format!("Noise handshake rejected: {err:?}")),
                        },
                        Err(err) => Err(format!("TCP connection rejected: {err:?}")),
                    }
                };
                // Never return the plaintext password to the UI or logs.
                let _ = tx.send(result);
            })?;
        Ok(Self {
            result_rx,
            cancelled,
            operator_cancelled: false,
        })
    }

    fn cancel(&mut self) {
        self.operator_cancelled = true;
        self.cancelled.store(true, Ordering::Release);
    }

    fn completed_status(&self) -> Option<String> {
        match self.result_rx.try_recv() {
            Ok(result) => {
                if self.operator_cancelled {
                    Some("Encrypted authentication probe cancelled; no remote control".to_owned())
                } else {
                    Some(match result {
                        Ok(()) => "Encrypted identity and temporary password verified (diagnostic only); remote control NOT authorized".to_owned(),
                        Err(error) => format!("Encrypted authentication probe rejected: {error}"),
                    })
                }
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(
                "Authentication worker ended without a result; no session authorized".to_owned(),
            ),
        }
    }
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
    identity_path: PathBuf,
    session_adapter: Option<TransportSessionAdapter<HostTransport>>,
    accessibility: Vec<AccessibilityNode>,
    accessibility_focus: Option<NodeId>,
    cursor_position: Option<(usize, usize)>,
    frameless_premium: bool,
    incoming_rx: std::sync::mpsc::Receiver<IncomingPeer>,
    inbound_proof: Option<InboundProofJob>,
    outbound_proof: Option<OutboundProofJob>,
}

fn copy_to_clipboard(text: &str) {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    if let Ok(mut child) = std::process::Command::new("clip.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
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
        // A corrupted/unwritable persisted device identity is not permission
        // to silently issue an unpinned ephemeral identity on every start.
        if let Ok(identity) = DeviceIdentity::load_or_create(&identity_path, now) {
            shell.set_local_device_id(identity.public_id());
        } else {
            shell.set_local_device_id("");
            shell.set_error("Device identity unavailable: cannot establish trusted sessions");
        }
        // Generate exactly ONE authoritative OS-random temporary password
        // on the real native host. Never present a random password created
        // on a transient shell clone: the host would reject what it displays.
        let _ = shell.host_password();
        let accessibility = accessibility_snapshot(&shell);

        // Production public listening stays disabled until authenticated
        // encrypted control, separate visible consent and licensing all pass.
        // A pre-release operator can opt into a PROOF-ONLY listener, strictly
        // bound to loopback or a named private LAN address. It never grants
        // remote desktop access and keeps the bounded incoming queue.
        let (incoming_tx, incoming_rx) = std::sync::mpsc::sync_channel::<IncomingPeer>(16);
        if let Some(listen_addr) = secure_proof_diagnostic_bind() {
            match std::net::TcpListener::bind(listen_addr) {
                Ok(listener) => {
                    let result = std::thread::Builder::new()
                        .name("omnidesk-auth-probe-listener".to_owned())
                        .spawn(move || {
                            while let Ok((stream, peer_addr)) = listener.accept() {
                                let deadline = Some(std::time::Duration::from_secs(3));
                                let _ = stream.set_read_timeout(deadline);
                                let _ = stream.set_write_timeout(deadline);
                                let _ = stream.set_nodelay(true);
                                match incoming_tx.try_send(IncomingPeer { stream, peer_addr }) {
                                    Ok(()) | Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                                }
                            }
                        });
                    if result.is_err() {
                        shell.set_error("Authentication-only diagnostic listener failed to start");
                    }
                }
                Err(err) => {
                    shell.set_error(format!(
                        "Authentication-only diagnostic listener could not bind: {err}"
                    ));
                }
            }
        } else if secure_proof_diagnostic_enabled() {
            shell.set_error(
                "Authentication probe bind refused: use a named loopback or private LAN address",
            );
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
            identity_path,
            session_adapter: None,
            accessibility,
            accessibility_focus: None,
            cursor_position: None,
            frameless_premium: false,
            incoming_rx,
            inbound_proof: None,
            outbound_proof: None,
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

    fn try_connect_peer(&mut self) {
        // Serialise proof attempts: concurrent GUI clicks must not spawn
        // overlapping password guesses or overwrite one another's result.
        if self.outbound_proof.is_some() {
            self.shell.clear_remote_password();
            self.shell.disconnect();
            self.shell.set_error(
                "Encrypted authentication already running; finish or cancel this attempt",
            );
            return;
        }
        // The diagnostic is intentionally opt-in and never a production
        // control path, even if a user clicks an enrolled device card.
        if !secure_proof_diagnostic_enabled() && !ATTENDED_PASSWORD_PROOF_TRANSPORT_READY {
            self.shell.disconnect();
            self.shell.set_error(
                "Remote control disabled: encrypted consent/licensing session is not ready",
            );
            return;
        }
        let Some(expected_host_id) = self.shell.selected_device().map(str::to_owned) else {
            self.shell.disconnect();
            self.shell
                .set_error("Select a trusted host device before connecting");
            return;
        };
        let Ok(store) = TrustedDeviceStore::load_or_create(&self.store_path) else {
            self.shell.disconnect();
            self.shell
                .set_error("Trusted peer store unavailable; connection refused");
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let Some(record) = store.get(&expected_host_id) else {
            self.shell.disconnect();
            self.shell
                .set_error("Remote host ID is not enrolled; connection refused");
            return;
        };
        if !record.is_trusted_at(now) {
            self.shell.disconnect();
            self.shell
                .set_error("Remote host trust revoked or expired; connection refused");
            return;
        }
        let Ok(identity) = DeviceIdentity::load_from_path(&self.identity_path) else {
            self.shell.disconnect();
            self.shell
                .set_error("Local signing identity unavailable; connection refused");
            return;
        };
        let target_addr = expected_host_id
            .parse::<std::net::SocketAddr>()
            .ok()
            .or_else(|| {
                std::env::var("OMNIDESK_PEER_ADDR")
                    .ok()
                    .and_then(|address| address.parse().ok())
            });
        let Some(address) = target_addr else {
            self.shell.disconnect();
            self.shell.set_error(
                "No approved host endpoint: configure OMNIDESK_PEER_ADDR for the enrolled host",
            );
            return;
        };
        let tenant = std::env::var("OMNIDESK_TENANT").unwrap_or_else(|_| "kmj-omnidesk".to_owned());
        if self.shell.remote_password_input().is_empty() {
            self.shell.disconnect();
            self.shell
                .set_error("Please enter the enrolled host's temporary password");
            return;
        }
        let password = self.shell.remote_password_input().to_owned();
        // Immediately remove the operator's plaintext password from the
        // editable GUI. The one worker owns it until completion.
        self.shell.clear_remote_password();
        self.shell.disconnect();
        match OutboundProofJob::launch(OutboundProofRequest {
            address,
            expected_host_id,
            identity,
            store,
            tenant,
            password,
            now,
        }) {
            Ok(job) => {
                self.outbound_proof = Some(job);
                self.shell
                    .set_error("Encrypted password authentication in progress (no remote control)");
            }
            Err(err) => {
                self.shell
                    .set_error(format!("Authentication worker could not start: {err}"));
            }
        }
    }

    fn poll_outbound_proof(&mut self) {
        let status = self
            .outbound_proof
            .as_ref()
            .and_then(OutboundProofJob::completed_status);
        if let Some(status) = status {
            self.outbound_proof = None;
            self.shell.disconnect();
            self.shell.set_error(status);
            self.refresh_presentation();
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

    fn poll_incoming(&mut self) {
        // Serialise host password guesses. The previous worker's updated
        // lockout budget MUST be restored before accepting another peer.
        if self.session_adapter.is_some() || self.inbound_proof.is_some() {
            return;
        }
        let Ok(incoming) = self.incoming_rx.try_recv() else {
            return;
        };
        if !secure_proof_diagnostic_enabled() || !self.shell.allow_remote_control() {
            self.shell.set_error(format!(
                "Incoming peer {} refused: encrypted host proof diagnostic disabled",
                incoming.peer_addr
            ));
            self.refresh_presentation();
            return;
        }
        let Ok(store) = TrustedDeviceStore::load_or_create(&self.store_path) else {
            self.shell
                .set_error("Incoming proof refused: trusted peer store unavailable");
            self.refresh_presentation();
            return;
        };
        let Ok(identity) = DeviceIdentity::load_from_path(&self.identity_path) else {
            self.shell
                .set_error("Incoming proof refused: host signing identity unavailable");
            self.refresh_presentation();
            return;
        };
        let _ = self.shell.host_password();
        let manager = self.shell.host_password_ref().clone();
        let tenant = std::env::var("OMNIDESK_TENANT").unwrap_or_else(|_| "kmj-omnidesk".to_owned());
        match InboundProofJob::launch(InboundProofRequest {
            stream: incoming.stream,
            peer_addr: incoming.peer_addr,
            identity,
            store,
            manager,
            tenant,
        }) {
            Ok(job) => {
                self.inbound_proof = Some(job);
                self.shell.set_error(
                    "Encrypted incoming password proof in progress; screen/input not shared",
                );
            }
            Err(err) => self.shell.set_error(format!(
                "Incoming authentication worker failed to start: {err}"
            )),
        }
        self.refresh_presentation();
    }

    fn poll_inbound_proof(&mut self) {
        let Some(job) = self.inbound_proof.as_ref() else {
            return;
        };
        match job.result_rx.try_recv() {
            Ok(outcome) => {
                let cancelled = job.cancelled.load(Ordering::Acquire);
                let generation_matches =
                    self.shell.host_password_ref().approval_generation() == job.original_generation;
                self.inbound_proof = None;
                // Restore the worker's *authoritative* failed-attempt count
                // before processing another TCP connection. UI credential
                // rotation/policy changes must never be silently undone.
                if generation_matches {
                    *self.shell.host_password_mut() = outcome.manager;
                }
                self.shell.disconnect();
                if cancelled || !generation_matches || !self.shell.allow_remote_control() {
                    self.shell.set_allow_remote_control(false);
                    self.shell.set_error(
                        "Host proof cancelled or host policy changed; no session authorized",
                    );
                } else {
                    match outcome.result {
                        Ok(()) => self.shell.set_error(format!(
                            "Encrypted password proof for {} verified (diagnostic only); screen/input NOT authorized",
                            outcome.peer_addr
                        )),
                        Err(err) => self.shell.set_error(format!(
                            "Incoming encrypted proof for {} rejected: {err}",
                            outcome.peer_addr
                        )),
                    }
                }
                self.refresh_presentation();
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.inbound_proof = None;
                self.shell.set_allow_remote_control(false);
                self.shell.disconnect();
                self.shell.set_error(
                    "Host authentication worker disconnected; sharing disabled, no control authorized",
                );
                self.refresh_presentation();
            }
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

    // A visible host-sharing switch cannot enable unaudited incoming sessions.
    fn apply_host_sharing_toggle(&mut self) {
        if ATTENDED_PASSWORD_PROOF_TRANSPORT_READY {
            apply_action(&mut self.shell, DesktopAction::ToggleRemoteControl);
        } else if secure_proof_diagnostic_bind().is_some() {
            // The toggle only permits host password PROOF in the explicit
            // pre-release diagnostic. Even if enabled, peer control and
            // session authorization remain hard-disabled.
            apply_action(&mut self.shell, DesktopAction::ToggleRemoteControl);
            self.shell.set_error(
                "Authentication-only LAN probe: no desktop control, screen or files are shared",
            );
        } else {
            self.shell.set_allow_remote_control(false);
            self.shell.set_error(
                "Remote sharing disabled: encrypted proof alone does not authorize desktop control",
            );
        }
    }

    // One guarded entrypoint for both mouse and keyboard Remote ID actions.
    // No password or session is sent over a TCP identity-only handshake.
    fn dispatch_remote_connect(&mut self) {
        if self.outbound_proof.is_some() {
            self.shell
                .set_error("Encrypted authentication already running; retry after it finishes");
            return;
        }
        if self.shell.remote_id_input().is_empty() {
            self.shell.set_error("Please enter a Remote Device ID");
        } else if self.shell.remote_password_input().is_empty() {
            self.shell.set_error("Please enter the session password");
        } else if !ATTENDED_PASSWORD_PROOF_TRANSPORT_READY && !secure_proof_diagnostic_enabled() {
            self.shell.disconnect();
            self.shell.set_error(
                "Remote desktop disabled: host consent, licensing and control transport not ready",
            );
        } else if !ATTENDED_PASSWORD_PROOF_TRANSPORT_READY {
            // Authentication QA only: validate a pinned Remote ID and probe
            // over Noise, with no session permission or control granted.
            if self.shell.begin_connect_remote_id().is_ok() {
                self.try_connect_peer();
            }
            // Failed early trust/endpoint/identity checks must not leave the
            // operator's password in the editable UI buffer.
            self.shell.clear_remote_password();
        } else {
            apply_action(&mut self.shell, DesktopAction::ConnectRemoteId);
            if self.session_adapter.is_none() && self.shell.selected_device().is_some() {
                self.try_connect_peer();
            }
        }
    }

    fn cancel_inbound_probe_for_policy_action(&mut self, action: DesktopAction) {
        if matches!(
            action,
            DesktopAction::ToggleRemoteControl
                | DesktopAction::RotateSessionPassword
                | DesktopAction::Disconnect
                | DesktopAction::DenyPermission
        ) {
            if let Some(job) = self.inbound_proof.as_ref() {
                job.cancel();
                if matches!(
                    action,
                    DesktopAction::Disconnect | DesktopAction::DenyPermission
                ) {
                    self.shell.set_allow_remote_control(false);
                }
            }
        }
    }

    fn dispatch_action(&mut self, action: DesktopAction) {
        self.cancel_inbound_probe_for_policy_action(action);
        if action == DesktopAction::EnrollDevice {
            self.handle_enroll_device();
        } else if matches!(
            action,
            DesktopAction::Disconnect | DesktopAction::DenyPermission
        ) {
            if let Some(job) = self.outbound_proof.as_mut() {
                job.cancel();
            }
            if let Some(mut adapter) = self.session_adapter.take() {
                adapter.close();
            }
            self.shell.disconnect();
        } else if action == DesktopAction::AllowPermission {
            // A signed handshake and a visible prompt are independent gates.
            // The peer ID must come from the authenticated transport, never
            // from an unverified selected device or a socket address.
            let peer_id = self
                .session_adapter
                .as_ref()
                .and_then(TransportSessionAdapter::authenticated_device_id);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let store = TrustedDeviceStore::load_or_create(&self.store_path);
            let trust_verified = store.as_ref().is_ok_and(|store| {
                peer_id.and_then(|id| store.get(id)).is_some_and(|record| {
                    !record.revoked
                        && now < record.trust_expires_at_epoch_secs
                        && self.session_adapter.as_ref().is_some_and(|adapter| {
                            adapter.session().authenticated_public_key() == Some(&record.public_key)
                        })
                })
            });
            if !verified_consent_for_authenticated_trust(&self.shell, peer_id, trust_verified) {
                if let Some(mut adapter) = self.session_adapter.take() {
                    adapter.close();
                }
                self.shell.disconnect();
                self.shell.set_error(
                    "Session approval rejected: authenticated trusted peer or consent invalid",
                );
            } else if !verified_attended_session_authorization(
                &self.shell,
                peer_id,
                trust_verified,
                ATTENDED_PASSWORD_PROOF_TRANSPORT_READY,
            ) {
                // Until the real encrypted proof exchange is complete, even a
                // signed, trusted peer and a user click cannot grant control.
                if let Some(mut adapter) = self.session_adapter.take() {
                    adapter.close();
                }
                self.shell.disconnect();
                self.shell
                    .set_error("Session approval blocked: secure host password proof not verified");
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
        } else if action == DesktopAction::ToggleRemoteControl {
            self.apply_host_sharing_toggle();
        } else if action == DesktopAction::CopyYourId {
            copy_to_clipboard(self.shell.local_device_id());
            apply_action(&mut self.shell, action);
        } else if action == DesktopAction::CopySessionPassword {
            let pwd = self.shell.host_password().to_owned();
            copy_to_clipboard(&pwd);
            apply_action(&mut self.shell, action);
        } else if action == DesktopAction::ConnectRemoteId {
            self.dispatch_remote_connect();
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
                if desktop_action_for_node(&self.shell, request.target_node).is_some() {
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
            let monitor_scale = initial_size.map_or(1.0, |(_, _, scale)| {
                if scale.is_finite() && scale > 0.0 {
                    scale
                } else {
                    1.0
                }
            });
            let frameless_premium =
                premium_frameless_on_monitor(inner_width, inner_height, monitor_scale);
            self.frameless_premium = frameless_premium;
            let attributes = WindowAttributes::default()
                .with_title(title)
                .with_visible(false)
                .with_window_icon(window_icon)
                .with_decorations(!frameless_premium)
                .with_min_inner_size(winit::dpi::LogicalSize::new(
                    if frameless_premium {
                        1280.0 / monitor_scale
                    } else {
                        640.0
                    },
                    if frameless_premium {
                        720.0 / monitor_scale
                    } else {
                        480.0
                    },
                ))
                // A maximized launch overrides the fitted 1672x941 V7 size
                // and stretches the locked hierarchy across the monitor.
                // Launch at the reference dimensions when they fit; users
                // can still maximize the window manually.
                .with_maximized(false)
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
            WindowEvent::CloseRequested => {
                if let Some(job) = self.inbound_proof.as_ref() {
                    job.cancel();
                }
                if let Some(job) = self.outbound_proof.as_mut() {
                    job.cancel();
                }
                event_loop.exit();
            }
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
                    if let Some(command) = premium_caption_action(
                        usize::try_from(size.width).unwrap_or(usize::MAX),
                        usize::try_from(size.height).unwrap_or(usize::MAX),
                        x,
                        y,
                        self.frameless_premium,
                    ) {
                        perform_premium_caption(window, event_loop, command);
                        return;
                    }
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
                        self.shell.set_remote_id_focused(false);
                        self.shell.set_remote_password_focused(false);
                        self.refresh_presentation();
                    }
                }
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
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
                        // All keyboard actions, including legacy fallback
                        // shortcuts, must pass the same transport/password
                        // proof security guard as pointer and AccessKit clicks.
                        if let Some(action) = selected_action
                            .or_else(|| action_for_key(self.shell.primary_view(), key))
                        {
                            self.dispatch_action(action);
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

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.poll_inbound_proof();
        self.poll_outbound_proof();
        self.poll_incoming();
        if secure_proof_diagnostic_enabled() {
            // A TCP listener runs on another thread. Without a wake event,
            // winit's default Wait flow may sleep until the user moves the
            // mouse, leaving an accepted peer stuck in the queue. Schedule
            // four low-duty-cycle wakeups per second ONLY in opt-in probe
            // mode; normal production UI retains its event-driven idle.
            event_loop.set_control_flow(winit::event_loop::ControlFlow::WaitUntil(
                std::time::Instant::now() + std::time::Duration::from_millis(250),
            ));
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
    use super::{
        MAX_PIXEL_OFFSET, PremiumCaptionAction, PremiumViewportFit, allowed_proof_diagnostic_bind,
        consent_matches_peer, premium_caption_action, premium_frameless_on_monitor,
        refuse_unverified_session_action, to_pixel, verified_attended_session_authorization,
        verified_consent_for_authenticated_trust,
    };
    use crate::DesktopAction;
    use omnidesk_core::product_shell::{DeviceStatus, DeviceSummary, PrimaryView, ProductShell};

    #[test]
    fn native_inbound_worker_rejects_wrong_password_and_retains_host_attempt_budget() {
        use omnidesk_core::{
            attended_proof_wire::client_prove_attended_password,
            device_identity::DeviceIdentity,
            noise_encrypted_transport::UnauthenticatedNoiseChannel,
            password_auth::{HostPasswordManager, PasswordVerificationError},
            transport::{TcpLanTransport, Transport},
            trusted_device_store::{
                PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore,
            },
        };
        use std::{
            net::TcpListener,
            thread,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let client = DeviceIdentity::from_seed(&[0x9A; 32]);
        let host = DeviceIdentity::from_seed(&[0x9B; 32]);
        let host_id = host.public_id().to_owned();
        let pin = |device: &DeviceIdentity| {
            let mut store = TrustedDeviceStore::new();
            store
                .add(TrustedDeviceRecord {
                    device_id: device.public_id().to_owned(),
                    display_name: "Pinned QA Device".to_owned(),
                    public_key: device.public_key_bytes(),
                    enrolled_at_epoch_secs: now - 1,
                    trust_expires_at_epoch_secs: now + 600,
                    managed: false,
                    revoked: false,
                    status: PersistedDeviceStatus::Offline,
                })
                .expect("pin peer");
            store
        };
        let host_store = pin(&client);
        let client_store = pin(&host);
        let mut manager = HostPasswordManager::new(now);
        manager.set_allow_remote_control(true);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let client_task = thread::spawn(move || {
            let tcp = TcpLanTransport::connect(address, Duration::from_secs(2)).expect("connect");
            let mut channel = UnauthenticatedNoiseChannel::connect(tcp).expect("Noise client");
            let result = client_prove_attended_password(
                &mut channel,
                &client,
                &client_store,
                &host_id,
                "kmj-tenant",
                "WRONG999",
                now,
            );
            channel.close();
            assert!(result.is_err(), "incorrect password must be refused");
        });
        let (stream, peer_addr) = listener.accept().expect("accept");
        let job = super::InboundProofJob::launch(super::InboundProofRequest {
            stream,
            peer_addr,
            identity: host,
            store: host_store,
            manager,
            tenant: "kmj-tenant".to_owned(),
        })
        .expect("native host worker");
        let mut result = job
            .result_rx
            .recv_timeout(Duration::from_secs(12))
            .expect("native worker result");
        assert!(
            result
                .result
                .as_ref()
                .is_err_and(|error| error.contains("InvalidPassword")),
            "host must reject encrypted wrong proof"
        );
        assert_eq!(
            result.manager.verify_candidate("WRONG999", now),
            Err(PasswordVerificationError::InvalidPassword {
                remaining_attempts: 3
            }),
            "wrong password count must persist after worker returns"
        );
        client_task.join().expect("client");
    }

    #[test]
    fn pending_outbound_probe_is_nonblocking_and_cancel_never_reports_authorized() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let (tx, result_rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut job = super::OutboundProofJob {
            result_rx,
            cancelled: Arc::clone(&cancelled),
            operator_cancelled: false,
        };
        assert_eq!(job.completed_status(), None, "UI polling never blocks");
        tx.send(Ok(())).expect("worker outcome");
        job.cancel();
        assert_eq!(
            job.completed_status(),
            Some("Encrypted authentication probe cancelled; no remote control".to_owned())
        );
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn dropped_window_probe_sets_cancellation_before_another_attempt() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let (_tx, result_rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let job = super::OutboundProofJob {
            result_rx,
            cancelled: Arc::clone(&cancelled),
            operator_cancelled: false,
        };
        drop(job);
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn disconnected_or_rejected_worker_never_reports_a_connected_desktop() {
        use std::sync::{Arc, atomic::AtomicBool, mpsc};

        let (tx, result_rx) = mpsc::sync_channel(1);
        let job = super::OutboundProofJob {
            result_rx,
            cancelled: Arc::new(AtomicBool::new(false)),
            operator_cancelled: false,
        };
        tx.send(Err("invalid host proof".to_owned()))
            .expect("worker rejection");
        let result = job.completed_status().expect("completed");
        assert!(result.contains("rejected"));
        assert!(!result.contains("authorized"));

        let (tx, result_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        drop(tx);
        let lost = super::OutboundProofJob {
            result_rx,
            cancelled: Arc::new(AtomicBool::new(false)),
            operator_cancelled: false,
        };
        let result = lost.completed_status().expect("worker disconnected");
        assert!(result.contains("without a result"));
        assert!(result.contains("no session authorized"));
    }

    #[test]
    fn pre_release_proof_probe_rejects_public_and_wildcard_network_listening() {
        for addr in [
            "0.0.0.0:21118",
            "[::]:21118",
            "8.8.8.8:21118",
            "203.0.113.11:21118",
            "[2606:4700:4700::1111]:21118",
            "127.0.0.1:0",
            "not-a-socket-address",
        ] {
            assert_eq!(
                allowed_proof_diagnostic_bind(addr),
                None,
                "probe must fail closed for {addr}"
            );
        }
        for addr in [
            "127.0.0.1:21118",
            "[::1]:21118",
            "10.0.0.4:21118",
            "172.16.1.10:21118",
            "192.168.1.15:21118",
            "[fd00::1]:21118",
        ] {
            assert_eq!(
                allowed_proof_diagnostic_bind(addr).map(|parsed| parsed.to_string()),
                Some(addr.to_owned()),
                "only explicitly named local/private interfaces may bind"
            );
        }
    }

    #[test]
    fn windows_high_dpi_launch_uses_physical_artboard_and_logical_minimum() {
        assert!(premium_frameless_on_monitor(1672.0, 941.0, 1.0));
        assert!(premium_frameless_on_monitor(1252.0, 678.0, 2.0));
        assert!(premium_frameless_on_monitor(1384.0, 816.0, 1.0));
        assert!(!premium_frameless_on_monitor(774.4, 547.2, 1.25));
        assert!(!premium_frameless_on_monitor(800.0, 600.0, f64::NAN));
        assert_eq!(1280.0 / 2.0, 640.0);
        assert_eq!(720.0 / 2.0, 360.0);
    }

    #[test]
    fn owner_locked_v7_caption_has_real_os_actions_and_compact_fallback() {
        assert_eq!(
            premium_caption_action(1672, 941, 1618, 29, true),
            Some(PremiumCaptionAction::Close)
        );
        assert_eq!(
            premium_caption_action(1672, 941, 1570, 29, true),
            Some(PremiumCaptionAction::Maximize)
        );
        assert_eq!(
            premium_caption_action(1672, 941, 1515, 29, true),
            Some(PremiumCaptionAction::Minimize)
        );
        assert_eq!(
            premium_caption_action(1672, 941, 650, 32, true),
            Some(PremiumCaptionAction::Drag)
        );
        assert!(premium_caption_action(1672, 941, 1320, 30, true).is_none());
        assert!(premium_caption_action(1672, 941, 1621, 78, true).is_none());
        assert!(premium_caption_action(1024, 768, 910, 20, false).is_none());
        let fitted = PremiumViewportFit::for_window(1440, 900).expect("fitted V7");
        let title_x = fitted.x + 1618 * fitted.width / 1672;
        let title_y = fitted.y + 29 * fitted.height / 941;
        assert_eq!(
            premium_caption_action(1440, 900, title_x, title_y, true),
            Some(PremiumCaptionAction::Close)
        );
        assert_eq!(
            premium_caption_action(1440, 900, title_x, 0, true),
            None,
            "letterboxed pixels must never trigger OS controls"
        );
    }

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
    fn transport_presence_cannot_bypass_trust_or_peer_identity() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "verified-peer".to_owned(),
            display_name: "Verified peer".to_owned(),
            status: DeviceStatus::Online,
        }]);
        shell
            .begin_connect("verified-peer")
            .expect("verified peer is in local directory");
        assert!(!verified_consent_for_authenticated_trust(
            &shell,
            Some("verified-peer"),
            false,
        ));
        assert!(!verified_consent_for_authenticated_trust(
            &shell, None, true
        ));
        assert!(!verified_consent_for_authenticated_trust(
            &shell,
            Some("other-peer"),
            true,
        ));
        assert!(verified_consent_for_authenticated_trust(
            &shell,
            Some("verified-peer"),
            true,
        ));
        shell.disconnect();
        assert!(!verified_consent_for_authenticated_trust(
            &shell,
            Some("verified-peer"),
            true,
        ));
    }

    #[test]
    fn trusted_peer_and_local_consent_cannot_bypass_missing_password_proof() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![DeviceSummary {
            id: "verified-peer".to_owned(),
            display_name: "Verified peer".to_owned(),
            status: DeviceStatus::Online,
        }]);
        shell
            .begin_connect("verified-peer")
            .expect("trusted directory peer");
        assert!(verified_consent_for_authenticated_trust(
            &shell,
            Some("verified-peer"),
            true,
        ));
        assert!(!verified_attended_session_authorization(
            &shell,
            Some("verified-peer"),
            true,
            super::ATTENDED_PASSWORD_PROOF_TRANSPORT_READY,
        ));
        assert!(!verified_attended_session_authorization(
            &shell,
            Some("verified-peer"),
            false,
            true,
        ));
        assert!(!verified_attended_session_authorization(
            &shell,
            Some("wrong-peer"),
            true,
            true,
        ));
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
