//! Deterministic product-shell state for the native desktop UI.
//!
//! This module contains no rendering toolkit. It keeps security-sensitive
//! connection state explicit so native front ends can stay lightweight.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Offline,
    Online,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSummary {
    pub id: String,
    pub display_name: String,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    Disconnected,
    AuthorizationRequired,
    Authorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryView {
    Devices,
    PermissionPrompt,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    UnknownDevice,
    DeviceOffline,
    UntrustedPeer(String),
    DeviceRevoked(String),
    TrustExpired(String),
    CrossTenantRejected(String),
    AuthenticationFailed(String),
    PeerUnreachable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityPreset {
    DataSaver,
    Balanced,
    HighQuality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    pub latency_ms: u32,
    pub bitrate_kbps: u32,
    pub fps: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NavTab {
    #[default]
    Devices,
    /// Dedicated V5 sidebar directory, distinct from the Remote Access form.
    TrustedDevices,
    Connections,
    FileTransfer,
    RemoteActions,
    Automation,
    Security,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceFilter {
    #[default]
    All,
    Online,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferItem {
    pub id: String,
    pub filename: String,
    pub size_bytes: u64,
    pub progress_percent: u8,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditItem {
    pub timestamp_epoch_secs: u64,
    pub event_type: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProductShell {
    devices: Vec<DeviceSummary>,
    // Binds queued connect actions to the exact directory snapshot.
    device_revision: u64,
    selected_device: Option<String>,
    last_attempted_device: Option<String>,
    last_error: Option<String>,
    discovery_active: bool,
    security_state: SecurityState,
    quality_preset: QualityPreset,
    connection_stats: Option<ConnectionStats>,
    nav_tab: NavTab,
    workspace_scroll_y: usize,
    device_filter: DeviceFilter,
    help_open: bool,
    local_device_id: String,
    remote_id_input: String,
    remote_id_focused: bool,
    password_manager: crate::password_auth::SessionPasswordManager,
    remote_password_input: String,
    remote_password_focused: bool,
    remote_password_revealed: bool,
    remote_input_enabled: bool,
    fullscreen_enabled: bool,
    selected_monitor: usize,
    total_monitors: usize,
    clipboard_sync_enabled: bool,
    unattended_access_enabled: bool,
    file_transfers: Vec<FileTransferItem>,
    audit_log: Vec<SecurityAuditItem>,
}

impl ProductShell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: Vec::new(),
            device_revision: 0,
            selected_device: None,
            last_attempted_device: None,
            last_error: None,
            discovery_active: false,
            security_state: SecurityState::Disconnected,
            quality_preset: QualityPreset::Balanced,
            connection_stats: None,
            nav_tab: NavTab::Devices,
            workspace_scroll_y: 0,
            device_filter: DeviceFilter::All,
            help_open: false,
            local_device_id: String::new(),
            remote_id_input: String::new(),
            remote_id_focused: false,
            password_manager: crate::password_auth::SessionPasswordManager::unconfigured(),
            remote_password_input: String::new(),
            remote_password_focused: false,
            remote_password_revealed: false,
            remote_input_enabled: true,
            fullscreen_enabled: false,
            selected_monitor: 1,
            total_monitors: 1,
            clipboard_sync_enabled: true,
            unattended_access_enabled: false,
            file_transfers: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Replace the current device directory, invalidating queued connect actions
    /// only when the snapshot changes.
    ///
    /// # Panics
    /// Panics if the revision counter is exhausted after `u64::MAX` changes;
    /// stale actions must never become valid again through counter wraparound.
    pub fn replace_devices(&mut self, devices: Vec<DeviceSummary>) {
        if self.devices != devices {
            // Fail closed on exhaustion rather than allowing an old revision to recur.
            self.device_revision = self
                .device_revision
                .checked_add(1)
                .expect("device directory revision exhausted");
        }
        self.devices = devices;
        if self
            .selected_device
            .as_ref()
            .is_some_and(|selected| !self.devices.iter().any(|device| &device.id == selected))
        {
            self.disconnect();
        }
    }

    #[must_use]
    pub fn devices(&self) -> &[DeviceSummary] {
        &self.devices
    }

    #[must_use]
    pub const fn device_revision(&self) -> u64 {
        self.device_revision
    }

    #[must_use]
    pub fn selected_device(&self) -> Option<&str> {
        self.selected_device.as_deref()
    }

    #[must_use]
    pub const fn security_state(&self) -> SecurityState {
        self.security_state
    }

    #[must_use]
    pub const fn primary_view(&self) -> PrimaryView {
        match self.security_state {
            SecurityState::Disconnected => PrimaryView::Devices,
            SecurityState::AuthorizationRequired => PrimaryView::PermissionPrompt,
            SecurityState::Authorized => PrimaryView::Session,
        }
    }

    #[must_use]
    pub const fn quality_preset(&self) -> QualityPreset {
        self.quality_preset
    }

    pub const fn set_quality_preset(&mut self, preset: QualityPreset) {
        self.quality_preset = preset;
    }

    #[must_use]
    pub const fn connection_stats(&self) -> Option<ConnectionStats> {
        self.connection_stats
    }

    pub const fn update_connection_stats(&mut self, stats: ConnectionStats) {
        self.connection_stats = Some(stats);
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn set_error(&mut self, err: impl Into<String>) {
        self.last_error = Some(err.into());
    }

    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    #[must_use]
    pub const fn is_discovering(&self) -> bool {
        self.discovery_active
    }

    pub fn start_discovery(&mut self) {
        self.discovery_active = true;
        self.last_error = None;
    }

    pub const fn stop_discovery(&mut self) {
        self.discovery_active = false;
    }

    /// Retries the most recent connection attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::UnknownDevice`] if no prior device was attempted,
    /// or the error returned by [`ProductShell::begin_connect`].
    pub fn retry_connect(&mut self) -> Result<(), ConnectError> {
        self.last_attempted_device
            .clone()
            .map_or(Err(ConnectError::UnknownDevice), |id| {
                self.begin_connect(&id)
            })
    }

    /// Starts a connection attempt for an online known device.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::UnknownDevice`] when the identifier is absent, or
    /// [`ConnectError::DeviceOffline`] when the device is not currently online.
    pub fn begin_connect(&mut self, device_id: &str) -> Result<(), ConnectError> {
        self.last_attempted_device = Some(device_id.to_owned());
        let device = self
            .devices
            .iter()
            .find(|device| device.id == device_id)
            .ok_or_else(|| {
                let err = ConnectError::UnknownDevice;
                self.last_error = Some(format!("Unknown device '{device_id}'"));
                err
            })?;

        if device.status != DeviceStatus::Online {
            self.last_error = Some(format!(
                "Device '{}' is offline - verify power and network",
                device.display_name
            ));
            return Err(ConnectError::DeviceOffline);
        }

        self.last_error = None;
        self.selected_device = Some(device.id.clone());
        self.security_state = SecurityState::AuthorizationRequired;
        Ok(())
    }

    /// Starts a connection attempt against an enrolled trusted device record.
    ///
    /// Validates device presence in the directory, online status, enrollment in
    /// the trusted device store, non-revocation, and valid time bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::UnknownDevice`] if absent from directory,
    /// [`ConnectError::DeviceOffline`] if offline,
    /// [`ConnectError::UntrustedPeer`] if not enrolled in the trusted store,
    /// [`ConnectError::DeviceRevoked`] if trust was revoked, or
    /// [`ConnectError::TrustExpired`] if the trust expiration timestamp has elapsed.
    pub fn begin_connect_trusted(
        &mut self,
        device_id: &str,
        store: &crate::trusted_device_store::TrustedDeviceStore,
        current_epoch_secs: u64,
    ) -> Result<(), ConnectError> {
        self.last_attempted_device = Some(device_id.to_owned());
        let device = self
            .devices
            .iter()
            .find(|d| d.id == device_id)
            .ok_or_else(|| {
                let err = ConnectError::UnknownDevice;
                self.last_error = Some(format!("Unknown device '{device_id}'"));
                err
            })?;

        if device.status != DeviceStatus::Online {
            self.last_error = Some(format!(
                "Device '{}' is offline - verify power and network",
                device.display_name
            ));
            return Err(ConnectError::DeviceOffline);
        }

        let record = store.get(device_id).ok_or_else(|| {
            let err = ConnectError::UntrustedPeer(device_id.to_owned());
            self.last_error = Some(format!(
                "Device '{device_id}' is not enrolled in the trusted device store"
            ));
            err
        })?;

        if record.revoked {
            let err = ConnectError::DeviceRevoked(device_id.to_owned());
            self.last_error = Some(format!("Device '{device_id}' trust has been revoked"));
            return Err(err);
        }

        if current_epoch_secs > record.trust_expires_at_epoch_secs {
            let err = ConnectError::TrustExpired(device_id.to_owned());
            self.last_error = Some(format!(
                "Device '{device_id}' trust expired at {}",
                record.trust_expires_at_epoch_secs
            ));
            return Err(err);
        }

        self.last_error = None;
        self.selected_device = Some(device.id.clone());
        self.security_state = SecurityState::AuthorizationRequired;
        Ok(())
    }

    pub fn decide_permission(&mut self, decision: PermissionDecision) {
        if self.selected_device.is_none()
            || self.security_state != SecurityState::AuthorizationRequired
        {
            return;
        }

        match decision {
            PermissionDecision::Allow => {
                self.security_state = SecurityState::Authorized;
            }
            PermissionDecision::Deny => self.disconnect(),
        }
    }

    pub fn mark_authorized(&mut self) {
        self.decide_permission(PermissionDecision::Allow);
    }

    pub fn disconnect(&mut self) {
        self.selected_device = None;
        self.security_state = SecurityState::Disconnected;
        self.connection_stats = None;
        // Never retain an entered remote session password across disconnection
        // or a failed/revoked connection attempt. This clears logical state;
        // secure heap zeroization must be added before handling real secrets.
        self.remote_password_input.clear();
        self.remote_password_focused = false;
        self.remote_password_revealed = false;
    }

    #[must_use]
    pub const fn nav_tab(&self) -> NavTab {
        self.nav_tab
    }

    /// Scroll offset for V5's center column; left rail and inspector stay fixed.
    #[must_use]
    pub const fn workspace_scroll_y(&self) -> usize {
        self.workspace_scroll_y
    }

    /// The Windows host clamps this to the actual viewport height.
    pub const fn set_workspace_scroll_y(&mut self, scroll: usize) {
        self.workspace_scroll_y = scroll.min(1240);
    }

    pub fn set_nav_tab(&mut self, tab: NavTab) {
        self.nav_tab = tab;
        self.workspace_scroll_y = 0;
        // The Help overlay is page-specific; a sidebar choice must reveal
        // the selected page rather than leave Help covering the workspace.
        self.help_open = false;
        // The V5 sidebar switches to a different native page. Never allow a
        // hidden Remote Access input to keep accepting keyboard characters.
        self.remote_id_focused = false;
        self.set_remote_password_focused(false);
        if tab != NavTab::Devices {
            self.clear_remote_password();
        }
    }

    #[must_use]
    pub const fn device_filter(&self) -> DeviceFilter {
        self.device_filter
    }

    pub const fn set_device_filter(&mut self, filter: DeviceFilter) {
        self.device_filter = filter;
    }

    #[must_use]
    pub const fn is_help_open(&self) -> bool {
        self.help_open
    }

    pub const fn toggle_help(&mut self) {
        self.set_help_open(!self.help_open);
    }

    pub const fn set_help_open(&mut self, open: bool) {
        self.help_open = open;
        if open {
            // Open Help from its visible top-bar position instead of leaving
            // the overlay scrolled off screen beneath the frozen sidebar.
            self.workspace_scroll_y = 0;
            // Help replaces the Remote Access canvas. Blur hidden fields,
            // including any revealed password, before rendering Help.
            self.remote_id_focused = false;
            self.set_remote_password_focused(false);
        }
    }

    #[must_use]
    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub fn set_local_device_id(&mut self, id: impl Into<String>) {
        self.local_device_id = id.into();
    }

    #[must_use]
    pub fn remote_id_input(&self) -> &str {
        &self.remote_id_input
    }

    pub fn set_remote_id_input(&mut self, input: impl Into<String>) {
        self.remote_id_input = input.into();
    }

    pub fn append_remote_id_char(&mut self, c: char) {
        if self.remote_id_input.len() < crate::device_identity::MAX_REMOTE_ID_LEN
            && (c.is_ascii_alphanumeric() || c == '-' || c == ' ' || c == '_')
        {
            self.remote_id_input.push(c);
        }
    }

    pub fn backspace_remote_id(&mut self) {
        self.remote_id_input.pop();
    }

    pub fn clear_remote_id(&mut self) {
        self.remote_id_input.clear();
    }

    #[must_use]
    pub const fn is_remote_id_focused(&self) -> bool {
        self.remote_id_focused
    }

    pub const fn set_remote_id_focused(&mut self, focused: bool) {
        self.remote_id_focused = focused;
    }

    /// Validates `remote_id_input` and sets selected device.
    ///
    /// # Errors
    /// Returns [`ConnectError`] if the Remote ID is invalid or matches `local_device_id`.
    pub fn begin_connect_remote_id(&mut self) -> Result<String, ConnectError> {
        let local_opt = if self.local_device_id.is_empty() {
            None
        } else {
            Some(self.local_device_id.as_str())
        };
        match crate::device_identity::validate_remote_id(&self.remote_id_input, local_opt) {
            Ok(normalized) => {
                self.selected_device = Some(normalized.clone());
                self.last_attempted_device = Some(normalized.clone());
                self.security_state = SecurityState::AuthorizationRequired;
                self.last_error = None;
                self.remote_id_focused = false;
                Ok(normalized)
            }
            Err(err) => {
                let msg = err.to_string();
                self.set_error(msg.clone());
                Err(ConnectError::UntrustedPeer(msg))
            }
        }
    }

    #[must_use]
    pub const fn password_manager(&self) -> &crate::password_auth::SessionPasswordManager {
        &self.password_manager
    }

    pub const fn password_manager_mut(
        &mut self,
    ) -> &mut crate::password_auth::SessionPasswordManager {
        &mut self.password_manager
    }

    #[must_use]
    pub fn remote_password_input(&self) -> &str {
        &self.remote_password_input
    }

    pub fn set_remote_password_input(&mut self, input: impl Into<String>) {
        // Match keyboard input limits; prevent programmatic/paste input from
        // storing unbounded data or terminal control characters.
        self.remote_password_input = input
            .into()
            .chars()
            .filter(|c| !c.is_control())
            .take(32)
            .collect();
        self.remote_password_revealed = false;
    }

    pub fn append_remote_password_char(&mut self, c: char) {
        if self.remote_password_input.len() < 32 && !c.is_control() {
            self.remote_password_input.push(c);
            self.remote_password_revealed = false;
        }
    }

    pub fn backspace_remote_password(&mut self) {
        self.remote_password_input.pop();
        self.remote_password_revealed = false;
    }

    pub fn clear_remote_password(&mut self) {
        self.remote_password_input.clear();
        self.remote_password_revealed = false;
    }

    #[must_use]
    pub const fn is_remote_password_revealed(&self) -> bool {
        self.remote_password_revealed
    }

    /// Reveal is a conscious local UI choice, never a permission grant.
    pub fn toggle_remote_password_reveal(&mut self) {
        if !self.remote_password_input.is_empty() {
            self.remote_password_revealed = !self.remote_password_revealed;
        }
    }

    #[must_use]
    pub const fn is_remote_password_focused(&self) -> bool {
        self.remote_password_focused
    }

    pub const fn set_remote_password_focused(&mut self, focused: bool) {
        self.remote_password_focused = focused;
        // Explicit reveal never persists when the secret input loses focus.
        if !focused {
            self.remote_password_revealed = false;
        }
    }

    pub const fn focus_remote_id(&mut self) {
        self.remote_id_focused = true;
        self.remote_password_focused = false;
        self.remote_password_revealed = false;
    }

    pub const fn focus_remote_password(&mut self) {
        self.remote_id_focused = false;
        self.remote_password_focused = true;
    }

    pub const fn toggle_local_password_reveal(&mut self) {
        self.password_manager.toggle_reveal();
    }

    pub fn rotate_local_password(&mut self, now_epoch_secs: u64) {
        self.password_manager.rotate(now_epoch_secs);
        self.add_audit_event(
            "PASSWORD_ROTATED",
            "Local session password rotated",
            now_epoch_secs,
        );
    }

    #[must_use]
    pub const fn remote_input_enabled(&self) -> bool {
        self.remote_input_enabled
    }

    pub const fn toggle_remote_input(&mut self) {
        self.remote_input_enabled = !self.remote_input_enabled;
    }

    #[must_use]
    pub const fn fullscreen_enabled(&self) -> bool {
        self.fullscreen_enabled
    }

    pub const fn toggle_fullscreen(&mut self) {
        self.fullscreen_enabled = !self.fullscreen_enabled;
    }

    #[must_use]
    pub const fn selected_monitor(&self) -> usize {
        self.selected_monitor
    }

    #[must_use]
    pub const fn total_monitors(&self) -> usize {
        self.total_monitors
    }

    pub fn set_total_monitors(&mut self, total: usize) {
        self.total_monitors = total.max(1);
    }

    pub const fn next_monitor(&mut self) {
        if self.total_monitors > 1 {
            self.selected_monitor = (self.selected_monitor % self.total_monitors) + 1;
        }
    }

    #[must_use]
    pub const fn clipboard_sync_enabled(&self) -> bool {
        self.clipboard_sync_enabled
    }

    pub const fn toggle_clipboard_sync(&mut self) {
        self.clipboard_sync_enabled = !self.clipboard_sync_enabled;
    }

    #[must_use]
    pub const fn unattended_access_enabled(&self) -> bool {
        self.unattended_access_enabled
    }

    pub const fn toggle_unattended_access(&mut self) {
        self.unattended_access_enabled = !self.unattended_access_enabled;
    }

    #[must_use]
    pub fn file_transfers(&self) -> &[FileTransferItem] {
        &self.file_transfers
    }

    pub fn add_file_transfer(&mut self, item: FileTransferItem) {
        self.file_transfers.push(item);
    }

    pub fn cancel_file_transfer(&mut self, id: &str) {
        if let Some(item) = self.file_transfers.iter_mut().find(|t| t.id == id) {
            "Cancelled".clone_into(&mut item.status);
        }
    }

    #[must_use]
    pub fn audit_log(&self) -> &[SecurityAuditItem] {
        &self.audit_log
    }

    pub fn add_audit_event(
        &mut self,
        event_type: impl Into<String>,
        detail: impl Into<String>,
        now_epoch_secs: u64,
    ) {
        self.audit_log.push(SecurityAuditItem {
            timestamp_epoch_secs: now_epoch_secs,
            event_type: event_type.into(),
            detail: detail.into(),
        });
        if self.audit_log.len() > 50 {
            self.audit_log.remove(0);
        }
    }
}

impl Default for ProductShell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, status: DeviceStatus) -> DeviceSummary {
        DeviceSummary {
            id: id.to_owned(),
            display_name: format!("Device {id}"),
            status,
        }
    }

    #[test]
    fn online_device_requires_authorization_before_authorized_state() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);

        assert_eq!(shell.begin_connect("desk-1"), Ok(()));
        assert_eq!(shell.selected_device(), Some("desk-1"));
        assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);

        shell.mark_authorized();
        assert_eq!(shell.security_state(), SecurityState::Authorized);
    }

    #[test]
    fn offline_and_unknown_devices_never_enter_connect_flow() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Offline)]);

        assert_eq!(
            shell.begin_connect("desk-1"),
            Err(ConnectError::DeviceOffline)
        );
        assert_eq!(
            shell.begin_connect("missing"),
            Err(ConnectError::UnknownDevice)
        );
        assert_eq!(shell.selected_device(), None);
        assert_eq!(shell.security_state(), SecurityState::Disconnected);
    }

    #[test]
    fn primary_flow_moves_devices_prompt_session_without_terminal_state() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);
        assert_eq!(shell.primary_view(), PrimaryView::Devices);

        shell.begin_connect("desk-1").unwrap();
        assert_eq!(shell.primary_view(), PrimaryView::PermissionPrompt);

        shell.decide_permission(PermissionDecision::Allow);
        assert_eq!(shell.primary_view(), PrimaryView::Session);

        shell.disconnect();
        assert_eq!(shell.primary_view(), PrimaryView::Devices);
    }

    #[test]
    fn denied_permission_fails_closed_and_clears_selected_device() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);
        shell.begin_connect("desk-1").unwrap();

        shell.decide_permission(PermissionDecision::Deny);

        assert_eq!(shell.selected_device(), None);
        assert_eq!(shell.security_state(), SecurityState::Disconnected);
        assert_eq!(shell.connection_stats(), None);
    }

    #[test]
    fn permission_decisions_are_ignored_without_a_pending_prompt() {
        let mut shell = ProductShell::new();
        shell.decide_permission(PermissionDecision::Allow);
        assert_eq!(shell.security_state(), SecurityState::Disconnected);

        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);
        shell.begin_connect("desk-1").unwrap();
        shell.decide_permission(PermissionDecision::Allow);
        assert_eq!(shell.security_state(), SecurityState::Authorized);

        shell.decide_permission(PermissionDecision::Deny);
        assert_eq!(shell.security_state(), SecurityState::Authorized);
    }

    #[test]
    fn quality_controls_and_stats_are_explicit_and_stats_clear_on_disconnect() {
        let mut shell = ProductShell::new();
        assert_eq!(shell.quality_preset(), QualityPreset::Balanced);
        assert_eq!(shell.connection_stats(), None);

        shell.set_quality_preset(QualityPreset::DataSaver);
        shell.update_connection_stats(ConnectionStats {
            latency_ms: 42,
            bitrate_kbps: 900,
            fps: 30,
        });

        assert_eq!(shell.quality_preset(), QualityPreset::DataSaver);
        assert_eq!(
            shell.connection_stats(),
            Some(ConnectionStats {
                latency_ms: 42,
                bitrate_kbps: 900,
                fps: 30,
            })
        );

        shell.disconnect();
        assert_eq!(shell.connection_stats(), None);
        assert_eq!(shell.quality_preset(), QualityPreset::DataSaver);
    }

    #[test]
    fn disappearing_selected_device_fails_closed() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);
        shell.begin_connect("desk-1").unwrap();
        shell.mark_authorized();

        shell.replace_devices(vec![device("desk-2", DeviceStatus::Online)]);

        assert_eq!(shell.selected_device(), None);
        assert_eq!(shell.security_state(), SecurityState::Disconnected);
    }

    #[test]
    fn offline_connect_records_explicit_error_and_supports_retry() {
        let mut shell = ProductShell::new();
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Offline)]);

        let err = shell.begin_connect("desk-1");
        assert_eq!(err, Err(ConnectError::DeviceOffline));
        assert!(shell.last_error().unwrap().contains("offline"));

        // Update to online and retry
        shell.replace_devices(vec![device("desk-1", DeviceStatus::Online)]);
        assert!(shell.retry_connect().is_ok());
        assert_eq!(shell.last_error(), None);
        assert_eq!(shell.selected_device(), Some("desk-1"));
        assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);
    }

    #[test]
    fn discovery_lifecycle_toggles_state_cleanly() {
        let mut shell = ProductShell::new();
        assert!(!shell.is_discovering());

        shell.start_discovery();
        assert!(shell.is_discovering());

        shell.stop_discovery();
        assert!(!shell.is_discovering());
    }

    #[test]
    fn trusted_connect_validates_store_revocation_and_expiration() {
        use crate::trusted_device_store::{
            PersistedDeviceStatus, TrustedDeviceRecord, TrustedDeviceStore,
        };

        let mut shell = ProductShell::new();
        shell.replace_devices(vec![
            device("desk-trusted", DeviceStatus::Online),
            device("desk-revoked", DeviceStatus::Online),
            device("desk-expired", DeviceStatus::Online),
            device("desk-offline", DeviceStatus::Offline),
            device("desk-untrusted", DeviceStatus::Online),
        ]);

        let mut store = TrustedDeviceStore::new();
        let valid_pk = [0x55_u8; 32];
        store
            .add(TrustedDeviceRecord {
                device_id: "desk-trusted".to_owned(),
                display_name: "Desk Trusted".to_owned(),
                public_key: valid_pk,
                enrolled_at_epoch_secs: 1000,
                trust_expires_at_epoch_secs: 2000,
                managed: true,
                revoked: false,
                status: PersistedDeviceStatus::Online,
            })
            .unwrap();

        store
            .add(TrustedDeviceRecord {
                device_id: "desk-revoked".to_owned(),
                display_name: "Desk Revoked".to_owned(),
                public_key: valid_pk,
                enrolled_at_epoch_secs: 1000,
                trust_expires_at_epoch_secs: 2000,
                managed: true,
                revoked: true,
                status: PersistedDeviceStatus::Online,
            })
            .unwrap();

        store
            .add(TrustedDeviceRecord {
                device_id: "desk-expired".to_owned(),
                display_name: "Desk Expired".to_owned(),
                public_key: valid_pk,
                enrolled_at_epoch_secs: 1000,
                trust_expires_at_epoch_secs: 1500,
                managed: true,
                revoked: false,
                status: PersistedDeviceStatus::Online,
            })
            .unwrap();

        store
            .add(TrustedDeviceRecord {
                device_id: "desk-offline".to_owned(),
                display_name: "Desk Offline".to_owned(),
                public_key: valid_pk,
                enrolled_at_epoch_secs: 1000,
                trust_expires_at_epoch_secs: 2000,
                managed: true,
                revoked: false,
                status: PersistedDeviceStatus::Offline,
            })
            .unwrap();

        let now = 1600;

        // 1. Success on valid trusted device
        assert_eq!(
            shell.begin_connect_trusted("desk-trusted", &store, now),
            Ok(())
        );
        assert_eq!(shell.selected_device(), Some("desk-trusted"));
        assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);
        assert_eq!(shell.last_error(), None);

        // 2. Reject untrusted device not in store
        assert_eq!(
            shell.begin_connect_trusted("desk-untrusted", &store, now),
            Err(ConnectError::UntrustedPeer("desk-untrusted".to_owned()))
        );
        assert!(shell.last_error().unwrap().contains("not enrolled"));

        // 3. Reject revoked device
        assert_eq!(
            shell.begin_connect_trusted("desk-revoked", &store, now),
            Err(ConnectError::DeviceRevoked("desk-revoked".to_owned()))
        );
        assert!(shell.last_error().unwrap().contains("revoked"));

        // 4. Reject expired device
        assert_eq!(
            shell.begin_connect_trusted("desk-expired", &store, now),
            Err(ConnectError::TrustExpired("desk-expired".to_owned()))
        );
        assert!(shell.last_error().unwrap().contains("expired"));

        // 5. Reject offline device
        assert_eq!(
            shell.begin_connect_trusted("desk-offline", &store, now),
            Err(ConnectError::DeviceOffline)
        );
        assert!(shell.last_error().unwrap().contains("offline"));
    }

    #[test]
    fn v5_sidebar_navigation_closes_help_overlay_and_shows_selected_page() {
        let mut shell = ProductShell::new();
        shell.set_help_open(true);
        assert!(shell.is_help_open());
        shell.set_nav_tab(NavTab::Settings);
        assert_eq!(shell.nav_tab(), NavTab::Settings);
        assert!(!shell.is_help_open());
        shell.set_help_open(true);
        shell.set_nav_tab(NavTab::Devices);
        assert!(!shell.is_help_open());
    }

    #[test]
    fn v5_help_overlay_blurs_hidden_password_and_resets_reveal() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("ui-test-only");
        shell.focus_remote_password();
        shell.toggle_remote_password_reveal();
        assert!(shell.is_remote_password_revealed());
        shell.set_help_open(true);
        assert!(shell.is_help_open());
        assert!(!shell.is_remote_password_focused());
        assert!(!shell.is_remote_password_revealed());
        shell.toggle_help();
        assert!(!shell.is_help_open());
    }

    #[test]
    fn v5_sidebar_transition_clears_hidden_password_and_keyboard_focus() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("temporary-secret");
        shell.focus_remote_password();
        shell.toggle_remote_password_reveal();
        assert!(shell.is_remote_password_focused());
        assert!(shell.is_remote_password_revealed());
        shell.set_nav_tab(NavTab::Security);
        assert_eq!(shell.nav_tab(), NavTab::Security);
        assert_eq!(shell.remote_password_input(), "");
        assert!(!shell.is_remote_password_focused());
        assert!(!shell.is_remote_password_revealed());
        shell.set_nav_tab(NavTab::Devices);
        assert!(!shell.is_remote_password_focused());
    }

    #[test]
    fn password_visibility_is_reset_when_the_field_blurs() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("ui-only");
        shell.focus_remote_password();
        shell.toggle_remote_password_reveal();
        assert!(shell.is_remote_password_revealed());
        shell.set_remote_password_focused(false);
        assert!(!shell.is_remote_password_revealed());
        assert!(!shell.is_remote_password_focused());
    }

    #[test]
    fn remote_password_reveal_resets_on_edit_or_focus_change() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("preview-only");
        shell.toggle_remote_password_reveal();
        assert!(shell.is_remote_password_revealed());
        shell.append_remote_password_char('!');
        assert!(!shell.is_remote_password_revealed());
        shell.toggle_remote_password_reveal();
        shell.backspace_remote_password();
        assert!(!shell.is_remote_password_revealed());
        shell.toggle_remote_password_reveal();
        shell.focus_remote_id();
        assert!(!shell.is_remote_password_revealed());
    }

    #[test]
    fn remote_password_is_masked_by_default_and_resets_on_disconnect() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input("local-ui-only");
        assert!(!shell.is_remote_password_revealed());
        shell.toggle_remote_password_reveal();
        assert!(shell.is_remote_password_revealed());
        shell.disconnect();
        assert!(!shell.is_remote_password_revealed());
        assert_eq!(shell.remote_password_input(), "");
    }

    #[test]
    fn remote_password_input_is_bounded_and_cleared_on_disconnect() {
        let mut shell = ProductShell::new();
        shell.set_remote_password_input(format!("{}\n", "x".repeat(200)));
        assert_eq!(shell.remote_password_input().chars().count(), 32);
        shell.set_remote_password_input("abcd-1234\r\n");
        assert_eq!(shell.remote_password_input(), "abcd-1234");
        shell.focus_remote_password();
        assert!(shell.is_remote_password_focused());
        shell.disconnect();
        assert_eq!(shell.remote_password_input(), "");
        assert!(!shell.is_remote_password_focused());
    }

    #[test]
    fn remote_id_input_and_connect_flow() {
        let mut shell = ProductShell::new();
        shell.set_local_device_id("KMJ-111-222-333");
        assert_eq!(shell.local_device_id(), "KMJ-111-222-333");

        // Type remote ID characters
        shell.set_remote_id_focused(true);
        assert!(shell.is_remote_id_focused());

        shell.append_remote_id_char('4');
        shell.append_remote_id_char('5');
        shell.append_remote_id_char('6');
        shell.append_remote_id_char('-');
        shell.append_remote_id_char('7');
        shell.append_remote_id_char('8');
        shell.append_remote_id_char('9');
        shell.append_remote_id_char('-');
        shell.append_remote_id_char('0');
        shell.append_remote_id_char('1');
        shell.append_remote_id_char('2');
        assert_eq!(shell.remote_id_input(), "456-789-012");

        // Backspace and append
        shell.backspace_remote_id();
        assert_eq!(shell.remote_id_input(), "456-789-01");
        shell.append_remote_id_char('2');
        assert_eq!(shell.remote_id_input(), "456-789-012");

        // Connect valid remote ID
        let res = shell.begin_connect_remote_id();
        assert_eq!(res, Ok("KMJ-456-789-012".to_owned()));
        assert_eq!(shell.selected_device(), Some("KMJ-456-789-012"));
        assert_eq!(shell.security_state(), SecurityState::AuthorizationRequired);
        assert!(!shell.is_remote_id_focused());

        // Self-connection must be refused
        shell.disconnect();
        shell.set_remote_id_input("111 222 333");
        let self_res = shell.begin_connect_remote_id();
        assert!(self_res.is_err());
        assert!(
            shell
                .last_error()
                .unwrap()
                .contains("Cannot connect to self")
        );
        assert_eq!(shell.security_state(), SecurityState::Disconnected);
    }
}
