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
    device_filter: DeviceFilter,
    help_open: bool,
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
            device_filter: DeviceFilter::All,
            help_open: false,
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
    }

    #[must_use]
    pub const fn nav_tab(&self) -> NavTab {
        self.nav_tab
    }

    pub const fn set_nav_tab(&mut self, tab: NavTab) {
        self.nav_tab = tab;
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
        self.help_open = !self.help_open;
    }

    pub const fn set_help_open(&mut self, open: bool) {
        self.help_open = open;
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
}
