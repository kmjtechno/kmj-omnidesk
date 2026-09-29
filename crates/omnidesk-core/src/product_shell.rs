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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductShell {
    devices: Vec<DeviceSummary>,
    selected_device: Option<String>,
    security_state: SecurityState,
    quality_preset: QualityPreset,
    connection_stats: Option<ConnectionStats>,
}

impl ProductShell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: Vec::new(),
            selected_device: None,
            security_state: SecurityState::Disconnected,
            quality_preset: QualityPreset::Balanced,
            connection_stats: None,
        }
    }

    pub fn replace_devices(&mut self, devices: Vec<DeviceSummary>) {
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

    /// Starts a connection attempt for an online known device.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::UnknownDevice`] when the identifier is absent, or
    /// [`ConnectError::DeviceOffline`] when the device is not currently online.
    pub fn begin_connect(&mut self, device_id: &str) -> Result<(), ConnectError> {
        let device = self
            .devices
            .iter()
            .find(|device| device.id == device_id)
            .ok_or(ConnectError::UnknownDevice)?;

        if device.status != DeviceStatus::Online {
            return Err(ConnectError::DeviceOffline);
        }

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
}
