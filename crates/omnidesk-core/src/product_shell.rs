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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    UnknownDevice,
    DeviceOffline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductShell {
    devices: Vec<DeviceSummary>,
    selected_device: Option<String>,
    security_state: SecurityState,
}

impl ProductShell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: Vec::new(),
            selected_device: None,
            security_state: SecurityState::Disconnected,
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

    pub fn mark_authorized(&mut self) {
        if self.selected_device.is_some()
            && self.security_state == SecurityState::AuthorizationRequired
        {
            self.security_state = SecurityState::Authorized;
        }
    }

    pub fn disconnect(&mut self) {
        self.selected_device = None;
        self.security_state = SecurityState::Disconnected;
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
