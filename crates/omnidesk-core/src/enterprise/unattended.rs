//! Unattended access.
//!
//! Unattended access is the one path in this product where a person grants a
//! stranger standing access to a machine, and nobody is present to notice the
//! stranger. Every other authorization question is about whether the *requesting*
//! principal may do something. This one is about leaving a durable capability
//! behind, so it gets its own rules rather than a flag on the interactive path:
//!
//! * it expires, and expiry is checked against a caller-supplied clock;
//! * it requires the strongest authentication strength the product models,
//!   regardless of role;
//! * a tenant can forbid it outright;
//! * it is revocable, and revocation is recorded rather than inferred from an
//!   absent grant.

use super::rbac::Permission;
use super::{Assurance, DenyReason, PolicyError};

/// The longest unattended grant identifier accepted.
pub const MAX_GRANT_ID_BYTES: usize = 128;

/// The longest unattended window accepted.
///
/// Not a product opinion about how long is reasonable; it is a bound so that
/// a grant cannot be issued "for ever" and then be described as expiring.
pub const MAX_UNATTENDED_WINDOW_SECONDS: u64 = 60 * 60 * 24 * 30;

/// A standing grant to reach a device without a person present.
///
/// Only constructible through [`UnattendedGrant::issue`], which is where the
/// bounds live. No public fields, no `Deserialize`.
#[derive(Clone, Debug)]
pub struct UnattendedAccess {
    grant_id: String,
    tenant: String,
    granted_to: String,
    device_id: String,
    permissions: Vec<Permission>,
    issued_at: u64,
    valid_until_epoch_seconds: u64,
    revoked: bool,
}

impl UnattendedAccess {
    /// Issues a grant.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::EmptyGrantId` or `GrantIdTooLong`,
    /// `NoPermissionsGranted` if the list is empty, or
    /// `UnattendedWindowTooLong` above [`MAX_UNATTENDED_WINDOW_SECONDS`].
    /// Also `UnattendedWindowNotInFuture` if the window has already elapsed,
    /// which is checked here rather than at use so a caller cannot mint a grant
    /// that is dead on arrival and file it as if it were not.
    pub fn issue(
        grant_id: &str,
        tenant: &str,
        granted_to: &str,
        device_id: &str,
        permissions: Vec<Permission>,
        issued_at: u64,
        valid_until_epoch_seconds: u64,
    ) -> Result<Self, PolicyError> {
        if grant_id.is_empty() {
            return Err(PolicyError::EmptyGrantId);
        }
        if grant_id.len() > MAX_GRANT_ID_BYTES {
            return Err(PolicyError::GrantIdTooLong {
                length: grant_id.len(),
                maximum: MAX_GRANT_ID_BYTES,
            });
        }
        if permissions.is_empty() {
            return Err(PolicyError::NoPermissionsGranted);
        }
        let window = valid_until_epoch_seconds.saturating_sub(issued_at);
        if window > MAX_UNATTENDED_WINDOW_SECONDS {
            return Err(PolicyError::UnattendedWindowTooLong {
                window_seconds: window,
                maximum: MAX_UNATTENDED_WINDOW_SECONDS,
            });
        }
        if window == 0 {
            return Err(PolicyError::UnattendedWindowNotInFuture);
        }
        Ok(Self {
            grant_id: grant_id.to_string(),
            tenant: tenant.to_string(),
            granted_to: granted_to.to_string(),
            device_id: device_id.to_string(),
            permissions,
            issued_at,
            valid_until_epoch_seconds,
            revoked: false,
        })
    }

    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn granted_to(&self) -> &str {
        &self.granted_to
    }

    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn valid_until_epoch_seconds(&self) -> u64 {
        self.valid_until_epoch_seconds
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Revokes this grant in place.
    pub const fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Whether the grant is live at `now`.
    ///
    /// Strictly less-than, so `now == valid_until` is expired. An expiring
    /// grant that is still valid at its expiry instant has no expiry.
    #[must_use]
    pub const fn is_valid(&self, now: u64) -> bool {
        !self.revoked && now < self.valid_until_epoch_seconds
    }

    /// Whether this grant was issued for `tenant`.
    ///
    /// Compared here as well as in the engine, because a grant carries its own
    /// tenant and evaluating a grant without checking it would mean the caller
    /// has to remember. A caller that forgets gets a deny here instead.
    #[must_use]
    pub fn belongs_to(&self, tenant: &str) -> bool {
        self.tenant == tenant
    }
}

/// The outcome of an unattended decision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UnattendedDecision {
    Allowed {
        grants: Vec<Permission>,
    },
    Denied {
        reason: DenyReason,
    },
    Expired {
        valid_until_epoch_seconds: u64,
    },
    InsufficientAssurance {
        required: Assurance,
        presented: Assurance,
    },
    WrongTenant,
}

impl UnattendedDecision {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}
