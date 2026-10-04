//! Roles and permissions.
//!
//! The design constraint is that permission assignment cannot grow. A role
//! table expressed as a `HashMap<Role, Vec<Permission>>` is extendable by any
//! caller who can reach the map; a `match` cannot. So the table is a `match`,
//! and the parse side rejects anything it does not recognise rather than
//! defaulting.

use super::Assurance;

/// Something a principal may do.
///
/// Closed set. There is no `Other(String)`, because a variant that swallows
/// unrecognised input is how an unknown permission becomes a permission.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Permission {
    /// View the devices enrolled in the tenant.
    DeviceList,
    /// Start a session against a device the principal operates.
    SessionStart,
    /// Attach to a running session.
    SessionAttach,
    /// Grant unattended access to a device.
    UnattendedGrant,
    /// Change tenant policy.
    PolicyEdit,
    /// Enrol or retire a device.
    DeviceManage,
    /// Enrol a principal or change their role.
    PrincipalManage,
    /// Read the audit history.
    AuditRead,
    /// Change a principal's own credentials.
    SelfService,
}

impl Permission {
    /// The wire name.
    ///
    /// Lower snake case, because these names appear in a policy document that
    /// someone will hand-edit.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DeviceList => "device_list",
            Self::SessionStart => "session_start",
            Self::SessionAttach => "session_attach",
            Self::UnattendedGrant => "unattended_grant",
            Self::PolicyEdit => "policy_edit",
            Self::DeviceManage => "device_manage",
            Self::PrincipalManage => "principal_manage",
            Self::AuditRead => "audit_read",
            Self::SelfService => "self_service",
        }
    }

    /// Every permission, in declaration order.
    ///
    /// Used by tests that assert exhaustiveness, and by the policy parser to
    /// reject unknown names.
    #[must_use]
    pub const fn all() -> [Self; 9] {
        [
            Self::DeviceList,
            Self::SessionStart,
            Self::SessionAttach,
            Self::UnattendedGrant,
            Self::PolicyEdit,
            Self::DeviceManage,
            Self::PrincipalManage,
            Self::AuditRead,
            Self::SelfService,
        ]
    }

    /// Parses a wire name.
    ///
    /// Returns `None` for anything unrecognised. Never a default: an unknown
    /// permission in a policy document must stop the document loading, not
    /// quietly become the least-privileged thing.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        // Matched by name rather than a table so `name()` and `parse()` cannot
        // drift: adding a variant without a name arm is a compile error, and
        // a name with no variant is unreachable rather than silently parsed.
        Some(match name {
            "device_list" => Self::DeviceList,
            "session_start" => Self::SessionStart,
            "session_attach" => Self::SessionAttach,
            "unattended_grant" => Self::UnattendedGrant,
            "policy_edit" => Self::PolicyEdit,
            "device_manage" => Self::DeviceManage,
            "principal_manage" => Self::PrincipalManage,
            "audit_read" => Self::AuditRead,
            "self_service" => Self::SelfService,
            _ => return None,
        })
    }

    /// Whether this permission changes what other principals can do.
    ///
    /// A classification, not the escalation rule. The escalation rule is
    /// [`Role::may_delegate`], which is bounded by what the granter's own role
    /// holds. `is_administrative` does not and must not gate delegation: an
    /// administrator is the role that holds these permissions, so refusing to
    /// delegate them because they are administrative would stop the only role
    /// that legitimately can.
    ///
    /// It is a predicate for classifying a permission for display or for a
    /// narrower decision that is not the ceiling. Kept honest by
    /// `escalation_the_administrative_classification_is_not_the_ceiling`.
    #[must_use]
    pub const fn is_administrative(self) -> bool {
        matches!(
            self,
            Self::PolicyEdit | Self::PrincipalManage | Self::UnattendedGrant
        )
    }
}

/// A job function within a tenant.
///
/// Roles are named rather than composed. A tenant that needs a role this
/// product has not heard of is a tenant that needs a product decision, not a
/// configuration string, because a configurable role is a role table that can
/// be edited by whoever can edit configuration -- which is the escalation
/// channel the whole module exists to close.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Role {
    /// May look, start sessions, and change their own credentials.
    Operator,
    /// Operator, plus device enrolment and audit reading.
    Supervisor,
    /// Supervisor, plus unattended access grants.
    Support,
    /// Full tenant control.
    Administrator,
    /// Read-only. The role a support engineer is dropped to while diagnosing.
    Auditor,
}

impl Role {
    /// Every role, in declaration order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Operator,
            Self::Supervisor,
            Self::Support,
            Self::Administrator,
            Self::Auditor,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Supervisor => "supervisor",
            Self::Support => "support",
            Self::Administrator => "administrator",
            Self::Auditor => "auditor",
        }
    }

    /// Parses a wire name, returning `None` for anything unrecognised.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "operator" => Self::Operator,
            "supervisor" => Self::Supervisor,
            "support" => Self::Support,
            "administrator" => Self::Administrator,
            "auditor" => Self::Auditor,
            _ => return None,
        })
    }

    /// What this role carries.
    ///
    /// A `match`, not a map. There is no way to register a role at runtime and
    /// no way for a caller to add a permission to one.
    #[must_use]
    pub const fn permissions(self) -> &'static [Permission] {
        match self {
            Self::Operator => &[
                Permission::DeviceList,
                Permission::SessionStart,
                Permission::SelfService,
            ],
            Self::Supervisor => &[
                Permission::DeviceList,
                Permission::SessionStart,
                Permission::SessionAttach,
                Permission::DeviceManage,
                Permission::AuditRead,
                Permission::SelfService,
            ],
            Self::Support => &[
                Permission::DeviceList,
                Permission::SessionStart,
                Permission::SessionAttach,
                Permission::UnattendedGrant,
                Permission::DeviceManage,
                Permission::AuditRead,
                Permission::SelfService,
            ],
            Self::Administrator => &[
                Permission::DeviceList,
                Permission::SessionStart,
                Permission::SessionAttach,
                Permission::UnattendedGrant,
                Permission::PolicyEdit,
                Permission::DeviceManage,
                Permission::PrincipalManage,
                Permission::AuditRead,
                Permission::SelfService,
            ],
            Self::Auditor => &[Permission::DeviceList, Permission::AuditRead],
        }
    }

    /// The authentication strength this role's permissions require.
    ///
    /// The floor applies to the role as a whole, so an administrator on a
    /// password cannot read the audit history. Per-permission floors were
    /// rejected: a policy that lowers the floor for one permission is a policy
    /// that lowers it for all of them, one edit later.
    #[must_use]
    pub const fn required_assurance(self) -> Assurance {
        match self {
            // Looking at a device list leaks who is at the desk. Still more
            // than a password.
            Self::Auditor | Self::Operator => Assurance::SingleFactor,
            Self::Supervisor | Self::Support => Assurance::MultiFactor,
            // A role that can rewrite policy must not be reachable on one
            // factor.
            Self::Administrator => Assurance::HardwareBacked,
        }
    }

    /// Whether a principal holding this role may delegate `permission` to
    /// another principal.
    ///
    /// Delegation is bounded by the granter's own role. There is no role from
    /// which any permission is delegable that the granter does not hold -- not
    /// Administrator -- because "administrator can grant anything" and "you
    /// can only pass on what you have" are the same rule, and the second is
    /// the one that survives a mistake.
    #[must_use]
    pub fn may_delegate(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}
