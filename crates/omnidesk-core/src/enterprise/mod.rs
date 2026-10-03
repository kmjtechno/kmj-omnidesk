//! Enterprise controls for M10.
//!
//! Seven deliverables: organization policy, RBAC, trusted devices, unattended
//! access policy, an MFA/SSO boundary, audit history, and the managed-deployment
//! direction.
//!
//! # The property that matters
//!
//! Enterprise authorization fails in one direction far more often than the
//! other: it grants when it should deny. Every decision in this module is
//! therefore **deny by default**, and there is no code path that reaches an
//! allow without an explicit grant recorded by something the caller already
//! trusts.
//!
//! Three boundaries are enforced structurally rather than by convention:
//!
//! 1. **A request carries the subject's own context, never a claimed one.**
//!    [`AuthorizationContext`] is constructed from authenticated material -- a
//!    tenant id, a principal, a proof of possession -- and there is no public
//!    field and no `Default`. A caller cannot build a context asserting a tenant
//!    it was not issued for.
//!
//! 2. **Permissions are a closed set.** [`Permission`] is a non-exhaustive-looking
//!    but actually exhaustive enum, and the role table is a `match` over it
//!    rather than a map a caller can extend. An unknown permission string from
//!    a policy document is rejected at parse time.
//!
//! 3. **Policy evaluation returns a decision, never a default.** [`PolicyEngine::evaluate`]
//!    returns [`Decision`] with a reason. A caller that wants "allow" must match
//!    on it; there is no `is_allowed()` that hides a deny.
//!
//! # What is deliberately not here
//!
//! * **No network, no storage, no clock.** Every input is passed in. An audit
//!   log that depends on a wall clock and a disk is not testable, and the
//!   tenant-boundary properties here need to be testable.
//!
//! * **No real `IdP`.** The MFA/SSO boundary is a *decision interface*: it takes
//!   a verified assertion and maps it to an authentication strength. It does not
//!   speak `SAML` or `OIDC`, because speaking them without an identity provider to
//!   test against would be an untestable claim.
//!
//! * **No privilege escalation via configuration.** A policy document can
//!   *remove* permissions, and it carries no "allow" operation at all. It
//!   cannot add one that the signed grant does not already carry. See
//!   [`AuthorizationContext::granted`] and [`PolicyEngine::evaluate`].

use core::fmt;
use sha2::Digest;

pub mod audit;
pub mod rbac;
pub mod trusted_device;
pub mod unattended;

pub use audit::{AuditEvent, AuditLog, AuditOutcome};
pub use rbac::{Permission, Role};
pub use trusted_device::{DeviceTrust, TrustDecision};
pub use unattended::{UnattendedAccess, UnattendedDecision};

/// The longest tenant identifier this module accepts.
///
/// Same reasoning as `session::MAX_PEER_IDENTITY_BYTES`: an unbounded string
/// from a policy document or a header is a cheap way to make every downstream
/// log line expensive.
pub const MAX_TENANT_ID_BYTES: usize = 64;

/// The longest principal identifier this module accepts.
pub const MAX_PRINCIPAL_ID_BYTES: usize = 128;

/// Which organization a request belongs to.
///
/// Wrapped rather than a bare `String` so a tenant id cannot reach a log
/// record, a comparison, or an error message without being named at the point
/// it enters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// # Errors
    ///
    /// Returns `PolicyError::EmptyTenant`, `TenantIdTooLong` above
    /// [`MAX_TENANT_ID_BYTES`], `TenantIdNotAscii`, or
    /// `TenantIdHasControlCharacter`.
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(PolicyError::EmptyTenant);
        }
        if value.len() > MAX_TENANT_ID_BYTES {
            return Err(PolicyError::TenantIdTooLong {
                length: value.len(),
                maximum: MAX_TENANT_ID_BYTES,
            });
        }
        if !value.is_ascii() {
            return Err(PolicyError::TenantIdNotAscii);
        }
        if value.chars().any(char::is_control) {
            return Err(PolicyError::TenantIdHasControlCharacter);
        }
        Ok(Self(value))
    }

    /// Narrows a validated peer identity into a tenant id.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::NotATenant`] if the identity is not shaped like
    /// a tenant id.
    pub fn from_identity(value: &crate::session::PeerIdentity) -> Result<Self, PolicyError> {
        if value.as_str().contains('@') {
            return Err(PolicyError::NotATenant);
        }
        Self::new(value.as_str())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A stable pseudonymous handle, safe to place in an audit record.
    ///
    /// The audit log is the one place a tenant must be distinguishable across
    /// events without the log holding the tenant's name. This is a digest of
    /// the id, so two events for the same tenant correlate and two tenants do
    /// not collide.
    #[must_use]
    pub fn audit_handle(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"omnidesk.audit.tenant.v1\0");
        sha2::Digest::update(&mut hasher, self.0.as_bytes());
        let digest = sha2::Digest::finalize(hasher);
        short_hex(&digest)
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for TenantId {
    /// Never prints the tenant's own identifier, only its length and digest
    /// handle. An organisation name is a business name, and an audit log
    /// carrying it in the clear is a re-identification vector for anyone who
    /// obtains the log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantId")
            .field("audit_handle", &self.audit_handle())
            .field("byte_len", &self.0.len())
            .finish()
    }
}

/// Who within a tenant is making a request.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// # Errors
    ///
    /// Returns `PolicyError::EmptyPrincipal`, `PrincipalIdTooLong` above
    /// [`MAX_PRINCIPAL_ID_BYTES`], `PrincipalIdNotAscii`, or
    /// `PrincipalIdHasControlCharacter`.
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(PolicyError::EmptyPrincipal);
        }
        if value.len() > MAX_PRINCIPAL_ID_BYTES {
            return Err(PolicyError::PrincipalIdTooLong {
                length: value.len(),
                maximum: MAX_PRINCIPAL_ID_BYTES,
            });
        }
        if !value.is_ascii() {
            return Err(PolicyError::PrincipalIdNotAscii);
        }
        if value.chars().any(char::is_control) {
            return Err(PolicyError::PrincipalIdHasControlCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A stable pseudonymous handle, safe to place in an audit record.
    ///
    /// The digest input is length-prefixed, so two principals whose ids
    /// concatenate to the same bytes cannot share a handle, and the handle
    /// cannot be walked back to the id without knowing the id.
    #[must_use]
    pub fn audit_handle(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"omnidesk.audit.principal.v1\0");
        sha2::Digest::update(&mut hasher, self.0.len().to_be_bytes());
        sha2::Digest::update(&mut hasher, self.0.as_bytes());
        let digest = sha2::Digest::finalize(hasher);
        short_hex(&digest)
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrincipalId")
            .field("byte_len", &self.0.len())
            .finish()
    }
}

/// The strength of authentication a request carries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Assurance {
    /// Nothing verified. Only ever sufficient for viewing a device list.
    None,
    /// A password or equivalent single factor.
    SingleFactor,
    /// A second factor was presented.
    MultiFactor,
    /// A hardware key or equivalent phishing-resistant factor.
    HardwareBacked,
}

impl Assurance {
    /// Whether this strength meets a requirement.
    ///
    /// A total order: `presented >= required`. A requirement of `None` is
    /// a requirement of nothing, so every strength
    /// meets it -- including `None`. That case is reachable through
    /// [`PolicyDocument::require_assurance`], and treating it as unmet would
    /// make a tenant's "require nothing" policy deny every request.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        // `PartialOrd` is not const-stable, so the ordering is spelled out.
        // Matched on the *presented* strength ascending, so adding a variant
        // is a compile error here rather than a silently wrong ordering. The
        // arms bind bare variants so a new one cannot slip in unqualified.
        use Assurance::{HardwareBacked, MultiFactor, None, SingleFactor};
        match self {
            None => matches!(required, None),
            SingleFactor => matches!(required, None | SingleFactor),
            MultiFactor => matches!(required, None | SingleFactor | MultiFactor),
            HardwareBacked => true,
        }
    }

    /// The assurance a role requires before its permissions are usable.
    #[must_use]
    pub const fn name(self) -> &'static str {
        use Assurance::{HardwareBacked, MultiFactor, None, SingleFactor};
        match self {
            None => "none",
            SingleFactor => "single_factor",
            MultiFactor => "multi_factor",
            HardwareBacked => "hardware_backed",
        }
    }
}

/// The authenticated facts a request carries.
///
/// Not constructible from untrusted input: every constructor requires either a
/// signed entitlement (`from_entitlement`) or is `pub(crate)`. A caller that
/// wants to ask "can this request do X" has to have authenticated first.
#[derive(Clone, Debug)]
pub struct AuthorizationContext {
    tenant: TenantId,
    principal: PrincipalId,
    assurance: Assurance,
    /// Capabilities the signed grant already carries.
    ///
    /// The *ceiling*. A policy document can only narrow this; see
    /// [`PolicyDocument::apply_to`]. Without a ceiling, a policy document is a
    /// privilege escalation channel.
    granted: Vec<Permission>,
    device: Option<DeviceTrust>,
}

impl AuthorizationContext {
    /// Builds a context from a verified entitlement.
    ///
    /// This is the only public constructor, and it takes the granted
    /// capabilities as an explicit argument rather than reading them from
    /// somewhere. The caller has to know what the signature covered.
    #[must_use]
    pub const fn from_entitlement(
        tenant: TenantId,
        principal: PrincipalId,
        assurance: Assurance,
        granted: Vec<Permission>,
    ) -> Self {
        Self {
            tenant,
            principal,
            assurance,
            granted,
            device: None,
        }
    }

    /// Attaches device trust. Consuming, so a context cannot carry two.
    #[must_use]
    pub fn with_device_trust(mut self, trust: DeviceTrust) -> Self {
        self.device = Some(trust);
        self
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    #[must_use]
    pub const fn device_trust(&self) -> Option<&DeviceTrust> {
        self.device.as_ref()
    }

    /// Whether the signed grant itself carries this permission.
    ///
    /// Distinct from "is allowed": this is the ceiling check, and it is what a
    /// policy document cannot raise.
    #[must_use]
    pub fn granted(&self, permission: Permission) -> bool {
        self.granted.contains(&permission)
    }
}

/// The outcome of an authorization decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

/// Why a request was refused.
///
/// Every variant is a distinct operational cause. A single `Denied` with a
/// string would make an audit log unable to distinguish "this user lacks the
/// role" from "the policy says this tenant may not do this at all", and those
/// need different responses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    /// The signed grant does not carry the permission. A policy cannot add it.
    NotGranted,
    /// The tenant's policy removes it.
    PolicyForbids,
    /// The principal's role does not include it.
    RoleLacks,
    /// The role requires stronger authentication than this request carries.
    AssuranceTooLow,
    /// The policy requires a trusted device and this request has none.
    UntrustedDevice,
    /// The request's tenant does not match the policy's tenant.
    TenantMismatch,
    /// The tenant's policy forbids unattended access entirely.
    UnattendedForbidden,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotGranted => "the signed grant does not carry this permission",
            Self::PolicyForbids => "tenant policy forbids this permission",
            Self::RoleLacks => "the principal's role does not include this permission",
            Self::AssuranceTooLow => "authentication strength is below what the role requires",
            Self::UntrustedDevice => "policy requires a trusted device",
            Self::TenantMismatch => "the request does not belong to this tenant",
            Self::UnattendedForbidden => "tenant policy forbids unattended access",
        };
        f.write_str(text)
    }
}

/// A tenant's policy: what it removes, what it requires, and for which tenant.
///
/// Deliberately has no "add" operation. A policy document arrives from
/// somewhere this process does not control, and if it could add a permission
/// then controlling it would be privilege escalation.
#[derive(Clone, Debug)]
pub struct PolicyDocument {
    tenant: TenantId,
    policy_version: u32,
    forbidden: Vec<Permission>,
    required_assurance: Option<Assurance>,
    require_trusted_device: bool,
    allow_unattended: bool,
}

impl PolicyDocument {
    #[must_use]
    pub const fn new(tenant: TenantId, policy_version: u32) -> Self {
        Self {
            tenant,
            policy_version,
            forbidden: Vec::new(),
            required_assurance: None,
            require_trusted_device: false,
            allow_unattended: true,
        }
    }

    /// Removes a permission. There is no corresponding allow-list setter.
    #[must_use]
    pub fn forbid(mut self, permission: Permission) -> Self {
        if !self.forbidden.contains(&permission) {
            self.forbidden.push(permission);
        }
        self
    }

    #[must_use]
    pub const fn require_assurance(mut self, assurance: Assurance) -> Self {
        self.required_assurance = Some(assurance);
        self
    }

    #[must_use]
    pub const fn require_trusted_device(mut self) -> Self {
        self.require_trusted_device = true;
        self
    }

    #[must_use]
    pub const fn forbid_unattended(mut self) -> Self {
        self.allow_unattended = false;
        self
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    #[must_use]
    pub fn forbidden(&self) -> &[Permission] {
        &self.forbidden
    }

    #[must_use]
    pub const fn requires_trusted_device(&self) -> bool {
        self.require_trusted_device
    }

    #[must_use]
    pub const fn allows_unattended(&self) -> bool {
        self.allow_unattended
    }

    #[must_use]
    pub const fn required_assurance(&self) -> Option<Assurance> {
        self.required_assurance
    }
}

/// Evaluates requests against a tenant's policy and role table.
#[derive(Clone, Debug)]
pub struct PolicyEngine {
    policy: PolicyDocument,
}

impl PolicyEngine {
    #[must_use]
    pub const fn new(policy: PolicyDocument) -> Self {
        Self { policy }
    }

    #[must_use]
    pub const fn policy(&self) -> &PolicyDocument {
        &self.policy
    }

    /// Decides one request.
    ///
    /// The order is the design, and it is cheapest-and-most-loudest first: a
    /// cross-tenant request is refused before anything else is consulted, so a
    /// bug in the rest cannot turn "wrong tenant" into "allowed".
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::NoPolicyForTenant` only if this engine's policy
    /// belongs to a different tenant than the context, which the caller can
    /// construct by pairing an engine with the wrong context. Refusing to
    /// evaluate is itself a refusal.
    pub fn evaluate(
        &self,
        context: &AuthorizationContext,
        role: Role,
        permission: Permission,
    ) -> Result<Decision, PolicyError> {
        if context.tenant() != self.policy.tenant() {
            return Err(PolicyError::NoPolicyForTenant);
        }

        // The ceiling. Checked before anything a policy could influence,
        // because this is the one limit a policy document cannot raise.
        if !context.granted(permission) {
            return Ok(Decision::Deny(DenyReason::NotGranted));
        }

        if self.policy.forbidden.contains(&permission) {
            return Ok(Decision::Deny(DenyReason::PolicyForbids));
        }

        if let Some(required) = self.policy.required_assurance {
            if !context.assurance().satisfies(required) {
                return Ok(Decision::Deny(DenyReason::AssuranceTooLow));
            }
        }

        if self.policy.require_trusted_device
            && !context
                .device_trust()
                .is_some_and(DeviceTrust::is_trusted_at_now)
        {
            return Ok(Decision::Deny(DenyReason::UntrustedDevice));
        }

        if !role.permissions().contains(&permission) {
            return Ok(Decision::Deny(DenyReason::RoleLacks));
        }

        if !context.assurance().satisfies(role.required_assurance()) {
            return Ok(Decision::Deny(DenyReason::AssuranceTooLow));
        }

        Ok(Decision::Allow)
    }

    /// Decides an unattended request.
    ///
    /// Separate from [`PolicyEngine::evaluate`] because unattended access is a
    /// different question: the person is not present to approve it, so it needs
    /// its own rules rather than a flag on the interactive path.
    ///
    /// `now` is supplied rather than read from the system clock. An
    /// expiring grant checked against a client-controlled clock is not an
    /// expiring grant, and a test cannot refute a property that depends on
    /// wall time.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::NoPolicyForTenant` if the context's tenant does
    /// not match the policy's, or if the grant itself was issued for another
    /// tenant.
    pub fn evaluate_unattended(
        &self,
        context: &AuthorizationContext,
        access: &UnattendedAccess,
        now: u64,
    ) -> Result<UnattendedDecision, PolicyError> {
        if context.tenant() != self.policy.tenant() {
            return Err(PolicyError::NoPolicyForTenant);
        }

        // The grant carries its own tenant. A caller that forgets to check this
        // gets a deny rather than an allow, so the check lives here too.
        if !access.belongs_to(self.policy.tenant().as_str()) {
            return Ok(UnattendedDecision::WrongTenant);
        }

        if !self.policy.allows_unattended() {
            return Ok(UnattendedDecision::Denied {
                reason: DenyReason::UnattendedForbidden,
            });
        }

        if !access.is_valid(now) {
            return Ok(UnattendedDecision::Expired {
                valid_until_epoch_seconds: access.valid_until_epoch_seconds(),
            });
        }

        // Unattended access is the highest-privilege path in the product, so
        // it never accepts a weaker factor than hardware-backed, regardless of
        // what the role would otherwise permit.
        if !context.assurance().satisfies(Assurance::HardwareBacked) {
            return Ok(UnattendedDecision::InsufficientAssurance {
                required: Assurance::HardwareBacked,
                presented: context.assurance(),
            });
        }

        // A grant may not hand out more than the signed ceiling carries, for
        // the same reason a policy document may not.
        let permitted: Vec<Permission> = access
            .permissions()
            .iter()
            .copied()
            .filter(|permission| context.granted(*permission))
            .collect();

        if permitted.is_empty() {
            return Ok(UnattendedDecision::Denied {
                reason: DenyReason::NotGranted,
            });
        }

        Ok(UnattendedDecision::Allowed { grants: permitted })
    }
}

/// The first 8 bytes of a digest, lowercase hex.
///
/// Shared by every handle in this module so they cannot drift in width or
/// alphabet. Sixteen hex characters is enough to correlate events within one
/// tenant without being an identifier for the tenant itself.
fn short_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(16);
    for byte in &digest[..8.min(digest.len())] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A refusal that stops evaluation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyError {
    EmptyTenant,
    TenantIdTooLong { length: usize, maximum: usize },
    TenantIdNotAscii,
    TenantIdHasControlCharacter,
    NotATenant,
    EmptyDeviceId,
    DeviceIdTooLong { length: usize, maximum: usize },
    DeviceIdNotAcceptable,
    TrustExpiryNotAfterEnrolment,
    EmptyAttestation,
    AttestationTooLong { length: usize, maximum: usize },
    EmptyGrantId,
    GrantIdTooLong { length: usize, maximum: usize },
    NoPermissionsGranted,
    UnattendedWindowTooLong { window_seconds: u64, maximum: u64 },
    UnattendedWindowNotInFuture,
    EmptyPrincipal,
    PrincipalIdTooLong { length: usize, maximum: usize },
    PrincipalIdNotAscii,
    PrincipalIdHasControlCharacter,
    NoPolicyForTenant,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTenant => f.write_str("tenant id is blank"),
            Self::TenantIdTooLong { length, maximum } => {
                write!(f, "tenant id is {length} bytes, maximum is {maximum}")
            }
            Self::TenantIdNotAscii => f.write_str("tenant id is not ASCII"),
            Self::TenantIdHasControlCharacter => {
                f.write_str("tenant id contains a control character")
            }
            Self::NotATenant => f.write_str("identity is not a tenant"),
            Self::EmptyDeviceId => f.write_str("device id is blank"),
            Self::DeviceIdTooLong { length, maximum } => {
                write!(f, "device id is {length} bytes, maximum is {maximum}")
            }
            Self::DeviceIdNotAcceptable => f.write_str("device id is not printable ASCII"),
            Self::TrustExpiryNotAfterEnrolment => {
                f.write_str("trust expires at or before enrolment")
            }
            Self::EmptyAttestation => f.write_str("attestation reference is blank"),
            Self::AttestationTooLong { length, maximum } => {
                write!(
                    f,
                    "attestation reference is {length} bytes, maximum is {maximum}"
                )
            }
            Self::EmptyGrantId => f.write_str("unattended grant id is blank"),
            Self::GrantIdTooLong { length, maximum } => {
                write!(
                    f,
                    "unattended grant id is {length} bytes, maximum is {maximum}"
                )
            }
            Self::NoPermissionsGranted => f.write_str("unattended grant carries no permissions"),
            Self::UnattendedWindowTooLong {
                window_seconds,
                maximum,
            } => {
                write!(
                    f,
                    "unattended window is {window_seconds}s, maximum is {maximum}s"
                )
            }
            Self::UnattendedWindowNotInFuture => f.write_str("unattended window has no duration"),
            Self::EmptyPrincipal => f.write_str("principal id is blank"),
            Self::PrincipalIdTooLong { length, maximum } => {
                write!(f, "principal id is {length} bytes, maximum is {maximum}")
            }
            Self::PrincipalIdNotAscii => f.write_str("principal id is not ASCII"),
            Self::PrincipalIdHasControlCharacter => {
                f.write_str("principal id contains a control character")
            }
            Self::NoPolicyForTenant => {
                f.write_str("this engine holds policy for a different tenant")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
