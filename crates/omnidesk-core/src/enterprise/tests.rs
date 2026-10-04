//! Tests for M10 enterprise controls.
//!
//! Every test carries a `Mutation:` line naming the single edit that would make
//! it fail if the property it covers were removed. Each was applied and each
//! failed; a mutation note without that check is a comment, not evidence.

use super::audit::{AuditError, AuditLog, AuditOutcome};
use super::rbac::{Permission, Role};
use super::trusted_device::{DeviceProof, TrustDecision, TrustRegistry};
use super::unattended::{
    MAX_GRANT_ID_BYTES, MAX_UNATTENDED_WINDOW_SECONDS, UnattendedAccess, UnattendedDecision,
};
use super::{
    Assurance, AuthorizationContext, Decision, DenyReason, MAX_PRINCIPAL_ID_BYTES,
    MAX_TENANT_ID_BYTES, PolicyDocument, PolicyEngine, PolicyError, PrincipalId, TenantId,
};

const NOW: u64 = 1_000_000;
const DAY: u64 = 24 * 60 * 60;

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).expect("test tenant id")
}

fn principal(name: &str) -> PrincipalId {
    PrincipalId::new(name).expect("test principal id")
}

/// A context with every permission granted, so a test can isolate the check it
/// is actually about.
fn admin(name: &str, tenant_name: &str) -> AuthorizationContext {
    AuthorizationContext::from_entitlement(
        tenant(tenant_name),
        principal(name),
        Assurance::HardwareBacked,
        Permission::all().to_vec(),
    )
}

fn engine_for(tenant_name: &str) -> PolicyEngine {
    PolicyEngine::new(PolicyDocument::new(tenant(tenant_name), 1))
}

// --- tenant boundary -------------------------------------------------------

/// Mutation: delete the `context.tenant() != self.policy.tenant()` guard in
/// `PolicyEngine::evaluate` and replace the `Err` with nothing.
#[test]
fn tenant_a_context_cannot_use_another_tenants_policy() {
    let acme = engine_for("acme");
    let globex = admin("mallory", "globex");

    let decision = acme.evaluate(&globex, Role::Administrator, Permission::PolicyEdit);

    assert_eq!(decision, Err(PolicyError::NoPolicyForTenant));
}

/// Mutation: change the mismatch guard to `!=` -> `==`, inverting it.
#[test]
fn tenant_matching_policy_is_evaluated_normally() {
    let acme = engine_for("acme");
    let mallory = admin("mallory", "acme");

    let decision = acme
        .evaluate(&mallory, Role::Administrator, Permission::PolicyEdit)
        .expect("same tenant evaluates");

    assert_eq!(decision, Decision::Allow);
}

/// Mutation: remove the tenant filter from `events_for_tenant_handle`.
#[test]
fn tenant_an_audit_query_returns_only_the_named_tenants_events() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let globex = tenant("globex");
    log.record(
        &acme,
        &principal("ann"),
        "session.start",
        AuditOutcome::Allow,
        "",
        1,
    )
    .expect("record");
    log.record(
        &globex,
        &principal("bob"),
        "session.start",
        AuditOutcome::Allow,
        "",
        2,
    )
    .expect("record");
    log.record(
        &acme,
        &principal("ann"),
        "session.stop",
        AuditOutcome::Allow,
        "",
        3,
    )
    .expect("record");

    let for_acme = log.events_for_tenant_handle(&acme.audit_handle());
    assert_eq!(for_acme.len(), 2);
    assert!(
        for_acme
            .iter()
            .all(|e| e.is_for_tenant_handle(&acme.audit_handle()))
    );
    assert!(
        for_acme
            .iter()
            .all(|e| !e.is_for_tenant_handle(&globex.audit_handle())),
        "a cross-tenant event leaked into another tenant's query"
    );
}

/// Mutation: drop the domain-separation prefix from the tenant handle digest.
#[test]
fn tenant_handles_are_unique_and_stable() {
    let acme = tenant("acme");
    assert_eq!(acme.audit_handle(), tenant("acme").audit_handle());
    assert_ne!(acme.audit_handle(), tenant("globex").audit_handle());
}

/// Mutation: make `TenantId::Debug` print `self.0` instead of the handle.
#[test]
fn a_tenant_debug_never_prints_the_tenants_own_name() {
    let rendered = format!("{:?}", tenant("globex-industrial"));
    assert!(
        !rendered.contains("globex"),
        "tenant name leaked into Debug: {rendered}"
    );
    assert!(rendered.contains("audit_handle"));
}

// --- tenant id validation --------------------------------------------------

/// Mutation: delete the `value.trim().is_empty()` guard in `TenantId::new`.
#[test]
fn tenant_a_blank_tenant_is_refused() {
    for candidate in ["", " ", "\t\t", "\n"] {
        assert_eq!(TenantId::new(candidate), Err(PolicyError::EmptyTenant));
    }
}

/// Mutation: change `MAX_TENANT_ID_BYTES` from 64 to 1024.
#[test]
fn tenant_an_overlong_tenant_is_refused() {
    let long = "a".repeat(MAX_TENANT_ID_BYTES + 1);
    assert_eq!(
        TenantId::new(long),
        Err(PolicyError::TenantIdTooLong {
            length: MAX_TENANT_ID_BYTES + 1,
            maximum: MAX_TENANT_ID_BYTES,
        })
    );
    assert!(TenantId::new("a".repeat(MAX_TENANT_ID_BYTES)).is_ok());
}

/// Mutation: delete the `chars().any(char::is_control)` guard in
/// `TenantId::new`.
#[test]
fn tenant_a_control_character_in_a_tenant_is_refused() {
    // Enumerated rather than asserted from a list, so a new control character
    // cannot slip past a hard-coded test vector.
    for code in 0x00u8..0x20 {
        // `char::from`, not `{code}`: formatting a u8 as 0 produces the digit
        // "0", which is a perfectly valid tenant, and the loop would pass
        // without ever testing a control character.
        let candidate = format!("ac{}me", char::from(code));
        assert!(
            matches!(
                TenantId::new(&candidate),
                Err(PolicyError::TenantIdHasControlCharacter)
            ),
            "control char U+{code:04X} was accepted"
        );
    }
    // DEL and C1 are control characters too, and live above the ASCII block
    // the loop covers.
    assert!(matches!(
        TenantId::new("ac\u{7f}me"),
        Err(PolicyError::TenantIdHasControlCharacter)
    ));
    assert!(TenantId::new("acme").is_ok());
}

/// Mutation: remove the `!value.is_ascii()` guard in `TenantId::new`.
#[test]
fn tenant_a_non_ascii_tenant_is_refused() {
    // A right-to-left override can render "evil.com" while comparing as
    // something else entirely. Rejecting all non-ASCII is blunt, and blunter
    // than a formatting-aware check, but a tenant id is not a place to be
    // clever about unicode.
    assert_eq!(
        TenantId::new("acme\u{202e}moc.live"),
        Err(PolicyError::TenantIdNotAscii)
    );
}

/// Mutation: delete the `contains('@')` check in `TenantId::from_identity`.
#[test]
fn tenant_a_user_identity_is_not_a_tenant() {
    let identity = crate::session::PeerIdentity::new("ann@acme.example").expect("peer identity");
    assert_eq!(
        TenantId::from_identity(&identity),
        Err(PolicyError::NotATenant)
    );

    let org = crate::session::PeerIdentity::new("acme-industries").expect("peer identity");
    assert!(TenantId::from_identity(&org).is_ok());
}

// --- privilege escalation: the ceiling -------------------------------------

/// Mutation: delete the `!context.granted(permission)` guard in `evaluate`.
#[test]
fn escalation_a_permission_the_grant_does_not_carry_is_refused() {
    let acme = engine_for("acme");
    // Full role, full assurance, empty signed grant. Only the ceiling stands
    // between this context and Administrator.
    let empty_grant = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("mallory"),
        Assurance::HardwareBacked,
        Vec::new(),
    );

    let decision = acme
        .evaluate(
            &empty_grant,
            Role::Administrator,
            Permission::PrincipalManage,
        )
        .expect("tenant matches");

    assert_eq!(decision, Decision::Deny(DenyReason::NotGranted));
}

/// Mutation: replace the ceiling check with `if false`.
#[test]
fn escalation_the_ceiling_is_checked_before_policy() {
    let acme = PolicyEngine::new(
        PolicyDocument::new(tenant("acme"), 1).forbid(Permission::PrincipalManage),
    );
    let empty_grant = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("mallory"),
        Assurance::HardwareBacked,
        Vec::new(),
    );

    // Not granted *and* policy-forbidden. The reported reason must be the
    // ceiling, because that is the one no policy can raise -- and a caller
    // reading "policy forbids" would go edit the policy.
    let decision = acme
        .evaluate(
            &empty_grant,
            Role::Administrator,
            Permission::PrincipalManage,
        )
        .expect("tenant matches");

    assert_eq!(decision, Decision::Deny(DenyReason::NotGranted));
}

/// Mutation: give `Role::may_delegate` `self.permissions().contains(&permission)`
/// inverted, or return `true` for `PrincipalManage`.
#[test]
fn escalation_no_role_may_delegate_a_permission_it_lacks() {
    for role in Role::all() {
        for permission in Permission::all() {
            let delegable = role.may_delegate(permission);
            let held = role.permissions().contains(&permission);
            assert!(
                !delegable || held,
                "{role:?} may delegate {permission:?} without holding it"
            );
        }
    }
}

/// Mutation: give `Administrator::permissions` only `DeviceList`.
#[test]
fn escalation_a_role_holds_exactly_its_declared_permissions() {
    assert!(
        Role::Administrator
            .permissions()
            .contains(&Permission::PrincipalManage)
    );
    assert!(
        !Role::Operator
            .permissions()
            .contains(&Permission::PrincipalManage)
    );
    assert!(
        !Role::Auditor
            .permissions()
            .contains(&Permission::SessionStart)
    );
}

/// Mutation: return `true` unconditionally from `may_delegate`, or add
/// `Permission::PrincipalManage` to a role that does not hold it.
#[test]
fn escalation_delegation_never_exceeds_the_delegating_role() {
    // The rule is one-directional: holding a permission makes it delegable,
    // and nothing else does. Pinned in both directions, because the failure
    // that matters is an administrator minting administrators.
    assert!(Role::Administrator.may_delegate(Permission::DeviceList));
    assert!(Role::Administrator.may_delegate(Permission::PrincipalManage));
    assert!(!Role::Supervisor.may_delegate(Permission::PrincipalManage));
    assert!(!Role::Operator.may_delegate(Permission::AuditRead));
    assert!(!Role::Auditor.may_delegate(Permission::SessionAttach));
}

// --- policy narrowing ------------------------------------------------------

/// Mutation: add an `allow(permission)` method to `PolicyDocument`.
#[test]
fn policy_a_document_can_narrow_but_cannot_widen() {
    let document = PolicyDocument::new(tenant("acme"), 1)
        .forbid(Permission::UnattendedGrant)
        .require_assurance(Assurance::HardwareBacked);

    assert!(document.forbidden().contains(&Permission::UnattendedGrant));
    assert_eq!(
        document.required_assurance(),
        Some(Assurance::HardwareBacked)
    );

    // There is no `allowed` field to assert on, so the property is asserted by
    // what the type does not expose: the only mutators are `forbid`,
    // `require_assurance`, `require_trusted_device`, `forbid_unattended`. The
    // source-level test below pins that list.
}

/// Mutation: add `allow`, `permit`, `allow_all`, or `enable` to the policy
/// setters.
///
/// Second mutation: drop the `.replace("\r\n", "\n")` and check out on
/// Windows. The block delimiters stop matching, the scan reads nothing, and
/// every `!contains` assertion below still passes -- this is how it reached
/// CI in the first place. The length assertion at the end is what makes that
/// failure loud instead of silent.
#[test]
fn policy_the_document_type_has_no_widening_operation() {
    // Normalized because `include_str!` reports the file exactly as it sits on
    // disk, and this is checked out with CRLF on Windows. Matching raw `\n}\n`
    // made the scan silently skip the block there -- the test still ran, so it
    // reported nothing wrong, but it was no longer looking at the code. A
    // security check that quietly stops reading its own subject is worse than
    // one that fails.
    let source = include_str!("mod.rs").replace("\r\n", "\n");

    // Scoped to the policy block, because the rest of the module legitimately
    // contains `UnattendedAccess::issue` and `AuthorizationContext::granted`.
    let start = source
        .find("impl PolicyDocument {")
        .expect("PolicyDocument impl block");
    let end = source[start..].find("\n}\n").expect("end of the block");
    let block = &source[start..start + end];

    // Matched with the open paren so `fn allows_unattended` -- a legitimate
    // reader, not a writer -- is not mistaken for `fn allow`.
    for forbidden in ["fn allow(", "fn permit(", "fn allow_all(", "fn enable("] {
        assert!(
            !block.contains(forbidden),
            "policy document grew a widening operation: {forbidden}"
        );
    }

    // The scan above proves the absence of four known names. It does not prove
    // the block was actually read: a pattern that fails to match returns
    // nothing and every `!contains` check still passes. So assert the block is
    // non-trivial, which fails loudly if the delimiters ever stop matching.
    assert!(
        block.len() > 200,
        "the PolicyDocument block was only {} bytes -- the scan is not \
         reading the code it claims to check",
        block.len()
    );
}

/// Mutation: change `PolicyDocument::forbid` to skip the `contains` check, or
/// invert it.
#[test]
fn policy_forbidding_twice_does_not_duplicate() {
    let document = PolicyDocument::new(tenant("acme"), 1)
        .forbid(Permission::AuditRead)
        .forbid(Permission::AuditRead);
    assert_eq!(document.forbidden().len(), 1);
}

/// Mutation: make `Assurance::None` satisfy nothing, including `None`.
#[test]
fn policy_a_requirement_of_nothing_is_met_by_everything() {
    // Reachable in practice: `require_assurance(Assurance::None)` is a tenant
    // saying "do not require a factor". Treating it as unmet would make that
    // policy deny every request, which is a lockout, not a security control.
    for presented in [
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
        Assurance::HardwareBacked,
    ] {
        assert!(presented.satisfies(Assurance::None));
    }
    assert!(!Assurance::None.satisfies(Assurance::SingleFactor));
}

/// Mutation: remove the `!context.assurance().satisfies(required)` guard.
#[test]
fn policy_a_demanding_policy_refuses_a_weak_request() {
    let strict = PolicyEngine::new(
        PolicyDocument::new(tenant("acme"), 1).require_assurance(Assurance::MultiFactor),
    );
    let weak = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::SingleFactor,
        Permission::all().to_vec(),
    );

    let decision = strict
        .evaluate(&weak, Role::Operator, Permission::DeviceList)
        .expect("tenant matches");

    assert_eq!(decision, Decision::Deny(DenyReason::AssuranceTooLow));
}

// --- role floors -----------------------------------------------------------

/// Mutation: set every role's `required_assurance` to `Assurance::None`.
#[test]
fn role_an_administrator_requires_a_hardware_key() {
    for assurance in [
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
    ] {
        let context = AuthorizationContext::from_entitlement(
            tenant("acme"),
            principal("mallory"),
            assurance,
            Permission::all().to_vec(),
        );
        let decision = engine_for("acme")
            .evaluate(&context, Role::Administrator, Permission::PolicyEdit)
            .expect("tenant matches");
        assert_eq!(
            decision,
            Decision::Deny(DenyReason::AssuranceTooLow),
            "administrator reached on {assurance:?}"
        );
    }
}

/// Mutation: set `Operator::required_assurance` to `Assurance::HardwareBacked`.
#[test]
fn role_an_operator_works_on_a_single_factor() {
    let context = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::SingleFactor,
        Permission::all().to_vec(),
    );

    let decision = engine_for("acme")
        .evaluate(&context, Role::Operator, Permission::SessionStart)
        .expect("tenant matches");

    assert_eq!(decision, Decision::Allow);
}

/// Mutation: remove the `role.permissions().contains(&permission)` guard.
#[test]
fn role_a_permission_outside_the_role_is_refused() {
    let context = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("audrey"),
        Assurance::HardwareBacked,
        Permission::all().to_vec(),
    );

    let decision = engine_for("acme")
        .evaluate(&context, Role::Auditor, Permission::SessionStart)
        .expect("tenant matches");

    assert_eq!(decision, Decision::Deny(DenyReason::RoleLacks));
}

/// Mutation: change `Assurance::satisfies` so `SingleFactor` satisfies
/// `MultiFactor`.
#[test]
fn role_strength_compares_as_a_ladder() {
    // `None` meeting `None` is the one pair a "no requirement" policy depends
    // on; it is covered by `policy_a_requirement_of_nothing_is_met_by_everything`.
    assert!(!Assurance::None.satisfies(Assurance::SingleFactor));
    assert!(Assurance::SingleFactor.satisfies(Assurance::SingleFactor));
    assert!(!Assurance::SingleFactor.satisfies(Assurance::MultiFactor));
    assert!(Assurance::MultiFactor.satisfies(Assurance::SingleFactor));
    assert!(!Assurance::MultiFactor.satisfies(Assurance::HardwareBacked));
    assert!(Assurance::HardwareBacked.satisfies(Assurance::HardwareBacked));
}

// --- rbac exhaustiveness ---------------------------------------------------

/// Mutation: remove an arm from `Permission::parse` or `Permission::name`.
#[test]
fn rbac_every_permission_round_trips() {
    for permission in Permission::all() {
        assert_eq!(Permission::parse(permission.name()), Some(permission));
    }
}

/// Mutation: make `Permission::parse` return `Some(DeviceList)` as a default.
#[test]
fn rbac_an_unknown_permission_is_refused_rather_than_defaulted() {
    for candidate in ["", "device-list", "DEVICE_LIST", "policy_edit ", "root"] {
        assert_eq!(
            Permission::parse(candidate),
            None,
            "{candidate:?} parsed instead of being refused"
        );
    }
}

/// Mutation: remove an arm from `Role::parse`.
#[test]
fn rbac_every_role_round_trips() {
    for role in Role::all() {
        assert_eq!(Role::parse(role.name()), Some(role));
    }
    assert_eq!(Role::parse("superuser"), None);
}

// --- device trust ----------------------------------------------------------

fn registry_with_device(device: &str) -> TrustRegistry {
    let mut registry = TrustRegistry::new();
    registry
        .enroll(device, NOW, NOW + 30 * DAY, NOW, true)
        .expect("enrol");
    registry
}

/// Mutation: make `TrustRegistry::assess` return `Trusted` for an unknown id.
#[test]
fn device_an_unenrolled_device_is_not_trusted() {
    let registry = registry_with_device("laptop-1");
    assert_eq!(registry.assess("laptop-2", NOW), TrustDecision::NotEnrolled);
}

/// Mutation: delete the `device.is_revoked()` check in `assess`.
#[test]
fn device_a_revoked_device_is_not_trusted() {
    let mut registry = registry_with_device("laptop-1");
    assert_eq!(registry.assess("laptop-1", NOW), TrustDecision::Trusted);
    assert!(registry.revoke("laptop-1"));
    assert_eq!(registry.assess("laptop-1", NOW), TrustDecision::Revoked);
    assert!(!registry.revoke("laptop-2"));
}

/// Mutation: change `now < self.trust_expires_at` to `now <=`.
#[test]
fn device_an_expired_device_is_not_trusted() {
    let registry = registry_with_device("laptop-1");
    assert_eq!(
        registry.assess("laptop-1", NOW + 30 * DAY),
        TrustDecision::Expired
    );
    assert_eq!(
        registry.assess("laptop-1", NOW + 30 * DAY - 1),
        TrustDecision::Trusted
    );
}

/// Mutation: delete the `retain` call in `enroll`.
#[test]
fn device_re_enrolment_replaces_rather_than_appends() {
    let mut registry = TrustRegistry::new();
    registry
        .enroll("laptop-1", NOW, NOW + DAY, NOW, true)
        .expect("first");
    registry
        .enroll("laptop-1", NOW, NOW + 60 * DAY, NOW, true)
        .expect("second");

    assert_eq!(registry.len(), 1);
    assert_eq!(
        registry.assess("laptop-1", NOW + 30 * DAY),
        TrustDecision::Trusted
    );
}

/// Mutation: delete the `trust_expires_at <= enrolled_at` guard in `enroll`.
#[test]
fn device_trust_must_expire_after_it_is_granted() {
    let mut registry = TrustRegistry::new();
    assert_eq!(
        registry.enroll("laptop-1", NOW, NOW, NOW, true).err(),
        Some(PolicyError::TrustExpiryNotAfterEnrolment)
    );
    assert_eq!(
        registry.enroll("laptop-1", NOW + DAY, NOW, NOW, true).err(),
        Some(PolicyError::TrustExpiryNotAfterEnrolment)
    );
}

/// Mutation: remove the device-id bound check in `enroll`.
#[test]
fn device_a_hostile_device_id_is_refused() {
    let mut registry = TrustRegistry::new();
    assert_eq!(
        registry.enroll("", NOW, NOW + DAY, NOW, true).err(),
        Some(PolicyError::EmptyDeviceId)
    );
    assert_eq!(
        registry.enroll("lap\ntop", NOW, NOW + DAY, NOW, true).err(),
        Some(PolicyError::DeviceIdNotAcceptable)
    );
    assert_eq!(
        registry
            .enroll(&"x".repeat(500), NOW, NOW + DAY, NOW, true)
            .err(),
        Some(PolicyError::DeviceIdTooLong {
            length: 500,
            maximum: 128
        })
    );
}

/// Mutation: delete the `require_trusted_device` guard in `evaluate`.
#[test]
fn device_a_policy_requiring_a_trusted_device_refuses_an_untrusted_one() {
    let strict = PolicyEngine::new(PolicyDocument::new(tenant("acme"), 1).require_trusted_device());
    let context = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::HardwareBacked,
        Permission::all().to_vec(),
    );

    let decision = strict
        .evaluate(&context, Role::Administrator, Permission::DeviceList)
        .expect("tenant matches");
    assert_eq!(decision, Decision::Deny(DenyReason::UntrustedDevice));

    let registry = registry_with_device("laptop-1");
    let trust = registry.get("laptop-1").expect("device present").clone();
    let trusted = context.with_device_trust(trust);
    let decision = strict
        .evaluate(&trusted, Role::Administrator, Permission::DeviceList)
        .expect("tenant matches");
    assert_eq!(decision, Decision::Allow);
}

// The tests below read `DeviceTrust`'s predicates directly rather than through
// `TrustRegistry::assess`. `assess` checks `is_revoked()` before it calls
// `is_trusted_at`, so the `!self.revoked` conjunct *inside* `is_trusted_at` is
// never the deciding clause on that path -- deleting it leaves every `assess`
// test green. The predicate has a second caller, `PolicyEngine::evaluate`, with
// no earlier revoked check of its own, so the conjunct is load-bearing there
// and only there.

/// Mutation: delete `!self.revoked &&` from `DeviceTrust::is_trusted_at`.
#[test]
fn device_the_authorization_predicate_itself_refuses_a_revoked_device() {
    let mut registry = registry_with_device("laptop-1");
    let trust = registry.get("laptop-1").expect("device present").clone();
    assert!(trust.is_trusted_at(NOW));
    assert!(trust.is_trusted_at_now());

    registry.revoke("laptop-1");
    let revoked = registry.get("laptop-1").expect("device present").clone();
    assert!(revoked.is_revoked());
    assert!(!revoked.is_trusted_at(NOW));
    assert!(!revoked.is_trusted_at_now());

    let strict = PolicyDocument::new(tenant("acme"), 1).require_trusted_device();
    let context = admin("ann", "acme").with_device_trust(revoked);
    assert_eq!(
        PolicyEngine::new(strict)
            .evaluate(&context, Role::Administrator, Permission::DeviceList)
            .expect("tenant matches"),
        Decision::Deny(DenyReason::UntrustedDevice)
    );
}

/// Mutation: change `now < self.trust_expires_at` to `now <=`.
#[test]
fn device_an_assessment_made_at_its_expiry_instant_is_already_expired() {
    let mut registry = TrustRegistry::new();
    registry
        .enroll("laptop-1", NOW, NOW + 30 * DAY, NOW + 30 * DAY, true)
        .expect("enrol");
    let trust = registry.get("laptop-1").expect("device present").clone();
    assert_eq!(trust.assessed_at(), trust.trust_expires_at());
    assert!(!trust.is_trusted_at_now());
    // The same record, one argument earlier. If these two ever agree the
    // predicate is reading a clock instead of the argument it was handed.
    assert!(trust.is_trusted_at(trust.trust_expires_at() - 1));

    let strict = PolicyDocument::new(tenant("acme"), 1).require_trusted_device();
    let context = admin("ann", "acme").with_device_trust(trust);
    assert_eq!(
        PolicyEngine::new(strict)
            .evaluate(&context, Role::Administrator, Permission::DeviceList)
            .expect("tenant matches"),
        Decision::Deny(DenyReason::UntrustedDevice)
    );
}

/// Mutation: replace `self.assessed_at` in `is_trusted_at_now` with `u64::MAX`.
#[test]
fn device_an_unexpired_assessment_is_trusted() {
    let registry = registry_with_device("laptop-1");
    let trust = registry.get("laptop-1").expect("device present").clone();
    assert!(trust.is_trusted_at_now());
    assert!(trust.is_trusted_at(trust.trust_expires_at() - 1));
    assert!(!trust.is_trusted_at(trust.trust_expires_at()));
}

/// Mutation: swap the `is_revoked` and `is_trusted_at` checks in `assess`.
#[test]
fn device_revocation_is_reported_even_when_the_trust_has_also_expired() {
    let mut registry = TrustRegistry::new();
    registry
        .enroll("laptop-1", NOW, NOW + DAY, NOW, true)
        .expect("enrol");
    assert!(registry.revoke("laptop-1"));
    assert_eq!(
        registry.assess("laptop-1", NOW + 30 * DAY),
        TrustDecision::Revoked,
        "a retired device is `Revoked`, not `Expired`: the two tell an \
         administrator the device was withdrawn rather than merely aged out"
    );
}

/// Mutation: change `matches!(self, Self::Trusted)` in `TrustDecision::is_trusted`
/// to `!matches!(self, Self::Trusted)`.
#[test]
fn device_only_the_trusted_decision_counts_as_trusted() {
    assert!(TrustDecision::Trusted.is_trusted());
    for decision in [
        TrustDecision::NotEnrolled,
        TrustDecision::Revoked,
        TrustDecision::Expired,
    ] {
        assert!(!decision.is_trusted(), "{decision:?} is not trusted");
    }
}

/// Mutation: make `DeviceProof::new` accept an unbounded attestation.
#[test]
fn device_proof_bounds_its_attestation_reference() {
    assert_eq!(
        DeviceProof::new("laptop-1", "", NOW).err(),
        Some(PolicyError::EmptyAttestation)
    );
    assert!(DeviceProof::new("laptop-1", &"a".repeat(257), NOW).is_err());
    assert!(DeviceProof::new("laptop-1", &"a".repeat(256), NOW).is_ok());
}

// --- unattended access -----------------------------------------------------

fn grant(tenant_name: &str, issued_at: u64, until: u64) -> UnattendedAccess {
    UnattendedAccess::issue(
        "grant-1",
        tenant_name,
        "carol",
        "laptop-1",
        vec![Permission::SessionAttach],
        issued_at,
        until,
    )
    .expect("test grant")
}

/// Mutation: delete the `HardwareBacked` check in `evaluate_unattended`.
#[test]
fn unattended_a_password_never_reaches_a_standing_grant() {
    for assurance in [
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
    ] {
        let context = AuthorizationContext::from_entitlement(
            tenant("acme"),
            principal("carol"),
            assurance,
            Permission::all().to_vec(),
        );
        let decision = engine_for("acme")
            .evaluate_unattended(&context, &grant("acme", NOW, NOW + DAY), NOW)
            .expect("tenant matches");
        assert_eq!(
            decision,
            UnattendedDecision::InsufficientAssurance {
                required: Assurance::HardwareBacked,
                presented: assurance,
            },
            "unattended granted on {assurance:?}"
        );
    }
}

/// Mutation: delete the `!self.policy.allows_unattended` guard.
#[test]
fn unattended_a_tenant_can_forbid_it_entirely() {
    let strict = PolicyEngine::new(PolicyDocument::new(tenant("acme"), 1).forbid_unattended());
    let context = admin("carol", "acme");

    let decision = strict
        .evaluate_unattended(&context, &grant("acme", NOW, NOW + DAY), NOW)
        .expect("tenant matches");

    assert_eq!(
        decision,
        UnattendedDecision::Denied {
            reason: DenyReason::UnattendedForbidden,
        }
    );
}

/// Mutation: change `now < self.valid_until_epoch_seconds` to `now <=`.
#[test]
fn unattended_a_grant_expires_at_its_expiry_instant() {
    let context = admin("carol", "acme");
    let engine = engine_for("acme");
    let access = grant("acme", NOW, NOW + DAY);

    assert_eq!(
        engine
            .evaluate_unattended(&context, &access, NOW + DAY)
            .expect("tenant matches"),
        UnattendedDecision::Expired {
            valid_until_epoch_seconds: NOW + DAY,
        }
    );
    assert!(
        engine
            .evaluate_unattended(&context, &access, NOW + DAY - 1)
            .expect("tenant matches")
            .is_allowed()
    );
}

/// Mutation: delete the `revoke` call inside `is_valid`.
#[test]
fn unattended_a_revoked_grant_stops_working_immediately() {
    let context = admin("carol", "acme");
    let engine = engine_for("acme");
    let mut access = grant("acme", NOW, NOW + DAY);
    assert!(
        engine
            .evaluate_unattended(&context, &access, NOW)
            .expect("tenant matches")
            .is_allowed()
    );

    access.revoke();
    assert_eq!(
        engine
            .evaluate_unattended(&context, &access, NOW)
            .expect("tenant matches"),
        UnattendedDecision::Expired {
            valid_until_epoch_seconds: NOW + DAY,
        }
    );
}

/// Mutation: delete the `!access.belongs_to(...)` guard.
#[test]
fn unattended_a_grant_from_another_tenant_is_refused() {
    let acme = engine_for("acme");
    let context = admin("carol", "acme");
    // A grant issued by another tenant, presented to this tenant's engine.
    let foreign = grant("globex", NOW, NOW + DAY);

    let decision = acme
        .evaluate_unattended(&context, &foreign, NOW)
        .expect("context tenant matches policy");

    assert_eq!(decision, UnattendedDecision::WrongTenant);
}

/// Mutation: delete the `filter(|permission| context.granted(...))` in
/// `evaluate_unattended`.
#[test]
fn unattended_a_grant_cannot_exceed_the_signed_ceiling() {
    let acme = engine_for("acme");
    // Ceiling carries only the device list. The grant claims session attach.
    let limited = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("carol"),
        Assurance::HardwareBacked,
        vec![Permission::DeviceList],
    );
    let access = grant("acme", NOW, NOW + DAY);

    let decision = acme
        .evaluate_unattended(&limited, &access, NOW)
        .expect("tenant matches");

    assert_eq!(
        decision,
        UnattendedDecision::Denied {
            reason: DenyReason::NotGranted,
        }
    );
}

/// Mutation: remove the `window > MAX_UNATTENDED_WINDOW_SECONDS` guard.
#[test]
fn unattended_a_standing_grant_cannot_be_issued_for_a_year() {
    assert_eq!(
        UnattendedAccess::issue(
            "grant-1",
            "acme",
            "carol",
            "laptop-1",
            vec![Permission::SessionAttach],
            NOW,
            NOW + 365 * DAY,
        )
        .err(),
        Some(PolicyError::UnattendedWindowTooLong {
            window_seconds: 365 * DAY,
            maximum: MAX_UNATTENDED_WINDOW_SECONDS,
        })
    );
    assert!(
        UnattendedAccess::issue(
            "grant-1",
            "acme",
            "carol",
            "laptop-1",
            vec![Permission::SessionAttach],
            NOW,
            NOW + MAX_UNATTENDED_WINDOW_SECONDS,
        )
        .is_ok()
    );
}

/// Mutation: delete the `permissions.is_empty()` guard in `issue`.
#[test]
fn unattended_a_grant_with_no_permissions_is_refused() {
    assert_eq!(
        UnattendedAccess::issue("g", "acme", "carol", "laptop-1", Vec::new(), NOW, NOW + DAY).err(),
        Some(PolicyError::NoPermissionsGranted)
    );
}

/// Mutation: delete the `window == 0` guard in `issue`.
#[test]
fn unattended_a_grant_that_expired_at_issue_is_refused() {
    assert_eq!(
        UnattendedAccess::issue(
            "g",
            "acme",
            "carol",
            "laptop-1",
            vec![Permission::DeviceList],
            NOW,
            NOW
        )
        .err(),
        Some(PolicyError::UnattendedWindowNotInFuture)
    );
}

/// Mutation: delete the `grant_id.is_empty()` and length guards in `issue`.
#[test]
fn unattended_a_grant_id_is_bounded() {
    let long = "g".repeat(MAX_GRANT_ID_BYTES + 1);
    assert_eq!(
        UnattendedAccess::issue(
            &long,
            "acme",
            "carol",
            "l",
            vec![Permission::DeviceList],
            NOW,
            NOW + DAY
        )
        .err(),
        Some(PolicyError::GrantIdTooLong {
            length: MAX_GRANT_ID_BYTES + 1,
            maximum: MAX_GRANT_ID_BYTES,
        })
    );
}

// --- audit -----------------------------------------------------------------

/// Mutation: delete the digest chaining in `record`.
#[test]
fn audit_events_are_hash_chained() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");

    log.record(&acme, &ann, "session.start", AuditOutcome::Allow, "", 1)
        .expect("first");
    log.record(&acme, &ann, "session.stop", AuditOutcome::Allow, "", 2)
        .expect("second");

    let events = log.events();
    assert_eq!(events[0].previous_digest(), &[0u8; 32]);
    assert_eq!(events[1].previous_digest(), events[0].digest());
    assert_ne!(events[0].digest(), events[1].digest());
    assert_eq!(log.verify_chain(), Ok(()));
}

/// Mutation: remove the `previous_digest` update in `verify_chain`.
#[test]
fn audit_a_recomputed_chain_verifies() {
    let mut log = AuditLog::new();
    log.record(
        &tenant("acme"),
        &principal("ann"),
        "a",
        AuditOutcome::Allow,
        "",
        1,
    )
    .expect("record");
    log.record(
        &tenant("acme"),
        &principal("ann"),
        "b",
        AuditOutcome::Allow,
        "",
        2,
    )
    .expect("record");
    assert_eq!(log.verify_chain(), Ok(()));
}

/// Mutation: remove the `ContentAltered` comparison in `verify_chain`.
#[test]
fn audit_altering_an_event_is_detected() {
    // Reconstructing the same chain and tampering with one event's payload is
    // what an attacker with write access to the Vec would do. The point of the
    // test is that the *verifier* notices, not that the attacker cannot try.
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    log.record(
        &acme,
        &ann,
        "policy.edit",
        AuditOutcome::Deny,
        "forbidden",
        1,
    )
    .expect("record");
    log.record(
        &acme,
        &ann,
        "policy.edit",
        AuditOutcome::Allow,
        "forbidden",
        2,
    )
    .expect("record");

    let tampered = log.clone();
    let mut events = tampered.events().to_vec();
    events[1].tamper_outcome(AuditOutcome::Deny);
    let forged = AuditLog::from_events(events);

    assert_eq!(
        forged.verify_chain(),
        Err(AuditError::ContentAltered { at_sequence: 2 })
    );
}

/// Mutation: remove the `SequenceGap` check in `verify_chain`.
#[test]
fn audit_removing_an_event_is_caught_by_the_gap_check() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    for second in 1..=3 {
        log.record(&acme, &ann, "a", AuditOutcome::Allow, "", second)
            .expect("record");
    }

    // Splice event 2 out. The sequence numbers no longer run 1,2,3, and that
    // is the first thing a verifier sees.
    let events = log.events();
    let forged = AuditLog::from_events(vec![events[0].clone(), events[2].clone()]);

    assert_eq!(
        forged.verify_chain(),
        Err(AuditError::SequenceGap {
            expected: 2,
            found: 3,
        })
    );
}

/// Mutation: remove the `event.previous_digest != previous_digest` check from
/// `verify_chain`.
#[test]
fn audit_a_rewired_link_is_caught_by_the_digest_check() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    log.record(&acme, &ann, "a", AuditOutcome::Allow, "", 1)
        .expect("first");
    log.record(&acme, &ann, "b", AuditOutcome::Allow, "", 2)
        .expect("second");
    log.record(&acme, &ann, "c", AuditOutcome::Allow, "", 3)
        .expect("third");

    // Sequence numbers stay contiguous, so the gap check has nothing to say.
    // Only the digest link catches this one, which is what makes both checks
    // load-bearing rather than one being redundant.
    let events = log.events();
    let mut rewired = events.to_vec();
    rewired[1].tamper_previous_digest([0u8; 32]);
    rewired[1].reseal();
    let forged = AuditLog::from_events(rewired);

    assert_eq!(
        forged.verify_chain(),
        Err(AuditError::ChainBroken { at_sequence: 2 })
    );
}

/// Mutation: give `AuditEvent::reseal` a signing key, or return a signed
/// digest. There is none, and this test fails if that changes.
#[test]
fn audit_a_full_rewrite_verifies_and_that_is_the_documented_limit() {
    // This test exists to *fail loudly if the module ever claims more than it
    // delivers*. An attacker who can edit every field and reseal every digest
    // produces a chain that verifies -- there is no signing key here. The
    // module docs say so. If this assertion ever starts failing because the
    // chain got stronger, the docs need updating, not this test.
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    log.record(
        &acme,
        &ann,
        "policy.edit",
        AuditOutcome::Deny,
        "forbidden",
        1,
    )
    .expect("record");
    log.record(
        &acme,
        &ann,
        "policy.edit",
        AuditOutcome::Allow,
        "forbidden",
        2,
    )
    .expect("record");

    let mut rewritten = log.events().to_vec();
    rewritten[1].tamper_outcome(AuditOutcome::Deny);
    rewritten[1].reseal();
    let forged = AuditLog::from_events(rewritten);

    assert_eq!(
        forged.verify_chain(),
        Ok(()),
        "the chain got stronger than the module docs claim; update them"
    );
}

/// Mutation: delete the `at_epoch_seconds < last.at_epoch_seconds` guard.
#[test]
fn audit_a_clock_that_goes_backwards_is_refused() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    log.record(&acme, &ann, "a", AuditOutcome::Allow, "", 100)
        .expect("record");
    assert_eq!(
        log.record(&acme, &ann, "b", AuditOutcome::Allow, "", 99),
        Err(AuditError::TimeWentBackwards {
            previous: 100,
            offered: 99
        })
    );
}

/// Mutation: raise `MAX_ACTION_BYTES` / `MAX_DETAIL_BYTES`.
#[test]
fn audit_attacker_controlled_text_is_bounded() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");

    assert_eq!(
        log.record(&acme, &ann, "", AuditOutcome::Allow, "", 1),
        Err(AuditError::EmptyAction)
    );
    assert!(
        log.record(&acme, &ann, &"a".repeat(65), AuditOutcome::Allow, "", 1)
            .is_err()
    );
    assert!(
        log.record(&acme, &ann, "ok", AuditOutcome::Allow, &"a".repeat(257), 1)
            .is_err()
    );
}

/// Mutation: remove the `self.truncated = true` at capacity.
#[test]
fn audit_a_full_log_says_it_is_incomplete() {
    let mut log = AuditLog::new();
    let acme = tenant("acme");
    let ann = principal("ann");
    for second in 0..=super::audit::MAX_EVENTS as u64 {
        log.record(&acme, &ann, "a", AuditOutcome::Allow, "", second)
            .expect("record");
    }

    assert!(log.is_truncated());
    assert_eq!(log.len(), super::audit::MAX_EVENTS);
    assert_eq!(log.verify_chain(), Err(AuditError::Truncated));
}

/// Mutation: delete the `audit_handle` usage in `record`.
#[test]
fn audit_a_record_never_contains_a_tenant_or_principal_name() {
    let mut log = AuditLog::new();
    let acme = tenant("globex-industrial");
    let ann = principal("ann@globex.example");
    log.record(
        &acme,
        &ann,
        "session.start",
        AuditOutcome::Allow,
        "detail",
        1,
    )
    .expect("record");

    let event = log.last().expect("one event");
    let rendered = format!("{event} {event:?}");
    assert!(
        !rendered.contains("globex-industrial") && !rendered.contains("ann@globex.example"),
        "audit record carried an identifier: {rendered}"
    );
}

/// Mutation: remove `PrincipalId::audit_handle`, or make it return the id.
#[test]
fn audit_principal_handles_are_unique_and_stable() {
    assert_eq!(
        principal("ann").audit_handle(),
        principal("ann").audit_handle()
    );
    assert_ne!(
        principal("ann").audit_handle(),
        principal("bob").audit_handle()
    );
}

/// Mutation: make `record` store `principal.as_str()` in the chain digest.
#[test]
fn audit_a_different_principal_produces_a_different_digest() {
    let mut one = AuditLog::new();
    let mut two = AuditLog::new();
    one.record(
        &tenant("acme"),
        &principal("ann"),
        "a",
        AuditOutcome::Allow,
        "",
        1,
    )
    .expect("record");
    two.record(
        &tenant("acme"),
        &principal("bob"),
        "a",
        AuditOutcome::Allow,
        "",
        1,
    )
    .expect("record");

    assert_ne!(
        one.last().expect("event").digest(),
        two.last().expect("event").digest()
    );
}

// --- mfa / sso boundary ----------------------------------------------------

/// Mutation: give `Assurance` no ordering, or make `satisfies` always true.
#[test]
fn mfa_strength_is_a_total_order() {
    let ladder = [
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
        Assurance::HardwareBacked,
    ];
    for (index, weaker) in ladder.iter().enumerate() {
        for stronger in &ladder[index + 1..] {
            assert!(
                stronger.satisfies(*weaker),
                "{stronger:?} should satisfy {weaker:?}"
            );
            assert!(
                !weaker.satisfies(*stronger),
                "{weaker:?} should not satisfy {stronger:?}"
            );
        }
    }
}

/// Mutation: remove `Assurance::name` or return a `String` from it.
#[test]
fn mfa_strength_names_are_static() {
    for assurance in [
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
        Assurance::HardwareBacked,
    ] {
        let name: &'static str = assurance.name();
        assert_ne!(name, "");
    }
}

// --- managed deployment ----------------------------------------------------

/// Mutation: remove the `TenantId::new` bound checks, or the `new` constructor.
#[test]
fn managed_a_principal_id_is_bounded_and_control_free() {
    assert_eq!(
        PrincipalId::new("a".repeat(MAX_PRINCIPAL_ID_BYTES + 1)),
        Err(PolicyError::PrincipalIdTooLong {
            length: MAX_PRINCIPAL_ID_BYTES + 1,
            maximum: MAX_PRINCIPAL_ID_BYTES,
        })
    );
    assert_eq!(
        PrincipalId::new("an\nn"),
        Err(PolicyError::PrincipalIdHasControlCharacter)
    );
    assert!(PrincipalId::new("ann").is_ok());
}

/// Mutation: make `AuthorizationContext`'s fields `pub`, or add a `Default`
/// impl.
#[test]
fn managed_an_empty_grant_allows_nothing() {
    let empty = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::HardwareBacked,
        Vec::new(),
    );
    for permission in Permission::all() {
        assert!(!empty.granted(permission));
    }
}

/// Mutation: replace the `Vec<Permission>` ceiling with a `Role`, so the
/// ceiling is derived from the caller's own claim rather than the signed grant.
#[test]
fn managed_the_ceiling_comes_from_the_grant_not_the_claimed_role() {
    // The same principal, the same claimed role, the same assurance -- only the
    // signed grant differs. Nothing about the request changed, so the decision
    // must not.
    let acme = engine_for("acme");

    let with_grant = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::HardwareBacked,
        vec![Permission::DeviceList],
    );
    let without_grant = AuthorizationContext::from_entitlement(
        tenant("acme"),
        principal("ann"),
        Assurance::HardwareBacked,
        Vec::new(),
    );

    assert_eq!(
        acme.evaluate(&with_grant, Role::Administrator, Permission::DeviceList)
            .expect("tenant matches"),
        Decision::Allow
    );
    assert_eq!(
        acme.evaluate(&without_grant, Role::Administrator, Permission::DeviceList)
            .expect("tenant matches"),
        Decision::Deny(DenyReason::NotGranted)
    );
}
