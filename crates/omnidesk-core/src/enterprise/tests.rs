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
    // The cross-kind assertions below were added when the mutation harness
    // applied this docstring and it survived: the first two hold with or
    // without the prefix. A docstring naming an edit the test cannot notice is
    // the same defect as no docstring -- it reads like evidence.
    let acme = tenant("acme");
    assert_eq!(acme.audit_handle(), tenant("acme").audit_handle());
    assert_ne!(acme.audit_handle(), tenant("globex").audit_handle());
    // Domain separation is what the pair above cannot see. Two distinct
    // tenants hash to two distinct digests whether or not a prefix is mixed
    // in, so dropping the prefix leaves both assertions passing. What the
    // prefix buys is that a tenant and a thing of another kind whose id is the
    // same string do not land on the same handle -- otherwise an event about
    // one is indistinguishable from an event about the other.
    assert_ne!(acme.audit_handle(), principal("acme").audit_handle());
    assert_ne!(
        acme.audit_handle(),
        DeviceProof::new("acme", "attestation", NOW)
            .expect("proof")
            .audit_handle()
    );
    // Pinned by value, because the assertions above cannot fail for this
    // mutation. Every one of them is an inequality between two SHA-256
    // digests, and SHA-256 of the same bytes without a prefix is still a
    // digest no other input produces -- so dropping the prefix leaves them all
    // green while the thing the prefix is *for* is gone. What makes the prefix
    // observable is that the handle is a stable published value: an auditor
    // correlating against an external store is matching on this exact string,
    // and a handle that changes when the derivation is refactored breaks every
    // correlation already recorded against it.
    //
    // That is a stronger claim than "unique", and it is the one the privacy
    // guarantee actually rests on, so it is the one asserted.
    assert_eq!(acme.audit_handle(), "12ddd5913bae1479");
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

/// Mutation: change `MAX_TENANT_ID_BYTES` from 64 to 8.
#[test]
fn tenant_an_overlong_tenant_is_refused() {
    // The bound is spelled out rather than derived. A test that builds its
    // input from `MAX_TENANT_ID_BYTES + 1` moves with the constant, so raising
    // the constant leaves it passing -- which is how this docstring's mutation
    // survived the harness the first time it was applied. A bound nobody can
    // move is a bound nobody can test.
    assert_eq!(MAX_TENANT_ID_BYTES, 64);
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

/// Mutation: set `managed: true` in `enroll` unconditionally, or make
/// `is_managed` return `!self.revoked`.
#[test]
fn device_the_managed_flag_is_recorded_verbatim_and_is_not_a_trust_input() {
    let mut registry = TrustRegistry::new();
    registry
        .enroll("managed-1", NOW, NOW + DAY, NOW, true)
        .expect("enrol managed");
    registry
        .enroll("self-1", NOW, NOW + DAY, NOW, false)
        .expect("enrol self");

    let managed = registry.get("managed-1").expect("present").clone();
    let self_enrolled = registry.get("self-1").expect("present").clone();
    assert!(managed.is_managed());
    assert!(!self_enrolled.is_managed());

    // Neither is trusted differently for it. `ENTERPRISE_CONTROLS.md` records
    // that managed deployment has a direction but no deployment client, so the
    // flag is a record and not an authorization input. That is a stated
    // limitation, not an accident -- and it is pinned here so that turning it
    // into an input is a deliberate change rather than a side effect of someone
    // adding a conjunct.
    assert!(managed.is_trusted_at(NOW));
    assert!(self_enrolled.is_trusted_at(NOW));

    // And revocation still governs both.
    assert!(registry.revoke("managed-1"));
    assert!(
        !registry
            .get("managed-1")
            .expect("present")
            .is_trusted_at(NOW)
    );
}

/// Mutation: make `may_delegate` refuse every administrative permission, on
/// the reading that "administrative" means "not delegable".
#[test]
fn escalation_the_administrative_classification_is_not_the_ceiling() {
    // `is_administrative` used to be documented as the mechanism that refuses
    // self-escalation. It was never wired to anything, and the rule it claimed
    // to implement is `may_delegate`. Wiring it in would look like closing the
    // escalation hole and would instead stop the one role that may legitimately
    // delegate: an administrator refusing to mint administrators breaks the
    // tenant, while a non-administrator holding an administrative permission
    // is already impossible because no role grants one.
    for permission in Permission::all() {
        let administrative = permission.is_administrative();
        let administrable = Role::Administrator.may_delegate(permission);
        assert!(
            administrable,
            "Administrator must be able to delegate {permission:?}"
        );
        assert_eq!(
            administrative,
            Role::Administrator.permissions().contains(&permission)
                && !matches!(
                    permission,
                    Permission::DeviceManage
                        | Permission::AuditRead
                        | Permission::DeviceList
                        | Permission::SessionStart
                        | Permission::SessionAttach
                        | Permission::SelfService
                ),
            "the administrative set drifted for {permission:?}"
        );
    }

    // The classification is exactly the three permissions that change what
    // other principals can do. Pinned by value, not by reimplementing the
    // match: a fourth added to the arm without this list would otherwise pass.
    let administrative: Vec<Permission> = Permission::all()
        .into_iter()
        .filter(|permission| permission.is_administrative())
        .collect();
    assert_eq!(
        administrative,
        vec![
            Permission::UnattendedGrant,
            Permission::PolicyEdit,
            Permission::PrincipalManage
        ]
    );

    // And the ceiling still holds for the permission that matters most: no role
    // that does not hold `PrincipalManage` may delegate it.
    for role in Role::all() {
        assert_eq!(
            role.may_delegate(Permission::PrincipalManage),
            role.permissions().contains(&Permission::PrincipalManage),
            "{role:?} delegation of PrincipalManage does not match what it holds"
        );
    }
}

/// Mutation: delete every entry from `Administrator::permissions` except
/// `PrincipalManage`.
#[test]
fn escalation_a_role_holds_exactly_its_declared_permissions() {
    // Pinned by value. Three spot-checks are what the harness found this test
    // lacking: deleting the seven entries a mutation would remove still leaves
    // `PrincipalManage` present, so every assertion below passed against a role
    // table that had been gutted. A spot-check says three permissions are
    // right; only the whole list says what the role holds.
    assert_eq!(
        Role::Administrator.permissions(),
        [
            Permission::DeviceList,
            Permission::SessionStart,
            Permission::SessionAttach,
            Permission::UnattendedGrant,
            Permission::PolicyEdit,
            Permission::DeviceManage,
            Permission::PrincipalManage,
            Permission::AuditRead,
            Permission::SelfService,
        ]
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

/// Mutation: change `short_hex` to emit the whole digest instead of 8 bytes.
#[test]
fn audit_every_handle_is_sixteen_lowercase_hex_characters() {
    let mut log = AuditLog::new();
    log.record(
        &tenant("acme"),
        &principal("ann"),
        "device.list",
        AuditOutcome::Allow,
        "",
        NOW,
    )
    .expect("record");
    let event = log.last().expect("one event");

    for handle in [
        event.handle(),
        tenant("acme").audit_handle(),
        principal("ann").audit_handle(),
        DeviceProof::new("laptop-1", "attestation-1", NOW)
            .expect("proof")
            .audit_handle(),
    ] {
        assert_eq!(handle.len(), 16, "handle width drifted: {handle}");
        assert!(
            handle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "handle is not lowercase hex: {handle}"
        );
    }
}

/// Mutation: make `AuditEvent::handle` return the tenant handle, or return the
/// digest as `Debug` rather than hex.
#[test]
fn audit_an_event_handle_correlates_with_nothing_but_its_own_digest() {
    let mut log = AuditLog::new();
    log.record(
        &tenant("acme"),
        &principal("ann"),
        "device.list",
        AuditOutcome::Allow,
        "",
        NOW,
    )
    .expect("record");
    let event = log.last().expect("one event").clone();

    assert_eq!(event.handle(), event.handle(), "handle must be stable");
    assert_ne!(event.handle(), event.tenant_handle());
    assert_ne!(event.handle(), tenant("acme").audit_handle());
    // The documented use is correlating with an external store that holds the
    // handle, so it must be derived from the digest and nothing else.
    assert_eq!(
        event.handle(),
        event.digest()[..8]
            .iter()
            .fold(String::with_capacity(16), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            })
    );
}

/// Mutation: make `DeviceProof::audit_handle` return the device id, or drop
/// its domain-separation prefix so it collides with the tenant handle.
#[test]
fn audit_a_device_handle_is_stable_and_hides_the_device_id() {
    let proof = DeviceProof::new("laptop-1", "attestation-1", NOW).expect("proof");
    let other = DeviceProof::new("laptop-2", "attestation-2", NOW).expect("proof");

    assert_eq!(proof.audit_handle(), proof.audit_handle());
    assert_ne!(proof.audit_handle(), other.audit_handle());
    // Distinct prefixes per kind: a device and a tenant whose ids would
    // otherwise hash alike must not share a handle, or an event about one is
    // indistinguishable from an event about the other.
    assert_ne!(
        proof.audit_handle(),
        tenant("laptop-1").audit_handle(),
        "the device prefix is missing, so this handle cannot tell a device \
         from a tenant"
    );
    assert!(!proof.audit_handle().contains("laptop-1"));
    // The assertion above is satisfied by a handle that returns the device id
    // in some other encoding, and it cannot see the device/principal prefix at
    // all. This one can see both: a principal is the third kind that shares the
    // id space, and a device handle that collides with a principal handle is
    // the same indistinguishability the tenant check above guards against.
    assert_ne!(
        proof.audit_handle(),
        principal("laptop-1").audit_handle(),
        "the device prefix is missing, so this handle cannot tell a device \
         from a principal"
    );
    assert_eq!(proof.audit_handle().len(), 16);
    // Pinned by value, for the same reason as the tenant and principal
    // handles: every assertion above is an inequality or a substring check,
    // and none of them can fail if the domain-separation prefix is dropped.
    assert_eq!(proof.audit_handle(), "223cbfebc4a9117a");
    assert_eq!(other.audit_handle(), "0141d80c3ff8ad2f");
}

/// Mutation: make `PrincipalId::audit_handle` return `self.0`, or drop its
/// domain-separation prefix.
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
    // The two assertions above hold for a handle that returns the principal id
    // outright, which is what the first half of this docstring names. This
    // pair is what rules that out: an id in the clear is the thing the handle
    // exists to prevent, and a handle that is merely *unique* is not yet
    // pseudonymous. The domain-separation check against a tenant is here for
    // the same reason the tenant one is -- the uniqueness assertions above
    // cannot see it.
    assert!(!principal("ann").audit_handle().contains("ann"));
    assert_ne!(
        principal("acme").audit_handle(),
        tenant("acme").audit_handle()
    );
    // Pinned by value for the reason given in `tenant_handles_are_unique_and_
    // stable`: the inequality above holds with or without the prefix, so it
    // cannot see the mutation its own docstring names. The handle is a
    // published value that an external store correlates on, so its exact
    // derivation is part of the contract.
    assert_eq!(principal("ann").audit_handle(), "dd8817c23f781735");
    assert_eq!(principal("bob").audit_handle(), "2f31a904780f07a5");
}

/// Mutation: make `record` store `principal.as_str()` in the record rather
/// than `principal.audit_handle()`.
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
    // The digest above differs because the whole record differs, which is a
    // weaker statement than it looks: swapping the principal handle for
    // anything else unique changes the digest too. What this test is actually
    // for is that the principal *is committed to* rather than merely present,
    // and only a cross-record comparison can show that -- an audit record whose
    // principal field never reached the digest would still verify, still
    // chain, and still name two different principals.
    let mut three = AuditLog::new();
    three
        .record(
            &tenant("acme"),
            &principal("ann"),
            "a",
            AuditOutcome::Allow,
            "",
            1,
        )
        .expect("record");
    assert_eq!(
        one.last().expect("event").digest(),
        three.last().expect("event").digest(),
        "the same principal must produce the same digest"
    );
    assert!(
        !format!("{}", one.last().expect("event")).contains("ann"),
        "the principal id reached the record rather than its handle"
    );
}

// --- mfa / sso boundary ----------------------------------------------------

/// Mutation: make `SingleFactor` satisfy `MultiFactor`.
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

/// Mutation: change `Assurance::name`'s `multi_factor` arm to return the
/// label another strength already uses.
#[test]
fn mfa_strength_names_are_static() {
    // Pinned by value, and distinct from each other. The previous version of
    // this test asserted only that each name was non-empty, which every
    // possible string satisfies -- it could not fail, and its `Mutation:`
    // docstring said so. Two strengths reporting the same wire name is a real
    // failure here: an audit line or a policy document that distinguishes
    // strength by name becomes ambiguous, and nothing downstream can recover
    // which was meant.
    let names: Vec<&'static str> = vec![
        Assurance::None,
        Assurance::SingleFactor,
        Assurance::MultiFactor,
        Assurance::HardwareBacked,
    ]
    .into_iter()
    .map(Assurance::name)
    .collect();
    assert_eq!(
        names,
        vec!["none", "single_factor", "multi_factor", "hardware_backed"]
    );
    let unique: std::collections::BTreeSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "two strengths share a wire name");
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
