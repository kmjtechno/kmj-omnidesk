"""Mutation harness for the M10 enterprise authorization and audit tests.

Applies one edit at a time, runs the enterprise tests, and reports whether any
test failed. A mutation that leaves the suite green is a hole in the tests, not
a win -- the suite is meant to be able to say no.

This harness exists because the `Mutation:` docstrings in
`enterprise/tests.rs` were, until now, comments. Every other suite in this
repository has a `verify_*_mutations.py` that CI runs; these were applied by
hand on one afternoon and never re-checked. A mutation note with nothing
applying it is documentation of an intention, not evidence.

Each entry names the test whose docstring it came from, and `main()` refuses
to run if the two lists disagree. Without that check, a test added after this
file was last updated would arrive carrying a `Mutation:` line, read like
evidence, and never be applied -- the exact defect this harness was written to
close, reintroduced one test at a time.

Multi-file, unlike the other harnesses: the enterprise module is split across
`mod.rs`, `rbac.rs`, `trusted_device.rs`, `unattended.rs`, and `audit.rs`, and
the mutations land in each. Every mutation names its target file explicitly so
a pattern that matches in the wrong module cannot be silently applied to the
wrong place -- the shape of bug that made the first version of the unreferenced
check scanner report a function that was called.

A mutation that fails to apply is reported, never skipped. A skipped mutation
looks identical to a caught one in a log full of checkmarks.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTERPRISE = ROOT / "crates" / "omnidesk-core" / "src" / "enterprise"

# (the test whose `Mutation:` docstring this is, target file, must-contain,
#  replacement). One entry per docstring, so a docstring with no entry left
#  to apply it is visible as a gap in this list rather than as a comment that
#  reads like evidence.
MUTATIONS: list[tuple[str, str, str, str]] = [
    # --- tenant boundary --------------------------------------------------
    (
        "tenant_a_context_cannot_use_another_tenants_policy",
        "mod.rs",
        "    ) -> Result<Decision, PolicyError> {\n        if context.tenant() != self.policy.tenant() {\n            return Err(PolicyError::NoPolicyForTenant);\n        }",
        "    ) -> Result<Decision, PolicyError> {\n        if false {\n            return Err(PolicyError::NoPolicyForTenant);\n        }",
    ),
    (
        "tenant_matching_policy_is_evaluated_normally",
        "mod.rs",
        "    ) -> Result<Decision, PolicyError> {\n        if context.tenant() != self.policy.tenant() {",
        "    ) -> Result<Decision, PolicyError> {\n        if context.tenant() == self.policy.tenant() {",
    ),
    (
        "tenant_an_audit_query_returns_only_the_named_tenants_events",
        "audit.rs",
        "    pub fn events_for_tenant_handle(&self, handle: &str) -> Vec<&AuditEvent> {\n        self.events\n            .iter()\n            .filter(|event| event.is_for_tenant_handle(handle))\n            .collect()\n    }",
        "    pub fn events_for_tenant_handle(&self, handle: &str) -> Vec<&AuditEvent> {\n        let _ = handle;\n        self.events.iter().collect()\n    }",
    ),
    (
        "tenant_handles_are_unique_and_stable",
        "mod.rs",
        '        sha2::Digest::update(&mut hasher, b"omnidesk.audit.tenant.v1\\0");\n',
        "",
    ),
    # --- privacy of identifiers -------------------------------------------
    (
        "a_tenant_debug_never_prints_the_tenants_own_name",
        "mod.rs",
        "impl fmt::Debug for TenantId {",
        "impl fmt::Debug for TenantId {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        return write!(f, \"{}\", self.0);\n    }\n}\n\n#[allow(dead_code)]\nimpl fmt::Debug for TenantIdUnused {",
    ),
    (
        "tenant_a_blank_tenant_is_refused",
        "mod.rs",
        "        let value = value.into();\n        if value.trim().is_empty() {\n            return Err(PolicyError::EmptyTenant);\n        }",
        "        let value = value.into();\n        if false {\n            return Err(PolicyError::EmptyTenant);\n        }",
    ),
    (
        "tenant_an_overlong_tenant_is_refused",
        "mod.rs",
        "MAX_TENANT_ID_BYTES: usize = 64",
        "MAX_TENANT_ID_BYTES: usize = 8",
    ),
    (
        "tenant_a_control_character_in_a_tenant_is_refused",
        "mod.rs",
        "            return Err(PolicyError::TenantIdNotAscii);\n        }\n        if value.chars().any(char::is_control) {",
        "            return Err(PolicyError::TenantIdNotAscii);\n        }\n        if false {",
    ),
    (
        "tenant_a_non_ascii_tenant_is_refused",
        "mod.rs",
        "        if !value.is_ascii() {\n            return Err(PolicyError::TenantIdNotAscii);",
        "        if false {\n            return Err(PolicyError::TenantIdNotAscii);",
    ),
    (
        "tenant_a_user_identity_is_not_a_tenant",
        "mod.rs",
        "        if value.as_str().contains('@') {",
        "        if false {",
    ),
    # --- privilege escalation ---------------------------------------------
    (
        "escalation_a_permission_the_grant_does_not_carry_is_refused",
        "mod.rs",
        "        if !context.granted(permission) {\n            return Ok(Decision::Deny(DenyReason::NotGranted));\n        }",
        "        if false {\n            return Ok(Decision::Deny(DenyReason::NotGranted));\n        }",
    ),
    (
        "escalation_the_ceiling_is_checked_before_policy",
        "mod.rs",
        "        if !context.granted(permission) {\n            return Ok(Decision::Deny(DenyReason::NotGranted));\n        }\n\n        if self.policy.forbidden.contains(&permission) {",
        "        if self.policy.forbidden.contains(&permission) {\n            return Ok(Decision::Deny(DenyReason::PolicyForbids));\n        }\n        if !context.granted(permission) {\n            return Ok(Decision::Deny(DenyReason::NotGranted));\n        }",
    ),
    (
        "escalation_no_role_may_delegate_a_permission_it_lacks",
        "rbac.rs",
        "    pub fn may_delegate(self, permission: Permission) -> bool {\n        self.permissions().contains(&permission)\n    }",
        "    pub fn may_delegate(self, permission: Permission) -> bool {\n        let _ = permission;\n        true\n    }",
    ),
    (
        "device_the_managed_flag_is_recorded_verbatim_and_is_not_a_trust_input",
        "trusted_device.rs",
        "        if !device_id.is_ascii() || device_id.chars().any(char::is_control) {\n            return Err(PolicyError::DeviceIdNotAcceptable);\n        }\n        if trust_expires_at <= enrolled_at {",
        "        if !device_id.is_ascii() || device_id.chars().any(char::is_control) {\n            return Err(PolicyError::DeviceIdNotAcceptable);\n        }\n        if false && trust_expires_at <= enrolled_at {",
    ),
    (
        "escalation_the_administrative_classification_is_not_the_ceiling",
        "rbac.rs",
        "    pub fn may_delegate(self, permission: Permission) -> bool {\n        self.permissions().contains(&permission)\n    }",
        "    pub fn may_delegate(self, permission: Permission) -> bool {\n        !permission.is_administrative() && self.permissions().contains(&permission)\n    }",
    ),
    (
        "escalation_a_role_holds_exactly_its_declared_permissions",
        "rbac.rs",
        "            Self::Administrator => &[\n                Permission::DeviceList,\n                Permission::SessionStart,\n                Permission::SessionAttach,\n                Permission::UnattendedGrant,\n                Permission::PolicyEdit,\n                Permission::DeviceManage,\n                Permission::PrincipalManage,\n                Permission::AuditRead,\n                Permission::SelfService,\n            ],",
        "            Self::Administrator => &[Permission::PrincipalManage],",
    ),
    (
        "escalation_delegation_never_exceeds_the_delegating_role",
        "rbac.rs",
        "            Self::Auditor => &[Permission::DeviceList, Permission::AuditRead],",
        "            Self::Auditor => &[\n                Permission::DeviceList,\n                Permission::AuditRead,\n                Permission::SessionAttach,\n            ],",
    ),
    # --- policy narrowing -------------------------------------------------
    (
        "policy_a_document_can_narrow_but_cannot_widen",
        "mod.rs",
        "    pub fn forbid(mut self, permission: Permission) -> Self {",
        "    /// Mutation: a widening operation the tests must notice.\n    #[must_use]\n    pub fn allow(mut self, permission: Permission) -> Self {\n        self.forbidden.retain(|held| *held != permission);\n        self\n    }\n\n    pub fn forbid(mut self, permission: Permission) -> Self {",
    ),
    (
        "policy_the_document_type_has_no_widening_operation",
        "mod.rs",
        "impl PolicyDocument {",
        "impl PolicyDocument {\n    #[must_use]\n    pub fn permit(mut self, permission: Permission) -> Self {\n        self.forbidden.retain(|held| *held != permission);\n        self\n    }\n",
    ),
    (
        "policy_forbidding_twice_does_not_duplicate",
        "mod.rs",
        "        if !self.forbidden.contains(&permission) {\n            self.forbidden.push(permission);\n        }",
        "        self.forbidden.push(permission);",
    ),
    (
        "policy_a_requirement_of_nothing_is_met_by_everything",
        "mod.rs",
        "            None => matches!(required, None),",
        "            None => false,",
    ),
    (
        "policy_a_demanding_policy_refuses_a_weak_request",
        "mod.rs",
        "        if let Some(required) = self.policy.required_assurance {\n            if !context.assurance().satisfies(required) {",
        "        if let Some(required) = self.policy.required_assurance {\n            if false && !context.assurance().satisfies(required) {",
    ),
    # --- roles ------------------------------------------------------------
    (
        "role_an_administrator_requires_a_hardware_key",
        "rbac.rs",
        "            Self::Administrator => Assurance::HardwareBacked,",
        "            Self::Administrator => Assurance::None,",
    ),
    (
        "role_an_operator_works_on_a_single_factor",
        "rbac.rs",
        "            Self::Auditor | Self::Operator => Assurance::SingleFactor,",
        "            Self::Auditor | Self::Operator => Assurance::HardwareBacked,",
    ),
    (
        "role_a_permission_outside_the_role_is_refused",
        "mod.rs",
        "        if !role.permissions().contains(&permission) {\n            return Ok(Decision::Deny(DenyReason::RoleLacks));\n        }",
        "        if false {\n            return Ok(Decision::Deny(DenyReason::RoleLacks));\n        }",
    ),
    (
        "role_strength_compares_as_a_ladder",
        "mod.rs",
        "            SingleFactor => matches!(required, None | SingleFactor),",
        "            SingleFactor => true,",
    ),
    # --- rbac tables ------------------------------------------------------
    (
        "rbac_every_permission_round_trips",
        "rbac.rs",
        '            Self::AuditRead => "audit_read",',
        '            Self::AuditRead => "audit_read_typo",',
    ),
    (
        "rbac_an_unknown_permission_is_refused_rather_than_defaulted",
        "rbac.rs",
        "            \"self_service\" => Self::SelfService,\n            _ => return None,\n        })",
        "            \"self_service\" => Self::SelfService,\n            _ => Self::DeviceList,\n        })",
    ),
    (
        "rbac_every_role_round_trips",
        "rbac.rs",
        '            "auditor" => Self::Auditor,\n            _ => return None,',
        '            _ => return None,',
    ),
    # --- trusted devices --------------------------------------------------
    (
        "device_an_unenrolled_device_is_not_trusted",
        "trusted_device.rs",
        "        let Some(device) = self.get(device_id) else {\n            return TrustDecision::NotEnrolled;\n        };",
        "        let Some(device) = self.get(device_id).or(Some(&UNENROLLED)) else {\n            return TrustDecision::NotEnrolled;\n        };",
    ),
    (
        "device_a_revoked_device_is_not_trusted",
        "trusted_device.rs",
        "        if device.is_revoked() {\n            return TrustDecision::Revoked;\n        }",
        "        if false {\n            return TrustDecision::Revoked;\n        }",
    ),
    (
        "device_an_expired_device_is_not_trusted",
        "trusted_device.rs",
        "        !self.revoked && now < self.trust_expires_at",
        "        !self.revoked && now <= self.trust_expires_at",
    ),
    (
        "device_re_enrolment_replaces_rather_than_appends",
        "trusted_device.rs",
        "        self.devices\n            .retain(|existing| existing.device_id != device_id);\n",
        "",
    ),
    (
        "device_trust_must_expire_after_it_is_granted",
        "trusted_device.rs",
        "        if trust_expires_at <= enrolled_at {\n            return Err(PolicyError::TrustExpiryNotAfterEnrolment);\n        }",
        "        if false {\n            return Err(PolicyError::TrustExpiryNotAfterEnrolment);\n        }",
    ),
    (
        "device_a_hostile_device_id_is_refused",
        "trusted_device.rs",
        "        if device_id.len() > MAX_DEVICE_ID_BYTES {\n            return Err(PolicyError::DeviceIdTooLong {\n                length: device_id.len(),\n                maximum: MAX_DEVICE_ID_BYTES,\n            });\n        }\n        if !device_id.is_ascii() || device_id.chars().any(char::is_control) {",
        "        if false {\n            return Err(PolicyError::DeviceIdTooLong {\n                length: device_id.len(),\n                maximum: MAX_DEVICE_ID_BYTES,\n            });\n        }\n        if !device_id.is_ascii() || device_id.chars().any(char::is_control) {",
    ),
    (
        "device_a_policy_requiring_a_trusted_device_refuses_an_untrusted_one",
        "mod.rs",
        "        if self.policy.require_trusted_device\n            && !context",
        "        if false\n            && !context",
    ),
    (
        "device_the_authorization_predicate_itself_refuses_a_revoked_device",
        "trusted_device.rs",
        "        !self.revoked && now < self.trust_expires_at",
        "        now < self.trust_expires_at",
    ),
    (
        "device_an_assessment_made_at_its_expiry_instant_is_already_expired",
        "trusted_device.rs",
        "        self.is_trusted_at(self.assessed_at)",
        "        self.is_trusted_at(self.trust_expires_at)",
    ),
    (
        "device_an_unexpired_assessment_is_trusted",
        "trusted_device.rs",
        "        if device.is_revoked() {\n            return TrustDecision::Revoked;\n        }\n        if !device.is_trusted_at(now) {\n            return TrustDecision::Expired;\n        }",
        "        if !device.is_trusted_at(now) {\n            return TrustDecision::Expired;\n        }\n        if device.is_revoked() {\n            return TrustDecision::Revoked;\n        }",
    ),
    (
        "device_revocation_is_reported_even_when_the_trust_has_also_expired",
        "trusted_device.rs",
        "        matches!(self, Self::Trusted)",
        "        !matches!(self, Self::Trusted)",
    ),
    (
        "device_only_the_trusted_decision_counts_as_trusted",
        "trusted_device.rs",
        "        matches!(self, Self::Trusted)",
        "        true",
    ),
    (
        "device_proof_bounds_its_attestation_reference",
        "trusted_device.rs",
        "        if attestation.len() > MAX_ATTESTATION_BYTES {\n            return Err(PolicyError::AttestationTooLong {\n                length: attestation.len(),\n                maximum: MAX_ATTESTATION_BYTES,\n            });\n        }",
        "        if false {\n            return Err(PolicyError::AttestationTooLong {\n                length: attestation.len(),\n                maximum: MAX_ATTESTATION_BYTES,\n            });\n        }",
    ),
    # --- unattended access ------------------------------------------------
    (
        "unattended_a_password_never_reaches_a_standing_grant",
        "mod.rs",
        "        if !context.assurance().satisfies(Assurance::HardwareBacked) {\n            return Ok(UnattendedDecision::InsufficientAssurance {",
        "        if false {\n            return Ok(UnattendedDecision::InsufficientAssurance {",
    ),
    (
        "unattended_a_tenant_can_forbid_it_entirely",
        "mod.rs",
        "        if !self.policy.allows_unattended() {",
        "        if false {",
    ),
    (
        "unattended_a_grant_expires_at_its_expiry_instant",
        "unattended.rs",
        "        !self.revoked && now < self.valid_until_epoch_seconds",
        "        !self.revoked && now <= self.valid_until_epoch_seconds",
    ),
    (
        "unattended_a_revoked_grant_stops_working_immediately",
        "unattended.rs",
        "        !self.revoked && now < self.valid_until_epoch_seconds",
        "        now < self.valid_until_epoch_seconds",
    ),
    (
        "unattended_a_grant_from_another_tenant_is_refused",
        "mod.rs",
        "        if !access.belongs_to(self.policy.tenant().as_str()) {",
        "        if false {",
    ),
    (
        "unattended_a_grant_cannot_exceed_the_signed_ceiling",
        "mod.rs",
        "            .filter(|permission| context.granted(*permission))\n",
        "",
    ),
    (
        "unattended_a_standing_grant_cannot_be_issued_for_a_year",
        "unattended.rs",
        "        if window > MAX_UNATTENDED_WINDOW_SECONDS {\n            return Err(PolicyError::UnattendedWindowTooLong {",
        "        if false {\n            return Err(PolicyError::UnattendedWindowTooLong {",
    ),
    (
        "unattended_a_grant_with_no_permissions_is_refused",
        "unattended.rs",
        "        if permissions.is_empty() {\n            return Err(PolicyError::NoPermissionsGranted);\n        }",
        "        if false {\n            return Err(PolicyError::NoPermissionsGranted);\n        }",
    ),
    (
        "unattended_a_grant_that_expired_at_issue_is_refused",
        "unattended.rs",
        "        if window == 0 {\n            return Err(PolicyError::UnattendedWindowNotInFuture);\n        }",
        "        if false {\n            return Err(PolicyError::UnattendedWindowNotInFuture);\n        }",
    ),
    (
        "unattended_a_grant_id_is_bounded",
        "unattended.rs",
        "        if grant_id.len() > MAX_GRANT_ID_BYTES {\n            return Err(PolicyError::GrantIdTooLong {\n                length: grant_id.len(),\n                maximum: MAX_GRANT_ID_BYTES,\n            });\n        }",
        "        if false {\n            return Err(PolicyError::GrantIdTooLong {\n                length: grant_id.len(),\n                maximum: MAX_GRANT_ID_BYTES,\n            });\n        }",
    ),
    # --- audit recording --------------------------------------------------
    (
        "audit_events_are_hash_chained",
        "audit.rs",
        "        let previous_digest = self\n            .events\n            .last()\n            .map_or([0u8; 32], |event| *event.digest());",
        "        let previous_digest = [0u8; 32];",
    ),
    (
        "audit_a_recomputed_chain_verifies",
        "audit.rs",
        "            previous_digest = event.digest;",
        "            previous_digest = [0u8; 32];",
    ),
    (
        "audit_altering_an_event_is_detected",
        "audit.rs",
        "            if recomputed != event.digest {",
        "            if false && recomputed != event.digest {",
    ),
    (
        "audit_removing_an_event_is_caught_by_the_gap_check",
        "audit.rs",
        "            if event.sequence != expected_sequence {",
        "            if false && event.sequence != expected_sequence {",
    ),
    (
        "audit_a_rewired_link_is_caught_by_the_digest_check",
        "audit.rs",
        "            if event.previous_digest != previous_digest {",
        "            if false && event.previous_digest != previous_digest {",
    ),
    (
        "audit_a_full_rewrite_verifies_and_that_is_the_documented_limit",
        "audit.rs",
        "    pub fn verify_chain(&self) -> Result<(), AuditError> {\n        if self.truncated {",
        "    pub fn verify_chain(&self) -> Result<(), AuditError> {\n        if false {",
    ),
    (
        "audit_a_clock_that_goes_backwards_is_refused",
        "audit.rs",
        "            if at_epoch_seconds < last.at_epoch_seconds {",
        "            if false && at_epoch_seconds < last.at_epoch_seconds {",
    ),
    (
        "audit_attacker_controlled_text_is_bounded",
        "audit.rs",
        "MAX_DETAIL_BYTES: usize = 256",
        "MAX_DETAIL_BYTES: usize = 65536",
    ),
    (
        "audit_a_full_log_says_it_is_incomplete",
        "audit.rs",
        "            self.truncated = true;\n            return Ok(sequence);",
        "            return Ok(sequence);",
    ),
    (
        "audit_a_record_never_contains_a_tenant_or_principal_name",
        "audit.rs",
        "        let tenant_handle = tenant.audit_handle();\n        let principal_handle = principal.audit_handle();",
        "        let tenant_handle = tenant.as_str().to_string();\n        let principal_handle = principal.as_str().to_string();",
    ),
    # --- handles ----------------------------------------------------------
    (
        "audit_every_handle_is_sixteen_lowercase_hex_characters",
        "mod.rs",
        "    for byte in &digest[..8.min(digest.len())] {",
        "    for byte in digest {",
    ),
    (
        "audit_an_event_handle_correlates_with_nothing_but_its_own_digest",
        "audit.rs",
        "    pub fn handle(&self) -> String {\n        short_hex(&self.digest)\n    }",
        "    pub fn handle(&self) -> String {\n        self.tenant_handle.clone()\n    }",
    ),
    (
        "audit_a_device_handle_is_stable_and_hides_the_device_id",
        "trusted_device.rs",
        '        sha2::Digest::update(&mut hasher, b"omnidesk.audit.device.v1\\0");\n',
        "",
    ),
    (
        "audit_principal_handles_are_unique_and_stable",
        "mod.rs",
        "        let digest = sha2::Digest::finalize(hasher);\n        short_hex(&digest)\n    }\n\n    #[must_use]\n    pub fn byte_len(&self) -> usize {\n        self.0.len()\n    }",
        "        self.0.clone()\n    }\n\n    #[must_use]\n    pub fn byte_len(&self) -> usize {\n        self.0.len()\n    }",
    ),
    (
        "audit_principal_handles_are_unique_and_stable",
        "mod.rs",
        '        sha2::Digest::update(&mut hasher, b"omnidesk.audit.principal.v1\\0");\n',
        "",
    ),
    (
        "audit_a_different_principal_produces_a_different_digest",
        "audit.rs",
        "        let principal_handle = principal.audit_handle();",
        "        let principal_handle = principal.as_str().to_string();",
    ),
    # --- mfa / sso boundary ----------------------------------------------
    (
        "mfa_strength_is_a_total_order",
        "mod.rs",
        "            MultiFactor => matches!(required, None | SingleFactor | MultiFactor),",
        "            MultiFactor => true,",
    ),
    (
        "mfa_strength_names_are_static",
        "mod.rs",
        '            MultiFactor => "multi_factor",',
        '            MultiFactor => "single_factor",',
    ),
    # --- managed deployment -----------------------------------------------
    (
        "managed_a_principal_id_is_bounded_and_control_free",
        "mod.rs",
        "        if value.len() > MAX_PRINCIPAL_ID_BYTES {\n            return Err(PolicyError::PrincipalIdTooLong {",
        "        if false {\n            return Err(PolicyError::PrincipalIdTooLong {",
    ),
    (
        "managed_an_empty_grant_allows_nothing",
        "mod.rs",
        "    pub fn granted(&self, permission: Permission) -> bool {\n        self.granted.contains(&permission)\n    }",
        "    pub fn granted(&self, permission: Permission) -> bool {\n        let _ = permission;\n        true\n    }",
    ),
    (
        "managed_the_ceiling_comes_from_the_grant_not_the_claimed_role",
        "mod.rs",
        "    pub const fn from_entitlement(\n        tenant: TenantId,\n        principal: PrincipalId,\n        assurance: Assurance,\n        granted: Vec<Permission>,\n    ) -> Self {\n        Self {\n            tenant,\n            principal,\n            assurance,\n            granted,",
        "    pub const fn from_entitlement(\n        tenant: TenantId,\n        principal: PrincipalId,\n        assurance: Assurance,\n        granted: Vec<Permission>,\n    ) -> Self {\n        Self {\n            tenant,\n            principal,\n            assurance,\n            granted: vec![Permission::DeviceList],",
    ),
]


def apply_mutation(filename: str, old: str, new: str) -> bool:
    """Apply one mutation to one file, or report False so the caller lists it.

    Matches against the whole file rather than line by line: a pattern that
    `rustfmt` wrapped across two lines never matches line-by-line, so those
    mutations report as "apply failed" and silently never run. That has hidden
    results in three other harnesses in this repository.
    """
    path = ENTERPRISE / filename
    source = path.read_text(encoding="utf-8")
    if old not in source:
        return False
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    return True


def run_tests() -> tuple[bool, str]:
    result = subprocess.run(
        ["cargo", "test", "-p", "omnidesk-core", "enterprise", "--lib"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode != 0, result.stdout + result.stderr


def tests_with_a_mutation_docstring() -> set[str]:
    """Every test in `tests.rs` whose doc comment carries a `Mutation:` line.

    Read from the file rather than from `MUTATIONS`, because the failure this
    guards against is a docstring that nothing applies. A test written after
    this list was last updated arrives carrying a `Mutation:` line, reads like
    evidence, and is not in `MUTATIONS` at all -- so a coverage check that
    compared the two lists against each other rather than against the file
    would never notice.
    """
    source = (ENTERPRISE / "tests.rs").read_text(encoding="utf-8")
    lines = source.splitlines()
    found: set[str] = set()
    for index, line in enumerate(lines):
        match = re.match(r"fn (\w+)\(\)", line)
        if not match:
            continue
        # Walk back over the doc comment, stopping at the `#[test]` attribute.
        cursor = index - 1
        if cursor >= 0 and lines[cursor].strip() == "#[test]":
            cursor -= 1
        while cursor >= 0 and lines[cursor].lstrip().startswith("///"):
            if lines[cursor].lstrip().startswith("/// Mutation:"):
                found.add(match.group(1))
                break
            cursor -= 1
    return found


def main() -> int:
    covered = {label for label, _, _, _ in MUTATIONS}
    declared = tests_with_a_mutation_docstring()
    uncovered = sorted(declared - covered)
    unknown = sorted(covered - declared)
    if uncovered or unknown:
        for name in uncovered:
            print(f"NO MUTATION: {name} declares one but nothing applies it")
        for name in unknown:
            print(f"NO DOCSTRING: {name} applies a mutation to a test that declares none")
        print(f"\n{len(uncovered) + len(unknown)} docstring(s) and harness entries disagree")
        return 1
    print(f"docstring coverage: {len(declared)} declared, {len(covered)} applied\n")

    originals = {
        path.name: path.read_text(encoding="utf-8")
        for path in ENTERPRISE.glob("*.rs")
        if not path.name.endswith("tests.rs")
    }
    baseline_failed, output = run_tests()
    if baseline_failed:
        print("FAIL: baseline enterprise tests do not pass")
        print(output[-2000:])
        return 1
    print(f"baseline: PASS ({len(MUTATIONS)} mutations)\n")

    survivors: list[str] = []
    skipped: list[str] = []
    for label, filename, old, new in MUTATIONS:
        if not apply_mutation(filename, old, new):
            skipped.append(f"{label} (pattern not found in {filename})")
            continue
        caught, output = run_tests()
        for name, text in originals.items():
            (ENTERPRISE / name).write_text(text, encoding="utf-8")
        if caught:
            failing = sorted(
                {
                    line.split(" ")[1]
                    for line in output.splitlines()
                    if line.startswith("test enterprise::tests::")
                    and " FAILED" in line
                }
            )
            names = ", ".join(failing[:3]) if failing else "compile error"
            print(f"CAUGHT: {label}  [{names}]")
        else:
            print(f"SURVIVED: {label}")
            survivors.append(label)

    print()
    for item in skipped:
        print(f"APPLY-FAILED: {item}")
    if survivors:
        print(f"\n{len(survivors)} mutation(s) survived")
        return 1
    if skipped:
        print(f"\n{len(skipped)} mutation(s) were never applied")
        return 1
    print("all mutations caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())