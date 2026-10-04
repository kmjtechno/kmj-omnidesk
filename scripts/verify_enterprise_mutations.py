"""Mutation harness for the M10 enterprise authorization and audit tests.

Applies one edit at a time, runs the enterprise tests, and reports whether any
test failed. A mutation that leaves the suite green is a hole in the tests, not
a win -- the suite is meant to be able to say no.

This harness exists because the 72 `Mutation:` docstrings in
`enterprise/tests.rs` were, until now, comments. Every other suite in this
repository has a `verify_*_mutations.py` that CI runs; these were applied by
hand on one afternoon and never re-checked. A mutation note with nothing
applying it is documentation of an intention, not evidence.

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

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTERPRISE = ROOT / "crates" / "omnidesk-core" / "src" / "enterprise"

# (label, target file, must-contain, replacement)
MUTATIONS: list[tuple[str, str, str, str]] = [
    # --- tenant boundary --------------------------------------------------
    (
        "the tenant guard in evaluate is deleted",
        "mod.rs",
        "if context.tenant() != self.policy.tenant() {",
        "if false {",
    ),
    (
        "the tenant guard in evaluate is inverted",
        "mod.rs",
        "if context.tenant() != self.policy.tenant() {",
        "if context.tenant() == self.policy.tenant() {",
    ),
    (
        "events_for_tenant_handle returns every tenant's events",
        "audit.rs",
        "pub fn events_for_tenant_handle(&self, handle: &str) -> Vec<&AuditEvent> {",
        "pub fn events_for_tenant_handle(&self, handle: &str) -> Vec<&AuditEvent> {\n        let _ = handle;\n        self.events.iter().collect()\n    }\n    #[allow(dead_code)]\n    pub fn events_for_tenant_handle_unused(&self, handle: &str) -> Vec<&AuditEvent> {",
    ),
    # --- identity ---------------------------------------------------------
    (
        "the tenant handle loses its domain separation",
        "mod.rs",
        "fn audit_handle(&self) -> String {",
        "fn audit_handle(&self) -> String {\n        return self.0.to_string();\n        #[allow(unreachable_code)]\n    }\n    fn audit_handle_unused(&self) -> String {",
    ),
    (
        "TenantId::new accepts an empty id",
        "mod.rs",
        'if value.trim().is_empty() {',
        "if false {",
    ),
    (
        "TenantId::new raises the length bound",
        "mod.rs",
        "MAX_TENANT_ID_BYTES",
        "1024",
    ),
    (
        "TenantId::new accepts control characters",
        "mod.rs",
        "chars().any(char::is_control)",
        "chars().any(|_| false)",
    ),
    (
        "TenantId::new accepts non-ascii",
        "mod.rs",
        "!value.is_ascii()",
        "false",
    ),
    (
        "TenantId::from_identity accepts an address without @",
        "mod.rs",
        "contains('@')",
        "false",
    ),
    # --- policy engine ----------------------------------------------------
    (
        "PolicyEngine::evaluate drops the granted check",
        "mod.rs",
        "!context.granted(permission)",
        "false",
    ),
    # --- RBAC -------------------------------------------------------------
    (
        "may_delegate ignores the granter's own permissions",
        "rbac.rs",
        "pub fn may_delegate(",
        "pub fn may_delegate(\n        &self,\n        permission: Permission,\n    ) -> bool {\n        let _ = permission;\n        true\n    }\n    #[allow(dead_code)]\n    pub fn may_delegate_unused(\n        &self,\n        permission: Permission,\n    ) -> bool {",
    ),
    (
        "Administrator loses UnattendedGrant",
        "rbac.rs",
        "                Permission::PrincipalManage,",
        "                Permission::PolicyEdit,",
    ),
    # --- assurance --------------------------------------------------------
    (
        "Assurance::None satisfies every level",
        "mod.rs",
        "fn satisfies(",
        "fn satisfies(\n        &self,\n        _required: Assurance,\n    ) -> bool {\n        let _ = _required;\n        true\n    }\n    #[allow(dead_code)]\n    fn satisfies_unused(",
    ),
    (
        "evaluate drops the assurance guard",
        "mod.rs",
        "!context.assurance().satisfies(required)",
        "false",
    ),
    # --- unattended access ------------------------------------------------
    (
        "unattended grants ignore the policy flag",
        "mod.rs",
        "if !self.policy.allows_unattended() {",
        "if false {",
    ),
    (
        "unattended grants accept any assurance level",
        "mod.rs",
        "if !context.assurance().satisfies(Assurance::HardwareBacked) {",
        "if false {",
    ),
    # --- trusted devices --------------------------------------------------
    (
        "assess trusts an unknown device id",
        "trusted_device.rs",
        "fn assess(",
        "fn assess(\n        &self,\n        _id: &str,\n        _now: u64,\n    ) -> TrustDecision {\n        let _ = _id;\n        let _ = _now;\n        TrustDecision::Trusted\n    }\n    #[allow(dead_code)]\n    fn assess_unused(",
    ),
    (
        "assess drops the revoked check",
        "trusted_device.rs",
        "        if device.is_revoked() {\n            return TrustDecision::Revoked;\n        }",
        "        if false {\n            return TrustDecision::Revoked;\n        }",
    ),
    (
        "trust expiry is inclusive at the boundary",
        "trusted_device.rs",
        "now < self.trust_expires_at",
        "now <= self.trust_expires_at",
    ),
    (
        "is_trusted_at drops the revoked conjunct",
        "trusted_device.rs",
        "!self.revoked &&",
        "",
    ),
    # --- audit chain ------------------------------------------------------
    (
        "record drops the digest chain",
        "audit.rs",
        "fn record(",
        "fn record(\n        &mut self,\n        event: AuditEvent,\n    ) {\n        self.events.push(event);\n    }\n    #[allow(dead_code)]\n    fn record_unused(\n        &mut self,\n        event: AuditEvent,\n    ) {",
    ),
    (
        "verify_chain accepts a tampered event",
        "audit.rs",
        "fn verify_chain(",
        "fn verify_chain(\n        &self,\n        tenant: &TenantId,\n        _through: u64,\n    ) -> Result<(), AuditError> {\n        let _ = (tenant, _through);\n        Ok(())\n    }\n    #[allow(dead_code)]\n    fn verify_chain_unused(\n        &self,\n        tenant: &TenantId,\n        through: u64,\n    ) -> Result<(), AuditError> {",
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


def main() -> int:
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