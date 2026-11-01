# KMJ OmniDesk — Support and Recovery (DRAFT / NOT APPROVED)

> **M14 support gate: BLOCKED — support lead sign-off and real-device recovery
> evidence are pending.** These are diagnostic guidelines, not an executable
> cleanup or rollback procedure for customer devices.

## 1. First-response triage (read-only)

Record the product version, operating-system build, affected installation
scope (per-user versus machine-wide), symptoms, timestamps, and approved
diagnostic identifiers. Verify the **exact** installer SHA-256 against a
trusted, independently authenticated release manifest. Confirm the release
signer and update channel before taking any action. Do not treat an unsigned
CI candidate as a customer installer.

PowerShell read-only hash example, with a file path explicitly selected by
the operator:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath "C:\\path\\to\\verified-installer.exe"
```

This does not establish signature authenticity on its own.

## 2. Installation and update failures

- Preserve user state, device identity, licenses, support logs and any
  previous known-good release before changing binaries.
- Do not run blanket `Remove-Item -Recurse -Force`, `Stop-Process -Force`,
  or move/replace application directories from this runbook.
- The operator must verify the actual installed path, directory ownership,
  ACLs, junction/reparse-point status, service state and backup restoration.
  Never infer a safe deletion target from a directory name or suffix match.
- A rollback is permitted only through an **implemented, tested, authenticated
  updater** with verified prior artifact and anti-downgrade policy. The
  proposed `bin.old` swap and 30-second recovery behavior are not certified
  by this document.
- Capture the actual updater/installer receipts and get explicit support
  authorization before executing any recovery action.

## 3. Licensing incidents (KSLP-v1)

The offline E2E suite uses mock signing keys and cannot prove the production
licensing service is live. For invalid signature, revoked key, offline grace
or clock-rollback symptoms, record the exact error and independently verify
the trusted public-key discovery and entitlement service before recommending
renewal. Do not edit lease state, change the clock to bypass restrictions,
or delete device identity. Tenant seat changes require authorized account
administration.

## 4. Deprovisioning and residue

Uninstall residue cleanup remains **NOT VALIDATED**. A safe future tool must
enforce explicit operator-approved paths, fixed roots, symlink/reparse-point
refusal, ACL verification, dry-run preview, backup/restore evidence and
separate owner confirmation. No state deletion command is provided here.
This also protects the user's P520 `Cargo.lock`, `.zed` and other work files.

## 5. Diagnostic privacy

Do not upload raw logs, session frames, clipboard contents, tokens, private
keys or user-identifying data. The previously referenced
`scripts/collect_support_bundle.ps1` has not been verified as present or
tested in this release review. Do **not** claim automatic redaction. Use
approved, independently validated redaction before sharing bounded evidence.

## 6. Release evidence required

- [ ] Verified Windows installer and recovery/rollback tests on real hardware
- [ ] Safe deprovisioning with junction/ACL and restoration tests
- [ ] Real production licensing failure/recovery evidence
- [ ] Reviewed support data collection and privacy controls
- [ ] Exact candidate SHA and support lead approval

```yaml
signoff_gate: support_and_recovery_path_defined
requires_role: support_lead
status: PENDING_HUMAN_SIGNOFF
reviewer: ""
date: ""
candidate_sha: ""
notes: "Recovery and cleanup are not approved for customer execution."
```
