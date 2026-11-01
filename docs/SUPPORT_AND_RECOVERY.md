# KMJ OmniDesk — Support and Recovery Runbook

> **M14 Gate Status**: Requires manual sign-off from `support_lead`.
> **Document Status**: Authoritative Engineering Runbook (Draft ready for Review).

---

## 1. Scope and Objective

This runbook defines the operational support, troubleshooting, and recovery procedures for the **KMJ OmniDesk** Windows desktop client (`omnidesk-desktop.exe`). It covers:
- Installation failure and corrupted local state recovery.
- Update failure rollback and atomic downgrade defense.
- Offline grace and licensing recovery (KSLP-v1).
- Uninstaller residue cleanup and registry state management.
- Log scrubbing, diagnostics extraction, and data privacy sanitization.

---

## 2. Architecture and Data Locations

### Standard User Paths (Per-User Installation)
- **Binary Directory**: `%LOCALAPPDATA%\Programs\KMJ-OmniDesk\bin\`
- **Configuration & Storage**: `%LOCALAPPDATA%\KMJ-OmniDesk\state\`
- **Cached Leases & Identity**: `%LOCALAPPDATA%\KMJ-OmniDesk\state\licensing.json`
- **Session & Network Logs**: `%LOCALAPPDATA%\KMJ-OmniDesk\logs\`

### System / Service Paths (When Running as Windows Service)
- **Service Executable**: `%ProgramFiles%\KMJ TECHNO\KMJ OmniDesk\omnidesk-service.exe`
- **System State**: `%ProgramData%\KMJ TECHNO\KMJ OmniDesk\`

---

## 3. Installation Recovery

### Symptoms:
- Installer terminates with error or hangs during file extraction.
- Desktop application fails to start after setup (`STATUS_DLL_NOT_FOUND` or missing runtime).

### Triage & Recovery Steps:
1. **Verify Binary Integrity**:
   Check the SHA-256 hash of the downloaded package against the official release manifest:
   ```powershell
   Get-FileHash -Algorithm SHA256 "kmj-omnidesk-0.0.2-windows-x86_64.zip"
   ```
2. **Check Antivirus / SmartScreen Interference**:
   - Ensure the executable is signed with the official KMJ TECHNO Authenticode certificate.
   - In corporate environments, confirm endpoint protection has not quarantined `omnidesk-desktop.exe`.
3. **Clean Installation Reset**:
   If local state is corrupted, back up the configuration directory and perform a clean reinstall:
   ```powershell
   Stop-Process -Name "omnidesk-desktop" -Force -ErrorAction SilentlyContinue
   Remove-Item -Path "$env:LOCALAPPDATA\Programs\KMJ-OmniDesk" -Recurse -Force
   # Re-extract clean binary from verified release ZIP
   ```

---

## 4. Update Failure and Rollback

### Architecture:
- Updates are delivered via authenticated manifest (`.bundle.json`) with Ed25519 payload signatures.
- Updates apply using an **atomic staging swap**:
  1. The new version is staged in `%LOCALAPPDATA%\Programs\KMJ-OmniDesk\staging\`.
  2. Cryptographic signature and SHA-256 digests are verified.
  3. The current binary is moved to `bin.old`, and `staging` is promoted to `bin`.
  4. If the new binary fails health checks within 30 seconds, automatic fallback swaps `bin.old` back into `bin`.

### Manual Rollback Procedure:
If an update results in a regression or crash-loop:
1. Terminate running instances:
   ```powershell
   Stop-Process -Name "omnidesk-desktop" -Force -ErrorAction SilentlyContinue
   ```
2. Inspect the rollback directory:
   ```powershell
   cd "$env:LOCALAPPDATA\Programs\KMJ-OmniDesk"
   if (Test-Path "bin.old") {
       Remove-Item -Path "bin" -Recurse -Force
       Move-Item -Path "bin.old" -Destination "bin"
       Write-Output "Rollback completed to previous known-good binary."
   }
   ```
3. Lock updater to prevent immediate re-upgrade:
   Set `"auto_update": false` in `%LOCALAPPDATA%\KMJ-OmniDesk\state\config.json`.

---

## 5. Licensing and Offline Grace Triage (KSLP-v1)

### Key Principles:
- Entitlements are signed with Ed25519 keys governed by KMJ Main Platform.
- Leases grant **offline grace** (up to 24 hours / 86,400s) after lease expiration before transitioning to `Restricted`.
- Explicit server revocation (`REVOKED`) permanently overrides offline grace.
- Clock rollback behind `last_trusted_server_time` fails closed immediately to prevent lease tampering.

### Troubleshooting Scenarios:

#### Scenario A: Client Shows `Restricted (Offline Grace Expired)`
- **Root Cause**: The client has been disconnected from the internet or cannot reach `https://kmjtechno.com/licensing/v1` for longer than the grace duration.
- **Resolution**:
  1. Verify network connectivity to `https://kmjtechno.com/licensing/v1/keys`.
  2. If the network is restored, trigger manual lease renewal in UI (Settings > License > Renew).
  3. If the server was down, verify backend status with KMJ Main Platform operations.

#### Scenario B: Client Shows `Clock Rollback Detected`
- **Root Cause**: The system clock was adjusted backwards behind the timestamp stored in the active lease.
- **Resolution**:
  1. Synchronize system time with an authoritative NTP server:
     ```powershell
     w32tm /resync /force
     ```
  2. Verify system clock is accurate to within ±60 seconds of UTC.
  3. Restart KMJ OmniDesk. Once online, the client reconciles with `server_time` from the status endpoint.

#### Scenario C: Server Error `TENANT_SEAT_QUOTA_EXCEEDED`
- **Root Cause**: All allocated seats or concurrent session licenses for the organization are in use.
- **Resolution**:
  1. Direct organization administrator to the KMJ Main Platform admin console.
  2. Revoke stale activations from decommissioned devices.
  3. Upgrade tenant plan seat capacity if needed.

---

## 6. Uninstaller Residue and State Cleanup

### Residue Cleanup Checklist:
Upon uninstalling KMJ OmniDesk:
- **Binaries**: Deleted automatically from `%LOCALAPPDATA%\Programs\KMJ-OmniDesk\`.
- **Shortcuts**: Start Menu and Desktop shortcuts removed.
- **State Files**:
  - By default, cached identity and leases remain to preserve device binding across upgrades.
  - For full clean de-provisioning (e.g. employee off-boarding or device repurposing):
    ```powershell
    Remove-Item -Path "$env:LOCALAPPDATA\KMJ-OmniDesk" -Recurse -Force
    Remove-Item -Path "$env:APPDATA\KMJ-OmniDesk" -Recurse -Force -ErrorAction SilentlyContinue
    ```

---

## 7. Diagnostics Collection and Log Scrubbing

### Mandatory Privacy Scrubbing:
Customer support personnel must NEVER collect or transmit un-scrubbed session data.
- **Device Private Key**: Stored in memory / DPAPI; never written to logs or dump files.
- **Session Payloads**: Audio/video frame buffers and keystrokes are ephemeral and must NEVER appear in logs.
- **PII Scrubbing**:
  Support bundle collector (`scripts/collect_support_bundle.ps1`) automatically masks:
  - Authorization tokens, bearer headers, and signatures.
  - Remote IP addresses (replaces last two octets with `.xxx.xxx`).
  - Passwords, credentials, and clipboard strings.

---

## 8. Support Escalation Matrix

| Severity | Issue Description | Initial Response | Escalation Target |
|:---|:---|:---|:---|
| **P0 - Blocker** | Widespread crash on startup or broken update roll-out | < 15 minutes | Release Engineering / Lead Core Dev |
| **P1 - Critical** | Licensing server outage or false mass revocation | < 30 minutes | Main Platform Backend Lead |
| **P2 - High** | Peer direct connect failure (falling back to relay) | < 2 hours | Networking / WebRTC Team |
| **P3 - Normal** | Single device installation / permission issue | < 8 hours | Tier 2 Support Specialist |

---

## 9. Official Sign-Off

```yaml
signoff_gate: support_and_recovery_path_defined
requires_role: support_lead
status: PENDING_HUMAN_SIGNOFF
reviewer: ""
date: ""
notes: "Engineering runbook authored and verified. Awaiting human Support Lead review and sign-off."
```
