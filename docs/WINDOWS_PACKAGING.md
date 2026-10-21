# Windows installer candidate

KMJ OmniDesk uses a pinned NSIS toolchain for the Windows installer candidate.

The Windows CI gate builds the exact release-mode `omnidesk-desktop.exe`, packages it into an installer, installs it silently on the ephemeral runner, verifies the installed executable and uninstaller exist, uninstalls it silently, and verifies the executable is removed.

## Why NSIS

The installer path must not create a paid maintenance or EULA acceptance dependency for normal KMJ OmniDesk engineering. NSIS is open source and suitable for commercial applications, so the repository can keep the installer build reproducible without introducing a paid build gate.

The CI toolchain is pinned to NSIS 3.13.0.

## Security boundary

The CI installer is an **unsigned release candidate**.

CI explicitly verifies that the candidate reports `NotSigned`, records its SHA-256, and marks the evidence `publishable: false`.

This is intentional. A CI-only unsigned candidate proves installer construction and install/uninstall mechanics; it is not a public production release.

Production release readiness still requires:

1. an organization-controlled Windows code-signing certificate/private key that is never committed to this repository;
2. signing in a protected release environment;
3. Authenticode verification after signing;
4. the M14 signed-artifact release gate;
5. required security/legal release signoff.

No CI test key is allowed to be presented as a production signing key.

## Production-signed release verification (fail-closed)

Run `scripts/windows_release_signing_gate.ps1` **only after** signing in a
protected Windows release environment. The command verifies Windows
Authenticode signature/certificate-chain status, the **exact expected leaf
publisher certificate thumbprint** (40 hex characters), and the **exact
SHA-256 release-artifact digest** (64 hex characters). Neither pin comes from
the downloaded artifact: supply both from protected, reviewed release metadata.

```powershell
pwsh -NoProfile -File scripts/windows_release_signing_gate.ps1 `
  -InstallerPath 'C:\release\KMJ-OmniDesk-setup.exe' `
  -ExpectedSha256 '<64-hex-sha256-from-protected-release-record>' `
  -ExpectedSignerThumbprint '<40-hex-thumbprint-of-KMJ-publisher-certificate>'
```

**Unsigned CI builds are always refused.** The Windows CI now runs a negative
test proving that even an otherwise digest-correct unsigned installer cannot
pass the production signature verification boundary. CI continues to install
and uninstall the unsigned candidate solely for engineering QA.

A `AUTHENTICODE_VERIFIED` result is **not** release approval. Independent
Main Platform licensing with production signer, real-network connectivity,
security review, update rollback, support, legal/codec signoff, and M14
commercial authorization remain mandatory. Never store signing private
keys/certificates or customer secrets in this repository.
