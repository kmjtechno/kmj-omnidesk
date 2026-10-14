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
