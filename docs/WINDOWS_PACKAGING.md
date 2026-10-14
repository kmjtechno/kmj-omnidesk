# Windows installer candidate

KMJ OmniDesk uses WiX Toolset 7 to build an MSI from the exact release-mode
`omnidesk-desktop.exe` produced by the same CI head.

The normal Windows CI gate builds the MSI, installs it silently on the ephemeral
runner, verifies the installed executable exists, uninstalls it silently, and
verifies the installed executable is removed.

## Security boundary

The CI MSI is an **unsigned release candidate**. It is not a production release
and must never be presented as signed or publishable.

Production release readiness still requires:

1. an organization-controlled Windows code-signing certificate/private key that
   is never committed to this repository;
2. signing in a protected release environment;
3. Authenticode verification after signing;
4. the M14 signed-artifact release gate;
5. human security/legal release signoff.

The unsigned CI build exists to verify installer construction and
install/update/uninstall mechanics without weakening the production signing
boundary.
