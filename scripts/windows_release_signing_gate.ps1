# KMJ OmniDesk production Windows Authenticode verification boundary.
# This is verification only: it never signs, publishes, grants entitlements,
# or overrides the separate M4/M9/M11/M13/M14 commercial release gates.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallerPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedSignerThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Path-based checks cannot replace a protected signer or handle-bound
# verification. They do prevent an operator-supplied junction/symlink parent
# from silently redirecting an otherwise ordinary installer file.
function Assert-NoRedirectedInstallerAncestors([string]$Path) {
    # Do not touch network shares, device namespaces, drive-relative paths or
    # a caller-dependent working directory. Check lexically before any IO.
    if ($Path -cnotmatch '^[A-Za-z]:[\\/]') {
        throw 'Installer path must be an absolute local drive path'
    }
    if (($Path -split '[\\/]') -contains '..') {
        throw 'Installer path cannot contain parent traversal'
    }
    # Windows accepts several lexical aliases for a path (alternate data
    # streams, trailing dots/spaces, and reserved DOS device basenames).
    # Reject them before GetFullPath, Get-Item, hashing, or Authenticode so
    # the manifest names one unambiguous local installer file.
    foreach ($component in ($Path.Substring(3) -split '[\\/]')) {
        if ($component -match ':' -or $component -match '[. ]    $absolute = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($absolute)
    while (-not [string]::IsNullOrEmpty($parent)) {
        $directory = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer) {
            throw "Installer ancestor is not a directory: $parent"
        }
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Redirected installer ancestor forbidden: $parent"
        }
        $next = [IO.Path]::GetDirectoryName($parent.TrimEnd([char]'\', [char]'/'))
        if ([string]::IsNullOrEmpty($next) -or $next -eq $parent) { break }
        $parent = $next
    }
}

try {
    Assert-NoRedirectedInstallerAncestors $InstallerPath
    $artifact = Get-Item -LiteralPath $InstallerPath -ErrorAction Stop
    if ($artifact.PSIsContainer -or $artifact.Length -le 0) {
        throw 'Installer must be a non-empty regular file'
    }
    if (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer cannot be a reparse point or symbolic link'
    }

    # Check the pinned artifact digest before processing its signature, then
    # hash again after Authenticode verification. This catches persistent
    # replacement during verification but is NOT a race-free handle binding.
    $beforeSignatureDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeSignatureDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 differs from the pinned release manifest digest'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
    if ($signature.Status.ToString() -cne 'Valid') {
        throw "Authenticode not valid: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw 'Authenticode contains no signer certificate'
    }

    # The thumbprint is a certificate *identity pin*, not a substitute for
    # Windows Authenticode signature and certificate-chain verification.
    $signerPin = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
    if ($signerPin -cne $ExpectedSignerThumbprint.ToLowerInvariant()) {
        throw 'Signed by a certificate other than the protected expected publisher'
    }

    $actualDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDigest -cne $beforeSignatureDigest -or
        $actualDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 changed during signature verification or differs from pinned digest'
    }

    [ordered]@{
        verification = 'AUTHENTICODE_VERIFIED'
        installer_sha256 = $actualDigest
        publisher_certificate_thumbprint = $signerPin
        certificate_subject = $signature.SignerCertificate.Subject
        commercial_release_authorized = $false
        note = 'Cryptographic artifact verification is necessary but M14 release approval remains separate'
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    [Console]::Error.WriteLine("OMNIDESK_SIGNED_RELEASE_REFUSED: $($_.Exception.Message)")
    exit 1
}
 -or
            $component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?    $absolute = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($absolute)
    while (-not [string]::IsNullOrEmpty($parent)) {
        $directory = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer) {
            throw "Installer ancestor is not a directory: $parent"
        }
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Redirected installer ancestor forbidden: $parent"
        }
        $next = [IO.Path]::GetDirectoryName($parent.TrimEnd([char]'\', [char]'/'))
        if ([string]::IsNullOrEmpty($next) -or $next -eq $parent) { break }
        $parent = $next
    }
}

try {
    Assert-NoRedirectedInstallerAncestors $InstallerPath
    $artifact = Get-Item -LiteralPath $InstallerPath -ErrorAction Stop
    if ($artifact.PSIsContainer -or $artifact.Length -le 0) {
        throw 'Installer must be a non-empty regular file'
    }
    if (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer cannot be a reparse point or symbolic link'
    }

    # Check the pinned artifact digest before processing its signature, then
    # hash again after Authenticode verification. This catches persistent
    # replacement during verification but is NOT a race-free handle binding.
    $beforeSignatureDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeSignatureDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 differs from the pinned release manifest digest'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
    if ($signature.Status.ToString() -cne 'Valid') {
        throw "Authenticode not valid: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw 'Authenticode contains no signer certificate'
    }

    # The thumbprint is a certificate *identity pin*, not a substitute for
    # Windows Authenticode signature and certificate-chain verification.
    $signerPin = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
    if ($signerPin -cne $ExpectedSignerThumbprint.ToLowerInvariant()) {
        throw 'Signed by a certificate other than the protected expected publisher'
    }

    $actualDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDigest -cne $beforeSignatureDigest -or
        $actualDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 changed during signature verification or differs from pinned digest'
    }

    [ordered]@{
        verification = 'AUTHENTICODE_VERIFIED'
        installer_sha256 = $actualDigest
        publisher_certificate_thumbprint = $signerPin
        certificate_subject = $signature.SignerCertificate.Subject
        commercial_release_authorized = $false
        note = 'Cryptographic artifact verification is necessary but M14 release approval remains separate'
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    [Console]::Error.WriteLine("OMNIDESK_SIGNED_RELEASE_REFUSED: $($_.Exception.Message)")
    exit 1
}
) {
            throw 'Installer path contains unsupported Windows path syntax'
        }
    }
    $absolute = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($absolute)
    while (-not [string]::IsNullOrEmpty($parent)) {
        $directory = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer) {
            throw "Installer ancestor is not a directory: $parent"
        }
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Redirected installer ancestor forbidden: $parent"
        }
        $next = [IO.Path]::GetDirectoryName($parent.TrimEnd([char]'\', [char]'/'))
        if ([string]::IsNullOrEmpty($next) -or $next -eq $parent) { break }
        $parent = $next
    }
}

try {
    Assert-NoRedirectedInstallerAncestors $InstallerPath
    $artifact = Get-Item -LiteralPath $InstallerPath -ErrorAction Stop
    if ($artifact.PSIsContainer -or $artifact.Length -le 0) {
        throw 'Installer must be a non-empty regular file'
    }
    if (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer cannot be a reparse point or symbolic link'
    }

    # Check the pinned artifact digest before processing its signature, then
    # hash again after Authenticode verification. This catches persistent
    # replacement during verification but is NOT a race-free handle binding.
    $beforeSignatureDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeSignatureDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 differs from the pinned release manifest digest'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
    if ($signature.Status.ToString() -cne 'Valid') {
        throw "Authenticode not valid: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw 'Authenticode contains no signer certificate'
    }

    # The thumbprint is a certificate *identity pin*, not a substitute for
    # Windows Authenticode signature and certificate-chain verification.
    $signerPin = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
    if ($signerPin -cne $ExpectedSignerThumbprint.ToLowerInvariant()) {
        throw 'Signed by a certificate other than the protected expected publisher'
    }

    $actualDigest = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDigest -cne $beforeSignatureDigest -or
        $actualDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 changed during signature verification or differs from pinned digest'
    }

    [ordered]@{
        verification = 'AUTHENTICODE_VERIFIED'
        installer_sha256 = $actualDigest
        publisher_certificate_thumbprint = $signerPin
        certificate_subject = $signature.SignerCertificate.Subject
        commercial_release_authorized = $false
        note = 'Cryptographic artifact verification is necessary but M14 release approval remains separate'
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    [Console]::Error.WriteLine("OMNIDESK_SIGNED_RELEASE_REFUSED: $($_.Exception.Message)")
    exit 1
}
