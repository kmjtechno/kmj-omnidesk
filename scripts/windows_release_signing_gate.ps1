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

try {
    $artifact = Get-Item -LiteralPath $InstallerPath -ErrorAction Stop
    if ($artifact.PSIsContainer -or $artifact.Length -le 0) {
        throw 'Installer must be a non-empty regular file'
    }
    if (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installer cannot be a reparse point or symbolic link'
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
    if ($actualDigest -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Installer SHA-256 differs from the pinned release manifest digest'
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
