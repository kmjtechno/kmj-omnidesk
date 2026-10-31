# Negative-only Windows signing boundary tests. No certificate or signer is used.
# These checks never authorize release; they assert unsafe inputs fail closed.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) { throw 'M9 signing-path tests require Windows' }
$gate = Join-Path $PSScriptRoot 'windows_release_signing_gate.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ("omnidesk-m9-" + [guid]::NewGuid().ToString('N'))
$real = Join-Path $root 'real'
$link = Join-Path $root 'redirected'
New-Item -ItemType Directory -Path $real -Force | Out-Null
try {
    $installer = Join-Path $real 'unsigned-candidate.exe'
    [IO.File]::WriteAllBytes($installer, [byte[]](1, 2, 3, 4))
    $digest = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash

    function Invoke-Refusal([string]$Path, [string]$Expected, [string]$ExpectedDigest = '') {
        if ([string]::IsNullOrEmpty($ExpectedDigest)) { $ExpectedDigest = $digest }
        $messages = & pwsh -NoProfile -File $gate -InstallerPath $Path -ExpectedSha256 $ExpectedDigest -ExpectedSignerThumbprint ('0' * 40) 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) { throw "Unsafe/unsigned candidate unexpectedly passed: $Path" }
        if (-not $messages.Contains($Expected)) {
            throw "Expected refusal '$Expected' was absent for $Path; actual: $messages"
        }
    }

    # Baseline: the same regular file is unsigned, not an ancestor redirect.
    Invoke-Refusal $installer 'Authenticode not valid'

    # A mismatched manifest digest must be refused before Authenticode checks,
    # even when the candidate is a normal, readable file.
    Invoke-Refusal $installer 'Installer SHA-256 differs from the pinned release manifest digest' ('0' * 64)

    # Junction to a real directory: the final file itself is ordinary, so
    # a leaf-only ReparsePoint check would miss this redirection.
    New-Item -ItemType Junction -Path $link -Target $real | Out-Null
    Invoke-Refusal (Join-Path $link 'unsigned-candidate.exe') 'Redirected installer ancestor forbidden'

    # Refuse remote/namespace paths before Get-Item, Authenticode or hashing:
    # no UNC share access or drive-relative/current-directory interpretation.
    Invoke-Refusal 'unsigned-candidate.exe' 'Installer path must be an absolute local drive path'
    Invoke-Refusal 'C:unsigned-candidate.exe' 'Installer path must be an absolute local drive path'
    Invoke-Refusal '\\invalid-host\share\unsigned-candidate.exe' 'Installer path must be an absolute local drive path'
    Invoke-Refusal '\\?\C:\Windows\unsigned-candidate.exe' 'Installer path must be an absolute local drive path'

    # Windows path aliases must fail before any disk or network access.
    # In particular, ADS can name a stream rather than the pinned installer,
    # and trailing dots/spaces or DOS devices can resolve unexpectedly.
    Invoke-Refusal ($installer + ':payload') 'Installer path contains unsupported Windows path syntax'
    Invoke-Refusal ($installer + '.') 'Installer path contains unsupported Windows path syntax'
    Invoke-Refusal ($installer + ' ') 'Installer path contains unsupported Windows path syntax'
    Invoke-Refusal (Join-Path $real 'NUL.exe') 'Installer path contains unsupported Windows path syntax'
    # Windows reserves superscript 1/2/3 in COM/LPT names, even with extensions.
    # Reject these aliases lexically before any filesystem access.
    Invoke-Refusal (Join-Path $real 'COM¹.exe') 'Installer path contains unsupported Windows path syntax'
    Invoke-Refusal (Join-Path $real 'com².exe') 'Installer path contains unsupported Windows path syntax'
    Invoke-Refusal (Join-Path $real 'LPT³.exe') 'Installer path contains unsupported Windows path syntax'

    # A path with parent traversal must not be normalized into approval.
    Invoke-Refusal (Join-Path $real '..\real\unsigned-candidate.exe') 'Installer path cannot contain parent traversal'

    if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $digest) {
        throw 'M9 negative tests modified owner/candidate bytes'
    }
    Write-Output 'M9_SIGNING_ANCESTOR_REFUSALS=PASS'
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    $global:LASTEXITCODE = 0
}
