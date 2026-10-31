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

    function Invoke-Refusal([string]$Path, [string]$Expected) {
        $messages = & pwsh -NoProfile -File $gate -InstallerPath $Path -ExpectedSha256 $digest -ExpectedSignerThumbprint ('0' * 40) 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) { throw "Unsafe/unsigned candidate unexpectedly passed: $Path" }
        if (-not $messages.Contains($Expected)) {
            throw "Expected refusal '$Expected' was absent for $Path; actual: $messages"
        }
    }

    # Baseline: the same regular file is unsigned, not an ancestor redirect.
    Invoke-Refusal $installer 'Authenticode not valid'

    # Junction to a real directory: the final file itself is ordinary, so
    # a leaf-only ReparsePoint check would miss this redirection.
    New-Item -ItemType Junction -Path $link -Target $real | Out-Null
    Invoke-Refusal (Join-Path $link 'unsigned-candidate.exe') 'Redirected installer ancestor forbidden'

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
