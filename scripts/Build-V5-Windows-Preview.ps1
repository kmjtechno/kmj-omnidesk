# KMJ OmniDesk V5 - guarded, zero-cost Windows preview build.
# This script deliberately never updates or stops the installed production app.
# Run in an interactive Windows account with Git and Rust toolchain installed.
[CmdletBinding()]
param(
    [switch]$Launch,
    [ValidatePattern('^[a-fA-F0-9]{40}$')]
    [string]$ExpectedSha
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'https://github.com/kmjtechno/kmj-omnidesk.git'
$branch = 'feat/omnidesk-v5-native-modernization-20261110'
$base = Join-Path $env:LOCALAPPDATA 'KMJ-OmniDesk-V5-Preview-QA'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$checkout = Join-Path $base ("source-" + $stamp + "-" + ([guid]::NewGuid().ToString('N').Substring(0,8)))
New-Item -ItemType Directory -Path $base -Force | Out-Null
if (Test-Path -LiteralPath $checkout) {
    throw "Refusing existing checkout: $checkout"
}
function Invoke-Checked([string]$Command, [string[]]$Parameters) {
    & $Command @Parameters
    if ($LASTEXITCODE -ne 0) {
        throw "$Command exited $LASTEXITCODE"
    }
}
foreach ($name in @('git','cargo','rustc')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: $name"
    }
}
# A fresh checkout avoids all user modifications in E:\KMJ\KMJ OmniDesk.
Invoke-Checked git @('clone','--single-branch','--branch',$branch,'--depth','1','--',$repository,$checkout)
Push-Location $checkout
try {
    $sha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sha -notmatch '^[0-9a-f]{40}$') {
        throw 'Cannot attest exact Git commit'
    }
    if ($ExpectedSha -and $sha -ne $ExpectedSha.ToLowerInvariant()) {
        throw "GitHub branch moved or checkout mismatch: expected $ExpectedSha got $sha"
    }
    Write-Host "KMJ_V5_EXACT_GITHUB_SHA=$sha"
    Invoke-Checked rustc @('--version')
    Invoke-Checked cargo @('--version')
    Invoke-Checked cargo @('fmt','--all','--','--check')
    Write-Host 'KMJ_V5_FMT=PASS'
    Invoke-Checked cargo @('clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings')
    Write-Host 'KMJ_V5_CLIPPY=PASS'
    Invoke-Checked cargo @('test','--locked','--workspace','--all-targets','--all-features')
    Write-Host 'KMJ_V5_TESTS=PASS'
    Invoke-Checked cargo @('build','--locked','--release','-p','omnidesk-desktop')
    Write-Host 'KMJ_V5_BUILD=PASS'

    $binary = Join-Path $checkout 'target\release\omnidesk-desktop.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "Built executable missing: $binary"
    }
    $previewDir = Join-Path $base ("preview-" + $sha.Substring(0,12))
    if (Test-Path -LiteralPath $previewDir) {
        throw "Preview output already exists: $previewDir"
    }
    New-Item -ItemType Directory -Path $previewDir | Out-Null
    $copy = Join-Path $previewDir 'omnidesk-desktop.exe'
    Copy-Item -LiteralPath $binary -Destination $copy -ErrorAction Stop
    $digest = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash

    # These are honest offline native Rust pixel-buffer captures, never
    # screenshots of a running Windows window or verified remote session.
    $captureDir = Join-Path $previewDir 'native-render-png'
    New-Item -ItemType Directory -Path $captureDir -ErrorAction Stop | Out-Null
    Invoke-Checked cargo @(
        'run','--locked','--release','-p','omnidesk-desktop',
        '--example','capture_v5_screens','--',$captureDir
    )
    $pngFiles = @(Get-ChildItem -LiteralPath $captureDir -Filter '*.png' -File)
    if ($pngFiles.Count -ne 11) {
        throw "Native renderer expected exactly 11 PNG files, found $($pngFiles.Count)"
    }
    foreach ($image in $pngFiles) {
        if ($image.Length -le 100) {
            throw "Empty or corrupt PNG capture: $($image.Name)"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $captureDir 'RECEIPT.txt') -PathType Leaf)) {
        throw 'Native renderer receipt missing'
    }
    Write-Host 'KMJ_V5_NATIVE_RENDER_PNG=PASS_COUNT_11'
    $receipt = @(
        "SOURCE_SHA=$sha",
        "BINARY_SHA256=$digest",
        "FMT=PASS",
        "CLIPPY=PASS",
        "TESTS=PASS",
        "BUILD=PASS",
        "NATIVE_RENDER_PNG_COUNT=11",
        "NATIVE_RENDER_TYPE=OFFLINE_RUST_PIXEL_BUFFER",
        "PHYSICAL_WINDOWS_SCREENSHOT=NOT_VERIFIED",
        "RELEASE=NOT_APPROVED",
        "ENCRYPTED_PEER_REMOTE_CONTROL=BLOCKED_UNTIL_REVIEW",
        "INSTALLED_PRODUCTION_APP_MODIFIED=NO",
        "PREVIEW_PATH=$copy",
        "NATIVE_RENDER_PNG_DIR=$captureDir"
    )
    Set-Content -LiteralPath (Join-Path $previewDir 'receipt.txt') -Value $receipt -Encoding UTF8
    $receipt | ForEach-Object { Write-Host $_ }
    if ($Launch) {
        Start-Process -FilePath $copy -WorkingDirectory $previewDir
        Write-Host 'KMJ_V5_PREVIEW_LAUNCHED=YES'
    } else {
        Write-Host 'KMJ_V5_PREVIEW_LAUNCHED=NO'
    }
}
finally {
    Pop-Location
}
