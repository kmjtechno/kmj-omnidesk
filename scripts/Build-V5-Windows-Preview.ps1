# KMJ OmniDesk V5 - guarded, zero-cost Windows preview build.
# This script deliberately never updates or stops the installed production app.
# Run in an interactive Windows account with Git and Rust toolchain installed.
[CmdletBinding()]
param(
    [switch]$Launch,
    [ValidatePattern('^[a-fA-F0-9]{40}$')]
    [Parameter(Mandatory = $true)]
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
    if ($sha -ne $ExpectedSha.ToLowerInvariant()) {
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
    # Preserve previous test evidence: every run gets an exclusive folder.
    $previewDir = Join-Path $base (
        "preview-" + $sha.Substring(0,12) + "-" + $stamp + "-" +
        ([guid]::NewGuid().ToString('N').Substring(0,8))
    )
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
    if ($pngFiles.Count -ne 12) {
        throw "Native renderer expected exactly 12 PNG files, found $($pngFiles.Count)"
    }
    # Pin the locked design's actual capture matrix, not merely a PNG count.
    # PNG IHDR stores width and height as unsigned big-endian 32-bit values.
    $expectedPng = @{
        '01_remote_access_small.png' = @(800, 600)
        '02_remote_access_iconrail.png' = @(960, 640)
        '04_remote_access_1024.png' = @(1024, 768)
        '03_remote_access_compact.png' = @(1419, 611)
        '10_remote_access_laptop.png' = @(1280, 800)
        '11_remote_access_wide.png' = @(1920, 1080)
        '06_trusted_devices.png' = @(1419, 800)
        '07_sessions.png' = @(1419, 800)
        '08_file_transfer.png' = @(1419, 800)
        '09_security_center.png' = @(1419, 800)
        '10_preferences.png' = @(1419, 800)
        '11_trusted_compact.png' = @(960, 640)
    }
    $pngReceipts = @()
    foreach ($image in ($pngFiles | Sort-Object Name)) {
        if (-not $expectedPng.ContainsKey($image.Name)) {
            throw "Unexpected native renderer PNG: $($image.Name)"
        }
        if ($image.Length -le 100) {
            throw "Empty or corrupt PNG capture: $($image.Name)"
        }
        $fileBytes = [System.IO.File]::ReadAllBytes($image.FullName)
        if ($fileBytes.Length -lt 24 -or
            [System.BitConverter]::ToString($fileBytes, 0, 8) -ne '89-50-4E-47-0D-0A-1A-0A') {
            throw "Invalid PNG signature: $($image.Name)"
        }
        if ([System.Text.Encoding]::ASCII.GetString($fileBytes, 12, 4) -ne 'IHDR') {
            throw "Missing PNG IHDR: $($image.Name)"
        }
        [array]::Reverse($fileBytes, 16, 4)
        [array]::Reverse($fileBytes, 20, 4)
        $actualWidth = [System.BitConverter]::ToUInt32($fileBytes, 16)
        $actualHeight = [System.BitConverter]::ToUInt32($fileBytes, 20)
        $expectedSize = $expectedPng[$image.Name]
        if ($actualWidth -ne $expectedSize[0] -or $actualHeight -ne $expectedSize[1]) {
            throw "Wrong PNG dimensions: $($image.Name) got ${actualWidth}x${actualHeight} expected $($expectedSize[0])x$($expectedSize[1])"
        }
        $pngReceipts += "PNG_DIMENSIONS=$($image.Name) ${actualWidth}x${actualHeight}"
        $pngSha = (Get-FileHash -LiteralPath $image.FullName -Algorithm SHA256).Hash
        $pngReceipts += ("PNG_SHA256=" + $pngSha + "  " + $image.Name)
    }

    # Owner-reviewable gallery of real, offline Rust-rendered V5 screens.
    # This is not a screenshot from a running Windows exe or connected peer.
    $galleryCards = @($pngFiles | Sort-Object Name | ForEach-Object {
        $safe = [System.Net.WebUtility]::HtmlEncode($_.Name)
        '<figure><img src="native-render-png/' + $safe + '" alt="' +
        $safe + '" loading="lazy"><figcaption>' + $safe + '</figcaption></figure>'
    })
    $galleryHeader = @'
<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KMJ OmniDesk V5 — Native Rust Renderer Review</title>
<style>
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif}
body{margin:0;background:#071019;color:#edf1f8;padding:24px}
h1{margin:0 0 8px}.note{color:#9dacbd;max-width:950px;line-height:1.5}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,480px),1fr));gap:18px}
figure{margin:0;border:1px solid #24323f;background:#101921;border-radius:12px;padding:8px;overflow:hidden}
img{display:block;width:100%;height:auto}
figcaption{font-size:13px;color:#b8c2cf;padding:10px}
</style>
<h1>KMJ OmniDesk · Native V5 render review</h1>
<p class="note">Generated from real Rust renderer pixel buffers at the commit in
receipt.txt. These images are <strong>not</strong> Windows desktop captures,
working remote sessions, or production acceptance evidence.</p>
<main>
'@
    $galleryFooter = @'
</main>
</html>
'@
    $galleryHtml = $galleryHeader + ($galleryCards -join "`n") + $galleryFooter
    Set-Content -LiteralPath (Join-Path $previewDir 'index.html') -Value $galleryHtml -Encoding UTF8
    $nativeReceiptPath = Join-Path $captureDir 'RECEIPT.txt'
    if (-not (Test-Path -LiteralPath $nativeReceiptPath -PathType Leaf)) {
        throw 'Native renderer receipt missing'
    }
    # Cross-check the renderer's own truth boundary. A PNG count alone must
    # never certify a Windows screenshot or a real remote-control session.
    $nativeReceiptLines = @(Get-Content -LiteralPath $nativeReceiptPath)
    $requiredNativeReceipt = @(
        'KMJ_OMNIDESK_V5_CAPTURE_TYPE=OFFLINE_NATIVE_RENDER_BUFFER_PNG',
        'SCREEN_COUNT=12',
        'VERIFIED_NETWORK_SESSION=NO',
        'CONNECTED_DESKTOP_CAPTURE=NO',
        'WINDOWS_EXE_SCREENSHOT=NO'
    )
    foreach ($requiredLine in $requiredNativeReceipt) {
        if (@($nativeReceiptLines | Where-Object { $_ -ceq $requiredLine }).Count -ne 1) {
            throw "Native renderer receipt missing or duplicated: $requiredLine"
        }
    }
    # Cargo's --locked mode protects dependency resolution, but a tool or build
    # script could still mutate tracked source. Re-attest the exact tree before
    # publishing a PASS receipt; never silently certify a changed checkout.
    $postBuildSha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $postBuildSha -cne $sha) {
        throw "Source HEAD changed during QA: expected $sha got $postBuildSha"
    }
    & git diff --quiet --exit-code
    if ($LASTEXITCODE -ne 0) {
        throw 'Tracked source changed during V5 QA; refusing PASS receipt'
    }
    & git diff --cached --quiet --exit-code
    if ($LASTEXITCODE -ne 0) {
        throw 'Staged source changed during V5 QA; refusing PASS receipt'
    }
    Write-Host 'KMJ_V5_POST_BUILD_SOURCE_ATTEST=PASS'
    Write-Host 'KMJ_V5_NATIVE_RENDER_PNG=PASS_COUNT_12'
    $receipt = @(
        "SOURCE_SHA=$sha",
        "BINARY_SHA256=$digest",
        "FMT=PASS",
        "CLIPPY=PASS",
        "TESTS=PASS",
        "BUILD=PASS",
        "NATIVE_RENDER_PNG_COUNT=12",
        "NATIVE_RENDER_TYPE=OFFLINE_RUST_PIXEL_BUFFER",
        "PHYSICAL_WINDOWS_SCREENSHOT=NOT_VERIFIED",
        "RELEASE=NOT_APPROVED",
        "ENCRYPTED_PEER_REMOTE_CONTROL=BLOCKED_UNTIL_REVIEW",
        "INSTALLED_PRODUCTION_APP_MODIFIED=NO",
        "PREVIEW_PATH=$copy",
        "NATIVE_RENDER_PNG_DIR=$captureDir"
    )
    # Explicit physical Windows acceptance matrix. Offline renderer PNGs never
    # satisfy these gates; a human must inspect the actual preview window.
    # Keep the status fail-closed even when the -Launch switch is used.
    $physicalViewports = @('800x600','960x640','1024x768','1419x611','1920x1080')
    foreach ($viewport in $physicalViewports) {
        $receipt += "WINDOWS_NATIVE_SCREENSHOT_$viewport=NOT_VERIFIED"
        $receipt += "WINDOWS_NATIVE_KEYBOARD_HITTEST_$viewport=NOT_VERIFIED"
        $receipt += "WINDOWS_NATIVE_CONTRAST_$viewport=NOT_VERIFIED"
    }
    $receipt += 'WINDOWS_NATIVE_ACCESSIBILITY_SCREENREADER=NOT_VERIFIED'
    $receipt += 'WINDOWS_NATIVE_DPI_SCALING=NOT_VERIFIED'
    $receipt += 'V5_LOCKED_DESIGN_PARITY=NOT_ACCEPTED'
    $receipt += $pngReceipts
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
