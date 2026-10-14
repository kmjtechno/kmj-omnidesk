param(
    [Parameter(Mandatory=$true)][string]$ReferencePath,
    [Parameter(Mandatory=$true)][string]$CandidatePath,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$report = [ordered]@{
    evidence_type = 'locked_reference_visual_comparison'
    approved_reference_hash_verified_by_runner = $true
    same_dimensions = $false
    compared_pixels = 0
    mismatched_pixels = 0
    mismatch_ratio = $null
    mean_absolute_rgb_error = $null
    verdict = 'UNVERIFIED'
    live_remote_session_verified = $false
}
$expected = $null
$actual = $null
try {
    if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
        throw 'RENDERER_EVIDENCE_MISSING'
    }
    $expected = [System.Drawing.Bitmap]::new($ReferencePath)
    $actual = [System.Drawing.Bitmap]::new($CandidatePath)
    $width = $expected.Width; $height = $expected.Height
    $report.reference_dimensions = "${width}x${height}"
    $report.actual_dimensions = "$($actual.Width)x$($actual.Height)"
    if ($width -ne 1419 -or $height -ne 611) {
        throw 'LOCKED_REFERENCE_DIMENSIONS_INVALID'
    }
    if ($actual.Width -ne $width -or $actual.Height -ne $height) {
        $report.verdict = 'SIZE_MISMATCH'
        throw 'Candidate does not match 1419x611 design dimensions'
    }
    $report.same_dimensions = $true
    $region = [System.Drawing.Rectangle]::new(0, 0, $width, $height)
    $pixelFormat = [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    $a = $expected.LockBits($region, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, $pixelFormat)
    $b = $actual.LockBits($region, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, $pixelFormat)
    try {
        $bytes = $width * $height * 4
        $left = [byte[]]::new($bytes)
        $right = [byte[]]::new($bytes)
        [Runtime.InteropServices.Marshal]::Copy($a.Scan0, $left, 0, $bytes)
        [Runtime.InteropServices.Marshal]::Copy($b.Scan0, $right, 0, $bytes)
        [long]$diff = 0; [long]$errorSum = 0
        for ($i = 0; $i -lt $bytes; $i += 4) {
            $deltaB = [Math]::Abs([int]$left[$i] - [int]$right[$i])
            $deltaG = [Math]::Abs([int]$left[$i+1] - [int]$right[$i+1])
            $deltaR = [Math]::Abs([int]$left[$i+2] - [int]$right[$i+2])
            $errorSum += $deltaB + $deltaG + $deltaR
            if (($deltaB + $deltaG + $deltaR) -gt 24) { $diff++ }
        }
        $n = $width * $height
        $report.compared_pixels = $n
        $report.mismatched_pixels = $diff
        $report.mismatch_ratio = [Math]::Round(($diff / $n), 6)
        $report.mean_absolute_rgb_error = [Math]::Round(($errorSum / ($n * 3)), 3)
        # Pixel differences can reflect legitimate content (real devices,
        # disconnected state, encrypted frames); this can never sign off UX.
        $report.verdict = 'REVIEW_REQUIRED'
    } finally {
        $expected.UnlockBits($a)
        $actual.UnlockBits($b)
    }
} catch {
    $report.error = $_.Exception.Message
} finally {
    if ($null -ne $expected) { $expected.Dispose() }
    if ($null -ne $actual) { $actual.Dispose() }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
Write-Output ($report | ConvertTo-Json -Compress)
if ($report.verdict -ne 'REVIEW_REQUIRED') { exit 1 }
