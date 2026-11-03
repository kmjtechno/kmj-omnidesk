param(
    [string]$BinaryPath = "target/release/omnidesk-desktop.exe",
    [string]$OutputDir = "artifacts/live-foreground-p520"
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$worktreeRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
# Refuse output paths outside the project, including existing junctions/symlinks.
# The mouse QA collector enforces the same project-contained evidence policy.
$resolvedOutputDir = [System.IO.Path]::GetFullPath((Join-Path $worktreeRoot $OutputDir))
$rootPrefix = $worktreeRoot.TrimEnd([char]92, [char]47) + [System.IO.Path]::DirectorySeparatorChar
if (-not $resolvedOutputDir.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Foreground QA output must remain under the project root"
}
$walk = $resolvedOutputDir
while ($walk.Length -ge $worktreeRoot.Length) {
    if (Test-Path -LiteralPath $walk) {
        $item = Get-Item -LiteralPath $walk -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Foreground QA output directory traverses a symlink/junction"
        }
    }
    $walk = Split-Path -Parent $walk
}
if (-not (Test-Path -LiteralPath $resolvedOutputDir)) {
    [System.IO.Directory]::CreateDirectory($resolvedOutputDir) | Out-Null
}

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

if (-not ([System.Management.Automation.PSTypeName]'WinUserForegroundApi').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinUserForegroundApi {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
}

# Only execute a project-contained, non-redirected QA executable.
$resolvedBin = (Resolve-Path -LiteralPath (Join-Path $worktreeRoot $BinaryPath)).Path
if (-not $resolvedBin.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not $resolvedBin.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Foreground QA binary must be a project-contained .exe"
}
$walk = $resolvedBin
while ($walk.Length -ge $worktreeRoot.Length) {
    $item = Get-Item -LiteralPath $walk -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Foreground QA binary path traverses a symlink/junction"
    }
    $walk = Split-Path -Parent $walk
}
$binHash = (Get-FileHash -LiteralPath $resolvedBin -Algorithm SHA256).Hash

Write-Host "Target executable: $resolvedBin"
Write-Host "Executable SHA-256: $binHash"

# Never commandeer an existing owner session or use an unverified binary.
$existing = Get-Process -Name "omnidesk-desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    throw "Existing OmniDesk PID $($existing.Id) detected; refusing to reposition or capture an owner session."
}
Write-Host "Launching selected executable in user interactive session..."
$proc = Start-Process -FilePath $resolvedBin -PassThru

$deadline = (Get-Date).AddSeconds(15)
do {
    Start-Sleep -Milliseconds 400
    $proc.Refresh()
    if ($proc.HasExited) { throw "Process exited unexpectedly with code $($proc.ExitCode)" }
} while ($proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)

if ($proc.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "MainWindowHandle not acquired for process PID $($proc.Id)"
}

$hwnd = $proc.MainWindowHandle
# Re-attest the process executable after launch. The pre-launch file hash
# alone cannot bind a later process to the selected path if files are swapped.
# This remains file/process evidence, not a signed-build or image attestation.
$proc.Refresh()
$launchedPath = [System.IO.Path]::GetFullPath($proc.MainModule.FileName)
if (-not [string]::Equals($launchedPath, $resolvedBin, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Launched foreground process executable path differs from the selected binary"
}
$launchedHash = (Get-FileHash -LiteralPath $launchedPath -Algorithm SHA256).Hash
if ($launchedHash -ne $binHash) {
    throw "Foreground QA executable changed between pre-launch hash and process verification"
}
Write-Host "Process path and post-launch executable hash: PASS"
Write-Host "Window Handle acquired: $hwnd"

# Position window prominently and bring to foreground
# SW_RESTORE = 9, SW_SHOW = 5
[WinUserForegroundApi]::ShowWindow($hwnd, 9) | Out-Null
if (-not [WinUserForegroundApi]::MoveWindow($hwnd, 100, 100, 1296, 759, $true)) {
    throw "Cannot position selected foreground QA window; no layout receipt will be issued"
}
[WinUserForegroundApi]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 800
$fg = [WinUserForegroundApi]::GetForegroundWindow()
if ($fg -ne [IntPtr]::Zero -and $fg -ne $hwnd) {
    throw "Foreground focus belongs to another process ($fg)."
}

$proc.Refresh()

# Capture live screenshot
# Per-invocation evidence path prevents overwriting existing owner receipts.
$runDir = Join-Path $resolvedOutputDir ("run-" + [Guid]::NewGuid().ToString("N"))
[System.IO.Directory]::CreateDirectory($runDir) | Out-Null
$screenshotPath = Join-Path $runDir "foreground-live.png"

$rect = [WinUserForegroundApi+RECT]::new()
if (-not [WinUserForegroundApi]::GetWindowRect($hwnd, [ref]$rect)) {
    throw "GetWindowRect failed; refusing an unbounded screenshot"
}
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
if ($w -lt 10 -or $h -lt 10 -or $w -gt 8192 -or $h -gt 8192 -or
    ([long]$w * [long]$h) -gt 16000000) {
    throw "Foreground QA window dimensions outside bounded screenshot policy"
}

$bmp = [System.Drawing.Bitmap]::new($w, $h)
try {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $dc = $g.GetHdc()
        try {
            if (-not [WinUserForegroundApi]::PrintWindow($hwnd, $dc, 0)) {
                throw "PrintWindow failed; refusing to issue a screenshot receipt."
            }
        } finally {
            $g.ReleaseHdc($dc)
        }
    } finally {
        $g.Dispose()
    }
    $bmp.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $bmp.Dispose()
}

$screenshotHash = (Get-FileHash $screenshotPath -Algorithm SHA256).Hash

$result = [ordered]@{
    status = "FOREGROUND_CAPTURE_OBSERVED_NOT_FUNCTIONAL_PROOF"
    pid = $proc.Id
    start_time_iso = $proc.StartTime.ToString("o")
    binary_path = $resolvedBin
    binary_sha256 = $binHash
    main_window_handle = $hwnd.ToInt64()
    main_window_title = $proc.MainWindowTitle
    window_dimensions = "${w}x${h}"
    working_set_mb = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
    thread_count = $proc.Threads.Count
    screenshot_path = $screenshotPath
    screenshot_sha256 = $screenshotHash
    note = "Foreground window and PrintWindow observed for the selected binary; not proof of functional UI, real network, or hardware signoff. QA process left running."
}

$jsonPath = Join-Path $runDir "foreground-app-status.json"
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
Write-Output ($result | ConvertTo-Json -Depth 5)

Write-Host "Entering daemon persistent foreground wait loop. Process PID $($proc.Id) will remain active indefinitely."
Wait-Process -Id $proc.Id
