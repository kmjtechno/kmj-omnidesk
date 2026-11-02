param(
    [string]$BinaryPath = "target/release/omnidesk-desktop.exe",
    [string]$OutputDir = "artifacts/live-foreground-p520"
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$worktreeRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$resolvedOutputDir = [System.IO.Path]::GetFullPath((Join-Path $worktreeRoot $OutputDir))

if (-not (Test-Path $resolvedOutputDir)) {
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

$resolvedBin = (Resolve-Path $BinaryPath).Path
$binHash = (Get-FileHash $resolvedBin -Algorithm SHA256).Hash

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
Write-Host "Window Handle acquired: $hwnd"

# Position window prominently and bring to foreground
# SW_RESTORE = 9, SW_SHOW = 5
[WinUserForegroundApi]::ShowWindow($hwnd, 9) | Out-Null
[WinUserForegroundApi]::MoveWindow($hwnd, 100, 100, 1296, 759, $true) | Out-Null
if (-not [WinUserForegroundApi]::SetForegroundWindow($hwnd)) {
    throw "Cannot bring the selected QA process to foreground; no foreground receipt will be issued."
}
Start-Sleep -Milliseconds 800
if ([WinUserForegroundApi]::GetForegroundWindow() -ne $hwnd) {
    throw "Foreground focus does not match the selected QA process."
}

$proc.Refresh()

# Capture live screenshot
# Per-invocation evidence path prevents overwriting existing owner receipts.
$runDir = Join-Path $resolvedOutputDir ("run-" + [Guid]::NewGuid().ToString("N"))
[System.IO.Directory]::CreateDirectory($runDir) | Out-Null
$screenshotPath = Join-Path $runDir "foreground-live.png"

$rect = [WinUserForegroundApi+RECT]::new()
[WinUserForegroundApi]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = [Math]::Max(10, $rect.Right - $rect.Left)
$h = [Math]::Max(10, $rect.Bottom - $rect.Top)

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
