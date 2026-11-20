param(
    [string]$BinaryPath = "C:\Users\KMJ TECHNO\AppData\Local\Programs\KMJ OmniDesk\omnidesk-desktop.exe",
    [string]$ScreenshotDir = "C:\Users\KMJ TECHNO\.gemini\antigravity\brain\6ed02b16-26b1-4f9d-9b39-e3cbe2b17e88\live-run"
)

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 1
}

if (-not (Test-Path $ScreenshotDir)) {
    New-Item -ItemType Directory -Path $ScreenshotDir -Force | Out-Null
}

Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue

if (-not ([System.Management.Automation.PSTypeName]'WinUserLive').Type) {
Add-Type @'
using System;
using System.Runtime.InteropServices;

public class WinUserLive {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
}

# Check if an instance is already running
$existing = Get-Process -Name "omnidesk-desktop" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing instances..."
    $existing | Stop-Process -Force
    Start-Sleep -Seconds 1
}

Write-Host "Launching live OmniDesk application: $BinaryPath"
$proc = Start-Process -FilePath $BinaryPath -PassThru

$deadline = (Get-Date).AddSeconds(10)
do {
    Start-Sleep -Milliseconds 250
    $proc.Refresh()
    if ($proc.HasExited) {
        Write-Error "Process exited immediately with code: $($proc.ExitCode)"
        exit 1
    }
} while ($proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)

if ($proc.MainWindowHandle -eq [IntPtr]::Zero) {
    Write-Error "Timed out waiting for MainWindowHandle."
    exit 1
}

$hwnd = $proc.MainWindowHandle
Write-Host "Process running: PID=$($proc.Id), HWND=$hwnd"

# SW_SHOWNORMAL = 1, SW_RESTORE = 9
[WinUserLive]::ShowWindow($hwnd, 9) | Out-Null
[WinUserLive]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 500

# Capture screenshot of the live interactive window
$rect = [WinUserLive+RECT]::new()
if ([WinUserLive]::GetWindowRect($hwnd, [ref]$rect)) {
    $w = [Math]::Max(10, $rect.Right - $rect.Left)
    $h = [Math]::Max(10, $rect.Bottom - $rect.Top)
    $bmp = [System.Drawing.Bitmap]::new($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $dc = $g.GetHdc()
    try {
        [void][WinUserLive]::PrintWindow($hwnd, $dc, 0)
    } finally {
        $g.ReleaseHdc($dc)
        $g.Dispose()
    }
    $screenshotPath = Join-Path $ScreenshotDir "live_application_running.png"
    $bmp.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $hash = (Get-FileHash $screenshotPath -Algorithm SHA256).Hash
    Write-Host "Live window screenshot captured: $screenshotPath"
    Write-Host "Dimensions: ${w}x${h}, SHA-256: $hash"
}

$proc.Refresh()
Write-Host "SUCCESS: OmniDesk live application is running on user desktop!"
Write-Host "PID: $($proc.Id)"
Write-Host "Window Title: '$($proc.MainWindowTitle)'"
Write-Host "Working Set: $([Math]::Round($proc.WorkingSet64 / 1MB, 2)) MB"
Write-Host "Responding: $($proc.Responding)"
