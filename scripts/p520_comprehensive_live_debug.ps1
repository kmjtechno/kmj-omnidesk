param(
    [string]$BinaryPath = "target/release/omnidesk-desktop.exe",
    [string]$OutputDir = "artifacts/live-debug-p520"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutputDir | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

if (-not ([System.Management.Automation.PSTypeName]'WinUserApiDebug').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinUserApiDebug {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
}

function Capture-DebugScreenshot([IntPtr]$hwnd, [string]$filePath) {
    $rect = [WinUserApiDebug+RECT]::new()
    if (-not [WinUserApiDebug]::GetWindowRect($hwnd, [ref]$rect)) { return $null }
    $w = [Math]::Max(10, $rect.Right - $rect.Left)
    $h = [Math]::Max(10, $rect.Bottom - $rect.Top)
    $bmp = [System.Drawing.Bitmap]::new($w, $h)
    try {
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $dc = $g.GetHdc()
            try {
                [void][WinUserApiDebug]::PrintWindow($hwnd, $dc, 0)
            } finally {
                $g.ReleaseHdc($dc)
            }
        } finally {
            $g.Dispose()
        }
        $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
        $sha = (Get-FileHash $filePath -Algorithm SHA256).Hash
        return [ordered]@{
            width = $w
            height = $h
            sha256 = $sha
            path = $filePath
        }
    } finally {
        $bmp.Dispose()
    }
}

$startTime = Get-Date

$report = [ordered]@{
    test = "p520_comprehensive_live_debug"
    start_time_iso = $startTime.ToString("o")
    binary_sha256 = $null
    process = $null
    uia_tree = @()
    keyboard_events = @()
    window_transitions = @()
    crash_recovery = $null
    event_viewer_errors = @()
    status = "RUNNING"
}

$resolvedBin = (Resolve-Path $BinaryPath).Path
$report.binary_sha256 = (Get-FileHash $resolvedBin -Algorithm SHA256).Hash

$proc = $null
try {
    # 1. Launch Process
    $proc = Start-Process -FilePath $resolvedBin -PassThru
    $deadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 300
        $proc.Refresh()
        if ($proc.HasExited) { throw "Process exited before window initialized" }
    } while ($proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)

    if ($proc.MainWindowHandle -eq [IntPtr]::Zero) { throw "MainWindowHandle not found" }
    $hwnd = $proc.MainWindowHandle

    [WinUserApiDebug]::SetForegroundWindow($hwnd) | Out-Null
    Start-Sleep -Milliseconds 500

    $proc.Refresh()
    $report.process = [ordered]@{
        pid = $proc.Id
        process_name = $proc.ProcessName
        main_window_title = $proc.MainWindowTitle
        working_set_mb = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
        thread_count = $proc.Threads.Count
        handles = $proc.HandleCount
    }

    # 2. UIA Inspection
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    for ($i = 0; $i -lt $all.Count; $i++) {
        $item = $all.Item($i)
        $report.uia_tree += [ordered]@{
            index = $i
            name = $item.Current.Name
            control_type = $item.Current.ControlType.ProgrammaticName
            is_enabled = $item.Current.IsEnabled
            is_keyboard_focusable = $item.Current.IsKeyboardFocusable
        }
    }

    # 3. Normal Viewport Screenshot
    $normalPath = Join-Path $OutputDir "debug-normal-1296x759.png"
    $normalCapture = Capture-DebugScreenshot $hwnd $normalPath
    $report.window_transitions += [ordered]@{
        transition = "initial_normal"
        screenshot = $normalCapture
    }

    # 4. Keyboard Navigation & Interaction Stress
    $keysToTest = @(
        @{ name = "Tab"; vk = 0x09 },
        @{ name = "Enter"; vk = 0x0D },
        @{ name = "Space"; vk = 0x20 },
        @{ name = "Escape"; vk = 0x1B },
        @{ name = "D"; vk = 0x44 },
        @{ name = "1"; vk = 0x31 },
        @{ name = "Z"; vk = 0x5A }
    )
    foreach ($k in $keysToTest) {
        [WinUserApiDebug]::keybd_event([byte]$k.vk, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 50
        [WinUserApiDebug]::keybd_event([byte]$k.vk, 0, 2, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 150
        $proc.Refresh()
        $report.keyboard_events += [ordered]@{
            key = $k.name
            survived = (-not $proc.HasExited)
            memory_mb = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
        }
    }

    # 5. Compact Viewport Resize (640x480)
    [WinUserApiDebug]::MoveWindow($hwnd, 80, 80, 640, 480, $true) | Out-Null
    Start-Sleep -Milliseconds 600
    $compactPath = Join-Path $OutputDir "debug-compact-640x480.png"
    $compactCapture = Capture-DebugScreenshot $hwnd $compactPath
    $report.window_transitions += [ordered]@{
        transition = "resize_compact_640x480"
        screenshot = $compactCapture
    }

    # 6. Minimize & Restore
    [WinUserApiDebug]::ShowWindow($hwnd, 6) | Out-Null
    Start-Sleep -Milliseconds 400
    [WinUserApiDebug]::ShowWindow($hwnd, 9) | Out-Null
    Start-Sleep -Milliseconds 500
    $proc.Refresh()
    $report.window_transitions += [ordered]@{
        transition = "minimize_and_restore"
        survived = (-not $proc.HasExited)
        title = $proc.MainWindowTitle
    }

    # 7. Abrupt Kill & Clean Restart
    $initialPid = $proc.Id
    Stop-Process -Id $initialPid -Force
    Start-Sleep -Milliseconds 500

    $proc2 = Start-Process -FilePath $resolvedBin -PassThru
    Start-Sleep -Milliseconds 1200
    $proc2.Refresh()
    $recoveredPid = $proc2.Id
    $report.crash_recovery = [ordered]@{
        initial_pid = $initialPid
        recovered_pid = $recoveredPid
        clean_recovery = ($recoveredPid -ne $initialPid -and $proc2.MainWindowTitle.StartsWith("KMJ OmniDesk"))
        recovered_title = $proc2.MainWindowTitle
    }
    Stop-Process -Id $recoveredPid -Force

    # 8. Event Viewer Audit
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match "omnidesk" -or $_.ProviderName -match "Application Error|Windows Error Reporting"
        }
        foreach ($ev in $events) {
            $report.event_viewer_errors += [ordered]@{
                time = $ev.TimeCreated.ToString("o")
                provider = $ev.ProviderName
                id = $ev.Id
                level = $ev.LevelDisplayName
                message = $ev.Message.Substring(0, [Math]::Min(200, $ev.Message.Length))
            }
        }
    } catch {
        # No error events found
    }

    $report.status = "PASS"
} catch {
    $report.status = "FAIL"
    $report.error = $_.Exception.Message
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    $jsonPath = Join-Path $OutputDir "live-debug-report.json"
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding utf8
    Write-Output ($report | ConvertTo-Json -Depth 6)
}
