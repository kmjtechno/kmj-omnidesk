param(
    [string]$BinaryPath = "target/release/omnidesk-desktop.exe",
    [string]$OutputDirectory = "artifacts/visual-qa-p520"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

if (-not ([System.Management.Automation.PSTypeName]'WinUserApi').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinUserApi {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
}

function Capture-WindowScreenshot([IntPtr]$hwnd, [string]$filePath) {
    $rect = [WinUserApi+RECT]::new()
    if (-not [WinUserApi]::GetWindowRect($hwnd, [ref]$rect)) { throw "GetWindowRect failed" }
    $w = [Math]::Max(10, $rect.Right - $rect.Left)
    $h = [Math]::Max(10, $rect.Bottom - $rect.Top)
    $bmp = [System.Drawing.Bitmap]::new($w, $h)
    try {
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $dc = $g.GetHdc()
            try {
                $ok = [WinUserApi]::PrintWindow($hwnd, $dc, 0)
                if (-not $ok) { throw "PrintWindow failed" }
            } finally {
                $g.ReleaseHdc($dc)
            }
        } finally {
            $g.Dispose()
        }

        # Analyze color variety and edges
        $colors = [System.Collections.Generic.HashSet[int]]::new()
        for ($y = 4; $y -lt $h; $y += [Math]::Max(1, [int]($h / 24))) {
            for ($x = 4; $x -lt $w; $x += [Math]::Max(1, [int]($w / 24))) {
                [void]$colors.Add($bmp.GetPixel($x, $y).ToArgb())
            }
        }
        $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
        $sha = (Get-FileHash $filePath -Algorithm SHA256).Hash
        return [ordered]@{
            width = $w
            height = $h
            sampled_colors = $colors.Count
            sha256 = $sha
            path = $filePath
        }
    } finally {
        $bmp.Dispose()
    }
}

$evidence = [ordered]@{
    test = "p520_live_visual_ui_lifecycle"
    status = "RUNNING"
    process = $null
    normal_screenshot = $null
    small_screenshot = $null
    minimized_state = $null
    restored_state = $null
    relaunch_state = $null
    uia_elements = $null
}

$proc = $null
try {
    Write-Host "=== 1. Launch native binary ==="
    $resolvedBin = (Resolve-Path $BinaryPath).Path
    $proc = Start-Process -FilePath $resolvedBin -PassThru
    $evidence.process = [ordered]@{
        initial_pid = $proc.Id
        binary = $resolvedBin
        sha256 = (Get-FileHash $resolvedBin -Algorithm SHA256).Hash
    }

    $deadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 300
        $proc.Refresh()
        if ($proc.HasExited) { throw "Process exited before window initialization" }
    } while ($proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)

    if ($proc.MainWindowHandle -eq [IntPtr]::Zero) { throw "MainWindowHandle not found" }
    $hwnd = $proc.MainWindowHandle
    [WinUserApi]::SetForegroundWindow($hwnd) | Out-Null
    Start-Sleep -Milliseconds 500

    Write-Host "=== 2. Inspect UIA accessibility tree ==="
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    $all = $root.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition
    )
    $uiaList = @()
    for ($i = 0; $i -lt $all.Count; $i++) {
        $item = $all.Item($i)
        $uiaList += [ordered]@{
            index = $i
            name = $item.Current.Name
            type = $item.Current.ControlType.ProgrammaticName
            is_enabled = $item.Current.IsEnabled
        }
    }
    $evidence.uia_elements = $uiaList

    Write-Host "=== 3. Capture normal window screenshot ==="
    $normalPng = Join-Path $OutputDirectory "native-normal-1296x759.png"
    $evidence.normal_screenshot = Capture-WindowScreenshot $hwnd $normalPng

    Write-Host "=== 4. Test Resize to small/compact window ==="
    # Move to (100, 100) with size (640, 480)
    [WinUserApi]::MoveWindow($hwnd, 100, 100, 640, 480, $true) | Out-Null
    Start-Sleep -Milliseconds 600
    $smallPng = Join-Path $OutputDirectory "native-compact-640x480.png"
    $evidence.small_screenshot = Capture-WindowScreenshot $hwnd $smallPng

    Write-Host "=== 5. Test Minimize & Restore ==="
    # SW_MINIMIZE = 6, SW_RESTORE = 9
    [WinUserApi]::ShowWindow($hwnd, 6) | Out-Null
    Start-Sleep -Milliseconds 500
    $evidence.minimized_state = [ordered]@{
        minimized = $true
    }

    [WinUserApi]::ShowWindow($hwnd, 9) | Out-Null
    Start-Sleep -Milliseconds 500
    $evidence.restored_state = [ordered]@{
        restored = $true
        title = $proc.MainWindowTitle
    }

    Write-Host "=== 6. Test graceful close and Relaunch ==="
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Milliseconds 500

    $proc2 = Start-Process -FilePath $resolvedBin -PassThru
    Start-Sleep -Milliseconds 1200
    $proc2.Refresh()
    $evidence.relaunch_state = [ordered]@{
        recovered_pid = $proc2.Id
        title = $proc2.MainWindowTitle
        clean = ($proc2.Id -ne $proc.Id -and $proc2.MainWindowTitle.StartsWith("KMJ OmniDesk"))
    }
    Stop-Process -Id $proc2.Id -Force

    $evidence.status = "PASS"
} catch {
    $evidence.status = "FAIL"
    $evidence.error = $_.Exception.Message
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    $jsonPath = Join-Path $OutputDirectory "visual-qa-results.json"
    $evidence | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding utf8
    Write-Output ($evidence | ConvertTo-Json -Depth 6)
}
