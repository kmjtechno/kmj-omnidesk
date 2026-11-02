param(
    [string]$BinaryPath = "target/release/omnidesk-desktop.exe",
    [string]$OutputDir = "artifacts/mouse-click-qa"
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$worktreeRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
# Each QA invocation gets a new evidence directory. Never overwrite a
# previous screenshot or owner-authored receipt in the checkout.
$baseOutputDir = [System.IO.Path]::GetFullPath((Join-Path $worktreeRoot $OutputDir))
$rootPrefix = $worktreeRoot.TrimEnd([char]92, [char]47) + [System.IO.Path]::DirectorySeparatorChar
if (-not $baseOutputDir.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "QA output must remain under the project root"
}
$walk = $baseOutputDir
while ($walk.Length -ge $worktreeRoot.Length -and $walk -ne $worktreeRoot) {
    if (Test-Path -LiteralPath $walk) {
        $item = Get-Item -LiteralPath $walk -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "QA output directory traverses a symlink/junction"
        }
    }
    $walk = Split-Path -Parent $walk
}
$resolvedOutputDir = Join-Path $baseOutputDir ("run-" + [Guid]::NewGuid().ToString("N"))
if (Test-Path -LiteralPath $resolvedOutputDir) { throw "QA run directory already exists" }
[System.IO.Directory]::CreateDirectory($resolvedOutputDir) | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

if (-not ([System.Management.Automation.PSTypeName]'WinUserClickApi').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinUserClickApi {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr hwnd, ref POINT pt);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);

    public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP   = 0x0004;

    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }

    public static void ClickAtClient(IntPtr hWnd, int clientX, int clientY) {
        RECT bounds;
        if (!GetClientRect(hWnd, out bounds) ||
            clientX < bounds.Left || clientX >= bounds.Right ||
            clientY < bounds.Top || clientY >= bounds.Bottom) {
            throw new InvalidOperationException("QA click target is outside the selected window client area");
        }
        if (GetForegroundWindow() != hWnd) {
            throw new InvalidOperationException("Selected QA window lost foreground before cursor movement");
        }
        POINT pt = new POINT { X = clientX, Y = clientY };
        if (!ClientToScreen(hWnd, ref pt)) throw new InvalidOperationException("ClientToScreen failed");

        // Deliver exactly one mouse down/up pair; duplicate PostMessage clicks
        // can toggle a control twice and invalidate the observation.
        if (!SetCursorPos(pt.X, pt.Y)) throw new InvalidOperationException("SetCursorPos failed");
        System.Threading.Thread.Sleep(80);
        // The user can change focus during the cursor-settle delay. Recheck
        // immediately before injection rather than clicking another application.
        if (GetForegroundWindow() != hWnd) {
            throw new InvalidOperationException("Selected QA window lost foreground before mouse down");
        }
        mouse_event(MOUSEEVENTF_LEFTDOWN, (uint)pt.X, (uint)pt.Y, 0, UIntPtr.Zero);
        try {
            System.Threading.Thread.Sleep(40);
        } finally {
            // Always release the button even if the delay throws.
            mouse_event(MOUSEEVENTF_LEFTUP, (uint)pt.X, (uint)pt.Y, 0, UIntPtr.Zero);
        }
    }
}
'@
}

function Capture-WindowScreenshot([IntPtr]$hwnd, [string]$outPath) {
    $rect = [WinUserClickApi+RECT]::new()
    if (-not [WinUserClickApi]::GetWindowRect($hwnd, [ref]$rect)) {
        throw "GetWindowRect failed; refusing to create screenshot evidence"
    }
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top
    if ($w -lt 10 -or $h -lt 10 -or $w -gt 8192 -or $h -gt 8192 -or
        ([long]$w * [long]$h) -gt 16000000) {
        throw "QA window dimensions outside bounded screenshot policy"
    }

    $bmp = [System.Drawing.Bitmap]::new($w, $h)
    try {
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $dc = $g.GetHdc()
            try {
                if (-not [WinUserClickApi]::PrintWindow($hwnd, $dc, 0)) {
                    throw "PrintWindow failed; refusing to treat a blank screenshot as QA evidence"
                }
            } finally {
                $g.ReleaseHdc($dc)
            }
        } finally {
            $g.Dispose()
        }
        $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bmp.Dispose()
    }
    return (Get-FileHash $outPath -Algorithm SHA256).Hash
}

# Reject arbitrary binaries and redirected paths before starting any process
# or injecting desktop input. Keep the QA binary inside this exact worktree.
$resolvedBin = (Resolve-Path -LiteralPath (Join-Path $worktreeRoot $BinaryPath)).Path
if (-not $resolvedBin.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not $resolvedBin.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Mouse QA binary must be a project-contained .exe"
}
$walk = $resolvedBin
while ($walk.Length -ge $worktreeRoot.Length) {
    $item = Get-Item -LiteralPath $walk -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Mouse QA binary path traverses a symlink/junction"
    }
    $walk = Split-Path -Parent $walk
}
$binHash = (Get-FileHash -LiteralPath $resolvedBin -Algorithm SHA256).Hash

Write-Host "Target: $resolvedBin"
Write-Host "Binary SHA256: $binHash"

# Never stop or replace a user-owned OmniDesk process. Launch a separate
# QA instance of the exact selected binary; leave existing sessions alone.
Write-Host "Launching separate OmniDesk QA process without stopping existing instances..."
$proc = Start-Process -FilePath $resolvedBin -PassThru

$deadline = (Get-Date).AddSeconds(15)
do {
    Start-Sleep -Milliseconds 400
    $proc.Refresh()
    if ($proc.HasExited) { throw "Process exited unexpectedly with code $($proc.ExitCode)" }
} while ($proc.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)

$hwnd = $proc.MainWindowHandle
if ($hwnd -eq [IntPtr]::Zero) { throw "No interactive main window acquired" }

# Re-attest the process launched from the selected file, rather than trusting
# a pre-launch pathname/hash that could have changed before Start-Process.
# This is a file/process identity check, not a signed-build or loaded-image proof.
$proc.Refresh()
$launchedPath = [System.IO.Path]::GetFullPath($proc.MainModule.FileName)
if (-not [string]::Equals($launchedPath, $resolvedBin, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Launched QA process executable path differs from the selected binary"
}
$launchedHash = (Get-FileHash -LiteralPath $launchedPath -Algorithm SHA256).Hash
if ($launchedHash -ne $binHash) {
    throw "QA executable changed between pre-launch hash and process verification"
}
Write-Host "Process path and post-launch executable hash: PASS"
Write-Host "Window handle: $hwnd"

# Position window at (100, 100), size (1296, 759)
$winX = 100
$winY = 100
$winW = 1296
$winH = 759
[WinUserClickApi]::ShowWindow($hwnd, 9) | Out-Null # SW_RESTORE
[WinUserClickApi]::MoveWindow($hwnd, $winX, $winY, $winW, $winH, $true) | Out-Null
if (-not [WinUserClickApi]::SetForegroundWindow($hwnd)) {
    throw "Cannot bring QA window to foreground; refusing to send clicks to another application"
}
Start-Sleep -Milliseconds 800
if ([WinUserClickApi]::GetForegroundWindow() -ne $hwnd) {
    throw "QA window is not foreground; refusing to move/click the mouse"
}

# Get exact client rect
$clientRect = [WinUserClickApi+RECT]::new()
if (-not [WinUserClickApi]::GetClientRect($hwnd, [ref]$clientRect)) {
    throw "GetClientRect failed; fixed click coordinates are unsafe"
}
$clientW = $clientRect.Right - $clientRect.Left
$clientH = $clientRect.Bottom - $clientRect.Top
if ($clientW -lt 800 -or $clientH -lt 500 -or
    $clientW -gt 8192 -or $clientH -gt 8192 -or
    ([long]$clientW * [long]$clientH) -gt 16000000) {
    throw "Unexpected client dimensions; fixed click coordinates are unsafe"
}
Write-Host "Client dimensions: ${clientW}x${clientH}"

# Capture initial screenshot
$initialPath = Join-Path $resolvedOutputDir "step0_initial_disconnected.png"
$initialHash = Capture-WindowScreenshot $hwnd $initialPath
Write-Host "Step 0 (Initial Disconnected): Hash=$initialHash"

$results = @()
$results += [PSCustomObject]@{
    step = 0
    target = "Initial State"
    action = "Launch & Position"
    client_x = $null
    client_y = $null
    screenshot_hash = $initialHash
}

# LockedDashboardLayout client coordinates for clientW x clientH:
# nav.x = 4, nav.y = 74, width = (clientW / 100 * 12).clamp(160, 198) = 153 -> 160.
# Navigation items:
# nav_tab_rect(i): x = 4 + 6 = 10, width = 148, height = 36.
# i=0 Devices: y = 74 + 9 + 0 = 83..119 -> mid 101
# i=1 Connections: y = 74 + 9 + 44 = 127..163 -> mid 145
# i=2 File Transfer: y = 74 + 9 + 88 = 171..207 -> mid 189
# i=5 Security: y = 74 + 9 + 220 = 303..339 -> mid 321
# i=6 Settings: y = 74 + 9 + 264 = 347..383 -> mid 365
# Nav tab center X: 10 + 74 = 84.

# Top Bar Buttons:
# Settings button: x = clientW - 194 = clientW - 194 .. clientW - 104, y = 20..50 -> mid X = clientW - 149, mid Y = 35
# Help button: x = clientW - 100 .. clientW - 20, y = 20..50 -> mid X = clientW - 60, mid Y = 35

# Devices Column Filters:
# devices.x = 4 + 160 + 6 = 170.
# All: x = 170 + 15 = 185..230, y = 74 + 70 = 144..166 -> mid X = 207, mid Y = 155
# Online: x = 170 + 68 = 238..303, y = 144..166 -> mid X = 270, mid Y = 155
# Offline: x = 170 + 140 = 310..380, y = 144..166 -> mid X = 345, mid Y = 155

$steps = @(
    @{ name = "Connections Tab"; cx = 84; cy = 145 },
    @{ name = "HELP Button"; cx = ($clientW - 60); cy = 35 },
    @{ name = "Settings Tab"; cx = 84; cy = 365 },
    @{ name = "Security Tab"; cx = 84; cy = 321 },
    @{ name = "Devices Tab"; cx = 84; cy = 101 },
    @{ name = "Online Filter"; cx = 270; cy = 155 },
    @{ name = "All Filter"; cx = 207; cy = 155 }
)

$prevHash = $initialHash
$stepIndex = 1

foreach ($s in $steps) {
    Write-Host "Executing actual mouse click on '$($s.name)' at client ($($s.cx), $($s.cy))..."
    if ([WinUserClickApi]::GetForegroundWindow() -ne $hwnd) {
        throw "Foreground focus changed during QA; refusing to click another window"
    }
    [WinUserClickApi]::ClickAtClient($hwnd, $s.cx, $s.cy)
    Start-Sleep -Milliseconds 600

    $outPath = Join-Path $resolvedOutputDir "step$($stepIndex)_$($s.name -replace '\s+','_').png"
    $newHash = Capture-WindowScreenshot $hwnd $outPath
    $changed = ($newHash -ne $prevHash)
    Write-Host "Step $stepIndex ($($s.name)): Hash=$newHash, ChangedFromPrev=$changed"

    $results += [PSCustomObject]@{
        step = $stepIndex
        target = $s.name
        action = "Actual Mouse Click"
        client_x = $s.cx
        client_y = $s.cy
        screenshot_hash = $newHash
        visual_state_changed = $changed
    }
    $prevHash = $newHash
    $stepIndex++
}

$allChanged = @($results | Where-Object { $_.step -gt 0 -and $_.visual_state_changed -ne $true }).Count -eq 0
$summary = [ordered]@{
    status = if ($allChanged) { "VISUAL_CHANGES_OBSERVED_FUNCTIONAL_QA_PENDING" } else { "FAIL_VISUAL_CHANGE_MISSING" }
    all_steps_changed = $allChanged
    process_id = $proc.Id
    window_handle = $hwnd.ToInt64()
    binary_sha256 = $binHash
    steps_tested = $results
    note = "Application remains open and responsive in foreground user session."
}

$jsonPath = Join-Path $resolvedOutputDir "mouse-click-results.json"
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
Write-Output ($summary | ConvertTo-Json -Depth 5)

if (-not $allChanged) {
    throw "One or more clicks did not produce a changed screenshot; see the QA report"
}
Write-Host "Visual changes observed; screenshots alone do not prove functional navigation. QA process PID $($proc.Id) left running; script exits."
