param(
    [string]$ShortcutPath = "C:\Users\KMJ TECHNO\Desktop\KMJ OmniDesk.lnk",
    [string]$BinaryPath = "C:\Users\KMJ TECHNO\AppData\Local\Programs\KMJ OmniDesk\omnidesk-desktop.exe"
)

# Terminate any leftover instances
Get-Process -Name "omnidesk-desktop" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

$proc = $null
if (Test-Path $ShortcutPath) {
    Write-Host "Launching via Desktop shortcut: $ShortcutPath"
    $wshell = New-Object -ComObject WScript.Shell
    # Run window style 1 = Normal/Active window
    $wshell.Run("`"$ShortcutPath`"", 1, $false)
} else {
    Write-Host "Launching binary directly: $BinaryPath"
    Start-Process -FilePath $BinaryPath
}

$deadline = (Get-Date).AddSeconds(10)
do {
    Start-Sleep -Milliseconds 250
    $proc = Get-Process -Name "omnidesk-desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
} while ((-not $proc -or $proc.MainWindowHandle -eq [IntPtr]::Zero) -and (Get-Date) -lt $deadline)

if (-not $proc) {
    Write-Error "OmniDesk process failed to start."
    exit 1
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinUtil {
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@ -ErrorAction SilentlyContinue

if ($proc.MainWindowHandle -ne [IntPtr]::Zero) {
    [WinUtil]::ShowWindow($proc.MainWindowHandle, 9)
    [WinUtil]::SetForegroundWindow($proc.MainWindowHandle)
}

Write-Host "OmniDesk LIVE INTERACTIVE INSTANCE STARTED:"
Write-Host "PID: $($proc.Id)"
Write-Host "MainWindowTitle: '$($proc.MainWindowTitle)'"
Write-Host "MainWindowHandle: $($proc.MainWindowHandle)"
Write-Host "WorkingSet: $([Math]::Round($proc.WorkingSet64 / 1MB, 2)) MB"
Write-Host "Responding: $($proc.Responding)"

# Keep daemon process monitoring and responding
$proc.WaitForExit()
