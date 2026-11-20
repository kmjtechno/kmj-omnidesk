Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinSearch {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
}
"@ -ErrorAction SilentlyContinue

$procs = Get-Process -Name "omnidesk-desktop" -ErrorAction SilentlyContinue
$targetPids = @($procs | ForEach-Object { $_.Id })

[WinSearch]::EnumWindows({
    param([IntPtr]$hwnd, [IntPtr]$lParam)
    $wpid = 0
    [WinSearch]::GetWindowThreadProcessId($hwnd, [ref]$wpid) | Out-Null
    if ($targetPids -contains $wpid) {
        $sb = New-Object System.Text.StringBuilder 256
        [WinSearch]::GetWindowText($hwnd, $sb, 256) | Out-Null
        Write-Host "Found HWND: $hwnd PID: $wpid Title: '$($sb.ToString())'"
    }
    return $true
}, [IntPtr]::Zero) | Out-Null
