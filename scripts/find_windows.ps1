param([uint32]$PidToFind = 7932)

if (-not ([System.Management.Automation.PSTypeName]'WindowFinder').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class WindowFinder {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    public static List<string> FindWindowsForPid(uint targetPid) {
        var list = new List<string>();
        EnumWindows((hWnd, lParam) => {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            if (pid == targetPid) {
                var sb = new System.Text.StringBuilder(256);
                GetWindowText(hWnd, sb, 256);
                list.Add(hWnd.ToString() + " | Visible: " + IsWindowVisible(hWnd) + " | Title: " + sb.ToString());
            }
            return true;
        }, IntPtr.Zero);
        return list;
    }
}
'@
}

[WindowFinder]::FindWindowsForPid($PidToFind)
