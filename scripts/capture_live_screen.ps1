Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinUserCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
}
"@ -ErrorAction SilentlyContinue

$hwnd = [IntPtr]3347666
$rect = [WinUserCapture+RECT]::new()
if (-not [WinUserCapture]::GetWindowRect($hwnd, [ref]$rect)) {
    Write-Error "Could not get rect for HWND $hwnd"
    exit 1
}

$w = [Math]::Max(10, $rect.Right - $rect.Left)
$h = [Math]::Max(10, $rect.Bottom - $rect.Top)
$bmp = [System.Drawing.Bitmap]::new($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dc = $g.GetHdc()
try {
    [void][WinUserCapture]::PrintWindow($hwnd, $dc, 0)
} finally {
    $g.ReleaseHdc($dc)
    $g.Dispose()
}

$outPath = "C:\Users\KMJ TECHNO\.gemini\antigravity\brain\6ed02b16-26b1-4f9d-9b39-e3cbe2b17e88\live-user-screen.png"
$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Captured live window: $w x $h to $outPath"
