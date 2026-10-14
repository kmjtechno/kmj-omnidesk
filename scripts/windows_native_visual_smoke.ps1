param([string]$BinaryPath='target/release/omnidesk-desktop.exe',[string]$OutputDirectory='artifacts/native-ui')
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$ev=[ordered]@{schema_version=1;evidence_type='real_windows_native_window';process_started=$false;window_found=$false;title_verified=$false;screenshot_state='UNVERIFIED';sampled_colors=0;visual_review_required=$true;reason=$null}
$p=$null
try {
  $p=Start-Process -FilePath (Resolve-Path $BinaryPath).Path -PassThru
  $ev.process_started=$true
  $deadline=(Get-Date).AddSeconds(12)
  do { Start-Sleep -Milliseconds 350; $p.Refresh(); if($p.HasExited){throw 'Application exited before window capture'} }
  while($p.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)
  if($p.MainWindowHandle -eq [IntPtr]::Zero){throw 'No MainWindowHandle; runner may not expose an interactive desktop'}
  $ev.window_found=$true
  $ev.title=$p.MainWindowTitle
  $ev.title_verified=$p.MainWindowTitle.StartsWith('KMJ OmniDesk')
  if(-not $ev.title_verified){throw 'Unexpected native window title'}
  Add-Type -AssemblyName System.Drawing
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class KmjCapture {
 [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd,out RECT rect);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd,IntPtr dc,uint flags);
}
'@
  $rect=[KmjCapture+RECT]::new()
  if(-not [KmjCapture]::GetWindowRect($p.MainWindowHandle,[ref]$rect)){throw 'GetWindowRect failed'}
  $w=$rect.Right-$rect.Left; $h=$rect.Bottom-$rect.Top
  if($w -lt 360 -or $h -lt 220 -or $w -gt 8192 -or $h -gt 8192){throw 'Invalid native window bounds'}
  $ev.width=$w; $ev.height=$h
  $bmp=[System.Drawing.Bitmap]::new($w,$h)
  try {
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    try {
      $dc=$g.GetHdc()
      try { $ok=[KmjCapture]::PrintWindow($p.MainWindowHandle,$dc,0) }
      finally { $g.ReleaseHdc($dc) }
    } finally { $g.Dispose() }
    if(-not $ok){throw 'PrintWindow unavailable'}
    $colors=[System.Collections.Generic.HashSet[int]]::new()
    for($y=4;$y -lt $h;$y += [Math]::Max(1,[int]($h/24))){
      for($x=4;$x -lt $w;$x += [Math]::Max(1,[int]($w/24))){
        [void]$colors.Add($bmp.GetPixel($x,$y).ToArgb())
      }
    }
    $ev.sampled_colors=$colors.Count
    $bmp.Save((Join-Path $OutputDirectory 'native-window.png'),[System.Drawing.Imaging.ImageFormat]::Png)
    if($colors.Count -ge 5){$ev.screenshot_state='CAPTURED_FROM_RUNNING_APP'}
    else {throw 'Capture is blank/flat'}
  } finally { $bmp.Dispose() }
} catch {
  $ev.reason=$_.Exception.Message
} finally {
  if($null -ne $p){try{if(-not $p.HasExited){Stop-Process -Id $p.Id -Force}}catch{};$p.Dispose()}
  $ev | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'native-ui-smoke.json')
  $ev | ConvertTo-Json -Compress
}
