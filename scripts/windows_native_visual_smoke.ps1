param([string]$BinaryPath='target/release/omnidesk-desktop.exe',[string]$OutputDirectory='artifacts/native-ui')
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$ev=[ordered]@{schema_version=1;evidence_type='real_windows_native_window';process_started=$false;window_found=$false;title_verified=$false;screenshot_state='UNVERIFIED';sampled_colors=0;visual_review_required=$true;display_width=$null;display_height=$null;right_edge_white_fraction=$null;reason=$null}
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
 [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd,IntPtr dc,uint flags);
}
'@
  $rect=[KmjCapture+RECT]::new()
  if(-not [KmjCapture]::GetWindowRect($p.MainWindowHandle,[ref]$rect)){throw 'GetWindowRect failed'}
  $w=$rect.Right-$rect.Left; $h=$rect.Bottom-$rect.Top
  if($w -lt 360 -or $h -lt 220 -or $w -gt 8192 -or $h -gt 8192){throw 'Invalid native window bounds'}
  $ev.width=$w; $ev.height=$h
  $ev.display_width=[KmjCapture]::GetSystemMetrics(0)
  $ev.display_height=[KmjCapture]::GetSystemMetrics(1)
  $ev.window_left=$rect.Left
  $ev.window_top=$rect.Top
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
    # A healthy full-window dark dashboard cannot have a pure-white right
    # interior. Hosted PrintWindow previously produced a false-positive
    # screenshot with its final ~300 pixels missing from the rendered surface.
    $rightWhite=0
    $rightSamples=0
    for($y=[int]($h*0.2);$y -lt [int]($h*0.8);$y += [Math]::Max(1,[int]($h/35))){
      for($x=[int]($w*0.85);$x -lt ($w-20);$x += [Math]::Max(1,[int]($w/65))){
        $pixel=$bmp.GetPixel($x,$y)
        $rightSamples++
        if($pixel.R -ge 245 -and $pixel.G -ge 245 -and $pixel.B -ge 245){$rightWhite++}
      }
    }
    $ev.right_edge_white_fraction=if($rightSamples -gt 0){[Math]::Round($rightWhite/$rightSamples,3)}else{$null}
    $bmp.Save((Join-Path $OutputDirectory 'native-window.png'),[System.Drawing.Imaging.ImageFormat]::Png)
    if($colors.Count -lt 5){throw 'Capture is blank/flat'}
    if($null -ne $ev.right_edge_white_fraction -and $ev.right_edge_white_fraction -gt 0.80){
      $ev.screenshot_state='PARTIAL_CAPTURE'
      throw 'Native capture has an unpainted right interior; do not certify visual QA'
    }
    $ev.screenshot_state='CAPTURED_FROM_RUNNING_APP'
  } finally { $bmp.Dispose() }
} catch {
  $ev.reason=$_.Exception.Message
} finally {
  if($null -ne $p){try{if(-not $p.HasExited){Stop-Process -Id $p.Id -Force}}catch{};$p.Dispose()}
  $ev | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'native-ui-smoke.json')
  $ev | ConvertTo-Json -Compress
}

# Returning JSON evidence is not enough: a partial/blank screenshot must
# fail the CI capture job rather than look like successful Windows UI QA.
if($ev.screenshot_state -ne 'CAPTURED_FROM_RUNNING_APP'){exit 1}
