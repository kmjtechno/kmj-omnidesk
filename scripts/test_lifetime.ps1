$bin = "C:\Users\KMJ TECHNO\AppData\Local\KMJ-CodeBridge\private\devices\kmj-kmj-omnidesk-desktop-5fvjmet\state\isolated-worktrees\kmj-omnidesk\omnidesk-p520-qa-oct30\target\release\omnidesk-desktop.exe"
$proc = Start-Process -FilePath $bin -PassThru
Write-Host "Started PID: $($proc.Id)"
for ($i = 0; $i -lt 5; $i++) {
    Start-Sleep -Seconds 1
    $proc.Refresh()
    Write-Host "Sec $i : HasExited=$($proc.HasExited) ExitCode=$($proc.ExitCode)"
    if ($proc.HasExited) { break }
}
if (-not $proc.HasExited) {
    Write-Host "Still alive after 5s! WindowHandle=$($proc.MainWindowHandle)"
}
