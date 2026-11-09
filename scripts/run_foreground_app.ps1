$bin = "C:\Users\KMJ TECHNO\AppData\Local\Programs\KMJ OmniDesk\omnidesk-desktop.exe"
if (-not (Test-Path $bin)) {
    $bin = "C:\Users\KMJ TECHNO\AppData\Local\KMJ-CodeBridge\private\devices\kmj-kmj-omnidesk-desktop-5fvjmet\state\isolated-worktrees\kmj-omnidesk\omnidesk-p520-qa-oct30\target\release\omnidesk-desktop.exe"
}
if (-not (Test-Path $bin)) {
    Write-Error "Binary not found: $bin"
    exit 1
}

$proc = Start-Process -FilePath $bin -PassThru
Write-Host "OmniDesk Foreground Process started: PID=$($proc.Id) [Path=$bin]"
$proc.WaitForExit()
