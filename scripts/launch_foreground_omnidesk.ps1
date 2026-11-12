param(
    [string]$BinaryPath = "C:\Users\KMJ TECHNO\AppData\Local\Programs\KMJ OmniDesk\omnidesk-desktop.exe"
)

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 1
}

$proc = Start-Process -FilePath $BinaryPath -PassThru
Write-Host "OmniDesk Foreground Process started: PID=$($proc.Id) [Path=$BinaryPath]"
$proc.WaitForExit()
