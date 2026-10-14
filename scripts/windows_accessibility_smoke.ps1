param(
    [Parameter(Mandatory=$true)][string]$BinaryPath,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$report = [ordered]@{
    evidence_type = 'interactive_windows_uia_smoke'
    process_started = $false
    window_found = $false
    accessible_control_count = 0
    accessible_button_count = 0
    status = 'UNVERIFIED'
    interactive_desktop_required = $true
}
$app = $null
try {
    $app = Start-Process -FilePath (Resolve-Path $BinaryPath).Path -PassThru
    $report.process_started = $true
    $deadline = (Get-Date).AddSeconds(12)
    do {
        Start-Sleep -Milliseconds 350
        $app.Refresh()
        if ($app.HasExited) { throw 'APP_EXITED_BEFORE_UIA' }
    } while ($app.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline)
    if ($app.MainWindowHandle -eq [IntPtr]::Zero) { throw 'NO_INTERACTIVE_WINDOW' }
    $report.window_found = $true
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $element = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
    if ($null -eq $element) { throw 'UIA_ROOT_NOT_FOUND' }
    $report.title_prefix_verified = $element.Current.Name.StartsWith('KMJ OmniDesk')
    $all = $element.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition
    )
    $report.accessible_control_count = $all.Count
    $buttons = 0
    for ($index = 0; $index -lt $all.Count; $index++) {
        if ($all.Item($index).Current.ControlType -eq [System.Windows.Automation.ControlType]::Button) {
            $buttons++
        }
    }
    $report.accessible_button_count = $buttons
    if (-not $report.title_prefix_verified) { throw 'UIA_WINDOW_IDENTITY_MISMATCH' }
    if ($buttons -lt 1) { throw 'NO_ACCESSIBLE_INTERACTIVE_BUTTONS' }
    $report.status = 'UIA_BASELINE_OBSERVED'
} catch {
    $report.issue = $_.Exception.Message
} finally {
    if ($null -ne $app) {
        try { if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force } } catch {}
        $app.Dispose()
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
Write-Output ($report | ConvertTo-Json -Compress)
if ($report.status -ne 'UIA_BASELINE_OBSERVED') { exit 1 }
