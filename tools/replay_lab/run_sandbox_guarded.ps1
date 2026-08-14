param(
    [Parameter(Mandatory = $true)][string]$Configuration,
    [Parameter(Mandatory = $true)][string]$CompletionMarker,
    [string]$EvidenceDirectory = '',
    [int]$TimeoutSeconds = 14400,
    [double]$MinimumFreeMemoryGb = 4,
    [ValidateSet('hunter')][string]$HeartbeatWorker = '',
    [int]$HeartbeatSeconds = 480,
    [switch]$AllowResourcePressure
)

$ErrorActionPreference = 'Stop'
$configurationPath = (Resolve-Path -LiteralPath $Configuration).Path
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Split-Path -Parent $configurationPath
}
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$evidencePath = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$completionMarkerPath = [IO.Path]::GetFullPath($CompletionMarker)

$sandbox = Join-Path $env:WINDIR 'System32\WindowsSandbox.exe'
if (-not (Test-Path -LiteralPath $sandbox)) {
    throw "Windows Sandbox executable is missing: $sandbox"
}

$guard = Join-Path $PSScriptRoot 'guarded_run.py'
$lifecycle = Join-Path $PSScriptRoot 'sandbox_lifecycle.py'
$preflight = Join-Path $PSScriptRoot 'preflight.py'
$guardTimeoutSeconds = $TimeoutSeconds + 120
$arguments = @(
    $guard,
    '--lock-file', (Join-Path $evidencePath '.sandbox-run.lock'),
    '--result', (Join-Path $evidencePath 'sandbox_guard_result.json'),
    '--stdout', (Join-Path $evidencePath 'sandbox_guard_stdout.txt'),
    '--stderr', (Join-Path $evidencePath 'sandbox_guard_stderr.txt'),
    '--timeout-seconds', $guardTimeoutSeconds.ToString(),
    '--require-no-sandbox',
    '--minimum-free-memory-gb', $MinimumFreeMemoryGb.ToString([Globalization.CultureInfo]::InvariantCulture)
)
if ($AllowResourcePressure) {
    $arguments += '--allow-resource-pressure'
}
if (-not [string]::IsNullOrWhiteSpace($HeartbeatWorker)) {
    $arguments += @(
        '--heartbeat-worker', $HeartbeatWorker,
        '--heartbeat-seconds', $HeartbeatSeconds.ToString()
    )
}
$arguments += @(
    '--', 'python', '-B', $lifecycle,
    '--sandbox-executable', $sandbox,
    '--configuration', $configurationPath,
    '--completion-marker', $completionMarkerPath,
    '--result', (Join-Path $evidencePath 'sandbox_lifecycle_result.json'),
    '--shutdown-timeout-seconds', $TimeoutSeconds.ToString()
)

$env:PYTHONDONTWRITEBYTECODE = '1'
& python -B @arguments
$guardExit = $LASTEXITCODE

$shutdownCheck = Join-Path $evidencePath 'sandbox_shutdown_check.json'
& python -B $preflight --sandbox-status-only --output $shutdownCheck
$shutdownExit = $LASTEXITCODE

$lifecycleResult = Join-Path $evidencePath 'sandbox_lifecycle_result.json'
if ($guardExit -ne 0) {
    exit $guardExit
}
if ($shutdownExit -ne 0 -or -not (Test-Path -LiteralPath $lifecycleResult -PathType Leaf)) {
    exit 2
}
$lifecyclePayload = Get-Content -LiteralPath $lifecycleResult -Raw | ConvertFrom-Json
if (-not $lifecyclePayload.success) {
    exit 2
}
exit 0
