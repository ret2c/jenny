param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,

    [string]$ResultPath = (Join-Path $PSScriptRoot 'elevated_workspace_script_RESULT.json')
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$result = [ordered]@{
    Stage = 'ELEVATED_WORKSPACE_SCRIPT'
    StartedAt = (Get-Date).ToString('o')
    CompletedAt = $null
    ScriptPath = $null
    ScriptSha256 = $null
    AlreadyElevated = $false
    ChildExitCode = $null
    Error = $null
}

try {
    $resolved = (Resolve-Path -LiteralPath $ScriptPath).Path
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    $workspacePrefix = $workspace.TrimEnd('\') + '\'
    if (-not $file.FullName.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The elevated script must be an existing file inside the JENNY workspace.'
    }
    if ($file.Extension -ne '.ps1') {
        throw 'The elevated workspace script must have a .ps1 extension.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.ScriptPath = $file.FullName
    $result.ScriptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    $result.AlreadyElevated = $isAdmin

    $childArguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $file.FullName + '"')
    )
    $start = @{
        FilePath = 'powershell.exe'
        ArgumentList = $childArguments
        PassThru = $true
        Wait = $true
        WindowStyle = 'Hidden'
    }
    if (-not $isAdmin) {
        $start.Verb = 'RunAs'
        $start.Remove('WindowStyle')
    }
    $process = Start-Process @start
    $result.ChildExitCode = $process.ExitCode
    if ($process.ExitCode -ne 0) {
        throw "Elevated workspace script exited $($process.ExitCode)."
    }
} catch {
    $result.Error = $_.Exception.ToString()
} finally {
    $result.CompletedAt = (Get-Date).ToString('o')
    $resultDirectory = Split-Path -Parent $ResultPath
    if ($resultDirectory) {
        New-Item -ItemType Directory -Force -Path $resultDirectory | Out-Null
    }
    $json = $result | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($ResultPath, $json, (New-Object Text.UTF8Encoding($false)))
}

if ($result.Error) { exit 1 }
