param(
    [string]$ZdiPath = "ZDI",

    [string]$OutputPath = "",

    [ValidateSet("Table", "Csv", "Json")]
    [string]$Format = "Table"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path -LiteralPath $ZdiPath
$gate = Join-Path (Split-Path -Parent $PSScriptRoot) "tools\sidecar_package_gate.ps1"
if (-not (Test-Path -LiteralPath $gate)) {
    throw "sidecar package gate not found: $gate"
}

function Get-ZdiPackageDirectories {
    param([string]$RootPath)

    foreach ($dir in Get-ChildItem -LiteralPath $RootPath -Directory | Sort-Object Name) {
        if ($dir.Name -in @("_SUBMITTED", "_NUMBERED")) {
            Get-ChildItem -LiteralPath $dir.FullName -Directory | Sort-Object Name
        } else {
            $dir
        }
    }
}

$rows = New-Object System.Collections.Generic.List[object]

foreach ($dir in Get-ZdiPackageDirectories -RootPath $root.Path) {
    $zips = @(Get-ChildItem -LiteralPath $dir.FullName -File -Filter "*.zip" -ErrorAction SilentlyContinue)
    $hashes = Test-Path -LiteralPath (Join-Path $dir.FullName "PACKAGE_HASHES.txt")
    $markers = @(Get-ChildItem -LiteralPath $dir.FullName -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(DO_NOT|NOT_FOR|SUPERSEDED|HOLD)" })
    $hasDoNotSubmitMarker = @($markers | Where-Object { $_.Name -match "^(DO_NOT|NOT_FOR|SUPERSEDED|HOLD)" }).Count -gt 0
    $descs = @(Get-ChildItem -LiteralPath $dir.FullName -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "description.*\.txt$" -or $_.Name -match "_description\.txt$" })
    if ($zips.Count -eq 0 -and -not $hashes) {
        $rows.Add([PSCustomObject]@{
            Package = $dir.Name
            Result = "SKIP_NO_PACKAGE"
            ShapeResult = "SKIP_NO_PACKAGE"
            ShapeWarnCount = 0
            ShapeFailCount = 0
            SecretResult = "SKIP_NO_PACKAGE"
            SecretHitCount = 0
            PortalResult = "SKIP_NO_DESCRIPTION"
            PortalWarnCount = 0
            PortalFailCount = 0
            Summary = "no zip or PACKAGE_HASHES.txt"
            FailCount = 0
        })
        continue
    }

    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gate -PackagePath $dir.FullName 2>&1
    $exitCode = $LASTEXITCODE
    $shapeArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path (Split-Path -Parent $PSScriptRoot) "tools\sidecar_package_shape.ps1"), "-PackagePath", $dir.FullName)
    if ($hashes) {
        $shapeArgs += "-Modern"
    }
    $shapeOutput = & powershell @shapeArgs 2>&1
    $shapeResultLine = @($shapeOutput | Where-Object { $_ -match "^RESULT " } | Select-Object -Last 1)
    $shapeWarnCount = @($shapeOutput | Where-Object { $_ -match "^WARN " }).Count
    $shapeFailCount = @($shapeOutput | Where-Object { $_ -match "^FAIL " }).Count
    $secretArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path (Split-Path -Parent $PSScriptRoot) "tools\sidecar_package_secret_scan.ps1"), "-PackagePath", $dir.FullName)
    $secretOutput = & powershell @secretArgs 2>&1
    $secretResultLine = @($secretOutput | Where-Object { $_ -match "^RESULT " } | Select-Object -Last 1)
    $secretScanLine = @($secretOutput | Where-Object { $_ -match "^SECRET_SCAN " } | Select-Object -Last 1)
    $secretHitCount = @($secretOutput | Where-Object { $_ -match "^SECRET_HIT " }).Count
    $portalResult = "SKIP_NO_DESCRIPTION"
    $portalWarnCount = 0
    $portalFailCount = 0
    $portalLine = $null
    if ($descs.Count -eq 1) {
        $portalMode = if ($dir.Name -match "21_LibreChat|DO_NOT|NOT_FOR|SUPERSEDED|HOLD" -or $hasDoNotSubmitMarker) { "do_not_submit" } else { "candidate" }
        $portalArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path (Split-Path -Parent $PSScriptRoot) "tools\sidecar_portal_text_gate.ps1"), "-DescriptionPath", $descs[0].FullName, "-Mode", $portalMode)
        $portalOutput = & powershell @portalArgs 2>&1
        $portalResultLine = @($portalOutput | Where-Object { $_ -match "^RESULT " } | Select-Object -Last 1)
        $portalLine = @($portalOutput | Where-Object { $_ -match "^PORTAL_TEXT " } | Select-Object -Last 1)
        $portalWarnCount = @($portalOutput | Where-Object { $_ -match "^WARN " }).Count
        $portalFailCount = @($portalOutput | Where-Object { $_ -match "^FAIL " }).Count
        $portalResult = if ($portalResultLine.Count -gt 0) { ($portalResultLine[-1] -replace "^RESULT ", "") } else { "ERROR" }
    } elseif ($descs.Count -gt 1) {
        $portalResult = "SKIP_MULTIPLE_DESCRIPTIONS"
    }
    $resultLine = @($output | Where-Object { $_ -match "^RESULT " } | Select-Object -Last 1)
    $zipLine = @($output | Where-Object { $_ -match "^ZIP " } | Select-Object -Last 1)
    $zipNulLine = @($output | Where-Object { $_ -match "^ZIP_NUL_SCAN " } | Select-Object -Last 1)
    $zipStaleLine = @($output | Where-Object { $_ -match "^ZIP_STALE_GREP " } | Select-Object -Last 1)
    $nulLine = @($output | Where-Object { $_ -match "^NUL_SCAN " } | Select-Object -Last 1)
    $staleLine = @($output | Where-Object { $_ -match "^STALE_GREP " } | Select-Object -Last 1)
    $failCount = @($output | Where-Object { $_ -match "^FAIL " }).Count

    $rows.Add([PSCustomObject]@{
        Package = $dir.Name
        Result = if ($resultLine.Count -gt 0) { ($resultLine[-1] -replace "^RESULT ", "") } elseif ($exitCode -eq 0) { "PASS" } else { "ERROR" }
        ShapeResult = if ($shapeResultLine.Count -gt 0) { ($shapeResultLine[-1] -replace "^RESULT ", "") } else { "ERROR" }
        ShapeWarnCount = $shapeWarnCount
        ShapeFailCount = $shapeFailCount
        SecretResult = if ($secretResultLine.Count -gt 0) { ($secretResultLine[-1] -replace "^RESULT ", "") } else { "ERROR" }
        SecretHitCount = $secretHitCount
        PortalResult = $portalResult
        PortalWarnCount = $portalWarnCount
        PortalFailCount = $portalFailCount
        Summary = ((@($zipLine[-1], $zipNulLine[-1], $zipStaleLine[-1], $nulLine[-1], $staleLine[-1], $secretScanLine[-1], $portalLine[-1]) | Where-Object { $_ }) -join " | ")
        FailCount = $failCount
    })
}

if ($OutputPath -ne "") {
    $parent = Split-Path -Parent $OutputPath
    if ($parent -ne "" -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }

    if ($Format -eq "Json") {
        $rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    } else {
        $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    }
}

if ($Format -eq "Json" -and $OutputPath -eq "") {
    $rows | ConvertTo-Json -Depth 4
} elseif ($Format -eq "Csv" -and $OutputPath -eq "") {
    $rows | ConvertTo-Csv -NoTypeInformation
} else {
    $rows | Format-Table -AutoSize
}
