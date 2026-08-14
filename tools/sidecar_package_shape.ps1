param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [switch]$Modern
)

$ErrorActionPreference = "Stop"

function Get-RelativePathCompat {
    param(
        [string]$BasePath,
        [string]$ChildPath
    )
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $child = [IO.Path]::GetFullPath($ChildPath)
    if ($child.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        return $child.Substring($base.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -replace "\\", "/"
    }
    return $child
}

$pkg = Resolve-Path -LiteralPath $PackagePath
$pkgPath = $pkg.Path
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

$topFiles = @(Get-ChildItem -LiteralPath $pkgPath -File -ErrorAction SilentlyContinue)
$descs = @($topFiles | Where-Object { $_.Name -match "description.*\.txt$" -or $_.Name -match "_description\.txt$" })
$zips = @($topFiles | Where-Object { $_.Extension -eq ".zip" })
$packageHashes = Join-Path $pkgPath "PACKAGE_HASHES.txt"
$foen = Join-Path $pkgPath "folder_of_everything_necessary"
$innerSums = Join-Path $foen "SHA256SUMS.txt"

if ($descs.Count -eq 0) {
    $failures.Add("missing top-level description txt")
} elseif ($descs.Count -gt 1) {
    $warnings.Add("multiple top-level description candidates: " + (($descs | Select-Object -ExpandProperty Name) -join ", "))
}

if ($zips.Count -eq 0) {
    $failures.Add("missing top-level evidence zip")
} elseif ($zips.Count -gt 1) {
    $failures.Add("multiple top-level zip files: " + (($zips | Select-Object -ExpandProperty Name) -join ", "))
}

if (-not (Test-Path -LiteralPath $foen -PathType Container)) {
    $failures.Add("missing folder_of_everything_necessary directory")
} else {
    if (-not (Test-Path -LiteralPath $innerSums -PathType Leaf)) {
        $failures.Add("missing folder_of_everything_necessary/SHA256SUMS.txt")
    }

    $foenFiles = @(Get-ChildItem -LiteralPath $foen -Recurse -File -ErrorAction SilentlyContinue)
    $relFiles = @($foenFiles | ForEach-Object { Get-RelativePathCompat -BasePath $foen -ChildPath $_.FullName })
    foreach ($pattern in @("README*", "poc/*", "evidence/*", "source_snippets/*")) {
        if (-not @($relFiles | Where-Object { $_ -like $pattern }).Count) {
            $warnings.Add("missing expected evidence section: folder_of_everything_necessary/$pattern")
        }
    }
    if (-not @($relFiles | Where-Object { $_ -match "version|fresh|current|release" }).Count) {
        $warnings.Add("no obvious version/current-release evidence filename under folder_of_everything_necessary")
    }
    if (-not @($relFiles | Where-Object { $_ -match "duplicate|prior|advisory|cve|stale" }).Count) {
        $warnings.Add("no obvious duplicate/prior-art evidence filename under folder_of_everything_necessary")
    }
}

if ($Modern -and -not (Test-Path -LiteralPath $packageHashes -PathType Leaf)) {
    $failures.Add("modern package missing PACKAGE_HASHES.txt")
}

Write-Output ("PACKAGE {0}" -f $pkgPath)
Write-Output ("SHAPE desc={0} zip={1} package_hashes={2} folder_of_everything={3}" -f $descs.Count, $zips.Count, (Test-Path -LiteralPath $packageHashes), (Test-Path -LiteralPath $foen -PathType Container))
foreach ($warning in $warnings) {
    Write-Output ("WARN {0}" -f $warning)
}

if ($failures.Count -gt 0) {
    Write-Output "RESULT FAIL"
    foreach ($failure in $failures) {
        Write-Output ("FAIL {0}" -f $failure)
    }
    exit 1
}

Write-Output "RESULT PASS"
