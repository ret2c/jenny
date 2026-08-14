param(
    [string]$ZdiPath = "ZDI",

    [string]$OutputPath = ""
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

$root = Resolve-Path -LiteralPath $ZdiPath
$rows = New-Object System.Collections.Generic.List[object]

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

foreach ($dir in Get-ZdiPackageDirectories -RootPath $root.Path) {
    $files = @(Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -ErrorAction SilentlyContinue)
    $topFiles = @(Get-ChildItem -LiteralPath $dir.FullName -File -ErrorAction SilentlyContinue)
    $zips = @($topFiles | Where-Object { $_.Extension -eq ".zip" })
    $descs = @($topFiles | Where-Object { $_.Name -match "description.*\.txt$" -or $_.Name -match "_description\.txt$" })
    $markers = @($topFiles | Where-Object { $_.Name -match "DO_NOT|NOT_FOR|NEEDS|SUPERSEDED|SUBMITTED|WRITE_OFF|HOLD" })
    $packageHashes = Test-Path -LiteralPath (Join-Path $dir.FullName "PACKAGE_HASHES.txt")
    $foen = Test-Path -LiteralPath (Join-Path $dir.FullName "folder_of_everything_necessary") -PathType Container
    $innerSums = Test-Path -LiteralPath (Join-Path $dir.FullName "folder_of_everything_necessary\SHA256SUMS.txt") -PathType Leaf

    $topHashes = @{}
    foreach ($file in $topFiles) {
        if ($file.Length -gt 0 -and ($file.Extension -in @(".zip", ".txt", ".md"))) {
            $topHashes[$file.Name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToUpperInvariant()
        }
    }

    $latestWrite = if ($files.Count -gt 0) {
        ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc.ToString("o")
    } else {
        $dir.LastWriteTimeUtc.ToString("o")
    }

    $rows.Add([PSCustomObject]@{
        Package = $dir.Name
        FileCount = $files.Count
        TopZipCount = $zips.Count
        TopDescriptionCount = $descs.Count
        HasPackageHashes = $packageHashes
        HasFolderOfEverything = $foen
        HasInnerSha256Sums = $innerSums
        MarkerFiles = (($markers | Select-Object -ExpandProperty Name) -join ";")
        LatestWriteUtc = $latestWrite
        TopFileSha256 = ($topHashes.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";"
    })
}

if ($OutputPath -ne "") {
    $parent = Split-Path -Parent $OutputPath
    if ($parent -ne "" -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
    $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
}

$rows | Format-Table -AutoSize
