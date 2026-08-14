param(
    [Parameter(Mandatory = $true)]
    [string]$Before,

    [Parameter(Mandatory = $true)]
    [string]$After
)

$ErrorActionPreference = "Stop"

$beforeRows = Import-Csv -LiteralPath $Before
$afterRows = Import-Csv -LiteralPath $After

$beforeByPackage = @{}
foreach ($row in $beforeRows) {
    $beforeByPackage[$row.Package] = $row
}

$afterByPackage = @{}
foreach ($row in $afterRows) {
    $afterByPackage[$row.Package] = $row
}

$allPackages = @($beforeByPackage.Keys + $afterByPackage.Keys | Sort-Object -Unique)
$changes = New-Object System.Collections.Generic.List[object]

foreach ($package in $allPackages) {
    $beforeRow = $beforeByPackage[$package]
    $afterRow = $afterByPackage[$package]

    if ($null -eq $beforeRow) {
        $changes.Add([PSCustomObject]@{
            Package = $package
            Change = "ADDED"
            Detail = "new package directory"
        })
        continue
    }

    if ($null -eq $afterRow) {
        $changes.Add([PSCustomObject]@{
            Package = $package
            Change = "REMOVED"
            Detail = "package directory missing"
        })
        continue
    }

    $fields = @(
        "FileCount",
        "TopZipCount",
        "TopDescriptionCount",
        "HasPackageHashes",
        "HasFolderOfEverything",
        "HasInnerSha256Sums",
        "MarkerFiles",
        "LatestWriteUtc",
        "TopFileSha256"
    )
    $diffs = New-Object System.Collections.Generic.List[string]
    foreach ($field in $fields) {
        if ($beforeRow.$field -ne $afterRow.$field) {
            $diffs.Add(("{0}: '{1}' -> '{2}'" -f $field, $beforeRow.$field, $afterRow.$field))
        }
    }

    if ($diffs.Count -gt 0) {
        $changes.Add([PSCustomObject]@{
            Package = $package
            Change = "CHANGED"
            Detail = ($diffs -join " | ")
        })
    }
}

if ($changes.Count -eq 0) {
    Write-Output "NO_CHANGES"
} else {
    $changes | Format-Table -AutoSize -Wrap
}
