param(
    [string]$ZdiRoot,
    [string]$StagingRoot,
    [string]$MailboxDb,
    [string]$Slug = "",
    [switch]$Create
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ZdiRoot)) {
    $ZdiRoot = Join-Path $repoRoot "ZDI"
}
if ([string]::IsNullOrWhiteSpace($StagingRoot)) {
    $StagingRoot = Join-Path $repoRoot "ZDI_STAGING"
}
if ([string]::IsNullOrWhiteSpace($MailboxDb)) {
    $MailboxDb = Join-Path $repoRoot "notes\review_mailbox\review_mailbox.sqlite3"
}

$ZdiRoot = (Resolve-Path -LiteralPath $ZdiRoot).Path
$StagingRoot = [System.IO.Path]::GetFullPath($StagingRoot)
$MailboxDb = [System.IO.Path]::GetFullPath($MailboxDb)

function Convert-ToPackageSlug {
    param([string]$Value)

    $clean = $Value.Trim()
    $clean = $clean -replace '[^\w.-]+', '_'
    $clean = $clean -replace '_+', '_'
    $clean = $clean.Trim('_', '.', '-')
    if ([string]::IsNullOrWhiteSpace($clean)) {
        throw "Slug is empty after normalization."
    }
    return $clean
}

$numberPattern = [regex]'^(?:(?:_?READY_TO_SUBMIT|_?SUBMITTED|_?ACCEPTED|_?REJECTED|_?DEAD|_?HOLD)_)?(\d+)_'
$seen = New-Object System.Collections.Generic.List[int]

@($ZdiRoot, $StagingRoot) | Select-Object -Unique | ForEach-Object {
    if (Test-Path -LiteralPath $_ -PathType Container) {
        Get-ChildItem -LiteralPath $_ -Directory -Recurse | ForEach-Object {
            $match = $numberPattern.Match($_.Name)
            if ($match.Success) {
                $seen.Add([int]$match.Groups[1].Value)
            }
        }
    }
}

if (Test-Path -LiteralPath $MailboxDb -PathType Leaf) {
    $sqliteScript = @'
import pathlib
import re
import sqlite3
import sys

path = pathlib.Path(sys.argv[1]).resolve()
connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
try:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    numbers = set()
    if "package_builds" in tables:
        numbers.update(
            int(row[0])
            for row in connection.execute("SELECT package_number FROM package_builds")
        )
    if "work_items" in tables:
        pattern = re.compile(
            r"^(?:(?:_?READY_TO_SUBMIT|_?SUBMITTED|_?ACCEPTED|"
            r"_?REJECTED|_?DEAD|_?HOLD)_)?(\d+)_"
        )
        for (package_path,) in connection.execute("SELECT package_path FROM work_items"):
            match = pattern.search(pathlib.Path(package_path).name)
            if match:
                numbers.add(int(match.group(1)))
    for number in sorted(numbers):
        print(number)
finally:
    connection.close()
'@
    $sqliteNumbers = $sqliteScript | & python -B - $MailboxDb
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read package numbers from mailbox database: $MailboxDb"
    }
    foreach ($value in $sqliteNumbers) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $seen.Add([int]$value)
        }
    }
}

if ($seen.Count -eq 0) {
    $highest = 0
} else {
    $highest = ($seen | Measure-Object -Maximum).Maximum
}

$next = [int]$highest + 1
if ($next -lt 100) {
    $nextLabel = "{0:D2}" -f $next
} else {
    $nextLabel = [string]$next
}

$result = [ordered]@{
    zdi_root = $ZdiRoot
    staging_root = $StagingRoot
    mailbox_db = $MailboxDb
    highest_number = [int]$highest
    next_number = $next
    next_label = $nextLabel
}

if (-not [string]::IsNullOrWhiteSpace($Slug)) {
    $safeSlug = Convert-ToPackageSlug -Value $Slug
    $folderName = "${nextLabel}_${safeSlug}"
    $folderPath = Join-Path $ZdiRoot $folderName
    $result["suggested_folder"] = $folderName
    $result["suggested_path"] = $folderPath

    if ($Create) {
        if (Test-Path -LiteralPath $folderPath) {
            throw "Refusing to overwrite existing package folder: $folderPath"
        }

        New-Item -ItemType Directory -Path $folderPath | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $folderPath "folder_of_everything_necessary") | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $folderPath "folder_of_everything_necessary\evidence") | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $folderPath "folder_of_everything_necessary\poc") | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $folderPath "folder_of_everything_necessary\source_snippets") | Out-Null
        $result["created"] = $true
    } else {
        $result["created"] = $false
    }
}

$result.GetEnumerator() | ForEach-Object {
    "{0}: {1}" -f $_.Key, $_.Value
}
