param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [string]$ZipPath = "",

    [string]$HashesPath = "",

    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Output $Message
    }
}

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

function Get-SafeLineMetadata {
    param([AllowEmptyString()][string]$Line)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Line)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    } finally {
        $sha.Dispose()
    }
    return [PSCustomObject]@{ ByteLength = $bytes.Length; Sha256 = $hash }
}

function Read-HashFile {
    param([string]$Path)
    $map = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0) { continue }
        if ($trimmed -notmatch "^(?<hash>[A-Fa-f0-9]{64})\s+(?<path>.+)$") {
            $errors.Add("invalid PACKAGE_HASHES.txt line $lineNumber")
            continue
        }
        $relative = $Matches["path"].Trim()
        if ($relative -match "[\\/]" -or [IO.Path]::GetFileName($relative) -ne $relative) {
            $errors.Add("PACKAGE_HASHES.txt target is not a top-level filename: $relative")
            continue
        }
        if ($map.ContainsKey($relative)) {
            $errors.Add("duplicate PACKAGE_HASHES.txt target: $relative")
            continue
        }
        $map[$relative] = $Matches["hash"].Trim().ToUpperInvariant()
    }
    return [PSCustomObject]@{ Map = $map; Errors = $errors }
}

function Get-MeaningfulNameTokens {
    param([string]$Value)
    $ignored = @(
        'archive', 'attachment', 'attachments', 'evidence', 'files', 'folder',
        'necessary', 'package', 'submission', 'vulnerability', 'zip'
    )
    $tokens = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($match in [regex]::Matches($Value, '[A-Za-z0-9]+')) {
        $token = $match.Value.ToLowerInvariant()
        if ($token.Length -ge 2 -and $token -notmatch '^\d+$' -and $ignored -notcontains $token) {
            [void]$tokens.Add($token)
        }
    }
    return $tokens
}

function Resolve-SumTarget {
    param(
        [string]$SumRoot,
        [string]$ExtractRoot,
        [string]$RelativePath
    )

    $normalized = ($RelativePath.Trim() -replace "\\", "/")
    if ($normalized.StartsWith("folder_of_everything_necessary/", [StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring("folder_of_everything_necessary/".Length)
    }
    if ($normalized -eq "" -or $normalized.StartsWith("/") -or $normalized -match "(^|/)\.\.(/|$)") {
        return $null
    }
    $candidate = Join-Path $SumRoot ($normalized -replace "/", [IO.Path]::DirectorySeparatorChar)
    $sumRootFull = [IO.Path]::GetFullPath($SumRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $candidateFull = [IO.Path]::GetFullPath($candidate)
    if (-not $candidateFull.StartsWith($sumRootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    if (Test-Path -LiteralPath $candidateFull -PathType Leaf) {
        return (Resolve-Path -LiteralPath $candidateFull).Path
    }

    return $null
}

$pkg = Resolve-Path -LiteralPath $PackagePath
$pkgPath = $pkg.Path

if ($HashesPath -eq "") {
    $candidate = Join-Path $pkgPath "PACKAGE_HASHES.txt"
    if (Test-Path -LiteralPath $candidate) {
        $HashesPath = $candidate
    }
}

if ($ZipPath -eq "") {
    $zips = Get-ChildItem -LiteralPath $pkgPath -File -Filter "*.zip"
    if ($zips.Count -eq 1) {
        $ZipPath = $zips[0].FullName
    } elseif ($zips.Count -gt 1) {
        throw "multiple zip files found; pass -ZipPath explicitly"
    }
}

$failures = New-Object System.Collections.Generic.List[string]
$textExts = @(".txt", ".md", ".ps1", ".py", ".js", ".json", ".yml", ".yaml", ".http", ".log")
$stalePattern = "\b(DO_NOT_SUBMIT|DO_NOT_PACKAGE|NEEDS_WORK|WRITE[ -]?OFF|TODO|FIXME|PENDING|PLACEHOLDER|TBD)\b"

Write-Info ("PACKAGE {0}" -f $pkgPath)

if ($HashesPath -ne "") {
    $hashFile = Resolve-Path -LiteralPath $HashesPath
    $parsedHashes = Read-HashFile -Path $hashFile.Path
    $topHashes = $parsedHashes.Map
    foreach ($parseError in $parsedHashes.Errors) {
        $failures.Add($parseError)
    }
    $topDescriptions = @(Get-ChildItem -LiteralPath $pkgPath -File | Where-Object { $_.Name -match "description.*\.txt$" -or $_.Name -match "_description\.txt$" })
    $topZips = @(Get-ChildItem -LiteralPath $pkgPath -File -Filter "*.zip")
    if ($topDescriptions.Count -ne 1 -or $topZips.Count -ne 1) {
        $failures.Add("PACKAGE_HASHES.txt requires exactly one description and one ZIP")
    } else {
        $genericArchiveStems = @(
            'archive', 'attachment', 'attachments', 'evidence', 'evidence_zip',
            'files', 'folder_of_everything_necessary', 'package'
        )
        $archiveStem = [IO.Path]::GetFileNameWithoutExtension($topZips[0].Name).ToLowerInvariant()
        if ($genericArchiveStems -contains $archiveStem) {
            $failures.Add("evidence ZIP filename must be descriptive; generic placeholder name is forbidden: $($topZips[0].Name)")
        } else {
            $packageTokens = Get-MeaningfulNameTokens -Value (Split-Path -Leaf $pkgPath)
            $archiveTokens = Get-MeaningfulNameTokens -Value $archiveStem
            $aligned = $false
            foreach ($token in $archiveTokens) {
                if ($packageTokens.Contains($token)) {
                    $aligned = $true
                    break
                }
            }
            if (-not $aligned) {
                $failures.Add("evidence ZIP filename must be aligned with the package vendor, product, or finding: $($topZips[0].Name)")
            }
        }
        $requiredTargets = @($topDescriptions[0].Name, $topZips[0].Name)
        $observedTargets = @($topHashes.Keys)
        foreach ($requiredTarget in $requiredTargets) {
            if (-not $topHashes.ContainsKey($requiredTarget)) {
                $failures.Add("PACKAGE_HASHES.txt missing required target: $requiredTarget")
            }
        }
        foreach ($observedTarget in $observedTargets) {
            if ($requiredTargets -notcontains $observedTarget) {
                $failures.Add("PACKAGE_HASHES.txt contains unexpected target: $observedTarget")
            }
        }
    }
    foreach ($rel in $topHashes.Keys) {
        $local = Join-Path $pkgPath ($rel -replace "/", [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $local)) {
            $failures.Add("missing top-level hash target: $rel")
            continue
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $local).Hash.ToUpperInvariant()
        $expected = $topHashes[$rel]
        $ok = ($actual -eq $expected)
        Write-Info ("TOP_HASH {0} match={1}" -f $rel, $ok)
        if (-not $ok) {
            $failures.Add("top-level hash mismatch: $rel expected=$expected actual=$actual")
        }
    }
} else {
    $failures.Add("PACKAGE_HASHES.txt not found")
}

if ($ZipPath -ne "") {
    $zip = Resolve-Path -LiteralPath $ZipPath
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("jenny_sidecar_gate_" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipHandle = [IO.Compression.ZipFile]::OpenRead($zip.Path)
        try {
            $roots = @{}
            foreach ($entry in $zipHandle.Entries) {
                $name = $entry.FullName
                if ($name.Contains("\")) {
                    $failures.Add("ZIP members must use forward slashes only: $name")
                    continue
                }
                $trimmedName = $name.TrimEnd("/")
                $parts = @($trimmedName -split "/")
                if ($trimmedName -eq "" -or $name.StartsWith("/") -or $parts -contains ".." -or $parts -contains "." -or $parts -contains "") {
                    $failures.Add("ZIP contains unsafe member path: $name")
                    continue
                }
                $roots[$parts[0]] = $true
                if ($entry.Name -ne "" -and $parts.Count -lt 2) {
                    $failures.Add("ZIP must contain exactly one enclosing root named folder_of_everything_necessary")
                }
            }
            if ($roots.Count -ne 1 -or -not $roots.ContainsKey("folder_of_everything_necessary")) {
                $failures.Add("ZIP must contain exactly one enclosing root named folder_of_everything_necessary")
            }
        } finally {
            $zipHandle.Dispose()
        }

        Expand-Archive -LiteralPath $zip.Path -DestinationPath $tmp -Force
        $extractedRoot = Join-Path $tmp "folder_of_everything_necessary"
        $sumFile = Join-Path $extractedRoot "SHA256SUMS.txt"

        $fileCount = (Get-ChildItem -LiteralPath $tmp -Recurse -File | Measure-Object).Count
        if (-not (Test-Path -LiteralPath $sumFile)) {
            $failures.Add("zip extracted but no SHA256SUMS.txt found")
            Write-Info ("ZIP files={0} sha256sums=missing" -f $fileCount)
        } else {
            $okCount = 0
            $badCount = 0
            $missingCount = 0
            $sumRoot = Split-Path -Parent $sumFile
            foreach ($line in Get-Content -LiteralPath $sumFile) {
                $trimmed = $line.Trim()
                if ($trimmed.Length -eq 0) { continue }
                if ($trimmed -notmatch "^(?<hash>[A-Fa-f0-9]{64})\s+(?<path>.+)$") { continue }
                $expected = $Matches["hash"].Trim().ToUpperInvariant()
                $rel = $Matches["path"].Trim()
                $target = Resolve-SumTarget -SumRoot $sumRoot -ExtractRoot $tmp -RelativePath $rel
                if ($null -eq $target) {
                    $missingCount++
                    $failures.Add("zip SHA256SUMS missing target: $rel")
                    continue
                }
                $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToUpperInvariant()
                if ($actual -eq $expected) {
                    $okCount++
                } else {
                    $badCount++
                    $failures.Add("zip hash mismatch: $rel expected=$expected actual=$actual")
                }
            }
            Write-Info ("ZIP files={0} sha256_ok={1} sha256_bad={2} sha256_missing={3}" -f $fileCount, $okCount, $badCount, $missingCount)
        }

        $looseRoot = Join-Path $pkgPath "folder_of_everything_necessary"
        if (-not (Test-Path -LiteralPath $looseRoot -PathType Container) -or -not (Test-Path -LiteralPath $extractedRoot -PathType Container)) {
            $failures.Add("loose/archive parity requires folder_of_everything_necessary in both package and ZIP")
        } else {
            $looseFiles = @{}
            foreach ($file in Get-ChildItem -LiteralPath $looseRoot -Recurse -File) {
                $relative = Get-RelativePathCompat -BasePath $looseRoot -ChildPath $file.FullName
                $looseFiles[$relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToUpperInvariant()
            }
            $archiveFiles = @{}
            foreach ($file in Get-ChildItem -LiteralPath $extractedRoot -Recurse -File) {
                $relative = Get-RelativePathCompat -BasePath $extractedRoot -ChildPath $file.FullName
                $archiveFiles[$relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToUpperInvariant()
            }
            $allRelative = @($looseFiles.Keys + $archiveFiles.Keys | Sort-Object -Unique)
            foreach ($relative in $allRelative) {
                if (-not $looseFiles.ContainsKey($relative) -or -not $archiveFiles.ContainsKey($relative)) {
                    $failures.Add("loose/archive file-list mismatch: $relative")
                } elseif ($looseFiles[$relative] -ne $archiveFiles[$relative]) {
                    $failures.Add("loose/archive byte mismatch: $relative")
                }
            }
        }

        $zipTextFiles = Get-ChildItem -LiteralPath $tmp -Recurse -File | Where-Object { $textExts -contains $_.Extension.ToLowerInvariant() }
        $zipNulHits = New-Object System.Collections.Generic.List[string]
        foreach ($file in $zipTextFiles) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            if ($bytes -contains 0) {
                $zipNulHits.Add((Get-RelativePathCompat -BasePath $tmp -ChildPath $file.FullName))
            }
        }
        Write-Info ("ZIP_NUL_SCAN files={0} hits={1}" -f $zipTextFiles.Count, $zipNulHits.Count)
        foreach ($hit in $zipNulHits) {
            $failures.Add("NUL byte in zip text file: $hit")
        }

        $zipStaleHits = Select-String -Path ($zipTextFiles | Select-Object -ExpandProperty FullName) -Pattern $stalePattern -AllMatches -ErrorAction SilentlyContinue
        Write-Info ("ZIP_STALE_GREP hits={0}" -f @($zipStaleHits).Count)
        foreach ($hit in @($zipStaleHits | Select-Object -First 25)) {
            $rel = Get-RelativePathCompat -BasePath $tmp -ChildPath $hit.Path
            $metadata = Get-SafeLineMetadata -Line ([string]$hit.Line)
            Write-Info ("ZIP_STALE_HIT {0}:{1} pattern=stale_workflow_marker bytes={2} sha256={3}" -f $rel, $hit.LineNumber, $metadata.ByteLength, $metadata.Sha256)
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Info "ZIP skipped: no zip file found"
}

$textFiles = Get-ChildItem -LiteralPath $pkgPath -Recurse -File | Where-Object { $textExts -contains $_.Extension.ToLowerInvariant() }
$nulHits = New-Object System.Collections.Generic.List[string]
foreach ($file in $textFiles) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) {
        $nulHits.Add((Get-RelativePathCompat -BasePath $pkgPath -ChildPath $file.FullName))
    }
}
Write-Info ("NUL_SCAN files={0} hits={1}" -f $textFiles.Count, $nulHits.Count)
foreach ($hit in $nulHits) {
    $failures.Add("NUL byte in text file: $hit")
}

$staleHits = Select-String -Path ($textFiles | Select-Object -ExpandProperty FullName) -Pattern $stalePattern -AllMatches -ErrorAction SilentlyContinue
Write-Info ("STALE_GREP hits={0}" -f @($staleHits).Count)
foreach ($hit in @($staleHits | Select-Object -First 25)) {
    $rel = Get-RelativePathCompat -BasePath $pkgPath -ChildPath $hit.Path
    $metadata = Get-SafeLineMetadata -Line ([string]$hit.Line)
    Write-Info ("STALE_HIT {0}:{1} pattern=stale_workflow_marker bytes={2} sha256={3}" -f $rel, $hit.LineNumber, $metadata.ByteLength, $metadata.Sha256)
}

if ($failures.Count -gt 0) {
    Write-Output "RESULT FAIL"
    foreach ($failure in $failures) {
        Write-Output ("FAIL {0}" -f $failure)
    }
    exit 1
}

Write-Output "RESULT PASS"
