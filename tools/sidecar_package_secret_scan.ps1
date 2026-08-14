param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath
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
$allFiles = @(Get-ChildItem -LiteralPath $pkgPath -Recurse -File)

function Read-PlausibleText {
    param([string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) {
        return [PSCustomObject]@{ Kind = "Text"; Text = ""; Reason = "empty" }
    }

    # Classify common package/evidence binaries by signature. Everything else
    # must decode as text or the scan fails closed.
    $knownBinary =
        ($bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) -or
        ($bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and $bytes[2] -in 0x03, 0x05, 0x07 -and $bytes[3] -in 0x04, 0x06, 0x08) -or
        ($bytes.Length -ge 4 -and $bytes[0] -eq 0x25 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x44 -and $bytes[3] -eq 0x46) -or
        ($bytes.Length -ge 4 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) -or
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8 -and $bytes[2] -eq 0xFF) -or
        ($bytes.Length -ge 6 -and [Text.Encoding]::ASCII.GetString($bytes, 0, 6) -in @("GIF87a", "GIF89a")) -or
        ($bytes.Length -ge 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) -or
        ($bytes.Length -ge 6 -and $bytes[0] -eq 0x37 -and $bytes[1] -eq 0x7A -and $bytes[2] -eq 0xBC -and $bytes[3] -eq 0xAF -and $bytes[4] -eq 0x27 -and $bytes[5] -eq 0x1C) -or
        # ISO 9660 volume descriptors begin at sector 16. Byte 0 is the
        # descriptor type and bytes 1-5 carry the standard identifier.
        ($bytes.Length -ge 32774 -and [Text.Encoding]::ASCII.GetString($bytes, 32769, 5) -eq "CD001")
    if ($knownBinary) {
        return [PSCustomObject]@{ Kind = "KnownBinary"; Text = $null; Reason = "signature" }
    }

    try {
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $text = [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
        } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $utf8 = New-Object Text.UTF8Encoding($false, $true)
            $text = $utf8.GetString($bytes, 3, $bytes.Length - 3)
        } else {
            if ($bytes -contains 0) {
                return [PSCustomObject]@{ Kind = "Unknown"; Text = $null; Reason = "embedded NUL" }
            }
            $utf8 = New-Object Text.UTF8Encoding($false, $true)
            $text = $utf8.GetString($bytes)
        }
    } catch {
        return [PSCustomObject]@{ Kind = "Unknown"; Text = $null; Reason = "undecodable" }
    }
    return [PSCustomObject]@{ Kind = "Text"; Text = $text; Reason = "decoded" }
}

$patterns = @(
    @{ Name = "bearer_token"; Regex = "(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}" },
    @{ Name = "api_key_assignment"; Regex = "(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*(?:['""][^'""]{12,}['""]|[^\s#;]{12,})" },
    @{ Name = "aws_access_key"; Regex = "\bAKIA[0-9A-Z]{16}\b" },
    @{ Name = "github_token"; Regex = "\bgh[pousr]_[A-Za-z0-9_]{30,}\b" },
    @{ Name = "slack_token"; Regex = "\bxox[baprs]-[A-Za-z0-9-]{20,}\b" },
    @{ Name = "jwt"; Regex = "\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b" },
    @{ Name = "pem_private_key"; Regex = "-----BEGIN [A-Z ]*PRIVATE KEY-----" }
)

$hits = New-Object System.Collections.Generic.List[object]
$readFailures = New-Object System.Collections.Generic.List[string]
$unscanned = New-Object System.Collections.Generic.List[string]
$scannedCount = 0

foreach ($file in $allFiles) {
    $rel = Get-RelativePathCompat -BasePath $pkgPath -ChildPath $file.FullName
    try {
        $classified = Read-PlausibleText -Path $file.FullName
    } catch {
        $readFailures.Add($rel)
        continue
    }
    if ($classified.Kind -eq "KnownBinary") {
        continue
    }
    if ($classified.Kind -ne "Text") {
        $unscanned.Add(("{0} reason={1}" -f $rel, $classified.Reason))
        continue
    }
    $scannedCount++
    $lineNo = 0
    $lines = @([Regex]::Split([string]$classified.Text, "\r\n|\n|\r"))
    foreach ($line in $lines) {
        $lineNo++
        foreach ($pattern in $patterns) {
            if ($line -match $pattern.Regex) {
                $hits.Add([PSCustomObject]@{
                    File = $rel
                    Line = $lineNo
                    Pattern = $pattern.Name
                })
            }
        }
    }
}

Write-Output ("PACKAGE {0}" -f $pkgPath)
Write-Output ("SECRET_SCAN files={0} hits={1}" -f $scannedCount, $hits.Count)
foreach ($failure in $readFailures) {
    Write-Output ("SECRET_SCAN_READ_FAILURE {0}" -f $failure)
}
foreach ($failure in $unscanned) {
    Write-Output ("SECRET_SCAN_UNSCANNED {0}" -f $failure)
}
foreach ($hit in $hits | Select-Object -First 50) {
    Write-Output ("SECRET_HIT {0}:{1} pattern={2}" -f $hit.File, $hit.Line, $hit.Pattern)
}

if ($hits.Count -gt 0 -or $readFailures.Count -gt 0 -or $unscanned.Count -gt 0 -or $scannedCount -eq 0) {
    Write-Output "RESULT FAIL"
    exit 1
}

Write-Output "RESULT PASS"
