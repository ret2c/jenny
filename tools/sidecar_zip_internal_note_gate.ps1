param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [string]$ZipPath = "",

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

$pkg = Resolve-Path -LiteralPath $PackagePath
$pkgPath = $pkg.Path

if ($ZipPath -eq "") {
    $zips = @(Get-ChildItem -LiteralPath $pkgPath -File -Filter "*.zip")
    if ($zips.Count -eq 1) {
        $ZipPath = $zips[0].FullName
    } elseif ($zips.Count -gt 1) {
        throw "multiple zip files found; pass -ZipPath explicitly"
    } else {
        throw "no zip file found"
    }
}

$zip = Resolve-Path -LiteralPath $ZipPath
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("jenny_zip_internal_note_gate_" + [Guid]::NewGuid().ToString("N"))
$textExts = @(".txt", ".md", ".ps1", ".py", ".js", ".json", ".yml", ".yaml", ".http", ".log", ".env", ".ini", ".toml")

$patterns = @(
    # Preserve exact bounded PoC tokens already present in raw runtime evidence
    # while continuing to reject standalone Codex/reviewer chatter.
    @{ Name = "codex_internal"; Regex = "(?i)(?<![:/])\bCodex\b(?!@|-private-proxy-marker\b|-fixture-only-\d{8}\b)" },
    @{ Name = "claude_agent_internal"; Regex = "(?i)\bClaude\b.{0,80}\b(sidecar|agent|worker|reviewer|handoff|promotion|checklist|package)" },
    @{ Name = "sidecar_internal"; Regex = "(?i)\bsidecar\b" },
    @{ Name = "human_name_internal"; Regex = "(?i)\b(private|internal)\s+(operator|analyst|reviewer)\s+name\b" },
    @{ Name = "notepad_internal"; Regex = "(?i)\bnotepad\b" },
    @{ Name = "user_note_internal"; Regex = "(?i)\b(notes?\s+to\s+(me|user|hunter|reviewer|human)|for\s+(operator|analyst|reviewer|human)|internal\s+workflow|workflow-note)" },
    @{ Name = "status_label_internal"; Regex = "(?i)\b(DO_NOT_SUBMIT|DO_NOT_PACKAGE|READY_TO_SUBMIT|SUBMITTED_CONFIRMED|NEEDS_FINAL|FINAL_GATE|HOLD\s*/\s*DO_NOT|VALIDATION_IN_PROGRESS)\b" },
    @{ Name = "todo_internal"; Regex = "(?i)\b(TODO|TBD|FIXME)\b" }
)

$todoAllow = "(?i)(?:expected|literal|upstream|vendor)\s+(?:TODO|FIXME|TBD)"
$claudeSourceAllow = "(?i)cline\.api\.getModel\(\)\.id\.includes\(`"?claude`"?\)"

$hits = New-Object System.Collections.Generic.List[object]

Write-Info ("PACKAGE {0}" -f $pkgPath)
Write-Info ("ZIP {0}" -f $zip.Path)

New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Expand-Archive -LiteralPath $zip.Path -DestinationPath $tmp -Force
    $files = @(Get-ChildItem -LiteralPath $tmp -Recurse -File | Where-Object { $textExts -contains $_.Extension.ToLowerInvariant() })
    foreach ($file in $files) {
        $rel = Get-RelativePathCompat -BasePath $tmp -ChildPath $file.FullName
        $lineNo = 0
        foreach ($line in Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue) {
            $lineNo++
            foreach ($pattern in $patterns) {
                if ($line -match $pattern.Regex) {
                    if ($pattern.Name -eq "todo_internal" -and $line -match $todoAllow) {
                        continue
                    }
                    if ($pattern.Name -eq "claude_agent_internal" -and $line -match $claudeSourceAllow) {
                        continue
                    }
                    if ($pattern.Name -eq "todo_internal" -and $rel -match "(?i)(^|/)source_(snippets|snapshots)/") {
                        continue
                    }
                    $hits.Add([PSCustomObject]@{
                        File = $rel
                        Line = $lineNo
                        Pattern = $pattern.Name
                        Text = $line.Trim()
                    })
                }
            }
        }
    }

    Write-Info ("ZIP_INTERNAL_NOTE_SCAN files={0} hits={1}" -f $files.Count, $hits.Count)
    foreach ($hit in @($hits | Select-Object -First 50)) {
        Write-Info ("ZIP_INTERNAL_NOTE_HIT {0}:{1} pattern={2}: {3}" -f $hit.File, $hit.Line, $hit.Pattern, $hit.Text)
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($hits.Count -gt 0) {
    Write-Output "RESULT FAIL"
    exit 1
}

Write-Output "RESULT PASS"
