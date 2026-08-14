param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$paths = @()
$paths += Get-ChildItem -LiteralPath "tools" -File -Filter "sidecar_*.ps1" -ErrorAction SilentlyContinue
$paths += Get-ChildItem -LiteralPath "artifacts/sidecar" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "sidecar_manifest_*.csv" }

$rows = foreach ($file in ($paths | Sort-Object FullName -Unique)) {
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName
    [PSCustomObject]@{
        Path = ($file.FullName.Substring((Get-Location).Path.Length).TrimStart("\") -replace "\\", "/")
        Length = $file.Length
        LastWriteUtc = $file.LastWriteTimeUtc.ToString("o")
        Sha256 = $hash.Hash.ToUpperInvariant()
    }
}

if ($OutputPath -ne "") {
    $parent = Split-Path -Parent $OutputPath
    if ($parent -ne "" -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
    $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
}

$rows | Format-Table -AutoSize
