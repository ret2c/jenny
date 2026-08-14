param(
    [string]$Path = "ZDI\signoff.txt",
    [int]$Tail = 80
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "signoff file not found: $Path"
}

$item = Get-Item -LiteralPath $Path
$lines = Get-Content -LiteralPath $Path
$timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ssZ")

Write-Output ("[{0}] {1}" -f $timestamp, $item.FullName)
Write-Output ("bytes={0} last_write_utc={1}" -f $item.Length, $item.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ssZ"))
Write-Output ""

$scanLines = $lines | Select-Object -Last $Tail
$decisionRegex = "COMPLETE_LOW_PRIORITY|NEEDS_WORK|REVIEWED HOLD| - HOLD|REVIEWED SUBMIT| - SUBMIT| - COMPLETE(\s|\(|$)"
$decisions = $scanLines | Where-Object {
    $_ -match $decisionRegex -and $_ -notmatch "^Format:" -and $_ -notmatch "^<finding-id>"
}

Write-Output ("Potential decisions / final-review relevant lines in tail ({0} lines):" -f $Tail)
if ($decisions.Count -eq 0) {
    Write-Output "  (none)"
} else {
    $decisions | ForEach-Object { Write-Output ("  {0}" -f $_) }
}

Write-Output ""
Write-Output ("Tail ({0} lines):" -f $Tail)
$scanLines | ForEach-Object { Write-Output ("  {0}" -f $_) }
