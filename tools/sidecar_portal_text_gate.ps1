param(
    [Parameter(Mandatory = $true)]
    [string]$DescriptionPath,

    [string]$Mode = "candidate"
)

$ErrorActionPreference = "Stop"

$path = Resolve-Path -LiteralPath $DescriptionPath
$text = Get-Content -Raw -LiteralPath $path.Path
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$disclosureNote = "Disclosure note: LLM assistance was used during identification, PoC development, report drafting, and verification; I have reviewed and validated the package contents."

function Get-NumberedSectionBody {
    param(
        [string]$Document,
        [int]$Number,
        [int]$NextNumber
    )
    $end = if ($NextNumber -gt 0) {
        "(?=^\s*$NextNumber\.\s+)"
    } else {
        "\z"
    }
    $pattern = "(?ms)^\s*$Number\.\s*[^\r\n]+\r?\n(?<body>.*?)$end"
    $match = [regex]::Match($Document, $pattern)
    if (-not $match.Success) { return "" }

    $headingOnly = "(?i)^\s*(?:Vulnerability Summary|Affected Product and Versions?|Confirmed affected|Technical Details|PoC|Impact|Security Impact|Duplicate Review|Public Duplicate Review|Fix|Mitigation|Suggested Fix|prior art|a\.\s*Detailed description of the vulnerability|b\.\s*Code flow from input to the vulnerable condition|c\.\s*Buffer size, injection point, etc\.|d\.\s*Suggested fixes are also welcomed|a\.\s*Upload all proof-of-concept code \*via file attachment\*|b\.\s*Put any additional instructions or explanation for executing the proof-of-concept here|c\.\s*Full exploit code is optional|a\.\s*For vetting purposes|Disclosure note:.*)\s*$"
    $content = @(
        $match.Groups["body"].Value -split "\r?\n" |
            Where-Object { $_.Trim() -ne "" -and $_ -notmatch $headingOnly }
    ) -join " "
    return $content.Trim()
}

$required = @(
    @{ Name = "title"; Regex = "(?im)^\s*(\d+\.\s*)?Vulnerability Title\s*$" },
    @{ Name = "summary"; Regex = "(?i)Vulnerability Summary" },
    @{ Name = "affected_version"; Regex = "(?i)Affected Product and Version|Affected Product and Versions|Confirmed affected" },
    @{ Name = "technical_details"; Regex = "(?i)Root Cause|Technical Details" },
    @{ Name = "poc"; Regex = "(?i)Proof of Concept|PoC" },
    @{ Name = "impact"; Regex = "(?i)Security Impact|Impact" },
    @{ Name = "duplicate_review"; Regex = "(?i)Public Duplicate Review|Duplicate Review|prior art|CVE-" },
    @{ Name = "fix"; Regex = "(?i)Mitigation|Suggested Fix|Fix" }
)

foreach ($item in $required) {
    if ($text -notmatch $item.Regex) {
        $failures.Add("missing required section/signal: $($item.Name)")
    }
}

$isSubmittedPackage = $path.Path -match "[\\/]+_SUBMITTED_\d+_"
$requireNumberedPortalFormat = ($Mode -eq "candidate" -and -not $isSubmittedPackage)

if ($requireNumberedPortalFormat) {
    $numberedRequired = @(
        @{ Name = "portal_field_1_vulnerability_title"; Regex = "(?im)^\s*1\.\s*Vulnerability Title\s*$" },
        @{ Name = "portal_field_2_high_level_overview"; Regex = "(?im)^\s*2\.\s*High-level overview of the vulnerability and the possible effect of using it\s*$" },
        @{ Name = "portal_field_3_exact_product_version"; Regex = "(?im)^\s*3\.\s*Exact product that was found to be vulnerable including complete version information\s*$" },
        @{ Name = "portal_field_4_root_cause_analysis"; Regex = "(?im)^\s*4\.\s*Root Cause Analysis(?: \(recommended but not required\))?\s*$" },
        @{ Name = "portal_field_5_proof_of_concept"; Regex = "(?im)^\s*5\.\s*Proof-of-Concept\s*$" },
        @{ Name = "portal_field_6_software_download_link"; Regex = "(?im)^\s*6\.\s*Software Download Link\s*$" }
    )

    foreach ($item in $numberedRequired) {
        if ($text -notmatch $item.Regex) {
            $failures.Add("missing required numbered ZDI portal field: $($item.Name)")
        }
    }

    $numberedSubitems = @(
        @{ Name = "portal_field_4a_detail"; Regex = "(?im)^\s*a\.\s*Detailed description of the vulnerability\s*$" },
        @{ Name = "portal_field_4b_code_flow"; Regex = "(?im)^\s*b\.\s*Code flow from input to the vulnerable condition\s*$" },
        @{ Name = "portal_field_4c_injection_point"; Regex = "(?im)^\s*c\.\s*Buffer size, injection point, etc\.\s*$" },
        @{ Name = "portal_field_4d_suggested_fixes"; Regex = "(?im)^\s*d\.\s*Suggested fixes are also welcomed\s*$" },
        @{ Name = "portal_field_5a_attachment"; Regex = "(?im)^\s*a\.\s*Upload all proof-of-concept code \*via file attachment\*\s*$" },
        @{ Name = "portal_field_5b_instructions"; Regex = "(?im)^\s*b\.\s*Put any additional instructions or explanation for executing the proof-of-concept here\s*$" },
        @{ Name = "portal_field_5c_full_exploit_optional"; Regex = "(?im)^\s*c\.\s*Full exploit code is optional\s*$" },
        @{ Name = "portal_field_6a_vetting"; Regex = "(?im)^\s*a\.\s*For vetting purposes\s*$" }
    )

    foreach ($item in $numberedSubitems) {
        if ($text -notmatch $item.Regex) {
            $failures.Add("missing required numbered ZDI portal subitem: $($item.Name)")
        }
    }

    for ($field = 1; $field -le 6; $field++) {
        $next = if ($field -lt 6) { $field + 1 } else { 0 }
        $body = Get-NumberedSectionBody -Document $text -Number $field -NextNumber $next
        if ($body.Length -lt 12 -or $body -notmatch "[A-Za-z0-9]") {
            $failures.Add("missing substantive content in numbered field: $field")
        }
    }
}

$disclosureCount = ([regex]::Matches($text, [regex]::Escape($disclosureNote))).Count
if ($disclosureCount -ne 1) {
    $failures.Add("missing or duplicated exact LLM assistance disclosure note")
}

if ($text -match "(?i)\b(no public|not find|not found|no .*advisory|no .*issue)") {
    $warnings.Add("contains no-public-duplicate language; verify against latest sidecar duplicate review before use")
}

if ($Mode -eq "do_not_submit" -and $text -notmatch "(?i)do not submit|duplicate|public|prior art|not zdi") {
    $warnings.Add("do_not_submit mode but description lacks explicit do-not-submit/duplicate warning")
}

if ($text -match "(?i)\bunauthenticated\b" -and $text -notmatch "(?i)not.*unauthenticated|does not claim unauthenticated|No unauthenticated|Important Scope Note|requires attacker network reach|attacker must reach") {
    $warnings.Add("mentions unauthenticated without an obvious non-claim caveat")
}

if ($text -match "(?i)\bRCE\b|remote code execution" -and $text -match "(?i)local file disclosure|confidentiality only|no RCE claim" -and $text -notmatch "(?i)No RCE claim is made|not RCE|does not claim RCE") {
    $warnings.Add("mixed RCE and non-RCE language; verify framing")
}

Write-Output ("DESCRIPTION {0}" -f $path.Path)
Write-Output ("PORTAL_TEXT mode={0} warnings={1} failures={2}" -f $Mode, $warnings.Count, $failures.Count)
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
