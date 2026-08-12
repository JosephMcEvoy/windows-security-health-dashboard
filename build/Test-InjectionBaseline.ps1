<#
.SYNOPSIS
    Runs InjectionHunter over src/ and compares the result to the reviewed
    baseline in build/InjectionHunterBaseline.psd1.

.DESCRIPTION
    InjectionHunter is heuristic and fires on patterns this tool is built out of:
    dynamic member access over its own column and section names, and passing its
    own scriptblocks across a runspace boundary as text. Those sites are reviewed
    and recorded in the baseline with the reasoning for each.

    Findings are matched by fingerprint - rule name, file, and a short SHA-256 of
    the flagged code with whitespace collapsed - not by line number, so the
    baseline survives the code moving around. It does not survive the code
    changing, which is the point: editing a flagged line forces a fresh look.

    Fails when a finding has no baseline entry, or appears more often than its
    entry allows. Warns when a baseline entry no longer matches anything, so
    stale ceilings get removed instead of quietly granting slack.

.PARAMETER Regenerate
    Print a baseline body for the current findings instead of checking, for
    pasting into the .psd1 after the new sites have been reviewed. It prints the
    flagged code next to each entry so there is something to review against.

.EXAMPLE
    ./build/Test-InjectionBaseline.ps1
    ./build/Test-InjectionBaseline.ps1 -Regenerate
#>
[CmdletBinding()]
param(
    [switch]$Regenerate,
    [string]$SourcePath = './src',
    [string]$BaselinePath = './build/InjectionHunterBaseline.psd1'
)

$ErrorActionPreference = 'Stop'

$mod = Get-Module -ListAvailable InjectionHunter | Sort-Object Version -Descending | Select-Object -First 1
if (-not $mod) {
    # Not fatal: the module is best-effort in CI, and a missing scanner must not
    # look like a clean scan. Say so loudly and let the caller decide.
    Write-Host '::warning::InjectionHunter is not installed; the injection pass did not run.'
    exit 0
}
Write-Host "InjectionHunter $($mod.Version)"

$found = @(Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -CustomRulePath $mod.Path -ErrorAction SilentlyContinue)
$found | Format-Table -AutoSize RuleName, Severity, Line, Message | Out-String -Width 200 | Write-Host

function Get-Fingerprint {
    param($Finding)
    $text = ($Finding.Extent.Text -replace '\s+', ' ').Trim()
    # Create() rather than the static HashData() so this still runs under 5.1.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) }
    finally { $sha.Dispose() }
    $short = -join ($bytes[0..7] | ForEach-Object { $_.ToString('x2') })
    "$($Finding.RuleName)|$(Split-Path $Finding.ScriptName -Leaf)|$short"
}

$counts = @{}
$sample = @{}
foreach ($f in $found) {
    $fp = Get-Fingerprint $f
    $counts[$fp] = 1 + [int]$counts[$fp]
    if (-not $sample.ContainsKey($fp)) {
        $snippet = ($f.Extent.Text -replace '\s+', ' ').Trim()
        if ($snippet.Length -gt 90) { $snippet = $snippet.Substring(0, 90) + '...' }
        $sample[$fp] = "L$($f.Line)  $snippet"
    }
}

if ($Regenerate) {
    Write-Host '@{'
    foreach ($fp in ($counts.Keys | Sort-Object)) {
        Write-Host ("    # {0}" -f $sample[$fp])
        Write-Host ("    '{0}' = {1}" -f $fp, $counts[$fp])
    }
    Write-Host '}'
    exit 0
}

$baseline = Import-PowerShellDataFile $BaselinePath

$problems = @()
foreach ($fp in ($counts.Keys | Sort-Object)) {
    if (-not $baseline.ContainsKey($fp)) {
        $problems += "unreviewed finding: $fp  ($($sample[$fp]))"
    }
    elseif ($counts[$fp] -gt [int]$baseline[$fp]) {
        $problems += "$fp appears $($counts[$fp]) time(s), baseline allows $([int]$baseline[$fp])  ($($sample[$fp]))"
    }
}
foreach ($fp in ($baseline.Keys | Sort-Object)) {
    $now = [int]$counts[$fp]
    if ($now -lt [int]$baseline[$fp]) {
        Write-Host "::warning::baseline entry $fp expects $($baseline[$fp]) but matched $now - lower or remove it."
    }
}

if ($problems) {
    $problems | ForEach-Object { Write-Host "::error::$_" }
    throw "InjectionHunter: $($problems.Count) finding(s) outside the reviewed baseline. Review the site, then run ./build/Test-InjectionBaseline.ps1 -Regenerate"
}

Write-Host "InjectionHunter: $($found.Count) finding(s) across $($counts.Keys.Count) fingerprint(s), all within the reviewed baseline."
