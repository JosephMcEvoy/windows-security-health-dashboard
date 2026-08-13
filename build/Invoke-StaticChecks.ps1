<#
.SYNOPSIS
    Structural guards for SecurityHealthDashboard.ps1.

.DESCRIPTION
    Every check here exists because something actually broke during development.
    They are cheap, they run anywhere PowerShell runs, and they catch classes of
    bug that unit tests do not:

      Parse            - the file must compile.
      Encoding         - pure ASCII. Windows PowerShell 5.1 reads a BOM-less file
                         as ANSI, so one stray non-ASCII byte silently corrupts
                         whatever line it lands on.
      Gallery manifest - the PSScriptInfo block and the comment-based help must
                         both still parse, and their version must agree with
                         $script:ToolVersion. build/Test-GalleryPublish.ps1
                         rehearses the whole publish; this is the cheap half,
                         so it runs under 5.1 too.
      XAML             - the embedded window must be well-formed XML and every
                         FindName lookup must resolve to a real x:Name.
      Param collisions - a $script:<Name> assignment where <Name> is also a
                         parameter writes to the PARAMETER variable and re-runs
                         its attributes. This shipped twice: once it prompted for
                         a credential on a headless run and hung forever, once it
                         silently erased -BaselinePath.
      Array wrapping   - "return , $array" from a function whose caller wraps in
                         @() double-wraps the result, so $_.Prop then reads the
                         ARRAY's own members. This shipped three times.

.PARAMETER Path
    Script to check. Defaults to ../src/SecurityHealthDashboard.ps1.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '../src/SecurityHealthDashboard.ps1')
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0

function Report {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) {
        Write-Host ("  [ ok ] {0}" -f $Name)
    }
    else {
        Write-Host ("  [FAIL] {0}" -f $Name)
        if ($Detail) { $Detail -split "`n" | ForEach-Object { Write-Host "         $_" } }
        $script:Failures++
    }
}

$Path = (Resolve-Path $Path).Path
Write-Host "Static checks: $Path"
Write-Host ''

# ------------------------------------------------------------------- parse
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$toks, [ref]$errs)
$detail = ''
if ($errs.Count) { $detail = ($errs | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "`n" }
Report 'Script parses without syntax errors' ($errs.Count -eq 0) $detail
if ($errs.Count) { exit 1 }

$src = Get-Content -Path $Path -Raw

# ---------------------------------------------------------------- encoding
$bytes = [System.IO.File]::ReadAllBytes($Path)
$nonAscii = @($bytes | Where-Object { $_ -gt 127 })
Report 'File is pure ASCII (safe for Windows PowerShell 5.1)' ($nonAscii.Count -eq 0) "$($nonAscii.Count) byte(s) above 0x7F"

# -------------------------------------------------------- Gallery manifest
# The PSScriptInfo block is what the PowerShell Gallery reads, and it sits
# directly above the comment-based help. The blank line between the two is
# load-bearing: without it the parser treats them as one comment region, keeps
# the first (which holds no help keywords), and the script silently loses its
# help. PowerShellGet then finds no Description and refuses to publish - at
# release time, with nothing earlier in the build having noticed.
$psiVersion = ''
$psiFound = $src -match '(?s)^<#PSScriptInfo\s.*?\.VERSION\s+(\S+).*?\.GUID\s+[0-9a-fA-F-]{36}.*?#>'
if ($psiFound) { $psiVersion = $Matches[1] }
Report 'PSScriptInfo block present, with a version and a GUID' $psiFound `
    'Required to publish to the PowerShell Gallery.'
Report 'Comment-based help is still attached to the script' ($null -ne $ast.GetHelpContent()) `
    'The Gallery reads .DESCRIPTION from here. Restore the blank line between the PSScriptInfo block and the help block.'

$toolVersion = ''
if ($src -match "\`$script:ToolVersion\s*=\s*'([^']+)'") { $toolVersion = $Matches[1] }
Report 'PSScriptInfo version matches $script:ToolVersion' `
    ($psiVersion -ne '' -and $psiVersion -eq $toolVersion) `
    "PSScriptInfo says '$psiVersion'; the script reports '$toolVersion' in every exported report."
Report 'PSScriptInfo version is a three-part semantic version' `
    ($psiVersion -match '^\d+\.\d+\.\d+$') `
    "Got '$psiVersion'. The Gallery normalises versions, so 1.5 and 1.5.0 are one release and the second push is refused."

# -------------------------------------------------------------------- XAML
$xamlOk = $true; $xamlDetail = ''; $names = @()
if ($src -match "(?s)\`$xaml = @'\r?\n(.*?)\r?\n'@") {
    $xamlText = $Matches[1]
    try { [void][xml]$xamlText } catch { $xamlOk = $false; $xamlDetail = $_.Exception.Message }
    $names = [regex]::Matches($xamlText, 'x:Name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
}
else { $xamlOk = $false; $xamlDetail = 'could not locate the $xaml here-string' }
Report 'Embedded XAML is well-formed XML' $xamlOk $xamlDetail

$refs = @()
if ($src -match "(?s)foreach \(\`$name in @\((.*?)\)\) \{") {
    $refs = [regex]::Matches($Matches[1], "'([A-Za-z]\w*)'") | ForEach-Object { $_.Groups[1].Value }
}
$missing = @($refs | Where-Object { $names -notcontains $_ })
Report "All $($refs.Count) FindName lookups resolve to an x:Name" ($missing.Count -eq 0) ($missing -join ', ')

$usedUi = [regex]::Matches($src, '\$ui\.([A-Za-z]\w+)') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique | Where-Object { $_ -ne 'Keys' }
$unresolved = @($usedUi | Where-Object { $refs -notcontains $_ })
Report "All $($usedUi.Count) `$ui.<Element> references resolve" ($unresolved.Count -eq 0) ($unresolved -join ', ')

# ------------------------------------------------- parameter-name collisions
$params = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$collisions = @()
foreach ($p in $params) {
    if ($src -match ('\$script:' + [regex]::Escape($p) + '\s*=')) { $collisions += $p }
}
Report 'No $script:<Name> assignment shadows a parameter' ($collisions.Count -eq 0) `
    ("Writes to the PARAMETER variable and re-runs its attributes: " + ($collisions -join ', '))

# -------------------------------------------------------- array double-wrap
$commaReturns = [regex]::Matches($src, '(?m)^\s+,\s*\$\w+') | ForEach-Object { $_.Value.Trim() } | Sort-Object -Unique
Report 'No comma-wrapped array returns' ($commaReturns.Count -eq 0) `
    ("Callers wrap in @(), so these double-wrap: " + ($commaReturns -join ', '))

# ---------------------------------------------- no plaintext secret handling
$secretHits = [regex]::Matches($src, 'GetNetworkCredential|ConvertFrom-SecureString|\.Password\b(?!LastSet|Required)') |
    ForEach-Object { $_.Value } | Sort-Object -Unique
Report 'Never extracts plaintext credential material' ($secretHits.Count -eq 0) ($secretHits -join ', ')

# ------------------------------------------------ Get-WinEvent ID list size
# FilterHashtable caps the Id array; overflowing it fails the entire query.
$tooBig = @()
foreach ($m in [regex]::Matches($src, '-Ids @\(([^)]*)\)')) {
    $n = @($m.Groups[1].Value -split ',' | Where-Object { $_.Trim() }).Count
    if ($n -gt 22) { $tooBig += "$n ids: $($m.Value)" }
}
Report 'No Get-WinEvent FilterHashtable exceeds 22 event IDs' ($tooBig.Count -eq 0) ($tooBig -join "`n")

# ------------------------------------------------------- read-only contract
# The tool must never modify a target. Flag any state-changing cmdlet that is
# not part of writing local output files.
$mutators = @()
foreach ($m in [regex]::Matches($src, '(?m)^\s*(Set-Mp\w+|Add-Mp\w+|Remove-Mp\w+|Set-NetFirewall\w+|New-NetFirewall\w+|Remove-NetFirewall\w+|Set-Service|Stop-Service|Start-Service|Restart-Computer|Enable-\w+|Disable-\w+)\b')) {
    $mutators += $m.Groups[1].Value
}
$mutators = @($mutators | Sort-Object -Unique)
Report 'No state-changing cmdlets against targets (read-only contract)' ($mutators.Count -eq 0) ($mutators -join ', ')

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) static check(s) FAILED."
    exit 1
}
Write-Host 'All static checks passed.'
exit 0
