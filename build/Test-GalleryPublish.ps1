<#
.SYNOPSIS
    Rehearses the PowerShell Gallery publish end to end against a throwaway
    local repository.

.DESCRIPTION
    The Gallery is append-only. A published version can be unlisted, but it can
    never be replaced or deleted, and the version number can never be reused. So
    every mistake this script looks for has to be caught before the tag is
    pushed, not after - by then the only remedy is to burn a version number.

    Everything here runs the real publish path against a temporary file-system
    repository, so a broken manifest fails a pull request instead of a release:

      Manifest    - Test-ScriptFileInfo accepts the PSScriptInfo block. This is
                    the same parse the Gallery does, and it rejects the file for
                    a missing Version, Guid, Author or Description.
      Identity    - name and GUID match what was published before. The Gallery
                    keys a script by name and refuses a push whose GUID differs
                    from the first version's, so renaming the file or
                    regenerating the GUID orphans the listing permanently.
      Version     - the PSScriptInfo version and $script:ToolVersion agree.
                    They are stamped into different places - the package and
                    every report's provenance panel - and nothing else notices
                    when they drift.
      Help        - the comment-based help still resolves to a Description. The
                    blank line between the PSScriptInfo block and the help block
                    below it is load-bearing: remove it and the parser reads the
                    two as one comment, keeps the first, and the script loses its
                    help. Nothing looks wrong, and the publish fails on a missing
                    Description.
      Round trip  - pack, publish, fetch back, and confirm the delivered file is
                    byte-identical to src/. That is what lets SHA256SUMS.txt from
                    the GitHub release verify the copy installed from the Gallery.

.PARAMETER Path
    Script to rehearse. Defaults to ../src/SecurityHealthDashboard.ps1.

.EXAMPLE
    ./build/Test-GalleryPublish.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '../src/SecurityHealthDashboard.ps1')
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0

# The published identity. Both are fixed for the life of the package: the
# Gallery rejects a push whose GUID does not match the one already on file, and
# the name is taken from the file name, so a rename publishes a second, empty
# listing rather than a new version of this one.
$script:PublishedName = 'SecurityHealthDashboard'
$script:PublishedGuid = '0c021c59-dfaa-4cdf-ac91-cd4c701dd77c'

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
Write-Host "Gallery publish rehearsal: $Path"
Write-Host ''

$psrg = Get-Module -ListAvailable Microsoft.PowerShell.PSResourceGet |
    Sort-Object Version -Descending | Select-Object -First 1
if (-not $psrg) {
    Write-Host '  [FAIL] Microsoft.PowerShell.PSResourceGet is not installed.'
    Write-Host '         Install-Module Microsoft.PowerShell.PSResourceGet -Scope CurrentUser'
    exit 1
}
Import-Module $psrg -Force
Write-Host ("Using PSResourceGet {0}" -f $psrg.Version)
Write-Host ''

# -------------------------------------------------------------- manifest
$info = $null
$manifestOk = $true
$manifestDetail = ''
try { $info = Test-ScriptFileInfo -Path $Path }
catch { $manifestOk = $false; $manifestDetail = $_.Exception.Message }
Report 'PSScriptInfo parses (Test-ScriptFileInfo)' $manifestOk $manifestDetail
if (-not $manifestOk) { exit 1 }

Report "Package name is '$script:PublishedName'" ($info.Name -eq $script:PublishedName) `
    "Got '$($info.Name)'. The Gallery takes the name from the file name; renaming it starts a new listing."

Report 'GUID matches the published identity' ($info.Guid.ToString() -eq $script:PublishedGuid) `
    "Got '$($info.Guid)', expected '$script:PublishedGuid'. A changed GUID is rejected by the Gallery."

Report 'Author is set' ([string]::IsNullOrWhiteSpace($info.Author) -eq $false)
Report 'Description is non-empty (comment-based help resolved)' `
    ([string]::IsNullOrWhiteSpace($info.Description) -eq $false) `
    'The help block did not attach to the script - restore the blank line between it and the PSScriptInfo block.'
Report 'LicenseUri is set' ([string]::IsNullOrWhiteSpace($info.LicenseUri) -eq $false)
Report 'ProjectUri is set' ([string]::IsNullOrWhiteSpace($info.ProjectUri) -eq $false)
Report 'At least three tags for Gallery search' (@($info.Tags).Count -ge 3) `
    "Got $(@($info.Tags).Count)."

# ------------------------------------------------------- version agreement
$src = Get-Content -Path $Path -Raw
$toolVersion = ''
if ($src -match "\`$script:ToolVersion\s*=\s*'([^']+)'") { $toolVersion = $Matches[1] }
Report 'Found $script:ToolVersion in the source' ($toolVersion -ne '')

Report 'PSScriptInfo version is a three-part semantic version' `
    ($info.Version -match '^\d+\.\d+\.\d+$') `
    "Got '$($info.Version)'. The Gallery normalises versions, so 1.5 and 1.5.0 are the same release and the second push is rejected as a duplicate."

Report 'PSScriptInfo version matches $script:ToolVersion' ($info.Version -eq $toolVersion) `
    "PSScriptInfo says '$($info.Version)', the script reports '$toolVersion' in every exported report."

# ------------------------------------------------------------- round trip
$stamp = [guid]::NewGuid().ToString('n')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "shd-gallery-$stamp"
$repoDir = Join-Path $tmp 'repo'
$outDir = Join-Path $tmp 'out'
$repoName = "shd-rehearsal-$stamp"
$null = New-Item -ItemType Directory -Force -Path $repoDir, $outDir

try {
    Register-PSResourceRepository -Name $repoName -Uri $repoDir -Trusted -Force

    $packOk = $true
    $packDetail = ''
    try { Publish-PSResource -Path $Path -Repository $repoName }
    catch { $packOk = $false; $packDetail = $_.Exception.Message }
    Report 'Packs and publishes to a local repository' $packOk $packDetail

    if ($packOk) {
        $found = Find-PSResource -Name $script:PublishedName -Repository $repoName
        Report 'Publishes as a Script, not a Module' ("$($found.Type)" -eq 'Script') "Got '$($found.Type)'."

        # Find-PSResource reports a normalised four-part version, so compare the
        # parts rather than the strings: 1.5.0 comes back as 1.5.0.0.
        $fv = [version]$found.Version
        $iv = [version]$info.Version
        $sameVersion = ($fv.Major -eq $iv.Major -and $fv.Minor -eq $iv.Minor -and
                        [Math]::Max($fv.Build, 0) -eq [Math]::Max($iv.Build, 0))
        Report "Resolves back as version $($info.Version)" $sameVersion "Got '$($found.Version)'."

        Save-PSResource -Name $script:PublishedName -Repository $repoName -Path $outDir -TrustRepository
        $delivered = Get-ChildItem -Path $outDir -Recurse -Filter '*.ps1' | Select-Object -First 1
        Report 'Installs back out of the package' ($null -ne $delivered)

        if ($delivered) {
            $a = [System.IO.File]::ReadAllBytes($Path)
            $b = [System.IO.File]::ReadAllBytes($delivered.FullName)
            $identical = ($a.Length -eq $b.Length)
            if ($identical) {
                for ($i = 0; $i -lt $a.Length; $i++) {
                    if ($a[$i] -ne $b[$i]) { $identical = $false; break }
                }
            }
            Report 'Delivered file is byte-identical to src/' $identical `
                "$($a.Length) bytes in, $($b.Length) bytes out. SHA256SUMS.txt from the release would not verify the installed copy."

            $errs = $null
            $toks = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($delivered.FullName, [ref]$toks, [ref]$errs)
            Report 'Delivered file parses' ($errs.Count -eq 0)
            Report 'Delivered file still carries its help' ($null -ne $ast.GetHelpContent())
        }
    }
}
finally {
    Unregister-PSResourceRepository -Name $repoName -ErrorAction SilentlyContinue
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) gallery check(s) FAILED."
    exit 1
}
Write-Host 'Gallery publish rehearsal passed.'
exit 0
