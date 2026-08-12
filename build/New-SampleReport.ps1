<#
.SYNOPSIS
    Renders a sample HTML report from mock scan data.

.DESCRIPTION
    Used by CI (to drive the report in a headless browser), by the release
    workflow (to attach a browsable sample), and to regenerate the screenshots
    in docs/screenshots.

    It builds the report from the SAME functions the tool uses at runtime -
    they are lifted out of the script by the test helper - so the sample can
    never drift from what a real scan produces.

.PARAMETER OutputPath
    Where to write the HTML.

.PARAMETER Fleet
    Include a multi-host Fleet tab and a baseline Changes tab, so the sample
    shows every surface rather than just the single-host ones.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = './SecurityHealth_SampleReport.html',
    [switch]$Fleet
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../tests/TestHelpers.psm1') -Force

. ([scriptblock]::Create((Import-DashboardFunction `
    -FunctionName 'Format-Value', 'New-NVRows', 'Get-Section', 'Get-ArrSection', 'New-Findings',
                  'Get-UnifiedEvents', 'New-HealthCards', 'ConvertTo-ReportRows', 'New-ReportPanel',
                  'Get-HtmlReport', 'ConvertTo-ScanSnapshot', 'Save-ScanSnapshot', 'Import-ScanSnapshot',
                  'Get-SnapshotRowKey', 'Test-IsRegression', 'Compare-ScanSnapshots',
                  'New-FleetRow', 'Add-FleetDeviation' `
    -VariableAssignment '$script:ReportTemplate', '$script:ModeMaps', '$script:EventSections',
                        '$script:SectionKeys', '$script:RegressionRules', '$script:AdditionIsNotable',
                        '$script:ToolVersion', '$script:FleetPostureColumns')))

$scan = New-MockScan
$script:FleetRows = @()
$script:DiffRows  = @()
$script:Baseline  = $null

if ($Fleet) {
    # A small fleet with one deliberate outlier, so the Deviation column and the
    # cross-fleet findings table both have something to show.
    $hosts = @()
    foreach ($n in 'PC-041', 'PC-042', 'PC-043') { $hosts += New-FleetRow -Computer $n -d (New-MockScan -Name $n) }
    $odd = New-MockScan -Name 'PC-BAD'
    $odd.DefenderStatus.RealTimeProtectionEnabled = $false
    $odd.SecuritySettings.SecureBoot = 'Off'
    $odd.PsLogging.ScriptBlockLogging = 'Not configured'
    $hosts += New-FleetRow -Computer 'PC-BAD' -d $odd
    $hosts += New-FleetRow -Computer 'PC-OFFLINE' -Failed -ScanError 'WinRM cannot complete the operation: the target did not respond within 300s.'
    $script:FleetRows = @(Add-FleetDeviation $hosts)

    # Sync is what the report reads for the cross-fleet findings panel.
    $script:Sync = @{
        Targets = @('PC-041', 'PC-042', 'PC-043', 'PC-BAD', 'PC-OFFLINE')
        Results = @{ 'PC-041' = (New-MockScan -Name 'PC-041'); 'PC-042' = $scan
                     'PC-043' = (New-MockScan -Name 'PC-043'); 'PC-BAD' = $odd }
        Errors  = @{ 'PC-OFFLINE' = 'timed out' }
    }

    # A baseline with a couple of deliberate drifts, to populate the Changes tab.
    $base = New-MockScan
    $base.DefenderStatus.RealTimeProtectionEnabled = $true
    $base.DefenderStatus.AMEngineVersion = '1.1.24010.1'
    $base.LocalAdmins = @([pscustomobject]@{ Member = 'CORP\Domain Admins'; Type = 'Group'; Source = 'ActiveDirectory' })
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) 'sample_baseline.json'
    [void](Save-ScanSnapshot -d $base -Path $tmp)
    $script:Baseline = Import-ScanSnapshot -Path $tmp
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue

    $drifted = New-MockScan
    $drifted.DefenderStatus.RealTimeProtectionEnabled = $false
    $drifted.LocalAdmins = @(
        [pscustomobject]@{ Member = 'CORP\Domain Admins'; Type = 'Group'; Source = 'ActiveDirectory' }
        [pscustomobject]@{ Member = 'CORP\contractor'; Type = 'User'; Source = 'ActiveDirectory' }
    )
    $drifted.DefenderExclusions = @($drifted.DefenderExclusions) + [pscustomobject]@{ Type = 'Path'; Value = 'C:\Users\Public\Downloads' }
    $script:DiffRows = @(Compare-ScanSnapshots -Baseline $script:Baseline `
        -Current ([pscustomobject]@{ Sections = (ConvertTo-ScanSnapshot $drifted) }))
    $scan = $drifted
}

$html = Get-HtmlReport $scan
$dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))
if ($dir -and -not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($OutputPath), $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "Sample report written: $OutputPath ($($html.Length) bytes)"
