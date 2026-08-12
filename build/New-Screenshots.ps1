<#
.SYNOPSIS
    Regenerates the HTML-report screenshots in docs/screenshots.

.DESCRIPTION
    Builds a sample report from mock data and drives it in headless Chromium.
    Runs anywhere Node and Playwright run, including Linux CI, because the
    report is just HTML. The WPF dashboard images are captured separately by
    build/Capture-Screenshots.ps1 on Windows.

.EXAMPLE
    ./build/New-Screenshots.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '../docs/screenshots')
)
$ErrorActionPreference = 'Stop'

$sample = Join-Path ([System.IO.Path]::GetTempPath()) 'shd-sample.html'
& (Join-Path $PSScriptRoot 'New-SampleReport.ps1') -OutputPath $sample -Fleet

# The script lives next to its node_modules; running node from anywhere else
# cannot resolve 'playwright'.
$browserDir = Join-Path $PSScriptRoot '../tests/browser'
if (-not (Test-Path (Join-Path $browserDir 'node_modules'))) {
    throw "Playwright is not installed. Run: cd tests/browser; npm ci; npx playwright install chromium"
}
Push-Location $browserDir
try {
    & node './capture-report.js' $sample (Resolve-Path $OutputPath).Path
    if ($LASTEXITCODE -ne 0) { throw 'Screenshot capture failed.' }
}
finally { Pop-Location }
Write-Host "Screenshots written to $OutputPath"
