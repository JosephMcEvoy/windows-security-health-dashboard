<#
.SYNOPSIS
    Captures the WPF dashboard screenshots for docs/screenshots. Windows only.

.DESCRIPTION
    The HTML report screenshots in docs/screenshots are generated headlessly by
    CI. The WPF dashboard cannot be: it needs a real Windows desktop session.
    Run this once on a Windows machine to fill in the remaining images.

    It launches the dashboard, waits for you to drive it to each view, and saves
    a PNG of the window on demand. Nothing is automated on purpose - you decide
    what a good screenshot looks like, and you control what host data ends up in
    a public image.

    BEFORE YOU PUBLISH: these images will show real machine names, account
    names, domain names, IP addresses and event detail. Scan a lab machine, or
    redact, before committing anything.

.PARAMETER OutputPath
    Directory for the PNGs. Defaults to docs/screenshots.

.EXAMPLE
    .\build\Capture-Screenshots.ps1
    # Then, for each view: bring the dashboard forward, arrange it, and press
    # Enter in this console to capture.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '../docs/screenshots')
)

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
    throw 'Screenshot capture requires Windows.'
}

Add-Type -AssemblyName System.Drawing, System.Windows.Forms

if (-not (Test-Path $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }
$OutputPath = (Resolve-Path $OutputPath).Path

# The views worth showing, in the order the README presents them.
$shots = @(
    @{ Name = 'gui-overview';    Prompt = 'Overview tab: health cards visible, plus the attention items grid.' }
    @{ Name = 'gui-events';      Prompt = 'Events tab: click Blocked, then open a column filter dropdown.' }
    @{ Name = 'gui-fleet';       Prompt = 'Fleet tab after scanning several hosts, sorted by Deviation.' }
    @{ Name = 'gui-changes';     Prompt = 'Changes tab with a baseline loaded, showing regressions first.' }
    @{ Name = 'gui-defender';    Prompt = 'Defender tab: status, preferences, ASR rules and exclusions.' }
    @{ Name = 'gui-persistence'; Prompt = 'Persistence tab: services and tasks from user-writable paths.' }
)

function Save-ForegroundWindow {
    param([string]$File)
    # Capture the whole virtual screen and crop to the foreground window, which
    # avoids PrintWindow's problems with hardware-composited WPF surfaces.
    $sig = @'
using System;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
    if (-not ('Win' -as [type])) { Add-Type -TypeDefinition $sig }
    $h = [Win]::GetForegroundWindow()
    $r = New-Object Win+RECT
    [void][Win]::GetWindowRect($h, [ref]$r)
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) { throw 'Could not measure the foreground window.' }
    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
    $bmp.Save($File, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}

Write-Host ''
Write-Host 'Launching the dashboard. Scan a LAB machine - these images become public.' -ForegroundColor Yellow
Write-Host ''
$script = Join-Path $PSScriptRoot '../src/SecurityHealthDashboard.ps1'
Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$script`""
)

foreach ($s in $shots) {
    Write-Host ''
    Write-Host "  Next: $($s.Name)" -ForegroundColor Cyan
    Write-Host "  $($s.Prompt)"
    Write-Host '  Arrange the dashboard, click it so it is the foreground window,'
    Write-Host '  then come back here and press Enter (or type s to skip).'
    $k = Read-Host '  >'
    if ($k -eq 's') { Write-Host '  skipped'; continue }
    Start-Sleep -Milliseconds 400   # let this console lose focus first
    $file = Join-Path $OutputPath "$($s.Name).png"
    try {
        Save-ForegroundWindow -File $file
        Write-Host "  saved $file" -ForegroundColor Green
    }
    catch { Write-Warning "  capture failed: $($_.Exception.Message)" }
}

Write-Host ''
Write-Host 'Done. Review every image for host names, user names and IPs before committing.' -ForegroundColor Yellow
