<#PSScriptInfo

.VERSION 1.5.0

.GUID 0c021c59-dfaa-4cdf-ac91-cd4c701dd77c

.AUTHOR Joseph McEvoy

.COMPANYNAME

.COPYRIGHT (c) 2026 Joseph McEvoy. Released under the MIT licence.

.TAGS Security Windows Defender ASR AppLocker WDAC Firewall BitLocker SmartScreen Hardening Audit Compliance DFIR BlueTeam Reporting WinRM PSEdition_Desktop PSEdition_Core

.LICENSEURI https://github.com/JosephMcEvoy/windows-security-health-dashboard/blob/main/LICENSE

.PROJECTURI https://github.com/JosephMcEvoy/windows-security-health-dashboard

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Read-only by design - the collector changes nothing on a target, and a CI contract
test fails the build if a state-changing cmdlet appears in the source. No runtime
dependencies: one self-contained script over in-box Windows cmdlets.
Full history: https://github.com/JosephMcEvoy/windows-security-health-dashboard/blob/main/CHANGELOG.md

.PRIVATEDATA

#>

<#
.SYNOPSIS
    Security Health Dashboard - remote Microsoft security tooling triage GUI.

.DESCRIPTION
    WPF-based operator dashboard. Enter a target computer name; the tool connects over
    PowerShell Remoting (WinRM) and collects a holistic snapshot of native Microsoft
    security tooling and identity state:

      - Microsoft Defender AV: engine/platform/signature versions, last signature sync,
        real-time protection, tamper protection, cloud (MAPS) settings, scan history,
        exclusions, ASR rules (block/audit/warn), threat detections
      - Defender operational events: detections, remediations, ASR / Controlled Folder
        Access / Network Protection blocks and audits, config changes, service state changes
      - Windows Firewall: profile state, default actions, rule counts, rule add/change/delete
        events, blocked connections (Filtering Platform audit events 5152/5157)
      - AppLocker: effective policy enforcement per rule collection + allowed/audited/blocked events
      - WDAC / Device Guard: VBS, HVCI, Credential Guard, Code Integrity enforcement + 3076/3077 events
      - Defender for Endpoint (Sense) onboarding state and last-connected time
      - SmartScreen app reputation: the "Windows protected your PC" prompts, from the
        Microsoft-Windows-SmartScreen/Debug analytic channel. That channel is DISABLED
        BY DEFAULT on Windows; the tool reports whether it is on, so an empty result
        reads as "not logged" rather than "nothing was blocked"
      - Smart App Control state (its blocks surface as Code Integrity 3077/3076)
      - BitLocker, Secure Boot, TPM, LSA protection (RunAsPPL), SmartScreen policy, UAC
      - Identity: domain / Entra (Azure AD) join state via dsregcmd, secure channel health,
        local admins, local users, active sessions, logon summary, failed logons,
        account/group-change and audit-policy-change events, log-cleared events
      - Policy: applied GPOs (gpresult), last GP refresh, MDM (Intune) enrollment,
        effective audit policy (auditpol)
      - Security-relevant services and recent hotfixes

    Results render as a tabbed dashboard with health cards, derived "attention items",
    and a unified Blocked / Audited / Allowed event view.

    "Export HTML report" writes a single self-contained .html file that mirrors this
    dashboard: the same tabs, the same health cards, the same attention items, and
    tables with click-to-sort headers, per-column filter dropdowns, a global find box
    with per-tab match counts, the Events quick filters, click-a-row detail, and a
    per-table CSV download of whatever is currently filtered. It has no external
    dependencies, so it works from a file share, an email attachment or a ticket, and
    Print / PDF expands every tab for archiving. The dashboard and the report are
    generated from the same New-HealthCards / Get-UnifiedEvents functions, so the two
    views cannot drift apart.

    FLEET
    Give it several targets and they are scanned in parallel through a throttled
    runspace pool. The Fleet tab lists one row per host with a Deviation count -
    how many posture fields differ from the fleet norm - so sorting by it floats
    the odd machines to the top. Pick any host to load its full detail.

    BASELINE AND DIFF
    "Save baseline" writes the whole scan as a normalised JSON snapshot;
    "Compare to..." loads one back and the Changes tab shows every difference,
    with security-relevant regressions (real-time protection switched off, a new
    exclusion, a new local admin, script block logging disabled) flagged and
    sorted first. Event volumes are compared by count, since individual events
    are time-windowed and would drown the diff in noise.

.NOTES
    Read-only: the tool changes nothing on the target.
    Event collection is capped per log (see $script:MaxEventsPerLog) to keep scans fast.
    Targets 'localhost' / '.' run the collector locally without requiring WinRM loopback.

    REQUIREMENTS
    Operator workstation : Windows PowerShell 5.1+ (or PowerShell 7 on Windows), WPF available.
    Target computer      : WinRM enabled (Enable-PSRemoting), operator must be an admin on the
                           target. In a domain, Kerberos SSO applies; in a workgroup, add the
                           target to TrustedHosts and use the alternate-credentials option.
    Some collectors (auditpol, security event log, BitLocker, exclusions) require elevation
    on the target - remoting as an administrator satisfies this.

    WORKING WITH THE TABLES
    Every table, in both the dashboard and the exported report, supports:
      - Click a column header to sort (click again to reverse). An arrow marks the
        sorted column.
      - Click the small arrow on the right of any header for that column's filter:
        distinct-value checkboxes, a "text contains" box, and sort shortcuts.
        A filtered column is marked with * in its header. The value list cascades,
        i.e. it only offers values still reachable under the other active filters.
      - The "Find" box in the top bar searches every column of every table on every
        tab at once. "Clear filters" resets search, filters and sorting everywhere.
      - Double-click any row for the full, untruncated record in a detail window
        (Copy all puts it on the clipboard). Hovering a cell shows its full text.
      - Columns are freely resizable by dragging the header edge, and double-clicking
        the edge auto-fits to content. Ctrl+C copies selected rows with headers.
    The Events tab additionally has one-click Blocked / Audited / Allowed / Detected /
    Alerts buttons that drive the same filter state.

.PARAMETER ComputerName
    One or more targets. In the GUI they also seed the target box; separate names
    with commas or spaces there.

.PARAMETER TargetFile
    A .txt of computer names (one per line, # comments allowed) or a .csv with a
    ComputerName or Name column.

.PARAMETER Throttle
    How many targets to scan concurrently (default 8).

.PARAMETER TimeoutSec
    Ceiling for the whole run (default 600). Anything still outstanding is
    recorded as timed out, so an unattended run can never wedge.

.PARAMETER BaselinePath
    A snapshot saved earlier. Every scan is diffed against it and the differences
    appear on the Changes tab and in the report.

.PARAMETER Quiet
    Headless. No GUI, no WPF loaded at all - safe on Server Core and from a
    Session 0 scheduled task. Writes files to -OutputPath, emits summary objects
    to the pipeline, and sets an exit code:
        0  everything scanned, nothing above Info
        1  at least one Warning finding
        2  at least one Critical finding, or a regression against the baseline
        3  at least one target could not be scanned (incomplete data outranks
           the finding severities, because a monitoring job that silently lost a
           host is worse than one that found problems)

.PARAMETER OutputPath
    Directory for the generated .html, .json and summary .csv (created if
    missing). With more than one target a fleet index HTML is written too.

.PARAMETER NoHtml
    Write only the JSON snapshots, skipping the HTML reports.

.PARAMETER Credential
    A PSCredential to connect with, supplied at launch instead of being typed into
    the GUI. Accepts a credential object, or a bare user name (you will be prompted
    for the password). When supplied, the "Alternate credentials" box is pre-checked
    and the credential is reused for every scan in the session until you clear or
    change it. It is held in memory only - never written to disk, never included in
    an exported report - and is discarded when the window closes.

.EXAMPLE
    .\SecurityHealthDashboard.ps1

.EXAMPLE
    .\SecurityHealthDashboard.ps1 -ComputerName PC-042 -LookbackDays 14

.EXAMPLE
    # Reuse one admin credential across a whole triage session
    $cred = Get-Credential CORP\svc_secops
    .\SecurityHealthDashboard.ps1 -ComputerName PC-042 -Credential $cred

.EXAMPLE
    # Prompts for the password; no Get-Credential call needed
    .\SecurityHealthDashboard.ps1 -ComputerName WKGRP-BOX -Credential .\LocalAdmin

.EXAMPLE
    # Fleet triage: scan a floor of machines, 12 at a time
    .\SecurityHealthDashboard.ps1 -ComputerName PC-041,PC-042,PC-043 -Throttle 12

.EXAMPLE
    # Compare a suspect machine against a known-good golden image
    .\SecurityHealthDashboard.ps1 -ComputerName PC-042 -BaselinePath .\golden.json

.EXAMPLE
    # Unattended: scan from a list, write reports to a share, use the exit code
    .\SecurityHealthDashboard.ps1 -Quiet -TargetFile .\workstations.txt ``
        -OutputPath \\fileserver\SecReports -Throttle 16
    if ($LASTEXITCODE -ge 2) { "Escalate - critical findings or regressions" }

.EXAMPLE
    # Register it as a weekly Monday 06:00 task that alerts on the exit code.
    # Run this once, elevated, on the machine that will do the scanning.
    $ps  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "C:\Tools\SecurityHealthDashboard.ps1" ' +
           '-Quiet -TargetFile "C:\Tools\workstations.txt" -OutputPath "\\fileserver\SecReports" ' +
           '-BaselinePath "C:\Tools\golden.json" -Throttle 16'
    Register-ScheduledTask -TaskName 'Security Health Weekly' ``
        -Action    (New-ScheduledTaskAction -Execute $ps -Argument $arg) ``
        -Trigger   (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am) ``
        -Principal (New-ScheduledTaskPrincipal -UserId 'CORP\svc_secops' ``
                        -LogonType Password -RunLevel Highest) ``
        -Description 'Weekly Defender/security posture sweep. Exit 2 = critical or regression, 3 = a host was unreachable.'
    # Task Scheduler records the exit code as the "Last Run Result", so a second
    # task triggered on Event ID 201 can mail or push on a non-zero result.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$ComputerName = @(),

    [ValidateRange(1, 90)]
    [int]$LookbackDays = 7,

    # The [Credential()] transformation lets callers pass a bare user name and be
    # prompted for the password, exactly like the built-in cmdlets do.
    [System.Management.Automation.Credential()]
    [System.Management.Automation.PSCredential]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    # Load a previously saved snapshot at startup and diff every scan against it.
    [string]$BaselinePath = '',

    # A text or CSV file of computer names, one per line (a 'Name' or
    # 'ComputerName' column is used if present).
    [string]$TargetFile = '',

    # How many targets to scan concurrently.
    [ValidateRange(1, 64)]
    [int]$Throttle = 8,

    # Headless: no GUI at all. Scans, writes files, sets an exit code and returns.
    # Safe to run from a scheduled task on a host with no desktop session.
    [switch]$Quiet,

    # Directory for the generated .html and .json (created if missing).
    [string]$OutputPath = '',

    # Write only the JSON snapshots, skipping the HTML reports.
    [switch]$NoHtml,

    # Overall ceiling for a scan run. Targets still outstanding when it expires
    # are recorded as timed out. Without this a wedged WinRM call could keep a
    # scheduled task running indefinitely.
    [ValidateRange(30, 7200)]
    [int]$TimeoutSec = 600
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# WPF needs an STA thread. PS 3.0+ consoles default to STA, but guard anyway.
# ---------------------------------------------------------------------------
if (-not $Quiet -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if ($Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        Write-Warning ("This host is not in STA mode, so the GUI has to be relaunched in a new process. " +
                       "A -Credential cannot be handed across that boundary - supply it in the GUI instead, " +
                       "or start your shell with -STA (Windows PowerShell 5.1 consoles already are).")
    }
    $exe = (Get-Process -Id $PID).Path
    # Forward the caller's arguments; previously they were silently dropped.
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    if ($ComputerName -and @($ComputerName).Count -gt 0) { $relaunch += @('-ComputerName', ('"' + (@($ComputerName) -join ',') + '"')) }
    if ($TargetFile) { $relaunch += @('-TargetFile', "`"$TargetFile`"") }
    if ($BaselinePath) { $relaunch += @('-BaselinePath', "`"$BaselinePath`"") }
    $relaunch += @('-LookbackDays', [string]$LookbackDays)
    $relaunch += @('-Throttle', [string]$Throttle)
    Start-Process -FilePath $exe -ArgumentList $relaunch
    return
}

# Quiet mode must not load WPF: a Server Core host or a Session 0 scheduled task
# may have no presentation stack at all.
if (-not $Quiet) {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
}

# ---------------------------------------------------------------------------
# Resolve the target list up front: quiet mode needs it long before any UI
# exists, and the GUI just seeds its text box from the same result.
# ---------------------------------------------------------------------------
$startupTargets = @($ComputerName | Where-Object { $_ })
if ($TargetFile) {
    try {
        if ($TargetFile -match '\.csv$') {
            foreach ($row in @(Import-Csv -Path $TargetFile)) {
                $n = $row.ComputerName
                if (-not $n) { $n = $row.Name }
                if (-not $n) { $n = ($row.PSObject.Properties | Select-Object -First 1).Value }
                if ($n) { $startupTargets += [string]$n }
            }
        }
        else {
            $startupTargets += @(Get-Content -Path $TargetFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
        }
    }
    catch { Write-Warning "Could not read -TargetFile '$TargetFile': $($_.Exception.Message)" }
}

$script:MaxEventsPerLog = 1200
$script:ToolVersion = '1.5.0'
# Deliberately NOT $script:Throttle / $script:TimeoutSec: at script scope those
# are the parameter variables, and assigning to them re-runs their attributes.
$script:ScanThrottle = [math]::Max(1, $Throttle)
$script:ScanTimeoutSec = $TimeoutSec

# The live credential for this session. Memory only: never serialised, never
# written to disk, cleared when the window closes.
#
# NOTE the name. It must NOT be $script:Credential: at script scope that is the
# same variable as the -Credential parameter, which carries a [Credential()]
# transformation attribute. Assigning to it re-runs that attribute, which
# prompts on the console - hanging -Quiet runs forever under a scheduled task.
$script:ScanCredential = $null
if ($Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) {
    $script:ScanCredential = $Credential
}

# ===========================================================================
#  REMOTE COLLECTOR
#  This scriptblock is shipped to the target via Invoke-Command and returns a
#  hashtable of sections. Everything inside must be self-contained, PS 5.1
#  compatible, and resilient (every collector is individually try/caught).
# ===========================================================================
$script:SecurityCollector = {
    param([int]$LookbackDays = 7, [int]$MaxEvents = 1200)

    $ErrorActionPreference = 'Stop'
    $since = (Get-Date).AddDays(-[math]::Abs($LookbackDays))
    $script:errors = @()
    $data = @{}

    function Add-CollectorError {
        param([string]$Area, [string]$Message)
        $script:errors += [pscustomobject]@{ Area = $Area; Message = $Message }
    }

    function Trunc {
        param([string]$s, [int]$n = 300)
        if ([string]::IsNullOrEmpty($s)) { return '' }
        $s = ($s -replace '\s+', ' ').Trim()
        if ($s.Length -gt $n) { return ($s.Substring(0, $n) + ' ...') }
        return $s
    }

    function Get-EventsSafe {
        # -Oldest is REQUIRED for Analytic/Debug channels (e.g. the SmartScreen
        # app-reputation channel); Get-WinEvent refuses to query them otherwise.
        param([string]$LogName, [int[]]$Ids, [int]$Max = 800, [switch]$Oldest)
        try {
            $fh = @{ LogName = $LogName; StartTime = $since }
            if ($Ids -and $Ids.Count -gt 0) { $fh['Id'] = $Ids }
            if ($Oldest) { @(Get-WinEvent -FilterHashtable $fh -MaxEvents $Max -Oldest -ErrorAction Stop) }
            else { @(Get-WinEvent -FilterHashtable $fh -MaxEvents $Max -ErrorAction Stop) }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found|NoMatchingEventsFound') {
                Add-CollectorError -Area "EventLog: $LogName" -Message $_.Exception.Message
            }
            @()
        }
    }

    function Get-EvData {
        # Parse an event's EventData into a hashtable of Name -> value.
        param($Ev)
        $h = @{}
        try {
            $x = [xml]$Ev.ToXml()
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name) { $h[$d.Name] = [string]$d.'#text' }
            }
        }
        catch { }
        $h
    }

    function Resolve-Sid {
        param($Sid)
        if (-not $Sid) { return '' }
        try { return ($Sid.Translate([System.Security.Principal.NTAccount])).Value }
        catch { return [string]$Sid.Value }
    }

    function Get-RegValue {
        param([string]$Path, [string]$Name)
        try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
        catch { return $null }
    }

    # ----------------------------------------------------------------- Meta
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $data.Meta = [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            OS           = $os.Caption
            Version      = $os.Version
            Build        = $os.BuildNumber
            LastBoot     = $os.LastBootUpTime
            UptimeDays   = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
            Domain       = $cs.Domain
            PartOfDomain = [bool]$cs.PartOfDomain
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            ScanTime     = Get-Date
            LookbackDays = $LookbackDays
        }
    }
    catch { Add-CollectorError 'Meta/OS' $_.Exception.Message }

    # ------------------------------------------------------------- Services
    try {
        $filter = "Name='WinDefend' OR Name='WdNisSvc' OR Name='Sense' OR Name='wscsvc' OR " +
                  "Name='SecurityHealthService' OR Name='mpssvc' OR Name='EventLog' OR " +
                  "Name='wuauserv' OR Name='gpsvc' OR Name='WinRM' OR Name='DiagTrack'"
        $data.Services = @(Get-CimInstance -ClassName Win32_Service -Filter $filter | ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                DisplayName = $_.DisplayName
                State       = $_.State
                StartMode   = $_.StartMode
            }
        })
    }
    catch { Add-CollectorError 'Services' $_.Exception.Message }

    # ------------------------------------------------------ Defender status
    try {
        $mp = Get-MpComputerStatus
        $data.DefenderStatus = [pscustomobject]@{
            AMRunningMode                 = [string]$mp.AMRunningMode
            AMServiceEnabled              = $mp.AMServiceEnabled
            AntivirusEnabled              = $mp.AntivirusEnabled
            AntispywareEnabled            = $mp.AntispywareEnabled
            RealTimeProtectionEnabled     = $mp.RealTimeProtectionEnabled
            BehaviorMonitorEnabled        = $mp.BehaviorMonitorEnabled
            IoavProtectionEnabled         = $mp.IoavProtectionEnabled
            OnAccessProtectionEnabled     = $mp.OnAccessProtectionEnabled
            NISEnabled                    = $mp.NISEnabled
            IsTamperProtected             = $mp.IsTamperProtected
            TamperProtectionSource        = [string]$mp.TamperProtectionSource
            AMEngineVersion               = [string]$mp.AMEngineVersion
            AMProductVersion              = [string]$mp.AMProductVersion
            AMServiceVersion              = [string]$mp.AMServiceVersion
            AntivirusSignatureVersion     = [string]$mp.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = $mp.AntivirusSignatureLastUpdated
            AntivirusSignatureAge         = $mp.AntivirusSignatureAge
            NISSignatureVersion           = [string]$mp.NISSignatureVersion
            NISSignatureLastUpdated       = $mp.NISSignatureLastUpdated
            QuickScanEndTime              = $mp.QuickScanEndTime
            QuickScanAge                  = $mp.QuickScanAge
            FullScanEndTime               = $mp.FullScanEndTime
            FullScanAge                   = $mp.FullScanAge
            DefenderSignaturesOutOfDate   = $mp.DefenderSignaturesOutOfDate
            RebootRequired                = $mp.RebootRequired
        }
    }
    catch { Add-CollectorError 'Defender status (Get-MpComputerStatus)' $_.Exception.Message }

    # -------------------------------------------------- Defender preferences
    $pref = $null
    try {
        $pref = Get-MpPreference
        $data.DefenderPrefs = [pscustomobject]@{
            DisableRealtimeMonitoring          = $pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring          = $pref.DisableBehaviorMonitoring
            DisableIOAVProtection              = $pref.DisableIOAVProtection
            DisableScriptScanning              = $pref.DisableScriptScanning
            MAPSReporting                      = $pref.MAPSReporting
            SubmitSamplesConsent               = $pref.SubmitSamplesConsent
            CloudBlockLevel                    = $pref.CloudBlockLevel
            CloudExtendedTimeout               = $pref.CloudExtendedTimeout
            PUAProtection                      = $pref.PUAProtection
            EnableNetworkProtection            = $pref.EnableNetworkProtection
            EnableControlledFolderAccess       = $pref.EnableControlledFolderAccess
            SignatureUpdateInterval            = $pref.SignatureUpdateInterval
            SignatureFallbackOrder             = [string]$pref.SignatureFallbackOrder
            CheckForSignaturesBeforeRunningScan = $pref.CheckForSignaturesBeforeRunningScan
            ScanScheduleQuickScanTime          = [string]$pref.ScanScheduleQuickScanTime
            DisableCatchupQuickScan            = $pref.DisableCatchupQuickScan
            DisableArchiveScanning             = $pref.DisableArchiveScanning
            DisableRemovableDriveScanning      = $pref.DisableRemovableDriveScanning
            DisableEmailScanning               = $pref.DisableEmailScanning
        }

        $excl = @()
        foreach ($p in @($pref.ExclusionPath))      { if ($p) { $excl += [pscustomobject]@{ Type = 'Path';      Value = [string]$p } } }
        foreach ($p in @($pref.ExclusionExtension)) { if ($p) { $excl += [pscustomobject]@{ Type = 'Extension'; Value = [string]$p } } }
        foreach ($p in @($pref.ExclusionProcess))   { if ($p) { $excl += [pscustomobject]@{ Type = 'Process';   Value = [string]$p } } }
        foreach ($p in @($pref.ExclusionIpAddress)) { if ($p) { $excl += [pscustomobject]@{ Type = 'IpAddress'; Value = [string]$p } } }
        foreach ($p in @($pref.AttackSurfaceReductionOnlyExclusions))        { if ($p) { $excl += [pscustomobject]@{ Type = 'ASR exclusion'; Value = [string]$p } } }
        foreach ($p in @($pref.ControlledFolderAccessAllowedApplications))   { if ($p) { $excl += [pscustomobject]@{ Type = 'CFA allowed app'; Value = [string]$p } } }
        foreach ($p in @($pref.ControlledFolderAccessProtectedFolders))      { if ($p) { $excl += [pscustomobject]@{ Type = 'CFA protected folder'; Value = [string]$p } } }
        $data.DefenderExclusions = $excl
    }
    catch { Add-CollectorError 'Defender preferences (Get-MpPreference)' $_.Exception.Message }

    # -------------------------------------------------------------- ASR rules
    try {
        $asrNames = @{
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
            '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence, age, or trusted-list criteria'
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
            'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript from launching downloaded executable content'
            '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
            '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
            '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes that run from USB'
            'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
            'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block webshell creation for servers'
            '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
            'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        }
        $asrModes = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Not configured'; 6 = 'Warn' }
        $asr = @()
        if ($pref -and $pref.AttackSurfaceReductionRules_Ids) {
            $ids  = @($pref.AttackSurfaceReductionRules_Ids)
            $acts = @($pref.AttackSurfaceReductionRules_Actions)
            for ($i = 0; $i -lt $ids.Count; $i++) {
                $g = ([string]$ids[$i]).ToLower()
                $name = $asrNames[$g]
                if (-not $name) { $name = '(unknown rule)' }
                $modeCode = 5
                if ($i -lt $acts.Count) { $modeCode = [int]$acts[$i] }
                $mode = $asrModes[$modeCode]
                if (-not $mode) { $mode = "Code $modeCode" }
                $asr += [pscustomobject]@{ Rule = $name; Mode = $mode; Guid = $g }
            }
        }
        $data.AsrRules = $asr
    }
    catch { Add-CollectorError 'ASR rules' $_.Exception.Message }

    # ---------------------------------------------------------------- Threats
    try {
        $sevMap = @{ 0 = 'Unknown'; 1 = 'Low'; 2 = 'Moderate'; 4 = 'High'; 5 = 'Severe' }
        $threatInfo = @{}
        foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) {
            $threatInfo[[string]$t.ThreatID] = [pscustomobject]@{
                Name     = [string]$t.ThreatName
                Severity = $sevMap[[int]$t.SeverityID]
            }
        }
        $data.Threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Sort-Object InitialDetectionTime -Descending |
            Select-Object -First 200 |
            ForEach-Object {
                $ti = $threatInfo[[string]$_.ThreatID]
                $tn = ''; $sv = ''
                if ($ti) { $tn = $ti.Name; $sv = $ti.Severity }
                [pscustomobject]@{
                    Time          = $_.InitialDetectionTime
                    Threat        = $tn
                    Severity      = $sv
                    User          = [string]$_.DomainUser
                    Process       = [string]$_.ProcessName
                    ActionSuccess = $_.ActionSuccess
                    Resources     = (Trunc (([string[]]@($_.Resources)) -join '; ') 900)
                }
            })
    }
    catch { Add-CollectorError 'Defender threats' $_.Exception.Message }

    # -------------------------------------------------------- Defender events
    try {
        # id -> @(category, action-class)
        $dmap = @{
            1000 = @('Scan started', 'Info');                1001 = @('Scan finished', 'Info')
            1002 = @('Scan stopped before finishing', 'Info'); 1005 = @('Scan failed', 'Alert')
            1006 = @('Malware detected', 'Detected');        1007 = @('Action taken on malware', 'Blocked')
            1008 = @('Action on malware FAILED', 'Alert');   1009 = @('Item restored from quarantine', 'Info')
            1010 = @('Restore from quarantine failed', 'Alert'); 1011 = @('Item deleted from quarantine', 'Info')
            1015 = @('Suspicious behavior detected', 'Detected')
            1116 = @('Malware detected', 'Detected');        1117 = @('Action taken on malware', 'Blocked')
            1118 = @('Remediation action failed', 'Alert');  1119 = @('Critical remediation failure', 'Alert')
            1121 = @('ASR rule triggered (block)', 'Blocked'); 1122 = @('ASR rule triggered (audit)', 'Audited')
            1123 = @('Controlled Folder Access block', 'Blocked'); 1124 = @('Controlled Folder Access audit', 'Audited')
            1125 = @('Network Protection (audit)', 'Audited'); 1126 = @('Network Protection block', 'Blocked')
            1127 = @('Controlled Folder Access sector block', 'Blocked')
            1150 = @('Endpoint health report', 'Info');      1151 = @('Endpoint health report', 'Info')
            2000 = @('Signatures updated', 'Info');          2001 = @('Signature update FAILED', 'Alert')
            2003 = @('Engine update failed', 'Alert');       2010 = @('Dynamic signatures retrieved', 'Info')
            3002 = @('Real-time protection feature failure', 'Alert')
            5000 = @('Real-time protection enabled', 'Info'); 5001 = @('Real-time protection DISABLED', 'Alert')
            5004 = @('Real-time protection config changed', 'Info')
            5007 = @('Defender configuration changed', 'Info')
            5010 = @('Malware scanning DISABLED', 'Alert');  5012 = @('Antivirus DISABLED', 'Alert')
            5013 = @('Tamper Protection blocked a change', 'Blocked')
        }
        $data.DefenderEvents = @(Get-EventsSafe -LogName 'Microsoft-Windows-Windows Defender/Operational' -Max $MaxEvents |
            ForEach-Object {
                $m = $dmap[[int]$_.Id]
                $cat = 'Other'; $act = 'Info'
                if ($m) { $cat = $m[0]; $act = $m[1] }
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Id       = $_.Id
                    Source   = 'Defender'
                    Category = $cat
                    Action   = $act
                    Detail   = (Trunc $_.Message 900)
                }
            })
    }
    catch { Add-CollectorError 'Defender event log' $_.Exception.Message }

    # --------------------------------------------------------------- Firewall
    try {
        $data.FirewallProfiles = @(Get-NetFirewallProfile | ForEach-Object {
            [pscustomobject]@{
                Profile               = [string]$_.Name
                Enabled               = [string]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
                NotifyOnListen        = [string]$_.NotifyOnListen
                LogAllowed            = [string]$_.LogAllowed
                LogBlocked            = [string]$_.LogBlocked
                LogFileName           = [string]$_.LogFileName
            }
        })
    }
    catch { Add-CollectorError 'Firewall profiles' $_.Exception.Message }

    try {
        $ruleGroups = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
            Group-Object Direction, Action
        $data.FirewallRuleSummary = @($ruleGroups | ForEach-Object {
            $parts = $_.Name -split ',\s*'
            [pscustomobject]@{
                Direction = $parts[0]
                Action    = $parts[1]
                EnabledRules = $_.Count
            }
        })
    }
    catch { Add-CollectorError 'Firewall rule summary' $_.Exception.Message }

    try {
        $fwMap = @{
            2004 = 'Firewall rule ADDED'; 2005 = 'Firewall rule MODIFIED'; 2006 = 'Firewall rule DELETED'
            2010 = 'Network profile changed on interface'; 2033 = 'All firewall rules deleted'
        }
        $data.FirewallChanges = @(Get-EventsSafe -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -Ids @(2004, 2005, 2006, 2010, 2033) -Max 500 |
            ForEach-Object {
                $d = Get-EvData $_
                $rn = ''
                if ($d.ContainsKey('RuleName')) { $rn = $d['RuleName'] }
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Id       = $_.Id
                    Source   = 'Firewall'
                    Category = [string]$fwMap[[int]$_.Id]
                    Action   = 'Info'
                    Detail   = (Trunc ("$rn $($d['ApplicationPath'])").Trim() 600)
                }
            })
    }
    catch { Add-CollectorError 'Firewall change events' $_.Exception.Message }

    try {
        # 5152 = packet blocked, 5157 = connection blocked (needs Filtering Platform auditing)
        $protoMap = @{ '1' = 'ICMP'; '6' = 'TCP'; '17' = 'UDP' }
        $blockedRaw = Get-EventsSafe -LogName 'Security' -Ids @(5152, 5157) -Max 1000
        $parsed = @($blockedRaw | ForEach-Object {
            $d = Get-EvData $_
            $dir = 'Unknown'
            if ($d['Direction'] -eq '%%14592') { $dir = 'Inbound' }
            elseif ($d['Direction'] -eq '%%14593') { $dir = 'Outbound' }
            $proto = $protoMap[[string]$d['Protocol']]
            if (-not $proto) { $proto = [string]$d['Protocol'] }
            [pscustomobject]@{
                Time        = $_.TimeCreated
                Application = [string]$d['Application']
                Direction   = $dir
                Remote      = "$($d['DestAddress']):$($d['DestPort'])"
                Local       = "$($d['SourceAddress']):$($d['SourcePort'])"
                Protocol    = $proto
            }
        })
        $data.FirewallBlockedCount = $parsed.Count
        $data.FirewallBlocked = @($parsed | Group-Object Application, Direction, Remote, Protocol |
            Sort-Object Count -Descending | Select-Object -First 40 | ForEach-Object {
                $f = $_.Group[0]
                [pscustomobject]@{
                    Count       = $_.Count
                    LastSeen    = ($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time
                    Application = $f.Application
                    Direction   = $f.Direction
                    Remote      = $f.Remote
                    Protocol    = $f.Protocol
                }
            })
    }
    catch { Add-CollectorError 'Firewall blocked connections (5152/5157)' $_.Exception.Message }

    # --------------------------------------------------------------- AppLocker
    try {
        $data.AppLockerPolicy = @()
        $polXml = $null
        try { $polXml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch { }
        if ($polXml -and $polXml.AppLockerPolicy) {
            $data.AppLockerPolicy = @($polXml.AppLockerPolicy.RuleCollection | ForEach-Object {
                $mode = [string]$_.EnforcementMode
                if (-not $mode) { $mode = 'NotConfigured' }
                $ruleCount = 0
                if ($_.ChildNodes) { $ruleCount = @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count }
                [pscustomobject]@{
                    Collection  = [string]$_.Type
                    Enforcement = $mode
                    Rules       = $ruleCount
                }
            })
        }
    }
    catch { Add-CollectorError 'AppLocker policy' $_.Exception.Message }

    try {
        $alMap = @{
            8002 = @('Exe/Dll allowed', 'Allowed');   8003 = @('Exe/Dll would be blocked (audit)', 'Audited')
            8004 = @('Exe/Dll BLOCKED', 'Blocked');   8005 = @('Script/MSI allowed', 'Allowed')
            8006 = @('Script/MSI would be blocked (audit)', 'Audited'); 8007 = @('Script/MSI BLOCKED', 'Blocked')
            8020 = @('Packaged app allowed', 'Allowed'); 8021 = @('Packaged app audited', 'Audited')
            8022 = @('Packaged app BLOCKED', 'Blocked'); 8023 = @('Packaged app install allowed', 'Allowed')
            8024 = @('Packaged app install audited', 'Audited'); 8025 = @('Packaged app install BLOCKED', 'Blocked')
        }
        $alLogs = @(
            'Microsoft-Windows-AppLocker/EXE and DLL',
            'Microsoft-Windows-AppLocker/MSI and Script',
            'Microsoft-Windows-AppLocker/Packaged app-Execution'
        )
        $alEvents = @()
        foreach ($log in $alLogs) {
            $alEvents += @(Get-EventsSafe -LogName $log -Max 400 | ForEach-Object {
                $m = $alMap[[int]$_.Id]
                if ($m) {
                    [pscustomobject]@{
                        Time     = $_.TimeCreated
                        Id       = $_.Id
                        Source   = 'AppLocker'
                        Category = $m[0]
                        Action   = $m[1]
                        User     = (Resolve-Sid $_.UserId)
                        Detail   = (Trunc $_.Message 900)
                    }
                }
            })
        }
        $data.AppLockerEvents = $alEvents
    }
    catch { Add-CollectorError 'AppLocker events' $_.Exception.Message }

    # ---------------------------------------------------- WDAC / Device Guard
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard'
        $svcNames = @{ 1 = 'Credential Guard'; 2 = 'HVCI (memory integrity)'; 3 = 'System Guard'; 4 = 'SMM firmware protection' }
        $vbsMap = @{ 0 = 'Not enabled'; 1 = 'Enabled, not running'; 2 = 'Enabled and running' }
        $ciMap  = @{ 0 = 'Off'; 1 = 'Audit mode'; 2 = 'Enforced' }
        $running    = @(); $configured = @()
        foreach ($c in @($dg.SecurityServicesRunning))    { if ($svcNames[[int]$c]) { $running += $svcNames[[int]$c] } }
        foreach ($c in @($dg.SecurityServicesConfigured)) { if ($svcNames[[int]$c]) { $configured += $svcNames[[int]$c] } }
        $data.DeviceGuard = [pscustomobject]@{
            VirtualizationBasedSecurity = [string]$vbsMap[[int]$dg.VirtualizationBasedSecurityStatus]
            ServicesConfigured          = ($configured -join ', ')
            ServicesRunning             = ($running -join ', ')
            KernelModeCodeIntegrity     = [string]$ciMap[[int]$dg.CodeIntegrityPolicyEnforcementStatus]
            UserModeCodeIntegrity       = [string]$ciMap[[int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus]
        }
    }
    catch { Add-CollectorError 'Device Guard / WDAC state' $_.Exception.Message }

    try {
        $ciEvtMap = @{
            3076 = @('Code Integrity would block (audit)', 'Audited')
            3077 = @('Code Integrity BLOCKED file', 'Blocked')
            3033 = @('Code Integrity blocked (requirements not met)', 'Blocked')
        }
        $data.CodeIntegrityEvents = @(Get-EventsSafe -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -Ids @(3076, 3077, 3033) -Max 400 |
            ForEach-Object {
                $m = $ciEvtMap[[int]$_.Id]
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Id       = $_.Id
                    Source   = 'WDAC'
                    Category = $m[0]
                    Action   = $m[1]
                    Detail   = (Trunc $_.Message 900)
                }
            })
    }
    catch { Add-CollectorError 'Code Integrity events' $_.Exception.Message }

    # ------------------------------------------- Platform security settings
    try {
        $secureBoot = 'N/A (BIOS or unsupported)'
        try { if (Confirm-SecureBootUEFI) { $secureBoot = 'On' } else { $secureBoot = 'Off' } } catch { }
        $tpmPresent = $null; $tpmReady = $null
        try { $tpm = Get-Tpm; $tpmPresent = $tpm.TpmPresent; $tpmReady = $tpm.TpmReady } catch { }
        $data.SecuritySettings = [pscustomobject]@{
            LsaRunAsPPL           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
            SmartScreenExplorer   = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
            SmartScreenPolicy     = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
            UacEnabled            = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            UacAdminPromptBehavior = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
            SecureBoot            = $secureBoot
            TpmPresent            = $tpmPresent
            TpmReady              = $tpmReady
        }
    }
    catch { Add-CollectorError 'Platform security settings' $_.Exception.Message }

    # ----------------------------------- SmartScreen / Smart App Control state
    try {
        $sacMap = @{ 0 = 'Off'; 1 = 'On (enforcement)'; 2 = 'Evaluation mode' }
        $sacRaw = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
        $sac = 'Not present (pre-Windows 11 or unsupported)'
        if ($null -ne $sacRaw) {
            $sac = [string]$sacMap[[int]$sacRaw]
            if (-not $sac) { $sac = "Unknown value ($sacRaw)" }
        }

        # The channel that records the "Windows protected your PC" app-reputation
        # prompt is an Analytic/Debug channel and is DISABLED BY DEFAULT. If it is
        # off, zero events means "not logged", not "nothing was blocked" - so we
        # report the channel state explicitly rather than showing a false zero.
        $ssLog = 'Microsoft-Windows-SmartScreen/Debug'
        $ssEnabled = $false
        $ssRecords = $null
        try {
            $li = Get-WinEvent -ListLog $ssLog -ErrorAction Stop
            $ssEnabled = [bool]$li.IsEnabled
            $ssRecords = $li.RecordCount
        }
        catch { }

        $shellLevel = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
        if (-not $shellLevel) { $shellLevel = '(not set - Warn, user can override)' }

        $data.SmartScreen = [pscustomobject]@{
            AppReputationLog        = $ssLog
            AppReputationLogEnabled = $ssEnabled
            AppReputationRecords    = $ssRecords
            EnableLoggingCommand    = "wevtutil sl $ssLog /e:true"
            ShellSmartScreen        = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
            PolicyEnableSmartScreen = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
            PolicyShellLevel        = $shellLevel
            EdgeSmartScreen         = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
            EdgeSmartScreenPua      = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled'
            SmartAppControl         = $sac
            SmartAppControlNote     = 'Smart App Control blocks surface as Code Integrity 3077 (enforced) / 3076 (evaluation) on the AppLocker/WDAC tab.'
        }
    }
    catch { Add-CollectorError 'SmartScreen / Smart App Control state' $_.Exception.Message }

    # ------------------------------------ SmartScreen app-reputation prompts
    try {
        $ssEvents = @()
        if ($data.SmartScreen -and $data.SmartScreen.AppReputationLogEnabled) {
            # EventData element names on this channel vary by Windows build, so
            # probe several and always keep the rendered message as ground truth.
            $raw = @(Get-EventsSafe -LogName 'Microsoft-Windows-SmartScreen/Debug' -Max 600 -Oldest)
            $ssEvents = @($raw | Sort-Object TimeCreated -Descending | Select-Object -First 300 | ForEach-Object {
                $dd = Get-EvData $_
                $file = ''
                foreach ($k in @('FileName', 'Path', 'FilePath', 'ImageName', 'TargetPath', 'Name')) {
                    if ($dd.ContainsKey($k) -and $dd[$k]) { $file = [string]$dd[$k]; break }
                }
                $url = ''
                foreach ($k in @('Url', 'HostUrl', 'DownloadUrl', 'SourceUrl', 'ReferrerUrl')) {
                    if ($dd.ContainsKey($k) -and $dd[$k]) { $url = [string]$dd[$k]; break }
                }
                $decision = ''
                foreach ($k in @('Experience', 'SmartScreenEnforcement', 'ResponseCategory', 'Decision', 'Status', 'Reason')) {
                    if ($dd.ContainsKey($k) -and $dd[$k]) { $decision = [string]$dd[$k]; break }
                }
                $act = 'Blocked'
                if ($decision -match 'Allow|Permit|Safe|Known|None') { $act = 'Allowed' }
                $cat = 'SmartScreen app reputation prompt'
                if ($decision) { $cat = "SmartScreen: $decision" }
                $parts = @()
                if ($file) { $parts += "File: $file" }
                if ($url) { $parts += "From: $url" }
                $parts += (Trunc $_.Message 500)
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Id       = $_.Id
                    Source   = 'SmartScreen'
                    Category = $cat
                    Action   = $act
                    Detail   = (Trunc ($parts -join '  |  ') 900)
                }
            })
        }
        $data.SmartScreenEvents = $ssEvents
    }
    catch { Add-CollectorError 'SmartScreen app reputation events' $_.Exception.Message }

    # --------------------------------------------------------------- BitLocker
    try {
        $data.BitLocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            $kp = ''
            if ($_.KeyProtector) { $kp = (@($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }) -join ', ') }
            [pscustomobject]@{
                MountPoint       = [string]$_.MountPoint
                VolumeType       = [string]$_.VolumeType
                ProtectionStatus = [string]$_.ProtectionStatus
                VolumeStatus     = [string]$_.VolumeStatus
                EncryptionMethod = [string]$_.EncryptionMethod
                PercentEncrypted = $_.EncryptionPercentage
                KeyProtectors    = $kp
            }
        })
    }
    catch { Add-CollectorError 'BitLocker' $_.Exception.Message }

    # ---------------------------------------- Microsoft Defender for Endpoint
    try {
        $mdePath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        $onboard = Get-RegValue $mdePath 'OnboardingState'
        $lastConnRaw = Get-RegValue $mdePath 'LastConnected'
        $lastConn = $null
        if ($lastConnRaw) { try { $lastConn = [datetime]::FromFileTime([int64]$lastConnRaw) } catch { } }
        $data.MDE = [pscustomobject]@{
            Onboarded     = ($onboard -eq 1)
            OnboardingState = $onboard
            OrgId         = [string](Get-RegValue $mdePath 'OrgId')
            LastConnected = $lastConn
        }
    }
    catch { Add-CollectorError 'MDE onboarding state' $_.Exception.Message }


    # ------------------------------------------------- PowerShell logging state
    try {
        $psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        $sbl = Get-RegValue "$psPol\ScriptBlockLogging" 'EnableScriptBlockLogging'
        $mod = Get-RegValue "$psPol\ModuleLogging" 'EnableModuleLogging'
        $tr  = Get-RegValue "$psPol\Transcription" 'EnableTranscripting'
        # PowerShell 2.0 is a downgrade-attack path: it predates script block
        # logging and AMSI, so an attacker can run "powershell -v 2" to go dark.
        $v2Feature = 'Unknown'
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction Stop
            $v2Feature = [string]$f.State
        }
        catch {
            try {
                $f2 = Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop
                if ($f2.Installed) { $v2Feature = 'Enabled' } else { $v2Feature = 'Disabled' }
            }
            catch { }
        }
        $data.PsLogging = [pscustomobject]@{
            ScriptBlockLogging        = $(if ($sbl -eq 1) { 'Enabled' } elseif ($null -eq $sbl) { 'Not configured' } else { 'Disabled' })
            ScriptBlockInvocationLog  = Get-RegValue "$psPol\ScriptBlockLogging" 'EnableScriptBlockInvocationLogging'
            ModuleLogging             = $(if ($mod -eq 1) { 'Enabled' } elseif ($null -eq $mod) { 'Not configured' } else { 'Disabled' })
            Transcription             = $(if ($tr -eq 1) { 'Enabled' } elseif ($null -eq $tr) { 'Not configured' } else { 'Disabled' })
            TranscriptOutputDirectory = Get-RegValue "$psPol\Transcription" 'OutputDirectory'
            PowerShellV2Feature       = $v2Feature
            PowerShellV2EngineKey     = (Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine')
        }
    }
    catch { Add-CollectorError 'PowerShell logging state' $_.Exception.Message }

    # ------------------------------------------------------------------- LAPS
    try {
        # Windows LAPS reads these roots in order; the first root with any value
        # set wins, and settings are never inherited across roots.
        $lapsRoots = @(
            @{ Name = 'LAPS CSP (Intune)';    Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' }
            @{ Name = 'LAPS Group Policy';    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' }
            @{ Name = 'LAPS local config';    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' }
            @{ Name = 'Legacy LAPS (AdmPwd)'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' }
        )
        $activeRoot = $null
        foreach ($r in $lapsRoots) {
            if (Test-Path $r.Path) {
                $props = Get-ItemProperty -Path $r.Path -ErrorAction SilentlyContinue
                if ($props) {
                    $real = @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })
                    if ($real.Count -gt 0) { $activeRoot = $r; break }
                }
            }
        }
        $backupMap = @{ 0 = 'Disabled'; 1 = 'Microsoft Entra ID'; 2 = 'Active Directory' }
        if ($activeRoot) {
            $bd = Get-RegValue $activeRoot.Path 'BackupDirectory'
            $bdText = 'Not set'
            if ($null -ne $bd) {
                $bdText = [string]$backupMap[[int]$bd]
                if (-not $bdText) { $bdText = "Unknown ($bd)" }
            }
            $legacyEnabled = Get-RegValue $activeRoot.Path 'AdmPwdEnabled'
            $data.Laps = [pscustomobject]@{
                Configured               = $true
                ActivePolicySource       = $activeRoot.Name
                PolicyKey                = $activeRoot.Path
                BackupDirectory          = $bdText
                LegacyAdmPwdEnabled      = $legacyEnabled
                AdministratorAccountName = Get-RegValue $activeRoot.Path 'AdministratorAccountName'
                PasswordAgeDays          = Get-RegValue $activeRoot.Path 'PasswordAgeDays'
                PasswordLength           = Get-RegValue $activeRoot.Path 'PasswordLength'
                PasswordComplexity       = Get-RegValue $activeRoot.Path 'PasswordComplexity'
                ExpirationProtection     = Get-RegValue $activeRoot.Path 'PasswordExpirationProtectionEnabled'
                ADPasswordEncryption     = Get-RegValue $activeRoot.Path 'ADPasswordEncryptionEnabled'
                PostAuthActions          = Get-RegValue $activeRoot.Path 'PostAuthenticationActions'
            }
        }
        else {
            $data.Laps = [pscustomobject]@{
                Configured         = $false
                ActivePolicySource = 'None - no LAPS policy found in any of the four policy roots'
                PolicyKey          = ''
                BackupDirectory    = 'Not configured'
            }
        }
    }
    catch { Add-CollectorError 'LAPS' $_.Exception.Message }

    # ------------------------------------------------- Exploit Protection (system)
    try {
        $pm = Get-ProcessMitigation -System -ErrorAction Stop
        $data.ExploitProtection = [pscustomobject]@{
            DEP                    = [string]$pm.Dep.Enable
            DEP_Emulation          = [string]$pm.Dep.EmulateAtlThunks
            ASLR_BottomUp          = [string]$pm.Aslr.BottomUp
            ASLR_ForceRelocate     = [string]$pm.Aslr.ForceRelocateImages
            ASLR_HighEntropy       = [string]$pm.Aslr.HighEntropy
            ControlFlowGuard       = [string]$pm.Cfg.Enable
            CFG_SuppressExports    = [string]$pm.Cfg.SuppressExports
            SEHOP                  = [string]$pm.SEHOP.Enable
            SEHOP_TelemetryOnly    = [string]$pm.SEHOP.TelemetryOnly
            Heap_TerminateOnError  = [string]$pm.Heap.TerminateOnError
        }
    }
    catch { Add-CollectorError 'Exploit Protection (Get-ProcessMitigation)' $_.Exception.Message }

    # ---------------------------------------------- Windows Update currency
    try {
        $auRes = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results'
        $pending = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'Component Based Servicing' }
        $pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
        if ($pfro) { $pending += 'Pending file rename' }
        $lastDetect = Get-RegValue "$auRes\Detect" 'LastSuccessTime'
        $lastInstall = Get-RegValue "$auRes\Install" 'LastSuccessTime'
        $detectAge = $null
        if ($lastDetect) { try { $detectAge = [math]::Round(((Get-Date) - [datetime]$lastDetect).TotalDays, 1) } catch { } }
        $data.UpdateStatus = [pscustomobject]@{
            LastDetectSuccess  = $lastDetect
            LastDetectAgeDays  = $detectAge
            LastInstallSuccess = $lastInstall
            RebootPending      = ($pending.Count -gt 0)
            RebootPendingFrom  = ($pending -join ', ')
        }
    }
    catch { Add-CollectorError 'Windows Update currency' $_.Exception.Message }

    # --------------------------------------- Permissive inbound firewall rules
    try {
        $permissive = @()
        $inRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)
        if ($inRules.Count -gt 0) {
            # Bulk-fetch the filters once and join by InstanceID; querying filters
            # per rule turns a 2-second job into a 2-minute one.
            $portOf = @{}; foreach ($f in Get-NetFirewallPortFilter) { $portOf[$f.InstanceID] = $f }
            $addrOf = @{}; foreach ($f in Get-NetFirewallAddressFilter) { $addrOf[$f.InstanceID] = $f }
            $appOf  = @{}; foreach ($f in Get-NetFirewallApplicationFilter) { $appOf[$f.InstanceID] = $f }
            foreach ($r in $inRules) {
                $pf = $portOf[$r.InstanceID]; $af = $addrOf[$r.InstanceID]
                $ap = $appOf[$r.InstanceID]
                if (-not $pf -or -not $af) { continue }
                $remote = (@($af.RemoteAddress) -join ',')
                $lport  = (@($pf.LocalPort) -join ',')
                $proto  = [string]$pf.Protocol
                $anyRemote = ($remote -eq 'Any' -or $remote -eq '*')
                $anyPort   = ($lport -eq 'Any' -or $lport -eq '*')
                $anyProto  = ($proto -eq 'Any')
                if ($anyRemote -and ($anyPort -or $anyProto)) {
                    $prog = 'Any'
                    if ($ap -and $ap.Program) { $prog = [string]$ap.Program }
                    $permissive += [pscustomobject]@{
                        Rule        = (Trunc ([string]$r.DisplayName) 90)
                        Profile     = [string]$r.Profile
                        Protocol    = $proto
                        LocalPort   = $lport
                        RemoteAddr  = $remote
                        Program     = (Trunc $prog 90)
                        Scoped      = $(if ($prog -eq 'Any') { 'No - any program' } else { 'Program-scoped' })
                        Group       = (Trunc ([string]$r.DisplayGroup) 60)
                    }
                }
            }
        }
        $data.FirewallPermissiveCount = $permissive.Count
        $data.FirewallPermissive = @($permissive | Sort-Object Scoped, Rule | Select-Object -First 80)
    }
    catch { Add-CollectorError 'Permissive firewall rules' $_.Exception.Message }


    # ------------------------------------------------------ Persistence triage
    try {
        # Paths a non-admin can typically write to. A service or scheduled task
        # launching from one of these is a classic privilege-escalation and
        # persistence pattern worth a human look.
        $writable = @(
            "$env:SystemDrive\Users\", "$env:SystemDrive\ProgramData\", "$env:SystemDrive\Temp\",
            "$env:windir\Temp\", "$env:SystemDrive\PerfLogs\", "$env:PUBLIC\", "$env:SystemDrive\Intel\",
            "$env:SystemDrive\Windows\Tasks\", "$env:SystemDrive\Windows\Tracing\"
        )
        function Test-WritablePath {
            param([string]$Path)
            if (-not $Path) { return $false }
            foreach ($w in $writable) { if ($Path -like "$w*") { return $true } }
            return $false
        }
        function Get-ExePath {
            # Pull the executable out of a service PathName / task action.
            param([string]$Cmd)
            if (-not $Cmd) { return '' }
            $c = $Cmd.Trim()
            if ($c.StartsWith('"')) {
                $end = $c.IndexOf('"', 1)
                if ($end -gt 1) { return $c.Substring(1, $end - 1) }
                return $c.Trim('"')
            }
            $m = [regex]::Match($c, '^(.*?\.(exe|bat|cmd|ps1|vbs|js|scr|dll))(\s|$)', 'IgnoreCase')
            if ($m.Success) { return $m.Groups[1].Value }
            $sp = $c.IndexOf(' ')
            if ($sp -gt 0) { return $c.Substring(0, $sp) }
            return $c
        }

        $svcFindings = @()
        foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $pathName = [string]$svc.PathName
            if (-not $pathName) { continue }
            $exe = Get-ExePath $pathName
            $reasons = @()
            # Unquoted path containing a space: Windows will try each prefix in
            # turn, so C:\Program.exe would run instead of C:\Program Files\...
            if (-not $pathName.Trim().StartsWith('"') -and $exe -match '\s' -and $pathName -match '^[A-Za-z]:\\') {
                $reasons += 'Unquoted path with spaces'
            }
            if (Test-WritablePath $exe) { $reasons += 'Runs from a user-writable location' }
            if ($reasons.Count -gt 0) {
                $svcFindings += [pscustomobject]@{
                    Service   = [string]$svc.Name
                    Display   = (Trunc ([string]$svc.DisplayName) 60)
                    State     = [string]$svc.State
                    StartMode = [string]$svc.StartMode
                    RunAs     = [string]$svc.StartName
                    Concern   = ($reasons -join '; ')
                    Path      = (Trunc $pathName 220)
                }
            }
        }
        $data.SuspectServices = @($svcFindings | Sort-Object Concern, Service)

        $taskFindings = @()
        try {
            foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
                # Skip the thousands of inbox Microsoft tasks; they are noise here.
                if ([string]$t.TaskPath -like '\Microsoft\*') { continue }
                if ([string]$t.State -eq 'Disabled') { continue }
                foreach ($act in @($t.Actions)) {
                    $ex = [string]$act.Execute
                    if (-not $ex) { continue }
                    $exp = Get-ExePath ([System.Environment]::ExpandEnvironmentVariables($ex))
                    if (-not (Test-WritablePath $exp)) { continue }
                    $last = $null; $lastResult = $null
                    try {
                        $ti = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                        $last = $ti.LastRunTime; $lastResult = $ti.LastTaskResult
                    }
                    catch { }
                    $taskFindings += [pscustomobject]@{
                        Task       = (Trunc ("$($t.TaskPath)$($t.TaskName)") 80)
                        State      = [string]$t.State
                        RunAs      = [string]$t.Principal.UserId
                        RunLevel   = [string]$t.Principal.RunLevel
                        Author     = (Trunc ([string]$t.Author) 40)
                        LastRun    = $last
                        LastResult = $lastResult
                        Concern    = 'Runs from a user-writable location'
                        Command    = (Trunc "$ex $($act.Arguments)" 220)
                    }
                }
            }
        }
        catch { Add-CollectorError 'Scheduled task triage' $_.Exception.Message }
        $data.SuspectTasks = @($taskFindings | Sort-Object Task)
    }
    catch { Add-CollectorError 'Persistence triage' $_.Exception.Message }

    # ------------------------------------------------------------ Audit policy
    try {
        $apRaw = auditpol /get /category:* /r 2>$null
        $data.AuditPolicy = @($apRaw | ConvertFrom-Csv | ForEach-Object {
            [pscustomobject]@{
                Subcategory = [string]$_.Subcategory
                Setting     = [string]$_.'Inclusion Setting'
            }
        })
    }
    catch { Add-CollectorError 'Audit policy (auditpol)' $_.Exception.Message }

    # -------------------------------------------- Identity / account change events
    try {
        $idMap = @{
            4720 = 'User account CREATED';        4722 = 'User account enabled'
            4723 = 'Password change attempted';   4724 = 'Password RESET by admin/other'
            4725 = 'User account disabled';       4726 = 'User account DELETED'
            4728 = 'Member added to GLOBAL group'; 4732 = 'Member added to LOCAL group'
            4756 = 'Member added to UNIVERSAL group'
            4740 = 'Account LOCKED OUT';          4767 = 'Account unlocked'
            4719 = 'AUDIT POLICY CHANGED';        1102 = 'SECURITY LOG CLEARED'
        }
        $data.IdentityEvents = @(Get-EventsSafe -LogName 'Security' -Ids @(4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4740, 4767, 4719, 1102) -Max 500 |
            ForEach-Object {
                $d = Get-EvData $_
                $act = 'Audited'
                if ($_.Id -eq 1102) { $act = 'Alert' }
                $target = [string]$d['TargetUserName']
                $member = [string]$d['MemberName']
                $subj   = [string]$d['SubjectUserName']
                $detail = "Target: $target"
                if ($member) { $detail += "  Member: $member" }
                if ($subj)   { $detail += "  By: $subj" }
                [pscustomobject]@{
                    Time     = $_.TimeCreated
                    Id       = $_.Id
                    Source   = 'Security'
                    Category = [string]$idMap[[int]$_.Id]
                    Action   = $act
                    Detail   = (Trunc $detail 600)
                }
            })
    }
    catch { Add-CollectorError 'Identity change events' $_.Exception.Message }

    # ------------------------------------------------------------------ Logons
    try {
        $ltMap = @{
            '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'; '7' = 'Unlock'
            '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive (RDP)'; '11' = 'CachedInteractive'
        }
        $failed = @(Get-EventsSafe -LogName 'Security' -Ids @(4625) -Max 1000 | ForEach-Object {
            $d = Get-EvData $_
            $lt = $ltMap[[string]$d['LogonType']]
            if (-not $lt) { $lt = [string]$d['LogonType'] }
            [pscustomobject]@{
                Time        = $_.TimeCreated
                Account     = "$($d['TargetDomainName'])\$($d['TargetUserName'])"
                LogonType   = $lt
                SourceIP    = [string]$d['IpAddress']
                Workstation = [string]$d['WorkstationName']
                Status      = [string]$d['Status']
            }
        })
        $data.FailedLogonCount = $failed.Count
        $data.FailedLogons = @($failed | Select-Object -First 60)
        $data.FailedLogonTop = @($failed | Group-Object Account | Sort-Object Count -Descending |
            Select-Object -First 12 | ForEach-Object {
                [pscustomobject]@{ Account = $_.Name; Failures = $_.Count }
            })
    }
    catch { Add-CollectorError 'Failed logons (4625)' $_.Exception.Message }

    try {
        $ltMap2 = @{
            '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'; '7' = 'Unlock'
            '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive (RDP)'; '11' = 'CachedInteractive'
        }
        $success = @(Get-EventsSafe -LogName 'Security' -Ids @(4624) -Max 1200 | ForEach-Object {
            $d = Get-EvData $_
            $lt = $ltMap2[[string]$d['LogonType']]
            if (-not $lt) { $lt = [string]$d['LogonType'] }
            [pscustomobject]@{
                Time    = $_.TimeCreated
                Account = "$($d['TargetDomainName'])\$($d['TargetUserName'])"
                Type    = $lt
            }
        })
        $data.LogonSummary = @($success | Group-Object Type | Sort-Object Count -Descending | ForEach-Object {
            $grp = @($_.Group | Sort-Object Time -Descending)
            [pscustomobject]@{
                LogonType   = $_.Name
                Count       = $_.Count
                UniqueAccounts = @($_.Group | Select-Object -ExpandProperty Account -Unique).Count
                MostRecent  = $grp[0].Time
                LastAccount = $grp[0].Account
            }
        })
    }
    catch { Add-CollectorError 'Logon summary (4624)' $_.Exception.Message }

    # ------------------------------------------- Device identity (dsregcmd)
    try {
        $dsRows = @()
        $dsRaw = & "$env:windir\System32\dsregcmd.exe" /status 2>$null
        if ($dsRaw) {
            $wanted = @(
                'AzureAdJoined', 'EnterpriseJoined', 'DomainJoined', 'DomainName', 'WorkplaceJoined',
                'DeviceId', 'TenantName', 'TenantId', 'AzureAdPrt', 'AzureAdPrtUpdateTime',
                'WamDefaultSet', 'MdmUrl', 'MdmComplianceUrl', 'KeySignTest', 'DeviceAuthStatus'
            )
            foreach ($line in $dsRaw) {
                if ($line -match '^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*:\s(.+)$') {
                    $k = ($Matches[1] -replace '\s', '')
                    $v = $Matches[2].Trim()
                    if ($wanted -contains $k) {
                        $dsRows += [pscustomobject]@{ Property = $k; Value = $v }
                    }
                }
            }
        }
        $data.DsRegStatus = $dsRows
    }
    catch { Add-CollectorError 'dsregcmd /status' $_.Exception.Message }

    # ----------------------------------------------- Domain secure channel
    try {
        $data.SecureChannel = [pscustomobject]@{ Checked = $false; Healthy = $null; Detail = 'Not domain joined' }
        if ($data.Meta -and $data.Meta.PartOfDomain) {
            # nltest writes to stderr precisely when the channel is broken; with
            # EAP=Stop the 2>&1 redirect would turn that into a terminating error
            # and we'd never reach the "broken" verdict. Relax EAP for this call.
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            $sc = & "$env:windir\System32\nltest.exe" "/sc_query:$($data.Meta.Domain)" 2>&1
            $ErrorActionPreference = $prevEap
            $scText = ($sc | Out-String).Trim()
            $healthy = ($scText -match 'Success')
            $dc = ''
            foreach ($line in $sc) {
                if ($line -match 'Trusted DC Name\s+(.+)$') { $dc = $Matches[1].Trim() }
            }
            $data.SecureChannel = [pscustomobject]@{
                Checked = $true
                Healthy = $healthy
                Detail  = (Trunc "DC: $dc  $scText" 600)
            }
        }
    }
    catch { Add-CollectorError 'Secure channel (nltest)' $_.Exception.Message }

    # ------------------------------------------------- Local admins and users
    try {
        $admins = @()
        try {
            $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Member = [string]$_.Name
                    Type   = [string]$_.ObjectClass
                    Source = [string]$_.PrincipalSource
                }
            })
        }
        catch {
            # Get-LocalGroupMember chokes on orphaned SIDs on some builds; fall back to net.exe
            $grpName = 'Administrators'
            try { $grpName = (Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' }).Name } catch { }
            $net = net localgroup "$grpName" 2>$null
            $inList = $false
            foreach ($line in $net) {
                if ($line -match '^-{5,}') { $inList = $true; continue }
                if ($line -match 'command completed') { $inList = $false; continue }
                if ($inList -and $line.Trim()) {
                    $admins += [pscustomobject]@{ Member = $line.Trim(); Type = ''; Source = '(via net.exe)' }
                }
            }
        }
        $data.LocalAdmins = $admins
    }
    catch { Add-CollectorError 'Local administrators' $_.Exception.Message }

    try {
        $data.LocalUsers = @(Get-LocalUser | ForEach-Object {
            [pscustomobject]@{
                Name             = [string]$_.Name
                Enabled          = $_.Enabled
                LastLogon        = $_.LastLogon
                PasswordLastSet  = $_.PasswordLastSet
                PasswordRequired = $_.PasswordRequired
                Description      = (Trunc ([string]$_.Description) 80)
            }
        })
    }
    catch { Add-CollectorError 'Local users' $_.Exception.Message }

    # ------------------------------------------------------- Active sessions
    try {
        $q = & "$env:windir\System32\quser.exe" 2>$null
        $sessions = @()
        if ($q) { $sessions = @($q | ForEach-Object { [string]$_ }) }
        $data.Sessions = $sessions
    }
    catch { $data.Sessions = @('No interactive sessions (or quser unavailable).') }

    # ------------------------------------------------------------ Group Policy
    try {
        $gpText = (& "$env:windir\System32\gpresult.exe" /r /scope:computer 2>&1 | Out-String)
        if ($gpText.Length -gt 15000) { $gpText = $gpText.Substring(0, 15000) + "`n... (truncated)" }
        $applied = @()
        $inSection = $false
        foreach ($line in ($gpText -split "`r?`n")) {
            if ($line -match 'Applied Group Policy Objects') { $inSection = $true; continue }
            if ($inSection) {
                $t = $line.Trim()
                if ($t -match '^-{3,}$') { continue }
                if (-not $t -or $line -match 'The following GPOs|was filtered out|^The computer') { $inSection = $false; continue }
                $applied += $t
            }
        }
        $lastRefresh = $null
        try {
            $gpEvt = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Id = @(8000, 8001, 8004, 8005) } -MaxEvents 1 -ErrorAction Stop
            if ($gpEvt) { $lastRefresh = $gpEvt.TimeCreated }
        }
        catch { }
        $data.Gpo = [pscustomobject]@{
            AppliedGpos = [string[]]$applied
            LastRefresh = $lastRefresh
            RawText     = $gpText
        }
    }
    catch { Add-CollectorError 'Group Policy (gpresult)' $_.Exception.Message }

    # -------------------------------------------------- MDM (Intune) enrollment
    try {
        $mdm = @()
        $enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
        if (Test-Path $enrollRoot) {
            foreach ($k in @(Get-ChildItem $enrollRoot -ErrorAction SilentlyContinue)) {
                $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                if ($p -and $p.UPN) {
                    $mdm += [pscustomobject]@{
                        UPN             = [string]$p.UPN
                        Provider        = [string]$p.ProviderID
                        EnrollmentState = $p.EnrollmentState
                        DiscoveryUrl    = (Trunc ([string]$p.DiscoveryServiceFullURL) 100)
                    }
                }
            }
        }
        $data.MdmEnrollment = $mdm
    }
    catch { Add-CollectorError 'MDM enrollment' $_.Exception.Message }

    # ---------------------------------------------------------------- Hotfixes
    try {
        $data.Hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 12 | ForEach-Object {
            [pscustomobject]@{
                HotFixID    = [string]$_.HotFixID
                Description = [string]$_.Description
                InstalledOn = $_.InstalledOn
                InstalledBy = [string]$_.InstalledBy
            }
        })
    }
    catch { Add-CollectorError 'Hotfixes' $_.Exception.Message }

    $data.Errors = @($script:errors)
    $data
}

# ===========================================================================
#  GUI - XAML
# ===========================================================================
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Security Health Dashboard"
        Height="880" Width="1400" MinHeight="640" MinWidth="1000"
        WindowStartupLocation="CenterScreen"
        Background="#FF14141A" FontFamily="Segoe UI" FontSize="13" Foreground="#FFE8E8EE">
  <Window.Resources>
    <SolidColorBrush x:Key="PanelBg"  Color="#FF1B1B22"/>
    <SolidColorBrush x:Key="CardBg"   Color="#FF23232C"/>
    <SolidColorBrush x:Key="MutedFg"  Color="#FF9B9BAA"/>
    <SolidColorBrush x:Key="Accent"   Color="#FF4FC3F7"/>

    <Style TargetType="GroupBox">
      <Setter Property="Foreground" Value="#FFB9B9C6"/>
      <Setter Property="BorderBrush" Value="#FF33333F"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Margin" Value="6"/>
      <Setter Property="Padding" Value="6"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#FF2A2A35"/>
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="BorderBrush" Value="#FF444452"/>
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="CaretBrush" Value="#FFE8E8EE"/>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF2F6FED"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Opacity" Value="0.85"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="bd" Property="Background" Value="#FF3A3A46"/>
                <Setter Property="Foreground" Value="#FF80808E"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>

    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#FF2A2A35"/>
      <Setter Property="BorderBrush" Value="#FF444452"/>
      <Setter Property="Padding" Value="6,4"/>
    </Style>

    <Style TargetType="TabControl">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
    </Style>

    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="#FFB9B9C6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="bd" Background="Transparent" CornerRadius="4,4,0,0" Padding="14,8" Margin="2,4,2,0">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="Background" Value="#FF23232C"/>
                <Setter Property="Foreground" Value="#FFFFFFFF"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="#FF20202A"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="RowBackground" Value="#FF1D1D25"/>
      <Setter Property="AlternatingRowBackground" Value="#FF22222B"/>
      <Setter Property="BorderBrush" Value="#FF33333F"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="GridLinesVisibility" Value="None"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <!-- Columns are built explicitly in Set-GridSource so that user column
           widths, sort arrows and filter markers survive every refilter. -->
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserResizeColumns" Value="True"/>
      <Setter Property="CanUserSortColumns" Value="True"/>
      <Setter Property="SelectionMode" Value="Extended"/>
      <Setter Property="ClipboardCopyMode" Value="IncludeHeader"/>
      <Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
      <Setter Property="EnableColumnVirtualization" Value="False"/>
      <!-- No MaxColumnWidth: capping it also caps manual drag-resize, which is
           what previously made the Detail column impossible to widen. -->
    </Style>

    <!-- Transparent grab handles on each header edge. These MUST be present in a
         custom DataGridColumnHeader template or drag-to-resize stops working. -->
    <Style x:Key="GripperStyle" TargetType="Thumb">
      <Setter Property="Width" Value="8"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Cursor" Value="SizeWE"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border Background="{TemplateBinding Background}"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#FF2A2A35"/>
      <Setter Property="Foreground" Value="#FFB9B9C6"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridColumnHeader">
            <Grid>
              <Border x:Name="hdrBd" Background="{TemplateBinding Background}"
                      BorderBrush="#FF33333F" BorderThickness="0,0,1,1">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <ContentPresenter Grid.Column="0" Margin="8,5,4,5"
                                    VerticalAlignment="Center" HorizontalAlignment="Left"/>
                  <TextBlock x:Name="SortArrow" Grid.Column="1" Text="" FontSize="9"
                             VerticalAlignment="Center" Margin="0,0,3,0" Foreground="#FF4FC3F7"/>
                  <Button x:Name="PART_FilterButton" Grid.Column="2" Content="&#x25BE;"
                          FontSize="10" Width="16" Height="16" Padding="0" Margin="0,0,4,0"
                          Background="Transparent" Foreground="#FF80808E" BorderThickness="0"
                          Focusable="False" Cursor="Hand" VerticalAlignment="Center"
                          ToolTip="Filter and sort this column"/>
                </Grid>
              </Border>
              <Thumb x:Name="PART_LeftHeaderGripper" HorizontalAlignment="Left"
                     Style="{StaticResource GripperStyle}"/>
              <Thumb x:Name="PART_RightHeaderGripper" HorizontalAlignment="Right"
                     Style="{StaticResource GripperStyle}"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="SortDirection" Value="Ascending">
                <Setter TargetName="SortArrow" Property="Text" Value="&#x25B2;"/>
              </Trigger>
              <Trigger Property="SortDirection" Value="Descending">
                <Setter TargetName="SortArrow" Property="Text" Value="&#x25BC;"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="hdrBd" Property="Background" Value="#FF353542"/>
              </Trigger>
              <!-- The trailing filler header has no Column; hide its glyph. -->
              <DataTrigger Binding="{Binding RelativeSource={RelativeSource Self}, Path=Column}" Value="{x:Null}">
                <Setter TargetName="PART_FilterButton" Property="Visibility" Value="Collapsed"/>
              </DataTrigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#FF2F6FED"/>
          <Setter Property="Foreground" Value="White"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="ListBox">
      <Setter Property="Background" Value="#FF1D1D25"/>
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="BorderBrush" Value="#FF33333F"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <!-- ============================ Top bar ============================ -->
    <Border DockPanel.Dock="Top" Background="{StaticResource PanelBg}" Padding="14,10">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="Target(s):" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource MutedFg}"/>
        <TextBox x:Name="TxtComputer" Width="300" VerticalAlignment="Center"
                 ToolTip="One or more computer names, separated by commas or spaces. Use localhost for this machine."/>
        <TextBlock Text="Lookback:" VerticalAlignment="Center" Margin="18,0,8,0" Foreground="{StaticResource MutedFg}"/>
        <ComboBox x:Name="CmbLookback" Width="110" VerticalAlignment="Center">
          <ComboBoxItem Content="24 hours" Tag="1"/>
          <ComboBoxItem Content="3 days"   Tag="3"/>
          <ComboBoxItem Content="7 days"   Tag="7"/>
          <ComboBoxItem Content="14 days"  Tag="14"/>
          <ComboBoxItem Content="30 days"  Tag="30"/>
        </ComboBox>
        <CheckBox x:Name="ChkCred" Content="Alternate credentials" Margin="18,0,0,0"
                  ToolTip="Connect as someone other than you. Required for workgroup targets."/>
        <Button x:Name="BtnCred" Content="Set..." Width="62" Margin="8,0,0,0" Background="#FF3A3A46"
                ToolTip="Enter or replace the credential used for scans"/>
        <Button x:Name="BtnScan" Content="Scan" Width="110" Margin="18,0,0,0"/>
        <Button x:Name="BtnExport" Content="Export HTML report" Width="160" Margin="10,0,0,0" IsEnabled="False" Background="#FF3A3A46"/>
        <Button x:Name="BtnSaveBaseline" Content="Save baseline" Width="112" Margin="8,0,0,0" IsEnabled="False" Background="#FF3A3A46"
                ToolTip="Save this scan as a JSON snapshot to compare against later"/>
        <Button x:Name="BtnLoadBaseline" Content="Compare to..." Width="112" Margin="8,0,0,0" Background="#FF3A3A46"
                ToolTip="Load a saved snapshot and show what has changed since"/>
        <Border Width="1" Background="#FF33333F" Margin="16,2,16,2"/>
        <TextBlock Text="Find:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource MutedFg}"/>
        <TextBox x:Name="TxtFind" Width="190" VerticalAlignment="Center"
                 ToolTip="Search every table on every tab. Matches any column."/>
        <Button x:Name="BtnClearFilters" Content="Clear filters" Width="110" Margin="10,0,0,0" Background="#FF3A3A46"
                ToolTip="Reset search, column filters and sorting on all tables"/>
      </StackPanel>
    </Border>

    <!-- =========================== Status bar ========================== -->
    <Border DockPanel.Dock="Bottom" Background="{StaticResource PanelBg}" Padding="14,7">
      <DockPanel>
        <ProgressBar x:Name="Progress" Width="170" Height="12" DockPanel.Dock="Right"
                     IsIndeterminate="True" Visibility="Collapsed" Foreground="{StaticResource Accent}" Background="#FF2A2A35"/>
        <TextBlock x:Name="TxtFilterInfo" DockPanel.Dock="Right" Margin="0,0,18,0"
                   Foreground="{StaticResource Accent}" Text=""/>
        <TextBlock x:Name="TxtStatus" Text="Ready. Enter a computer name and click Scan." Foreground="{StaticResource MutedFg}"/>
      </DockPanel>
    </Border>

    <!-- ============================== Tabs ============================= -->
    <TabControl x:Name="Tabs">

      <TabItem Header="Fleet">
        <DockPanel Margin="4">
          <Border DockPanel.Dock="Top" Background="{StaticResource CardBg}" CornerRadius="4" Padding="10,8" Margin="6">
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnOpenHost" Content="Open selected host" Width="150"/>
              <TextBlock x:Name="TxtFleetHeader" VerticalAlignment="Center" Margin="16,0,0,0"
                         Foreground="{StaticResource MutedFg}" TextWrapping="Wrap"
                         Text="Scan one or more targets. Separate names with commas or spaces."/>
            </StackPanel>
          </Border>
          <DataGrid x:Name="GridFleet" Margin="6"/>
        </DockPanel>
      </TabItem>

      <TabItem Header="Overview">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="8">
            <TextBlock x:Name="TxtScanHeader" FontSize="16" FontWeight="SemiBold" Margin="6,4,6,10"
                       Text="No scan yet - enter a target and click Scan."/>
            <WrapPanel x:Name="PnlCards"/>
            <TextBlock Text="Attention items" FontSize="15" FontWeight="SemiBold" Margin="6,16,6,6"/>
            <DataGrid x:Name="GridFindings" MaxHeight="340" Margin="6"/>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="Defender">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="3*"/>
            <RowDefinition Height="2*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Engine and protection status" Grid.Row="0" Grid.Column="0">
            <DataGrid x:Name="GridDefStatus"/>
          </GroupBox>
          <GroupBox Header="Preferences (policy-effective)" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridDefPrefs"/>
          </GroupBox>
          <GroupBox Header="Attack Surface Reduction rules" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridAsr"/>
          </GroupBox>
          <GroupBox Header="Exclusions and CFA lists (review these)" Grid.Row="1" Grid.Column="1">
            <DataGrid x:Name="GridExclusions"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Detections">
        <Grid Margin="4">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Defender threat detections (most recent first)">
            <DataGrid x:Name="GridThreats"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Events (Blocked / Audited / Allowed)">
        <DockPanel Margin="4">
          <Border DockPanel.Dock="Top" Background="{StaticResource CardBg}" CornerRadius="4" Padding="10,8" Margin="6">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Action:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{StaticResource MutedFg}"/>
              <Button x:Name="BtnEvtAll"      Content="All"      Width="66" Padding="8,5" Background="#FF3A3A46"/>
              <Button x:Name="BtnEvtBlocked"  Content="Blocked"  Width="82" Padding="8,5" Margin="5,0,0,0" Background="#FF3A3A46"/>
              <Button x:Name="BtnEvtAudited"  Content="Audited"  Width="82" Padding="8,5" Margin="5,0,0,0" Background="#FF3A3A46"/>
              <Button x:Name="BtnEvtAllowed"  Content="Allowed"  Width="82" Padding="8,5" Margin="5,0,0,0" Background="#FF3A3A46"/>
              <Button x:Name="BtnEvtDetected" Content="Detected" Width="86" Padding="8,5" Margin="5,0,0,0" Background="#FF3A3A46"/>
              <Button x:Name="BtnEvtAlert"    Content="Alerts"   Width="76" Padding="8,5" Margin="5,0,0,0" Background="#FF3A3A46"/>
              <TextBlock Text="Source:" VerticalAlignment="Center" Margin="18,0,8,0" Foreground="{StaticResource MutedFg}"/>
              <ComboBox x:Name="CmbEvtSource" Width="130" VerticalAlignment="Center"/>
              <TextBlock x:Name="TxtEvtCount" VerticalAlignment="Center" Margin="18,0,0,0" Foreground="{StaticResource MutedFg}"/>
            </StackPanel>
          </Border>
          <DataGrid x:Name="GridEvents" Margin="6"/>
        </DockPanel>
      </TabItem>

      <TabItem Header="Firewall">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Profiles" Grid.Row="0" Grid.Column="0">
            <DataGrid x:Name="GridFwProfiles"/>
          </GroupBox>
          <GroupBox Header="Enabled rule counts" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridFwRules"/>
          </GroupBox>
          <GroupBox Header="Rule changes in window" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridFwChanges"/>
          </GroupBox>
          <GroupBox x:Name="GrpFwBlocked" Header="Blocked connections (Filtering Platform audits, grouped)" Grid.Row="1" Grid.Column="1">
            <DataGrid x:Name="GridFwBlocked"/>
          </GroupBox>
          <GroupBox x:Name="GrpFwPermissive" Header="Permissive inbound rules" Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2">
            <DataGrid x:Name="GridFwPermissive" MaxHeight="240"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="AppLocker / WDAC">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="AppLocker effective policy" Grid.Row="0" Grid.Column="0">
            <DataGrid x:Name="GridAppLockerPolicy"/>
          </GroupBox>
          <GroupBox Header="Device Guard / WDAC / VBS state" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridDeviceGuard"/>
          </GroupBox>
          <GroupBox Header="AppLocker events" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridAppLockerEvents"/>
          </GroupBox>
          <GroupBox Header="Code Integrity events (3076 audit / 3077 block)" Grid.Row="1" Grid.Column="1">
            <DataGrid x:Name="GridCiEvents"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Identity">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <Grid Margin="4">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <GroupBox Header="Device identity (dsregcmd) and domain" Grid.Row="0" Grid.Column="0">
              <StackPanel>
                <DataGrid x:Name="GridDsreg" MaxHeight="260"/>
                <TextBlock x:Name="TxtSecureChannel" Margin="4,8,4,2" TextWrapping="Wrap" Foreground="{StaticResource MutedFg}"/>
              </StackPanel>
            </GroupBox>
            <GroupBox Header="Local Administrators group" Grid.Row="0" Grid.Column="1">
              <DataGrid x:Name="GridLocalAdmins" MaxHeight="290"/>
            </GroupBox>
            <GroupBox Header="Local user accounts" Grid.Row="1" Grid.Column="0">
              <DataGrid x:Name="GridLocalUsers" MaxHeight="260"/>
            </GroupBox>
            <GroupBox Header="Logon summary in window (4624)" Grid.Row="1" Grid.Column="1">
              <StackPanel>
                <DataGrid x:Name="GridLogonSummary" MaxHeight="180"/>
                <TextBlock Text="Active sessions (quser):" Margin="4,8,4,2" Foreground="{StaticResource MutedFg}"/>
                <TextBox x:Name="TxtSessions" IsReadOnly="True" FontFamily="Consolas" MinHeight="50" MaxHeight="90"
                         VerticalScrollBarVisibility="Auto" TextWrapping="NoWrap" HorizontalScrollBarVisibility="Auto"/>
              </StackPanel>
            </GroupBox>
            <GroupBox x:Name="GrpFailed" Header="Failed logons (4625)" Grid.Row="2" Grid.Column="0">
              <StackPanel>
                <DataGrid x:Name="GridFailedTop" MaxHeight="150"/>
                <DataGrid x:Name="GridFailedLogons" MaxHeight="240" Margin="0,8,0,0"/>
              </StackPanel>
            </GroupBox>
            <GroupBox Header="Account / group / audit-policy changes" Grid.Row="2" Grid.Column="1">
              <DataGrid x:Name="GridIdEvents" MaxHeight="400"/>
            </GroupBox>
          </Grid>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="Policies">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Applied computer GPOs" Grid.Row="0" Grid.Column="0">
            <StackPanel>
              <TextBlock x:Name="TxtGpRefresh" Margin="4,2,4,6" Foreground="{StaticResource MutedFg}"/>
              <ListBox x:Name="LstGpos" MinHeight="90" MaxHeight="170"/>
            </StackPanel>
          </GroupBox>
          <GroupBox Header="MDM (Intune) enrollment" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridMdm" MinHeight="90" MaxHeight="170"/>
          </GroupBox>
          <GroupBox Header="Effective audit policy (auditpol)" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridAuditPol"/>
          </GroupBox>
          <GroupBox Header="gpresult /r (computer scope)" Grid.Row="1" Grid.Column="1">
            <TextBox x:Name="TxtGpresult" IsReadOnly="True" FontFamily="Consolas" FontSize="12"
                     VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="System">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Security-relevant services" Grid.Row="0" Grid.Column="0">
            <DataGrid x:Name="GridServices"/>
          </GroupBox>
          <GroupBox Header="Platform security (Secure Boot, TPM, LSA, SmartScreen, UAC)" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridSecSettings"/>
          </GroupBox>
          <GroupBox Header="BitLocker volumes" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridBitLocker"/>
          </GroupBox>
          <GroupBox Header="Recent hotfixes" Grid.Row="1" Grid.Column="1">
            <DataGrid x:Name="GridHotfix"/>
          </GroupBox>
          <GroupBox x:Name="GrpSmartScreen" Header="SmartScreen and Smart App Control"
                    Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="2">
            <DataGrid x:Name="GridSmartScreen" MaxHeight="230"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Changes">
        <DockPanel Margin="4">
          <Border DockPanel.Dock="Top" Background="{StaticResource CardBg}" CornerRadius="4" Padding="10,8" Margin="6">
            <StackPanel Orientation="Horizontal">
              <TextBlock x:Name="TxtDiffHeader" VerticalAlignment="Center" Foreground="{StaticResource MutedFg}"
                         Text="No baseline loaded. Use &quot;Compare to...&quot; to pick a saved snapshot."/>
              <Button x:Name="BtnClearBaseline" Content="Clear baseline" Width="118" Margin="18,0,0,0"
                      Background="#FF3A3A46" IsEnabled="False"/>
            </StackPanel>
          </Border>
          <DataGrid x:Name="GridDiff" Margin="6"/>
        </DockPanel>
      </TabItem>

      <TabItem Header="Hardening">
        <Grid Margin="4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="PowerShell logging and v2 engine" Grid.Row="0" Grid.Column="0">
            <DataGrid x:Name="GridPsLogging"/>
          </GroupBox>
          <GroupBox Header="LAPS (local administrator password management)" Grid.Row="0" Grid.Column="1">
            <DataGrid x:Name="GridLaps"/>
          </GroupBox>
          <GroupBox Header="Exploit Protection (system-wide)" Grid.Row="1" Grid.Column="0">
            <DataGrid x:Name="GridExploit"/>
          </GroupBox>
          <GroupBox Header="Windows Update currency" Grid.Row="1" Grid.Column="1">
            <DataGrid x:Name="GridUpdate"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Persistence">
        <Grid Margin="4">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox x:Name="GrpSuspectSvc" Header="Services from user-writable or unquoted paths" Grid.Row="0">
            <DataGrid x:Name="GridSuspectSvc"/>
          </GroupBox>
          <GroupBox x:Name="GrpSuspectTask" Header="Non-Microsoft scheduled tasks from user-writable paths" Grid.Row="1">
            <DataGrid x:Name="GridSuspectTask"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem Header="Collection errors">
        <GroupBox Header="Collectors that reported problems on the target (partial data is normal)" Margin="4">
          <DataGrid x:Name="GridErrors"/>
        </GroupBox>
      </TabItem>

    </TabControl>
  </DockPanel>
</Window>
'@

# ===========================================================================
#  Build the window and wire up element references
# ===========================================================================
$window = $null
$ui = @{}
if (-not $Quiet) {
$reader = [System.Xml.XmlNodeReader]::new([xml]$xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

foreach ($name in @(
    'TxtComputer', 'CmbLookback', 'ChkCred', 'BtnScan', 'BtnExport', 'TxtStatus', 'Progress', 'Tabs',
    'BtnCred', 'TxtFind', 'BtnClearFilters', 'TxtFilterInfo',
    'TxtScanHeader', 'PnlCards', 'GridFindings',
    'GridDefStatus', 'GridDefPrefs', 'GridAsr', 'GridExclusions', 'GridThreats',
    'BtnEvtAll', 'BtnEvtBlocked', 'BtnEvtAudited', 'BtnEvtAllowed', 'BtnEvtDetected', 'BtnEvtAlert',
    'CmbEvtSource', 'TxtEvtCount', 'GridEvents',
    'GridFwProfiles', 'GridFwRules', 'GridFwChanges', 'GridFwBlocked', 'GrpFwBlocked',
    'GridAppLockerPolicy', 'GridDeviceGuard', 'GridAppLockerEvents', 'GridCiEvents',
    'GridDsreg', 'TxtSecureChannel', 'GridLocalAdmins', 'GridLocalUsers', 'GridLogonSummary', 'TxtSessions',
    'GridFailedTop', 'GridFailedLogons', 'GridIdEvents', 'GrpFailed',
    'TxtGpRefresh', 'LstGpos', 'GridMdm', 'GridAuditPol', 'TxtGpresult',
    'GridServices', 'GridSecSettings', 'GridBitLocker', 'GridHotfix', 'GridErrors',
    'GridSmartScreen', 'GrpSmartScreen',
    'GridPsLogging', 'GridLaps', 'GridExploit', 'GridUpdate',
    'GridSuspectSvc', 'GrpSuspectSvc', 'GridSuspectTask', 'GrpSuspectTask',
    'GridFwPermissive', 'GrpFwPermissive',
    'BtnSaveBaseline', 'BtnLoadBaseline', 'BtnClearBaseline', 'TxtDiffHeader', 'GridDiff',
    'GridFleet', 'TxtFleetHeader', 'BtnOpenHost'
)) {
    $ui[$name] = $window.FindName($name)
}

if ($startupTargets.Count -gt 0) { $ui.TxtComputer.Text = ($startupTargets -join ', ') }
$lookbackIndex = switch ($LookbackDays) { 1 { 0 } 3 { 1 } 7 { 2 } 14 { 3 } 30 { 4 } default { 2 } }
$ui.CmbLookback.SelectedIndex = $lookbackIndex
}   # end if (-not $Quiet) - window construction

$script:LastScan     = $null
$script:AllEvents    = @()
$script:Baseline     = $null   # loaded snapshot wrapper
# NOT $script:BaselinePath: at script scope that is the -BaselinePath PARAMETER,
# and assigning '' to it would silently erase the caller's value. Same trap as
# $script:Credential vs the -Credential parameter.
$script:CurrentBaselinePath = ''
$script:DiffRows     = @()
$script:FleetRows    = @()
$script:FleetJobs    = @()
$script:Pool         = $null
$script:ScanStopwatch = $null

# ===========================================================================
#  Credential handling
#  One credential per session, reused across scans. Prompting on every scan
#  makes iterative triage painful, and re-typing invites typos and lockouts.
# ===========================================================================
function Update-CredentialUi {
    # Deliberately asymmetric: the else branch never writes IsChecked. Clearing it
    # here would recurse, because Add_Unchecked calls Clear-ScanCredential, which
    # calls straight back into this function. Leave the asymmetry alone.
    if ($script:ScanCredential) {
        $ui.ChkCred.Content = "Alternate credentials ($($script:ScanCredential.UserName))"
        $ui.ChkCred.IsChecked = $true
        $ui.BtnCred.Content = 'Change...'
    }
    else {
        $ui.ChkCred.Content = 'Alternate credentials'
        $ui.BtnCred.Content = 'Set...'
    }
}

function Request-ScanCredential {
    param([switch]$Silent)
    $target = $ui.TxtComputer.Text.Trim()
    $msg = 'Credentials to connect with'
    if ($target) { $msg = "Credentials to connect to $target" }
    $c = $null
    try { $c = Get-Credential -Message $msg } catch { }
    if ($c) {
        $script:ScanCredential = $c
        Update-CredentialUi
        $ui.TxtStatus.Text = "Scans will connect as $($c.UserName)."
        return $true
    }
    if (-not $Silent) { $ui.TxtStatus.Text = 'Credential entry cancelled.' }
    return $false
}

function Clear-ScanCredential {
    $script:ScanCredential = $null
    Update-CredentialUi
}

# Reflect a -Credential supplied at launch (must run after the helpers exist).
if (-not $Quiet) { Update-CredentialUi }

# ===========================================================================
#  Rendering helpers
# ===========================================================================
$script:BrushConv = $null
if (-not $Quiet) { $script:BrushConv = New-Object System.Windows.Media.BrushConverter }
$script:StateColors = @{
    Good = '#FF3FB68B'; Warn = '#FFE7B549'; Bad = '#FFE36262'; Info = '#FF8A8A99'
}
$script:ModeMaps = @{
    Maps       = @{ 0 = 'Disabled'; 1 = 'Basic'; 2 = 'Advanced' }
    CloudBlock = @{ 0 = 'Default'; 2 = 'High'; 4 = 'High+'; 6 = 'Zero tolerance' }
    Pua        = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'Audit' }
    OnOffAudit = @{ 0 = 'Disabled'; 1 = 'Enabled (block)'; 2 = 'Audit' }
    Samples    = @{ 0 = 'Always prompt'; 1 = 'Send safe samples'; 2 = 'Never send'; 3 = 'Send all samples' }
}

function Format-Value {
    param($v)
    if ($null -eq $v) { return '' }
    if ($v -is [datetime]) { return $v.ToString('yyyy-MM-dd HH:mm') }
    if ($v -is [System.Array] -or $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
        return (@($v | ForEach-Object { [string]$_ }) -join ', ')
    }
    return [string]$v
}

function New-NVRows {
    # Turn any object's properties into Setting/Value rows for a two-column grid.
    param($obj)
    if (-not $obj) { return @() }
    @($obj.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Setting = $_.Name; Value = (Format-Value $_.Value) }
    })
}

function Get-Section {
    param($data, [string]$key)
    if ($data -and $data.ContainsKey($key)) { return $data[$key] }
    return $null
}

function Get-ArrSection {
    # Array-context accessor: missing/null sections come back as an empty array,
    # never as @($null) (which would break .Count logic).
    param($data, [string]$key)
    $v = Get-Section $data $key
    if ($null -eq $v) { return @() }
    return @($v | Where-Object { $null -ne $_ })
}

function Add-Card {
    param([string]$Title, [string]$Value, [string]$Sub, [string]$State = 'Info')
    $color = $script:StateColors[$State]
    if (-not $color) { $color = $script:StateColors.Info }

    $border = New-Object System.Windows.Controls.Border
    $border.Background = $script:BrushConv.ConvertFromString('#FF23232C')
    $border.CornerRadius = New-Object System.Windows.CornerRadius 6
    $border.BorderThickness = New-Object System.Windows.Thickness 4, 0, 0, 0
    $border.BorderBrush = $script:BrushConv.ConvertFromString($color)
    $border.Margin = New-Object System.Windows.Thickness 6
    $border.Padding = New-Object System.Windows.Thickness 12, 9, 12, 9
    $border.Width = 215
    $border.MinHeight = 78

    $sp = New-Object System.Windows.Controls.StackPanel

    $t1 = New-Object System.Windows.Controls.TextBlock
    $t1.Text = $Title
    $t1.FontSize = 11.5
    $t1.Foreground = $script:BrushConv.ConvertFromString('#FF9B9BAA')
    $t1.TextTrimming = 'CharacterEllipsis'
    [void]$sp.Children.Add($t1)

    $t2 = New-Object System.Windows.Controls.TextBlock
    $t2.Text = $Value
    $t2.FontSize = 17
    $t2.FontWeight = [System.Windows.FontWeights]::SemiBold
    $t2.Foreground = $script:BrushConv.ConvertFromString($color)
    $t2.Margin = New-Object System.Windows.Thickness 0, 2, 0, 2
    $t2.TextTrimming = 'CharacterEllipsis'
    [void]$sp.Children.Add($t2)

    if ($Sub) {
        $t3 = New-Object System.Windows.Controls.TextBlock
        $t3.Text = $Sub
        $t3.FontSize = 11
        $t3.Foreground = $script:BrushConv.ConvertFromString('#FF80808E')
        $t3.TextWrapping = 'Wrap'
        [void]$sp.Children.Add($t3)
    }

    $border.Child = $sp
    [void]$script:ui.PnlCards.Children.Add($border)
}

function New-Findings {
    # Derive prioritized "attention items" from the collected data.
    param($d)
    $f = New-Object System.Collections.Generic.List[object]
    function AddF([string]$sev, [string]$area, [string]$text) {
        $f.Add([pscustomobject]@{ Severity = $sev; Area = $area; Finding = $text })
    }

    $st  = Get-Section $d 'DefenderStatus'
    $pf  = Get-Section $d 'DefenderPrefs'
    $meta = Get-Section $d 'Meta'

    if ($st) {
        if ($st.AntivirusEnabled -eq $false) { AddF 'Critical' 'Defender' 'Defender antivirus is DISABLED.' }
        if ($st.RealTimeProtectionEnabled -eq $false) { AddF 'Critical' 'Defender' 'Real-time protection is OFF.' }
        if ($st.AMRunningMode -match 'Passive') { AddF 'Info' 'Defender' "Defender is in passive mode ($($st.AMRunningMode)) - another AV is primary." }
        if ($st.IsTamperProtected -eq $false) { AddF 'Warning' 'Defender' 'Tamper Protection is not enabled.' }
        # Note: these ages are uint32; Defender reports 4294967295 when "never".
        $sigAge = $st.AntivirusSignatureAge
        if ($null -ne $sigAge -and [int64]$sigAge -lt 4294967295) {
            if ([int64]$sigAge -gt 7) { AddF 'Critical' 'Defender' "Signatures are $sigAge days old (last sync: $(Format-Value $st.AntivirusSignatureLastUpdated))." }
            elseif ([int64]$sigAge -gt 3) { AddF 'Warning' 'Defender' "Signatures are $sigAge days old (last sync: $(Format-Value $st.AntivirusSignatureLastUpdated))." }
        }
        if ($null -ne $st.QuickScanAge) {
            if ([int64]$st.QuickScanAge -ge 4294967295) { AddF 'Warning' 'Defender' 'No quick scan has ever completed on this device.' }
            elseif ([int64]$st.QuickScanAge -gt 7) { AddF 'Warning' 'Defender' "No quick scan in $($st.QuickScanAge) days." }
        }
        if ($st.RebootRequired -eq $true) { AddF 'Warning' 'Defender' 'Defender reports a reboot is required to complete remediation.' }
    }
    if ($pf) {
        if ($pf.MAPSReporting -eq 0) { AddF 'Warning' 'Defender' 'Cloud-delivered protection (MAPS) is disabled.' }
        if ($pf.SubmitSamplesConsent -eq 2) { AddF 'Info' 'Defender' 'Sample submission set to "Never send".' }
        if ($pf.PUAProtection -eq 0) { AddF 'Info' 'Defender' 'PUA (potentially unwanted app) protection is disabled.' }
        if ($pf.EnableNetworkProtection -eq 0) { AddF 'Info' 'Defender' 'Network Protection is disabled.' }
        elseif ($pf.EnableNetworkProtection -eq 2) { AddF 'Info' 'Defender' 'Network Protection is in audit mode (not blocking).' }
        if ($pf.EnableControlledFolderAccess -eq 0) { AddF 'Info' 'Defender' 'Controlled Folder Access is disabled.' }
        if ($pf.DisableScriptScanning -eq $true) { AddF 'Warning' 'Defender' 'Script scanning is disabled.' }
    }
    $excl = @(Get-ArrSection $d 'DefenderExclusions')
    $realExcl = @($excl | Where-Object { $_.Type -in @('Path', 'Extension', 'Process', 'IpAddress') })
    if ($realExcl.Count -gt 0) { AddF 'Info' 'Defender' "$($realExcl.Count) Defender exclusion(s) configured - review the Defender tab." }

    $asr = @(Get-ArrSection $d 'AsrRules')
    if ($asr.Count -eq 0) { AddF 'Warning' 'ASR' 'No Attack Surface Reduction rules are configured.' }
    else {
        $auditCount = @($asr | Where-Object { $_.Mode -eq 'Audit' }).Count
        if ($auditCount -gt 0) { AddF 'Info' 'ASR' "$auditCount ASR rule(s) are audit-only (not blocking)." }
    }

    $threats = @(Get-ArrSection $d 'Threats')
    if ($threats.Count -gt 0) { AddF 'Warning' 'Detections' "$($threats.Count) Defender threat detection(s) on record - see Detections tab." }

    foreach ($p in @(Get-ArrSection $d 'FirewallProfiles')) {
        if ($p.Enabled -ne 'True') { AddF 'Critical' 'Firewall' "Firewall profile '$($p.Profile)' is DISABLED." }
        elseif ($p.DefaultInboundAction -eq 'Allow') { AddF 'Warning' 'Firewall' "Profile '$($p.Profile)' default inbound action is ALLOW." }
    }
    $fwChanges = @(Get-ArrSection $d 'FirewallChanges')
    $deleted = @($fwChanges | Where-Object { $_.Id -in @(2006, 2033) })
    if ($deleted.Count -gt 0) { AddF 'Info' 'Firewall' "$($deleted.Count) firewall rule deletion event(s) in window." }

    $mde = Get-Section $d 'MDE'
    if ($mde) {
        if (-not $mde.Onboarded) { AddF 'Warning' 'MDE' 'Not onboarded to Microsoft Defender for Endpoint.' }
        elseif ($mde.LastConnected -and $mde.LastConnected -lt (Get-Date).AddDays(-2)) {
            AddF 'Warning' 'MDE' "MDE sensor last connected $(Format-Value $mde.LastConnected) - may be offline."
        }
    }

    $bl = @(Get-ArrSection $d 'BitLocker')
    foreach ($v in $bl) {
        if ($v.VolumeType -eq 'OperatingSystem' -and $v.ProtectionStatus -ne 'On') {
            AddF 'Warning' 'BitLocker' "OS volume $($v.MountPoint) BitLocker protection is $($v.ProtectionStatus)."
        }
    }

    $idEvents = @(Get-ArrSection $d 'IdentityEvents')
    if (@($idEvents | Where-Object { $_.Id -eq 1102 }).Count -gt 0) { AddF 'Critical' 'Security log' 'The Security event log was CLEARED during the window.' }
    if (@($idEvents | Where-Object { $_.Id -eq 4719 }).Count -gt 0) { AddF 'Warning' 'Audit policy' 'Audit policy was changed during the window.' }
    $lockouts = @($idEvents | Where-Object { $_.Id -eq 4740 }).Count
    if ($lockouts -gt 0) { AddF 'Info' 'Identity' "$lockouts account lockout(s) in window." }
    $grpAdds = @($idEvents | Where-Object { $_.Id -in @(4728, 4732, 4756) }).Count
    if ($grpAdds -gt 0) { AddF 'Info' 'Identity' "$grpAdds group-membership addition(s) in window - verify they were expected." }

    $failedCount = Get-Section $d 'FailedLogonCount'
    if ($failedCount -ge 25) { AddF 'Warning' 'Identity' "High volume of failed logons in window ($failedCount)." }

    $ss = Get-Section $d 'SecuritySettings'
    if ($ss) {
        if ($ss.UacEnabled -eq 0) { AddF 'Critical' 'Platform' 'UAC is DISABLED (EnableLUA = 0).' }
        if (-not ($ss.LsaRunAsPPL -in @(1, 2))) { AddF 'Info' 'Platform' 'LSA protection (RunAsPPL) is not enabled.' }
        if ($ss.SmartScreenExplorer -eq 'Off' -or $ss.SmartScreenPolicy -eq 0) { AddF 'Warning' 'Platform' 'SmartScreen is off.' }
        if ($ss.SecureBoot -eq 'Off') { AddF 'Info' 'Platform' 'Secure Boot is off.' }
    }

    $ssn = Get-Section $d 'SmartScreen'
    if ($ssn) {
        if (-not $ssn.AppReputationLogEnabled) {
            AddF 'Info' 'SmartScreen' ("App-reputation prompts (the 'Windows protected your PC' dialog) are NOT being recorded on this host: " +
                "the $($ssn.AppReputationLog) channel is analytic and is disabled by default. Zero SmartScreen events means 'not logged', " +
                "not 'nothing blocked'. Enable with: $($ssn.EnableLoggingCommand)")
        }
        else {
            $ssc = @(Get-ArrSection $d 'SmartScreenEvents').Count
            if ($ssc -gt 0) { AddF 'Warning' 'SmartScreen' "$ssc SmartScreen app-reputation event(s) in window - Events tab, Source = SmartScreen." }
        }
        if ($ssn.SmartAppControl -match 'Evaluation') {
            AddF 'Info' 'SmartScreen' 'Smart App Control is in evaluation mode - it is not blocking. Its would-block events appear as Code Integrity 3076.'
        }
        elseif ($ssn.SmartAppControl -match 'enforcement') {
            AddF 'Info' 'SmartScreen' 'Smart App Control is enforcing. Its blocks appear as Code Integrity 3077 on the AppLocker/WDAC tab.'
        }
    }

    $psl = Get-Section $d 'PsLogging'
    if ($psl) {
        if ($psl.ScriptBlockLogging -ne 'Enabled') { AddF 'Warning' 'PS logging' 'PowerShell script block logging is not enabled - malicious PowerShell will leave almost no forensic trace.' }
        if ($psl.ModuleLogging -ne 'Enabled') { AddF 'Info' 'PS logging' 'PowerShell module logging is not enabled.' }
        if ($psl.Transcription -ne 'Enabled') { AddF 'Info' 'PS logging' 'PowerShell transcription is not enabled.' }
        if ($psl.PowerShellV2Feature -eq 'Enabled') {
            AddF 'Warning' 'PS logging' 'PowerShell 2.0 engine is INSTALLED. It predates AMSI and script block logging, so "powershell -v 2" bypasses both. Remove the optional feature.'
        }
    }

    $lp = Get-Section $d 'Laps'
    if ($lp) {
        if (-not $lp.Configured) { AddF 'Warning' 'LAPS' 'No LAPS policy found. The local administrator password is not being managed or rotated.' }
        elseif ($lp.BackupDirectory -eq 'Disabled' -or $lp.BackupDirectory -eq 'Not set') {
            AddF 'Warning' 'LAPS' "LAPS policy is present ($($lp.ActivePolicySource)) but BackupDirectory is '$($lp.BackupDirectory)', so passwords are not being backed up anywhere."
        }
    }

    $ep = Get-Section $d 'ExploitProtection'
    if ($ep) {
        if ($ep.ControlFlowGuard -eq 'OFF') { AddF 'Warning' 'Exploit Protection' 'System-wide Control Flow Guard is OFF.' }
        if ($ep.DEP -eq 'OFF') { AddF 'Critical' 'Exploit Protection' 'System-wide DEP is OFF.' }
        if ($ep.SEHOP -eq 'OFF') { AddF 'Info' 'Exploit Protection' 'System-wide SEHOP is OFF.' }
    }

    $us = Get-Section $d 'UpdateStatus'
    if ($us) {
        if ($us.RebootPending) { AddF 'Warning' 'Updates' "A reboot is pending ($($us.RebootPendingFrom)) - patches are not fully applied until it happens." }
        if ($null -ne $us.LastDetectAgeDays -and [double]$us.LastDetectAgeDays -gt 14) {
            AddF 'Warning' 'Updates' "Windows Update has not successfully checked in for $($us.LastDetectAgeDays) days."
        }
    }

    $permCount = Get-Section $d 'FirewallPermissiveCount'
    if ($permCount -and [int]$permCount -gt 0) {
        $unscoped = @(@(Get-ArrSection $d 'FirewallPermissive') | Where-Object { $_.Scoped -like 'No*' }).Count
        $sev = 'Info'
        if ($unscoped -gt 0) { $sev = 'Warning' }
        AddF $sev 'Firewall' "$permCount enabled inbound Allow rule(s) accept traffic from any address on any port/protocol ($unscoped of them not scoped to a program)."
    }

    $ss2 = @(Get-ArrSection $d 'SuspectServices')
    $unq = @($ss2 | Where-Object { $_.Concern -like '*Unquoted*' }).Count
    $wrt = @($ss2 | Where-Object { $_.Concern -like '*writable*' }).Count
    if ($wrt -gt 0) { AddF 'Warning' 'Persistence' "$wrt service(s) run from a user-writable location - see the Persistence tab." }
    if ($unq -gt 0) { AddF 'Info' 'Persistence' "$unq service(s) have an unquoted path containing spaces (privilege-escalation pattern)." }
    $tk = @(Get-ArrSection $d 'SuspectTasks').Count
    if ($tk -gt 0) { AddF 'Warning' 'Persistence' "$tk non-Microsoft scheduled task(s) launch from a user-writable location." }

    $sc = Get-Section $d 'SecureChannel'
    if ($sc -and $sc.Checked -and $sc.Healthy -eq $false) { AddF 'Critical' 'Identity' 'Domain secure channel is BROKEN (nltest /sc_query failed).' }

    foreach ($svc in @(Get-ArrSection $d 'Services')) {
        if ($svc.Name -in @('WinDefend', 'mpssvc', 'EventLog') -and $svc.State -ne 'Running') {
            AddF 'Critical' 'Services' "Service '$($svc.DisplayName)' ($($svc.Name)) is $($svc.State)."
        }
        if ($svc.Name -eq 'Sense' -and $svc.State -ne 'Running' -and $mde -and $mde.Onboarded) {
            AddF 'Warning' 'Services' 'MDE sensor service (Sense) is not running despite onboarding.'
        }
    }

    $alAudit = @(@(Get-ArrSection $d 'AppLockerEvents') | Where-Object { $_.Action -eq 'Audited' }).Count
    if ($alAudit -gt 0) { AddF 'Info' 'AppLocker' "$alAudit AppLocker audit event(s) - would be blocked under enforcement." }
    $ciAudit = @(@(Get-ArrSection $d 'CodeIntegrityEvents') | Where-Object { $_.Action -eq 'Audited' }).Count
    if ($ciAudit -gt 0) { AddF 'Info' 'WDAC' "$ciAudit Code Integrity audit event(s) - would be blocked under enforcement." }

    $gpo = Get-Section $d 'Gpo'
    if ($meta -and $meta.PartOfDomain -and $gpo -and $gpo.LastRefresh -and $gpo.LastRefresh -lt (Get-Date).AddDays(-1)) {
        AddF 'Warning' 'Policy' "Group Policy has not refreshed since $(Format-Value $gpo.LastRefresh)."
    }
    if ($meta -and $meta.UptimeDays -gt 30) { AddF 'Info' 'System' "No reboot in $($meta.UptimeDays) days." }

    $errs = @(Get-ArrSection $d 'Errors')
    if ($errs.Count -gt 0) { AddF 'Info' 'Collection' "$($errs.Count) collector(s) reported errors - see the Collection errors tab." }

    if ($f.Count -eq 0) { AddF 'Good' 'Overall' 'No attention items - security posture looks healthy.' }

    $sevOrder = @{ Critical = 0; Warning = 1; Info = 2; Good = 3 }
    @($f | Sort-Object { $sevOrder[$_.Severity] })
}

# ===========================================================================
#  GRID ENGINE
#  Every DataGrid gets: click-to-sort headers with arrows, a per-column filter
#  popup (distinct-value checkboxes + contains-text + sort), participation in
#  the global Find box, and double-click row detail.
#
#  Design notes:
#   - Columns are built explicitly (AutoGenerateColumns=False). Auto-generated
#     columns are destroyed and rebuilt every time ItemsSource is reassigned,
#     which would wipe the user's column widths and our sort/filter markers on
#     every keystroke.
#   - Per-grid state lives on $Grid.Tag. Popup state lives in $script:FilterCtx.
#     Nothing relies on scriptblock closures, which do not capture function
#     locals in PowerShell.
# ===========================================================================

# Columns whose content is long: these star-size to fill the viewport instead
# of sizing to content. Everything else is Auto and drag-resizable without cap.
$script:WideColumnNames = @(
    'Detail', 'Finding', 'Resources', 'Value', 'Message', 'Description',
    'Application', 'LogFileName', 'Event', 'Change', 'Rule', 'Member'
)
$script:GlobalSearch = ''
$script:AllGrids = @()
$script:FilterPopup = $null
$script:FilterCtx = $null
$script:RowDetailCtx = $null
$script:SuppressEventControls = $false

function Get-VisualAncestor {
    param($Element, [type]$Type)
    $cur = $Element
    while ($cur) {
        if ($Type.IsInstanceOfType($cur)) { return $cur }
        try { $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur) }
        catch { return $null }
    }
    return $null
}

function Test-RowPasses {
    # $ExcludeColumn lets the filter popup show the values that WOULD be
    # available if this column's own filter were lifted (Excel behaviour).
    param($State, $Row, [string]$ExcludeColumn = '')

    if ($State.Search) {
        $hit = $false
        foreach ($p in $Row.PSObject.Properties) {
            $sv = [string]$p.Value
            if ($sv -and $sv.IndexOf($State.Search, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hit = $true; break
            }
        }
        if (-not $hit) { return $false }
    }

    foreach ($k in @($State.Filters.Keys)) {
        if ($k -eq $ExcludeColumn) { continue }
        $allowed = @($State.Filters[$k])
        if ($allowed -notcontains ([string]$Row.$k)) { return $false }
    }

    foreach ($k in @($State.ContainsText.Keys)) {
        if ($k -eq $ExcludeColumn) { continue }
        $needle = [string]$State.ContainsText[$k]
        if (-not $needle) { continue }
        $sv = [string]$Row.$k
        if (-not $sv) { return $false }
        if ($sv.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }

    return $true
}

function Update-GridView {
    # Re-applies search + column filters + sort and re-materialises ItemsSource.
    param($Grid)
    $st = $Grid.Tag
    if (-not $st) { return }

    $rows = @($st.Source | Where-Object { Test-RowPasses -State $st -Row $_ })
    if ($st.SortColumn) {
        $rows = @($rows | Sort-Object -Property $st.SortColumn -Descending:([bool]$st.SortDesc))
    }
    $Grid.ItemsSource = $rows
    $st.Visible = $rows.Count

    # Mark filtered columns in the header text.
    foreach ($c in $Grid.Columns) {
        $n = [string]$c.SortMemberPath
        if (-not $n) { continue }
        $marked = $false
        if ($st.Filters.ContainsKey($n)) { $marked = $true }
        if ($st.ContainsText.ContainsKey($n) -and $st.ContainsText[$n]) { $marked = $true }
        if ($marked) { $c.Header = "$n *" } else { $c.Header = $n }
    }

    if ($st.Name -eq 'GridEvents') {
        $ui.TxtEvtCount.Text = "$($rows.Count) of $($st.Source.Count) events"
    }
}

function Show-GridInfo {
    param($Grid)
    $st = $Grid.Tag
    if (-not $st) { $ui.TxtFilterInfo.Text = ''; return }
    $label = $st.Name -replace '^Grid', ''
    $bits = @()
    if ($st.Search) { $bits += "find '$($st.Search)'" }
    $fcols = @(@(@($st.Filters.Keys) + @($st.ContainsText.Keys | Where-Object { $st.ContainsText[$_] })) | Sort-Object -Unique)
    if ($fcols.Count -gt 0) { $bits += "filtered on $($fcols -join ', ')" }
    if ($st.SortColumn) {
        $dir = 'asc'
        if ($st.SortDesc) { $dir = 'desc' }
        $bits += "sorted by $($st.SortColumn) $dir"
    }
    $suffix = ''
    if ($bits.Count -gt 0) { $suffix = "  (" + ($bits -join '; ') + ")" }
    $ui.TxtFilterInfo.Text = "$($label): $($st.Visible) of $($st.Source.Count) rows$suffix"
}

function Set-GridSource {
    # Installs a fresh dataset on a grid and rebuilds its columns.
    param($Grid, $Rows)
    if (-not $Grid) { return }
    # NOTE: do not name this $rows - PowerShell variable names are case
    # insensitive, so $rows IS $Rows and we would erase the incoming data.
    $list = @()
    if ($null -ne $Rows) { $list = @($Rows | Where-Object { $null -ne $_ }) }

    $Grid.Tag = @{
        Name         = [string]$Grid.Name
        Source       = $list
        Filters      = @{}
        ContainsText = @{}
        Search       = $script:GlobalSearch
        SortColumn   = $null
        SortDesc     = $false
        Visible      = 0
    }

    $Grid.ItemsSource = $null
    $Grid.Columns.Clear()

    if ($list.Count -gt 0) {
        foreach ($prop in $list[0].PSObject.Properties) {
            $n = [string]$prop.Name
            $col = New-Object System.Windows.Controls.DataGridTextColumn
            $col.Header = $n
            $col.SortMemberPath = $n
            $col.CanUserSort = $true
            $col.CanUserResize = $true

            $bind = New-Object System.Windows.Data.Binding -ArgumentList $n
            $bind.Mode = [System.Windows.Data.BindingMode]::OneWay
            $col.Binding = $bind

            $col.MaxWidth = 4000
            if ($script:WideColumnNames -contains $n) {
                $col.Width = New-Object System.Windows.Controls.DataGridLength -ArgumentList 1, ([System.Windows.Controls.DataGridLengthUnitType]::Star)
                $col.MinWidth = 180
            }
            else {
                $col.Width = [System.Windows.Controls.DataGridLength]::Auto
                $col.MinWidth = 40
            }

            # Single-line cells with an ellipsis, full text on hover. Wrapped in
            # try/catch so a style failure degrades to a plain cell instead of
            # taking down the whole render.
            try {
                $ts = New-Object System.Windows.Style -ArgumentList ([System.Windows.Controls.TextBlock])
                [void]$ts.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.Controls.TextBlock]::TextTrimmingProperty), ([System.Windows.TextTrimming]::CharacterEllipsis)))
                $ttBind = New-Object System.Windows.Data.Binding -ArgumentList $n
                $ttBind.Mode = [System.Windows.Data.BindingMode]::OneWay
                [void]$ts.Setters.Add((New-Object System.Windows.Setter -ArgumentList ([System.Windows.FrameworkElement]::ToolTipProperty), $ttBind))
                $col.ElementStyle = $ts
            }
            catch { }

            [void]$Grid.Columns.Add($col)
        }
    }

    Update-GridView $Grid
}

function Clear-GridFilters {
    param($Grid, [switch]$KeepSort)
    $st = $Grid.Tag
    if (-not $st) { return }
    $st.Filters = @{}
    $st.ContainsText = @{}
    if (-not $KeepSort) {
        $st.SortColumn = $null
        $st.SortDesc = $false
        foreach ($c in $Grid.Columns) { $c.SortDirection = $null }
    }
    Update-GridView $Grid
}

function Clear-AllGridFilters {
    $script:GlobalSearch = ''
    $ui.TxtFind.Text = ''
    # Setting Text fired TextChanged, which armed the debounce timer. Cancel it,
    # otherwise it would overwrite the status line moments from now.
    if ($script:FindTimer) { $script:FindTimer.Stop() }
    foreach ($g in $script:AllGrids) {
        $st = $g.Tag
        if (-not $st) { continue }
        $st.Search = ''
        Clear-GridFilters -Grid $g
    }
    Sync-EventControls
    $ui.TxtFilterInfo.Text = 'All table filters cleared.'
}

function Set-GlobalSearch {
    param([string]$Text)
    $script:GlobalSearch = $Text
    $matched = 0
    $total = 0
    foreach ($g in $script:AllGrids) {
        $st = $g.Tag
        if (-not $st) { continue }
        # Only re-materialise grids that actually have rows and whose search
        # term changed - a full sweep of ~30 grids per keystroke is expensive.
        if ($st.Search -ne $Text) {
            $st.Search = $Text
            if ($st.Source.Count -gt 0) { Update-GridView $g }
        }
        $matched += $st.Visible
        $total += $st.Source.Count
    }
    Sync-EventControls
    if ($Text) { $ui.TxtFilterInfo.Text = "Find '$Text': $matched of $total rows across all tables" }
    else { $ui.TxtFilterInfo.Text = '' }
}

# ---------------------------------------------------------------- Row detail
$script:RowDetailXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Row detail" Height="580" Width="860" WindowStartupLocation="CenterOwner"
        Background="#FF14141A" Foreground="#FFE8E8EE" FontFamily="Segoe UI" FontSize="13"
        ShowInTaskbar="False">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <DockPanel Margin="14">
    <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="BtnCopyRow" Content="Copy all" Width="100" Padding="12,6"
              Background="#FF3A3A46" Foreground="White" BorderThickness="0"/>
      <Button x:Name="BtnCloseRow" Content="Close" Width="90" Padding="12,6" Margin="8,0,0,0"
              Background="#FF2F6FED" Foreground="White" BorderThickness="0"/>
    </StackPanel>
    <ScrollViewer VerticalScrollBarVisibility="Auto">
      <ItemsControl x:Name="ItemsRow">
        <ItemsControl.ItemTemplate>
          <DataTemplate>
            <StackPanel Margin="0,0,0,10">
              <TextBlock Text="{Binding Field}" Foreground="#FF9B9BAA" FontSize="11" FontWeight="SemiBold" Margin="0,0,0,2"/>
              <TextBox Text="{Binding Value, Mode=OneWay}" IsReadOnly="True" TextWrapping="Wrap"
                       Background="#FF1D1D25" Foreground="#FFE8E8EE" BorderBrush="#FF33333F"
                       BorderThickness="1" Padding="7,5" CaretBrush="#FFE8E8EE"/>
            </StackPanel>
          </DataTemplate>
        </ItemsControl.ItemTemplate>
      </ItemsControl>
    </ScrollViewer>
  </DockPanel>
</Window>
'@

function Show-RowDetail {
    param($Row)
    if (-not $Row) { return }
    $fields = @($Row.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Field = $_.Name; Value = (Format-Value $_.Value) }
    })

    $rd = [System.Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new([xml]$script:RowDetailXaml))
    $rd.Owner = $window
    $items = $rd.FindName('ItemsRow')
    $items.ItemsSource = $fields

    $script:RowDetailCtx = @{ Window = $rd; Fields = $fields }

    $rd.FindName('BtnCloseRow').Add_Click({ $script:RowDetailCtx.Window.Close() })
    $rd.FindName('BtnCopyRow').Add_Click({
        $text = (@($script:RowDetailCtx.Fields | ForEach-Object { "$($_.Field): $($_.Value)" }) -join "`r`n")
        try { [System.Windows.Clipboard]::SetText($text) } catch { }
    })
    [void]$rd.ShowDialog()
    $script:RowDetailCtx = $null
}

# ------------------------------------------------------------- Filter popup
$script:FilterPopupXaml = @'
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Background="#FF23232C" BorderBrush="#FF4A4A5A" BorderThickness="1"
        CornerRadius="4" Padding="10" Width="310">
  <Border.Resources>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF3A3A46"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#FF2A2A35"/>
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="BorderBrush" Value="#FF444452"/>
      <Setter Property="CaretBrush" Value="#FFE8E8EE"/>
      <Setter Property="Padding" Value="5,3"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="2,1"/>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="#FF1D1D25"/>
      <Setter Property="Foreground" Value="#FFE8E8EE"/>
      <Setter Property="BorderBrush" Value="#FF33333F"/>
    </Style>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="#FF9B9BAA"/>
      <Setter Property="FontSize" Value="11"/>
    </Style>
  </Border.Resources>
  <StackPanel>
    <TextBlock x:Name="LblCol" Foreground="#FFE8E8EE" FontSize="13" FontWeight="SemiBold" Margin="0,0,0,8"/>
    <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
      <Button x:Name="BtnSortAsc"  Content="Sort A-Z" Width="139"/>
      <Button x:Name="BtnSortDesc" Content="Sort Z-A" Width="139" Margin="6,0,0,0"/>
    </StackPanel>
    <TextBlock Text="Text contains"/>
    <TextBox x:Name="TxtContains" Margin="0,2,0,8"/>
    <TextBlock x:Name="LblValues" Text="Values"/>
    <TextBox x:Name="TxtValueSearch" Margin="0,2,0,4" ToolTip="Narrow the list below"/>
    <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
      <Button x:Name="BtnAll"  Content="Select all" Width="139"/>
      <Button x:Name="BtnNone" Content="Select none" Width="139" Margin="6,0,0,0"/>
    </StackPanel>
    <!-- A StackPanel rather than a ListBox: collapsing a ListBox item's content
         still leaves an empty container row, which breaks the value search. -->
    <Border BorderBrush="#FF33333F" BorderThickness="1" Background="#FF1D1D25" Height="210">
      <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="4">
        <StackPanel x:Name="PnlValues"/>
      </ScrollViewer>
    </Border>
    <TextBlock x:Name="TxtHint" Margin="0,6,0,0" TextWrapping="Wrap"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
      <Button x:Name="BtnClearCol" Content="Clear filter" Width="96"/>
      <Button x:Name="BtnApply" Content="Apply" Width="86" Margin="6,0,0,0" Background="#FF2F6FED"/>
    </StackPanel>
  </StackPanel>
</Border>
'@

function Close-FilterPopup {
    if ($script:FilterPopup) {
        try { $script:FilterPopup.IsOpen = $false } catch { }
    }
    $script:FilterPopup = $null
    $script:FilterCtx = $null
}

function Set-ColumnSort {
    param($Grid, [string]$Name, [bool]$Descending)
    $st = $Grid.Tag
    if (-not $st) { return }
    $st.SortColumn = $Name
    $st.SortDesc = $Descending
    foreach ($c in $Grid.Columns) {
        if ([string]$c.SortMemberPath -eq $Name) {
            if ($Descending) { $c.SortDirection = [System.ComponentModel.ListSortDirection]::Descending }
            else { $c.SortDirection = [System.ComponentModel.ListSortDirection]::Ascending }
        }
        else { $c.SortDirection = $null }
    }
    Update-GridView $Grid
    Show-GridInfo $Grid
}

function Show-ColumnFilter {
    param($Grid, $Column, $Anchor)
    $st = $Grid.Tag
    if (-not $st) { return }
    $name = [string]$Column.SortMemberPath
    if (-not $name) { return }

    Close-FilterPopup

    $content = [System.Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new([xml]$script:FilterPopupXaml))
    $parts = @{}
    foreach ($n in @('LblCol', 'BtnSortAsc', 'BtnSortDesc', 'TxtContains', 'LblValues',
                     'TxtValueSearch', 'BtnAll', 'BtnNone', 'PnlValues', 'TxtHint',
                     'BtnClearCol', 'BtnApply')) {
        $parts[$n] = $content.FindName($n)
    }
    $parts.LblCol.Text = $name

    # Distinct values as they would be if this column's own filter were lifted.
    $candidates = @($st.Source | Where-Object { Test-RowPasses -State $st -Row $_ -ExcludeColumn $name })
    $distinct = @($candidates | ForEach-Object { [string]$_.$name } | Sort-Object -Unique)

    $selected = $null
    if ($st.Filters.ContainsKey($name)) { $selected = @($st.Filters[$name]) }
    if ($st.ContainsText.ContainsKey($name)) { $parts.TxtContains.Text = [string]$st.ContainsText[$name] }

    $parts.LblValues.Text = "Values ($($distinct.Count) distinct)"
    $valuesSuppressed = $false
    if ($distinct.Count -gt 600) {
        $parts.TxtHint.Text = 'Too many distinct values to list. Use "Text contains" above.'
        $parts.PnlValues.IsEnabled = $false
        $parts.BtnAll.IsEnabled = $false
        $parts.BtnNone.IsEnabled = $false
        $parts.TxtValueSearch.IsEnabled = $false
        $valuesSuppressed = $true
    }
    else {
        foreach ($v in $distinct) {
            $cb = New-Object System.Windows.Controls.CheckBox
            if ([string]::IsNullOrEmpty($v)) { $cb.Content = '(blank)' } else { $cb.Content = $v }
            $cb.Tag = $v
            if ($null -eq $selected) { $cb.IsChecked = $true }
            else { $cb.IsChecked = ($selected -contains $v) }
            [void]$parts.PnlValues.Children.Add($cb)
        }
        $parts.TxtHint.Text = 'Unchecked values are hidden. Double-click any row for full detail.'
    }

    $popup = New-Object System.Windows.Controls.Primitives.Popup
    $popup.PlacementTarget = $Anchor
    $popup.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
    $popup.StaysOpen = $false
    $popup.AllowsTransparency = $true
    $popup.Child = $content
    $popup.HorizontalOffset = -270

    $script:FilterPopup = $popup
    $script:FilterCtx = @{ Grid = $Grid; Name = $name; Parts = $parts; ValuesSuppressed = [bool]$valuesSuppressed }

    $parts.BtnSortAsc.Add_Click({
        $c = $script:FilterCtx
        Set-ColumnSort -Grid $c.Grid -Name $c.Name -Descending $false
        Close-FilterPopup
    })
    $parts.BtnSortDesc.Add_Click({
        $c = $script:FilterCtx
        Set-ColumnSort -Grid $c.Grid -Name $c.Name -Descending $true
        Close-FilterPopup
    })
    $parts.BtnAll.Add_Click({
        foreach ($i in $script:FilterCtx.Parts.PnlValues.Children) {
            if ($i.Visibility -eq [System.Windows.Visibility]::Visible) { $i.IsChecked = $true }
        }
    })
    $parts.BtnNone.Add_Click({
        foreach ($i in $script:FilterCtx.Parts.PnlValues.Children) {
            if ($i.Visibility -eq [System.Windows.Visibility]::Visible) { $i.IsChecked = $false }
        }
    })
    $parts.TxtValueSearch.Add_TextChanged({
        $c = $script:FilterCtx
        $needle = [string]$c.Parts.TxtValueSearch.Text
        foreach ($i in $c.Parts.PnlValues.Children) {
            $txt = [string]$i.Content
            if (-not $needle -or $txt.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $i.Visibility = [System.Windows.Visibility]::Visible
            }
            else { $i.Visibility = [System.Windows.Visibility]::Collapsed }
        }
    })
    $parts.BtnClearCol.Add_Click({
        $c = $script:FilterCtx
        $st2 = $c.Grid.Tag
        [void]$st2.Filters.Remove($c.Name)
        [void]$st2.ContainsText.Remove($c.Name)
        Update-GridView $c.Grid
        Show-GridInfo $c.Grid
        Sync-EventControls
        Close-FilterPopup
    })
    $parts.BtnApply.Add_Click({
        $c = $script:FilterCtx
        $st2 = $c.Grid.Tag
        $items = @($c.Parts.PnlValues.Children)
        if ($c.ValuesSuppressed) {
            # The value list was too large to render, so it could not represent
            # an existing selection. Drop it rather than silently keeping it.
            [void]$st2.Filters.Remove($c.Name)
        }
        elseif ($items.Count -gt 0) {
            $checked = @($items | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag })
            if ($checked.Count -eq $items.Count) { [void]$st2.Filters.Remove($c.Name) }
            else { $st2.Filters[$c.Name] = $checked }
        }
        $needle = [string]$c.Parts.TxtContains.Text
        if ($needle) { $st2.ContainsText[$c.Name] = $needle }
        else { [void]$st2.ContainsText.Remove($c.Name) }
        Update-GridView $c.Grid
        Show-GridInfo $c.Grid
        Sync-EventControls
        Close-FilterPopup
    })

    $popup.IsOpen = $true
}

function Enable-GridTools {
    param($Grid)
    if (-not $Grid) { return }

    # Header click sorting - handled manually so the arrow, the filter marker
    # and the explicit column collection all stay consistent.
    $Grid.Add_Sorting({
        param($s, $e)
        $e.Handled = $true
        $st = $s.Tag
        if (-not $st) { return }
        $n = [string]$e.Column.SortMemberPath
        if (-not $n) { return }
        $desc = $false
        if ($st.SortColumn -eq $n) { $desc = -not $st.SortDesc }
        Set-ColumnSort -Grid $s -Name $n -Descending $desc
    })

    # One class handler for every filter button inside this grid's headers.
    $Grid.AddHandler(
        [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent,
        [System.Windows.RoutedEventHandler]{
            param($s, $e)
            $src = $e.OriginalSource
            if (-not ($src -is [System.Windows.Controls.Button])) { return }
            if ($src.Name -ne 'PART_FilterButton') { return }
            $e.Handled = $true
            $hdr = Get-VisualAncestor -Element $src -Type ([System.Windows.Controls.Primitives.DataGridColumnHeader])
            if (-not $hdr) { return }
            if (-not $hdr.Column) { return }
            Show-ColumnFilter -Grid $s -Column $hdr.Column -Anchor $src
        })

    # Double-click a row (not a header gripper) for the full untruncated record.
    $Grid.Add_MouseDoubleClick({
        param($s, $e)
        $row = Get-VisualAncestor -Element $e.OriginalSource -Type ([System.Windows.Controls.DataGridRow])
        if ($row -and $row.Item) { Show-RowDetail -Row $row.Item }
    })

    $script:AllGrids += $Grid
}

# --------------------------------------------------- Events tab quick filters
function Sync-EventControls {
    $g = $ui.GridEvents
    if (-not $g) { return }
    $st = $g.Tag
    $script:SuppressEventControls = $true
    try {
        $srcs = @('All')
        $active = ''
        $curSrc = 'All'
        if ($st) {
            $srcs += @($st.Source | ForEach-Object { [string]$_.Source } | Sort-Object -Unique)
            if ($st.Filters.ContainsKey('Source')) {
                $v = @($st.Filters['Source'])
                if ($v.Count -eq 1) { $curSrc = [string]$v[0] }
                else { $curSrc = '(custom)'; $srcs += '(custom)' }
            }
            if ($st.Filters.ContainsKey('Action')) {
                $a = @($st.Filters['Action'])
                if ($a.Count -eq 1) { $active = [string]$a[0] }
            }
        }
        $ui.CmbEvtSource.ItemsSource = $srcs
        $ui.CmbEvtSource.SelectedItem = $curSrc

        foreach ($pair in @(@('BtnEvtAll', ''), @('BtnEvtBlocked', 'Blocked'), @('BtnEvtAudited', 'Audited'),
                            @('BtnEvtAllowed', 'Allowed'), @('BtnEvtDetected', 'Detected'), @('BtnEvtAlert', 'Alert'))) {
            $b = $ui[$pair[0]]
            if (-not $b) { continue }
            if ($pair[1] -eq $active) { $b.Background = $script:BrushConv.ConvertFromString('#FF2F6FED') }
            else { $b.Background = $script:BrushConv.ConvertFromString('#FF3A3A46') }
        }
    }
    finally { $script:SuppressEventControls = $false }
}

function Set-EventActionFilter {
    param([string]$Action)
    $g = $ui.GridEvents
    $st = $g.Tag
    if (-not $st) { return }
    if ($Action) { $st.Filters['Action'] = @($Action) }
    else { [void]$st.Filters.Remove('Action') }
    Update-GridView $g
    Sync-EventControls
    Show-GridInfo $g
}

# ===========================================================================
#  BASELINE AND DIFF
#  A snapshot is the whole scan normalised to strings. Normalising on the way
#  in means a live scan and a scan reloaded from JSON compare identically -
#  otherwise DateTime round-tripping alone would produce phantom differences.
# ===========================================================================

# Sections that are time-windowed. Diffing individual events is pure noise, so
# these are compared by count only.
$script:EventSections = @(
    'DefenderEvents', 'AppLockerEvents', 'CodeIntegrityEvents', 'SmartScreenEvents',
    'FirewallChanges', 'IdentityEvents', 'FailedLogons', 'FailedLogonTop',
    'LogonSummary', 'Threats', 'FirewallBlocked', 'Sessions', 'Errors'
)

# How to identify "the same row" across two scans, per section. Without a key
# the diff would report every row as removed-and-re-added on any reordering.
$script:SectionKeys = @{
    AsrRules            = @('Guid')
    DefenderExclusions  = @('Type', 'Value')
    Services            = @('Name')
    SuspectServices     = @('Service')
    SuspectTasks        = @('Task', 'Command')   # one row per task ACTION
    FirewallProfiles    = @('Profile')
    FirewallRuleSummary = @('Direction', 'Action')
    # DisplayName alone is NOT unique - Windows ships many same-named rules per
    # profile/service, and a new permissive rule reusing a name would vanish.
    FirewallPermissive  = @('Rule', 'Protocol', 'LocalPort', 'Program')
    AppLockerPolicy     = @('Collection')
    LocalAdmins         = @('Member')
    LocalUsers          = @('Name')
    BitLocker           = @('MountPoint')
    DsRegStatus         = @('Property')
    MdmEnrollment       = @('UPN')
    AuditPolicy         = @('Subcategory')
    Hotfixes            = @('HotFixID')
}

# Changes that mean posture got worse. Everything else is reported neutrally.
#   To    = regression when the new value equals this
#   NotTo = regression when the new value is anything else (and non-empty)
# NotTo matters because a control can lapse to more than one bad value: script
# block logging reads 'Disabled' when a policy turns it off but 'Not configured'
# when the policy is simply deleted, and both mean the control is not running.
# An empty new value means the collector failed, not that posture changed, so
# NotTo deliberately ignores it rather than crying wolf on a broken collector.
$script:RegressionRules = @(
    @{ Section = 'DefenderStatus';    Property = 'RealTimeProtectionEnabled'; NotTo = 'True' }
    @{ Section = 'DefenderStatus';    Property = 'AntivirusEnabled';          NotTo = 'True' }
    @{ Section = 'DefenderStatus';    Property = 'IsTamperProtected';         NotTo = 'True' }
    @{ Section = 'DefenderPrefs';     Property = 'MAPSReporting';             To    = '0' }
    @{ Section = 'DefenderPrefs';     Property = 'DisableScriptScanning';     To    = 'True' }
    @{ Section = 'SecuritySettings';  Property = 'UacEnabled';                To    = '0' }
    @{ Section = 'PsLogging';         Property = 'ScriptBlockLogging';        NotTo = 'Enabled' }
    @{ Section = 'PsLogging';         Property = 'PowerShellV2Feature';       To    = 'Enabled' }
    @{ Section = 'DeviceGuard';       Property = 'KernelModeCodeIntegrity';   To    = 'Off' }
    @{ Section = 'Laps';              Property = 'Configured';                NotTo = 'True' }
    @{ Section = 'SmartScreen';       Property = 'SmartAppControl';           To    = 'Off' }
)
# Sections where a NEW row is itself security-relevant.
$script:AdditionIsNotable = @('DefenderExclusions', 'LocalAdmins', 'FirewallPermissive', 'SuspectServices', 'SuspectTasks')

function ConvertTo-ScanSnapshot {
    # Whole scan -> all-string structure, safe to JSON round-trip and diff.
    #
    # Everything is emitted as PSCustomObject, NOT [ordered]/hashtable. A live
    # snapshot is compared against one reloaded from JSON, and ConvertFrom-Json
    # produces PSCustomObjects. An OrderedDictionary exposes its own .NET members
    # (Count, IsFixedSize, IsReadOnly, Keys, ...) through PSObject.Properties, so
    # mixing the two shapes makes a scan differ from itself on dozens of phantom
    # properties. Same type on both sides is what keeps the diff honest.
    param($d)
    $snap = [ordered]@{}
    foreach ($key in @($d.Keys | Sort-Object)) {
        $val = $d[$key]
        if ($null -eq $val) { continue }
        if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
            $rows = @()
            foreach ($r in @($val)) {
                if ($null -eq $r) { continue }
                if ($r -is [string]) { $rows += [pscustomobject]@{ Value = $r }; continue }
                $o = [ordered]@{}
                foreach ($pp in $r.PSObject.Properties) { $o[$pp.Name] = (Format-Value $pp.Value) }
                $rows += [pscustomobject]$o
            }
            $snap[$key] = [pscustomobject]@{ Kind = 'rows'; Rows = @($rows) }
        }
        elseif ($val -is [string] -or $val -is [valuetype]) {
            # A bare scalar (FailedLogonCount, FirewallPermissiveCount, ...) has no
            # adapted properties, so the generic path would store an empty bag and
            # the value would silently drop out of every snapshot and diff.
            $snap[$key] = [pscustomobject]@{ Kind = 'props'; Props = ([pscustomobject]@{ Value = (Format-Value $val) }) }
        }
        else {
            $o = [ordered]@{}
            foreach ($pp in $val.PSObject.Properties) { $o[$pp.Name] = (Format-Value $pp.Value) }
            $snap[$key] = [pscustomobject]@{ Kind = 'props'; Props = ([pscustomobject]$o) }
        }
    }
    [pscustomobject]$snap
}

function Save-ScanSnapshot {
    param($d, [string]$Path)
    $snap = ConvertTo-ScanSnapshot $d
    $meta = Get-Section $d 'Meta'
    $cc = Get-Section $d 'ClientContext'
    $wrapper = [pscustomobject]@{
        SchemaVersion = 1
        ToolVersion   = $script:ToolVersion
        Computer      = $(if ($meta) { [string]$meta.ComputerName } else { 'unknown' })
        ScanTime      = $(if ($meta) { Format-Value $meta.ScanTime } else { '' })
        LookbackDays  = $(if ($meta) { [string]$meta.LookbackDays } else { '' })
        CollectedBy   = $(if ($cc) { [string]$cc.RunBy } else { '' })
        Sections      = $snap
    }
    $json = $wrapper | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
    $Path
}

function Import-ScanSnapshot {
    param([string]$Path)
    $raw = [System.IO.File]::ReadAllText($Path)
    $o = $raw | ConvertFrom-Json
    if (-not $o.Sections) { throw "Not a Security Health Dashboard snapshot: $Path" }
    if ($null -ne $o.SchemaVersion -and [int]$o.SchemaVersion -ne 1) {
        throw "Snapshot schema v$($o.SchemaVersion) was written by a different build and cannot be compared safely (this tool is $($script:ToolVersion), schema 1)."
    }
    $o
}

function Get-SnapshotRowKey {
    param([string]$Section, $Row)
    $keys = $script:SectionKeys[$Section]
    if (-not $keys) {
        # No declared key: fall back to the whole row, which degrades the diff to
        # added/removed rather than reporting a bogus "changed".
        return (@($Row.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '|')
    }
    (@($keys | ForEach-Object { [string]$Row.$_ }) -join ' | ')
}

function Test-IsRegression {
    param([string]$Section, [string]$Property, [string]$To, [string]$Change)
    if ($Change -eq 'Added' -and $script:AdditionIsNotable -contains $Section) { return $true }
    foreach ($r in $script:RegressionRules) {
        if ($r.Section -ne $Section -or $r.Property -ne $Property) { continue }
        if ($r.ContainsKey('To') -and $To -eq $r.To) { return $true }
        if ($r.ContainsKey('NotTo') -and $To -and $To -ne $r.NotTo) { return $true }
    }
    return $false
}

function Compare-ScanSnapshots {
    # Returns diff rows: Impact / Area / Item / Property / Baseline / Current / Change
    param($Baseline, $Current)
    $out = New-Object System.Collections.Generic.List[object]
    function AddD {
        param([string]$Area, [string]$Item, [string]$Property, [string]$Was, [string]$Now, [string]$Change)
        $impact = 'Change'
        if (Test-IsRegression -Section $Area -Property $Property -To $Now -Change $Change) { $impact = 'Regression' }
        $out.Add([pscustomobject]@{
            Impact = $impact; Area = $Area; Item = $Item; Property = $Property
            Baseline = $Was; Current = $Now; Change = $Change
        })
    }

    $bs = $Baseline.Sections
    $cs = $Current.Sections
    $names = @(@($bs.PSObject.Properties.Name) + @($cs.PSObject.Properties.Name)) | Sort-Object -Unique

    foreach ($name in $names) {
        if ($script:EventSections -contains $name) {
            $bc = 0; $cc2 = 0
            if ($bs.$name -and $bs.$name.Rows) { $bc = @($bs.$name.Rows).Count }
            if ($cs.$name -and $cs.$name.Rows) { $cc2 = @($cs.$name.Rows).Count }
            if ($bc -ne $cc2) { AddD $name '(event volume)' 'RowCount' ([string]$bc) ([string]$cc2) 'Changed' }
            continue
        }
        $b = $bs.$name
        $c = $cs.$name
        if (-not $b -and -not $c) { continue }
        if (-not $b) { AddD $name '(whole section)' '' '(absent)' '(present)' 'Added'; continue }
        if (-not $c) { AddD $name '(whole section)' '' '(present)' '(absent)' 'Removed'; continue }

        if ($b.Kind -ne $c.Kind) {
            AddD $name '(whole section)' 'Shape' ([string]$b.Kind) ([string]$c.Kind) 'Changed'
            continue
        }
        if ($b.Kind -eq 'props') {
            $bp = $b.Props; $cp = $c.Props
            $props = @(@($bp.PSObject.Properties.Name) + @($cp.PSObject.Properties.Name)) | Sort-Object -Unique
            foreach ($pn in $props) {
                $bv = [string]$bp.$pn
                $cv = [string]$cp.$pn
                # -ne, not -cne: domain\user and path casing is not stable across
                # scans or DCs, and case-only noise would bury the real changes.
                if ($bv -ne $cv) { AddD $name '' $pn $bv $cv 'Changed' }
            }
            continue
        }

        # Filter nulls: ConvertFrom-Json can hand back $null for an empty array,
        # and @($null) is a one-element array that would diff as a removed row.
        $bRows = @($b.Rows | Where-Object { $null -ne $_ })
        $cRows = @($c.Rows | Where-Object { $null -ne $_ })
        $bMap = @{}; foreach ($r in $bRows) { $bMap[(Get-SnapshotRowKey $name $r)] = $r }
        $cMap = @{}; foreach ($r in $cRows) { $cMap[(Get-SnapshotRowKey $name $r)] = $r }
        foreach ($k in @($bMap.Keys)) {
            if (-not $cMap.ContainsKey($k)) {
                AddD $name $k '' '(present)' '(absent)' 'Removed'
                continue
            }
            $br = $bMap[$k]; $cr = $cMap[$k]
            $props = @(@($br.PSObject.Properties.Name) + @($cr.PSObject.Properties.Name)) | Sort-Object -Unique
            foreach ($pn in $props) {
                $bv = [string]$br.$pn
                $cv = [string]$cr.$pn
                if ($bv -ne $cv) { AddD $name $k $pn $bv $cv 'Changed' }
            }
        }
        foreach ($k in @($cMap.Keys)) {
            if (-not $bMap.ContainsKey($k)) { AddD $name $k '' '(absent)' '(present)' 'Added' }
        }
    }

    $order = @{ Regression = 0; Change = 1 }
    @($out | Sort-Object { $order[$_.Impact] }, Area, Item, Property)
}

# ===========================================================================
#  SHARED RENDER MODEL
#  The WPF dashboard and the HTML report both build from these two functions,
#  so the two views cannot drift apart.
# ===========================================================================

function Get-UnifiedEvents {
    # Merges every event source into one Blocked/Audited/Allowed stream.
    param($d)
    $all = @()
    $all += @(Get-ArrSection $d 'DefenderEvents')
    $all += @(Get-ArrSection $d 'AppLockerEvents')
    $all += @(Get-ArrSection $d 'CodeIntegrityEvents')
    $all += @(Get-ArrSection $d 'SmartScreenEvents')
    $all += @(Get-ArrSection $d 'FirewallChanges')
    $all += @(Get-ArrSection $d 'IdentityEvents')
    $out = @($all | Where-Object { $_ } | Sort-Object Time -Descending | ForEach-Object {
        [pscustomobject]@{
            Time     = Format-Value $_.Time
            Source   = [string]$_.Source
            Action   = [string]$_.Action
            Id       = $_.Id
            Category = [string]$_.Category
            Detail   = [string]$_.Detail
        }
    })
    # Return plain; every caller wraps in @(). Wrapping here as well would
    # produce a one-element array containing the array.
    $out
}

function New-HealthCards {
    # Returns the Overview health tiles as data: Title / Value / Sub / State.
    param($Data, $Events)

    $d    = $Data
    $all  = @($Events)
    $meta = Get-Section $d 'Meta'
    $st   = Get-Section $d 'DefenderStatus'
    $pf   = Get-Section $d 'DefenderPrefs'
    $mde  = Get-Section $d 'MDE'
    $dg   = Get-Section $d 'DeviceGuard'
    $ss   = Get-Section $d 'SecuritySettings'

    $cards = New-Object System.Collections.Generic.List[object]
    function AddCard {
        param([string]$Title, [string]$Value, [string]$Sub, [string]$State = 'Info')
        $cards.Add([pscustomobject]@{ Title = $Title; Value = $Value; Sub = $Sub; State = $State })
    }

    if ($st) {
        $avState = 'Bad'; $avVal = 'Disabled'
        if ($st.AntivirusEnabled) {
            $avVal = 'Enabled'; $avState = 'Good'
            if ($st.AMRunningMode -match 'Passive') { $avVal = 'Passive'; $avState = 'Warn' }
        }
        AddCard 'Defender AV' $avVal "Mode: $($st.AMRunningMode)  Engine $($st.AMEngineVersion)" $avState

        $rtp = if ($st.RealTimeProtectionEnabled) { 'On' } else { 'OFF' }
        AddCard 'Real-Time Protection' $rtp "Behavior monitor: $($st.BehaviorMonitorEnabled)" $(if ($st.RealTimeProtectionEnabled) { 'Good' } else { 'Bad' })

        # Ages are uint32; 4294967295 means "never" - guard before any [int] math.
        $sigState = 'Good'; $sigVal = "$($st.AntivirusSignatureAge) day(s)"
        if ($null -ne $st.AntivirusSignatureAge) {
            if ([int64]$st.AntivirusSignatureAge -ge 4294967295) { $sigState = 'Bad'; $sigVal = 'Never synced' }
            elseif ([int64]$st.AntivirusSignatureAge -gt 7) { $sigState = 'Bad' }
            elseif ([int64]$st.AntivirusSignatureAge -gt 3) { $sigState = 'Warn' }
        }
        AddCard 'Signature Age (last sync)' $sigVal "Updated $(Format-Value $st.AntivirusSignatureLastUpdated)  v$($st.AntivirusSignatureVersion)" $sigState

        $qsState = 'Good'; $qsVal = "$($st.QuickScanAge) day(s) ago"
        if ($null -ne $st.QuickScanAge) {
            if ([int64]$st.QuickScanAge -ge 4294967295) { $qsState = 'Warn'; $qsVal = 'Never' }
            elseif ([int64]$st.QuickScanAge -gt 7) { $qsState = 'Warn' }
        }
        AddCard 'Last Quick Scan' $qsVal "Ended $(Format-Value $st.QuickScanEndTime)" $qsState

        $tp = if ($st.IsTamperProtected) { 'On' } else { 'Off' }
        AddCard 'Tamper Protection' $tp "Source: $($st.TamperProtectionSource)" $(if ($st.IsTamperProtected) { 'Good' } else { 'Warn' })
    }
    if ($pf) {
        $mapsVal = $script:ModeMaps.Maps[[int]$pf.MAPSReporting]
        if (-not $mapsVal) { $mapsVal = [string]$pf.MAPSReporting }
        $cbl = $script:ModeMaps.CloudBlock[[int]$pf.CloudBlockLevel]
        if (-not $cbl) { $cbl = [string]$pf.CloudBlockLevel }
        AddCard 'Cloud Protection (MAPS)' $mapsVal "Block level: $cbl" $(if ($pf.MAPSReporting -ge 1) { 'Good' } else { 'Warn' })

        $npVal = $script:ModeMaps.OnOffAudit[[int]$pf.EnableNetworkProtection]
        if (-not $npVal) { $npVal = [string]$pf.EnableNetworkProtection }
        AddCard 'Network Protection' $npVal '' $(if ($pf.EnableNetworkProtection -eq 1) { 'Good' } elseif ($pf.EnableNetworkProtection -eq 2) { 'Warn' } else { 'Info' })

        $cfaVal = $script:ModeMaps.OnOffAudit[[int]$pf.EnableControlledFolderAccess]
        if (-not $cfaVal) { $cfaVal = [string]$pf.EnableControlledFolderAccess }
        AddCard 'Controlled Folder Access' $cfaVal '' $(if ($pf.EnableControlledFolderAccess -eq 1) { 'Good' } elseif ($pf.EnableControlledFolderAccess -eq 2) { 'Warn' } else { 'Info' })
    }

    $asr = @(Get-ArrSection $d 'AsrRules')
    $asrBlock = @($asr | Where-Object { $_.Mode -in @('Block', 'Warn') }).Count
    $asrAudit = @($asr | Where-Object { $_.Mode -eq 'Audit' }).Count
    $asrState = if ($asrBlock -gt 0) { 'Good' } elseif ($asrAudit -gt 0) { 'Warn' } else { 'Info' }
    AddCard 'ASR Rules' "$asrBlock block / $asrAudit audit" "$($asr.Count) rule(s) configured" $asrState

    $fw = @(Get-ArrSection $d 'FirewallProfiles')
    if ($fw.Count -gt 0) {
        $fwOn = @($fw | Where-Object { $_.Enabled -eq 'True' }).Count
        AddCard 'Firewall' "$fwOn / $($fw.Count) profiles on" (@($fw | ForEach-Object { "$($_.Profile): in=$($_.DefaultInboundAction)" }) -join '  ') $(if ($fwOn -eq $fw.Count) { 'Good' } elseif ($fwOn -gt 0) { 'Warn' } else { 'Bad' })
    }

    if ($mde) {
        $mdeVal = if ($mde.Onboarded) { 'Onboarded' } else { 'Not onboarded' }
        $mdeSub = ''
        if ($mde.LastConnected) { $mdeSub = "Last connected $(Format-Value $mde.LastConnected)" }
        AddCard 'Defender for Endpoint' $mdeVal $mdeSub $(if ($mde.Onboarded) { 'Good' } else { 'Warn' })
    }

    $alPol = @(Get-ArrSection $d 'AppLockerPolicy')
    $alEnforced = @($alPol | Where-Object { $_.Enforcement -eq 'Enabled' }).Count
    $alAuditM   = @($alPol | Where-Object { $_.Enforcement -eq 'AuditOnly' }).Count
    $alVal = 'Not configured'; $alState = 'Info'
    if ($alEnforced -gt 0) { $alVal = "$alEnforced collection(s) enforced"; $alState = 'Good' }
    elseif ($alAuditM -gt 0) { $alVal = "$alAuditM collection(s) audit"; $alState = 'Warn' }
    AddCard 'AppLocker' $alVal '' $alState

    if ($dg) {
        $ciVal = $dg.KernelModeCodeIntegrity
        if (-not $ciVal) { $ciVal = 'Off' }
        AddCard 'WDAC / Code Integrity' $ciVal "User mode: $($dg.UserModeCodeIntegrity)  VBS: $($dg.VirtualizationBasedSecurity)" $(if ($ciVal -eq 'Enforced') { 'Good' } elseif ($ciVal -eq 'Audit mode') { 'Warn' } else { 'Info' })
        $cgVal = if ($dg.ServicesRunning -match 'Credential Guard') { 'Running' } else { 'Not running' }
        AddCard 'Credential Guard' $cgVal "Running: $($dg.ServicesRunning)" $(if ($cgVal -eq 'Running') { 'Good' } else { 'Info' })
    }

    $bl = @(Get-ArrSection $d 'BitLocker')
    $osVol = $bl | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
    if ($osVol) {
        AddCard 'BitLocker (OS volume)' ([string]$osVol.ProtectionStatus) "$($osVol.MountPoint) $($osVol.EncryptionMethod) $($osVol.PercentEncrypted)%" $(if ($osVol.ProtectionStatus -eq 'On') { 'Good' } else { 'Warn' })
    }

    if ($ss) {
        AddCard 'Secure Boot' ([string]$ss.SecureBoot) "TPM present: $($ss.TpmPresent)  ready: $($ss.TpmReady)" $(if ($ss.SecureBoot -eq 'On') { 'Good' } elseif ($ss.SecureBoot -eq 'Off') { 'Warn' } else { 'Info' })
        $uacVal = if ($ss.UacEnabled -eq 0) { 'Disabled' } else { 'Enabled' }
        AddCard 'UAC' $uacVal "LSA PPL: $($ss.LsaRunAsPPL)  SmartScreen: $($ss.SmartScreenExplorer)" $(if ($ss.UacEnabled -eq 0) { 'Bad' } else { 'Good' })
    }

    $ssn = Get-Section $d 'SmartScreen'
    if ($ssn) {
        $ssEv = @(Get-ArrSection $d 'SmartScreenEvents')
        if ($ssn.AppReputationLogEnabled) {
            AddCard 'SmartScreen Prompts' ([string]$ssEv.Count) 'App-reputation events in window' $(if ($ssEv.Count -gt 0) { 'Warn' } else { 'Good' })
        }
        else {
            AddCard 'SmartScreen Prompts' 'Not logged' 'Analytic channel off - see attention items' 'Info'
        }
        AddCard 'Smart App Control' ([string]$ssn.SmartAppControl) 'Blocks appear as Code Integrity 3077/3076' $(if ($ssn.SmartAppControl -match 'enforcement') { 'Good' } elseif ($ssn.SmartAppControl -match 'Evaluation') { 'Warn' } else { 'Info' })
    }

    $psl = Get-Section $d 'PsLogging'
    if ($psl) {
        AddCard 'PS Script Block Logging' ([string]$psl.ScriptBlockLogging) "Transcription: $($psl.Transcription)  Module: $($psl.ModuleLogging)" $(if ($psl.ScriptBlockLogging -eq 'Enabled') { 'Good' } else { 'Warn' })
        if ($psl.PowerShellV2Feature -eq 'Enabled') { AddCard 'PowerShell v2 Engine' 'Installed' 'Bypasses AMSI and script block logging' 'Bad' }
    }
    $lp = Get-Section $d 'Laps'
    if ($lp) {
        $lVal = 'Not configured'; $lState = 'Warn'
        if ($lp.Configured) { $lVal = [string]$lp.BackupDirectory; $lState = $(if ($lp.BackupDirectory -match 'Entra|Active Directory') { 'Good' } else { 'Warn' }) }
        AddCard 'LAPS' $lVal $(if ($lp.Configured) { [string]$lp.ActivePolicySource } else { 'Local admin password unmanaged' }) $lState
    }
    $us = Get-Section $d 'UpdateStatus'
    if ($us) {
        $uVal = 'Up to date'; $uState = 'Good'
        if ($us.RebootPending) { $uVal = 'Reboot pending'; $uState = 'Warn' }
        AddCard 'Windows Update' $uVal "Last check-in: $(Format-Value $us.LastDetectSuccess)" $uState
    }
    $permC = Get-Section $d 'FirewallPermissiveCount'
    if ($null -ne $permC) {
        AddCard 'Permissive Inbound Rules' ([string]$permC) 'Any address, any port/protocol' $(if ([int]$permC -gt 0) { 'Warn' } else { 'Good' })
    }
    $persist = @(Get-ArrSection $d 'SuspectServices').Count + @(Get-ArrSection $d 'SuspectTasks').Count
    AddCard 'Persistence Flags' ([string]$persist) 'Services/tasks from writable or unquoted paths' $(if ($persist -gt 0) { 'Warn' } else { 'Good' })

    $dsRows = @(Get-ArrSection $d 'DsRegStatus')
    $aad = ($dsRows | Where-Object { $_.Property -eq 'AzureAdJoined' } | Select-Object -First 1)
    $joinVal = 'Workgroup'; $joinState = 'Info'
    $isAad = ($aad -and $aad.Value -eq 'YES')
    $isDom = ($meta -and $meta.PartOfDomain)
    if ($isAad -and $isDom) { $joinVal = 'Hybrid joined'; $joinState = 'Good' }
    elseif ($isAad) { $joinVal = 'Entra joined'; $joinState = 'Good' }
    elseif ($isDom) { $joinVal = 'Domain joined'; $joinState = 'Good' }
    $joinSub = ''
    if ($meta) { $joinSub = $meta.Domain }
    AddCard 'Identity Join' $joinVal $joinSub $joinState

    $mdm = @(Get-ArrSection $d 'MdmEnrollment')
    AddCard 'MDM Enrollment' $(if ($mdm.Count -gt 0) { 'Enrolled' } else { 'None' }) $(if ($mdm.Count -gt 0) { [string]$mdm[0].UPN } else { '' }) $(if ($mdm.Count -gt 0) { 'Good' } else { 'Info' })

    $threats = @(Get-ArrSection $d 'Threats')
    AddCard 'Threat Detections' ([string]$threats.Count) 'On record (Defender history)' $(if ($threats.Count -gt 0) { 'Warn' } else { 'Good' })

    $blockedCount = @($all | Where-Object { $_.Action -eq 'Blocked' }).Count
    $auditedCount = @($all | Where-Object { $_.Action -eq 'Audited' }).Count
    $alertCount   = @($all | Where-Object { $_.Action -eq 'Alert' }).Count
    AddCard 'Events In Window' ([string]$all.Count) "$blockedCount blocked / $auditedCount audited / $alertCount alerts" $(if ($alertCount -gt 0) { 'Warn' } else { 'Info' })
    if ($meta) { AddCard 'Uptime' "$($meta.UptimeDays) day(s)" "Last boot $(Format-Value $meta.LastBoot)" $(if ($meta.UptimeDays -gt 30) { 'Warn' } else { 'Good' }) }

    # ToArray(): "@($list)" on a List[object] throws "Argument types do not match".
    $cards.ToArray()
}

function Update-DiffView {
    $ui.GridDiff.ItemsSource = $null
    $script:DiffRows = @()
    if (-not $script:Baseline) {
        $ui.TxtDiffHeader.Text = 'No baseline loaded. Use "Compare to..." to pick a saved snapshot.'
        $ui.BtnClearBaseline.IsEnabled = $false
        Set-GridSource $ui.GridDiff @()
        return
    }
    $ui.BtnClearBaseline.IsEnabled = $true
    if (-not $script:LastScan) {
        $ui.TxtDiffHeader.Text = "Baseline loaded ($($script:Baseline.Computer), $($script:Baseline.ScanTime)). Run a scan to compare."
        Set-GridSource $ui.GridDiff @()
        return
    }
    $cur = [pscustomobject]@{ Sections = (ConvertTo-ScanSnapshot $script:LastScan) }
    $script:DiffRows = @(Compare-ScanSnapshots -Baseline $script:Baseline -Current $cur)
    $reg = @($script:DiffRows | Where-Object { $_.Impact -eq 'Regression' }).Count
    $meta = Get-Section $script:LastScan 'Meta'
    $curName = ''
    if ($meta) { $curName = [string]$meta.ComputerName }
    $warn = ''
    if ($curName -and $script:Baseline.Computer -and $curName -ne $script:Baseline.Computer) {
        $warn = "  [comparing DIFFERENT hosts: $($script:Baseline.Computer) vs $curName]"
    }
    $ui.TxtDiffHeader.Text = "Baseline: $($script:Baseline.Computer) @ $($script:Baseline.ScanTime)  ->  current scan.  " +
                             "$($script:DiffRows.Count) difference(s), $reg flagged as regressions.$warn"
    Set-GridSource $ui.GridDiff @($script:DiffRows)
}

function Show-ScanResults {
    param($d)
    $script:LastScan = $d

    $meta = Get-Section $d 'Meta'
    $st   = Get-Section $d 'DefenderStatus'
    $pf   = Get-Section $d 'DefenderPrefs'
    $dg   = Get-Section $d 'DeviceGuard'
    $ss   = Get-Section $d 'SecuritySettings'

    # ---------------- header ----------------
    if ($meta) {
        $hdr = "$($meta.ComputerName)  |  $($meta.OS) (build $($meta.Build))  |  scanned $(Format-Value $meta.ScanTime)  |  event window: last $($meta.LookbackDays) day(s)"
        $cc0 = Get-Section $d 'ClientContext'
        if ($cc0) { $hdr += "  |  as $($cc0.RunBy)" }
        $ui.TxtScanHeader.Text = $hdr
    }

    # ---------------- cards + unified events (shared with the HTML report) ----
    $ui.PnlCards.Children.Clear()
    $all = @(Get-UnifiedEvents $d)
    $script:AllEvents = $all
    foreach ($c in @(New-HealthCards -Data $d -Events $all)) {
        Add-Card $c.Title $c.Value $c.Sub $c.State
    }
    Set-GridSource $ui.GridEvents $all
    Sync-EventControls

    # locals the detail grids below still need
    $asr     = @(Get-ArrSection $d 'AsrRules')
    $fw      = @(Get-ArrSection $d 'FirewallProfiles')
    $mdm     = @(Get-ArrSection $d 'MdmEnrollment')
    $threats = @(Get-ArrSection $d 'Threats')
    $alPol   = @(Get-ArrSection $d 'AppLockerPolicy')
    $bl      = @(Get-ArrSection $d 'BitLocker')
    $dsRows  = @(Get-ArrSection $d 'DsRegStatus')
    $ssn     = Get-Section $d 'SmartScreen'

    # ---------------- findings ----------------
    Set-GridSource $ui.GridFindings @(New-Findings $d)

    # ---------------- detail grids ----------------
    Set-GridSource $ui.GridDefStatus @(New-NVRows $st)
    Set-GridSource $ui.GridDefPrefs @(New-NVRows $pf)
    Set-GridSource $ui.GridAsr @($asr | Select-Object Rule, Mode, Guid)
    Set-GridSource $ui.GridExclusions @(Get-ArrSection $d 'DefenderExclusions')
    Set-GridSource $ui.GridThreats @($threats | ForEach-Object {
        [pscustomobject]@{
            Time = Format-Value $_.Time; Threat = $_.Threat; Severity = $_.Severity
            User = $_.User; Process = $_.Process; ActionSuccess = $_.ActionSuccess; Resources = $_.Resources
        }
    })

    Set-GridSource $ui.GridFwProfiles @($fw)
    Set-GridSource $ui.GridFwRules @(Get-ArrSection $d 'FirewallRuleSummary')
    Set-GridSource $ui.GridFwChanges @(@(Get-ArrSection $d 'FirewallChanges') | ForEach-Object {
        [pscustomobject]@{ Time = Format-Value $_.Time; Id = $_.Id; Change = $_.Category; Detail = $_.Detail }
    })
    $fwBlocked = @(Get-ArrSection $d 'FirewallBlocked')
    Set-GridSource $ui.GridFwBlocked @($fwBlocked | ForEach-Object {
        [pscustomobject]@{
            Count = $_.Count; LastSeen = Format-Value $_.LastSeen; Application = $_.Application
            Direction = $_.Direction; Remote = $_.Remote; Protocol = $_.Protocol
        }
    })
    $fwBlockedTotal = Get-Section $d 'FirewallBlockedCount'
    if ($fwBlockedTotal) {
        $ui.GrpFwBlocked.Header = "Blocked connections - $fwBlockedTotal audit event(s), grouped (top 40)"
    }
    else {
        $ui.GrpFwBlocked.Header = 'Blocked connections - none captured (enable Filtering Platform auditing for visibility)'
    }

    Set-GridSource $ui.GridAppLockerPolicy @($alPol)
    Set-GridSource $ui.GridDeviceGuard @(New-NVRows $dg)
    Set-GridSource $ui.GridAppLockerEvents @(@(Get-ArrSection $d 'AppLockerEvents') | ForEach-Object {
        [pscustomobject]@{ Time = Format-Value $_.Time; Action = $_.Action; Category = $_.Category; User = $_.User; Detail = $_.Detail }
    })
    Set-GridSource $ui.GridCiEvents @(@(Get-ArrSection $d 'CodeIntegrityEvents') | ForEach-Object {
        [pscustomobject]@{ Time = Format-Value $_.Time; Action = $_.Action; Category = $_.Category; Detail = $_.Detail }
    })

    Set-GridSource $ui.GridDsreg @($dsRows)
    $sc = Get-Section $d 'SecureChannel'
    if ($sc -and $sc.Checked) {
        $scState = if ($sc.Healthy) { 'HEALTHY' } else { 'BROKEN' }
        $ui.TxtSecureChannel.Text = "Domain secure channel: $scState.  $($sc.Detail)"
    }
    elseif ($sc) { $ui.TxtSecureChannel.Text = 'Domain secure channel: not applicable (not domain joined).' }

    Set-GridSource $ui.GridLocalAdmins @(Get-ArrSection $d 'LocalAdmins')
    Set-GridSource $ui.GridLocalUsers @(@(Get-ArrSection $d 'LocalUsers') | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name; Enabled = $_.Enabled; LastLogon = Format-Value $_.LastLogon
            PasswordLastSet = Format-Value $_.PasswordLastSet; PasswordRequired = $_.PasswordRequired; Description = $_.Description
        }
    })
    Set-GridSource $ui.GridLogonSummary @(@(Get-ArrSection $d 'LogonSummary') | ForEach-Object {
        [pscustomobject]@{
            LogonType = $_.LogonType; Count = $_.Count; UniqueAccounts = $_.UniqueAccounts
            MostRecent = Format-Value $_.MostRecent; LastAccount = $_.LastAccount
        }
    })
    $ui.TxtSessions.Text = (@(Get-ArrSection $d 'Sessions') -join "`r`n")

    $failedCount = Get-Section $d 'FailedLogonCount'
    if ($null -eq $failedCount) { $failedCount = 0 }
    $ui.GrpFailed.Header = "Failed logons (4625) - $failedCount in window"
    Set-GridSource $ui.GridFailedTop @(Get-ArrSection $d 'FailedLogonTop')
    Set-GridSource $ui.GridFailedLogons @(@(Get-ArrSection $d 'FailedLogons') | ForEach-Object {
        [pscustomobject]@{
            Time = Format-Value $_.Time; Account = $_.Account; LogonType = $_.LogonType
            SourceIP = $_.SourceIP; Workstation = $_.Workstation; Status = $_.Status
        }
    })
    Set-GridSource $ui.GridIdEvents @(@(Get-ArrSection $d 'IdentityEvents') | ForEach-Object {
        [pscustomobject]@{ Time = Format-Value $_.Time; Id = $_.Id; Event = $_.Category; Detail = $_.Detail }
    })

    $gpo = Get-Section $d 'Gpo'
    if ($gpo) {
        $ui.TxtGpRefresh.Text = "Last Group Policy refresh: $(Format-Value $gpo.LastRefresh)"
        $ui.LstGpos.ItemsSource = @(@($gpo.AppliedGpos) | Where-Object { $_ })
        $ui.TxtGpresult.Text = [string]$gpo.RawText
    }
    Set-GridSource $ui.GridMdm @($mdm)
    Set-GridSource $ui.GridAuditPol @(Get-ArrSection $d 'AuditPolicy')

    Set-GridSource $ui.GridServices @(Get-ArrSection $d 'Services')
    Set-GridSource $ui.GridSecSettings @(New-NVRows $ss)
    Set-GridSource $ui.GridBitLocker @($bl)
    Set-GridSource $ui.GridSmartScreen @(New-NVRows $ssn)
    if ($ssn -and -not $ssn.AppReputationLogEnabled) {
        $ui.GrpSmartScreen.Header = 'SmartScreen and Smart App Control - app-reputation prompts are NOT being logged on this host (see Overview)'
    }
    else { $ui.GrpSmartScreen.Header = 'SmartScreen and Smart App Control' }
    Set-GridSource $ui.GridHotfix @(@(Get-ArrSection $d 'Hotfixes') | ForEach-Object {
        [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = Format-Value $_.InstalledOn; InstalledBy = $_.InstalledBy }
    })
    Set-GridSource $ui.GridPsLogging @(New-NVRows (Get-Section $d 'PsLogging'))
    Set-GridSource $ui.GridLaps      @(New-NVRows (Get-Section $d 'Laps'))
    Set-GridSource $ui.GridExploit   @(New-NVRows (Get-Section $d 'ExploitProtection'))
    Set-GridSource $ui.GridUpdate    @(New-NVRows (Get-Section $d 'UpdateStatus'))

    $suspectSvc  = @(Get-ArrSection $d 'SuspectServices')
    $suspectTask = @(Get-ArrSection $d 'SuspectTasks')
    Set-GridSource $ui.GridSuspectSvc  @($suspectSvc)
    Set-GridSource $ui.GridSuspectTask @($suspectTask | ForEach-Object {
        [pscustomobject]@{
            Task = $_.Task; State = $_.State; RunAs = $_.RunAs; RunLevel = $_.RunLevel
            Author = $_.Author; LastRun = Format-Value $_.LastRun; LastResult = $_.LastResult
            Concern = $_.Concern; Command = $_.Command
        }
    })
    $ui.GrpSuspectSvc.Header  = "Services from user-writable or unquoted paths - $($suspectSvc.Count) flagged"
    $ui.GrpSuspectTask.Header = "Non-Microsoft scheduled tasks from user-writable paths - $($suspectTask.Count) flagged"

    $fwPerm = @(Get-ArrSection $d 'FirewallPermissive')
    $fwPermTotal = Get-Section $d 'FirewallPermissiveCount'
    Set-GridSource $ui.GridFwPermissive @($fwPerm)
    $ui.GrpFwPermissive.Header = "Permissive inbound rules - $fwPermTotal enabled Allow rule(s) open to any address on any port/protocol (showing $($fwPerm.Count))"

    Set-GridSource $ui.GridErrors @(Get-ArrSection $d 'Errors')

    $ui.BtnExport.IsEnabled = $true
    $ui.BtnExport.Background = $script:BrushConv.ConvertFromString('#FF2F6FED')
    $ui.BtnSaveBaseline.IsEnabled = $true
    $ui.BtnSaveBaseline.Background = $script:BrushConv.ConvertFromString('#FF2F6FED')
    Update-DiffView
}

# ===========================================================================
#  HTML report export
#  Emits a single self-contained file: the scan data as embedded JSON plus a
#  small vanilla-JS app that mirrors the WPF dashboard (tabs, health cards,
#  sortable columns, per-column filters, global find, row detail, CSV).
#  No CDN, no external assets - it works from a file share or an email.
# ===========================================================================

$script:ReportTemplate = @'
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#14141a; --panel:#1b1b22; --card:#23232c; --row:#1d1d25; --rowalt:#22222b;
  --line:#33333f; --fg:#e8e8ee; --muted:#9b9baa; --dim:#70707e;
  --accent:#4fc3f7; --blue:#2f6fed; --good:#3fb68b; --warn:#e7b549; --bad:#e36262;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:13px/1.45 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
a{color:var(--accent)}
.hdr{background:var(--panel);border-bottom:1px solid var(--line);padding:14px 18px;position:sticky;top:0;z-index:40}
.hdr h1{margin:0 0 4px;font-size:19px;font-weight:600}
.sub{color:var(--muted);font-size:12px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:11px}
input[type=text],input[type=search]{background:#2a2a35;color:var(--fg);border:1px solid #444452;border-radius:4px;padding:6px 9px;font:inherit;outline:none}
input:focus{border-color:var(--blue)}
button{background:#3a3a46;color:#fff;border:0;border-radius:4px;padding:7px 13px;font:inherit;cursor:pointer}
button:hover{filter:brightness(1.18)}
button.pri{background:var(--blue)}
button.on{background:var(--blue)}
.spacer{flex:1}
.hint{color:var(--dim);font-size:11.5px}
nav{display:flex;flex-wrap:wrap;gap:3px;background:var(--panel);padding:0 12px;border-bottom:1px solid var(--line);position:sticky;top:var(--hdrh,104px);z-index:35}
nav button{background:transparent;color:var(--muted);border-radius:4px 4px 0 0;padding:10px 15px}
nav button.on{background:var(--card);color:#fff}
nav .badge{display:inline-block;margin-left:7px;background:var(--blue);color:#fff;border-radius:9px;padding:0 7px;font-size:10.5px;line-height:16px;vertical-align:1px}
main{padding:14px 18px 60px}
section{display:none}
section.on{display:block}
.cards{display:flex;flex-wrap:wrap;gap:11px;margin-bottom:22px}
.card{background:var(--card);border-left:4px solid var(--dim);border-radius:6px;padding:10px 13px;width:216px;min-height:76px}
.card .t{color:var(--muted);font-size:11.5px}
.card .v{font-size:17px;font-weight:600;margin:2px 0}
.card .s{color:var(--dim);font-size:11px}
.card.Good{border-left-color:var(--good)} .card.Good .v{color:var(--good)}
.card.Warn{border-left-color:var(--warn)} .card.Warn .v{color:var(--warn)}
.card.Bad{border-left-color:var(--bad)}   .card.Bad  .v{color:var(--bad)}
.card.Info{border-left-color:var(--dim)}  .card.Info .v{color:#c3c3d0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;margin:0 0 16px;overflow:hidden}
.panel>h2{margin:0;padding:9px 13px;font-size:13px;font-weight:600;color:#bcd9ee;background:#20202a;border-bottom:1px solid var(--line)}
.note{color:var(--muted);font-size:11.5px;padding:8px 13px 0}
.chips{display:flex;flex-wrap:wrap;gap:6px;padding:10px 13px 0}
.chips button{padding:5px 12px;font-size:12px}
.tw{overflow:auto;max-height:70vh}
table{border-collapse:collapse;width:100%}
th{position:sticky;top:0;background:#2a2a35;color:#b9b9c6;text-align:left;font-weight:600;font-size:12px;white-space:nowrap;z-index:5;border-bottom:1px solid var(--line);border-right:1px solid var(--line)}
th .th{display:flex;align-items:center;gap:6px;padding:6px 9px}
th .lbl{cursor:pointer;user-select:none;flex:1}
th .lbl:hover{color:#fff}
th .arw{color:var(--accent);font-size:9px;width:8px}
th .fb{cursor:pointer;color:var(--dim);font-size:10px;padding:0 2px;border-radius:3px}
th .fb:hover{color:#fff;background:#3a3a46}
th.filtered .fb{color:var(--accent)}
th.filtered .lbl::after{content:" *";color:var(--accent)}
td{padding:4px 9px;border-bottom:1px solid #26262e;font-size:12px;max-width:640px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:top}
tbody tr{background:var(--row);cursor:pointer}
tbody tr:nth-child(even){background:var(--rowalt)}
tbody tr:hover{background:#2c2c39}
tbody tr.empty{background:transparent;cursor:default;color:var(--dim);font-style:italic}
tbody tr.empty td{white-space:normal}
.foot{display:flex;gap:10px;align-items:center;padding:7px 13px;color:var(--muted);font-size:11.5px;border-top:1px solid var(--line);background:#1a1a21}
.foot button{padding:4px 10px;font-size:11.5px;background:#2f2f3a}
.sev-Critical{color:var(--bad);font-weight:600}
.sev-Warning{color:var(--warn);font-weight:600}
.sev-Good{color:var(--good);font-weight:600}
.sev-Info{color:var(--muted)}
pre.raw{margin:0;padding:11px 13px;background:#171720;color:#c8c8d4;font:11.5px/1.5 Consolas,"Courier New",monospace;overflow:auto;max-height:65vh;white-space:pre}
ul.plain{margin:0;padding:10px 13px 12px 30px}
ul.plain li{margin:2px 0}
/* filter dropdown */
#fp{position:absolute;z-index:80;width:312px;background:var(--card);border:1px solid #4a4a5a;border-radius:5px;padding:10px;box-shadow:0 10px 30px rgba(0,0,0,.6);display:none}
#fp h3{margin:0 0 8px;font-size:13px}
#fp .row{display:flex;gap:6px;margin-bottom:7px}
#fp .row button{flex:1;font-size:12px;padding:6px}
#fp input{width:100%}
#fp label{font-size:11px;color:var(--muted);display:block;margin:6px 0 2px}
#fp .vals{height:196px;overflow:auto;background:var(--row);border:1px solid var(--line);border-radius:4px;padding:5px;margin-top:4px}
#fp .vals div{padding:1px 2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#fp .vals input{width:auto;margin-right:6px;vertical-align:-1px}
#fp .vals label{display:inline;color:var(--fg);font-size:12px;margin:0}
/* row modal */
#mask{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;z-index:90;padding:36px}
#mask.on{display:flex;align-items:flex-start;justify-content:center}
#modal{background:var(--bg);border:1px solid var(--line);border-radius:7px;width:min(880px,100%);max-height:100%;display:flex;flex-direction:column}
#modal .mh{display:flex;align-items:center;padding:12px 15px;border-bottom:1px solid var(--line)}
#modal .mh h3{margin:0;font-size:15px;flex:1}
#modal .mb{overflow:auto;padding:14px 15px}
#modal .f{color:var(--muted);font-size:11px;font-weight:600;margin-bottom:2px}
#modal .v{background:var(--row);border:1px solid var(--line);border-radius:4px;padding:6px 8px;margin-bottom:10px;white-space:pre-wrap;word-break:break-word;font-size:12.5px}
@media print{
  .hdr,nav,#fp,#mask,.foot,.chips{display:none!important}
  section{display:block!important;break-inside:auto}
  .tw{max-height:none;overflow:visible}
  th{position:static}
  body{background:#fff;color:#000}
  .panel,.card{border-color:#bbb;background:#fff}
  .panel>h2{background:#eee;color:#000}
  td,th{color:#000;background:#fff!important}
  tr{break-inside:avoid}
}
</style></head>
<body>
<div class="hdr">
  <h1 id="h1"></h1>
  <div class="sub" id="sub"></div>
  <div class="toolbar">
    <input type="search" id="find" placeholder="Find in all tables&hellip;  (press /)" style="width:250px">
    <button id="clr">Clear filters</button>
    <span class="spacer"></span>
    <span class="hint">Click a header to sort &middot; the arrow opens filters &middot; click a row for full detail</span>
    <button onclick="window.print()">Print / PDF</button>
  </div>
</div>
<nav id="nav"></nav>
<main id="main"></main>
<div id="fp"></div>
<div id="mask"><div id="modal">
  <div class="mh"><h3>Row detail</h3><button id="mcopy">Copy all</button>
  <button id="mclose" class="pri" style="margin-left:8px">Close</button></div>
  <div class="mb" id="mbody"></div>
</div></div>
<script type="application/json" id="payload">__PAYLOAD__</script>
<script>
"use strict";
var A = function(x){ return Array.isArray(x) ? x : (x===null||x===undefined ? [] : [x]); };
var D = JSON.parse(document.getElementById('payload').textContent);
var PANELS = A(D.panels), CARDS = A(D.cards), FINDINGS = A(D.findings);
var esc = function(s){ return String(s===null||s===undefined?'':s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
var ST = {};            // panel id -> {sort,desc,filters{},contains{},search}
var find = '';

// ---- ordering for the Events quick chips
var QORDER = ['Blocked','Audited','Allowed','Detected','Alert','Info'];

function cols(rows){ return rows.length ? Object.keys(rows[0]) : []; }

function passes(p, r, skipCol){
  var s = ST[p.id];
  if (find){
    var hit = false, k;
    for (k in r){ if (String(r[k]).toLowerCase().indexOf(find) >= 0){ hit = true; break; } }
    if (!hit) return false;
  }
  for (var c in s.filters){
    if (c === skipCol) continue;
    if (s.filters[c].indexOf(String(r[c])) < 0) return false;
  }
  for (var c2 in s.contains){
    if (c2 === skipCol) continue;
    var n = s.contains[c2].toLowerCase();
    if (!n) continue;
    if (String(r[c2]).toLowerCase().indexOf(n) < 0) return false;
  }
  return true;
}

function view(p, skipCol){
  var rows = A(p.rows).filter(function(r){ return passes(p, r, skipCol); });
  var s = ST[p.id];
  if (s.sort){
    var c = s.sort, dir = s.desc ? -1 : 1;
    rows = rows.slice().sort(function(a,b){
      var x = a[c], y = b[c];
      var nx = parseFloat(x), ny = parseFloat(y);
      var num = !isNaN(nx) && !isNaN(ny) && /^-?[\d.,]+%?$/.test(String(x).trim()) && /^-?[\d.,]+%?$/.test(String(y).trim());
      if (num) return (nx - ny) * dir;
      return String(x).localeCompare(String(y), undefined, {numeric:true, sensitivity:'base'}) * dir;
    });
  }
  return rows;
}

function tabsOf(){
  var seen = [], i;
  for (i = 0; i < PANELS.length; i++) if (seen.indexOf(PANELS[i].tab) < 0) seen.push(PANELS[i].tab);
  return seen;
}

// ------------------------------------------------------------------ render
function renderNav(){
  var tabs = tabsOf(), cur = document.querySelector('nav button.on');
  var curName = cur ? cur.dataset.tab : tabs[0];
  document.getElementById('nav').innerHTML = tabs.map(function(t){
    var n = 0;
    if (find){
      PANELS.forEach(function(p){ if (p.tab === t && p.type === 'table') n += view(p).length; });
    }
    return '<button data-tab="' + esc(t) + '" class="' + (t === curName ? 'on' : '') + '">' + esc(t) +
      (find ? '<span class="badge">' + n + '</span>' : '') + '</button>';
  }).join('');
  document.querySelectorAll('nav button').forEach(function(b){
    b.onclick = function(){ showTab(b.dataset.tab); };
  });
}

function showTab(t){
  document.querySelectorAll('nav button').forEach(function(b){ b.classList.toggle('on', b.dataset.tab === t); });
  document.querySelectorAll('main section').forEach(function(s){ s.classList.toggle('on', s.dataset.tab === t); });
  hideFp();
}

function renderTable(p){
  var rows = view(p), s = ST[p.id], cs = cols(A(p.rows));
  var h = '<div class="tw"><table><thead><tr>' + cs.map(function(c){
    var filtered = (s.filters[c] || (s.contains[c] && s.contains[c].length));
    var arw = s.sort === c ? (s.desc ? '&#9660;' : '&#9650;') : '';
    return '<th class="' + (filtered ? 'filtered' : '') + '"><div class="th">' +
      '<span class="lbl" data-p="' + p.id + '" data-c="' + esc(c) + '">' + esc(c) + '</span>' +
      '<span class="arw">' + arw + '</span>' +
      '<span class="fb" data-p="' + p.id + '" data-c="' + esc(c) + '">&#9662;</span></div></th>';
  }).join('') + '</tr></thead><tbody>';
  if (!rows.length){
    h += '<tr class="empty"><td colspan="' + Math.max(cs.length,1) + '">' +
         (A(p.rows).length ? 'No rows match the current filters.' : 'No data.') + '</td></tr>';
  } else {
    h += rows.map(function(r, i){
      return '<tr data-p="' + p.id + '" data-i="' + i + '">' + cs.map(function(c){
        var v = r[c] === null || r[c] === undefined ? '' : String(r[c]);
        var cls = (c === 'Severity') ? ' class="sev-' + esc(v) + '"' : '';
        return '<td' + cls + ' title="' + esc(v) + '">' + esc(v) + '</td>';
      }).join('') + '</tr>';
    }).join('');
  }
  h += '</tbody></table></div>';
  h += '<div class="foot"><span>' + rows.length + ' of ' + A(p.rows).length + ' rows</span>' +
       '<button data-csv="' + p.id + '">Download CSV</button>' +
       '<button data-rst="' + p.id + '">Reset this table</button></div>';
  return h;
}

function renderPanel(p){
  var h = '<div class="panel" id="pnl_' + p.id + '"><h2>' + esc(p.title) + '</h2>';
  if (p.note) h += '<div class="note">' + esc(p.note) + '</div>';
  if (p.type === 'text'){ h += '<pre class="raw">' + esc(p.text) + '</pre></div>'; return h; }
  if (p.type === 'list'){
    var items = A(p.rows);
    h += items.length ? '<ul class="plain">' + items.map(function(x){ return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>'
                      : '<div class="note" style="padding-bottom:10px">No data.</div>';
    return h + '</div>';
  }
  if (p.quick){
    var vals = [], seen = {};
    A(p.rows).forEach(function(r){ var v = String(r[p.quick]); if (!seen[v]){ seen[v] = 1; vals.push(v); } });
    vals.sort(function(a,b){
      var ia = QORDER.indexOf(a), ib = QORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
    var cf = ST[p.id].filters[p.quick];
    var act = (cf && cf.length === 1) ? cf[0] : '';
    h += '<div class="chips"><button data-q="' + p.id + '" data-qv="" class="' + (act ? '' : 'on') + '">All</button>' +
      vals.map(function(v){
        return '<button data-q="' + p.id + '" data-qv="' + esc(v) + '" class="' + (act === v ? 'on' : '') + '">' + esc(v) + '</button>';
      }).join('') + '</div>';
  }
  return h + renderTable(p) + '</div>';
}

function renderAll(){
  var tabs = tabsOf();
  document.getElementById('main').innerHTML = tabs.map(function(t, i){
    return '<section data-tab="' + esc(t) + '" class="' + (i === 0 ? 'on' : '') + '">' +
      (t === 'Overview' ? '<div class="cards">' + CARDS.map(function(c){
        return '<div class="card ' + esc(c.State) + '"><div class="t">' + esc(c.Title) + '</div>' +
               '<div class="v">' + esc(c.Value) + '</div><div class="s">' + esc(c.Sub) + '</div></div>';
      }).join('') + '</div>' : '') +
      PANELS.filter(function(p){ return p.tab === t; }).map(renderPanel).join('') + '</section>';
  }).join('');
  renderNav();
  wire();
}

function repaint(p){
  var el = document.getElementById('pnl_' + p.id);
  if (!el) return;
  el.outerHTML = renderPanel(p);
  wire();
  renderNav();
}

// ------------------------------------------------------------------ events
function wire(){
  document.querySelectorAll('th .lbl').forEach(function(e){
    e.onclick = function(){
      var p = byId(e.dataset.p), s = ST[p.id], c = e.dataset.c;
      if (s.sort === c) s.desc = !s.desc; else { s.sort = c; s.desc = false; }
      repaint(p);
    };
  });
  document.querySelectorAll('th .fb').forEach(function(e){
    e.onclick = function(ev){ ev.stopPropagation(); openFp(byId(e.dataset.p), e.dataset.c, e); };
  });
  document.querySelectorAll('tbody tr[data-p]').forEach(function(tr){
    tr.onclick = function(){
      var p = byId(tr.dataset.p);
      showRow(view(p)[parseInt(tr.dataset.i, 10)]);
    };
  });
  document.querySelectorAll('[data-q]').forEach(function(b){
    b.onclick = function(){
      var p = byId(b.dataset.q), s = ST[p.id], v = b.dataset.qv;
      if (v) s.filters[p.quick] = [v]; else delete s.filters[p.quick];
      repaint(p);
    };
  });
  document.querySelectorAll('[data-csv]').forEach(function(b){
    b.onclick = function(){ csv(byId(b.dataset.csv)); };
  });
  document.querySelectorAll('[data-rst]').forEach(function(b){
    b.onclick = function(){
      var p = byId(b.dataset.rst);
      ST[p.id] = { sort:null, desc:false, filters:{}, contains:{} };
      repaint(p);
    };
  });
}
function byId(id){ for (var i = 0; i < PANELS.length; i++) if (PANELS[i].id === id) return PANELS[i]; return null; }

// ------------------------------------------------------- filter dropdown
var fpPanel = null, fpCol = null;
function hideFp(){ document.getElementById('fp').style.display = 'none'; fpPanel = null; }

function openFp(p, c, anchor){
  fpPanel = p; fpCol = c;
  var s = ST[p.id];
  var pool = view(p, c);
  var seen = {}, vals = [];
  pool.forEach(function(r){ var v = String(r[c]); if (!seen[v]){ seen[v] = 1; vals.push(v); } });
  vals.sort(function(a,b){ return a.localeCompare(b, undefined, {numeric:true, sensitivity:'base'}); });
  var sel = s.filters[c] || null;
  var big = vals.length > 600;
  var fp = document.getElementById('fp');
  fp.innerHTML = '<h3>' + esc(c) + '</h3>' +
    '<div class="row"><button id="sa">Sort A-Z</button><button id="sd">Sort Z-A</button></div>' +
    '<label>Text contains</label><input type="text" id="ct" value="' + esc(s.contains[c] || '') + '">' +
    '<label>Values (' + vals.length + ' distinct)</label>' +
    (big ? '<div class="note" style="padding:4px 0">Too many distinct values to list. Use "Text contains".</div>'
         : '<input type="text" id="vs" placeholder="Search values"><div class="row" style="margin-top:6px">' +
           '<button id="va">Select all</button><button id="vn">Select none</button></div>' +
           '<div class="vals" id="vl">' + vals.map(function(v, i){
             var ck = (sel === null) ? 'checked' : (sel.indexOf(v) >= 0 ? 'checked' : '');
             return '<div><label><input type="checkbox" ' + ck + ' data-v="' + esc(v) + '">' +
                    esc(v === '' ? '(blank)' : v) + '</label></div>';
           }).join('') + '</div>') +
    '<div class="row" style="margin-top:9px"><button id="fc">Clear filter</button><button id="fa" class="pri">Apply</button></div>';

  // Anchor under the button; flip to right-aligned only if it would overflow.
  var r = anchor.getBoundingClientRect();
  fp.style.display = 'block';
  var vw = document.documentElement.clientWidth, w = 312;
  var left = r.left + window.scrollX;
  if (left + w > window.scrollX + vw - 8) left = r.right + window.scrollX - w;
  left = Math.max(window.scrollX + 6, Math.min(left, window.scrollX + vw - w - 8));
  fp.style.left = left + 'px';
  fp.style.top = (r.bottom + window.scrollY + 4) + 'px';

  fp.querySelector('#sa').onclick = function(){ s.sort = c; s.desc = false; hideFp(); repaint(p); };
  fp.querySelector('#sd').onclick = function(){ s.sort = c; s.desc = true;  hideFp(); repaint(p); };
  fp.querySelector('#fc').onclick = function(){ delete s.filters[c]; delete s.contains[c]; hideFp(); repaint(p); };
  fp.querySelector('#fa').onclick = function(){
    var ct = fp.querySelector('#ct').value;
    if (ct) s.contains[c] = ct; else delete s.contains[c];
    var vl = fp.querySelector('#vl');
    if (big){ delete s.filters[c]; }
    else if (vl){
      var boxes = vl.querySelectorAll('input[type=checkbox]');
      var on = [];
      boxes.forEach(function(b){ if (b.checked) on.push(b.dataset.v); });
      if (on.length === boxes.length) delete s.filters[c]; else s.filters[c] = on;
    }
    hideFp(); repaint(p);
  };
  if (!big){
    fp.querySelector('#va').onclick = function(){
      fp.querySelectorAll('#vl div').forEach(function(d){
        if (d.style.display !== 'none') d.querySelector('input').checked = true; });
    };
    fp.querySelector('#vn').onclick = function(){
      fp.querySelectorAll('#vl div').forEach(function(d){
        if (d.style.display !== 'none') d.querySelector('input').checked = false; });
    };
    fp.querySelector('#vs').oninput = function(){
      var n = this.value.toLowerCase();
      fp.querySelectorAll('#vl div').forEach(function(d){
        d.style.display = d.textContent.toLowerCase().indexOf(n) >= 0 ? '' : 'none'; });
    };
  }
}
document.addEventListener('mousedown', function(e){
  var fp = document.getElementById('fp');
  if (fp.style.display === 'block' && !fp.contains(e.target) && !e.target.classList.contains('fb')) hideFp();
});

// ------------------------------------------------------------- row modal
var modalRow = null;
function showRow(r){
  if (!r) return;
  modalRow = r;
  document.getElementById('mbody').innerHTML = Object.keys(r).map(function(k){
    return '<div class="f">' + esc(k) + '</div><div class="v">' + esc(r[k]) + '</div>';
  }).join('');
  document.getElementById('mask').classList.add('on');
}
document.getElementById('mclose').onclick = function(){ document.getElementById('mask').classList.remove('on'); };
document.getElementById('mask').onclick = function(e){ if (e.target.id === 'mask') this.classList.remove('on'); };
document.getElementById('mcopy').onclick = function(){
  if (!modalRow) return;
  var t = Object.keys(modalRow).map(function(k){ return k + ': ' + modalRow[k]; }).join('\n');
  if (navigator.clipboard) navigator.clipboard.writeText(t);
  else { var a = document.createElement('textarea'); a.value = t; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
  this.textContent = 'Copied';
  var b = this; setTimeout(function(){ b.textContent = 'Copy all'; }, 1200);
};

// ----------------------------------------------------------------- CSV
function csv(p){
  var rows = view(p), cs = cols(A(p.rows));
  var q = function(v){ return '"' + String(v === null || v === undefined ? '' : v).replace(/"/g, '""') + '"'; };
  var txt = cs.map(q).join(',') + '\r\n' + rows.map(function(r){ return cs.map(function(c){ return q(r[c]); }).join(','); }).join('\r\n');
  var url = URL.createObjectURL(new Blob(['\uFEFF' + txt], {type:'text/csv;charset=utf-8'}));
  var a = document.createElement('a');
  a.href = url; a.download = (D.host || 'report') + '_' + p.id + '.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 4000);
}

// ----------------------------------------------------------------- boot
PANELS.forEach(function(p){ ST[p.id] = { sort:null, desc:false, filters:{}, contains:{} }; });
document.getElementById('h1').textContent = D.title;
document.getElementById('sub').textContent = D.subtitle;

var findTimer = null;
document.getElementById('find').addEventListener('input', function(){
  var v = this.value;
  clearTimeout(findTimer);
  findTimer = setTimeout(function(){
    find = v.trim().toLowerCase();
    var cur = document.querySelector('nav button.on');
    var t = cur ? cur.dataset.tab : null;
    renderAll();
    if (t) showTab(t);
  }, 180);
});
document.getElementById('clr').onclick = function(){
  find = ''; document.getElementById('find').value = '';
  PANELS.forEach(function(p){ ST[p.id] = { sort:null, desc:false, filters:{}, contains:{} }; });
  var cur = document.querySelector('nav button.on');
  var t = cur ? cur.dataset.tab : null;
  renderAll(); if (t) showTab(t);
};
document.addEventListener('keydown', function(e){
  if (e.key === 'Escape'){ hideFp(); document.getElementById('mask').classList.remove('on'); }
  if (e.key === '/' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA'){
    e.preventDefault(); document.getElementById('find').focus();
  }
});
function sizeNav(){
  document.documentElement.style.setProperty('--hdrh', document.querySelector('.hdr').offsetHeight + 'px');
}
window.addEventListener('resize', sizeNav);
renderAll(); sizeNav();
</script>
</body></html>
'@

function ConvertTo-ReportRows {
    # Flattens rows to all-string properties so the JSON is predictable and the
    # browser renders exactly what the WPF grids show.
    param($Rows)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $o[$p.Name] = (Format-Value $p.Value) }
        $out.Add([pscustomobject]$o)
    }
    $out.ToArray()
}

function New-ReportPanel {
    param(
        [string]$Tab,
        [string]$Title,
        [ValidateSet('table', 'text', 'list')][string]$Type = 'table',
        $Rows,
        [string]$Text = '',
        [string]$Note = '',
        [string]$Quick = ''
    )
    $script:ReportPanelSeq++
    $id = 'p{0}' -f $script:ReportPanelSeq
    $r = @()
    if ($Type -eq 'table') { $r = @(ConvertTo-ReportRows $Rows) }
    elseif ($Type -eq 'list') { $r = @($Rows | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    [pscustomobject]@{
        id = $id; tab = $Tab; title = $Title; type = $Type
        note = $Note; quick = $Quick; text = $Text; rows = $r
    }
}

function Get-HtmlReport {
    param($d)

    $script:ReportPanelSeq = 0
    $meta = Get-Section $d 'Meta'
    $host_ = 'target'
    $title = 'Security Health Report'
    $subtitle = ''
    if ($meta) {
        $host_ = [string]$meta.ComputerName
        $title = "Security Health Report - $host_"
        $subtitle = "$($meta.OS) (build $($meta.Build))  |  Domain: $($meta.Domain)  |  Scanned $(Format-Value $meta.ScanTime)  |  " +
                    "Event window: last $($meta.LookbackDays) day(s)  |  Uptime $($meta.UptimeDays) day(s)"
    }
    $cc = Get-Section $d 'ClientContext'
    if ($cc) {
        $subtitle += "  |  Collected by $($cc.RunBy) from $($cc.FromHost)"
    }

    $events = @(Get-UnifiedEvents $d)
    $cards  = @(New-HealthCards -Data $d -Events $events)
    $panels = New-Object System.Collections.Generic.List[object]

    # ---------------------------------------------------------- Overview
    $panels.Add((New-ReportPanel -Tab 'Overview' -Title 'Attention items' -Rows (New-Findings $d)))

    # ---------------------------------------------------------- Defender
    $panels.Add((New-ReportPanel -Tab 'Defender' -Title 'Engine and protection status' -Rows (New-NVRows (Get-Section $d 'DefenderStatus'))))
    $panels.Add((New-ReportPanel -Tab 'Defender' -Title 'Preferences (policy-effective)' -Rows (New-NVRows (Get-Section $d 'DefenderPrefs'))))
    $panels.Add((New-ReportPanel -Tab 'Defender' -Title 'Attack Surface Reduction rules' -Rows (Get-ArrSection $d 'AsrRules')))
    $panels.Add((New-ReportPanel -Tab 'Defender' -Title 'Exclusions and Controlled Folder Access lists' -Rows (Get-ArrSection $d 'DefenderExclusions') -Note 'Every entry here is a hole in coverage or an explicit allowance - review them.'))

    # -------------------------------------------------------- Detections
    $panels.Add((New-ReportPanel -Tab 'Detections' -Title 'Defender threat detections' -Rows (Get-ArrSection $d 'Threats')))

    # ------------------------------------------------------------ Events
    $panels.Add((New-ReportPanel -Tab 'Events' -Title 'Unified security events' -Rows $events -Quick 'Action' -Note 'Every source merged: Defender, ASR, Controlled Folder Access, Network Protection, SmartScreen, AppLocker, WDAC, firewall and the Security log.'))

    # ---------------------------------------------------------- Firewall
    $fwBlockedTotal = Get-Section $d 'FirewallBlockedCount'
    $fwNote = 'No blocked-connection audits captured. Filtering Platform auditing is off, so this is "not logged", not "nothing blocked".'
    if ($fwBlockedTotal) { $fwNote = "$fwBlockedTotal audit event(s), grouped into the top 40 talkers." }
    $panels.Add((New-ReportPanel -Tab 'Firewall' -Title 'Profiles' -Rows (Get-ArrSection $d 'FirewallProfiles')))
    $panels.Add((New-ReportPanel -Tab 'Firewall' -Title 'Enabled rule counts' -Rows (Get-ArrSection $d 'FirewallRuleSummary')))
    $panels.Add((New-ReportPanel -Tab 'Firewall' -Title 'Rule changes in window' -Rows (Get-ArrSection $d 'FirewallChanges')))
    $panels.Add((New-ReportPanel -Tab 'Firewall' -Title 'Blocked connections (grouped)' -Rows (Get-ArrSection $d 'FirewallBlocked') -Note $fwNote))
    $permTotalR = Get-Section $d 'FirewallPermissiveCount'
    $panels.Add((New-ReportPanel -Tab 'Firewall' -Title 'Permissive inbound rules' -Rows (Get-ArrSection $d 'FirewallPermissive') -Quick 'Scoped' -Note "$permTotalR enabled inbound Allow rule(s) accept traffic from any address on any port or protocol. Rules not scoped to a program are the ones worth challenging."))

    # ---------------------------------------------------- AppLocker/WDAC
    $panels.Add((New-ReportPanel -Tab 'AppLocker / WDAC' -Title 'AppLocker effective policy' -Rows (Get-ArrSection $d 'AppLockerPolicy')))
    $panels.Add((New-ReportPanel -Tab 'AppLocker / WDAC' -Title 'Device Guard / WDAC / VBS' -Rows (New-NVRows (Get-Section $d 'DeviceGuard'))))
    $panels.Add((New-ReportPanel -Tab 'AppLocker / WDAC' -Title 'AppLocker events' -Rows (Get-ArrSection $d 'AppLockerEvents') -Quick 'Action'))
    $panels.Add((New-ReportPanel -Tab 'AppLocker / WDAC' -Title 'Code Integrity events (3076 audit / 3077 block)' -Rows (Get-ArrSection $d 'CodeIntegrityEvents') -Note 'Smart App Control blocks also land here.'))

    # ---------------------------------------------------------- Identity
    $sc = Get-Section $d 'SecureChannel'
    $scNote = ''
    if ($sc -and $sc.Checked) {
        $scState = 'HEALTHY'
        if (-not $sc.Healthy) { $scState = 'BROKEN' }
        $scNote = "Domain secure channel: $scState.  $($sc.Detail)"
    }
    elseif ($sc) { $scNote = 'Domain secure channel: not applicable (not domain joined).' }
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Device identity (dsregcmd)' -Rows (Get-ArrSection $d 'DsRegStatus') -Note $scNote))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Local Administrators group' -Rows (Get-ArrSection $d 'LocalAdmins')))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Local user accounts' -Rows (Get-ArrSection $d 'LocalUsers')))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Logon summary (4624)' -Rows (Get-ArrSection $d 'LogonSummary')))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Active sessions (quser)' -Type 'text' -Text ((@(Get-ArrSection $d 'Sessions')) -join "`r`n")))
    $failedCount = Get-Section $d 'FailedLogonCount'
    if ($null -eq $failedCount) { $failedCount = 0 }
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Top failed-logon accounts (4625)' -Rows (Get-ArrSection $d 'FailedLogonTop') -Note "$failedCount failed logon(s) in window."))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Recent failed logons (4625)' -Rows (Get-ArrSection $d 'FailedLogons')))
    $panels.Add((New-ReportPanel -Tab 'Identity' -Title 'Account / group / audit-policy changes' -Rows (Get-ArrSection $d 'IdentityEvents')))

    # ---------------------------------------------------------- Policies
    $gpo = Get-Section $d 'Gpo'
    $gpoRows = @(); $gpoNote = ''; $gpoRaw = ''
    if ($gpo) {
        $gpoRows = @(@($gpo.AppliedGpos) | Where-Object { $_ })
        $gpoNote = "Last Group Policy refresh: $(Format-Value $gpo.LastRefresh)"
        $gpoRaw = [string]$gpo.RawText
    }
    $panels.Add((New-ReportPanel -Tab 'Policies' -Title 'Applied computer GPOs' -Type 'list' -Rows $gpoRows -Note $gpoNote))
    $panels.Add((New-ReportPanel -Tab 'Policies' -Title 'MDM (Intune) enrollment' -Rows (Get-ArrSection $d 'MdmEnrollment')))
    $panels.Add((New-ReportPanel -Tab 'Policies' -Title 'Effective audit policy (auditpol)' -Rows (Get-ArrSection $d 'AuditPolicy') -Quick 'Setting'))
    $panels.Add((New-ReportPanel -Tab 'Policies' -Title 'gpresult /r (computer scope)' -Type 'text' -Text $gpoRaw))

    # ------------------------------------------------------------ System
    $ssnR = Get-Section $d 'SmartScreen'
    $ssNote = ''
    if ($ssnR -and -not $ssnR.AppReputationLogEnabled) {
        $ssNote = 'App-reputation prompts are NOT recorded on this host: the Microsoft-Windows-SmartScreen/Debug channel is analytic and off by default. ' +
                  'An empty SmartScreen result means "not logged", not "nothing blocked". Enable with: ' + [string]$ssnR.EnableLoggingCommand
    }
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'Security-relevant services' -Rows (Get-ArrSection $d 'Services') -Quick 'State'))
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'Platform security settings' -Rows (New-NVRows (Get-Section $d 'SecuritySettings'))))
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'SmartScreen and Smart App Control' -Rows (New-NVRows $ssnR) -Note $ssNote))
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'SmartScreen app-reputation events' -Rows (Get-ArrSection $d 'SmartScreenEvents')))
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'BitLocker volumes' -Rows (Get-ArrSection $d 'BitLocker')))
    $panels.Add((New-ReportPanel -Tab 'System' -Title 'Recent hotfixes' -Rows (Get-ArrSection $d 'Hotfixes')))

    # ------------------------------------------------------------- Fleet
    if (@($script:FleetRows).Count -gt 1) {
        $panels.Add((New-ReportPanel -Tab 'Fleet' -Title 'Fleet posture summary' -Rows $script:FleetRows -Quick 'Status' `
            -Note 'One row per target. Deviation counts how many posture fields differ from the fleet norm - sort by it to surface the odd machines.'))
        $allFindings = New-Object System.Collections.Generic.List[object]
        foreach ($t in @($script:Sync.Targets)) {
            if (-not $script:Sync.Results.ContainsKey($t)) { continue }
            $hd = $script:Sync.Results[$t]
            $hm = Get-Section $hd 'Meta'
            $hn = $t
            if ($hm) { $hn = [string]$hm.ComputerName }
            foreach ($fi in @(New-Findings $hd)) {
                $allFindings.Add([pscustomobject]@{ Host = $hn; Severity = $fi.Severity; Area = $fi.Area; Finding = $fi.Finding })
            }
        }
        $panels.Add((New-ReportPanel -Tab 'Fleet' -Title 'All findings across the fleet' -Rows $allFindings.ToArray() -Quick 'Severity' `
            -Note 'Filter by Severity, or by Host, to see which machines share a problem.'))
    }

    # ----------------------------------------------------------- Changes
    if ($script:Baseline -and @($script:DiffRows).Count -gt 0) {
        $regN = @($script:DiffRows | Where-Object { $_.Impact -eq 'Regression' }).Count
        $panels.Add((New-ReportPanel -Tab 'Changes' -Title 'Differences from baseline' -Rows $script:DiffRows -Quick 'Impact' `
            -Note ("Compared against $($script:Baseline.Computer) @ $($script:Baseline.ScanTime). " +
                   "$(@($script:DiffRows).Count) difference(s), $regN flagged as regressions. " +
                   "Event volumes are compared by count only - individual events are time-windowed and would be pure noise here.")))
    }

    # --------------------------------------------------------- Hardening
    $panels.Add((New-ReportPanel -Tab 'Hardening' -Title 'PowerShell logging and v2 engine' -Rows (New-NVRows (Get-Section $d 'PsLogging')) -Note 'Script block logging is the single highest-value PowerShell forensic control. The v2 engine, if installed, bypasses it and AMSI entirely.'))
    $panels.Add((New-ReportPanel -Tab 'Hardening' -Title 'LAPS (local administrator password management)' -Rows (New-NVRows (Get-Section $d 'Laps'))))
    $panels.Add((New-ReportPanel -Tab 'Hardening' -Title 'Exploit Protection (system-wide)' -Rows (New-NVRows (Get-Section $d 'ExploitProtection'))))
    $panels.Add((New-ReportPanel -Tab 'Hardening' -Title 'Windows Update currency' -Rows (New-NVRows (Get-Section $d 'UpdateStatus'))))

    # ------------------------------------------------------- Persistence
    $panels.Add((New-ReportPanel -Tab 'Persistence' -Title 'Services from user-writable or unquoted paths' -Rows (Get-ArrSection $d 'SuspectServices') -Quick 'Concern' -Note 'An unquoted service path containing spaces lets a lower-privileged file take precedence; a service binary in a user-writable directory can simply be replaced.'))
    $panels.Add((New-ReportPanel -Tab 'Persistence' -Title 'Non-Microsoft scheduled tasks from user-writable paths' -Rows (Get-ArrSection $d 'SuspectTasks')))

    # ------------------------------------------------------ Collection log
    $panels.Add((New-ReportPanel -Tab 'Collection log' -Title 'Scan provenance' -Rows (New-NVRows (Get-Section $d 'ClientContext')) -Note 'Who ran this scan, from where, and with which build of the tool. The connecting account is recorded by name only - no credential material is ever stored in or exported from this tool.'))
    $panels.Add((New-ReportPanel -Tab 'Collection log' -Title 'Collectors that reported problems' -Rows (Get-ArrSection $d 'Errors') -Note 'Partial data is normal - a client SKU has no AppLocker module, a workgroup box has no GPO, and so on.'))

    $payload = [pscustomobject]@{
        title     = $title
        subtitle  = $subtitle
        host      = $host_
        generated = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        cards     = @($cards)
        findings  = @()
        panels    = $panels.ToArray()
    }

    $json = $payload | ConvertTo-Json -Depth 8 -Compress
    # '<' can only occur inside a JSON string, and '\/' is a legal JSON escape,
    # so this cannot break the JSON but does stop '</script' ending the block.
    $json = $json.Replace('</', '<\/')

    # .Replace, not -replace: the regex operator would interpret '$' sequences
    # in registry values and file paths as capture-group references.
    $htmlTitle = [System.Net.WebUtility]::HtmlEncode($title)
    $script:ReportTemplate.Replace('__TITLE__', $htmlTitle).Replace('__PAYLOAD__', $json)
}

# ===========================================================================
#  FLEET VIEW
#  One row per host. The Deviation column counts how many posture fields differ
#  from the fleet's most common value, so sorting by it floats the odd machines
#  to the top without needing per-cell colouring.
# ===========================================================================
$script:FleetPostureColumns = @(
    'Defender', 'RTP', 'Tamper', 'Cloud', 'ASR', 'Firewall', 'MDE',
    'BitLocker', 'WDAC', 'SmartScreenLog', 'LAPS', 'PSLogging', 'SecureBoot', 'UAC'
)

function New-FleetRow {
    # -Failed is explicit rather than inferred from $ScanError: some exceptions
    # carry an empty Message, and a blank string would fall through to the
    # success path and render a dead host as a healthy all-blank row - which
    # would also skew the fleet's modal values in Add-FleetDeviation.
    param([string]$Computer, $d, [string]$ScanError, [switch]$Failed)

    if ($Failed -or $ScanError) {
        if (-not $ScanError) { $ScanError = 'Scan failed (no error message reported).' }
        return [pscustomobject]@{
            Host = $Computer; Status = 'FAILED'; Deviation = ''; Critical = ''; Warning = ''; Info = ''
            OS = ''; Defender = ''; RTP = ''; SigAgeDays = ''; Tamper = ''; Cloud = ''; ASR = ''
            Firewall = ''; MDE = ''; BitLocker = ''; WDAC = ''; SmartScreenLog = ''; LAPS = ''
            PSLogging = ''; SecureBoot = ''; UAC = ''; Persistence = ''; Events = ''; Uptime = ''
            Detail = $ScanError
        }
    }

    $meta = Get-Section $d 'Meta'
    $st   = Get-Section $d 'DefenderStatus'
    $pf   = Get-Section $d 'DefenderPrefs'
    $mde  = Get-Section $d 'MDE'
    $dg   = Get-Section $d 'DeviceGuard'
    $ss   = Get-Section $d 'SecuritySettings'
    $ssn  = Get-Section $d 'SmartScreen'
    $lp   = Get-Section $d 'Laps'
    $psl  = Get-Section $d 'PsLogging'
    $fw   = @(Get-ArrSection $d 'FirewallProfiles')
    $asr  = @(Get-ArrSection $d 'AsrRules')
    $bl   = @(Get-ArrSection $d 'BitLocker') | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1

    $f = @(New-Findings $d)
    $events = @(Get-UnifiedEvents $d)

    $sigAge = ''
    if ($st -and $null -ne $st.AntivirusSignatureAge) {
        if ([int64]$st.AntivirusSignatureAge -ge 4294967295) { $sigAge = 'never' }
        else { $sigAge = [string]$st.AntivirusSignatureAge }
    }
    $defVal = ''
    if ($st) {
        if (-not $st.AntivirusEnabled) { $defVal = 'Disabled' }
        elseif ($st.AMRunningMode -match 'Passive') { $defVal = 'Passive' }
        else { $defVal = 'Enabled' }
    }
    $asrBlock = @($asr | Where-Object { $_.Mode -in @('Block', 'Warn') }).Count
    $asrAudit = @($asr | Where-Object { $_.Mode -eq 'Audit' }).Count
    $fwOn = @($fw | Where-Object { $_.Enabled -eq 'True' }).Count

    [pscustomobject]@{
        Host           = $(if ($meta) { [string]$meta.ComputerName } else { $Computer })
        Status         = 'OK'
        Deviation      = 0
        Critical       = @($f | Where-Object { $_.Severity -eq 'Critical' }).Count
        Warning        = @($f | Where-Object { $_.Severity -eq 'Warning' }).Count
        Info           = @($f | Where-Object { $_.Severity -eq 'Info' }).Count
        OS             = $(if ($meta) { "$($meta.OS) ($($meta.Build))" } else { '' })
        Defender       = $defVal
        RTP            = $(if ($st) { $(if ($st.RealTimeProtectionEnabled) { 'On' } else { 'OFF' }) } else { '' })
        SigAgeDays     = $sigAge
        Tamper         = $(if ($st) { $(if ($st.IsTamperProtected) { 'On' } else { 'Off' }) } else { '' })
        Cloud          = $(if ($pf) { [string]$script:ModeMaps.Maps[[int]$pf.MAPSReporting] } else { '' })
        ASR            = "$asrBlock block / $asrAudit audit"
        Firewall       = $(if ($fw.Count) { "$fwOn/$($fw.Count) on" } else { '' })
        MDE            = $(if ($mde) { $(if ($mde.Onboarded) { 'Onboarded' } else { 'No' }) } else { '' })
        BitLocker      = $(if ($bl) { [string]$bl.ProtectionStatus } else { 'n/a' })
        WDAC           = $(if ($dg) { [string]$dg.KernelModeCodeIntegrity } else { '' })
        SmartScreenLog = $(if ($ssn) { $(if ($ssn.AppReputationLogEnabled) { 'Logging' } else { 'Not logged' }) } else { '' })
        LAPS           = $(if ($lp) { $(if ($lp.Configured) { [string]$lp.BackupDirectory } else { 'None' }) } else { '' })
        PSLogging      = $(if ($psl) { [string]$psl.ScriptBlockLogging } else { '' })
        SecureBoot     = $(if ($ss) { [string]$ss.SecureBoot } else { '' })
        UAC            = $(if ($ss) { $(if ($ss.UacEnabled -eq 0) { 'Disabled' } else { 'Enabled' }) } else { '' })
        Persistence    = (@(Get-ArrSection $d 'SuspectServices').Count + @(Get-ArrSection $d 'SuspectTasks').Count)
        Events         = $events.Count
        Uptime         = $(if ($meta) { "$($meta.UptimeDays)d" } else { '' })
        Detail         = ''
    }
}

function Add-FleetDeviation {
    # Deviation = number of posture fields where this host differs from the
    # fleet's modal value. Meaningless for a single host, so it stays 0 there.
    param($Rows)
    $okRows = @($Rows | Where-Object { $_.Status -eq 'OK' })
    if ($okRows.Count -lt 2) { return $Rows }
    $modes = @{}
    foreach ($c in $script:FleetPostureColumns) {
        $g = @($okRows | Group-Object -Property $c | Sort-Object Count -Descending)
        if ($g.Count -gt 0) { $modes[$c] = [string]$g[0].Name }
    }
    foreach ($r in $okRows) {
        $n = 0
        foreach ($c in $script:FleetPostureColumns) {
            if ($modes.ContainsKey($c) -and ([string]$r.$c) -ne $modes[$c]) { $n++ }
        }
        $r.Deviation = $n
    }
    $Rows
}

function Show-FleetResults {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($script:Sync.Targets)) {
        if ($script:Sync.Results.ContainsKey($t)) {
            $rows.Add((New-FleetRow -Computer $t -d $script:Sync.Results[$t]))
        }
        else {
            $rows.Add((New-FleetRow -Computer $t -Failed -ScanError ([string]$script:Sync.Errors[$t])))
        }
    }
    $arr = @(Add-FleetDeviation $rows.ToArray())
    $script:FleetRows = @($arr | Sort-Object @{ Expression = { if ($_.Status -eq 'OK') { 1 } else { 0 } } },
                                             @{ Expression = { [int]("0" + [string]$_.Deviation) }; Descending = $true },
                                             Host)
    Set-GridSource $ui.GridFleet $script:FleetRows

    $ok = @($arr | Where-Object { $_.Status -eq 'OK' }).Count
    $bad = @($arr | Where-Object { $_.Status -ne 'OK' }).Count
    $crit = (@($arr | Where-Object { $_.Status -eq 'OK' } | ForEach-Object { [int]$_.Critical }) | Measure-Object -Sum).Sum
    if (-not $crit) { $crit = 0 }
    $devNote = ''
    if ($ok -ge 2) { $devNote = '  Deviation = posture fields differing from the fleet norm; sort by it to surface outliers.' }
    $ui.TxtFleetHeader.Text = "$ok host(s) scanned, $bad failed, $crit critical finding(s) across the fleet.$devNote"
}

function Show-SelectedFleetHost {
    $sel = $ui.GridFleet.SelectedItem
    if (-not $sel) {
        $ui.TxtStatus.Text = 'Pick a host in the Fleet table first.'
        return
    }
    $name = [string]$sel.Host
    $key = @($script:Sync.Targets | Where-Object { $_ -eq $name })
    if ($key.Count -eq 0) {
        # The grid shows the name the target reported, which can differ from the
        # name it was addressed by (alias, FQDN). Fall back to a scan of the map.
        foreach ($t in @($script:Sync.Targets)) {
            if ($script:Sync.Results.ContainsKey($t)) {
                $m = Get-Section $script:Sync.Results[$t] 'Meta'
                if ($m -and [string]$m.ComputerName -eq $name) { $key = @($t); break }
            }
        }
    }
    if ($key.Count -eq 0 -or -not $script:Sync.Results.ContainsKey($key[0])) {
        $ui.TxtStatus.Text = "No scan data for $name (that target failed)."
        return
    }
    Show-ScanResults $script:Sync.Results[$key[0]]
    $ui.TxtStatus.Text = "Loaded $name into the detail tabs."
    foreach ($ti in $ui.Tabs.Items) { if ([string]$ti.Header -eq 'Overview') { $ui.Tabs.SelectedItem = $ti; break } }
}

# ===========================================================================
#  Scan orchestration (throttled runspace pool + dispatcher timer)
#  A single-target scan is just a fleet of one, so there is only one code path
#  to reason about and to keep correct.
# ===========================================================================
$script:RunspaceWorker = {
    # $Cred is explicitly typed so a plaintext string can never be passed in.
    param(
        $Sync, [string]$Computer, [System.Management.Automation.PSCredential]$Cred,
        [int]$Days, [int]$MaxEvents, [string]$CollectorText, [string]$ToolVersion, [string]$FromHost
    )
    $started = Get-Date
    try {
        $isLocal = ($Computer -match '^(localhost|127\.0\.0\.1|\.|::1)$') -or ($Computer -eq $env:COMPUTERNAME)
        $sbCollector = [scriptblock]::Create($CollectorText)
        if ($isLocal) {
            $res = & $sbCollector $Days $MaxEvents
        }
        else {
            $tw = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
            if ($Cred) { $tw.Credential = $Cred; $tw.Authentication = 'Default' }
            $null = Test-WSMan @tw
            $icm = @{ ComputerName = $Computer; ScriptBlock = $sbCollector; ArgumentList = @($Days, $MaxEvents); ErrorAction = 'Stop' }
            if ($Cred) { $icm.Credential = $Cred }
            $res = Invoke-Command @icm
        }
        if ($res) {
            # Provenance is built here because only the worker knows whether the
            # credential was actually applied (it is not, for a local target).
            $runAs = "$env:USERDOMAIN\$env:USERNAME"
            if ($Cred -and -not $isLocal) { $runAs = $Cred.UserName }
            $res['ClientContext'] = [pscustomobject]@{
                Target      = $Computer
                RunBy       = $runAs
                FromHost    = $FromHost
                ToolVersion = $ToolVersion
                PSVersion   = [string]$PSVersionTable.PSVersion
                DurationSec = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            }
            $Sync.Results[$Computer] = $res
        }
        else {
            $Sync.Errors[$Computer] = 'Scan returned no data.'
        }
    }
    catch {
        $Sync.Errors[$Computer] = $_.Exception.Message
    }
}

function Split-TargetList {
    # Accepts commas, semicolons, whitespace and newlines; dedupes, keeps order.
    param([string]$Text)
    if (-not $Text) { return @() }
    $parts = $Text -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $seen = @{}
    $out = @()
    foreach ($p in $parts) {
        $k = $p.ToLowerInvariant()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out += $p }
    }
    $out
}

function Start-Scan {
    $targets = @(Split-TargetList $ui.TxtComputer.Text)
    if ($targets.Count -eq 0) {
        [void][System.Windows.MessageBox]::Show('Enter one or more computer names (comma or space separated).', 'Security Health Dashboard', 'OK', 'Warning')
        return
    }
    $days = 7
    if ($ui.CmbLookback.SelectedItem) { $days = [int]$ui.CmbLookback.SelectedItem.Tag }

    $cred = $null
    if ($ui.ChkCred.IsChecked) {
        if (-not $script:ScanCredential) {
            if (-not (Request-ScanCredential)) {
                $ui.ChkCred.IsChecked = $false
                $ui.TxtStatus.Text = 'Scan cancelled (no credentials supplied).'
                return
            }
        }
        $cred = $script:ScanCredential
    }

    $who = "$env:USERDOMAIN\$env:USERNAME"
    if ($cred) { $who = $cred.UserName }

    $ui.BtnScan.IsEnabled = $false
    $ui.Progress.Visibility = 'Visible'
    $plural = ''
    if ($targets.Count -ne 1) { $plural = 's' }
    $ui.TxtStatus.Text = "Scanning $($targets.Count) target$plural as $who (up to $($script:ScanThrottle) at a time)..."

    $script:Sync = [hashtable]::Synchronized(@{
        Results = [hashtable]::Synchronized(@{})
        Errors  = [hashtable]::Synchronized(@{})
        Total   = $targets.Count
        Targets = $targets
    })

    $script:ScanStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $script:Pool = [runspacefactory]::CreateRunspacePool(1, [math]::Max(1, [int]$script:ScanThrottle))
    $script:Pool.Open()
    $script:FleetJobs = @()
    foreach ($t in $targets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $script:Pool
        [void]$ps.AddScript($script:RunspaceWorker.ToString())
        [void]$ps.AddArgument($script:Sync)
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($cred)
        [void]$ps.AddArgument($days)
        [void]$ps.AddArgument($script:MaxEventsPerLog)
        [void]$ps.AddArgument($script:SecurityCollector.ToString())
        [void]$ps.AddArgument($script:ToolVersion)
        [void]$ps.AddArgument($env:COMPUTERNAME)
        $script:FleetJobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Target = $t }
    }
    $script:Timer.Start()
}

function Stop-FleetScan {
    foreach ($j in @($script:FleetJobs)) {
        # EndInvoke BLOCKS until the pipeline finishes. On the timeout path the
        # job is by definition still wedged, so stop it first - otherwise this
        # freezes the dispatcher thread and defeats -TimeoutSec entirely.
        try { if ($j.PS -and $j.Handle -and -not $j.Handle.IsCompleted) { $j.PS.Stop() } } catch { }
        try { if ($j.PS -and $j.Handle) { [void]$j.PS.EndInvoke($j.Handle) } } catch { }
        try { if ($j.PS) { $j.PS.Dispose() } } catch { }
    }
    $script:FleetJobs = @()
    try { if ($script:Pool) { $script:Pool.Close(); $script:Pool.Dispose() } } catch { }
    $script:Pool = $null
}

$script:Timer = $null
if (-not $Quiet) {
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [timespan]::FromMilliseconds(400)
$script:Timer.Add_Tick({
    if (-not $script:Sync) { return }
    # .Count, not @(.Keys).Count - workers are still inserting concurrently.
    $ok = $script:Sync.Results.Count
    $bad = $script:Sync.Errors.Count
    $done = $ok + $bad
    $total = [int]$script:Sync.Total
    if ($done -lt $total) {
        $elapsed = 0
        if ($script:ScanStopwatch) { $elapsed = [int]$script:ScanStopwatch.Elapsed.TotalSeconds }
        if ($elapsed -gt $script:ScanTimeoutSec) {
            foreach ($t in @($script:Sync.Targets)) {
                if (-not $script:Sync.Results.ContainsKey($t) -and -not $script:Sync.Errors.ContainsKey($t)) {
                    $script:Sync.Errors[$t] = "Timed out after $($script:ScanTimeoutSec)s."
                }
            }
            $bad = $script:Sync.Errors.Count
            $done = $ok + $bad
        }
        else {
            $ui.TxtStatus.Text = "Scanning... $done of $total complete ($ok succeeded, $bad failed).  ${elapsed}s elapsed."
            return
        }
    }

    $script:Timer.Stop()
    Stop-FleetScan
    $ui.Progress.Visibility = 'Collapsed'
    $ui.BtnScan.IsEnabled = $true

    if ($ok -eq 0) {
        $first = @($script:Sync.Errors.Keys)[0]
        $reason = [string]$script:Sync.Errors[$first]
        $ui.TxtStatus.Text = "All $total scan(s) failed. $first : $reason"
        $msg = "No target could be scanned.`n`nFirst error ($first):`n$reason`n`n" +
               "Checklist:`n - Is WinRM enabled on the target? (Enable-PSRemoting)`n" +
               " - Are you an administrator on the target?`n" +
               " - Workgroup targets: add to TrustedHosts and use alternate credentials.`n" +
               " - Is TCP 5985/5986 open between you and the target?"
        [void][System.Windows.MessageBox]::Show($msg, 'Scan failed', 'OK', 'Error')
        Show-FleetResults
        return
    }

    try {
        Show-FleetResults
        # Load the first successful host into the detail tabs.
        $firstOk = @($script:Sync.Targets | Where-Object { $script:Sync.Results.ContainsKey($_) })[0]
        if ($firstOk) { Show-ScanResults $script:Sync.Results[$firstOk] }
        $errNote = ''
        if ($bad -gt 0) { $errNote = "  $bad target(s) failed - see the Fleet tab." }
        $shown = ''
        if ($total -gt 1) { $shown = "  Showing $firstOk; pick another on the Fleet tab." }
        $ui.TxtStatus.Text = "Scan complete: $ok of $total succeeded.$errNote$shown"
    }
    catch {
        $ui.TxtStatus.Text = "Scan succeeded but rendering failed: $($_.Exception.Message)"
    }
})
}   # end if (-not $Quiet) - dispatcher timer


# ===========================================================================
#  UNATTENDED MODE
#  Runs before any WPF type is touched, so a scheduled task can use it on a
#  host with no desktop session. Everything here writes to the console and to
#  disk; nothing depends on the dashboard.
# ===========================================================================
function Invoke-QuietScan {
    param(
        [string[]]$Targets, [int]$Days,
        [System.Management.Automation.PSCredential]$Cred,
        [int]$Throttle, [string]$OutDir, [string]$Baseline, [switch]$NoHtml
    )

    $sync = [hashtable]::Synchronized(@{
        Results = [hashtable]::Synchronized(@{})
        Errors  = [hashtable]::Synchronized(@{})
        Total   = $Targets.Count
        Targets = $Targets
    })
    $script:Sync = $sync

    Write-Verbose "Scanning $($Targets.Count) target(s), up to $Throttle at a time."
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Max(1, $Throttle))
    $pool.Open()
    $jobs = @()
    foreach ($t in $Targets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:RunspaceWorker.ToString())
        [void]$ps.AddArgument($sync)
        [void]$ps.AddArgument($t)
        [void]$ps.AddArgument($Cred)
        [void]$ps.AddArgument($Days)
        [void]$ps.AddArgument($script:MaxEventsPerLog)
        [void]$ps.AddArgument($script:SecurityCollector.ToString())
        [void]$ps.AddArgument($script:ToolVersion)
        [void]$ps.AddArgument($env:COMPUTERNAME)
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Target = $t }
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # .Count is a locked operation on a synchronized hashtable; enumerating .Keys
    # while up to $Throttle workers insert throws "Collection was modified".
    while (($sync.Results.Count + $sync.Errors.Count) -lt $Targets.Count) {
        if ($sw.Elapsed.TotalSeconds -gt $script:ScanTimeoutSec) {
            foreach ($t in $Targets) {
                if (-not $sync.Results.ContainsKey($t) -and -not $sync.Errors.ContainsKey($t)) {
                    $sync.Errors[$t] = "Timed out after $($script:ScanTimeoutSec)s."
                }
            }
            Write-Warning "Scan timed out after $($script:ScanTimeoutSec)s; unfinished targets recorded as timed out."
            break
        }
        Start-Sleep -Milliseconds 400
    }
    foreach ($j in $jobs) {
        # Stop before EndInvoke; a timed-out job is still running and EndInvoke
        # would block past the ceiling we just enforced.
        try { if (-not $j.Handle.IsCompleted) { $j.PS.Stop() } } catch { }
        try { [void]$j.PS.EndInvoke($j.Handle) } catch { }
        try { $j.PS.Dispose() } catch { }
    }
    try { $pool.Close(); $pool.Dispose() } catch { }

    # Baseline is optional; when present every host is diffed against it.
    $baseObj = $null
    if ($Baseline) {
        try { $baseObj = Import-ScanSnapshot -Path $Baseline }
        catch { Write-Warning "Could not load baseline '$Baseline': $($_.Exception.Message)" }
    }

    if ($OutDir -and -not (Test-Path $OutDir)) {
        [void](New-Item -ItemType Directory -Path $OutDir -Force)
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmm'
    $summary = New-Object System.Collections.Generic.List[object]

    foreach ($t in $Targets) {
        if (-not $sync.Results.ContainsKey($t)) {
            $errText = [string]$sync.Errors[$t]
            if (-not $errText) { $errText = 'Scan failed (no error message reported).' }
            $summary.Add([pscustomobject]@{
                Host = $t; Status = 'FAILED'; Critical = 0; Warning = 0; Info = 0
                Regressions = 0; HtmlPath = ''; JsonPath = ''; Error = $errText
            })
            Write-Warning "$t : $($sync.Errors[$t])"
            continue
        }
        $d = $sync.Results[$t]
        $meta = Get-Section $d 'Meta'
        $name = $t
        if ($meta) { $name = [string]$meta.ComputerName }
        $findings = @(New-Findings $d)

        $regressions = 0
        if ($baseObj) {
            $cur = [pscustomobject]@{ Sections = (ConvertTo-ScanSnapshot $d) }
            $script:DiffRows = @(Compare-ScanSnapshots -Baseline $baseObj -Current $cur)
            $regressions = @($script:DiffRows | Where-Object { $_.Impact -eq 'Regression' }).Count
            $script:Baseline = $baseObj
        }
        else { $script:DiffRows = @() }

        $htmlPath = ''; $jsonPath = ''
        if ($OutDir) {
            $jsonPath = Join-Path $OutDir ("SecurityScan_{0}_{1}.json" -f $name, $stamp)
            try { [void](Save-ScanSnapshot -d $d -Path $jsonPath) }
            catch { Write-Warning "Could not write $jsonPath : $($_.Exception.Message)"; $jsonPath = '' }
            if (-not $NoHtml) {
                $htmlPath = Join-Path $OutDir ("SecurityHealth_{0}_{1}.html" -f $name, $stamp)
                try {
                    $script:FleetRows = @()   # per-host report, no fleet panel
                    $html = Get-HtmlReport $d
                    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($false))
                }
                catch { Write-Warning "Could not write $htmlPath : $($_.Exception.Message)"; $htmlPath = '' }
            }
        }

        $summary.Add([pscustomobject]@{
            Host        = $name
            Status      = 'OK'
            Critical    = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            Warning     = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
            Info        = @($findings | Where-Object { $_.Severity -eq 'Info' }).Count
            Regressions = $regressions
            HtmlPath    = $htmlPath
            JsonPath    = $jsonPath
            Error       = ''
        })
    }

    # A fleet index when there is more than one target.
    if ($OutDir -and -not $NoHtml -and $Targets.Count -gt 1) {
        try {
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($t in $Targets) {
                if ($sync.Results.ContainsKey($t)) { $rows.Add((New-FleetRow -Computer $t -d $sync.Results[$t])) }
                else { $rows.Add((New-FleetRow -Computer $t -Failed -ScanError ([string]$sync.Errors[$t]))) }
            }
            $script:FleetRows = @(Add-FleetDeviation $rows.ToArray())
            $firstOk = @($Targets | Where-Object { $sync.Results.ContainsKey($_) })[0]
            if ($firstOk) {
                # Recompute the diff for the host actually being rendered; the loop
                # above left $script:DiffRows holding the LAST host's differences.
                $script:DiffRows = @()
                if ($baseObj) {
                    $script:DiffRows = @(Compare-ScanSnapshots -Baseline $baseObj `
                        -Current ([pscustomobject]@{ Sections = (ConvertTo-ScanSnapshot $sync.Results[$firstOk]) }))
                }
                $idx = Join-Path $OutDir ("SecurityHealth_FLEET_{0}.html" -f $stamp)
                $html = Get-HtmlReport $sync.Results[$firstOk]
                [System.IO.File]::WriteAllText($idx, $html, [System.Text.UTF8Encoding]::new($false))
                Write-Verbose "Fleet index: $idx"
            }
        }
        catch { Write-Warning "Could not write the fleet index: $($_.Exception.Message)" }
    }

    # Return plain; the caller wraps in @(). Wrapping here too would produce a
    # one-element array containing the array, and every [int]$_.Critical would
    # then read the ARRAY's .Length property instead of a finding count.
    $summary.ToArray()
}

# ---------------------------------------------------------------------------
#  Quiet-mode entry point. Everything the scan needs is defined by now, and the
#  GUI has not been built, so this returns without ever touching WPF.
#
#  Exit codes (a scheduled task can alert on these):
#     0  all targets scanned, nothing above Info
#     1  at least one Warning finding
#     2  at least one Critical finding, or a regression against the baseline
#     3  at least one target could not be scanned (incomplete data - worst case
#        for a monitoring job, so it outranks the finding severities)
# ---------------------------------------------------------------------------
if ($Quiet) {
    $qTargets = @(Split-TargetList (($startupTargets -join ',')))
    if ($qTargets.Count -eq 0) {
        # Write-Error would be terminating under EAP=Stop and exit 3 would never run.
        Write-Warning 'Quiet mode needs at least one target: use -ComputerName or -TargetFile.'
        exit 3
    }
    $qCred = $null
    if ($script:ScanCredential) { $qCred = $script:ScanCredential }

    $qSummary = @(Invoke-QuietScan -Targets $qTargets -Days $LookbackDays -Cred $qCred `
                                   -Throttle $script:ScanThrottle -OutDir $OutputPath `
                                   -Baseline $BaselinePath -NoHtml:$NoHtml)

    if ($OutputPath) {
        try {
            $csv = Join-Path $OutputPath ("SecurityHealth_SUMMARY_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
            $qSummary | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
        }
        catch { Write-Warning "Could not write the summary CSV: $($_.Exception.Message)" }
    }

    $failed = @($qSummary | Where-Object { $_.Status -ne 'OK' }).Count
    $crit   = (@($qSummary | ForEach-Object { [int]$_.Critical })    | Measure-Object -Sum).Sum
    $warn   = (@($qSummary | ForEach-Object { [int]$_.Warning })     | Measure-Object -Sum).Sum
    $regs   = (@($qSummary | ForEach-Object { [int]$_.Regressions }) | Measure-Object -Sum).Sum
    if (-not $crit) { $crit = 0 }; if (-not $warn) { $warn = 0 }; if (-not $regs) { $regs = 0 }

    Write-Host ("Security Health Dashboard {0} - {1} target(s): {2} scanned, {3} failed. " -f
                $script:ToolVersion, $qTargets.Count, ($qTargets.Count - $failed), $failed)
    Write-Host ("Findings across the fleet: {0} critical, {1} warning. Baseline regressions: {2}." -f $crit, $warn, $regs)
    if ($OutputPath) { Write-Host "Output written to: $OutputPath" }

    # Emit the summary objects so the caller can pipe them.
    $qSummary

    $code = 0
    if ($warn -gt 0) { $code = 1 }
    if ($crit -gt 0 -or $regs -gt 0) { $code = 2 }
    if ($failed -gt 0) { $code = 3 }
    exit $code
}

# ===========================================================================
#  Event wiring
# ===========================================================================
$ui.BtnScan.Add_Click({ Start-Scan })

$ui.BtnCred.Add_Click({ [void](Request-ScanCredential) })

$ui.ChkCred.Add_Checked({
    # Prompt as soon as the box is ticked rather than at scan time, so the
    # operator finds out about a bad password before waiting on a scan.
    if (-not $script:ScanCredential) {
        if (-not (Request-ScanCredential)) { $ui.ChkCred.IsChecked = $false }
    }
})

$ui.ChkCred.Add_Unchecked({
    Clear-ScanCredential
    $ui.TxtStatus.Text = 'Cleared. Scans will connect as the current user.'
})

$ui.TxtComputer.Add_KeyDown({
    # $s, not $sender: the latter is a PowerShell automatic variable.
    param($s, $e)
    # Gate on the button so Enter can't launch a second concurrent scan.
    if ($e.Key -eq 'Return' -and $ui.BtnScan.IsEnabled) { Start-Scan }
})

foreach ($pair in @(@('BtnEvtAll', ''), @('BtnEvtBlocked', 'Blocked'), @('BtnEvtAudited', 'Audited'),
                    @('BtnEvtAllowed', 'Allowed'), @('BtnEvtDetected', 'Detected'), @('BtnEvtAlert', 'Alert'))) {
    # Tag carries the action value so the shared handler needs no closure.
    $ui[$pair[0]].Tag = $pair[1]
    $ui[$pair[0]].Add_Click({
        param($s, $e)
        Set-EventActionFilter -Action ([string]$s.Tag)
    })
}

$ui.CmbEvtSource.Add_SelectionChanged({
    if ($script:SuppressEventControls) { return }
    $g = $ui.GridEvents
    $st = $g.Tag
    if (-not $st) { return }
    $sel = [string]$ui.CmbEvtSource.SelectedItem
    if ($sel -eq '(custom)') { return }
    if (-not $sel -or $sel -eq 'All') { [void]$st.Filters.Remove('Source') }
    else { $st.Filters['Source'] = @($sel) }
    Update-GridView $g
    Sync-EventControls
    Show-GridInfo $g
})

# Global find box, debounced so a fast typist does not refilter every table
# on every keystroke.
$script:FindTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FindTimer.Interval = [timespan]::FromMilliseconds(400)
$script:FindTimer.Add_Tick({
    $script:FindTimer.Stop()
    Set-GlobalSearch -Text ([string]$ui.TxtFind.Text)
})
$ui.TxtFind.Add_TextChanged({
    $script:FindTimer.Stop()
    $script:FindTimer.Start()
})

$ui.BtnClearFilters.Add_Click({ Clear-AllGridFilters })

$ui.BtnOpenHost.Add_Click({ Show-SelectedFleetHost })

$ui.BtnSaveBaseline.Add_Click({
    if (-not $script:LastScan) { return }
    $meta = Get-Section $script:LastScan 'Meta'
    $name = 'target'
    if ($meta) { $name = [string]$meta.ComputerName }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'Scan snapshot (*.json)|*.json'
    $dlg.FileName = 'SecurityBaseline_{0}_{1}.json' -f $name, (Get-Date -Format 'yyyyMMdd_HHmm')
    if ($dlg.ShowDialog()) {
        try {
            [void](Save-ScanSnapshot -d $script:LastScan -Path $dlg.FileName)
            $ui.TxtStatus.Text = "Baseline saved: $($dlg.FileName)"
        }
        catch { [void][System.Windows.MessageBox]::Show("Save failed: $($_.Exception.Message)", 'Baseline', 'OK', 'Error') }
    }
})

$ui.BtnLoadBaseline.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'Scan snapshot (*.json)|*.json|All files (*.*)|*.*'
    if ($dlg.ShowDialog()) {
        try {
            $script:Baseline = Import-ScanSnapshot -Path $dlg.FileName
            $script:CurrentBaselinePath = $dlg.FileName
            Update-DiffView
            $ui.TxtStatus.Text = "Baseline loaded: $($script:Baseline.Computer) @ $($script:Baseline.ScanTime)"
            foreach ($ti in $ui.Tabs.Items) { if ([string]$ti.Header -eq 'Changes') { $ui.Tabs.SelectedItem = $ti; break } }
        }
        catch {
            [void][System.Windows.MessageBox]::Show("Could not load that snapshot:`n`n$($_.Exception.Message)", 'Baseline', 'OK', 'Error')
        }
    }
})

$ui.BtnClearBaseline.Add_Click({
    $script:Baseline = $null
    $script:CurrentBaselinePath = ''
    Update-DiffView
    $ui.TxtStatus.Text = 'Baseline cleared.'
})

# Give every DataGrid sorting, column filters, global-search participation and
# double-click row detail. Must run after the engine functions are defined.
foreach ($k in @($ui.Keys)) {
    if ($ui[$k] -is [System.Windows.Controls.DataGrid]) { Enable-GridTools $ui[$k] }
}

$ui.BtnExport.Add_Click({
    if (-not $script:LastScan) { return }
    $meta = Get-Section $script:LastScan 'Meta'
    $name = 'target'
    if ($meta) { $name = $meta.ComputerName }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'
    $dlg.FileName = "SecurityHealth_{0}_{1}.html" -f $name, (Get-Date -Format 'yyyyMMdd_HHmm')
    if ($dlg.ShowDialog()) {
        try {
            $html = Get-HtmlReport $script:LastScan
            [System.IO.File]::WriteAllText($dlg.FileName, $html, [System.Text.Encoding]::UTF8)
            $ui.TxtStatus.Text = "Report saved: $($dlg.FileName)"
        }
        catch {
            [void][System.Windows.MessageBox]::Show("Export failed: $($_.Exception.Message)", 'Export', 'OK', 'Error')
        }
    }
})

$window.Add_Closed({
    $script:ScanCredential = $null   # do not leave the credential in memory
    try { $script:Timer.Stop() } catch { }
    foreach ($j in @($script:FleetJobs)) {
        try { if ($j.PS) { $j.PS.Stop(); $j.PS.Dispose() } } catch { }
    }
    try { if ($script:Pool) { $script:Pool.Close(); $script:Pool.Dispose() } } catch { }
})

# A -BaselinePath supplied at launch is loaded once the UI exists.
if ($BaselinePath -and -not $Quiet) {
    try {
        $script:Baseline = Import-ScanSnapshot -Path $BaselinePath
        $script:CurrentBaselinePath = $BaselinePath
        Update-DiffView
        $ui.TxtStatus.Text = "Baseline loaded: $($script:Baseline.Computer) @ $($script:Baseline.ScanTime). Run a scan to compare."
    }
    catch {
        $ui.TxtStatus.Text = "Could not load baseline '$BaselinePath': $($_.Exception.Message)"
    }
}

$window.Add_ContentRendered({ [void]$ui.TxtComputer.Focus() })

[void]$window.ShowDialog()
