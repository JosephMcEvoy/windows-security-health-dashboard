<#
    Loads individual functions out of SecurityHealthDashboard.ps1 without
    executing the script.

    The script is a single self-contained file that builds a WPF window at the
    top level, so it cannot simply be dot-sourced on a build agent (and not at
    all on Linux). Instead we parse it and evaluate only the definitions a test
    needs. That keeps the tests honest: they exercise the real shipping code,
    not a copy that can drift.
#>

function Get-ScriptUnderTest {
    param([string]$Path)
    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot '../src/SecurityHealthDashboard.ps1'
    }
    (Resolve-Path $Path).Path
}

function Import-DashboardFunction {
    <#
        Dot-sources the named functions and script-scope assignments from the
        tool into the CALLER's scope.
    #>
    param(
        [string[]]$FunctionName = @(),
        [string[]]$VariableAssignment = @(),
        [string]$Path
    )
    $file = Get-ScriptUnderTest -Path $Path
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in $FunctionName) {
        $f = $ast.FindAll({
            param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n
        }, $true)
        if (-not $f) { throw "Function '$n' not found in $file" }
        $out.Add($f[0].Extent.Text)
    }
    foreach ($v in $VariableAssignment) {
        $a = $ast.FindAll({
            param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left.Extent.Text -eq $v
        }, $true)
        if (-not $a) { throw "Assignment '$v' not found in $file" }
        $out.Add($a[0].Extent.Text)
    }
    # Returned as text so the caller can dot-source it into its own scope.
    ($out -join "`n`n")
}

function Get-DashboardAst {
    param([string]$Path)
    [System.Management.Automation.Language.Parser]::ParseFile((Get-ScriptUnderTest -Path $Path), [ref]$null, [ref]$null)
}

function New-MockScan {
    <#
        A representative scan result. Deliberately includes the nasty cases:
        a uint32 "never" sentinel, a single-element array, HTML/script-tag
        injection, regex replacement tokens, and an empty section.
    #>
    param([string]$Name = 'PC-042', [datetime]$ScanTime = ([datetime]'2026-08-11T14:30:00'))
    $now = $ScanTime
    $d = @{}
    $d.Meta = [pscustomobject]@{
        ComputerName = $Name; OS = 'Microsoft Windows 11 Enterprise'; Version = '10.0.26100'
        Build = '26100'; LastBoot = $now.AddDays(-41); UptimeDays = 41.2; Domain = 'corp.example.com'
        PartOfDomain = $true; Manufacturer = 'Dell Inc.'; Model = 'Latitude 7440'
        ScanTime = $now; LookbackDays = 7
    }
    $d.ClientContext = [pscustomobject]@{
        Target = $Name; RunBy = 'CORP\svc_secops'; FromHost = 'SOC-WS01'
        ToolVersion = '1.5'; PSVersion = '5.1.26100.1'; DurationSec = 12.4
    }
    $d.DefenderStatus = [pscustomobject]@{
        AMRunningMode = 'Normal'; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true
        BehaviorMonitorEnabled = $true; IsTamperProtected = $false; TamperProtectionSource = 'Registry'
        AMEngineVersion = '1.1.24080.9'; AntivirusSignatureVersion = '1.417.512.0'
        AntivirusSignatureLastUpdated = $now.AddDays(-9); AntivirusSignatureAge = 9
        QuickScanEndTime = $null; QuickScanAge = 4294967295; FullScanAge = 4294967295; RebootRequired = $false
    }
    $d.DefenderPrefs = [pscustomobject]@{
        MAPSReporting = 2; CloudBlockLevel = 0; PUAProtection = 1; EnableNetworkProtection = 2
        EnableControlledFolderAccess = 0; SubmitSamplesConsent = 1; DisableScriptScanning = $false
    }
    # single-element array: the classic ConvertTo-Json collapse case
    $d.AsrRules = @([pscustomobject]@{ Rule = 'Block credential stealing from LSASS'; Mode = 'Audit'; Guid = '9e6c4e1f' })
    $d.DefenderExclusions = @(
        [pscustomobject]@{ Type = 'Path'; Value = 'C:\App\data' }
        [pscustomobject]@{ Type = 'Process'; Value = '</script><img src=x onerror=alert(1)>' }
        [pscustomobject]@{ Type = 'Path'; Value = 'C:\Temp\$1 $& "quoted" <tag> & amp' }
    )
    $d.Threats = @(); $d.CodeIntegrityEvents = @(); $d.SmartScreenEvents = @()
    $d.FirewallBlocked = @(); $d.AppLockerPolicy = @(); $d.SuspectServices = @(); $d.SuspectTasks = @()
    $d.DefenderEvents = @(
        [pscustomobject]@{ Time = $now.AddHours(-2); Id = 1121; Source = 'Defender'; Category = 'ASR rule triggered (block)'; Action = 'Blocked'; Detail = ('X' * 700) }
        [pscustomobject]@{ Time = $now.AddHours(-5); Id = 1122; Source = 'Defender'; Category = 'ASR rule triggered (audit)'; Action = 'Audited'; Detail = 'powershell.exe -enc from WINWORD.EXE' }
    )
    $d.AppLockerEvents = @([pscustomobject]@{ Time = $now.AddHours(-3); Id = 8004; Source = 'AppLocker'; Category = 'Exe/Dll BLOCKED'; Action = 'Blocked'; User = 'CORP\joe'; Detail = 'C:\Users\joe\Downloads\tool.exe was prevented from running.' })
    $d.FirewallChanges = @([pscustomobject]@{ Time = $now.AddHours(-30); Id = 2006; Source = 'Firewall'; Category = 'Firewall rule DELETED'; Action = 'Info'; Detail = 'Allow RDP inbound' })
    $d.IdentityEvents = @(
        [pscustomobject]@{ Time = $now.AddHours(-1); Id = 4732; Source = 'Security'; Category = 'Member added to LOCAL group'; Action = 'Audited'; Detail = 'Target: Administrators Member: CORP\contractor' }
        [pscustomobject]@{ Time = $now.AddHours(-8); Id = 1102; Source = 'Security'; Category = 'SECURITY LOG CLEARED'; Action = 'Alert'; Detail = 'By: CORP\joe' }
    )
    $d.FirewallProfiles = @(
        [pscustomobject]@{ Profile = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; LogBlocked = 'False'; LogFileName = 'x' }
        [pscustomobject]@{ Profile = 'Public'; Enabled = 'False'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow'; LogBlocked = 'False'; LogFileName = 'x' }
    )
    $d.FirewallRuleSummary = @([pscustomobject]@{ Direction = 'Inbound'; Action = 'Allow'; EnabledRules = 212 })
    $d.FirewallBlockedCount = 0
    $d.FirewallPermissiveCount = 2
    $d.FirewallPermissive = @(
        [pscustomobject]@{ Rule = 'Remote Desktop - User Mode (TCP-In)'; Profile = 'Domain'; Protocol = 'TCP'; LocalPort = '3389'; RemoteAddr = 'Any'; Program = 'Any'; Scoped = 'No - any program'; Group = 'Remote Desktop' }
        [pscustomobject]@{ Rule = 'App Traffic'; Profile = 'Any'; Protocol = 'Any'; LocalPort = 'Any'; RemoteAddr = 'Any'; Program = 'C:\App\app.exe'; Scoped = 'Program-scoped'; Group = '' }
    )
    $d.DeviceGuard = [pscustomobject]@{
        VirtualizationBasedSecurity = 'Enabled and running'; ServicesConfigured = 'Credential Guard, HVCI'
        ServicesRunning = 'HVCI'; KernelModeCodeIntegrity = 'Audit mode'; UserModeCodeIntegrity = 'Off'
    }
    $d.SecuritySettings = [pscustomobject]@{
        LsaRunAsPPL = 1; SmartScreenExplorer = 'Warn'; SmartScreenPolicy = $null; UacEnabled = 1
        UacAdminPromptBehavior = 5; SecureBoot = 'On'; TpmPresent = $true; TpmReady = $true
    }
    $d.SmartScreen = [pscustomobject]@{
        AppReputationLog = 'Microsoft-Windows-SmartScreen/Debug'; AppReputationLogEnabled = $false
        AppReputationRecords = $null; EnableLoggingCommand = 'wevtutil sl Microsoft-Windows-SmartScreen/Debug /e:true'
        ShellSmartScreen = 'Warn'; PolicyEnableSmartScreen = $null; PolicyShellLevel = '(not set)'
        EdgeSmartScreen = $null; EdgeSmartScreenPua = $null; SmartAppControl = 'Evaluation mode'
        SmartAppControlNote = 'CI 3077/3076.'
    }
    $d.PsLogging = [pscustomobject]@{
        ScriptBlockLogging = 'Enabled'; ScriptBlockInvocationLog = $null; ModuleLogging = 'Enabled'
        Transcription = 'Enabled'; TranscriptOutputDirectory = '\\fs\transcripts'
        PowerShellV2Feature = 'Disabled'; PowerShellV2EngineKey = $false
    }
    $d.Laps = [pscustomobject]@{
        Configured = $true; ActivePolicySource = 'LAPS CSP (Intune)'; PolicyKey = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
        BackupDirectory = 'Microsoft Entra ID'; LegacyAdmPwdEnabled = $null; AdministratorAccountName = $null
        PasswordAgeDays = 30; PasswordLength = 14; PasswordComplexity = 4; ExpirationProtection = 1
        ADPasswordEncryption = $null; PostAuthActions = $null
    }
    $d.ExploitProtection = [pscustomobject]@{
        DEP = 'ON'; DEP_Emulation = 'NOTSET'; ASLR_BottomUp = 'ON'; ASLR_ForceRelocate = 'OFF'
        ASLR_HighEntropy = 'ON'; ControlFlowGuard = 'ON'; CFG_SuppressExports = 'NOTSET'
        SEHOP = 'ON'; SEHOP_TelemetryOnly = 'NOTSET'; Heap_TerminateOnError = 'ON'
    }
    $d.UpdateStatus = [pscustomobject]@{
        LastDetectSuccess = '2026-08-10 03:12:00'; LastDetectAgeDays = 1.5
        LastInstallSuccess = '2026-07-22 04:00:00'; RebootPending = $false; RebootPendingFrom = ''
    }
    $d.BitLocker = @([pscustomobject]@{ MountPoint = 'C:'; VolumeType = 'OperatingSystem'; ProtectionStatus = 'On'; VolumeStatus = 'FullyEncrypted'; EncryptionMethod = 'XtsAes256'; PercentEncrypted = 100; KeyProtectors = 'Tpm, RecoveryPassword' })
    $d.MDE = [pscustomobject]@{ Onboarded = $true; OnboardingState = 1; OrgId = 'ab12'; LastConnected = $now.AddMinutes(-12) }
    $d.DsRegStatus = @(
        [pscustomobject]@{ Property = 'AzureAdJoined'; Value = 'YES' }
        [pscustomobject]@{ Property = 'DomainJoined'; Value = 'YES' }
    )
    $d.SecureChannel = [pscustomobject]@{ Checked = $true; Healthy = $true; Detail = 'DC: \\DC01 Success' }
    $d.LocalAdmins = @([pscustomobject]@{ Member = 'CORP\Domain Admins'; Type = 'Group'; Source = 'ActiveDirectory' })
    $d.LocalUsers = @([pscustomobject]@{ Name = 'Administrator'; Enabled = $false; LastLogon = $null; PasswordLastSet = $now.AddDays(-400); PasswordRequired = $true; Description = 'Built-in' })
    $d.LogonSummary = @([pscustomobject]@{ LogonType = 'RemoteInteractive (RDP)'; Count = 6; UniqueAccounts = 2; MostRecent = $now.AddHours(-4); LastAccount = 'CORP\joe' })
    $d.Sessions = @(' USERNAME  SESSIONNAME  ID  STATE', ' joe       rdp-tcp#3     2  Active')
    $d.FailedLogonCount = 31
    $d.FailedLogonTop = @([pscustomobject]@{ Account = 'CORP\svc_backup'; Failures = 27 })
    $d.FailedLogons = @([pscustomobject]@{ Time = $now.AddHours(-6); Account = 'CORP\svc_backup'; LogonType = 'Network'; SourceIP = '10.4.2.19'; Workstation = 'FILE01'; Status = '0xC000006D' })
    $d.Gpo = [pscustomobject]@{ AppliedGpos = @('Default Domain Policy', 'Corp - Defender Baseline'); LastRefresh = $now.AddHours(-3); RawText = "RSOP data`r`n  Applied Group Policy Objects" }
    $d.MdmEnrollment = @([pscustomobject]@{ UPN = 'joe@example.com'; Provider = 'MS DM Server'; EnrollmentState = 1; DiscoveryUrl = 'https://enrollment.manage.microsoft.com' })
    $d.AuditPolicy = @(
        [pscustomobject]@{ Subcategory = 'Logon'; Setting = 'Success and Failure' }
        [pscustomobject]@{ Subcategory = 'Filtering Platform Connection'; Setting = 'No Auditing' }
    )
    $d.Services = @(
        [pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; State = 'Running'; StartMode = 'Auto' }
        [pscustomobject]@{ Name = 'Sense'; DisplayName = 'MDE Sensor'; State = 'Stopped'; StartMode = 'Auto' }
    )
    $d.Hotfixes = @([pscustomobject]@{ HotFixID = 'KB5041585'; Description = 'Security Update'; InstalledOn = $now.AddDays(-20); InstalledBy = 'NT AUTHORITY\SYSTEM' })
    $d.Errors = @([pscustomobject]@{ Area = 'AppLocker policy'; Message = "The term 'Get-AppLockerPolicy' is not recognized." })
    $d
}

Export-ModuleMember -Function Get-ScriptUnderTest, Import-DashboardFunction, Get-DashboardAst, New-MockScan
