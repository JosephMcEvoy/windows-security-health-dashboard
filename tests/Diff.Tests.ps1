#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    . ([scriptblock]::Create((Import-DashboardFunction `
        -FunctionName 'Format-Value', 'Get-Section', 'Get-ArrSection', 'ConvertTo-ScanSnapshot',
                      'Save-ScanSnapshot', 'Import-ScanSnapshot', 'Get-SnapshotRowKey',
                      'Test-IsRegression', 'Compare-ScanSnapshots' `
        -VariableAssignment '$script:EventSections', '$script:SectionKeys',
                            '$script:RegressionRules', '$script:AdditionIsNotable',
                            '$script:ToolVersion')))

    function New-Pair {
        param([scriptblock]$Mutate)
        $b = New-MockScan
        $c = New-MockScan
        if ($Mutate) { & $Mutate $c }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("base_{0}.json" -f [guid]::NewGuid())
        [void](Save-ScanSnapshot -d $b -Path $tmp)
        $loaded = Import-ScanSnapshot -Path $tmp
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        @(Compare-ScanSnapshots -Baseline $loaded -Current ([pscustomobject]@{ Sections = (ConvertTo-ScanSnapshot $c) }))
    }
}

Describe 'Snapshot round-trip' {
    It 'reports zero differences when a scan is compared against itself' {
        # The load-bearing property. A snapshot taken live and one reloaded from
        # JSON must be structurally identical, or every diff is pure noise.
        # This caught ordered-dictionaries leaking .NET members (Count,
        # IsFixedSize, IsReadOnly) as if they were data: 63 phantom differences.
        (New-Pair).Count | Should -Be 0
    }

    It 'is not confused by row ordering' {
        $diff = New-Pair { param($c)
            $c.Services = @(
                [pscustomobject]@{ Name = 'Sense'; DisplayName = 'MDE Sensor'; State = 'Stopped'; StartMode = 'Auto' }
                [pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        $diff.Count | Should -Be 0
    }

    It 'preserves scalar sections such as FailedLogonCount' {
        # A bare [int] section has no adapted properties, so the generic path
        # stored an empty bag and the value vanished from every snapshot.
        $snap = ConvertTo-ScanSnapshot (New-MockScan)
        $snap.FailedLogonCount.Props.Value | Should -Be '31'
    }

    It 'rejects a file that is not a snapshot' {
        $bad = Join-Path ([System.IO.Path]::GetTempPath()) 'notasnapshot.json'
        '{"nope":true}' | Set-Content -Path $bad
        { Import-ScanSnapshot -Path $bad } | Should -Throw '*not a Security Health Dashboard snapshot*'
        Remove-Item $bad -Force
    }

    It 'refuses a snapshot written by an incompatible schema' {
        $f = Join-Path ([System.IO.Path]::GetTempPath()) 'v99.json'
        [void](Save-ScanSnapshot -d (New-MockScan) -Path $f)
        $o = Get-Content $f -Raw | ConvertFrom-Json
        $o.SchemaVersion = 99
        $o | ConvertTo-Json -Depth 12 | Set-Content -Path $f
        { Import-ScanSnapshot -Path $f } | Should -Throw '*schema v99*'
        Remove-Item $f -Force
    }
}

Describe 'Change detection' {
    It 'detects real-time protection being switched off' {
        $diff = New-Pair { param($c) $c.DefenderStatus.RealTimeProtectionEnabled = $false }
        $row = $diff | Where-Object { $_.Area -eq 'DefenderStatus' -and $_.Property -eq 'RealTimeProtectionEnabled' }
        $row | Should -Not -BeNullOrEmpty
        $row.Impact | Should -Be 'Regression'
    }

    It 'treats an engine version bump as a neutral change, not a regression' {
        $diff = New-Pair { param($c) $c.DefenderStatus.AMEngineVersion = '1.1.24999.1' }
        ($diff | Where-Object { $_.Property -eq 'AMEngineVersion' }).Impact | Should -Be 'Change'
    }

    It 'flags script block logging lapsing to Not configured, not just Disabled' {
        # The rule originally matched only the literal 'Disabled' and missed
        # 'Not configured', which is equally unprotected.
        $diff = New-Pair { param($c) $c.PsLogging.ScriptBlockLogging = 'Not configured' }
        ($diff | Where-Object { $_.Property -eq 'ScriptBlockLogging' }).Impact | Should -Be 'Regression'
    }

    It 'flags a newly added Defender exclusion as a regression' {
        $diff = New-Pair { param($c)
            $c.DefenderExclusions = @($c.DefenderExclusions) + [pscustomobject]@{ Type = 'Path'; Value = 'C:\Users\Public' }
        }
        $added = $diff | Where-Object { $_.Area -eq 'DefenderExclusions' -and $_.Change -eq 'Added' }
        $added | Should -Not -BeNullOrEmpty
        $added.Impact | Should -Be 'Regression'
    }

    It 'flags a newly added local administrator as a regression' {
        $diff = New-Pair { param($c)
            $c.LocalAdmins = @($c.LocalAdmins) + [pscustomobject]@{ Member = 'CORP\contractor'; Type = 'User'; Source = 'ActiveDirectory' }
        }
        ($diff | Where-Object { $_.Area -eq 'LocalAdmins' -and $_.Change -eq 'Added' }).Impact | Should -Be 'Regression'
    }

    It 'detects a service changing state' {
        $diff = New-Pair { param($c) ($c.Services | Where-Object Name -eq 'WinDefend').State = 'Stopped' }
        ($diff | Where-Object { $_.Area -eq 'Services' -and $_.Property -eq 'State' }) | Should -Not -BeNullOrEmpty
    }

    It 'detects an ASR rule downgraded from Block to Audit' {
        $diff = New-Pair { param($c) $c.AsrRules[0].Mode = 'Block' }
        ($diff | Where-Object { $_.Area -eq 'AsrRules' -and $_.Property -eq 'Mode' }) | Should -Not -BeNullOrEmpty
    }

    It 'distinguishes permissive firewall rules that share a display name' {
        # DisplayName is NOT unique on Windows. Keying on it alone let a newly
        # added permissive rule collapse into an existing key and disappear.
        $diff = New-Pair { param($c)
            $c.FirewallPermissive = @($c.FirewallPermissive) + [pscustomobject]@{
                Rule = 'Remote Desktop - User Mode (TCP-In)'; Profile = 'Public'; Protocol = 'Any'
                LocalPort = 'Any'; RemoteAddr = 'Any'; Program = 'Any'; Scoped = 'No - any program'; Group = ''
            }
        }
        ($diff | Where-Object { $_.Area -eq 'FirewallPermissive' -and $_.Change -eq 'Added' }) | Should -Not -BeNullOrEmpty
    }

    It 'compares event sections by count only, never row by row' {
        $diff = New-Pair { param($c)
            $c.DefenderEvents = @(1..40 | ForEach-Object {
                [pscustomobject]@{ Time = (Get-Date); Id = 1121; Source = 'Defender'; Category = 'x'; Action = 'Blocked'; Detail = "e$_" }
            })
        }
        $rows = @($diff | Where-Object { $_.Area -eq 'DefenderEvents' })
        $rows.Count | Should -Be 1
        $rows[0].Property | Should -Be 'RowCount'
    }

    It 'sorts regressions ahead of neutral changes' {
        $diff = New-Pair { param($c)
            $c.DefenderStatus.AMEngineVersion = '9.9.9.9'
            $c.DefenderStatus.RealTimeProtectionEnabled = $false
        }
        $diff[0].Impact | Should -Be 'Regression'
    }

    It 'ignores case-only differences in identity and path values' {
        $diff = New-Pair { param($c) $c.LocalAdmins[0].Member = 'corp\domain admins' }
        $diff.Count | Should -Be 0
    }
}
