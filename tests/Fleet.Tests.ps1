#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    . ([scriptblock]::Create((Import-DashboardFunction `
        -FunctionName 'Format-Value', 'Get-Section', 'Get-ArrSection', 'New-Findings',
                      'Get-UnifiedEvents', 'Split-TargetList', 'New-FleetRow', 'Add-FleetDeviation' `
        -VariableAssignment '$script:ModeMaps', '$script:FleetPostureColumns')))
}

Describe 'Target list parsing' {
    It 'splits on commas, semicolons and whitespace' {
        @(Split-TargetList 'PC-1, PC-2;PC-3  PC-4') | Should -Be @('PC-1', 'PC-2', 'PC-3', 'PC-4')
    }
    It 'removes duplicates case-insensitively but keeps the first spelling' {
        @(Split-TargetList 'PC-1,pc-1,PC-2') | Should -Be @('PC-1', 'PC-2')
    }
    It 'tolerates empty and whitespace-only input' {
        @(Split-TargetList '').Count | Should -Be 0
        @(Split-TargetList "  `t ").Count | Should -Be 0
    }
    It 'handles newline-separated input pasted from a file' {
        @(Split-TargetList "PC-1`r`nPC-2`nPC-3").Count | Should -Be 3
    }
}

Describe 'Fleet rows' {
    It 'summarises a successful scan' {
        $row = New-FleetRow -Computer 'PC-042' -d (New-MockScan)
        $row.Status | Should -Be 'OK'
        $row.Host | Should -Be 'PC-042'
        $row.RTP | Should -Be 'On'
        $row.Tamper | Should -Be 'Off'
        $row.SmartScreenLog | Should -Be 'Not logged'
    }

    It 'marks a failed target as FAILED even when the exception message is empty' {
        # An empty message used to fall through to the success path and render a
        # dead host as a healthy all-blank row, which also skewed the fleet norm.
        $row = New-FleetRow -Computer 'PC-099' -Failed -ScanError ''
        $row.Status | Should -Be 'FAILED'
        $row.Detail | Should -Not -BeNullOrEmpty
    }

    It 'renders the never-scanned sentinel as text' {
        (New-FleetRow -Computer 'PC-042' -d (New-MockScan)).SigAgeDays | Should -Be '9'
    }
}

Describe 'Fleet deviation scoring' {
    It 'scores zero when every host matches' {
        $rows = 1..3 | ForEach-Object { New-FleetRow -Computer "PC-$_" -d (New-MockScan -Name "PC-$_") }
        $scored = @(Add-FleetDeviation @($rows))
        @($scored | ForEach-Object { $_.Deviation }) | Should -Be @(0, 0, 0)
    }

    It 'floats the odd machine out' {
        $rows = @()
        1..3 | ForEach-Object { $rows += New-FleetRow -Computer "PC-$_" -d (New-MockScan -Name "PC-$_") }
        $odd = New-MockScan -Name 'PC-BAD'
        $odd.DefenderStatus.RealTimeProtectionEnabled = $false
        $odd.SecuritySettings.SecureBoot = 'Off'
        $rows += New-FleetRow -Computer 'PC-BAD' -d $odd
        $scored = @(Add-FleetDeviation $rows)
        $bad = $scored | Where-Object { $_.Host -eq 'PC-BAD' }
        $bad.Deviation | Should -BeGreaterThan 0
        foreach ($r in @($scored | Where-Object { $_.Host -ne 'PC-BAD' })) { $r.Deviation | Should -Be 0 }
    }

    It 'leaves deviation at zero for a single host, where it is meaningless' {
        $scored = @(Add-FleetDeviation @((New-FleetRow -Computer 'PC-1' -d (New-MockScan))))
        $scored[0].Deviation | Should -Be 0
    }

    It 'ignores failed hosts when computing the fleet norm' {
        $rows = @()
        1..2 | ForEach-Object { $rows += New-FleetRow -Computer "PC-$_" -d (New-MockScan -Name "PC-$_") }
        $rows += New-FleetRow -Computer 'DEAD' -Failed -ScanError 'unreachable'
        $scored = @(Add-FleetDeviation $rows)
        foreach ($r in @($scored | Where-Object { $_.Status -eq 'OK' })) { $r.Deviation | Should -Be 0 }
    }
}
