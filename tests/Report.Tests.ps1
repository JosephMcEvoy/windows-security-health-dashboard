#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    . ([scriptblock]::Create((Import-DashboardFunction `
        -FunctionName 'Format-Value', 'New-NVRows', 'Get-Section', 'Get-ArrSection', 'New-Findings',
                      'Get-UnifiedEvents', 'New-HealthCards', 'ConvertTo-ReportRows',
                      'New-ReportPanel', 'Get-HtmlReport' `
        -VariableAssignment '$script:ReportTemplate', '$script:ModeMaps')))

    $script:Scan = New-MockScan
    $script:Html = Get-HtmlReport $script:Scan
    $script:Payload = $null
    if ($script:Html -match '(?s)<script type="application/json" id="payload">(.*?)</script>') {
        $script:Payload = $Matches[1] | ConvertFrom-Json
    }
}

Describe 'HTML report generation' {
    It 'produces a self-contained document with no external references' {
        $script:Html | Should -Match '<!DOCTYPE html>'
        # No CDN, no remote fonts, no remote images: the report has to work from
        # a file share, an email attachment or an air-gapped jump box.
        $script:Html | Should -Not -Match '<script[^>]+src='
        $script:Html | Should -Not -Match '<link[^>]+href="https?:'
        $script:Html | Should -Not -Match "url\(['`"]?https?:"
    }

    It 'embeds a payload that parses as JSON' {
        $script:Payload | Should -Not -BeNullOrEmpty
        @($script:Payload.panels).Count | Should -BeGreaterThan 20
        @($script:Payload.cards).Count | Should -BeGreaterThan 10
    }

    It 'never lets a value break out of the JSON script block' {
        # A Defender exclusion path is attacker-influenceable and the report gets
        # emailed around, so "</script>" in a value must not end the block.
        $raw = ([regex]::Match($script:Html, '(?s)<script type="application/json" id="payload">(.*?)</script>')).Groups[1].Value
        $raw | Should -Not -Match '</script'
        $raw | Should -Match '<\\/script'
    }

    It 'preserves regex replacement tokens verbatim' {
        # -replace would treat $1 and $& as capture references and corrupt the
        # value; the generator must use ordinal String.Replace.
        $panel = $script:Payload.panels | Where-Object { $_.title -like 'Exclusions*' }
        @($panel.rows | Where-Object { $_.Value -like '*$1 $&*' }).Count | Should -Be 1
    }

    It 'keeps a single-row section as an array' {
        # ConvertTo-Json collapses one-element arrays; the client-side A() helper
        # and the generator both have to cope.
        $panel = $script:Payload.panels | Where-Object { $_.title -like 'Attack Surface*' }
        @($panel.rows).Count | Should -Be 1
    }

    It 'records scan provenance without any credential material' {
        $script:Payload.subtitle | Should -Match 'Collected by CORP\\svc_secops from SOC-WS01'
        $script:Html | Should -Not -Match 'GetNetworkCredential|SecureString|ConvertFrom-SecureString'
    }

    It 'carries the SmartScreen "not logged" caveat into the report' {
        # Absence of evidence must never render as evidence of absence.
        $script:Html | Should -Match 'not logged'
    }

    It 'builds every expected tab' {
        $tabs = @($script:Payload.panels | ForEach-Object { $_.tab } | Sort-Object -Unique)
        foreach ($t in 'Overview', 'Defender', 'Events', 'Firewall', 'Identity', 'Policies', 'System', 'Hardening', 'Persistence') {
            $tabs | Should -Contain $t
        }
    }
}

Describe 'Shared render model' {
    It 'derives the same event stream the dashboard uses' {
        $events = @(Get-UnifiedEvents $script:Scan)
        $events.Count | Should -Be 6   # 2 Defender + 1 AppLocker + 1 Firewall + 2 Security
        @($events | Where-Object { $_.Action -eq 'Blocked' }).Count | Should -Be 2
        @($events | Where-Object { $_.Source -eq 'SmartScreen' }).Count | Should -Be 0
    }

    It 'sorts events newest first' {
        $events = @(Get-UnifiedEvents $script:Scan)
        $sorted = @($events | Sort-Object Time -Descending)
        $events[0].Time | Should -Be $sorted[0].Time
    }

    It 'returns health cards as data, not as UI objects' {
        $cards = @(New-HealthCards -Data $script:Scan -Events @(Get-UnifiedEvents $script:Scan))
        $cards.Count | Should -BeGreaterThan 15
        $cards[0].PSObject.Properties.Name | Should -Contain 'State'
        @($cards | ForEach-Object { $_.State } | Sort-Object -Unique) |
            ForEach-Object { $_ | Should -BeIn @('Good', 'Warn', 'Bad', 'Info') }
    }

    It 'renders a uint32 never-scanned sentinel as text, not a huge number' {
        # Defender reports 4294967295 for "never". Casting that to [int] throws
        # and blanked the entire dashboard.
        $cards = @(New-HealthCards -Data $script:Scan -Events @())
        ($cards | Where-Object { $_.Title -eq 'Last Quick Scan' }).Value | Should -Be 'Never'
    }
}

Describe 'Findings' {
    It 'raises a critical finding when the Security log was cleared' {
        $f = @(New-Findings $script:Scan)
        ($f | Where-Object { $_.Finding -like '*Security event log was CLEARED*' }).Severity | Should -Be 'Critical'
    }

    It 'explains that SmartScreen prompts are not being logged' {
        $f = @(New-Findings $script:Scan)
        ($f | Where-Object { $_.Area -eq 'SmartScreen' -and $_.Finding -like '*NOT being recorded*' }) |
            Should -Not -BeNullOrEmpty
    }

    It 'orders findings by severity' {
        $f = @(New-Findings $script:Scan)
        $f[0].Severity | Should -Be 'Critical'
    }

    It 'reports a healthy host as having no attention items' {
        $clean = New-MockScan
        $clean.DefenderStatus.IsTamperProtected = $true
        $clean.DefenderStatus.AntivirusSignatureAge = 1
        $clean.DefenderStatus.QuickScanAge = 2
        $clean.IdentityEvents = @()
        $clean.FirewallProfiles = @([pscustomobject]@{ Profile = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; LogBlocked = 'True'; LogFileName = 'x' })
        $clean.FailedLogonCount = 0
        $clean.Services = @([pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Defender'; State = 'Running'; StartMode = 'Auto' })
        $f = @(New-Findings $clean)
        # Still expected to raise Info items, but nothing critical.
        @($f | Where-Object { $_.Severity -eq 'Critical' }).Count | Should -Be 0
    }
}
