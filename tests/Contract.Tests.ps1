#Requires -Modules Pester

<#
    Contract tests. These assert properties of the tool as a whole rather than
    the behaviour of one function: the things a reviewer would want guaranteed
    before running it against production machines with admin rights.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    $script:File = Get-ScriptUnderTest
    $script:Src = Get-Content -Path $script:File -Raw
    $script:Ast = Get-DashboardAst
}

Describe 'Read-only contract' {
    It 'contains no cmdlet that changes state on a target' {
        # The whole value proposition is that this is safe to hand to a junior
        # tech and point at a production box. If that ever stops being true it
        # must be a deliberate, reviewed change - not an accident.
        $mutators = [regex]::Matches($script:Src,
            '(?m)^\s*(Set-Mp\w+|Add-Mp\w+|Remove-Mp\w+|Set-NetFirewall\w+|New-NetFirewall\w+|Remove-NetFirewall\w+|Set-Service|Stop-Service|Start-Service|Restart-Computer|Remove-Item|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $mutators | Should -BeNullOrEmpty
    }

    It 'only ever writes files the operator explicitly asked for' {
        # WriteAllText is fine (report/snapshot export); anything writing to the
        # remote target would not be.
        $writes = [regex]::Matches($script:Src, '\[System\.IO\.File\]::Write\w+') |
            ForEach-Object { $_.Value } | Sort-Object -Unique
        foreach ($w in $writes) { $w | Should -Be '[System.IO.File]::WriteAllText' }
    }
}

Describe 'Credential safety' {
    It 'never extracts a plaintext password' {
        $script:Src | Should -Not -Match 'GetNetworkCredential'
        $script:Src | Should -Not -Match 'ConvertFrom-SecureString'
    }

    It 'never persists a credential to disk' {
        $script:Src | Should -Not -Match 'Export-Clixml'
    }

    It 'does not shadow the -Credential parameter with script state' {
        # $script:Credential IS the -Credential parameter at script scope.
        # Assigning to it re-runs the [Credential()] transformation attribute,
        # which prompts on the console - hanging any headless run forever.
        $script:Src | Should -Not -Match '\$script:Credential\s*='
    }

    It 'does not shadow any parameter with script state' {
        $params = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($p in $params) {
            $script:Src | Should -Not -Match ('\$script:' + [regex]::Escape($p) + '\s*=')
        }
    }
}

Describe 'PowerShell 5.1 compatibility' {
    It 'is pure ASCII' {
        # A BOM-less file is read as ANSI by Windows PowerShell 5.1, so any byte
        # above 0x7F corrupts the line it sits on.
        $bytes = [System.IO.File]::ReadAllBytes($script:File)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'uses no PowerShell 7-only syntax' {
        $script:Src | Should -Not -Match '\?\?'          # null coalescing
        $script:Src | Should -Not -Match '\$\w+\?\.'     # null conditional
        $script:Src | Should -Not -Match '-Parallel\b'   # ForEach-Object -Parallel
        $script:Src | Should -Not -Match '\bchain\b\s*\|\|'
    }

    It 'declares a 5.1 minimum' {
        $script:Src | Should -Match '#Requires -Version 5\.1'
    }
}

Describe 'Structural integrity' {
    It 'parses without errors' {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:File, [ref]$null, [ref]$errs)
        $errs.Count | Should -Be 0
    }

    It 'has well-formed embedded XAML' {
        $script:Src -match "(?s)\`$xaml = @'\r?\n(.*?)\r?\n'@" | Should -BeTrue
        { [xml]$Matches[1] } | Should -Not -Throw
    }

    It 'resolves every UI element reference' {
        $null = $script:Src -match "(?s)\`$xaml = @'\r?\n(.*?)\r?\n'@"
        $names = [regex]::Matches($Matches[1], 'x:Name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
        $null = $script:Src -match "(?s)foreach \(\`$name in @\((.*?)\)\) \{"
        $refs = [regex]::Matches($Matches[1], "'([A-Za-z]\w*)'") | ForEach-Object { $_.Groups[1].Value }
        @($refs | Where-Object { $names -notcontains $_ }) | Should -BeNullOrEmpty
        $used = [regex]::Matches($script:Src, '\$ui\.([A-Za-z]\w+)') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique | Where-Object { $_ -ne 'Keys' }
        @($used | Where-Object { $refs -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'returns no comma-wrapped arrays' {
        # "return , $array" from a function whose caller wraps in @() produces a
        # one-element array containing the array, so $_.Prop then reads the
        # ARRAY's members. This shipped three separate times.
        @([regex]::Matches($script:Src, '(?m)^\s+,\s*\$\w+')) | Should -BeNullOrEmpty
    }

    It 'keeps every Get-WinEvent id list under the FilterHashtable limit' {
        foreach ($m in [regex]::Matches($script:Src, '-Ids @\(([^)]*)\)')) {
            @($m.Groups[1].Value -split ',' | Where-Object { $_.Trim() }).Count | Should -BeLessOrEqual 22
        }
    }
}

Describe 'Documented interface' {
    It 'exposes the documented parameters' {
        $params = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($p in 'ComputerName', 'LookbackDays', 'Credential', 'BaselinePath',
                       'TargetFile', 'Throttle', 'Quiet', 'OutputPath', 'NoHtml', 'TimeoutSec') {
            $params | Should -Contain $p
        }
    }

    It 'documents every parameter in comment-based help' {
        $help = $script:Ast.GetHelpContent()
        foreach ($p in 'Credential', 'Quiet', 'OutputPath', 'BaselinePath', 'TargetFile', 'Throttle', 'TimeoutSec', 'NoHtml') {
            $help.Parameters.Keys | Should -Contain $p.ToUpperInvariant()
        }
    }

    It 'accepts a bare user name for -Credential' {
        $cp = $script:Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Credential' }
        @($cp.Attributes | Where-Object { $_.TypeName.FullName -match 'Credential' -and $_.Extent.Text -match '\(\)' }) |
            Should -Not -BeNullOrEmpty
    }
}
