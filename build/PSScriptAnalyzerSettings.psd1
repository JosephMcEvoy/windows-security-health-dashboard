@{
    # The tool is a single self-contained script by design: an operator copies
    # one .ps1 to a jump box and runs it. Several PSScriptAnalyzer defaults
    # assume a module with exported functions and do not apply.
    ExcludeRules = @(
        # Verbs are chosen for readability inside one file, and the script is
        # never imported as a module, so unapproved verbs mislead nobody.
        'PSUseApprovedVerbs'

        # Write-Host is correct here: quiet mode's banner is human-facing
        # console output, deliberately kept off the success stream so the
        # summary objects stay pipeable.
        'PSAvoidUsingWriteHost'

        # The functions live in one script and are called by other functions in
        # the same script; they are not a public API surface.
        'PSUseShouldProcessForStateChangingFunctions'

        # Interactive credential entry is the point of Request-ScanCredential.
        'PSAvoidUsingUsernameAndPasswordParams'

        # Deliberate, and load-bearing. The collector is a long series of
        # independent best-effort probes: a client SKU has no AppLocker module,
        # a workgroup box has no GPO, an older build has no Get-ProcessMitigation.
        # Each probe that cannot run must be skipped so the rest of the scan
        # still completes. Throwing or writing an error - which is what this
        # rule asks for - would abort a scan because one optional data source
        # was unavailable.
        #
        # This is not silent failure: every TOP-LEVEL collector records what
        # went wrong via Add-CollectorError, and those surface on the
        # "Collection log" tab and in the exported report. The empty catches are
        # the inner probes underneath that, where the outer handler has already
        # taken responsibility for reporting.
        'PSAvoidUsingEmptyCatchBlock'

        # These are internal helpers inside one script, not exported cmdlets, and
        # they return collections. Get-UnifiedEvents and New-HealthCards read
        # correctly; Get-UnifiedEvent and New-HealthCard would read as though
        # they returned one item.
        'PSUseSingularNouns'

        # WPF event handlers must match a fixed delegate signature, so
        # param($s, $e) is required even when a handler only uses one of them.
        'PSReviewUnusedParameter'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            # Windows PowerShell 5.1 is the primary target; PowerShell 7 on
            # Windows must also work.
            TargetVersions = @('5.1', '7.0')
        }
        PSPlaceOpenBrace = @{
            Enable     = $true
            OnSameLine = $true
        }
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }
    }
}
