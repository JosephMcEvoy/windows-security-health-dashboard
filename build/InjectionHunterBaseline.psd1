<#
    InjectionHunter baseline for src/SecurityHealthDashboard.ps1.

    InjectionHunter is a heuristic scanner. It flags every dynamic member access
    and every string-to-scriptblock conversion, because in the general case those
    can be injection sinks. In this script they are neither: each one was read and
    the reasoning is recorded below.

    Each key is a fingerprint - rule name, file, and a short SHA-256 of the
    flagged code with whitespace collapsed - mapped to how many times that exact
    snippet is expected. Binding to the code rather than to a per-rule total is
    deliberate: a bare count would let someone delete a reviewed site, add an
    unsafe one under the same rule, and slip through on an unchanged total.
    Fingerprints move with the code, so line numbers below are only a hint.

    This is a CEILING, not a mute button. CI fails on any finding whose
    fingerprint is absent, or which appears more often than its count. Editing a
    flagged line changes its fingerprint and so demands a fresh look, which is
    the intended cost. If an entry stops matching, CI warns so it gets deleted
    rather than left behind as slack.

    To regenerate after a reviewed change, run:
        ./build/Test-InjectionBaseline.ps1 -Regenerate

    Reviewed 2026-08-12. Fourteen findings across thirteen fingerprints, all
    accepted. The credential path is covered separately and precisely: the
    built-in PSScriptAnalyzer rules in this workflow report zero findings, and
    tests/Contract.Tests.ps1 asserts no plaintext extraction or persistence.
#>
@{
    # -- Runspace plumbing -----------------------------------------------------
    # Both fleet paths (GUI L4613, quiet L4735) marshal this script's own worker
    # into a runspace pool as text, which is the standard [runspacefactory]
    # idiom. Per-target values go through AddArgument, never concatenation.
    'InjectionRisk.AddScript|SecurityHealthDashboard.ps1|fac8dde92f6ca754'             = 2

    # L4519 [scriptblock]::Create($CollectorText) where $CollectorText is
    # $script:SecurityCollector.ToString() - again this script's own code, not
    # external input, serialized to cross the same boundary.
    'InjectionRisk.Create|SecurityHealthDashboard.ps1|19becefad82155d8'                = 1

    # -- Assembly loading ------------------------------------------------------
    # L250 Add-Type -AssemblyName PresentationFramework, PresentationCore,
    # WindowsBase. Literal names, no interpolation; loads WPF for the dashboard.
    'InjectionRisk.AddType|SecurityHealthDashboard.ps1|a7d417b2aae32f51'               = 1

    # -- Fixed property reads over Defender output -----------------------------
    # L530 threat rows, L3539 detection rows. Both read fixed, named properties;
    # nothing is built from a string.
    'InjectionRisk.ForeachObjectInjection|SecurityHealthDashboard.ps1|60f408855ea14bf6' = 1
    'InjectionRisk.ForeachObjectInjection|SecurityHealthDashboard.ps1|3ffbf4df24fae043' = 1

    # -- Dynamic member access over this script's own names --------------------
    # L362  (Get-ItemProperty -Path $Path -Name $Name).$Name - reads back the
    #       value just requested; both come from this script's own registry map.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|d79c95c16805010b' = 1
    # L2464 $Row.$k  - grid column name from $State.Filters.Keys.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|1f9b82f3de141cfe' = 1
    # L2828 $_.$name - column name, building a filter's distinct-value list.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|5c2e7dcef3acb0e1' = 1
    # L3165 $Row.$_  - key name from $script:SectionKeys, defined in-script.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|f56d7b1a3126ab17' = 1
    # L3200 $bs.$name - section name off a loaded baseline snapshot. The one site
    #       whose name can come from an operator-supplied file. Still only
    #       instance property access on a PSCustomObject, which cannot execute
    #       code; a hostile name yields $null and the diff degrades to
    #       added/removed.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|89ba396426573018' = 1
    # L4446 $r.$c   - column name from $script:FleetPostureColumns.
    'InjectionRisk.StaticPropertyInjection|SecurityHealthDashboard.ps1|e3f0290c8e6e81a2' = 1

    # -- Literal -replace patterns ---------------------------------------------
    # L1293 $Matches[1] -replace '\s', '' over a dsregcmd line already matched by
    #       a regex, then gated by a $wanted allowlist before use as a key.
    'InjectionRisk.UnsafeEscaping|SecurityHealthDashboard.ps1|d9152a5c5e13d55c'         = 1
    # L2511 $st.Name -replace '^Grid', '' - strips a literal prefix off a control
    #       name. Pattern and replacement are both literals.
    'InjectionRisk.UnsafeEscaping|SecurityHealthDashboard.ps1|651a1ccb7459dcd5'         = 1
}
