<#
    InjectionHunter baseline for src/SecurityHealthDashboard.ps1.

    InjectionHunter is a heuristic scanner. It flags every dynamic member access
    and every string-to-scriptblock conversion, because in the general case those
    can be injection sinks. In this script they are neither: each one was read and
    the reasoning is recorded below.

    This file is a CEILING, not a mute button. The CI job fails if a rule appears
    that is not listed here, or if a listed rule produces more hits than its
    count. Adding to it means someone reviewed the new site and wrote down why.
    If a count drops, CI warns so the ceiling gets lowered rather than left slack.

    Reviewed 2026-08-12 against commit 57ca83c. Fourteen findings, all accepted.

    ------------------------------------------------------------------ AddType 1
    L250  Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
          Literal assembly names, no interpolation. Loads WPF for the dashboard.

    ------------------------------------------------- ForeachObjectInjection 2
    L530  Threat rows: property reads off Get-MpThreatDetection output.
    L3539 Detection rows: property reads off the same objects for the grid.
          Both read fixed, named properties. Nothing is built from a string.

    --------------------------------------------------------- UnsafeEscaping 2
    L1293 -replace '\s', '' over a dsregcmd line already matched by a regex, then
          gated by a $wanted allowlist before it is used as a key.
    L2511 -replace '^Grid', '' to strip a literal prefix off a control name.
          Both patterns and replacements are literals.

    ------------------------------------------------- StaticPropertyInjection 6
    L362  (Get-ItemProperty -Path $Path -Name $Name).$Name  - reads back the value
          just requested; $Path and $Name come from this script's own registry map.
    L2464 $Row.$k    - $k is a grid column name from $State.Filters.Keys.
    L2828 $_.$name   - column name, building the distinct-value list for a filter.
    L3165 $Row.$_    - key name from $script:SectionKeys, a table defined in-script.
    L3200 $bs.$name  - section name off a loaded baseline snapshot. This is the one
          site whose name can come from an operator-supplied file. It is still only
          instance property access on a PSCustomObject, which cannot execute code;
          a hostile name yields $null, and the diff degrades to added/removed.
    L4446 $r.$c      - column name from $script:FleetPostureColumns.

    ------------------------------------------------------------------- Create 1
    L4519 [scriptblock]::Create($CollectorText) where $CollectorText is
          $script:SecurityCollector.ToString() - this script's own collector,
          serialized so it can cross a runspace boundary. Not external input.

    ---------------------------------------------------------------- AddScript 2
    L4613 GUI fleet scan  - $ps.AddScript($script:RunspaceWorker.ToString())
    L4735 Quiet fleet scan - the same worker on the headless path.
          Both marshal this script's own worker into a runspace pool, which is the
          standard idiom for [runspacefactory]. The values that vary per target
          are passed with AddArgument, not concatenated into the script text.

    Note the credential path is covered separately and precisely: the built-in
    PSScriptAnalyzer rules in this workflow report zero findings, and
    tests/Contract.Tests.ps1 asserts no plaintext extraction or persistence.
#>
@{
    'InjectionRisk.AddType'                 = 1
    'InjectionRisk.ForeachObjectInjection'  = 2
    'InjectionRisk.UnsafeEscaping'          = 2
    'InjectionRisk.StaticPropertyInjection' = 6
    'InjectionRisk.Create'                  = 1
    'InjectionRisk.AddScript'               = 2
}
