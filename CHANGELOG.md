# Changelog

All notable changes are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-08-12

First public release.

### Added
- **Fleet scanning.** Multiple targets in parallel through a throttled runspace
  pool, with a Fleet tab whose *Deviation* column counts how many posture fields
  differ from the fleet norm.
- **Baseline and diff.** Save a scan as a normalised JSON snapshot and compare
  later. Keyed per section so row reordering is not a change; event sections are
  compared by count so time-windowed noise cannot drown the signal. Security
  regressions are flagged and sorted first.
- **Unattended mode.** `-Quiet` loads no WPF at all, so it runs on Server Core
  and under a Session 0 scheduled task. Writes HTML, JSON and a summary CSV,
  emits summary objects to the pipeline, and sets severity-based exit codes.
- **Hardening collectors.** PowerShell script-block / module / transcription
  logging and the PowerShell 2.0 engine, LAPS across all four policy roots,
  system Exploit Protection, Windows Update currency and pending reboots.
- **Persistence triage.** Services and non-Microsoft scheduled tasks running
  from user-writable directories or with unquoted paths containing spaces.
- **Permissive firewall rules.** Enabled inbound Allow rules open to any address
  on any port or protocol, with a column distinguishing program-scoped rules.
- **SmartScreen app reputation**, plus explicit reporting of whether the
  analytic channel that records it is even enabled.
- **Smart App Control** state.
- **`-Credential`** at launch, reused across scans for a whole triage session.
- **Scan provenance** recorded in the report: who collected it, from where, with
  which build.
- **Interactive HTML report** — tabs, sortable columns, per-column filters,
  global find with per-tab match counts, row detail, per-table CSV export, and a
  print mode that expands every tab. Self-contained, no external references.
- `-TimeoutSec` ceiling so an unattended run can never wedge on a hung host.

### Fixed
These all shipped during development and are now covered by regression tests:
- `$script:Credential = $null` aliased the `-Credential` **parameter**, re-running
  its `[Credential()]` transformation attribute and prompting on the console —
  hanging every headless run forever. `$script:BaselinePath` had the same
  collision and silently erased the caller's value.
- `-TimeoutSec` did not bound anything: cleanup called `EndInvoke` on jobs that
  were still wedged, which blocks, freezing the dispatcher thread.
- Enumerating `.Keys` on a synchronized hashtable while workers inserted raced
  and threw "collection was modified".
- Snapshots built live used ordered dictionaries whose .NET members leaked in as
  data, so a scan compared against itself reported 63 phantom differences.
- `MaxColumnWidth` on the DataGrid capped *manual* resizing, making the Detail
  column impossible to widen.
- `[int]` cast of Defender's `4294967295` "never scanned" sentinel threw and
  blanked the entire dashboard.
- `, $array` returns combined with `@()` at call sites double-wrapped results.
- An invalid `.REQUIREMENTS` comment-based-help keyword truncated the help block,
  so `Get-Help` showed no parameters and only one example.
- The script-block-logging regression rule matched only the literal `Disabled`
  and missed `Not configured`, which is equally unprotected.

[1.5.0]: https://github.com/JosephMcEvoy/windows-security-health-dashboard/releases/tag/v1.5.0
