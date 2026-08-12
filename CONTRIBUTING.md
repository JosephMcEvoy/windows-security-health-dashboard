# Contributing

Thanks for looking. This is a focused tool with a narrow purpose, and the bar
for merging is "would I run this against a production fleet at 2am". That is not
meant to be discouraging — it is meant to tell you what reviews will focus on.

## Before you start

**Open an issue first for anything non-trivial.** A quick "I'd like to add X"
saves you writing something that turns out to conflict with a design decision.
Small fixes, typos, and obviously-correct bug fixes can go straight to a PR.

## The PR process

1. **Fork** the repository and create a branch off `main`:

   ```bash
   git clone https://github.com/<you>/windows-security-health-dashboard.git
   cd windows-security-health-dashboard
   git checkout -b fix/quick-scan-age-overflow
   ```

2. **Make the change.** Keep it to one logical change per PR. A PR that fixes a
   bug *and* reformats 400 lines is very hard to review.

3. **Run the checks locally.** All of these run in CI anyway, but the loop is
   much faster on your machine:

   ```powershell
   ./build/Invoke-StaticChecks.ps1          # structural guards
   Invoke-Pester ./tests                    # unit + contract tests
   Invoke-ScriptAnalyzer ./src -Recurse -Settings ./build/PSScriptAnalyzerSettings.psd1
   ```

   If you touched the HTML report:

   ```powershell
   ./build/New-SampleReport.ps1 -OutputPath ./tests/browser/report.html -Fleet
   cd tests/browser && npm install && npx playwright install chromium && node report.test.js report.html
   ```

4. **Add a test.** Every bug fix should come with a test that fails before the
   fix and passes after. `tests/` has plenty of examples; most of them exist
   because that exact bug shipped once.

5. **Open the PR** against `main`. Fill in the template — especially *how you
   tested it* and *what you did not test*. "Ran it against one Windows 11 box"
   is a perfectly good answer; silence is not.

6. **CI must be green.** Reviews happen after that, not before.

## What gets merged easily

- Bug fixes with a regression test.
- New collectors that use **in-box Windows cmdlets only**, are wrapped in their
  own `try`/`catch`, and degrade to a Collection-log entry rather than failing
  the scan.
- Better findings: clearer wording, fewer false positives, tighter thresholds.
- Documentation that corrects something wrong or unclear.

## What will get pushed back on

- **Anything that writes to a target.** The tool is read-only and a CI contract
  test enforces it. If remediation is ever added it will be behind an explicit
  opt-in switch with per-action confirmation and logging — that is a design
  discussion to have in an issue, not a surprise in a PR.
- **New runtime dependencies.** No modules to install, no NuGet, no internet at
  scan time. An operator copies one `.ps1` to a jump box and runs it, sometimes
  on an isolated network. Node and Playwright are dev-only, for the report test.
- **Anything that puts credential material on disk, in a log, on a command line,
  or in a report.**
- **Silent failure.** If a collector cannot get data, say so. The single worst
  outcome for this tool is showing a reassuring empty table when the truth is
  "nobody was writing that down" — see the SmartScreen handling for the pattern
  to follow.
- **PowerShell 7-only syntax.** Windows PowerShell 5.1 is the primary target
  because it is what is already on every Windows host. No `??`, no `?.`, no
  `-Parallel`.
- **Non-ASCII characters in `src/`.** A BOM-less file is read as ANSI by
  Windows PowerShell 5.1, so a stray non-ASCII byte corrupts its line. Use XML
  character references in the XAML (`&#x25BE;`) and `[char]0x2022` in code.

## House rules that have teeth

These are enforced by `build/Invoke-StaticChecks.ps1` and `tests/Contract.Tests.ps1`,
and each one exists because it broke something real:

| Rule | Why |
|---|---|
| No `$script:<Name>` that matches a parameter name | At script scope that *is* the parameter variable. Assigning to it re-runs its attributes — this once prompted for a credential on a headless run and hung forever, and once silently erased `-BaselinePath`. |
| No `return , $array` | Callers wrap in `@()`; the comma double-wraps, so `$_.Prop` then reads the *array's* members. Shipped three times. |
| Pure ASCII | See above. |
| No comment-based-help keyword that PowerShell does not recognise | An invalid one truncates the whole help block. `Get-Help` silently lost every parameter for a while because of `.REQUIREMENTS`. |
| Every `Get-WinEvent -FilterHashtable` id list ≤ 22 ids | Overflowing it fails the whole query, silently returning nothing. |

## Style

- Follow the surrounding code. 4-space indent, `PascalCase` functions,
  `$camelCase` locals.
- **Comment the "why", not the "what".** `# increment i` is noise. `# .Count,
  not @(.Keys).Count - workers are still inserting concurrently` is the kind of
  comment that stops the next person reintroducing a race.
- Keep the single-file layout. It is deliberate: one file to copy to a jump box.

## Reporting bugs

Open an issue with the template. The single most useful thing you can include is
the **Collection log tab** from a scan (or the `Errors` section of a JSON
snapshot) — it says exactly which collectors failed and why.

**Security issues do not go in the issue tracker.** See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contributions are licensed under the
[MIT Licence](LICENSE) that covers this project.
