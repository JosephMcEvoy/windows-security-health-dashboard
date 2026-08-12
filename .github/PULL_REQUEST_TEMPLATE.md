## What this changes

<!-- One or two sentences. Link the issue if there is one: Fixes #123 -->

## Why

<!-- What was wrong, or what could not be done before. -->

## How it was tested

<!-- Be specific and be honest about the gaps. "Ran against one Windows 11 box
     and one Server 2019 box; did not test on a workgroup machine" is a good
     answer. Silence is not. -->

- [ ] `./build/Invoke-StaticChecks.ps1` passes
- [ ] `Invoke-Pester ./tests` passes
- [ ] PSScriptAnalyzer is clean
- [ ] Ran against a real Windows host (say which OS below)
- [ ] Report browser test passes (only if the HTML report changed)

Tested on:

## Checklist

- [ ] One logical change
- [ ] A test covers the fix or the new behaviour
- [ ] Nothing is written to, or changed on, a scanned target
- [ ] No credential material reaches disk, a log, a command line, or a report
- [ ] No new runtime dependency — in-box cmdlets only
- [ ] Windows PowerShell 5.1 compatible (no `??`, `?.`, `-Parallel`)
- [ ] `src/` is still pure ASCII
- [ ] Comment-based help updated if a parameter changed

## Anything reviewers should look at closely

<!-- Threading, error handling, a collector that can fail on older OS versions,
     anything you are unsure about. Point at it. -->
