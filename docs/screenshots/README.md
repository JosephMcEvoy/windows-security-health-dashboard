# Screenshots

## Report images (automated)

`report-*.png` are generated reproducibly from mock scan data:

```powershell
./build/New-Screenshots.ps1
```

That builds a sample report with `build/New-SampleReport.ps1 -Fleet` and drives
it in headless Chromium. It runs anywhere Node and Playwright run, including
Linux CI, because the report is just HTML. No real host data is involved.

## Dashboard images (manual, Windows only)

`gui-*.png` cannot be automated — the WPF dashboard needs a real Windows desktop
session. To produce them:

```powershell
./build/Capture-Screenshots.ps1
```

It launches the dashboard and prompts you through each view, saving a PNG of the
foreground window on demand.

> **Scan a lab machine.** These images become public and will show real machine
> names, account names, domain names, IP addresses and event detail. Redact
> before committing, or use a throwaway VM.

Expected filenames, referenced by the README once they exist:

| File | View |
|---|---|
| `gui-overview.png` | Overview: health cards and attention items |
| `gui-events.png` | Events with a column filter open |
| `gui-fleet.png` | Fleet tab sorted by Deviation |
| `gui-changes.png` | Changes tab with a baseline loaded |
| `gui-defender.png` | Defender status, preferences, ASR, exclusions |
| `gui-persistence.png` | Services and tasks from user-writable paths |
