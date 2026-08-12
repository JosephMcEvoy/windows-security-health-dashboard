# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub Security Advisories:

**[Report a vulnerability](https://github.com/JosephMcEvoy/windows-security-health-dashboard/security/advisories/new)**
(repository → **Security** tab → **Advisories** → **Report a vulnerability**)

That opens a private thread visible only to you and the maintainers, and it
gives us somewhere to work on a fix and request a CVE before anything is public.

If GitHub Advisories is unavailable to you, email **joe.maci@gmail.com** with
`SECURITY` in the subject. Please do not include exploit details in the first
message — just enough to establish scope, and we will move to a private channel.

### What to include

- What an attacker gains, and what access they need to start.
- Affected version (the release tag, or the commit SHA).
- Reproduction steps, ideally against a lab machine.
- Whether you intend to disclose publicly, and on what timeline.

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment | within 10 business days |
| Fix or documented mitigation | target 30 days for High/Critical |
| Credit | in the advisory and release notes, unless you prefer otherwise |

This is a personal project, not a funded product. There is no bug bounty. Those
timelines are honest intentions, not a contractual SLA.

## Supported versions

Only the latest release receives fixes. There are no maintenance branches.

| Version | Supported |
|---|---|
| Latest release | yes |
| Anything older | no — upgrade |

## Scope

This is a single PowerShell script that connects to Windows hosts over WinRM
with administrative rights and renders the results as HTML. The interesting
attack surface is small but real.

**In scope**

- Anything that makes the tool **write to, or change state on, a target**. It is
  read-only by design and that is enforced in CI.
- **Credential exposure**: a credential reaching disk, a log, an exported
  report, a process command line, or a remote host.
- **Injection into the HTML report.** Report content includes attacker- or
  operator-influenced strings — Defender exclusion paths, firewall rule names,
  service binary paths, event message text. All of it must render as inert text.
  A working XSS in a generated report is a valid finding, and reports get
  emailed and put on file shares, so this matters more than it looks.
- **Code injection into the collector** — anything causing arbitrary code to run
  on a scanned target beyond the intended read-only collection.
- **Misleading output that would change an operator's decision.** If the tool
  reports a control as present when it is absent, that is a security bug here,
  not a cosmetic one. The clearest example: SmartScreen's app-reputation channel
  is disabled by default, so "no events" must never be presented as "nothing was
  blocked."
- **Supply chain**: a compromised or unpinned GitHub Action, or a release
  artifact that does not match the source.

**Out of scope**

- Weaknesses the tool *reports on*. Finding that a host has Defender disabled is
  the tool working correctly.
- Needing administrative rights to scan. That is the documented prerequisite.
- Findings that require an attacker to already control the operator's
  workstation or the credential being used.
- WinRM/Kerberos design issues — report those to Microsoft.
- Output files containing sensitive host data. That is inherent: a scan report
  describes a machine's security posture. Handle the files accordingly; the
  `.gitignore` deliberately excludes them.

## Design decisions relevant to security

- **Read-only.** The collector never modifies a target. A CI contract test fails
  the build if a state-changing cmdlet appears in `src/`.
- **Credentials stay in memory.** Never written to disk, never placed on a
  command line, never included in a report or snapshot. Only the *user name* is
  recorded, as scan provenance. A contract test asserts the script contains no
  `GetNetworkCredential`, `ConvertFrom-SecureString` or `Export-Clixml`.
- **Reports are self-contained.** No CDN, no remote fonts, no telemetry. A
  report opened on an isolated machine makes zero network requests. CI asserts
  the generated HTML has no external references.
- **The JSON payload is escaped so it cannot break out of its `<script>` block**,
  and every value is HTML-escaped before it reaches the DOM.
- **No `Invoke-Expression`** anywhere. Scriptblocks are created only from the
  tool's own text, never from collected data.
