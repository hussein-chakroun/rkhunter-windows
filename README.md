# Rootkit Hunter for Windows

[![Windows checks](https://github.com/hussein-chakroun/rkhunter/actions/workflows/windows.yml/badge.svg)](https://github.com/hussein-chakroun/rkhunter/actions/workflows/windows.yml)
[![License: GPL v2 or later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

A PowerShell command-line tool for Windows file integrity checks, persistence
inspection, and security configuration review. It adapts the Rootkit Hunter
workflow to Windows APIs, with explicit baselines, configurable checks, readable
summaries, and JSON reports.

This is an **independent Windows adaptation**, not an official upstream release.
The original Rootkit Hunter 1.4.6 source is preserved in [`upstream/`](upstream/).

> **Scope:** This tool performs user-mode integrity and heuristic checks. It
> cannot establish that a computer is free of rootkits. Linux-only checks are
> reported as skipped, and the Windows threat indicator database starts empty.
> It complements other security controls and investigation methods.

[Quick start](#quick-start) · [Features](#features) · [Commands and configuration](#commands-and-configuration) · [Reports and exit codes](#reports-and-exit-codes) · [Installation options](#installation-options) · [Development](#development)

## Requirements

Use 64-bit Windows PowerShell 5.1 (included with Windows 10/11) or PowerShell 7
on Windows. There are no Python, WSL, Bash, Perl, Pester or third-party module
dependencies. Administrator access is recommended for the most complete
inspection. Windows Server can run the core checks, but desktop antivirus
registration and some optional cmdlets may be unavailable.

## Quick start

### 1. Clone and install

Open a normal PowerShell terminal and run these commands in order:

```powershell
git clone https://github.com/hussein-chakroun/rkhunter.git
Set-Location .\rkhunter
.\setup.cmd
```

Git is needed only for cloning. If you download a repository ZIP instead,
extract it and open PowerShell inside the folder containing `setup.cmd`, then
run `.\setup.cmd`.

This installs to `%LOCALAPPDATA%\Programs\rkhunter` and adds that directory to
**your user PATH**. Installation does not need Administrator rights at this
default location.

### 2. Make the command available

Close and reopen your terminal application after installation, including Windows
Terminal or VS Code if it hosts the terminal.

To use the newly installed command immediately in the **same PowerShell window**,
run:

```powershell
$env:Path = "$env:LOCALAPPDATA\Programs\rkhunter;$env:Path"
```

This refreshes this terminal session only; the installer already saved
the user PATH for future terminals. For a custom installation destination, use
that directory instead of `%LOCALAPPDATA%\Programs\rkhunter` in the command.

### 3. Run a scan

You can then run these commands **from any folder**:

```powershell
rkhunter --config-check
rkhunter --admin --check
```

To inspect with your current permissions instead, run `rkhunter --check`.

Use **`--admin` for the most complete scan**: it requests Windows UAC approval
and opens an Administrator console. A normal scan works with reduced access;
protected checks may report errors or skips. Installation does not grant
permanent Administrator privileges. Standard accounts need administrator
credentials at the Windows prompt. If already elevated, the command stays in
the existing console. `rkhunter-admin --check` is an equivalent convenience
command; double-clicking `rkhunter-admin.cmd` requests an elevated scan.

The new Administrator window waits for Enter after completion so its results
stay visible. Use `--sk`, `--quiet` or `--cronjob` to disable that final pause.
The original terminal waits and receives the scan's exit code. `--admin` is an
interactive UAC flow, not an unattended task-elevation mechanism.

### 4. Save a report

To save a report at a path that works from any folder:

```powershell
rkhunter --admin --check --json "$env:USERPROFILE\rkhunter-report.json"
```

### 5. Create a trusted baseline

A first scan reports a missing property/account baseline. **After independently
verifying the computer**, explicitly create one, then scan again:

```powershell
rkhunter --admin --propupd
rkhunter --admin --check
```

`--propupd` trusts the current state. Do not use it to make unexplained changes
disappear. The scanner never creates a baseline automatically and never deletes
malware, stops processes, changes security settings or starts an antivirus scan.
Scan writes are limited to its database lock, text log and optional JSON report.
Baselines, imports and installation write their explicitly selected destinations.

To use the checkout without installing, open a terminal in the cloned folder:

```powershell
.\rkhunter.cmd --admin --check
.\rkhunter.cmd --check --enable system_commands,network --nocolors
```

The PowerShell entry point accepts the same arguments. The `.cmd` launchers use
`-ExecutionPolicy Bypass` for their PowerShell process so reviewed local scripts
can run on a default Windows installation. They do not change the saved user or
machine execution policy; organizational Group Policy can still restrict them.
Direct `.ps1` invocation follows your terminal's execution policy.

## Features

| Area | Windows behavior |
| --- | --- |
| Properties | SHA256, length, last-write time, attributes, owner and security descriptor compared with a per-computer baseline |
| Processes | Reported executable paths, missing executables and system-name masquerading |
| Drivers | Installed/running driver paths and embedded Authenticode signature status |
| Persistence | Service paths, unquoted service executables, registry autoruns, Winlogon, IFEO, AppInit, startup folders, task actions and permanent WMI consumers |
| Network | TCP listeners, UDP endpoints and adapter promiscuous-mode state when exposed |
| Accounts | Local account state and Administrators membership changes; password-required flags |
| Security settings | Defender/antivirus registration, firewall profiles, UAC, Secure Boot and recognized boot integrity flags |
| Filesystem | Hidden executables/scripts and non-default alternate data streams in bounded configured directories |
| Hosts | Active non-default redirects |
| Local indicators | User-supplied exact Windows paths and whole-file SHA256 hashes |

Warnings are leads for review. Legitimate tools can use writable locations,
unquoted paths, WMI persistence, debug settings, hidden files or unusual streams.
Many legitimate drivers are catalog-signed without embedded signatures;
`Get-AuthenticodeSignature` results are not a complete Windows driver trust check.
Port matches come from the **historical upstream Unix database**, not a current
Windows threat feed.

The bundled Windows indicator database starts **empty**. `known_rkts` reports
`Skipped` until you supply verified indicators. The tool has no active vendor
signature feed, CVE scanner, offline image scan, hidden process/port detector,
or automatic malware removal. A compromised kernel can hide information from
the user-mode APIs used by this scanner.

## Commands and configuration

After installation, these commands work from any folder:

| Command | Purpose |
| --- | --- |
| `rkhunter --help` | Show commands and options |
| `rkhunter --version` | Show the Windows port version |
| `rkhunter --list tests` | List checks, groups, and unsupported checks |
| `rkhunter --list propfiles` | List monitored files |
| `rkhunter --config-check` | Validate configuration and indicator data |
| `rkhunter --admin --check` | Request an elevated scan |
| `rkhunter --check --enable properties,ports --disable attributes` | Select checks and groups |
| `rkhunter --admin --propupd cmd.exe` | Explicitly refresh matching existing baseline file entries |

For noninteractive console output, use the following with the permissions of
the terminal or task that launches it:

```powershell
rkhunter --cronjob --rwo --json "$env:USERPROFILE\rkhunter-scheduled-report.json"
```

Only one primary command is accepted per invocation. Scans do not pause between
checks. `--sk` also suppresses the final pause in a newly opened Administrator
window. Unsupported flags fail with an error.
`--versioncheck` fails explicitly because no Windows release feed exists.
The CLI and Windows reports are English; the original translations remain
available as reference.

Edit configuration inside the installation you run. For the default install,
this is `%LOCALAPPDATA%\Programs\rkhunter`; a checkout uses its own files and
state.

Edit `rkhunter.conf`, add `rkhunter.conf.local`, or use sorted
`rkhunter.d/*.conf` files beside it. Overrides load in that order. Values are
literal data; shell/PowerShell expressions are never evaluated. Paths support
`%ENVIRONMENT_VARIABLES%` and resolve relative to the main config file.
Whole-line comments begin with `#`; inline comments are not supported.

`FILE`, `SCAN_DIR` and `ALLOW` can be repeated. An empty assignment clears the
accumulated list. For example:

```ini
# rkhunter.conf.local
FILE=C:/Tools/critical-tool.exe
SCAN_DIR=C:/Tools
MAX_FILES=3000
ALLOW=services|ReviewedServiceName
```

`ALLOW=test|subject-pattern` converts matching **warnings** to `Allowed`;
the original warning and detail remain in the report. It cannot hide errors.
Keep rules narrow. Disabling a test excludes it from the selected tests in
the report; an unsupported selected test produces a `Skipped` result.

`FILE` accepts exact files, without globbing or recursive directory traversal.
The scanner and active configuration/data files are also monitored. Full
`--propupd` replaces the property/account baseline; targeted `--propupd`
updates only matching existing file entries and preserves the account snapshot.
Targets may be an exact path, existing baseline directory, bare filename, or a
comma-separated list. Package-manager names are not supported.

Scan directories are nonrecursive, exclude reparse points, and share the
`MAX_FILES` limit. They are not a whole-disk scan. Autoruns cover HKLM and the
current user, not every loaded or offline user hive. Startup shortcuts are
listed without executing or resolving them. Task COM handlers require manual
review. Protected/inaccessible inventory is recorded as `Skipped` or `Error`.

Default state lives under `var/lib/rkhunter`; logs live under `var/log`.
Protect the installation, configuration, database and reports with appropriate
Windows permissions. The portable tool inherits its destination directory's
ACLs. A baseline that an attacker can rewrite cannot establish integrity.
Logs contain local paths, account names, process information and persistence
commands; review them before sharing.

## Reports and exit codes

Each result has a test, subject, status, original status and explanation. JSON
includes the selected tests, counts, timestamps, elevation status and exit code,
plus a structured `Summary` with the same interpretation shown in the console.

Abbreviated example:

```text
Result: REVIEW NEEDED - warnings were reported
Run: 38 selected checks; Administrator=True. Baseline: Missing.
Windows threat indicators: Empty; Windows threat indicator inspection was skipped.

Warnings grouped for review:
  File/account comparisons have no usable baseline - results: 4; distinct entries: 4
    No usable earlier state is available for comparison. ...
```

The final summary explains the outcome in plain language:

- **REVIEW NEEDED (exit 1):** warnings need context; this is not an infection count.
- **SCAN INCOMPLETE (exit 2):** one or more inspections failed. Read the error
  examples and resolve the affected access/configuration problem.
- **NO WARNINGS REPORTED (exit 0):** the selected checks reported no warnings or
  errors. Skipped inspections and unselected checks remain gaps in coverage.

Warnings are grouped by cause, with counts, up to two distinct examples per group,
explanations and review guidance. Repeated process warnings for the same
executable are combined in the examples; raw results remain intact. Groups
distinguish missing baselines, changed files/accounts, writable locations,
unquoted service paths, missing executables, driver signatures, security settings,
hosts entries, WMI subscriptions and supplied indicator matches.

The summary also lists observed security settings, groups the reasons for skipped
inspections, states whether the run was elevated, and shows baseline and Windows
indicator coverage. Next steps include a command for an elevated rerun when
needed. A baseline command is suggested only when comparisons lack a baseline,
with an explicit instruction to verify the computer before trusting its state.

Counts refer to **result entries**, not distinct tests, infected files or malware
families. `Info` means an observation was recorded; `Allowed` means your own rule
accepted a warning, not that the scanner verified it safe. No warnings are
automatically dismissed as false positives. A file's publisher is not verified
by the summary merely because its path resembles a familiar application.

The detailed summary is saved in the text log even with `--quiet`, `--rwo` or
`--cronjob`; those switches retain their console suppression behavior. The
original one-line counts and exit codes remain available for existing workflows.

| Command | Code | Meaning |
| --- | --- | --- |
| Check | 0 | No warnings or errors; skipped checks can still exist |
| Check | 1 | One or more warnings |
| Check/other | 2 | Inspection, configuration, permission or execution error |
| Update | 0 | No change |
| Update | 1 | Import error |
| Update | 2 | Indicators updated, following the upstream convention |

Normal logs rotate to `.old`; `--appendlog` appends. `--quiet` suppresses console
results, and `--rwo` shows only warnings/errors while retaining the complete log.
`--cronjob` assumes `--check --nocolors`, suppresses console results unless
`--rwo` is present, and never creates a Windows scheduled task.
Scans, property updates and indicator updates share an exclusive database file
handle. Its lock filename can remain after completion; the OS handle is the
lock, so there is no stale-lock removal command. Separate `--dbdir` values do
not coordinate concurrent runs; use the same DB directory for an installation.

## Add or update Windows indicators

See [`docs/indicators.md`](docs/indicators.md). `--update` imports from a trusted
local directory, validates a manifest SHA256 and the indicator schema, and
replaces the active data atomically. It does not download the incompatible
upstream Unix databases or execute update content. A checksum confirms file
consistency; it does not authenticate the source. Review your source yourself.

## Installation options

The checkout is portable. To copy a complete installation to
`%LOCALAPPDATA%\Programs\rkhunter`:

```powershell
.\setup.cmd
# Or choose a destination:
.\setup.cmd --prefix C:\Tools\rkhunter
# Portable copy without registering a command:
.\setup.cmd --prefix C:\Tools\rkhunter --no-path
```

The installer preserves existing configuration, indicator data and baselines;
new defaults are written with `.dist` when necessary. It registers the selected
directory in your **user** PATH, preserving other entries and avoiding duplicate
registration. It does not change the machine PATH, create scheduled tasks or
initialize trust. Use `--no-path` to skip PATH registration. Custom destinations
need write access; protected destinations may require an Administrator terminal.
The original entry point `.\installer.ps1 --install` supports the same options.

For upgrades, run `setup.cmd` from the newer checkout with the same destination.
Review changed program/launcher files before refreshing their baseline.

If `rkhunter` is not found after installation, close/reopen your terminal host,
or refresh the current PowerShell session:

```powershell
$env:Path = "$env:LOCALAPPDATA\Programs\rkhunter;$env:Path"
rkhunter --admin --check
```

You can also run the installed launcher directly from any folder:

```powershell
& "$env:LOCALAPPDATA\Programs\rkhunter\rkhunter.cmd" --admin --check
```

To remove command registration later, remove the installation directory's entry
from **Edit environment variables for your account → Path**. This does not
remove the installed files or saved reports. A clone and an installed copy have
separate state; installing does not migrate a clone's `var` directory.

## Development

Run the automated checks from the repository root:

```powershell
powershell.exe -NoLogo -NoProfile -File .\tests\run.ps1
powershell.exe -NoLogo -NoProfile -File .\tests\integration.ps1
powershell.exe -NoLogo -NoProfile -File .\tests\launchers.ps1
```

Tests use harmless temporary fixtures under ignored `test-results/`, including
hidden files, alternate streams and a directory junction. They do not install
system persistence or change machine security settings. Integration covers the
real launchers, baseline workflow, locking, reports and installer upgrades.
Installation tests use `--no-path`; PATH merging is tested without changing the
real user PATH. Elevation argument forwarding executes a harmless fixture at
current permissions; UAC requests and cancellation are mocked, so automated
tests do not display UAC prompts.
Keep test artifacts for inspection or remove that directory after testing.

The [Windows checks workflow](https://github.com/hussein-chakroun/rkhunter/actions/workflows/windows.yml)
also runs regression tests on Windows PowerShell 5.1 and PowerShell 7.

### Contributing

Issues and pull requests are welcome. For bug reports, include the Windows and
PowerShell versions, the output of `rkhunter --version`, the command used, and
relevant sanitized output. Describe expected and actual behavior. For code
changes, include tests and explain any changes to detection coverage.

Logs can contain usernames, paths, process details, and persistence commands.
**Review and redact reports before posting them publicly.**

## License and attribution

Distributed under **GNU GPL version 2 or later**. See [LICENSE](LICENSE) for the
license text and [NOTICE.md](NOTICE.md) for provenance and modification notices.

The original Rootkit Hunter project is credited to Michael Boelen and its
contributors. Original source, notices, documentation, translations, and
signatures are retained under [`upstream/`](upstream/), with source checksums in
[`upstream/SHA256SUMS.json`](upstream/SHA256SUMS.json). See also the upstream
[acknowledgments](upstream/files/ACKNOWLEDGMENTS) and the
[Windows compatibility guide](docs/compatibility.md).
