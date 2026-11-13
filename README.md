# Rootkit Hunter for Windows

A native Windows adaptation of the supplied Linux/Unix Rootkit Hunter project.
It keeps the command-line scan, property baseline, configuration, warning,
log and test-selection workflow, using PowerShell and Windows APIs.
The original source is preserved in [`upstream/`](upstream/).

**This is a Windows port, not a detection-equivalent replica.** Linux rootkit
paths, kernel interfaces, PAM, shell commands and ELF signatures cannot be
applied to Windows. Unsupported checks explicitly report `Skipped`.
This is a user-mode integrity and heuristic inspection tool, not a kernel
rootkit detector or an antivirus replacement. A compromised kernel can hide
information from every API this tool uses.

## Run

Use 64-bit Windows PowerShell 5.1 (included with Windows 10/11) or PowerShell 7
on Windows. There are no Python, WSL, Bash, Perl, Pester or third-party module
dependencies. Windows Server can run the core checks, but desktop antivirus
registration and some optional cmdlets may be unavailable.

Open a terminal in this repository, preferably **as Administrator** for access
to protected inventories:

```powershell
.\rkhunter.cmd --config-check
.\rkhunter.cmd --check --json .\var\report.json
```

A first scan reports a missing property/account baseline. After independently
verifying the computer, explicitly create one, then scan again:

```powershell
.\rkhunter.cmd --propupd
.\rkhunter.cmd --check --sk
```

`--propupd` trusts the current state. Do not use it to make unexplained changes
disappear. The scanner never creates a baseline automatically and never deletes
malware, stops processes, changes security settings or starts an antivirus scan.
Scan writes are limited to its database lock, text log and optional JSON report.
Baselines, imports and installation write their explicitly selected destinations.

The PowerShell entry point also accepts the same arguments:

```powershell
.\rkhunter.ps1 --check --enable system_commands,network --nocolors
```

PowerShell execution policy still applies. If a downloaded checkout is blocked,
review it and follow your organization's script signing/unblocking policy. The
launchers do not bypass execution policy or request elevation automatically.

## What it inspects

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

The bundled Windows indicator database is intentionally **empty**. There is no
invented Windows rootkit-family coverage, active vendor signature feed, CVE
scanner, offline image scan, hidden process/port detector, or malware removal.
`known_rkts` reports `Skipped` until you supply verified indicators.

## Commands and configuration

```powershell
.\rkhunter.cmd --help
.\rkhunter.cmd --list tests
.\rkhunter.cmd --list propfiles
.\rkhunter.cmd --check --enable properties,ports --disable attributes
.\rkhunter.cmd --cronjob --rwo --json .\var\scheduled-report.json
.\rkhunter.cmd --propupd cmd.exe
```

Only one primary command is accepted per invocation. `--sk` is accepted for
compatibility; this port never pauses. Unsupported flags fail with an error.
`--versioncheck` fails explicitly because no Windows release feed exists.
The CLI and Windows reports are English; the original translations remain
available as reference.

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
includes the selected tests, counts, timestamps, elevation status and exit code.

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

## Optional installation

The checkout is portable. To copy a complete installation to
`%LOCALAPPDATA%\Programs\rkhunter`:

```powershell
.\installer.ps1 --install
# Or choose a destination:
.\installer.ps1 --install --prefix C:\Tools\rkhunter
```

The installer preserves existing configuration, indicator data and baselines;
new defaults are written with `.dist` when necessary. It does not modify PATH,
create scheduled tasks or initialize trust. Review changed program files before
refreshing their baseline after an upgrade.

## Verify

```powershell
powershell.exe -NoLogo -NoProfile -File .\tests\run.ps1
powershell.exe -NoLogo -NoProfile -File .\tests\integration.ps1
```

Tests use harmless temporary fixtures under ignored `test-results/`, including
hidden files, alternate streams and a directory junction. They do not install
system persistence or change machine security settings. Integration covers the
real launchers, baseline workflow, locking, reports and installer upgrades.
Keep test artifacts for inspection or remove that directory after testing.

For the upstream-to-Windows mapping, see
[`docs/compatibility.md`](docs/compatibility.md). Upstream attribution and
modifications are recorded in [`NOTICE.md`](NOTICE.md); GPL terms are in
[`LICENSE`](LICENSE).
