# Compatibility with the supplied project

The original shell script, supporting scripts, installer, configuration, manual,
data, ClamAV logical signatures and translations are retained under `upstream/`.
They are reference material and are not executed by the Windows scanner.
`upstream/SHA256SUMS.json` records the supplied source checksums.

The original recognizable test names are all accepted, either as checks or test
groups. `--list tests` shows the exact implementation. Adaptation means a similar
purpose using Windows data; it does not imply equivalent detection coverage.

| Original check/group | Windows mapping |
| --- | --- |
| `properties`, `hashes`, `attributes` | Explicit file baseline with SHA256 and Windows metadata/ACLs |
| `system_commands` | Property checks plus explicitly skipped Unix-specific command tests |
| `running_procs`, `deleted_files` | CIM process executable inventory |
| `known_rkts` | Locally supplied Windows indicators; empty database explicitly skips |
| `loaded_modules`, `avail_modules` | CIM driver inventories and embedded signature inspection of running drivers |
| `os_specific` | Drivers, services, scheduled tasks, WMI persistence |
| `startup_files`, `startup_malware` | Registry and startup folder checks; group also includes tasks and WMI |
| `passwd_changes`, `group_changes` | Local account state and Administrators membership baseline |
| `group_accounts` | Enabled accounts without a required password; does not read password hashes |
| `system_configs` | Windows security settings; Unix SSH/syslog tests separately skip |
| `filesystem` | Bounded hidden-file and ADS checks |
| `ports` | Windows TCP/UDP endpoints compared with the unchanged legacy upstream port list |
| `promisc` | Exposed Windows adapter state |
| `network`, `local_host`, `rootkits`, `malware`, `additional_rkts` | Test groups; see `--list tests` |
| `hidden_procs`, `hidden_ports` | Skipped: no independent kernel/offline view |
| `strings`, `scripts`, `immutable`, `shared_libs`, `shared_libs_path` | Skipped: Unix command, linker, signature and immutable-flag checks |
| `possible_rkt_files`, `possible_rkt_strings`, `trojans`, `suspscan` | Skipped: upstream signatures and artifact rules are platform-specific |
| `login_backdoors`, `sniffer_logs`, `tripwire`, `susp_dirs`, `ipc_shared_mem` | Skipped: original Unix-specific checks |
| `packet_cap_apps`, `apps` | Skipped: upstream application checks and version data target Unix |
| `system_configs_ssh`, `system_configs_syslog` | Skipped: no equivalent Windows configuration coverage implemented |

Additional Windows check names are `services`, `scheduled_tasks`,
`wmi_persistence`, and `hosts`.

Supported commands: `--check`/`-c`, `--propupd`, `--list`,
`--config-check`/`-C`, `--update`, `--version`/`-V`, `--help`/`-h`.
Supported original options include `--enable`, `--disable`, `--configfile`,
`--dbdir`, `--logfile`/`-l`, `--nocolors`, `--appendlog`, `--quiet`/`-q`,
`--cronjob`, `--rwo`/`--report-warnings-only`, and
`--sk`/`--skip-keypress`. The Windows extension `--json` writes a structured
report, `--update-source` selects a reviewed local indicator source, and
`--admin` requests an Administrator window through Windows UAC.

There is no Unix package-manager integration, Perl helper execution, upstream
network updater, ClamAV signature execution, mail sending, or automatic task
creation. `--versioncheck` and unknown options fail explicitly. The OS releases
file locks automatically, so an `--unlock` command is unnecessary and unsupported.
The CLI does not silently emulate unsupported options.

Configuration files keep the `KEY=value` and local override workflow but accept
only the documented Windows keys. The original Unix configuration is preserved
as reference and cannot be used as the Windows configuration.
