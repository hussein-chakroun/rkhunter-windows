# SPDX-License-Identifier: GPL-2.0-or-later
# Native Windows adaptation of Rootkit Hunter. See upstream/files/LICENSE.
$script:RkhVersion = '1.0.0-windows'
$script:RkhTests = [ordered]@{
    hashes = 'SHA256 file integrity against an explicit trusted baseline'
    attributes = 'File size, timestamps, attributes, owner and DACL changes'
    known_rkts = 'Locally supplied Windows SHA256 and exact-path indicators'
    running_procs = 'Process executable locations and Windows name masquerading'
    deleted_files = 'Running processes whose reported executable is missing'
    services = 'Service image paths, unquoted paths and writable locations'
    startup_malware = 'Registry autoruns, Winlogon, IFEO, AppInit and startup folders'
    scheduled_tasks = 'Scheduled task executable and argument inspection'
    wmi_persistence = 'Permanent WMI event consumers and bindings'
    loaded_modules = 'Running kernel drivers and embedded Authenticode signatures'
    avail_modules = 'Installed kernel driver image paths'
    ports = 'TCP listeners and UDP endpoints matching upstream legacy port indicators'
    promisc = 'Network adapter promiscuous-mode status when exposed by Windows'
    passwd_changes = 'Local account inventory changes against baseline'
    group_changes = 'Local Administrators membership changes against baseline'
    group_accounts = 'Enabled local accounts with no required password'
    system_configs = 'Defender/antivirus, firewall, UAC, Secure Boot and test signing'
    filesystem = 'Hidden executable files and alternate data streams in configured directories'
    hosts = 'Unexpected hosts-file redirects'
    hidden_procs = 'UNSUPPORTED: requires an independent kernel/offline view'
    hidden_ports = 'UNSUPPORTED: requires an independent kernel/offline view'
    strings = 'UNSUPPORTED: upstream string signatures target Unix binaries'
    scripts = 'UNSUPPORTED: upstream script replacement tests target Unix commands'
    immutable = 'UNSUPPORTED: Unix immutable flags do not map to Windows attributes'
    shared_libs_path = 'UNSUPPORTED: Unix dynamic linker search path checks'
    possible_rkt_files = 'UNSUPPORTED: upstream Unix rootkit file paths'
    possible_rkt_strings = 'UNSUPPORTED: upstream Unix rootkit string signatures'
    trojans = 'UNSUPPORTED: upstream Unix command-specific trojan checks'
    suspscan = 'UNSUPPORTED: upstream Unix suspicious-string database'
    login_backdoors = 'UNSUPPORTED: upstream Unix login/PAM checks'
    sniffer_logs = 'UNSUPPORTED: upstream Unix sniffer log filenames'
    tripwire = 'UNSUPPORTED: upstream Tripwire checks'
    susp_dirs = 'UNSUPPORTED: upstream Unix suspicious directories'
    ipc_shared_mem = 'UNSUPPORTED: upstream Unix shared memory checks'
    packet_cap_apps = 'UNSUPPORTED: upstream Unix packet capture application checks'
    apps = 'UNSUPPORTED: upstream obsolete Unix application version database'
    system_configs_ssh = 'UNSUPPORTED: upstream Unix SSH configuration checks'
    system_configs_syslog = 'UNSUPPORTED: upstream Unix syslog configuration checks'
}
$script:RkhGroups = @{
    properties = @('hashes','attributes')
    system_commands = @('properties','strings','scripts','immutable','shared_libs')
    shared_libs = @('shared_libs_path')
    additional_rkts = @('possible_rkt_files','possible_rkt_strings')
    rootkits = @('known_rkts','additional_rkts','malware','trojans','os_specific')
    malware = @('running_procs','hidden_procs','deleted_files','suspscan','login_backdoors','sniffer_logs','tripwire','susp_dirs','ipc_shared_mem')
    os_specific = @('loaded_modules','avail_modules','services','scheduled_tasks','wmi_persistence')
    network = @('ports','hidden_ports','promisc','packet_cap_apps')
    startup_files = @('startup_malware','scheduled_tasks','wmi_persistence')
    local_host = @('startup_files','passwd_changes','group_changes','group_accounts','system_configs','filesystem','hosts','system_configs_ssh','system_configs_syslog')
}

function Get-RkhHelp {
    @'
Rootkit Hunter for Windows
Usage: rkhunter {--check | --propupd [file,...] | --list [tests|rootkits|propfiles|languages]
                 | --config-check | --update | --version | --help} [options]

  -c, --check              Perform a read-only Windows inspection
      --admin             Request an Administrator window through Windows UAC
      --propupd [files]    Explicitly trust current files and account state
  -C, --config-check       Validate configuration, test selection and indicator data
      --list tests        List supported, adapted and unsupported checks
      --update            Import indicators from an explicitly configured local source
      --update-source DIR Source containing windows-indicators.json and manifest.json
      --configfile FILE   Use a different configuration file
      --dbdir DIR         Override the baseline database directory
  -l, --logfile FILE      Override the text log destination
      --json FILE         Also write a structured JSON scan report
      --enable LIST       Comma/space separated tests or groups (default: all)
      --disable LIST      Comma/space separated tests or groups (default: none)
      --rwo               Display warnings/errors only (full log is still written)
      --cronjob           Check quietly; use --rwo to print warnings
      --nocolors          Plain console output
      --sk, --skip-keypress  Do not pause the new Administrator window at exit
      --appendlog         Append instead of rotating the previous log to .old
  -q, --quiet             Suppress console results
  -V, --version           Show Windows port version
  -h, --help              Show this help

Check exit codes: 0=no warnings/errors (review skipped checks), 1=warnings, 2=error.
Update exit codes: 0=unchanged, 1=import error, 2=updated (upstream convention).
Linux-only checks report Skipped. No malware is removed or quarantined.
'@
}

function ConvertTo-RkhList([string]$Value) {
    @($Value -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
}

function Get-RkhOptions([string[]]$Arguments) {
    $opt = @{ Command = ''; List = 'tests'; Targets = @(); Quiet = $false; Rwo = $false; Cron = $false; NoColors = $false; Append = $false }
    $values = @{ '--configfile'='ConfigFile'; '--dbdir'='DbDir'; '--logfile'='LogFile'; '-l'='LogFile'; '--json'='Json'; '--enable'='Enable'; '--disable'='Disable'; '--update-source'='UpdateSource' }
    $commands = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($pair in @('--check|check','-c|check','--propupd|propupd','--config-check|config-check','-C|config-check','--list|list','--update|update','--version|version','-V|version','--help|help','-h|help')) {
        $parts = $pair -split '\|'; $commands.Add($parts[0], $parts[1])
    }
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $arg = $Arguments[$i]
        if ($values.ContainsKey($arg)) {
            $i++
            if ($i -ge $Arguments.Count -or $Arguments[$i] -match '^--') { throw "Missing value for $arg" }
            $opt[$values[$arg]] = $Arguments[$i]
        } elseif ($commands.ContainsKey($arg)) {
            $cmd = $commands[$arg]
            if ($opt.Command -and $opt.Command -ne $cmd) { throw 'Choose exactly one command per invocation.' }
            $opt.Command = $cmd
            if ($cmd -eq 'list' -and $i + 1 -lt $Arguments.Count -and $Arguments[$i+1] -notmatch '^-') { $i++; $opt.List = $Arguments[$i] }
            if ($cmd -eq 'propupd' -and $i + 1 -lt $Arguments.Count -and $Arguments[$i+1] -notmatch '^-') { $i++; $opt.Targets = @($Arguments[$i] -split ',') }
        } else {
            switch -CaseSensitive ($arg) {
                '--cronjob' { $opt.Cron = $true; $opt.NoColors = $true }
                '--rwo' { $opt.Rwo = $true }
                '--report-warnings-only' { $opt.Rwo = $true }
                '--nocolors' { $opt.NoColors = $true }
                '--quiet' { $opt.Quiet = $true }
                '-q' { $opt.Quiet = $true }
                '--appendlog' { $opt.Append = $true }
                '--sk' { }
                '--skip-keypress' { }
                '--versioncheck' { throw 'No Windows release feed is configured. --version shows the installed port version; Unix releases cannot update this port.' }
                default { throw "Unknown or unsupported option: $arg. Use --help." }
            }
        }
    }
    if ($opt.Cron) {
        if ($opt.Command -and $opt.Command -ne 'check') { throw '--cronjob requires --check.' }
        $opt.Command = 'check'
    }
    if (-not $opt.Command) { $opt.Command = 'help' }
    return $opt
}

function Resolve-RkhPath([string]$Path, [string]$Base) {
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -match '%[^%]+%') { throw "Unresolved environment variable in path: $Path" }
    if (-not [IO.Path]::IsPathRooted($expanded)) { $expanded = Join-Path $Base $expanded }
    return [IO.Path]::GetFullPath($expanded)
}

function Read-RkhConfig([string]$Path) {
    $base = Split-Path -Parent $Path
    $cfg = @{ DBDIR='var/lib/rkhunter'; LOGFILE='var/log/rkhunter.log'; ENABLE_TESTS='all'; DISABLE_TESTS='none'; FILE=@(); SCAN_DIR=@(); ALLOW=@(); MAX_FILES='3000'; CHECK_SIGNATURES='1'; UPDATE_SOURCE=''; ConfigFiles=@() }
    $files = @($Path)
    if (Test-Path -LiteralPath "$Path.local") { $files += "$Path.local" }
    $dropin = Join-Path $base 'rkhunter.d'
    if (Test-Path -LiteralPath $dropin) { $files += @(Get-ChildItem -LiteralPath $dropin -Filter '*.conf' -File | Sort-Object Name | ForEach-Object { $_.FullName }) }
    foreach ($file in $files) {
        $lineNo = 0
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            $lineNo++
            if ($line -match '^\s*(#|$)') { continue }
            if ($line -notmatch '^\s*([A-Z_]+)\s*=\s*(.*?)\s*$') { throw "Invalid configuration at ${file}:$lineNo" }
            $key = $Matches[1]; $value = $Matches[2]
            if (-not $cfg.ContainsKey($key) -or $key -eq 'ConfigFiles') { throw "Unknown configuration option $key at ${file}:$lineNo" }
            if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) { $value = $value.Substring(1, $value.Length-2) }
            if ($key -in @('FILE','SCAN_DIR','ALLOW')) {
                if ($value -eq '') { $cfg[$key] = @() } else { $cfg[$key] += $value }
            } else { $cfg[$key] = $value }
        }
        $cfg.ConfigFiles += $file
    }
    if ($cfg.MAX_FILES -notmatch '^\d+$' -or [long]$cfg.MAX_FILES -lt 1 -or [long]$cfg.MAX_FILES -gt 100000) { throw 'MAX_FILES must be between 1 and 100000.' }
    if ($cfg.CHECK_SIGNATURES -notin @('0','1')) { throw 'CHECK_SIGNATURES must be 0 or 1.' }
    foreach ($rule in $cfg.ALLOW) {
        if ($rule -notmatch '^[a-z_]+\|.+$') { throw "Invalid ALLOW rule: $rule (expected test|subject-pattern)" }
        try { $null = [System.Management.Automation.WildcardPattern]::new(($rule -split '\|',2)[1], 'IgnoreCase') } catch { throw "Invalid ALLOW wildcard: $rule" }
    }
    foreach ($key in @('DBDIR','LOGFILE')) { $cfg[$key] = Resolve-RkhPath $cfg[$key] $base }
    foreach ($key in @('FILE','SCAN_DIR')) { $cfg[$key] = @($cfg[$key] | ForEach-Object { Resolve-RkhPath $_ $base } | Select-Object -Unique) }
    if ($cfg.UPDATE_SOURCE) { $cfg.UPDATE_SOURCE = Resolve-RkhPath $cfg.UPDATE_SOURCE $base }
    return $cfg
}

function Expand-RkhTests([string[]]$Names) {
    $result = @()
    foreach ($name in $Names) {
        if ($name -eq 'all') { $result += @($script:RkhTests.Keys) }
        elseif ($name -eq 'none') { continue }
        elseif ($script:RkhGroups.ContainsKey($name)) { $result += @(Expand-RkhTests $script:RkhGroups[$name]) }
        elseif ($script:RkhTests.Contains($name)) { $result += $name }
        else { throw "Unknown test or test group: $name" }
    }
    return @($result | Select-Object -Unique)
}

function Get-RkhSelectedTests($Config, $Options) {
    $enable = $Config.ENABLE_TESTS; $disable = $Config.DISABLE_TESTS
    if ($Options.ContainsKey('Enable')) { $enable = $Options.Enable }
    if ($Options.ContainsKey('Disable')) { $disable = $Options.Disable }
    $enabled = @(Expand-RkhTests (ConvertTo-RkhList $enable))
    $disabled = @(Expand-RkhTests (ConvertTo-RkhList $disable))
    return @($script:RkhTests.Keys | Where-Object { $_ -in $enabled -and $_ -notin $disabled })
}

function Write-RkhAtomicJson([string]$Path, $Value) {
    $parent = Split-Path -Parent $Path
    $null = [IO.Directory]::CreateDirectory($parent)
    $temp = Join-Path $parent ([IO.Path]::GetRandomFileName() + '.tmp')
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
        Move-RkhAtomicFile $temp $Path
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

function Move-RkhAtomicFile([string]$Source, [string]$Destination) {
    # Windows security/indexing software can hold a short-lived handle without
    # FILE_SHARE_DELETE. Retry the same atomic operation; never delete first.
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        try {
            if ([IO.File]::Exists($Destination)) { [IO.File]::Replace($Source, $Destination, [System.Management.Automation.Language.NullString]::Value) }
            else { [IO.File]::Move($Source, $Destination) }
            return
        } catch {
            $errorCode = $_.Exception.GetBaseException().HResult -band 0xffff
            if ($attempt -eq 5 -or $errorCode -notin @(32,33,1175,1176,1177)) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Read-RkhIndicators([string]$Path) {
    $data = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($data.schemaVersion -ne 1 -or -not $data.version -or $null -eq $data.sha256 -or $null -eq $data.paths) { throw 'Invalid Windows indicator schema.' }
    if ($data.sha256 -isnot [array] -or $data.paths -isnot [array]) { throw 'Indicator sha256 and paths must be arrays.' }
    foreach ($item in $data.sha256) {
        if ($item.hash -notmatch '^[a-fA-F0-9]{64}$' -or -not $item.name) { throw 'Each SHA256 indicator requires a 64-character hash and name.' }
    }
    foreach ($item in $data.paths) {
        if (-not $item.path -or -not $item.name -or $item.path -match '[*?]') { throw 'Each path indicator requires an exact path and name; wildcards are not accepted.' }
        $expanded = [Environment]::ExpandEnvironmentVariables($item.path)
        if (-not [IO.Path]::IsPathRooted($expanded) -or $expanded -match '%[^%]+%') { throw "Indicator path must resolve to an absolute path: $($item.path)" }
    }
    return $data
}

function Test-RkhReparsePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $false
}

function Get-RkhFileRecord([string]$Path) {
    if (Test-RkhReparsePath $Path) { throw "Refusing to baseline a reparse point: $Path" }
    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($file.PSIsContainer) { throw "Expected a file: $Path" }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sizeBefore = $file.Length; $writeBefore = $file.LastWriteTimeUtc
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $file.Refresh()
    if ($file.Length -ne $sizeBefore -or $file.LastWriteTimeUtc -ne $writeBefore) { throw "File changed during hashing; retry when it is stable: $Path" }
    [pscustomobject][ordered]@{ Path=$file.FullName; Sha256=$hash; Length=$file.Length; LastWriteUtc=$file.LastWriteTimeUtc.ToString('o'); Attributes=[int]$file.Attributes; Owner=$acl.Owner; Sddl=$acl.Sddl }
}

function Get-RkhPropertyFiles($Context) {
    @(@($Context.Config.FILE) + @($Context.Config.ConfigFiles) + @(
        (Join-Path $Context.Root 'rkhunter.ps1'), (Join-Path $Context.Root 'rkhunter.cmd'),
        (Join-Path $Context.Root 'rkhunter-admin.cmd'), (Join-Path $Context.Root 'setup.cmd'),
        (Join-Path $Context.Root 'installer.ps1'), (Join-Path $Context.Root 'src\Rkhunter.psm1'),
        (Join-Path $Context.Root 'src\Rkhunter.Launcher.psm1'), (Join-Path $Context.Root 'src\Rkhunter.Install.psm1'),
        (Join-Path $Context.Root 'data\windows-indicators.json'), (Join-Path $Context.Root 'data\backdoorports.dat')
    ) | Sort-Object -Unique)
}

function Read-RkhBaseline($Context) {
    $path = Join-Path $Context.Config.DBDIR 'rkhunter.dat.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $value = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($value.SchemaVersion -ne 1 -or $value.Machine -ne [Environment]::MachineName -or $value.Files -isnot [array] -or $value.Accounts -isnot [array] -or $value.Administrators -isnot [array]) { throw 'Invalid baseline schema or baseline belongs to another computer.' }
    $seen = @{}
    foreach ($file in $value.Files) {
        if (-not $file.Path -or -not [IO.Path]::IsPathRooted($file.Path) -or $file.Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $null -eq $file.Length -or -not $file.Sddl) { throw 'Invalid file entry in baseline.' }
        if ($seen.ContainsKey($file.Path)) { throw 'Duplicate file entry in baseline.' }
        $seen[$file.Path] = $true
    }
    return $value
}

function Add-RkhResult($Context, [string]$Test, [string]$Subject, [string]$Status, [string]$Detail) {
    $original = $Status
    if ($Status -eq 'Warning') {
        foreach ($rule in $Context.Config.ALLOW) {
            $parts = $rule -split '\|',2
            if ($parts[0] -eq $Test -and $Subject -like $parts[1]) { $Status = 'Allowed'; break }
        }
    }
    $Context.Results.Add([pscustomobject][ordered]@{ Test=$Test; Subject=$Subject; Status=$Status; OriginalStatus=$original; Detail=$Detail })
    $line = ('  {0,-18} {1} [ {2} ] {3}' -f $Test, $Subject, $Status, $Detail)
    if ($Context.Log) { $Context.Log.WriteLine(('[{0}] {1}' -f [DateTime]::UtcNow.ToString('o'), $line)); $Context.Log.Flush() }
    $opt = $Context.Options
    if ($opt.Quiet -or ($opt.Cron -and -not $opt.Rwo) -or ($opt.Rwo -and $Status -notin @('Warning','Error'))) { return }
    if ($opt.NoColors) { Write-Host $line }
    else {
        $color = switch ($Status) { 'Warning' { 'Red' } 'Error' { 'Red' } 'Skipped' { 'Yellow' } 'Allowed' { 'Cyan' } default { 'Green' } }
        Write-Host $line -ForegroundColor $color
    }
}

function Get-RkhInventory($Context, [string]$Key, [scriptblock]$Collect) {
    if (-not $Context.Cache.ContainsKey($Key)) { $Context.Cache[$Key] = @(& $Collect) }
    return $Context.Cache[$Key]
}

function Get-RkhAccounts {
    @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Sort-Object SID | ForEach-Object {
        [pscustomobject]@{ Sid=$_.SID; Name=$_.Name; Disabled=[bool]$_.Disabled; PasswordRequired=[bool]$_.PasswordRequired; Lockout=[bool]$_.Lockout }
    })
}

function Get-RkhAdministrators {
    # SID is independent of the Windows display language.
    $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    @(Get-LocalGroupMember -Group $group -ErrorAction Stop | Sort-Object SID | ForEach-Object { '{0}|{1}' -f $_.SID.Value,$_.Name })
}

function Update-RkhBaseline($Context) {
    $previous = Read-RkhBaseline $Context
    $files = @(Get-RkhPropertyFiles $Context)
    $targets = $Context.Options.Targets
    if ($targets.Count -gt 0) {
        if (-not $previous) { throw 'Create a complete baseline with --propupd before updating individual entries.' }
        $selected = @()
        foreach ($target in $targets) {
            if ([IO.Path]::IsPathRooted($target)) { $target = [IO.Path]::GetFullPath($target) }
            $matches = @($previous.Files | Where-Object {
                $_.Path -eq $target -or [IO.Path]::GetFileName($_.Path) -eq $target -or $_.Path.StartsWith($target.TrimEnd('\','/') + '\', [StringComparison]::OrdinalIgnoreCase)
            } | ForEach-Object { $_.Path })
            if ($matches.Count -eq 0) { throw "Target is not in the baseline: $target" }
            $selected += $matches
        }
        $files = @($selected | Sort-Object -Unique)
    }
    Write-Host 'Trusting current properties. Only baseline a system you have independently verified.'
    $records = @($files | ForEach-Object { Get-RkhFileRecord $_ })
    if ($targets.Count -gt 0) {
        $records += @($previous.Files | Where-Object { $_.Path -notin $files })
        $accounts = @($previous.Accounts); $admins = @($previous.Administrators)
    } else {
        # A failed inventory aborts the transaction rather than recording an empty trusted state.
        $accounts = @(Get-RkhAccounts); $admins = @(Get-RkhAdministrators)
    }
    $baseline = [ordered]@{ SchemaVersion=1; Machine=[Environment]::MachineName; CreatedUtc=[DateTime]::UtcNow.ToString('o'); Version=$script:RkhVersion; Files=@($records | Sort-Object Path); Accounts=$accounts; Administrators=$admins }
    Write-RkhAtomicJson (Join-Path $Context.Config.DBDIR 'rkhunter.dat.json') $baseline
    Write-Host ("Properties stored: {0} files. Database: {1}" -f $records.Count,$Context.Config.DBDIR)
}

function Invoke-RkhProperties($Context, [string]$Test) {
    $baseline = $Context.Baseline
    if (-not $baseline) { Add-RkhResult $Context $Test 'Property database' 'Warning' 'Missing baseline; verify this computer, then run --propupd.'; return }
    $expected = @(Get-RkhPropertyFiles $Context)
    foreach ($path in $expected) {
        if ($path -notin @($baseline.Files.Path)) { Add-RkhResult $Context $Test $path 'Warning' 'Configured file is not in the baseline.' }
    }
    foreach ($old in $baseline.Files) {
        try {
            if (-not $Context.Cache.ContainsKey('file:' + $old.Path)) { $Context.Cache['file:' + $old.Path] = Get-RkhFileRecord $old.Path }
            $now = $Context.Cache['file:' + $old.Path]
            $fields = if ($Test -eq 'hashes') { @('Sha256') } else { @('Length','LastWriteUtc','Attributes','Owner','Sddl') }
            $changed = @($fields | Where-Object { $old.$_ -cne $now.$_ })
            if ($changed.Count) { Add-RkhResult $Context $Test $old.Path 'Warning' ('Changed: ' + ($changed -join ', ') + '. Updates can also cause this; investigate before trusting again.') }
            else { Add-RkhResult $Context $Test $old.Path 'OK' 'Matches baseline.' }
        } catch { Add-RkhResult $Context $Test $old.Path 'Error' $_.Exception.Message }
    }
}

function Get-RkhScanFiles($Context) {
    Get-RkhInventory $Context 'scanfiles' {
        $files = [Collections.Generic.List[object]]::new()
        $seen = @{}
        foreach ($dir in $Context.Config.SCAN_DIR) {
            if (-not (Test-Path -LiteralPath $dir)) { Add-RkhResult $Context 'filesystem' $dir 'Skipped' 'Configured directory does not exist.'; continue }
            if (Test-RkhReparsePath $dir) { Add-RkhResult $Context 'filesystem' $dir 'Skipped' 'Reparse-point directory excluded.'; continue }
            try {
                foreach ($item in Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction Stop) {
                    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if ($seen.ContainsKey($item.FullName)) { continue }
                    if ($files.Count -ge [int]$Context.Config.MAX_FILES) { Add-RkhResult $Context 'filesystem' 'Scan limit' 'Skipped' 'MAX_FILES reached; remaining files were not inspected.'; return $files.ToArray() }
                    $seen[$item.FullName] = $true; $files.Add($item)
                }
            } catch { Add-RkhResult $Context 'filesystem' $dir 'Error' $_.Exception.Message }
        }
        $files.ToArray()
    }
}

function Invoke-RkhIndicators($Context) {
    $data = $Context.Indicators
    if ($data.sha256.Count -eq 0 -and $data.paths.Count -eq 0) {
        Add-RkhResult $Context 'known_rkts' 'Windows indicator database' 'Skipped' 'No Windows indicators supplied. The bundled upstream signatures target Unix and are not used.'; return
    }
    foreach ($entry in $data.paths) {
        $path = [Environment]::ExpandEnvironmentVariables($entry.path)
        if (Test-Path -LiteralPath $path -ErrorAction Stop) { Add-RkhResult $Context 'known_rkts' $path 'Warning' ('Path indicator: ' + $entry.name + '. Filename alone is not proof of infection.') }
        else { Add-RkhResult $Context 'known_rkts' $path 'OK' ('Not found: ' + $entry.name) }
    }
    if ($data.sha256.Count) {
        $paths = @(@(Get-RkhScanFiles $Context | ForEach-Object { $_.FullName }) + @(Get-RkhPropertyFiles $Context) | Select-Object -Unique)
        $index = @{}; foreach ($entry in $data.sha256) { $index[$entry.hash] = $entry.name }
        $count = 0
        foreach ($path in $paths) {
            try {
                if (Test-RkhReparsePath $path) { Add-RkhResult $Context 'known_rkts' $path 'Skipped' 'Reparse-point file excluded.'; continue }
                $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                $count++
                if ($index.ContainsKey($hash)) { Add-RkhResult $Context 'known_rkts' $path 'Warning' ('SHA256 indicator match: ' + $index[$hash]) }
            } catch { Add-RkhResult $Context 'known_rkts' $path 'Error' $_.Exception.Message }
        }
        Add-RkhResult $Context 'known_rkts' 'Hash inspection' 'Info' ("Inspected $count configured and bounded scan files against $($data.sha256.Count) indicators.")
    }
}

function Resolve-RkhImage([string]$CommandLine) {
    $value = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    $value = $value -replace '^\\\?\?\\',''
    $value = $value -replace '^\\SystemRoot(?=\\)', $env:SystemRoot
    if ($value -match '^"([^"]+)"') { return $Matches[1] }
    if ($value -match '^(.*?\.(?:exe|com|sys|dll))(?=\s|$)') { return $Matches[1] }
    if ($value -match '^(\S+)') { return $Matches[1] }
    return ''
}

function Test-RkhRiskyPath([string]$Path) {
    $Path = [IO.Path]::GetFullPath($Path)
    $roots = @($env:TEMP, $env:TMP, $env:APPDATA, $env:LOCALAPPDATA, (Join-Path $env:SystemRoot 'Temp'), (Join-Path $env:PUBLIC 'Downloads'))
    foreach ($root in $roots) {
        if ($root -and ($Path -eq $root -or $Path.StartsWith($root.TrimEnd('\','/') + '\', [StringComparison]::OrdinalIgnoreCase))) { return $true }
    }
    return $Path -match '(?i)\\Users\\[^\\]+\\(?:AppData|Downloads|Desktop)\\'
}

function Test-RkhImage($Context, [string]$Test, [string]$Subject, [string]$CommandLine, [switch]$Driver) {
    $image = Resolve-RkhImage $CommandLine
    if (-not $image) { Add-RkhResult $Context $Test $Subject 'Skipped' 'No executable path exposed.'; return }
    if ($Driver -and $image -match '^(?i)System32\\') { $image = Join-Path $env:SystemRoot $image }
    if (-not [IO.Path]::IsPathRooted($image)) { Add-RkhResult $Context $Test $Subject 'Skipped' ("Relative executable requires manual resolution: $image"); return }
    if (Test-RkhRiskyPath $image) { Add-RkhResult $Context $Test $Subject 'Warning' ("Executable in a commonly writable location: $image") }
    if (-not (Test-Path -LiteralPath $image -PathType Leaf -ErrorAction Stop)) { Add-RkhResult $Context $Test $Subject 'Warning' ("Executable not found: $image"); return }
    if ($Driver -and $Context.Config.CHECK_SIGNATURES -eq '1') {
        $sig = Get-AuthenticodeSignature -LiteralPath $image -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { Add-RkhResult $Context $Test $Subject 'OK' ("Valid embedded Authenticode signature: $image") }
        elseif ($sig.Status -eq 'NotSigned') { Add-RkhResult $Context $Test $Subject 'Warning' ("No embedded Authenticode signature: $image. A catalog signature may exist; verify with Windows driver tools.") }
        else { Add-RkhResult $Context $Test $Subject 'Warning' ("Authenticode status $($sig.Status): $image. $($sig.StatusMessage)") }
    } else { Add-RkhResult $Context $Test $Subject 'Info' $CommandLine }
}

function Invoke-RkhProcesses($Context, [string]$Test) {
    $items = @(Get-RkhInventory $Context 'processes' { Get-CimInstance Win32_Process -ErrorAction Stop })
    $unavailable = 0
    foreach ($item in $items) {
        $subject = '{0} (PID {1})' -f $item.Name,$item.ProcessId
        $path = [string]$item.ExecutablePath
        if (-not $path) { $unavailable++; continue }
        if ($Test -eq 'deleted_files') {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) { Add-RkhResult $Context $Test $subject 'Warning' ("Executable no longer exists: $path. Process exit/update races are possible.") }
        } else {
            if (Test-RkhRiskyPath $path) { Add-RkhResult $Context $Test $subject 'Warning' ("Running from a commonly writable location: $path") }
            if ($item.Name -in @('lsass.exe','services.exe','winlogon.exe','csrss.exe','smss.exe','svchost.exe')) {
                $expected = @((Join-Path $env:SystemRoot ('System32\' + $item.Name)), (Join-Path $env:SystemRoot ('SysWOW64\' + $item.Name)))
                if ($path -notin $expected) { Add-RkhResult $Context $Test $subject 'Warning' ("Windows system process name outside expected system directories: $path") }
            }
        }
    }
    Add-RkhResult $Context $Test 'Process inventory' 'Info' ("Inspected $($items.Count - $unavailable) exposed executable paths.")
    if ($unavailable) { Add-RkhResult $Context $Test 'Protected or exited processes' 'Skipped' ("$unavailable executable paths unavailable; elevation cannot expose every protected process.") }
}

function Invoke-RkhServices($Context, [string]$Test) {
    $drivers = $Test -in @('loaded_modules','avail_modules')
    $key = if ($drivers) { 'drivers' } else { 'services' }
    $class = if ($drivers) { 'Win32_SystemDriver' } else { 'Win32_Service' }
    $items = @(Get-RkhInventory $Context $key { Get-CimInstance -ClassName $class -ErrorAction Stop })
    if ($Test -eq 'loaded_modules') { $items = @($items | Where-Object { $_.State -eq 'Running' }) }
    if ($Test -eq 'loaded_modules' -and $Context.Config.CHECK_SIGNATURES -eq '0') { Add-RkhResult $Context $Test 'Driver signatures' 'Skipped' 'Signature inspection disabled in configuration.' }
    foreach ($item in $items) {
        try {
            $command = [string]$item.PathName
            $image = Resolve-RkhImage $command
            if (-not $drivers -and -not $command.TrimStart().StartsWith('"') -and $image -match '\s') { Add-RkhResult $Context $Test $item.Name 'Warning' ("Unquoted service executable path contains spaces: $command. Exploitability depends on directory permissions.") }
            Test-RkhImage $Context $Test $item.Name $command -Driver:($Test -eq 'loaded_modules')
        } catch { Add-RkhResult $Context $Test $item.Name 'Error' $_.Exception.Message }
    }
    Add-RkhResult $Context $Test 'Inventory' 'Info' ("Inspected $($items.Count) entries using $class; kernel hooks and hidden drivers cannot be excluded by this inventory.")
}

function Get-RkhAutoruns($Context) {
    $locations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($location in $locations) {
        try {
            if (-not (Test-Path -LiteralPath $location -ErrorAction Stop)) { continue }
            $key = Get-Item -LiteralPath $location -ErrorAction Stop
            foreach ($name in $key.GetValueNames()) { [pscustomobject]@{ Subject="$location\$name"; Command=[string]$key.GetValue($name); Kind='Run' } }
        } catch { Add-RkhResult $Context 'startup_malware' $location 'Error' $_.Exception.Message }
    }
    $special = @(
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Names=@('Shell','Userinit'); Kind='Winlogon' },
        @{ Key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Names=@('AppInit_DLLs'); Kind='AppInit' },
        @{ Key='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'; Names=@('AppInit_DLLs'); Kind='AppInit' }
    )
    foreach ($entry in $special) {
        try {
            if (-not (Test-Path -LiteralPath $entry.Key -ErrorAction Stop)) { continue }
            $key = Get-Item -LiteralPath $entry.Key -ErrorAction Stop
            foreach ($name in $entry.Names) {
                $value = [string]$key.GetValue($name)
                if ($value) { [pscustomobject]@{ Subject=($entry.Key + '\' + $name); Command=$value; Kind=$entry.Kind; Name=$name } }
            }
        } catch { Add-RkhResult $Context 'startup_malware' $entry.Key 'Error' $_.Exception.Message }
    }
    foreach ($location in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            if (-not (Test-Path -LiteralPath $location -ErrorAction Stop)) { continue }
            foreach ($key in Get-ChildItem -LiteralPath $location -ErrorAction Stop) {
                try {
                    $value = [string]$key.GetValue('Debugger')
                    if ($value) { [pscustomobject]@{ Subject=($key.Name + '\Debugger'); Command=$value; Kind='IFEO' } }
                } catch { Add-RkhResult $Context 'startup_malware' $key.Name 'Error' $_.Exception.Message }
            }
        } catch { Add-RkhResult $Context 'startup_malware' $location 'Error' $_.Exception.Message }
    }
}

function Invoke-RkhStartup($Context) {
    foreach ($item in @(Get-RkhAutoruns $Context)) {
        if ($item.Kind -eq 'IFEO' -or $item.Kind -eq 'AppInit') { Add-RkhResult $Context 'startup_malware' $item.Subject 'Warning' ("$($item.Kind) persistence/debugging configuration: $($item.Command)"); continue }
        if ($item.Kind -eq 'Winlogon') {
            $expected = if ($item.Name -eq 'Shell') { 'explorer.exe' } else { (Join-Path $env:SystemRoot 'system32\userinit.exe') + ',' }
            if ($item.Command -ne $expected) { Add-RkhResult $Context 'startup_malware' $item.Subject 'Warning' ("Non-default Winlogon value: $($item.Command)") }
            else { Add-RkhResult $Context 'startup_malware' $item.Subject 'OK' 'Default Winlogon value.' }
            continue
        }
        Test-RkhImage $Context 'startup_malware' $item.Subject $item.Command
        if ($item.Command -match '(?i)(?:-enc(?:odedcommand)?\s|FromBase64String|javascript:|vbscript:|https?://)') { Add-RkhResult $Context 'startup_malware' $item.Subject 'Warning' ('Encoded command or URL in autorun; review: ' + $item.Command) }
    }
    foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        if (Test-RkhReparsePath $folder) { Add-RkhResult $Context 'startup_malware' $folder 'Skipped' 'Reparse-point startup folder.'; continue }
        foreach ($file in Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop) {
            if ($file.Extension -ne '.ini') { Add-RkhResult $Context 'startup_malware' $file.FullName 'Info' 'Startup item; inspect manually. Shortcuts and their targets are not executed.' }
        }
    }
    Add-RkhResult $Context 'startup_malware' 'Registry scope' 'Skipped' 'Inspected HKLM and the current user only; other users and unloaded hives are not inspected.'
}

function Invoke-RkhTasks($Context) {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($task in $tasks) {
        foreach ($action in $task.Actions) {
            $subject = $task.TaskPath + $task.TaskName
            if (-not $action.Execute) { Add-RkhResult $Context 'scheduled_tasks' $subject 'Skipped' 'Non-executable action (for example a COM handler); manual review required.'; continue }
            Test-RkhImage $Context 'scheduled_tasks' $subject ([string]$action.Execute)
            if ($action.Arguments -match '(?i)(?:-enc(?:odedcommand)?\s|FromBase64String|javascript:|vbscript:|https?://)') { Add-RkhResult $Context 'scheduled_tasks' $subject 'Warning' ('Encoded command or URL in task arguments; review: ' + $action.Arguments) }
        }
    }
    Add-RkhResult $Context 'scheduled_tasks' 'Task inventory' 'Info' ("Inspected $($tasks.Count) visible tasks. Protected tasks may require elevation.")
}

function Invoke-RkhWmi($Context) {
    foreach ($class in @('CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
        $items = @(Get-CimInstance -Namespace root/subscription -ClassName $class -ErrorAction Stop)
        foreach ($item in $items) {
            $detail = if ($class -eq 'CommandLineEventConsumer') { [string]$item.CommandLineTemplate } elseif ($class -eq 'ActiveScriptEventConsumer') { [string]$item.ScriptText } else { [string]$item.Consumer }
            $subject = if ($item.Name) { [string]$item.Name } else { "$class : $($item.Filter) -> $($item.Consumer)" }
            Add-RkhResult $Context 'wmi_persistence' $subject 'Warning' ("Permanent WMI $class requires review (legitimate management software also uses this): $detail")
        }
        if (-not $items.Count) { Add-RkhResult $Context 'wmi_persistence' $class 'OK' 'None found in root/subscription.' }
    }
}

function Read-RkhPorts([string]$Path) {
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*(#|Version:|$)') { continue }
        if ($line -notmatch '^(\d+):([^:]+):(TCP|UDP):?$' -or [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535) { throw "Invalid legacy port indicator: $line" }
        [pscustomobject]@{ Port=[int]$Matches[1]; Description=$Matches[2]; Protocol=$Matches[3] }
    }
}

function Invoke-RkhPorts($Context) {
    $index = @{}; foreach ($entry in @(Read-RkhPorts (Join-Path $Context.Root 'data\backdoorports.dat'))) { $index["$($entry.Protocol):$($entry.Port)"] = $entry.Description }
    foreach ($protocol in @('TCP','UDP')) {
        try {
            $items = if ($protocol -eq 'TCP') { @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } else { @(Get-NetUDPEndpoint -ErrorAction Stop) }
            foreach ($item in $items) {
                $key = "${protocol}:$($item.LocalPort)"
                $subject = "${key}:$($item.LocalAddress):PID=$($item.OwningProcess)"
                if ($index.ContainsKey($key)) { Add-RkhResult $Context 'ports' $subject 'Warning' ("Legacy upstream port indicator: $($index[$key]). A port match does not identify malware; legitimate applications can use it.") }
                else { Add-RkhResult $Context 'ports' $subject 'Info' 'Listening endpoint.' }
            }
        } catch { Add-RkhResult $Context 'ports' $protocol 'Error' $_.Exception.Message }
    }
}

function Invoke-RkhAccounts($Context, [string]$Test) {
    if ($Test -eq 'group_accounts') {
        $accounts = @(Get-RkhInventory $Context 'accounts' { Get-RkhAccounts })
        foreach ($account in $accounts) {
            if (-not $account.Disabled -and -not $account.PasswordRequired) { Add-RkhResult $Context $Test $account.Name 'Warning' 'Enabled account does not require a password; this does not establish that the password is blank.' }
            else { Add-RkhResult $Context $Test $account.Name 'Info' ("SID=$($account.Sid); disabled=$($account.Disabled); passwordRequired=$($account.PasswordRequired)") }
        }
        return
    }
    if (-not $Context.Baseline) { Add-RkhResult $Context $Test 'Account baseline' 'Warning' 'Missing baseline; run --propupd only after verifying the computer.'; return }
    if ($Test -eq 'passwd_changes') {
        $current = @(Get-RkhInventory $Context 'accounts' { Get-RkhAccounts } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Sid,$_.Name,$_.Disabled,$_.PasswordRequired })
        $previous = @($Context.Baseline.Accounts | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Sid,$_.Name,$_.Disabled,$_.PasswordRequired })
    } else { $current = @(Get-RkhAdministrators); $previous = @($Context.Baseline.Administrators) }
    $removed = @($previous | Where-Object { $_ -notin $current }); $added = @($current | Where-Object { $_ -notin $previous })
    foreach ($entry in $removed) { Add-RkhResult $Context $Test $entry 'Warning' 'Removed or changed since baseline.' }
    foreach ($entry in $added) { Add-RkhResult $Context $Test $entry 'Warning' 'Added or changed since baseline.' }
    if (-not $removed.Count -and -not $added.Count) { Add-RkhResult $Context $Test 'Local account state' 'OK' 'Matches baseline. Password hashes and domain accounts are not inspected.' }
}

function Invoke-RkhSecurity($Context) {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled) {
            Add-RkhResult $Context 'system_configs' 'Microsoft Defender' 'Warning' 'Defender is not fully active. A third-party antivirus or organizational policy may account for this.'
        } else { Add-RkhResult $Context 'system_configs' 'Microsoft Defender' 'OK' 'Antimalware service, antivirus and real-time protection enabled.' }
        $antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop)
        foreach ($av in $antivirus) { Add-RkhResult $Context 'system_configs' $av.displayName 'Info' ("Registered antivirus product; productState=$($av.productState). Registration alone does not prove it is active.") }
    } catch { Add-RkhResult $Context 'system_configs' 'Antivirus status' 'Skipped' $_.Exception.Message }
    try {
        foreach ($profile in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            $state = if ($profile.Enabled -eq $true) { 'OK' } else { 'Warning' }
            Add-RkhResult $Context 'system_configs' ("Firewall: $($profile.Name)") $state ("Enabled=$($profile.Enabled)")
        }
    } catch { Add-RkhResult $Context 'system_configs' 'Firewall status' 'Error' $_.Exception.Message }
    try {
        $uac = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
        $state = if ($uac -eq 1) { 'OK' } else { 'Warning' }
        Add-RkhResult $Context 'system_configs' 'User Account Control' $state ("EnableLUA=$uac")
    } catch { Add-RkhResult $Context 'system_configs' 'User Account Control' 'Error' $_.Exception.Message }
    try {
        $secure = Confirm-SecureBootUEFI -ErrorAction Stop
        $state = if ($secure) { 'OK' } else { 'Warning' }
        Add-RkhResult $Context 'system_configs' 'Secure Boot' $state ("Enabled=$secure")
    } catch { Add-RkhResult $Context 'system_configs' 'Secure Boot' 'Skipped' ('Unavailable, legacy firmware or insufficient access: ' + $_.Exception.Message) }
    try {
        $bcd = @(& "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>&1)
        if ($LASTEXITCODE -ne 0) { throw ($bcd -join ' ') }
        $risky = @($bcd | Where-Object { $_ -match '(?i)^\s*(testsigning|nointegritychecks|debug)\s+(Yes|On|1)\s*$' })
        if ($risky.Count) { Add-RkhResult $Context 'system_configs' 'Boot integrity' 'Warning' ($risky -join '; ') }
        else { Add-RkhResult $Context 'system_configs' 'Boot integrity' 'Info' 'No enabled testsigning, nointegritychecks or debug flag recognized in bcdedit output. Localized output may require manual review.' }
    } catch { Add-RkhResult $Context 'system_configs' 'Boot integrity' 'Skipped' $_.Exception.Message }
}

function Invoke-RkhFilesystem($Context) {
    $files = @(Get-RkhScanFiles $Context)
    foreach ($file in $files) {
        if ($file.Extension -in @('.exe','.dll','.sys','.ps1','.bat','.cmd','.vbs','.js') -and ($file.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) { Add-RkhResult $Context 'filesystem' $file.FullName 'Warning' 'Hidden executable or script; hidden attributes can also be legitimate.' }
        try {
            foreach ($stream in @(Get-Item -LiteralPath $file.FullName -Stream '*' -Force -ErrorAction Stop)) {
                if ($stream.Stream -notin @(':$DATA','Zone.Identifier') -and $stream.Length -gt 0) { Add-RkhResult $Context 'filesystem' ($file.FullName + ':' + $stream.Stream) 'Warning' ("Non-default alternate data stream ($($stream.Length) bytes). Review; applications also use streams legitimately.") }
            }
        } catch { Add-RkhResult $Context 'filesystem' $file.FullName 'Skipped' ('ADS inspection unavailable: ' + $_.Exception.Message) }
    }
    Add-RkhResult $Context 'filesystem' 'File inspection' 'Info' ("Inspected $($files.Count) files in explicitly configured directories, without recursion. Zone.Identifier is expected download metadata.")
}

function Invoke-RkhHosts($Context) {
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        $value = ($line -split '#',2)[0].Trim()
        if (-not $value) { continue }
        if ($value -match '^(127\.0\.0\.1|::1)\s+localhost\s*$') { continue }
        Add-RkhResult $Context 'hosts' $path 'Warning' ("Non-default hosts entry: $value. Development tools and blocking lists may add legitimate entries.")
    }
    Add-RkhResult $Context 'hosts' 'Hosts inspection' 'Info' 'Inspected active hosts entries.'
}

function Invoke-RkhTest($Context, [string]$Test) {
    if ($script:RkhTests[$Test].StartsWith('UNSUPPORTED:')) { Add-RkhResult $Context $Test 'Platform support' 'Skipped' $script:RkhTests[$Test]; return }
    switch ($Test) {
        'hashes' { Invoke-RkhProperties $Context $Test }
        'attributes' { Invoke-RkhProperties $Context $Test }
        'known_rkts' { Invoke-RkhIndicators $Context }
        'running_procs' { Invoke-RkhProcesses $Context $Test }
        'deleted_files' { Invoke-RkhProcesses $Context $Test }
        'services' { Invoke-RkhServices $Context $Test }
        'loaded_modules' { Invoke-RkhServices $Context $Test }
        'avail_modules' { Invoke-RkhServices $Context $Test }
        'startup_malware' { Invoke-RkhStartup $Context }
        'scheduled_tasks' { Invoke-RkhTasks $Context }
        'wmi_persistence' { Invoke-RkhWmi $Context }
        'ports' { Invoke-RkhPorts $Context }
        'passwd_changes' { Invoke-RkhAccounts $Context $Test }
        'group_changes' { Invoke-RkhAccounts $Context $Test }
        'group_accounts' { Invoke-RkhAccounts $Context $Test }
        'system_configs' { Invoke-RkhSecurity $Context }
        'filesystem' { Invoke-RkhFilesystem $Context }
        'hosts' { Invoke-RkhHosts $Context }
        'promisc' {
            $items = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
            foreach ($item in $items) {
                if ($null -eq $item.PromiscuousMode) { Add-RkhResult $Context $Test $item.Name 'Skipped' 'Adapter does not expose promiscuous-mode state.' }
                elseif ($item.PromiscuousMode) { Add-RkhResult $Context $Test $item.Name 'Warning' 'Promiscuous mode enabled; capture tools and virtualization may enable it legitimately.' }
                else { Add-RkhResult $Context $Test $item.Name 'OK' 'Promiscuous mode is not reported enabled.' }
            }
        }
    }
}

function Update-RkhIndicators($Context) {
    $source = $Context.Config.UPDATE_SOURCE
    if ($Context.Options.UpdateSource) { $source = Resolve-RkhPath $Context.Options.UpdateSource (Get-Location).Path }
    if (-not $source) { throw 'No Windows update source configured. Use --update-source with a trusted local directory. The upstream Unix feed is incompatible.' }
    $manifest = [IO.File]::ReadAllText((Join-Path $source 'manifest.json')) | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or $manifest.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $manifest.file -cne 'windows-indicators.json') { throw 'Invalid update manifest. Expected schemaVersion=1, file=windows-indicators.json, sha256=<hash>.' }
    # Copy to a staging file first so validation and installation use identical bytes.
    $dest = Join-Path $Context.Root 'data\windows-indicators.json'
    if (Test-RkhReparsePath $dest) { throw 'Indicator installation path cannot traverse a reparse point.' }
    $temp = Join-Path (Split-Path $dest -Parent) ([IO.Path]::GetRandomFileName() + '.tmp')
    try {
        [IO.File]::Copy((Join-Path $source 'windows-indicators.json'), $temp, $false)
        $hash = (Get-FileHash -LiteralPath $temp -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($hash -ne $manifest.sha256) { throw 'Update checksum mismatch; installed indicators were not changed.' }
        $null = Read-RkhIndicators $temp
        if ($hash -eq (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction Stop).Hash) { Write-Host 'Windows indicators are unchanged.'; return 0 }
        Move-RkhAtomicFile $temp $dest
        Write-Host 'Windows indicators updated. Review the changes before explicitly refreshing their baseline entry.'
        return 2
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

function Get-RkhFindingCategory($Result) {
    if ($Result.Test -eq 'known_rkts' -and $Result.Detail -like 'SHA256 indicator match:*') { return 'hash_indicator' }
    if ($Result.Detail -like '*Missing baseline*') { return 'missing_baseline' }
    if ($Result.Test -in @('hashes','attributes')) { return 'file_changes' }
    if ($Result.Test -eq 'known_rkts') { return 'path_indicator' }
    if ($Result.Detail -like '*outside expected system directories*') { return 'masquerading' }
    if ($Result.Detail -like '*commonly writable location*') { return 'writable_location' }
    if ($Result.Detail -like 'Unquoted service executable path*') { return 'unquoted_service' }
    if ($Result.Detail -like 'Executable not found:*' -or $Result.Test -eq 'deleted_files') { return 'missing_executable' }
    if ($Result.Test -eq 'group_accounts') { return 'password_policy' }
    if ($Result.Test -in @('passwd_changes','group_changes')) { return 'account_changes' }
    if ($Result.Test -eq 'wmi_persistence') { return 'wmi' }
    if ($Result.Test -eq 'hosts') { return 'hosts' }
    if ($Result.Test -eq 'loaded_modules') { return 'driver_signature' }
    if ($Result.Test -eq 'ports') { return 'legacy_port' }
    if ($Result.Test -eq 'system_configs') { return 'security_settings' }
    if ($Result.Test -eq 'filesystem') { return 'filesystem' }
    if ($Result.Test -in @('startup_malware','scheduled_tasks')) { return 'persistence_commands' }
    if ($Result.Test -eq 'promisc') { return 'network_capture' }
    return 'other'
}

function Get-RkhNextCommand($Context, [string]$Command) {
    $parts = @((Join-Path $Context.Root 'rkhunter.cmd'), '--admin', $Command)
    if ($Context.Config.ConfigFiles.Count) { $parts += @('--configfile', $Context.Config.ConfigFiles[0]) }
    if ($Context.Options.DbDir) { $parts += @('--dbdir', $Context.Config.DBDIR) }
    if ($Command -eq '--check') {
        foreach ($pair in @(@('Enable','--enable'),@('Disable','--disable'),@('LogFile','--logfile'),@('Json','--json'))) {
                if ($Context.Options[$pair[0]]) {
                    $value = [string]$Context.Options[$pair[0]]
                    if ($pair[0] -eq 'LogFile') { $value = $Context.Config.LOGFILE }
                    if ($pair[0] -eq 'Json') { $value = Resolve-RkhPath $value (Get-Location).Path }
                    $parts += @($pair[1], $value)
                }
        }
    }
    # Printable PowerShell command. Single-quote every value, including apostrophes.
    '& ' + (($parts | ForEach-Object { "'" + $_.Replace("'","''") + "'" }) -join ' ')
}

function Get-RkhScanSummary($Context, [string[]]$Tests, $Counts, [int]$ExitCode, [bool]$Elevated) {
    $findings = [ordered]@{
        hash_indicator = @('File hashes match supplied threat indicators','A whole-file SHA256 matched your local indicator database. Validate the indicator source and investigate the file promptly; the scanner does not quarantine it.')
        masquerading = @('Windows process names in unexpected directories','A process uses a Windows system name outside the expected directories. Check its full path, publisher and origin promptly.')
        file_changes = @('Monitored file properties changed','Compare the changed files with their trusted source or expected updates. Do not refresh the baseline until the changes are explained.')
        account_changes = @('Local account or administrator membership changed','Review added, removed or changed accounts and group members against authorized changes.')
        persistence_commands = @('Startup or scheduled commands need review','Inspect the listed command, arguments and owning application. Custom login values, encoded commands, debugger hooks and URLs may be legitimate but require explanation.')
        security_settings = @('Security settings need review','Review the specific disabled or unexpected setting. Organizational policy or another security product may explain it.')
        driver_signature = @('Driver signature checks need review','Verify the driver publisher and package. Drivers can be catalog-signed without an embedded signature; this result alone does not establish malware.')
        unquoted_service = @('Service executable paths are unquoted','Have the owning application installer/vendor or an administrator review and correct quoting, preserving arguments. Exploitability depends on writable path locations; this finding alone does not establish a vulnerability or infection.')
        missing_executable = @('Executables referenced by processes or tasks are missing','Compare the task/process path with the owning application installation. Updates, uninstall leftovers or process-exit races can explain this; repair the application or review obsolete entries before removal. Review Windows tasks before making changes.')
        path_indicator = @('Paths match supplied threat indicators','Check the indicator source and inspect the file. An exact filename/path match alone does not identify malware.')
        wmi = @('Permanent WMI subscriptions need review','Review the consumer and filter. Management tools and Windows use WMI subscriptions too; the SCM Event Log names alone do not establish malicious persistence.')
        writable_location = @('Executables use commonly writable locations','AppData and Temp are also used by legitimate applications. Verify the publisher, full path and expected installation; location alone does not identify malware.')
        password_policy = @('Enabled accounts do not require a password','Review account policy. PasswordRequired=False does not mean the password is blank and does not describe Windows Hello/PIN configuration.')
        hosts = @('Hosts file contains non-default entries','Check whether each redirect is expected. Docker, development tools and blocking lists can add legitimate entries.')
        legacy_port = @('Listeners match historical port indicators','Identify the owning application. The upstream Unix-era port list is not a current Windows threat feed; matching a port does not identify malware.')
        network_capture = @('Network adapters report promiscuous mode','Check whether a capture tool or virtualization software enabled this intentionally. Promiscuous mode alone does not identify a malicious sniffer.')
        filesystem = @('Hidden files or alternate data streams need review','Inspect the listed file/stream and its origin. Hidden attributes and streams can have legitimate application uses.')
        missing_baseline = @('File/account comparisons have no usable baseline','No usable earlier state is available for comparison. Resolve baseline errors first. After independently verifying the computer, --propupd explicitly trusts the current state; it does not repair findings.')
        other = @('Other findings need review','Read the affected subjects and details in the log; these findings require context and are not confirmed infections.')
    }
    $groups = @{}
    foreach ($result in @($Context.Results | Where-Object Status -eq Warning)) {
        $key = Get-RkhFindingCategory $result
        if (-not $groups.ContainsKey($key)) { $groups[$key] = [Collections.Generic.List[object]]::new() }
        $groups[$key].Add($result)
    }
    $warningGroups = @(
        foreach ($key in $findings.Keys) {
            if (-not $groups.ContainsKey($key)) { continue }
            $seen = @{}; $examples = @()
            foreach ($result in $groups[$key]) {
                $subject = $result.Subject -replace ' \(PID \d+\)$',''
                $identity = $result.Test + '|' + $subject + '|' + $result.Detail
                if (-not $seen.ContainsKey($identity)) {
                    $seen[$identity] = $true
                    $examples += [pscustomobject]@{ Test=$result.Test; Subject=$subject; Detail=$result.Detail }
                }
            }
            [pscustomobject]@{ Category=$key; Title=$findings[$key][0]; Count=$groups[$key].Count; DistinctEntries=$examples.Count; Explanation=$findings[$key][1]; Examples=@($examples | Select-Object -First 2) }
        }
    )
    $errorGroups = @($Context.Results | Where-Object Status -eq Error | Group-Object Test | ForEach-Object {
        [pscustomobject]@{ Test=$_.Name; Count=$_.Count; Examples=@($_.Group | Select-Object -First 2 Subject,Detail) }
    })
    $skippedGroups = @($Context.Results | Where-Object Status -eq Skipped | Group-Object -Property {
        if ($_.Detail -like 'UNSUPPORTED:*') { 'Platform-specific / unsupported checks' }
        elseif ($_.Test -eq 'scheduled_tasks' -and $_.Detail -like 'Non-executable action*') { 'Scheduled task actions without an inspected executable (for example COM handlers)' }
        elseif ($_.Subject -eq 'Protected or exited processes') { 'Protected or exited process executable paths' }
        elseif ($_.Test -eq 'known_rkts') { 'Windows indicator inspection incomplete or unavailable' }
        elseif ($_.Subject -eq 'Elevation') { 'Not running as Administrator' }
        elseif ($_.Subject -eq 'Scan limit') { 'File inspection limit reached' }
        else { 'Other unavailable inspections: ' + $_.Test }
    } | ForEach-Object { [pscustomobject]@{ Reason=$_.Name; Count=$_.Count; Example=$_.Group[0].Detail } })
    $baseline = if (@($Context.Results | Where-Object { $_.Test -eq 'environment' -and $_.Subject -eq 'Baseline database' -and $_.Status -eq 'Error' }).Count) { 'Invalid or unreadable' }
        elseif ($null -ne $Context.Baseline) { 'Loaded' } else { 'Missing' }
    $hashCount = @($Context.Indicators.sha256).Count; $pathCount = @($Context.Indicators.paths).Count
    $indicatorStatus = if ('known_rkts' -notin $Tests) { 'Not selected; Windows threat indicators were not checked.' }
        elseif ($hashCount + $pathCount -eq 0) { 'Empty; Windows threat indicator inspection was skipped.' }
        else { "$hashCount SHA256 and $pathCount path indicators supplied; inspection is limited to configured files/directories." }
    $nextSteps = [Collections.Generic.List[string]]::new()
    if ($Counts.Error) { $nextSteps.Add('Resolve the inspection errors below before relying on the affected checks.') }
    if (-not $Elevated) { $nextSteps.Add('For access to protected inventories, rerun with Administrator privileges:'); $nextSteps.Add((Get-RkhNextCommand $Context '--check')) }
    if ($warningGroups.Count) { $nextSteps.Add('Review the warning groups and their examples; the log contains every affected entry.') }
    if ($baseline -eq 'Missing' -and 'missing_baseline' -in @($warningGroups.Category)) {
        $nextSteps.Add('Only after independently verifying the current files and accounts, create the baseline with:')
        $nextSteps.Add((Get-RkhNextCommand $Context '--propupd'))
    }
    if ('known_rkts' -in $Tests -and $hashCount + $pathCount -eq 0) { $nextSteps.Add(('For Windows indicator coverage, supply verified indicators as described in ' + (Join-Path $Context.Root 'docs\indicators.md') + '. This tool has no active vendor threat feed.')) }
    if ($Counts.Allowed) { $nextSteps.Add('Review Allowed entries too: they are warnings accepted by your configuration, not findings verified safe.') }
    $outcome = if ($ExitCode -eq 2) { 'SCAN INCOMPLETE - inspection errors occurred' }
        elseif ($ExitCode -eq 1) { 'REVIEW NEEDED - warnings were reported' }
        elseif ($Counts.Skipped) { 'NO WARNINGS REPORTED - coverage is limited by skipped inspections' }
        else { 'NO WARNINGS REPORTED by the selected checks' }
    [pscustomobject]@{
        Outcome=$outcome; ExitCode=$ExitCode; Elevated=$Elevated; SelectedChecks=$Tests.Count
        Baseline=$baseline; BaselineComparisonsSelected=(@($Tests | Where-Object { $_ -in @('hashes','attributes','passwd_changes','group_changes') }).Count -gt 0)
        IndicatorCoverage=$indicatorStatus; WarningGroups=$warningGroups; ErrorGroups=$errorGroups; SkippedGroups=$skippedGroups
        SecuritySettings=@($Context.Results | Where-Object Test -eq system_configs | Select-Object Subject,Status,Detail)
        NextSteps=$nextSteps.ToArray(); LogPath=$Context.Config.LOGFILE
        JsonPath=if ($Context.Options.Json) { Resolve-RkhPath $Context.Options.Json (Get-Location).Path } else { $null }
        Limitations='Warnings are findings to review, not a count of infected files. No result establishes that a computer is rootkit-free. The scanner does not remove malware.'
    }
}

function Format-RkhScanSummary($Summary, $Counts) {
    "Summary: $($Counts.OK) OK, $($Counts.Info) informational, $($Counts.Warning) warnings, $($Counts.Error) errors, $($Counts.Skipped) skipped, $($Counts.Allowed) allowed. Exit=$($Summary.ExitCode)"
    "Result: $($Summary.Outcome)"
    'Counts are result entries, not infected-file counts or distinct tests. Informational entries are observations, not passed checks.'
    "Run: $($Summary.SelectedChecks) selected checks; Administrator=$($Summary.Elevated). Baseline: $($Summary.Baseline)."
    if (-not $Summary.BaselineComparisonsSelected) { 'File/account baseline comparisons were not selected for this scan.' }
    "Windows threat indicators: $($Summary.IndicatorCoverage)"
    if ($Summary.SecuritySettings.Count) {
        ''; 'Security settings observed:'
        foreach ($item in $Summary.SecuritySettings) { "  $($item.Subject): $($item.Status) - $($item.Detail)" }
    }
    if ($Summary.ErrorGroups.Count) {
        ''; 'Inspection errors (these checks did not complete):'
        foreach ($group in $Summary.ErrorGroups) {
            "  $($group.Test): $($group.Count) error(s)"
            foreach ($item in $group.Examples) { "    $($item.Subject): $($item.Detail)" }
        }
    }
    if ($Summary.WarningGroups.Count) {
        ''; 'Warnings grouped for review:'
        foreach ($group in $Summary.WarningGroups) {
            "  $($group.Title) - results: $($group.Count); distinct entries: $($group.DistinctEntries)"
            "    $($group.Explanation)"
            foreach ($item in $group.Examples) { "    Example [$($item.Test)] $($item.Subject): $($item.Detail)" }
            if ($group.DistinctEntries -gt $group.Examples.Count) { "    See the log for $($group.DistinctEntries - $group.Examples.Count) more distinct entries in this group." }
        }
    }
    if ($Counts.Allowed) { ''; "Allowed: $($Counts.Allowed) warning(s) accepted by your ALLOW rules; original details remain in the report." }
    if ($Summary.SkippedGroups.Count) {
        ''; 'Coverage gaps (skipped inspections were not passed):'
        foreach ($group in $Summary.SkippedGroups) {
            "  $($group.Reason): $($group.Count) result(s)"
            "    Example: $($group.Example)"
        }
    }
    if ($Summary.NextSteps.Count) { ''; 'Next steps:'; foreach ($step in $Summary.NextSteps) { "  $step" } }
    ''; $Summary.Limitations
    "Log: $($Summary.LogPath)"
    if ($Summary.JsonPath) { "JSON report: $($Summary.JsonPath)" }
}

function Invoke-RkhCheck($Context, [string[]]$Tests) {
    $started = [DateTime]::UtcNow
    $logPath = $Context.Config.LOGFILE
    $null = [IO.Directory]::CreateDirectory((Split-Path $logPath -Parent))
    if (-not $Context.Options.Append -and [IO.File]::Exists($logPath)) { [IO.File]::Copy($logPath, "$logPath.old", $true) }
    $Context.Log = [IO.StreamWriter]::new($logPath, [bool]$Context.Options.Append, [Text.UTF8Encoding]::new($false))
    try {
        $Context.Log.WriteLine(('Rootkit Hunter {0}; computer={1}; started={2}' -f $script:RkhVersion,[Environment]::MachineName,$started.ToString('o')))
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $admin) { Add-RkhResult $Context 'environment' 'Elevation' 'Skipped' 'Running without Administrator rights. Some system inventories may be inaccessible.' }
        try { $Context.Baseline = Read-RkhBaseline $Context }
        catch { Add-RkhResult $Context 'environment' 'Baseline database' 'Error' $_.Exception.Message }
        foreach ($test in $Tests) {
            try { Invoke-RkhTest $Context $test }
            catch { Add-RkhResult $Context $test 'Inspection incomplete' 'Error' $_.Exception.Message }
        }
        $counts = [ordered]@{ OK=0; Info=0; Warning=0; Error=0; Skipped=0; Allowed=0 }
        foreach ($result in $Context.Results) { $counts[$result.Status]++ }
        $exitCode = if ($counts.Error) { 2 } elseif ($counts.Warning) { 1 } else { 0 }
        $interpretation = Get-RkhScanSummary $Context $Tests $counts $exitCode $admin
        $report = [ordered]@{ SchemaVersion=1; Version=$script:RkhVersion; Computer=[Environment]::MachineName; StartedUtc=$started.ToString('o'); FinishedUtc=[DateTime]::UtcNow.ToString('o'); Elevated=$admin; Tests=$Tests; Counts=$counts; ExitCode=$exitCode; Summary=$interpretation; Results=$Context.Results.ToArray() }
        if ($Context.Options.Json) { Write-RkhAtomicJson (Resolve-RkhPath $Context.Options.Json (Get-Location).Path) $report }
        foreach ($line in @(Format-RkhScanSummary $interpretation $counts)) {
            $Context.Log.WriteLine($line)
            if (-not $Context.Options.Quiet -and -not $Context.Options.Cron -and -not $Context.Options.Rwo) { Write-Host $line }
        }
        return $exitCode
    } finally { $Context.Log.Dispose(); $Context.Log = $null }
}

function Test-RkhOutputPaths($Context) {
    $protected = @(Get-RkhPropertyFiles $Context) + @(
        (Join-Path $Context.Config.DBDIR 'rkhunter.dat.json'),
        (Join-Path $Context.Config.DBDIR 'rkhunter.lock'),
        (Join-Path $Context.Root 'rkhunter.cmd'), (Join-Path $Context.Root 'installer.ps1')
    )
    $outputs = @($Context.Config.LOGFILE, ($Context.Config.LOGFILE + '.old'))
    if ($Context.Options.Json) { $outputs += (Resolve-RkhPath $Context.Options.Json (Get-Location).Path) }
    $seen = @{}
    foreach ($path in $outputs) {
        if ($path -in $protected -or $seen.ContainsKey($path)) { throw "Output path collides with protected data or another output: $path" }
        if (Test-RkhReparsePath $path) { throw "Output path cannot traverse a reparse point: $path" }
        $seen[$path] = $true
    }
}

function Invoke-Rkhunter {
    [CmdletBinding()]
    param([string[]]$Arguments, [Parameter(Mandatory=$true)][string]$Root)
    $opt = Get-RkhOptions $Arguments
    if ($opt.Command -eq 'help') { Write-Host (Get-RkhHelp); return 0 }
    if ($opt.Command -eq 'version') { Write-Host ("Rootkit Hunter $script:RkhVersion (native Windows port; upstream source bundled separately)"); return 0 }
    if ($env:OS -ne 'Windows_NT') { throw 'This port requires Windows and PowerShell 5.1 or later.' }
    if ([IntPtr]::Size -ne 8) { throw 'Use 64-bit PowerShell to avoid registry and System32 redirection.' }
    $configPath = Join-Path $Root 'rkhunter.conf'
    if ($opt.ConfigFile) { $configPath = Resolve-RkhPath $opt.ConfigFile (Get-Location).Path }
    $cfg = Read-RkhConfig $configPath
    if ($opt.DbDir) { $cfg.DBDIR = Resolve-RkhPath $opt.DbDir (Get-Location).Path }
    if ($opt.LogFile) { $cfg.LOGFILE = Resolve-RkhPath $opt.LogFile (Get-Location).Path }
    $tests = @(Get-RkhSelectedTests $cfg $opt)
    $ctx = @{ Root=$Root; Config=$cfg; Options=$opt; Results=[Collections.Generic.List[object]]::new(); Cache=@{}; Log=$null; Baseline=$null }
    if ($opt.Command -ne 'update') { $ctx.Indicators = Read-RkhIndicators (Join-Path $Root 'data\windows-indicators.json') }
    $null = @(Read-RkhPorts (Join-Path $Root 'data\backdoorports.dat'))
    switch ($opt.Command) {
        'config-check' { Write-Host ("Configuration OK; $($tests.Count) selected checks (including explicitly unsupported checks). File paths: $($cfg.FILE.Count)."); return 0 }
        'list' {
            switch ($opt.List) {
                'tests' {
                    foreach ($name in $script:RkhTests.Keys) { Write-Host ('{0,-24} {1}' -f $name,$script:RkhTests[$name]) }
                    Write-Host 'Groups:'
                    foreach ($name in @($script:RkhGroups.Keys | Sort-Object)) { Write-Host ("  $name => " + ($script:RkhGroups[$name] -join ', ')) }
                }
                'rootkits' { Write-Host 'Only locally supplied Windows indicators are active. Unix families are not Windows detections.'; foreach ($entry in @($ctx.Indicators.sha256) + @($ctx.Indicators.paths)) { Write-Host $entry.name } }
                'propfiles' { foreach ($file in @(Get-RkhPropertyFiles $ctx)) { Write-Host $file } }
                { $_ -in @('lang','languages') } { Write-Host 'en (Windows port); upstream translations are preserved in upstream/files/i18n.' }
                'perl' { Write-Host 'Perl is not required by the Windows port.' }
                default { throw "Unknown list: $($opt.List)" }
            }
            return 0
        }
    }
    if ($opt.Command -eq 'check' -and -not $tests.Count) { throw 'No checks selected.' }
    if ($opt.Command -eq 'check') { Test-RkhOutputPaths $ctx }
    # Exclusive OS handle, automatically released even if the process terminates.
    # The lock filename remains; its existence alone never means a process is active.
    if (Test-RkhReparsePath $cfg.DBDIR) { throw 'Database directory cannot traverse a reparse point.' }
    $null = [IO.Directory]::CreateDirectory($cfg.DBDIR)
    $lock = $null
    try {
        try { $lock = [IO.File]::Open((Join-Path $cfg.DBDIR 'rkhunter.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch { throw 'Cannot acquire database lock. Another scan/update may be running, or the database directory is not writable.' }
        if ($opt.Command -eq 'update') {
            try { return (Update-RkhIndicators $ctx) } catch { [Console]::Error.WriteLine(('rkhunter update: ' + $_.Exception.Message)); return 1 }
        }
        if ($opt.Command -eq 'propupd') { Update-RkhBaseline $ctx; return 0 }
        return (Invoke-RkhCheck $ctx $tests)
    } finally { if ($lock) { $lock.Dispose() } }
}

Export-ModuleMember -Function Invoke-Rkhunter
