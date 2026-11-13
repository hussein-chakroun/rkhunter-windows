# Dependency-free regression tests for Windows PowerShell 5.1 and PowerShell 7.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Rkhunter.psm1') -Force -DisableNameChecking
$module = Get-Module Rkhunter
$fixture = Join-Path $root ('test-results\run-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($fixture)
& $module {
    param($Root, $Fixture)
    $script:TestPassed = 0; $script:TestFailed = 0
    function Assert-True($Condition, [string]$Message = 'Assertion failed') { if (-not $Condition) { throw $Message } }
    function Assert-Throws([scriptblock]$Action) {
        $threw = $false
        try { $null = & $Action } catch { $threw = $true }
        Assert-True $threw 'Expected an exception.'
    }
    function Test-Case([string]$Name, [scriptblock]$Action) {
        try { & $Action; $script:TestPassed++; Write-Host "PASS $Name" -ForegroundColor Green }
        catch { $script:TestFailed++; Write-Host ("FAIL ${Name}: " + $_.Exception.Message + ' at ' + $_.ScriptStackTrace) -ForegroundColor Red }
    }
    function New-TestContext {
        $cfg = Read-RkhConfig (Join-Path $Root 'rkhunter.conf')
        $cfg.DBDIR = Join-Path $Fixture 'db'
        $cfg.LOGFILE = Join-Path $Fixture 'scan.log'
        $cfg.ConfigFiles = @(); $cfg.FILE = @(); $cfg.SCAN_DIR = @(); $cfg.ALLOW = @()
        @{ Root=$Root; Config=$cfg; Options=(Get-RkhOptions @('--check','--quiet')); Results=[Collections.Generic.List[object]]::new(); Cache=@{}; Log=$null; Baseline=$null; Indicators=(Read-RkhIndicators (Join-Path $Root 'data\windows-indicators.json')) }
    }
    function New-TestSummary($Context,[string[]]$Tests,[bool]$Elevated=$true) {
        $counts = [ordered]@{ OK=0; Info=0; Warning=0; Error=0; Skipped=0; Allowed=0 }
        foreach ($result in $Context.Results) { $counts[$result.Status]++ }
        $code = if ($counts.Error) { 2 } elseif ($counts.Warning) { 1 } else { 0 }
        Get-RkhScanSummary $Context $Tests $counts $code $Elevated
    }
    Test-Case 'GNU-style aliases preserve -c versus -C' {
        Assert-True ((Get-RkhOptions @('-c')).Command -eq 'check')
        Assert-True ((Get-RkhOptions @('-C')).Command -eq 'config-check')
        Assert-True ((Get-RkhOptions @('--cronjob')).Command -eq 'check')
    }
    Test-Case 'all original named checks have an explicit Windows disposition' {
        $source = [IO.File]::ReadAllText((Join-Path $Root 'upstream\files\rkhunter'))
        $match = [regex]::Match($source, '(?ms)^KNOWN_TESTS="(.*?)"')
        Assert-True $match.Success
        foreach ($name in ($match.Groups[1].Value -split '\s+' | Where-Object { $_ })) {
            Assert-True ($script:RkhTests.Contains($name) -or $script:RkhGroups.ContainsKey($name)) ("Missing platform mapping for $name")
        }
    }
    Test-Case 'supplied upstream files are byte-for-byte preserved' {
        $manifest = [IO.File]::ReadAllText((Join-Path $Root 'upstream\SHA256SUMS.json')) | ConvertFrom-Json
        foreach ($entry in $manifest) {
            $path = Join-Path $Root ('upstream\' + $entry.path)
            Assert-True ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $entry.sha256) ("Upstream file changed: $($entry.path)")
        }
    }
    Test-Case 'invalid or conflicting options fail' {
        Assert-Throws { Get-RkhOptions @('--enable') }
        Assert-Throws { Get-RkhOptions @('--check','--propupd') }
        Assert-Throws { Get-RkhOptions @('--cronjob','--update') }
        Assert-Throws { Get-RkhOptions @('--bogus') }
    }
    Test-Case 'test groups expand and explicit disabling wins' {
        $ctx = New-TestContext
        $ctx.Options.Enable = 'system_commands,network'; $ctx.Options.Disable = 'hashes,ports'
        $tests = @(Get-RkhSelectedTests $ctx.Config $ctx.Options)
        Assert-True ('attributes' -in $tests -and 'hashes' -notin $tests -and 'ports' -notin $tests -and 'promisc' -in $tests)
        Assert-Throws { Expand-RkhTests @('imaginary') }
    }
    Test-Case 'configuration overlays, quotes, resets and literal values' {
        $dir = Join-Path $Fixture 'config'; $null = [IO.Directory]::CreateDirectory($dir)
        $path = Join-Path $dir 'rkhunter.conf'
        [IO.File]::WriteAllText($path, "FILE=`"one file.exe`"`nSCAN_DIR=.`nMAX_FILES=25`n")
        [IO.File]::WriteAllText("$path.local", "FILE=`nFILE=second.exe`nMAX_FILES=20`n")
        $null = [IO.Directory]::CreateDirectory((Join-Path $dir 'rkhunter.d'))
        [IO.File]::WriteAllText((Join-Path $dir 'rkhunter.d\last.conf'), "MAX_FILES=10`n")
        $cfg = Read-RkhConfig $path
        Assert-True ($cfg.MAX_FILES -eq '10' -and $cfg.FILE.Count -eq 1 -and $cfg.FILE[0] -eq (Join-Path $dir 'second.exe'))
        Assert-True ($cfg.ConfigFiles.Count -eq 3)
        [IO.File]::WriteAllText($path, 'UNKNOWN=1')
        Assert-Throws { Read-RkhConfig $path }
        [IO.File]::WriteAllText($path, 'MAX_FILES=25')
        [IO.File]::WriteAllText((Join-Path $dir 'rkhunter.d\last.conf'), 'MAX_FILES=0')
        Assert-Throws { Read-RkhConfig $path }
    }
    Test-Case 'paths expand environment variables without executing code' {
        Assert-True ((Resolve-RkhPath '%SystemRoot%/System32/cmd.exe' $Root) -eq (Join-Path $env:SystemRoot 'System32\cmd.exe'))
        Assert-Throws { Resolve-RkhPath '%RKH_NONEXISTENT_VARIABLE%/x' $Root }
        $literal = Resolve-RkhPath '$(throw injected).exe' $Fixture
        Assert-True ($literal.Contains('$(throw injected)'))
    }
    Test-Case 'image parsing handles quotes, spaces and NT driver prefixes' {
        Assert-True ((Resolve-RkhImage '"C:\Program Files\App\a.exe" -x') -eq 'C:\Program Files\App\a.exe')
        Assert-True ((Resolve-RkhImage 'C:\Program Files\App\a.exe -x') -eq 'C:\Program Files\App\a.exe')
        Assert-True ((Resolve-RkhImage '\??\C:\Windows\a.sys') -eq 'C:\Windows\a.sys')
        Assert-True ((Resolve-RkhImage '\SystemRoot\System32\drivers\a.sys') -eq (Join-Path $env:SystemRoot 'System32\drivers\a.sys'))
        Assert-True (Test-RkhRiskyPath ($env:LOCALAPPDATA.Replace('\','/') + '/app/a.exe'))
    }
    Test-Case 'baseline detects content changes and refuses missing files' {
        $ctx = New-TestContext; $file = Join-Path $Fixture 'tracked.exe'
        [IO.File]::WriteAllText($file, 'trusted content')
        $record = Get-RkhFileRecord $file
        $ctx.Config.FILE = @($file)
        $ctx.Baseline = [pscustomobject]@{ Files=@($record) }
        Invoke-RkhProperties $ctx 'hashes'
        Assert-True (@($ctx.Results | Where-Object { $_.Subject -eq $file -and $_.Status -eq 'OK' }).Count -eq 1)
        [IO.File]::WriteAllText($file, 'changed content')
        $ctx.Cache.Clear(); $ctx.Results.Clear()
        Invoke-RkhProperties $ctx 'hashes'
        Assert-True (@($ctx.Results | Where-Object { $_.Subject -eq $file -and $_.Status -eq 'Warning' }).Count -eq 1)
        Assert-Throws { Get-RkhFileRecord (Join-Path $Fixture 'missing.exe') }
    }
    Test-Case 'ACL-only and metadata changes are visible' {
        $ctx = New-TestContext; $file = Join-Path $Fixture 'metadata.exe'
        [IO.File]::WriteAllText($file, 'same bytes')
        $record = Get-RkhFileRecord $file; $record.Sddl = 'different DACL'
        $ctx.Config.FILE = @($file); $ctx.Baseline = [pscustomobject]@{ Files=@($record) }
        Invoke-RkhProperties $ctx 'attributes'
        Assert-True (@($ctx.Results | Where-Object { $_.Subject -eq $file -and $_.Status -eq 'Warning' -and $_.Detail.Contains('Sddl') }).Count -eq 1)
    }
    Test-Case 'missing baseline warns instead of auto-trusting' {
        $ctx = New-TestContext; Invoke-RkhProperties $ctx 'hashes'
        Assert-True ($ctx.Results[0].Status -eq 'Warning')
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $ctx.Config.DBDIR 'rkhunter.dat.json')))
    }
    Test-Case 'allowlists retain the original warning and never suppress errors' {
        $ctx = New-TestContext; $ctx.Config.ALLOW = @('services|Example*')
        Add-RkhResult $ctx 'services' 'Example service' 'Warning' 'test'
        Add-RkhResult $ctx 'services' 'Example service' 'Error' 'test'
        Assert-True ($ctx.Results[0].Status -eq 'Allowed' -and $ctx.Results[0].OriginalStatus -eq 'Warning')
        Assert-True ($ctx.Results[1].Status -eq 'Error')
    }
    Test-Case 'unsupported kernel checks explicitly skip' {
        $ctx = New-TestContext; Invoke-RkhTest $ctx 'hidden_procs'; Invoke-RkhTest $ctx 'hidden_ports'
        Assert-True (@($ctx.Results | Where-Object Status -eq Skipped).Count -eq 2)
    }
    Test-Case 'empty indicator database does not claim malware checks passed' {
        $ctx = New-TestContext
        $ctx.Indicators = [pscustomobject]@{ sha256=@(); paths=@() }
        Invoke-RkhIndicators $ctx
        Assert-True ($ctx.Results[0].Status -eq 'Skipped')
    }
    Test-Case 'process masquerading and missing executables are reported' {
        $ctx = New-TestContext; $fake = Join-Path $Fixture 'lsass.exe'
        $ctx.Cache.processes = @([pscustomobject]@{ Name='lsass.exe'; ProcessId=123; ExecutablePath=$fake }, [pscustomobject]@{ Name='Protected'; ProcessId=124; ExecutablePath=$null })
        Invoke-RkhProcesses $ctx 'running_procs'; Invoke-RkhProcesses $ctx 'deleted_files'
        Assert-True (@($ctx.Results | Where-Object { $_.Test -eq 'running_procs' -and $_.Status -eq 'Warning' -and $_.Detail.Contains('outside expected') }).Count -eq 1)
        Assert-True (@($ctx.Results | Where-Object { $_.Test -eq 'deleted_files' -and $_.Status -eq 'Warning' }).Count -eq 1)
        Assert-True (@($ctx.Results | Where-Object Status -eq Skipped).Count -eq 2)
    }
    Test-Case 'unquoted service executable paths produce a warning' {
        $ctx = New-TestContext
        $ctx.Cache.services = @([pscustomobject]@{ Name='Harmless fixture service'; PathName='C:\Program Files\Test\missing.exe -argument' })
        Invoke-RkhServices $ctx 'services'
        Assert-True (@($ctx.Results | Where-Object { $_.Status -eq 'Warning' -and $_.Detail.Contains('Unquoted') }).Count -eq 1)
    }
    Test-Case 'account snapshots expose added and removed account state' {
        $ctx = New-TestContext
        $ctx.Cache.accounts = @([pscustomobject]@{ Sid='S-1-5-21-new'; Name='New'; Disabled=$false; PasswordRequired=$false })
        $ctx.Baseline = [pscustomobject]@{ Accounts=@([pscustomobject]@{ Sid='S-1-5-21-old'; Name='Old'; Disabled=$false; PasswordRequired=$true }) }
        Invoke-RkhAccounts $ctx 'passwd_changes'; Invoke-RkhAccounts $ctx 'group_accounts'
        Assert-True (@($ctx.Results | Where-Object { $_.Test -eq 'passwd_changes' -and $_.Status -eq 'Warning' }).Count -eq 2)
        Assert-True (@($ctx.Results | Where-Object { $_.Test -eq 'group_accounts' -and $_.Status -eq 'Warning' }).Count -eq 1)
    }
    Test-Case 'exact hash and path indicators detect harmless fixtures' {
        $ctx = New-TestContext; $file = Join-Path $Fixture 'indicator.bin'
        [IO.File]::WriteAllText($file, 'harmless fixture, not malware')
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $ctx.Config.FILE = @($file)
        $ctx.Indicators = [pscustomobject]@{ sha256=@([pscustomobject]@{ hash=$hash; name='test hash' }); paths=@([pscustomobject]@{ path=$file; name='test path' }) }
        Invoke-RkhIndicators $ctx
        Assert-True (@($ctx.Results | Where-Object { $_.Subject -eq $file -and $_.Status -eq 'Warning' }).Count -eq 2)
    }
    Test-Case 'file enumeration is bounded and records incomplete coverage' {
        $ctx = New-TestContext; $dir = Join-Path $Fixture 'bounded'; $null = [IO.Directory]::CreateDirectory($dir)
        1..3 | ForEach-Object { [IO.File]::WriteAllText((Join-Path $dir "f$_.txt"), 'x') }
        $ctx.Config.SCAN_DIR = @($dir); $ctx.Config.MAX_FILES = '2'
        $files = @(Get-RkhScanFiles $ctx)
        Assert-True ($files.Count -eq 2)
        Assert-True (@($ctx.Results | Where-Object { $_.Status -eq 'Skipped' -and $_.Subject -eq 'Scan limit' }).Count -eq 1)
    }
    Test-Case 'hidden executables and alternate data streams are detected' {
        $ctx = New-TestContext; $dir = Join-Path $Fixture 'streams'; $null = [IO.Directory]::CreateDirectory($dir)
        $file = Join-Path $dir 'hidden.exe'; [IO.File]::WriteAllText($file, 'harmless fixture')
        [IO.File]::SetAttributes($file, [IO.FileAttributes]::Hidden)
        Set-Content -LiteralPath $file -Stream 'test-payload' -Value 'harmless stream' -ErrorAction Stop
        $ctx.Config.SCAN_DIR = @($dir); Invoke-RkhFilesystem $ctx
        Assert-True (@($ctx.Results | Where-Object Status -eq Warning).Count -eq 2)
    }
    Test-Case 'directory junctions are excluded from inspection and output' {
        $ctx = New-TestContext; $target = Join-Path $Fixture 'junction-target'; $null = [IO.Directory]::CreateDirectory($target)
        $link = Join-Path $Fixture 'junction'
        $null = New-Item -ItemType Junction -Path $link -Target $target
        $ctx.Config.SCAN_DIR = @($link)
        Assert-True (@(Get-RkhScanFiles $ctx).Count -eq 0)
        Assert-True (Test-RkhReparsePath (Join-Path $link 'not-created.log'))
        Assert-Throws { Get-RkhFileRecord (Join-Path $link 'file.exe') }
    }
    Test-Case 'legacy port database is parsed and malformed ports rejected' {
        $ports = @(Read-RkhPorts (Join-Path $Root 'data\backdoorports.dat'))
        Assert-True (@($ports | Where-Object Port -eq 31337).Count -eq 1)
        $bad = Join-Path $Fixture 'ports.dat'; [IO.File]::WriteAllText($bad, '70000:invalid:TCP:')
        Assert-Throws { Read-RkhPorts $bad }
    }
    Test-Case 'invalid indicator schema and traversal-like paths fail' {
        $path = Join-Path $Fixture 'bad-indicators.json'
        [IO.File]::WriteAllText($path, '{"schemaVersion":1,"version":"1","sha256":[{"hash":"bad","name":"bad"}],"paths":[]}')
        Assert-Throws { Read-RkhIndicators $path }
        [IO.File]::WriteAllText($path, '{"schemaVersion":1,"version":"1","sha256":[],"paths":[{"path":"../relative","name":"bad"}]}')
        Assert-Throws { Read-RkhIndicators $path }
    }
    Test-Case 'output files cannot overwrite monitored files or one another' {
        $ctx = New-TestContext; $ctx.Config.LOGFILE = Join-Path $Root 'rkhunter.ps1'
        Assert-Throws { Test-RkhOutputPaths $ctx }
        $ctx = New-TestContext; $ctx.Options.Json = $ctx.Config.LOGFILE
        Assert-Throws { Test-RkhOutputPaths $ctx }
    }
    Test-Case 'baseline rejects wrong-machine and corrupt entries' {
        $ctx = New-TestContext
        $path = Join-Path $ctx.Config.DBDIR 'rkhunter.dat.json'
        Write-RkhAtomicJson $path @{ SchemaVersion=1; Machine='another-computer'; Files=@() }
        Assert-Throws { Read-RkhBaseline $ctx }
        Write-RkhAtomicJson $path @{ SchemaVersion=1; Machine=[Environment]::MachineName; Files=@(@{Path='relative'; Sha256='bad'}) }
        Assert-Throws { Read-RkhBaseline $ctx }
        [IO.File]::Delete($path)
    }
    Test-Case 'atomic writes replace valid JSON without leftover staging files' {
        $dir = Join-Path $Fixture 'atomic'; $path = Join-Path $dir 'value.json'
        Write-RkhAtomicJson $path @{ value=1 }; Write-RkhAtomicJson $path @{ value=2 }
        Assert-True (([IO.File]::ReadAllText($path) | ConvertFrom-Json).value -eq 2)
        Assert-True (@(Get-ChildItem -LiteralPath $dir -Filter '*.tmp').Count -eq 0)
    }
    Test-Case 'checksum-protected indicator update is transactional' {
        $ctx = New-TestContext; $fakeRoot = Join-Path $Fixture 'updater'; $source = Join-Path $Fixture 'update-source'
        $null = [IO.Directory]::CreateDirectory((Join-Path $fakeRoot 'data')); $null = [IO.Directory]::CreateDirectory($source)
        $dest = Join-Path $fakeRoot 'data\windows-indicators.json'
        [IO.File]::WriteAllText($dest, '{"schemaVersion":1,"version":"1","sha256":[],"paths":[]}')
        $new = Join-Path $source 'windows-indicators.json'
        [IO.File]::WriteAllText($new, '{"schemaVersion":1,"version":"2","sha256":[],"paths":[]}')
        $ctx.Root = $fakeRoot; $ctx.Config.UPDATE_SOURCE = $source
        $manifest = Join-Path $source 'manifest.json'
        Write-RkhAtomicJson $manifest @{ schemaVersion=1; file='windows-indicators.json'; sha256=('0' * 64) }
        Assert-Throws { Update-RkhIndicators $ctx }
        Assert-True ((Read-RkhIndicators $dest).version -eq '1')
        Write-RkhAtomicJson $manifest @{ schemaVersion=1; file='windows-indicators.json'; sha256=(Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash }
        Assert-True ((Update-RkhIndicators $ctx) -eq 2)
        Assert-True ((Update-RkhIndicators $ctx) -eq 0)
        Assert-True ((Read-RkhIndicators $dest).version -eq '2')
    }
    Test-Case 'scan reports preserve skipped coverage and exit status' {
        $ctx = New-TestContext; $ctx.Options.Json = Join-Path $Fixture 'coverage.json'
        $code = Invoke-RkhCheck $ctx @('hidden_procs')
        $report = [IO.File]::ReadAllText($ctx.Options.Json) | ConvertFrom-Json
        Assert-True ($code -eq 0 -and $report.Counts.Skipped -ge 1 -and $report.Results.Count -ge 1)
        $ctx = New-TestContext; $code = Invoke-RkhCheck $ctx @('hashes')
        Assert-True ($code -eq 1)
        Assert-True (Test-Path -LiteralPath ($ctx.Config.LOGFILE + '.old'))
    }
    Test-Case 'summary explains repeated process warnings without changing raw findings' {
        $ctx = New-TestContext
        Add-RkhResult $ctx 'running_procs' 'Example.exe (PID 1)' 'Warning' 'Running from a commonly writable location: C:\Users\example\AppData\Example.exe'
        Add-RkhResult $ctx 'running_procs' 'Example.exe (PID 2)' 'Warning' 'Running from a commonly writable location: C:\Users\example\AppData\Example.exe'
        Add-RkhResult $ctx 'services' 'Example service' 'Warning' 'Unquoted service executable path contains spaces: C:\Program Files\Example.exe'
        $summary = New-TestSummary $ctx @('running_procs','services')
        $group = $summary.WarningGroups | Where-Object Category -eq writable_location
        Assert-True ($group.Count -eq 2 -and $group.DistinctEntries -eq 1 -and $group.Examples.Count -eq 1)
        Assert-True ($group.Explanation.Contains('location alone does not identify malware'))
        Assert-True ($ctx.Results.Count -eq 3 -and $summary.ExitCode -eq 1 -and $summary.WarningGroups.Count -eq 2)
    }
    Test-Case 'summary separates hash indicator evidence from path-only findings' {
        $ctx = New-TestContext
        Add-RkhResult $ctx 'known_rkts' 'fixture-hash' 'Warning' 'SHA256 indicator match: fixture'
        Add-RkhResult $ctx 'known_rkts' 'fixture-path' 'Warning' 'Path indicator: fixture. Filename alone is not proof of infection.'
        $summary = New-TestSummary $ctx @('known_rkts')
        Assert-True ($summary.WarningGroups[0].Category -eq 'hash_indicator' -and $summary.WarningGroups[1].Category -eq 'path_indicator')
        Assert-True ($summary.WarningGroups[1].Explanation.Contains('path match alone'))
    }
    Test-Case 'summary identifies incomplete scans and preserves custom rerun paths' {
        $ctx = New-TestContext; $ctx.Root = Join-Path $Fixture "path with ' apostrophe"
        $ctx.Options.Enable = 'hashes'; $ctx.Options.DbDir = $ctx.Config.DBDIR; $ctx.Options.Json = 'relative report.json'
        Add-RkhResult $ctx 'hashes' 'example' 'Warning' 'Changed: Sha256.'
        Add-RkhResult $ctx 'filesystem' 'protected folder' 'Error' 'Access is denied.'
        $summary = New-TestSummary $ctx @('hashes','filesystem') $false
        Assert-True ($summary.ExitCode -eq 2 -and $summary.Outcome.StartsWith('SCAN INCOMPLETE') -and $summary.ErrorGroups.Count -eq 1)
        $next = $summary.NextSteps -join "`n"
        Assert-True ($next.Contains("path with '' apostrophe") -and $next.Contains('--dbdir') -and $next.Contains((Resolve-RkhPath $ctx.Options.Json (Get-Location).Path)))
        Assert-True (-not $next.Contains('--propupd'))
    }
    Test-Case 'summary groups skipped reasons without claiming a clean computer' {
        $ctx = New-TestContext
        Add-RkhResult $ctx 'hidden_procs' 'Kernel view' 'Skipped' 'UNSUPPORTED: independent kernel view required'
        1..3 | ForEach-Object { Add-RkhResult $ctx 'scheduled_tasks' "Task $_" 'Skipped' 'Non-executable action (for example a COM handler); manual review required.' }
        $summary = New-TestSummary $ctx @('hidden_procs','scheduled_tasks')
        Assert-True ($summary.ExitCode -eq 0 -and $summary.Outcome.Contains('coverage is limited'))
        Assert-True (@($summary.SkippedGroups | Where-Object Count -eq 3).Count -eq 1 -and $summary.SkippedGroups.Count -eq 2)
        Assert-True ($summary.IndicatorCoverage.StartsWith('Not selected'))
    }
    Test-Case 'summary advises explicit trust only for a missing baseline' {
        $ctx = New-TestContext
        Add-RkhResult $ctx 'hashes' 'Property database' 'Warning' 'Missing baseline; verify this computer, then run --propupd.'
        $summary = New-TestSummary $ctx @('hashes','known_rkts')
        Assert-True ($summary.Baseline -eq 'Missing' -and ($summary.NextSteps -join ' ').Contains('Only after independently verifying'))
        Assert-True (($summary.NextSteps -join ' ').Contains("'--propupd'") -and $summary.IndicatorCoverage.StartsWith('Empty'))
        Add-RkhResult $ctx 'environment' 'Baseline database' 'Error' 'Corrupt database'
        $summary = New-TestSummary $ctx @('hashes')
        Assert-True ($summary.Baseline -eq 'Invalid or unreadable' -and -not ($summary.NextSteps -join ' ').Contains("'--propupd'"))
    }
    Test-Case 'summary retains accepted warning context and healthy settings' {
        $ctx = New-TestContext; $ctx.Config.ALLOW = @('services|Reviewed')
        Add-RkhResult $ctx 'services' 'Reviewed' 'Warning' 'Reviewed warning'
        Add-RkhResult $ctx 'system_configs' 'Secure Boot' 'OK' 'Enabled=True'
        $summary = New-TestSummary $ctx @('services','system_configs')
        Assert-True ($summary.WarningGroups.Count -eq 0 -and $summary.SecuritySettings[0].Detail -eq 'Enabled=True')
        Assert-True (($summary.NextSteps -join ' ').Contains('not findings verified safe') -and $ctx.Results[0].OriginalStatus -eq 'Warning')
    }
    Test-Case 'quiet, warning-only and cron scans save explanatory log and JSON summaries' {
        foreach ($options in @(@('--check','--quiet'),@('--check','--rwo'),@('--cronjob'))) {
            $ctx = New-TestContext; $ctx.Options = Get-RkhOptions $options
            $ctx.Options.Json = Join-Path $Fixture 'quiet-summary.json'
            $output = @(& { Invoke-RkhCheck $ctx @('hidden_procs') } 6>&1)
            Assert-True ($output.Count -eq 1 -and $output[0] -eq 0) 'Console suppression must preserve the numeric exit code.'
            $json = [IO.File]::ReadAllText($ctx.Options.Json) | ConvertFrom-Json
            $log = [IO.File]::ReadAllText($ctx.Config.LOGFILE)
            Assert-True ($json.Summary.Outcome.Contains('coverage is limited') -and $json.Summary.WarningGroups.Count -eq 0)
            Assert-True ($log.Contains('Coverage gaps') -and $log.Contains('not infected-file counts') -and $log.Contains('JSON report:'))
        }
    }
    Write-Host ("Tests: $script:TestPassed passed, $script:TestFailed failed. Artifacts: $Fixture")
    if ($script:TestFailed) { exit 1 }
} $root $fixture
