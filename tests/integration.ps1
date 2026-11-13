# SPDX-License-Identifier: GPL-2.0-or-later
# Real Windows launchers, isolated install, real inventory baseline and locking.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$run = Join-Path $root ('test-results\integration-' + [Guid]::NewGuid().ToString('N'))
$install = Join-Path $run 'installed with spaces'
$null = [IO.Directory]::CreateDirectory($run)
$engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:passed = 0

function Invoke-Entry([string]$ScriptPath, [string[]]$CliArguments) {
    $ErrorActionPreference = 'Continue'
    if ($ScriptPath.EndsWith('.cmd')) { $output = @(& $ScriptPath @CliArguments 2>&1) }
    else { $output = @(& $engine -NoLogo -NoProfile -File $ScriptPath @CliArguments 2>&1) }
    [pscustomobject]@{ Code=$LASTEXITCODE; Output=($output -join "`n") }
}
function Assert-Result($Condition, [string]$Message) { if (-not $Condition) { throw $Message }; $script:passed++; Write-Host "PASS $Message" -ForegroundColor Green }
function Run-Scanner([string[]]$CliArguments) { Invoke-Entry (Join-Path $install 'rkhunter.cmd') $CliArguments }

try {
    $userPathBefore = [Environment]::GetEnvironmentVariable('Path','User')
    $result = Invoke-Entry (Join-Path $root 'setup.cmd') @('--prefix',$install,'--no-path')
    Assert-Result ($result.Code -eq 0 -and (Test-Path -LiteralPath (Join-Path $install 'rkhunter.cmd'))) 'installer creates a usable installation at a path containing spaces'
    $processPathBefore = $env:Path
    Push-Location -LiteralPath $run
    try {
        # Model a newly opened terminal without touching the persistent PATH.
        $env:Path = $install + ';' + $env:Path
        $result = Invoke-Entry 'rkhunter.cmd' @('--version')
    } finally { $env:Path = $processPathBefore; Pop-Location }
    Assert-Result ($result.Code -eq 0 -and $result.Output.Contains('native Windows port')) 'installed command resolves through PATH from another working directory'

    $tracked = Join-Path $install 'trusted fixture.bin'
    [IO.File]::WriteAllText($tracked, 'verified original fixture')
    $config = Join-Path $install 'rkhunter.conf'
    [IO.File]::WriteAllText($config, "DBDIR=state`nLOGFILE=logs/scan.log`nENABLE_TESTS=properties`nFILE=trusted fixture.bin`n")
    $report = Join-Path $run 'report with spaces.json'
    $result = Run-Scanner @('--check','--quiet','--json',$report)
    $json = [IO.File]::ReadAllText($report) | ConvertFrom-Json
    Assert-Result ($result.Code -eq 1 -and $json.Counts.Warning -ge 1 -and -not (Test-Path -LiteralPath (Join-Path $install 'state\rkhunter.dat.json'))) 'first scan warns and does not create trust automatically'

    $result = Run-Scanner @('--propupd')
    Assert-Result ($result.Code -eq 0) ("explicit baseline creation succeeds: " + $result.Output)
    $result = Run-Scanner @('--check','--quiet','--json',$report)
    $json = [IO.File]::ReadAllText($report) | ConvertFrom-Json
    Assert-Result ($result.Code -eq 0 -and $json.Counts.Warning -eq 0 -and $json.Counts.Error -eq 0) 'unchanged trusted files produce a clean property report'

    [IO.File]::WriteAllText($tracked, 'modified fixture content')
    $result = Run-Scanner @('--check','--quiet','--json',$report)
    $json = [IO.File]::ReadAllText($report) | ConvertFrom-Json
    Assert-Result ($result.Code -eq 1 -and @($json.Results | Where-Object { $_.Test -eq 'hashes' -and $_.Subject -eq $tracked -and $_.Status -eq 'Warning' }).Count -eq 1) 'real CLI detects modified content'

    $baselinePath = Join-Path $install 'state\rkhunter.dat.json'
    $before = [IO.File]::ReadAllText($baselinePath) | ConvertFrom-Json
    $result = Run-Scanner @('--propupd','trusted fixture.bin')
    $after = [IO.File]::ReadAllText($baselinePath) | ConvertFrom-Json
    Assert-Result ($result.Code -eq 0 -and $before.Files.Count -eq $after.Files.Count -and ($before.Accounts | ConvertTo-Json -Compress) -eq ($after.Accounts | ConvertTo-Json -Compress)) 'targeted property update preserves other files and account snapshots'
    $result = Run-Scanner @('--check','--quiet','--json',$report)
    Assert-Result ($result.Code -eq 0) 'targeted trust refresh is reflected in the next scan'

    $baselineHash = (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash
    $configHash = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
    $dataPath = Join-Path $install 'data\windows-indicators.json'
    $data = [IO.File]::ReadAllText($dataPath) | ConvertFrom-Json; $data.version = 'locally-reviewed-version'
    $data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $dataPath -Encoding UTF8
    $result = Invoke-Entry (Join-Path $root 'setup.cmd') @('--prefix',$install,'--no-path')
    Assert-Result ($result.Code -eq 0 -and (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash -eq $baselineHash -and (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -eq $configHash -and ([IO.File]::ReadAllText($dataPath) | ConvertFrom-Json).version -eq 'locally-reviewed-version' -and (Test-Path -LiteralPath ($config + '.dist'))) 'installer upgrade preserves trust, configuration and local indicators'

    $lock = [IO.File]::Open((Join-Path $install 'state\rkhunter.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $result = Run-Scanner @('--check','--quiet') }
    finally { $lock.Dispose() }
    Assert-Result ($result.Code -eq 2 -and $result.Output.Contains('lock')) 'concurrent use of the same database is rejected'

    $result = Run-Scanner @('--check','--quiet','--logfile',$config)
    Assert-Result ($result.Code -eq 2 -and (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -eq $configHash) 'output collision fails without modifying configuration'
    $result = Run-Scanner @('--definitely-invalid')
    Assert-Result ($result.Code -eq 2) 'invalid flags return a failure status through the batch launcher'
    Assert-Result ([Environment]::GetEnvironmentVariable('Path','User') -eq $userPathBefore) '--no-path leaves the real user PATH unchanged'
    Assert-Result ((Test-Path -LiteralPath (Join-Path $install 'rkhunter-admin.cmd')) -and (Test-Path -LiteralPath (Join-Path $install 'src\Rkhunter.Launcher.psm1'))) 'installation includes the Administrator launcher and elevation support'
    Write-Host "Integration: $script:passed passed. Artifacts: $run"
    exit 0
} catch {
    Write-Host ('FAIL ' + $_.Exception.Message + ' at ' + $_.ScriptStackTrace) -ForegroundColor Red
    if ($result) { Write-Host $result.Output }
    exit 1
}
