#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Rkhunter.Launcher.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'src\Rkhunter.Install.psm1') -Force -DisableNameChecking
$fixture = Join-Path $root ('test-results\launchers-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($fixture)
$script:passed = 0
function Assert-Result($Condition,[string]$Message) { if (-not $Condition) { throw $Message }; $script:passed++; Write-Host "PASS $Message" -ForegroundColor Green }
try {
    Assert-Result ((Add-RkhPathEntry '' 'C:\Tools\rkhunter') -eq 'C:\Tools\rkhunter') 'PATH registration handles an absent user PATH'
    $current = '%SystemRoot%\System32;C:\Other Tools'
    Assert-Result ((Add-RkhPathEntry $current 'C:\Tools\rkhunter') -eq ($current + ';C:\Tools\rkhunter')) 'PATH registration preserves existing variables and entries'
    $current = 'C:\Other;"C:\Tools\rkhunter\"'
    Assert-Result ((Add-RkhPathEntry $current 'c:\tools\RKHUNTER') -ceq $current) 'PATH registration does not duplicate quoted or differently cased entries'
    $current = '%LOCALAPPDATA%\Programs\rkhunter'
    Assert-Result ((Add-RkhPathEntry $current (Join-Path $env:LOCALAPPDATA 'Programs\rkhunter')) -ceq $current) 'PATH registration detects existing expandable entries'

    $entry = Join-Path $fixture 'harmless entry point.ps1'
    [IO.File]::WriteAllText($entry, @'
$output = $args[0]
$received = @($args | Select-Object -Skip 1)
[IO.File]::WriteAllText($output, (@{ Arguments=$received; WorkingDirectory=(Get-Location).Path } | ConvertTo-Json -Depth 4))
exit 1
'@)
    $report = Join-Path $fixture 'received arguments.json'
    $arguments = @($report,'space value','$(throw injected)',"'; exit 9; #",'back`tick','a"quoted"value','--quiet')
    $encoded = New-RkhElevationCommand $entry $arguments $fixture
    $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $engine -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
    $childExit = $LASTEXITCODE
    $received = [IO.File]::ReadAllText($report) | ConvertFrom-Json
    Assert-Result ($childExit -eq 1) 'elevated command payload preserves the scanner exit code'
    Assert-Result ($received.WorkingDirectory -eq $fixture) 'elevated command payload preserves the caller working directory'
    Assert-Result (($received.Arguments | ConvertTo-Json -Compress) -ceq (@($arguments | Select-Object -Skip 1) | ConvertTo-Json -Compress)) 'quotes, spaces and code-like arguments remain literal data'

    $launcher = Get-Module Rkhunter.Launcher
    $mockResult = & $launcher {
        param($Entry,$Working)
        function Start-Process {
            param($FilePath,$Verb,$ArgumentList,$WorkingDirectory,[switch]$Wait,[switch]$PassThru,$ErrorAction)
            if ($Verb -ne 'RunAs' -or -not $Wait -or -not $PassThru -or $WorkingDirectory -ne $Working) { throw 'Invalid elevation parameters' }
            $script:CapturedElevation = $ArgumentList
            [pscustomobject]@{ ExitCode=7 }
        }
        $code = Request-RkhElevation $Entry @('--check','--quiet') $Working
        [pscustomobject]@{ Code=$code; Arguments=$script:CapturedElevation }
    } $entry $fixture
    Assert-Result ($mockResult.Code -eq 7 -and $mockResult.Arguments[-2] -eq '-EncodedCommand') 'UAC launcher requests RunAs and returns the elevated exit code (mocked; no UAC prompt)'
    $cancelled = & $launcher {
        param($Entry,$Working)
        function Start-Process { throw [ComponentModel.Win32Exception]::new(1223) }
        try { Request-RkhElevation $Entry @('--check') $Working; return $false }
        catch { return $_.Exception.Message.Contains('cancelled') }
    } $entry $fixture
    Assert-Result $cancelled 'cancelling UAC returns an explicit cancellation error (mocked)'
    Write-Host "Launcher tests: $script:passed passed. Artifacts: $fixture"
    exit 0
} catch {
    Write-Host ('FAIL ' + $_.Exception.Message + ' at ' + $_.ScriptStackTrace) -ForegroundColor Red
    exit 1
}
