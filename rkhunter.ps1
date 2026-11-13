#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
# Windows entry point. No param block: preserve the original GNU-style switches.
$ErrorActionPreference = 'Stop'
try {
    $cli = @($args)
    if ('--admin' -in $cli) {
        Import-Module (Join-Path $PSScriptRoot 'src\Rkhunter.Launcher.psm1') -Force -DisableNameChecking
        $cli = @($cli | Where-Object { $_ -ne '--admin' })
        if (-not $cli.Count) { $cli = @('--check') }
        if (-not (Test-RkhAdministrator)) {
            $code = Request-RkhElevation -EntryPoint $PSCommandPath -Arguments $cli -WorkingDirectory (Get-Location).ProviderPath
            exit $code
        }
    }
    Import-Module (Join-Path $PSScriptRoot 'src\Rkhunter.psm1') -Force -DisableNameChecking
    $code = Invoke-Rkhunter -Arguments $cli -Root $PSScriptRoot
    exit $code
} catch {
    [Console]::Error.WriteLine(('rkhunter: ' + $_.Exception.Message))
    exit 2
}
