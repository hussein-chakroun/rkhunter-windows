#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
# Windows entry point. No param block: preserve the original GNU-style switches.
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'src\Rkhunter.psm1') -Force -DisableNameChecking
    $code = Invoke-Rkhunter -Arguments @($args) -Root $PSScriptRoot
    exit $code
} catch {
    [Console]::Error.WriteLine(('rkhunter: ' + $_.Exception.Message))
    exit 2
}
