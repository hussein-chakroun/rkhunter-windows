#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
function Test-RkhAdministrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RkhElevationCommand {
    param([string]$EntryPoint, [string[]]$Arguments, [string]$WorkingDirectory)
    $request = @{
        EntryPoint = [IO.Path]::GetFullPath($EntryPoint)
        Arguments = @($Arguments)
        WorkingDirectory = $WorkingDirectory
        Pause = -not (@($Arguments | Where-Object { $_ -in @('--quiet','-q','--cronjob','--sk','--skip-keypress') }).Count)
    }
    # The only interpolated text is base64. Paths/arguments remain data, even
    # when they contain quotes, dollar signs, semicolons or PowerShell syntax.
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Compress -Depth 4)))
    $command = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$code = 2
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
try {
    Set-Location -LiteralPath $request.WorkingDirectory
    $arguments = @($request.Arguments)
    & $request.EntryPoint @arguments
    $code = $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine(('rkhunter: ' + $_.Exception.Message))
}
if ($request.Pause) { $null = Read-Host 'Press Enter to close this Administrator window' }
exit $code
'@
    $command = $command.Replace('__PAYLOAD__', $payload)
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
}

function Request-RkhElevation {
    param([string]$EntryPoint, [string[]]$Arguments, [string]$WorkingDirectory)
    $encoded = New-RkhElevationCommand $EntryPoint $Arguments $WorkingDirectory
    $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    # UAC is requested only by --admin. Wait/PassThru preserve the scan exit code.
    try {
        $process = Start-Process -FilePath $engine -Verb RunAs -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -WorkingDirectory $WorkingDirectory -Wait -PassThru -ErrorAction Stop
        return $process.ExitCode
    } catch {
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 1223) { throw 'Administrator request was cancelled. No elevated scan was started.' }
        throw
    }
}
Export-ModuleMember -Function Test-RkhAdministrator,New-RkhElevationCommand,Request-RkhElevation
