#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
try {
    $prefix = Join-Path $env:LOCALAPPDATA 'Programs\rkhunter'
    $install = $false
    for ($i = 0; $i -lt $args.Count; $i++) {
        switch ($args[$i]) {
            '--install' { $install = $true }
            '--prefix' {
                $i++
                if ($i -ge $args.Count) { throw '--prefix requires a destination.' }
                $prefix = [IO.Path]::GetFullPath($args[$i])
            }
            '--help' { Write-Host 'Usage: .\installer.ps1 --install [--prefix DIRECTORY]'; exit 0 }
            default { throw "Unknown installer option: $($args[$i])" }
        }
    }
    if (-not $install) { Write-Host 'Usage: .\installer.ps1 --install [--prefix DIRECTORY]'; exit 0 }
    if ($prefix.TrimEnd('\') -eq $PSScriptRoot.TrimEnd('\')) { throw 'Installation destination must differ from the source directory.' }
    $current = $prefix
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installation destination cannot traverse a reparse point.' }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    $null = New-Item -ItemType Directory -Path $prefix -Force
    foreach ($dir in @('src','docs','tests','upstream')) {
        $dest = Join-Path $prefix $dir
        $null = New-Item -ItemType Directory -Path $dest -Force
        Copy-Item -Path (Join-Path $PSScriptRoot "$dir\*") -Destination $dest -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path (Join-Path $prefix 'data') -Force
    foreach ($name in @('backdoorports.dat','windows-indicators.json')) {
        $dest = Join-Path $prefix "data\$name"
        if (Test-Path -LiteralPath $dest) { $dest += '.dist' }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "data\$name") -Destination $dest -Force
    }
    foreach ($name in @('rkhunter.ps1','rkhunter.cmd','installer.ps1','README.md','LICENSE','NOTICE.md')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $prefix $name) -Force
    }
    $config = Join-Path $prefix 'rkhunter.conf'
    if (Test-Path -LiteralPath $config) { $config += '.dist' }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'rkhunter.conf') -Destination $config -Force
    Write-Host "Installed to $prefix"
    Write-Host 'Existing configuration, indicators and baseline were preserved. New defaults use .dist.'
    Write-Host 'After verifying the computer, run rkhunter.cmd --propupd, then rkhunter.cmd --check.'
    Write-Host 'No scheduled task or PATH modification was made.'
    exit 0
} catch {
    [Console]::Error.WriteLine(('installer: ' + $_.Exception.Message))
    exit 2
}
