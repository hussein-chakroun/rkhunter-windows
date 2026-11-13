#requires -Version 5.1
# SPDX-License-Identifier: GPL-2.0-or-later
function Add-RkhPathEntry {
    param([AllowEmptyString()][string]$CurrentPath, [string]$Directory)
    $directoryKey = [Environment]::ExpandEnvironmentVariables($Directory).TrimEnd('\','/')
    foreach ($entry in ($CurrentPath -split ';')) {
        $key = [Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"')).TrimEnd('\','/')
        if ($key -eq $directoryKey) { return $CurrentPath }
    }
    if (-not $CurrentPath) { return $Directory }
    return ($CurrentPath.TrimEnd(';') + ';' + $Directory)
}

function Register-RkhUserPath([string]$Directory) {
    # Read raw registry text so expandable tokens in the user's PATH survive.
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $before = [string]$key.GetValue('Path','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $after = Add-RkhPathEntry $before $Directory
        if ($before -eq $after) { return }
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ('Path' -in $key.GetValueNames()) { $kind = $key.GetValueKind('Path') }
        $key.SetValue('Path',$after,$kind)
    } finally { $key.Dispose() }
    # Notify Explorer so newly launched terminals can inherit the new value.
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Rkhunter.Install {
    public static class EnvironmentNotification {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(IntPtr window, uint message,
            UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
    }
}
'@
        $result = [UIntPtr]::Zero
        $null = [Rkhunter.Install.EnvironmentNotification]::SendMessageTimeout([IntPtr]0xffff,0x1a,[UIntPtr]::Zero,'Environment',2,2000,[ref]$result)
    } catch { Write-Warning 'User PATH was saved. Sign out and back in if new terminals do not see the command.' }
}
Export-ModuleMember -Function Add-RkhPathEntry,Register-RkhUserPath
