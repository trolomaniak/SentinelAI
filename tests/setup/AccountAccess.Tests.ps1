# Native checks of removing an earlier central installation's account from real Windows ACLs, as Setup's
# maintenance does under Windows PowerShell 5.1 (its worker) and PowerShell 7. The module object and the
# lifecycle adapter are the real ones; the account is synthetic. Elsewhere Windows ACLs are unavailable.
#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'Setup account access tests need Windows ACLs; skipped on this platform.'
    return
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:checks = 0
function Assert-AccessTest([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw ('Account access regression: ' + $Label) }
    $script:checks++
}

# The administrators-only module object Setup's worker imports, and its lifecycle adapter.
$pilot = New-Module -Name AccessTestPilot -ArgumentList @($true) -ScriptBlock ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $repo 'installer/pilot/PilotInstaller.psm1'))))
Import-Module $pilot -DisableNameChecking
. (Join-Path $repo 'installer/setup/SetupLifecycle.ps1')

$admins = 'S-1-5-32-544'; $system = 'S-1-5-18'; $localService = 'S-1-5-19'; $users = 'S-1-5-32-545'
$coreSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'
$legacy = 'S-1-5-21-2000-2000-2000-1002'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $current = $identity.User.Value } finally { $identity.Dispose() }

# Rules are @(sid, rights[, type[, inheritance, propagation]]); directories inherit to all children by default.
function Set-AccessTestAcl([string]$Path, [object[]]$Rules, [switch]$Inherit, [string]$Owner = $admins) {
    $container = Test-Path -LiteralPath $Path -PathType Container
    $acl = if ($container) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection((-not $Inherit), $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($Owner)))
    foreach ($rule in $Rules) {
        $sid = New-Object Security.Principal.SecurityIdentifier($rule[0])
        $type = if ($rule.Count -gt 2) { $rule[2] } else { 'Allow' }
        if ($container) {
            $inheritance = if ($rule.Count -gt 3) { $rule[3] } else { 'ContainerInherit, ObjectInherit' }
            $propagation = if ($rule.Count -gt 4) { $rule[4] } else { 'None' }
            $entry = New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule[1], $inheritance, $propagation, $type)
        } else { $entry = New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule[1], $type) }
        $acl.AddAccessRule($entry)
    }
    Set-PilotAcl -Path $Path -Container $container -Acl $acl
}
function Get-AccessTestAcl([string]$Path) { return Get-PilotAcl -Path $Path -Container (Test-Path -LiteralPath $Path -PathType Container) }
function Get-AccessTestRules([string]$Path, [string]$Sid) {
    return @((Get-AccessTestAcl $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ceq $Sid })
}
function Get-AccessTestEntries($Locations) {
    $entries = @()
    foreach ($name in @('CodeRoot', 'Menu', 'InstallerCode', 'DataRoot')) {
        $entries += $Locations[$name]
        $entries += @(Get-ChildItem -LiteralPath $Locations[$name] -Recurse -Force | ForEach-Object { $_.FullName })
    }
    return $entries
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-account-access-' + [Guid]::NewGuid().ToString('N'))
$held = $null
$junction = $null
try {
    $locations = @{ CodeRoot = Join-Path $root 'ProgramFiles\SentinelAI'; InstallerCode = Join-Path $root 'ProgramFiles\SentinelAI Setup';
        Menu = Join-Path $root 'Programs\SentinelAI'; DataRoot = Join-Path $root 'ProgramData\SentinelAI' }
    $locations.CoreCode = Join-Path $locations.CodeRoot 'Core'
    foreach ($component in @('Core', 'Agent', 'Setup')) { $locations[$component + 'Data'] = Join-Path $locations.DataRoot $component }
    foreach ($directory in @($locations.InstallerCode, $locations.Menu, (Join-Path $locations.CoreCode 'runtimes'), $locations.CoreData, $locations.AgentData, $locations.SetupData)) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    $files = @{ Executable = Join-Path $locations.CoreCode 'SentinelAI.Core.exe'; Runtime = Join-Path $locations.CoreCode 'runtimes\native.dll'
        Configuration = Join-Path $locations.CoreData 'pilot-config.json'; Database = Join-Path $locations.CoreData 'sentinelai.db'
        Sidecar = Join-Path $locations.CoreData 'sentinelai.db-wal'; Enrollment = Join-Path $locations.AgentData 'enrollment-state'
        PublicKey = Join-Path $locations.SetupData 'public-key.pem'; Shortcut = Join-Path $locations.Menu 'SentinelAI.lnk'
        Installer = Join-Path $locations.InstallerCode 'SentinelAI-Setup.exe' }
    foreach ($path in $files.Values) { [IO.File]::WriteAllText($path, 'synthetic') }

    # The ACLs an earlier central installation left: its installing account on Core's folders and the shared roots.
    $roots = @(@($admins, 'FullControl'), @($system, 'FullControl'), @($legacy, 'FullControl'), @($localService, 'ReadAndExecute'))
    foreach ($path in @($locations.CodeRoot, $locations.DataRoot, $locations.SetupData)) { Set-AccessTestAcl $path $roots }
    $code = @(@($admins, 'FullControl'), @($system, 'FullControl'), @($legacy, 'FullControl'), @($coreSid, 'ReadAndExecute'))
    foreach ($path in @($locations.CoreCode, (Join-Path $locations.CoreCode 'runtimes'), $files.Executable, $files.Runtime)) { Set-AccessTestAcl $path $code }
    Set-AccessTestAcl $locations.CoreData @(@($admins, 'FullControl'), @($system, 'FullControl'), @($legacy, 'FullControl'),
        @($coreSid, 'ReadAndExecute, CreateFiles', 'Allow', 'None', 'None'), @($coreSid, 'Modify', 'Allow', 'ObjectInherit', 'InheritOnly'))
    Set-AccessTestAcl $files.Configuration @(@($admins, 'FullControl'), @($system, 'FullControl'), @($legacy, 'FullControl'), @($coreSid, 'Read'), @($legacy, 'Write', 'Deny'))
    # SQLite files the Core service creates inherit from its data directory.
    foreach ($path in @($files.Database, $files.Sidecar)) { Set-AccessTestAcl $path @() -Inherit }
    Set-AccessTestAcl $locations.AgentData @(@($admins, 'FullControl'), @($system, 'FullControl'), @($localService, 'Modify'))
    Set-AccessTestAcl $files.Enrollment @(@($admins, 'FullControl'), @($system, 'FullControl'), @($localService, 'Modify'))
    Set-AccessTestAcl $files.PublicKey @(@($admins, 'FullControl'), @($system, 'FullControl'))
    foreach ($path in @($locations.Menu, $locations.InstallerCode, $files.Shortcut, $files.Installer)) {
        Set-AccessTestAcl $path @(@($admins, 'FullControl'), @($system, 'FullControl'), @($users, 'ReadAndExecute'))
    }
    Assert-AccessTest (@(Get-AccessTestRules $files.Database $legacy).Count -gt 0 -and @(Get-AccessTestRules $files.Database $legacy)[0].IsInherited) 'The fixture did not inherit the account into Core''s database.'
    Assert-AccessTest ((Get-SetupLifecycleLegacyOperatorSid $locations) -ceq $legacy) 'The earlier installing account was not recognized on the real shared data root.'
    $before = @{}
    foreach ($path in Get-AccessTestEntries $locations) {
        $acl = Get-AccessTestAcl $path
        $before[$path] = @{ Protected = $acl.AreAccessRulesProtected
            Others = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -cne $legacy } |
                ForEach-Object { $_.IdentityReference.Value + '|' + [int]$_.FileSystemRights + '|' + $_.AccessControlType + '|' + $_.InheritanceFlags + '|' + $_.PropagationFlags + '|' + $_.IsInherited }) }
    }

    # A running service holds its SQLite sidecar exclusively; changing access needs no data access.
    $held = New-Object IO.FileStream($files.Sidecar, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    Remove-SetupLifecycleLegacyAccess $locations $legacy
    $held.Dispose(); $held = $null
    foreach ($path in Get-AccessTestEntries $locations) {
        $acl = Get-AccessTestAcl $path
        $allowed = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -ceq $legacy -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow })
        Assert-AccessTest ($allowed.Count -eq 0) ('The earlier installing account kept access: ' + $path)
        Assert-AccessTest ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $admins) ('An entry changed its owner: ' + $path)
        Assert-AccessTest ($acl.AreAccessRulesProtected -eq $before[$path].Protected) ('An entry changed its inheritance protection: ' + $path)
        $others = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -cne $legacy } |
            ForEach-Object { $_.IdentityReference.Value + '|' + [int]$_.FileSystemRights + '|' + $_.AccessControlType + '|' + $_.InheritanceFlags + '|' + $_.PropagationFlags + '|' + $_.IsInherited })
        Assert-AccessTest (($others -join ';') -ceq ($before[$path].Others -join ';')) ('Another access entry changed: ' + $path)
    }
    $deny = @(Get-AccessTestRules $files.Configuration $legacy)
    Assert-AccessTest ($deny.Count -eq 1 -and $deny[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) 'A deny entry for the account was removed or changed.'
    Assert-AccessTest ($null -eq (Get-SetupLifecycleLegacyOperatorSid $locations)) 'The shared data root still identifies the earlier installing account.'
    # Repeating the removal finds nothing to change.
    Remove-SetupLifecycleLegacyAccess $locations $legacy
    Assert-AccessTest (@(Get-AccessTestRules $locations.DataRoot $legacy).Count -eq 0) 'A repeated removal restored access.'

    # The account's ownership goes to Administrators; another account keeps its entry.
    $owned = Join-Path $root 'owned.json'
    [IO.File]::WriteAllText($owned, 'synthetic')
    Set-AccessTestAcl $owned @(@($admins, 'FullControl'), @($system, 'FullControl'), @($current, 'FullControl'), @($legacy, 'Read')) -Owner $current
    Remove-PilotAccountAccess -Path $owned -Sid $current
    $acl = Get-AccessTestAcl $owned
    Assert-AccessTest ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $admins) 'An account-owned entry was not given to Administrators.'
    Assert-AccessTest (@(Get-AccessTestRules $owned $current).Count -eq 0 -and @(Get-AccessTestRules $owned $legacy).Count -eq 1) 'Removal did not affect exactly one account.'

    # Installed code is owned by Administrators whichever account extracted it; access entries are unchanged.
    $extracted = Join-Path $root 'Extracted'
    [void][IO.Directory]::CreateDirectory((Join-Path $extracted 'runtimes'))
    foreach ($path in @((Join-Path $extracted 'SentinelAI.Agent.exe'), (Join-Path $extracted 'runtimes\native.dll'))) { [IO.File]::WriteAllText($path, 'synthetic') }
    foreach ($path in @((Join-Path $extracted 'runtimes'), (Join-Path $extracted 'SentinelAI.Agent.exe'), (Join-Path $extracted 'runtimes\native.dll'))) {
        Set-AccessTestAcl $path @(@($admins, 'FullControl'), @($system, 'FullControl'), @($localService, 'ReadAndExecute')) -Owner $current
    }
    $rules = (Get-AccessTestAcl (Join-Path $extracted 'SentinelAI.Agent.exe')).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]).Count
    Set-PilotAdministratorsOwner -Path $extracted
    foreach ($entry in @(Get-ChildItem -LiteralPath $extracted -Recurse -Force)) {
        Assert-AccessTest ((Get-AccessTestAcl $entry.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $admins) ('Extracted code kept its account owner: ' + $entry.FullName)
    }
    Assert-AccessTest ((Get-AccessTestAcl (Join-Path $extracted 'SentinelAI.Agent.exe')).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]).Count -eq $rules) 'Owner normalization changed access entries.'

    # A link stops the removal before anything reached through it is changed.
    $outside = Join-Path $root 'Outside'
    [void][IO.Directory]::CreateDirectory($outside)
    Set-AccessTestAcl $outside $roots
    $junction = Join-Path $locations.CoreCode 'linked'
    New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
    $message = $null
    try { Remove-SetupLifecycleLegacyAccess $locations $legacy } catch { $message = $_.Exception.Message }
    Assert-AccessTest ($message -ceq 'Links and reparse points are unsupported.') ('A linked entry was not refused (got: ' + $message + ')')
    Assert-AccessTest (@(Get-AccessTestRules $outside $legacy).Count -eq 1) 'An entry reached through a link was changed.'
    Write-Output ('Setup account access native tests passed: ' + $script:checks + ' assertions.')
} finally {
    if ($null -ne $held) { $held.Dispose() }
    # Remove the link itself first, never what it points to.
    if ($null -ne $junction -and (Test-Path -LiteralPath $junction)) { [IO.Directory]::Delete($junction) }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Module AccessTestPilot -ErrorAction SilentlyContinue
}
