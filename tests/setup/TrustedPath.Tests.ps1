# Portable checks of the ownership scan over live, service-writable data trees.
# Running services create and remove transient files there while Setup scans them:
# Core's SQLite rollback journal and the Agent's atomic-write temporaries. The scan
# must skip only a listed entry the file system reports missing, and still fail
# closed on links, hard links, foreign owners and foreign write access, whatever
# the name. Owners and ACLs are synthetic; link counts are real on Windows (the
# native helper) and come from the file system's own link type elsewhere.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:checks = 0
$script:onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$script:coreSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'
$script:transientName = '\A(?:sentinelai\.db-journal|\.event-checkpoints\.[0-9a-f]{32}\.tmp)\z'
$script:hook = $null
$script:owners = @{}
$script:rules = @{}
$script:aclFailures = @{}
$script:inspected = New-Object 'System.Collections.Generic.List[string]'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-trusted-path-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null

function Assert-TrustedPathTest([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw ('Trusted path regression: ' + $Label) }
    $script:checks++
}
function Reject-TrustedPathTest([scriptblock]$Operation, [string]$Expected, [string]$Label) {
    $message = $null
    try { & $Operation | Out-Null } catch { $message = $_.Exception.Message }
    Assert-TrustedPathTest ($null -ne $message -and ($Expected.Length -eq 0 -or $message -ceq $Expected)) ($Label + ' (got: ' + $message + ')')
}

function Import-TrustedPathTestFunctions([string]$Path, [hashtable]$Names) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'The source policy could not be parsed.' }
    foreach ($name in $Names.Keys) {
        $node = $ast.Find({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -ceq $name }, $true)
        if ($null -eq $node) { throw ('Missing source policy: ' + $name) }
        $text = $node.Extent.Text.Replace(('function ' + $name), ('function script:' + $Names[$name]))
        # The policy compares Windows paths by their '\' separator. Windows runs it
        # unchanged; elsewhere only that separator literal maps to the platform's.
        if (-not $script:onWindows) { $text = $text.Replace("'\'", "'/'") }
        Invoke-Expression $text
    }
}
Import-TrustedPathTestFunctions (Join-Path $repo 'installer/pilot/PilotInstaller.psm1') @{
    'Assert-PilotTrustedPath' = 'Assert-PilotTrustedPath'; 'Initialize-PilotNativeHelpers' = 'Initialize-PilotNativeHelpers'
    'Get-PilotAcl' = 'Get-PilotAclSource'; 'Get-PilotTrustedAccountSids' = 'Get-PilotTrustedAccountSids'
    'Get-PilotOperatorAccessSid' = 'Get-PilotOperatorAccessSid'; 'Set-PilotLegacyOperatorSid' = 'Set-PilotLegacyOperatorSid'
    'Set-PilotSharedProgramsWriterSid' = 'Set-PilotSharedProgramsWriterSid' }
$script:SharedProgramsWriterSid = $null
$script:ServiceSid = 'S-1-5-19'
$script:AdministratorsSid = 'S-1-5-32-544'
$script:SystemSid = 'S-1-5-18'
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Setup loads the module administrators-only; the console pilot's operator access is checked separately below.
$script:OperatorAccess = $false
$script:LegacyOperatorSid = $null
$script:operatorSid = 'S-1-5-21-1000-1000-1000-1001'
$script:legacySid = 'S-1-5-21-2000-2000-2000-1002'

# OS boundary stubs. The test hook runs after a directory is listed and before each
# inspection, and can remove or replace an entry there, as a running service would.
function Invoke-TrustedPathHook([string]$Stage, [string]$Path) { if ($null -ne $script:hook) { & $script:hook $Stage $Path } }
function Get-PilotCurrentOperatorSid { return $script:operatorSid }
$script:sharedPrograms = ''
function Get-PilotSharedProgramsPath { return $script:sharedPrograms }
function Get-ChildItem {
    param([string]$LiteralPath, [switch]$Force)
    $children = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force)
    foreach ($child in $children) { Invoke-TrustedPathHook 'listed' $child.FullName }
    return $children
}
function Get-PilotHardLinkCount {
    param([string]$Path)
    Invoke-TrustedPathHook 'links' $Path
    if ($script:onWindows) { return [SentinelAI.Pilot.Native]::GetLinkCount($Path) }
    # Elsewhere the file system's own link type stands in for the native count, and a
    # missing file is reported as the native helper reports it.
    try { $type = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force).LinkType }
    catch [Management.Automation.ItemNotFoundException] { throw (New-Object IO.FileNotFoundException('Cannot inspect file links.', $Path)) }
    if ($type -ceq 'HardLink') { return [uint32]2 }
    return [uint32]1
}
function Get-PilotAcl {
    param([string]$Path, [bool]$Container)
    Invoke-TrustedPathHook 'acl' $Path
    if ($script:aclFailures.ContainsKey($Path)) { throw $script:aclFailures[$Path] }
    # Like the access control API, a missing entry is reported as not found.
    if ($Container -and -not [IO.Directory]::Exists($Path)) { throw (New-Object IO.DirectoryNotFoundException($Path)) }
    if (-not $Container -and -not [IO.File]::Exists($Path)) { throw (New-Object IO.FileNotFoundException('Could not find file.', $Path)) }
    $script:inspected.Add($Path)
    $acl = [pscustomobject]@{ Owner = $(if ($script:owners.ContainsKey($Path)) { $script:owners[$Path] } else { $script:AdministratorsSid })
        Rules = $(if ($script:rules.ContainsKey($Path)) { @($script:rules[$Path]) } else { @() }) }
    $acl | Add-Member -MemberType ScriptMethod -Name GetOwner -Value { param($Type) [pscustomobject]@{ Value = $this.Owner } }
    $acl | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value { param($Explicit, $Inherited, $Type) $this.Rules }
    return $acl
}
function New-TrustedPathTestRule([string]$Sid, [Security.AccessControl.FileSystemRights]$Rights) {
    return [pscustomobject]@{ AccessControlType = [Security.AccessControl.AccessControlType]::Allow
        PropagationFlags = [Security.AccessControl.PropagationFlags]::None; FileSystemRights = $Rights
        IdentityReference = [pscustomobject]@{ Value = $Sid } }
}
function New-TrustedPathTestReparsePoint([string]$Path, [string]$Target) {
    # A junction needs no symbolic-link privilege on Windows; both are reparse points.
    if ($script:onWindows) { New-Item -ItemType Junction -Path $Path -Target $Target | Out-Null }
    else { New-Item -ItemType SymbolicLink -Path $Path -Target $Target | Out-Null }
}

# A Core and an Agent data tree as running services leave them, each with one
# transient file that the owning service is about to remove.
function New-TrustedPathTestFixture {
    $root = Join-Path $testRoot ([Guid]::NewGuid().ToString('N'))
    $core = Join-Path $root 'Core'; $agent = Join-Path $root 'Agent'
    New-Item -ItemType Directory -Path $core, $agent | Out-Null
    foreach ($name in @('pilot-config.json', 'pilot-installation.json', 'core-service-installation.json', 'sentinelai.db', 'sentinelai.db-journal')) {
        [IO.File]::WriteAllText((Join-Path $core $name), 'synthetic')
    }
    $checkpoint = '.event-checkpoints.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    foreach ($name in @('pilot-config.json', 'pilot-installation.json', 'endpoint-id', 'installation-id', 'enrollment-state', 'event-checkpoints', $checkpoint)) {
        [IO.File]::WriteAllText((Join-Path $agent $name), 'synthetic')
    }
    $script:owners = @{}; $script:rules = @{}; $script:aclFailures = @{}; $script:hook = $null
    $script:inspected.Clear()
    $script:owners[(Join-Path $core 'sentinelai.db')] = $script:coreSid
    $script:owners[(Join-Path $core 'sentinelai.db-journal')] = $script:coreSid
    foreach ($name in @('event-checkpoints', $checkpoint)) { $script:owners[(Join-Path $agent $name)] = $script:ServiceSid }
    return [pscustomobject]@{ Core = $core; Agent = $agent; Journal = Join-Path $core 'sentinelai.db-journal'; Checkpoint = Join-Path $agent $checkpoint }
}
# The exact scans the Setup lifecycle runs over the live data trees.
function Assert-TrustedPathTestCore($Fixture) { Assert-PilotTrustedPath -Path $Fixture.Core -Tree -AllowServiceWrite -ServiceWriteSid $script:coreSid -ServiceWriteRoot $Fixture.Core }
function Assert-TrustedPathTestAgent($Fixture) { Assert-PilotTrustedPath -Path $Fixture.Agent -Tree -AllowServiceWrite }
function Get-TrustedPathTestEntries([string]$Directory) { return @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Directory -Force | ForEach-Object { $_.FullName }) }

try {
    # The native link helper still compiles everywhere; Windows uses it below for real.
    Initialize-PilotNativeHelpers
    Assert-TrustedPathTest ($null -ne ('SentinelAI.Pilot.Native' -as [type])) 'The native link helper does not compile.'
    if ($script:onWindows) {
        # A service writes its temporaries with FileShare.None. Counting links must
        # not need data access, so an exclusively held file is still inspected.
        $held = Join-Path $testRoot 'held.tmp'
        $stream = New-Object IO.FileStream($held, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Assert-TrustedPathTest ([SentinelAI.Pilot.Native]::GetLinkCount($held) -eq 1) 'An exclusively held file was not inspected.' }
        finally { $stream.Dispose() }
        $linked = Join-Path $testRoot 'held.link'
        New-Item -ItemType HardLink -Path $linked -Target $held | Out-Null
        Assert-TrustedPathTest ([SentinelAI.Pilot.Native]::GetLinkCount($held) -eq 2) 'A real hard link was not counted.'
        # Missing entries are reported as not found, and only as not found.
        $missing = $null
        try { [void][SentinelAI.Pilot.Native]::GetLinkCount((Join-Path $testRoot 'missing.tmp')) } catch { $missing = $_.Exception.GetBaseException() }
        Assert-TrustedPathTest ($missing -is [IO.FileNotFoundException]) 'The native helper did not report a missing file as not found.'
        Assert-TrustedPathTest ($null -ne (Get-PilotAclSource -Path $held -Container $false).GetOwner([Security.Principal.SecurityIdentifier])) 'The access control of a file was not read.'
        $missing = $null
        try { [void](Get-PilotAclSource -Path (Join-Path $testRoot 'missing.tmp') -Container $false) } catch { $missing = $_.Exception.GetBaseException() }
        Assert-TrustedPathTest ($missing -is [IO.FileNotFoundException]) 'The access control read did not report a missing file as not found.'
        $missing = $null
        try { [void](Get-PilotAclSource -Path (Join-Path $testRoot 'missing') -Container $true) } catch { $missing = $_.Exception.GetBaseException() }
        Assert-TrustedPathTest ($missing -is [IO.DirectoryNotFoundException]) 'The access control read did not report a missing directory as not found.'
    }

    # Live trees with service-owned transient files pass and every entry is inspected.
    $fixture = New-TrustedPathTestFixture
    Assert-TrustedPathTestCore $fixture
    Assert-TrustedPathTestAgent $fixture
    foreach ($entry in (Get-TrustedPathTestEntries $fixture.Core) + (Get-TrustedPathTestEntries $fixture.Agent)) {
        Assert-TrustedPathTest ($script:inspected.Contains($entry)) ('A data tree entry was not inspected: ' + $entry)
    }

    # Reproduction: the transient file vanishes after the directory was listed, before
    # each inspection step. The scan skips only that entry and inspects the rest.
    foreach ($stage in @('listed', 'links', 'acl')) {
        foreach ($tree in @('Core', 'Agent')) {
            $fixture = New-TrustedPathTestFixture
            $directory = $fixture.$tree
            $transient = if ($tree -ceq 'Core') { $fixture.Journal } else { $fixture.Checkpoint }
            $others = @(Get-TrustedPathTestEntries $directory | Where-Object { $_ -cne $transient })
            $script:vanishStage = $stage; $script:vanishPath = $transient; $script:vanished = $false
            $script:hook = {
                param($Stage, $Path)
                if ($Stage -ceq $script:vanishStage -and $Path -ceq $script:vanishPath -and [IO.File]::Exists($Path)) {
                    [IO.File]::Delete($Path); $script:vanished = $true
                }
            }
            if ($tree -ceq 'Core') { Assert-TrustedPathTestCore $fixture } else { Assert-TrustedPathTestAgent $fixture }
            Assert-TrustedPathTest $script:vanished ('The ' + $tree + ' transient file was not removed at ' + $stage + '.')
            Assert-TrustedPathTest (-not $script:inspected.Contains($transient)) ('A vanished ' + $tree + ' entry was reported as inspected at ' + $stage + '.')
            foreach ($entry in $others) { Assert-TrustedPathTest ($script:inspected.Contains($entry)) ('A vanished ' + $tree + ' entry at ' + $stage + ' stopped the scan of ' + $entry) }
        }
    }
    # The same name created again after listing is a new entry and is inspected.
    $fixture = New-TrustedPathTestFixture
    $script:vanishPath = $fixture.Journal; $script:recreated = $false
    $script:hook = {
        param($Stage, $Path)
        if ($Stage -ceq 'listed' -and $Path -ceq $script:vanishPath -and -not $script:recreated) {
            [IO.File]::Delete($Path); [IO.File]::WriteAllText($Path, 'next transaction'); $script:recreated = $true
        }
    }
    Assert-TrustedPathTestCore $fixture
    Assert-TrustedPathTest ($script:recreated -and $script:inspected.Contains($fixture.Journal)) 'A recreated Core journal was not inspected.'

    # Only listed entries may vanish: the requested path and its ancestors fail closed.
    $fixture = New-TrustedPathTestFixture
    $script:vanishPath = $fixture.Core
    $script:hook = { param($Stage, $Path) if ($Stage -ceq 'acl' -and $Path -ceq $script:vanishPath -and [IO.Directory]::Exists($Path)) { [IO.Directory]::Delete($Path, $true) } }
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } '' 'A vanished scan root was skipped.'
    $fixture = New-TrustedPathTestFixture
    $script:vanishPath = [IO.Path]::GetDirectoryName($fixture.Agent)
    $script:hook = { param($Stage, $Path) if ($Stage -ceq 'acl' -and $Path -ceq $script:vanishPath) { throw (New-Object IO.DirectoryNotFoundException($Path)) } }
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } '' 'A missing ancestor was skipped.'

    # An entry whose inspection fails for any other reason is never skipped.
    $fixture = New-TrustedPathTestFixture
    $script:aclFailures[$fixture.Checkpoint] = New-Object UnauthorizedAccessException('Access to the path is denied.')
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'Access to the path is denied.' 'An uninspectable Agent temporary was skipped.'
    $fixture = New-TrustedPathTestFixture
    $script:aclFailures[$fixture.Journal] = New-Object IO.IOException('The process cannot access the file because it is being used by another process.')
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } 'The process cannot access the file because it is being used by another process.' 'An uninspectable Core journal was skipped.'
    $fixture = New-TrustedPathTestFixture
    $script:aclFailures[$fixture.Journal] = New-Object Management.Automation.ItemNotFoundException('Cannot find path because it does not exist.')
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } 'Cannot find path because it does not exist.' 'A Core journal reported missing only by PowerShell was skipped.'

    # Transient names get no exemption: links, hard links, foreign owners and
    # foreign write access fail closed, including on an entry replaced after listing.
    $fixture = New-TrustedPathTestFixture
    [IO.File]::Delete($fixture.Journal)
    New-Item -ItemType HardLink -Path $fixture.Journal -Target (Join-Path $fixture.Core 'sentinelai.db') | Out-Null
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } 'Hard-linked files are unsupported.' 'A hard-linked Core journal was accepted.'
    $fixture = New-TrustedPathTestFixture
    $script:vanishPath = $fixture.Checkpoint; $script:linkTarget = Join-Path $fixture.Agent 'enrollment-state'; $script:replaced = $false
    $script:hook = {
        param($Stage, $Path)
        if ($Stage -ceq 'listed' -and $Path -ceq $script:vanishPath -and -not $script:replaced) {
            [IO.File]::Delete($Path); New-Item -ItemType HardLink -Path $Path -Target $script:linkTarget | Out-Null; $script:replaced = $true
        }
    }
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'Hard-linked files are unsupported.' 'An Agent temporary replaced by a hard link after listing was accepted.'
    $fixture = New-TrustedPathTestFixture
    $target = Join-Path $fixture.Agent 'linked-target'
    New-Item -ItemType Directory -Path $target | Out-Null
    [IO.File]::Delete($fixture.Checkpoint)
    New-TrustedPathTestReparsePoint $fixture.Checkpoint $target
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'Links and reparse points are unsupported.' 'A linked Agent temporary was accepted.'
    # A dangling link still exists, so it is rejected rather than taken as vanished.
    [IO.Directory]::Delete($target)
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'Links and reparse points are unsupported.' 'A dangling linked Agent temporary was accepted.'
    $fixture = New-TrustedPathTestFixture
    $script:owners[$fixture.Journal] = 'S-1-5-32-545'
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } 'An existing installation path has an untrusted owner. Provision a protected location first.' 'A Core journal with a foreign owner was accepted.'
    $fixture = New-TrustedPathTestFixture
    $script:owners[$fixture.Journal] = $script:ServiceSid
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } 'An existing installation path has an untrusted owner. Provision a protected location first.' 'A Core journal owned by another service was accepted.'
    $fixture = New-TrustedPathTestFixture
    $script:owners[$fixture.Checkpoint] = 'S-1-5-32-545'
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'An existing installation path has an untrusted owner. Provision a protected location first.' 'An Agent temporary with a foreign owner was accepted.'
    $fixture = New-TrustedPathTestFixture
    $script:rules[$fixture.Checkpoint] = @(New-TrustedPathTestRule 'S-1-5-32-545' ([Security.AccessControl.FileSystemRights]::Modify))
    Reject-TrustedPathTest { Assert-TrustedPathTestAgent $fixture } 'An existing installation path grants write access outside the trusted installer accounts.' 'An Agent temporary writable by Users was accepted.'

    # Administrators only: the account running maintenance is no writer or owner of an installation,
    # because its own non-elevated programs could otherwise change what the services run.
    $untrustedOwner = 'An existing installation path has an untrusted owner. Provision a protected location first.'
    $untrustedWriter = 'An existing installation path grants write access outside the trusted installer accounts.'
    $fixture = New-TrustedPathTestFixture
    $script:rules[$fixture.Core] = @(New-TrustedPathTestRule $script:operatorSid ([Security.AccessControl.FileSystemRights]::FullControl))
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedWriter 'The current operator was trusted as a Core data writer.'
    $fixture = New-TrustedPathTestFixture
    $script:owners[(Join-Path $fixture.Core 'pilot-config.json')] = $script:operatorSid
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedOwner 'The current operator was trusted as a Core configuration owner.'
    $fixture = New-TrustedPathTestFixture
    $script:rules[[IO.Path]::GetDirectoryName($fixture.Core)] = @(New-TrustedPathTestRule $script:operatorSid ([Security.AccessControl.FileSystemRights]::FullControl))
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedWriter 'The current operator was trusted as a writer of a shared root.'
    # The console pilot alone grants its installing operator, so only there that account is trusted.
    $script:OperatorAccess = $true
    try {
        Assert-TrustedPathTest ((@(Get-PilotTrustedAccountSids) -join ',') -ceq $script:operatorSid -and (@(Get-PilotOperatorAccessSid) -join ',') -ceq $script:operatorSid) 'The console pilot did not trust its operator.'
        $fixture = New-TrustedPathTestFixture
        $script:rules[$fixture.Core] = @(New-TrustedPathTestRule $script:operatorSid ([Security.AccessControl.FileSystemRights]::FullControl))
        Assert-TrustedPathTestCore $fixture
        Reject-TrustedPathTest { Set-PilotLegacyOperatorSid -Sid $script:legacySid } 'Invalid legacy installation account.' 'The console pilot accepted a legacy installation account.'
    } finally { $script:OperatorAccess = $false }
    Assert-TrustedPathTest (@(Get-PilotTrustedAccountSids).Count -eq 0 -and @(Get-PilotOperatorAccessSid).Count -eq 0) 'An administrators-only installation trusted an account.'

    # Setup maintenance accepts the one account an earlier central installation granted, until it is removed:
    # whoever installed it, never the account running maintenance by itself, never a second account.
    foreach ($sid in @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11', 'S-1-5-18', 'S-1-5-21-1-2-3', 'S-1-5-21-1-2-3-4-5', 'S-1-5-80-1-2-3-4-5', 's-1-5-21-1-2-3-4', 'S-1-5-21-1-2-3-4 ')) {
        Reject-TrustedPathTest { Set-PilotLegacyOperatorSid -Sid $sid } 'Invalid legacy installation account.' ('A group, built-in or malformed legacy account was accepted: ' + $sid)
    }
    Assert-TrustedPathTest ($null -eq $script:LegacyOperatorSid) 'A rejected legacy account was kept.'
    Set-PilotLegacyOperatorSid -Sid 'S-1-12-1-100-200-300-400'
    Assert-TrustedPathTest ($script:LegacyOperatorSid -ceq 'S-1-12-1-100-200-300-400') 'A Microsoft Entra legacy account was not accepted.'
    Set-PilotLegacyOperatorSid -Sid $script:legacySid
    try {
        $fixture = New-TrustedPathTestFixture
        $script:rules[$fixture.Core] = @(New-TrustedPathTestRule $script:legacySid ([Security.AccessControl.FileSystemRights]::FullControl))
        $script:rules[[IO.Path]::GetDirectoryName($fixture.Core)] = @(New-TrustedPathTestRule $script:legacySid ([Security.AccessControl.FileSystemRights]::FullControl))
        $script:owners[(Join-Path $fixture.Core 'pilot-config.json')] = $script:legacySid
        Assert-TrustedPathTestCore $fixture
        $fixture = New-TrustedPathTestFixture
        $script:rules[$fixture.Core] = @((New-TrustedPathTestRule $script:legacySid ([Security.AccessControl.FileSystemRights]::FullControl)),
            (New-TrustedPathTestRule 'S-1-5-21-3000-3000-3000-1003' ([Security.AccessControl.FileSystemRights]::FullControl)))
        Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedWriter 'A second account was trusted beside the legacy account.'
        $fixture = New-TrustedPathTestFixture
        $script:rules[$fixture.Core] = @(New-TrustedPathTestRule $script:operatorSid ([Security.AccessControl.FileSystemRights]::FullControl))
        Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedWriter 'The current operator was trusted during legacy maintenance.'
    } finally { Set-PilotLegacyOperatorSid -Sid $null }
    Assert-TrustedPathTest ($null -eq $script:LegacyOperatorSid) 'The legacy account was not cleared.'
    $fixture = New-TrustedPathTestFixture
    $script:rules[$fixture.Core] = @(New-TrustedPathTestRule $script:legacySid ([Security.AccessControl.FileSystemRights]::FullControl))
    Reject-TrustedPathTest { Assert-TrustedPathTestCore $fixture } $untrustedWriter 'A cleared legacy account was still trusted.'

    # Windows' shared Start Menu Programs folder may be writable by the account running Setup, and only that
    # folder, only as a parent, only as a writer: never as owner, never another account, never Setup's own folder.
    $fixture = New-TrustedPathTestFixture
    $programs = Join-Path ([IO.Path]::GetDirectoryName($fixture.Core)) 'Programs'
    $menu = Join-Path $programs 'SentinelAI'
    New-Item -ItemType Directory -Path $menu | Out-Null
    [IO.File]::WriteAllText((Join-Path $menu 'SentinelAI.lnk'), 'synthetic')
    $script:sharedPrograms = $programs
    try {
        $writable = [Security.AccessControl.FileSystemRights]::Modify
        $script:rules[$programs] = @(New-TrustedPathTestRule $script:operatorSid $writable)
        Assert-PilotTrustedPath -Path $menu -Tree
        Assert-PilotTrustedPath -Path (Join-Path $programs 'NotYetCreated')
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $programs } $untrustedWriter 'The shared Programs folder was trusted as a target rather than a parent.'
        $script:rules[$programs] = @(New-TrustedPathTestRule 'S-1-5-21-3000-3000-3000-1003' $writable)
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'Another account was trusted on the shared Programs folder.'
        # MVP-7: the nightly upgrade (SYSTEM) accepts the one account an administrator's Setup recorded, there only.
        Set-PilotSharedProgramsWriterSid -Sid 'S-1-5-21-3000-3000-3000-1003'
        try {
            Assert-PilotTrustedPath -Path $menu -Tree
            $script:rules[$menu] = @(New-TrustedPathTestRule 'S-1-5-21-3000-3000-3000-1003' $writable)
            Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'The recorded Start Menu account was trusted on Setup''s own Start Menu folder.'
            $script:rules.Remove($menu)
            $script:owners[$programs] = 'S-1-5-21-3000-3000-3000-1003'
            Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedOwner 'The recorded Start Menu account was trusted as owner of the shared Programs folder.'
            $script:owners.Remove($programs)
            Reject-TrustedPathTest { Set-PilotSharedProgramsWriterSid -Sid 'S-1-5-32-545' } '' 'A group was accepted as the recorded Start Menu account.'
        } finally { Set-PilotSharedProgramsWriterSid -Sid $null }
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'A cleared Start Menu account record was still trusted.'
        $script:rules[$programs] = @(New-TrustedPathTestRule 'S-1-5-32-545' $writable)
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'Users were trusted on the shared Programs folder.'
        $script:rules.Remove($programs)
        $script:owners[$programs] = $script:operatorSid
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedOwner 'The account running Setup was trusted as owner of the shared Programs folder.'
        $script:owners.Remove($programs)
        $script:rules[$menu] = @(New-TrustedPathTestRule $script:operatorSid $writable)
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'The account running Setup was trusted on Setup''s own Start Menu folder.'
        $script:rules.Remove($menu)
        $parent = [IO.Path]::GetDirectoryName($programs)
        $script:rules[$parent] = @(New-TrustedPathTestRule $script:operatorSid $writable)
        Reject-TrustedPathTest { Assert-PilotTrustedPath -Path $menu -Tree } $untrustedWriter 'The account running Setup was trusted on a parent of the shared Programs folder.'
    } finally { $script:sharedPrograms = '' }

    # Live churn: a writer thread repeatedly creates, writes and removes the Core
    # journal and replaces the Agent checkpoint through an exclusive temporary file,
    # as the running services do, while both trees are scanned again and again.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
namespace SentinelAI.Tests {
    public sealed class TransientChurn : IDisposable {
        private readonly string core, agent;
        private readonly Thread thread;
        private volatile bool stopping;
        public long Cycles;
        public TransientChurn(string coreData, string agentData) {
            core = coreData; agent = agentData;
            thread = new Thread(Run) { IsBackground = true };
            thread.Start();
        }
        private void Run() {
            var bytes = new byte[512];
            while (!stopping) {
                try {
                    var journal = Path.Combine(core, "sentinelai.db-journal");
                    using (var stream = new FileStream(journal, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite)) stream.Write(bytes, 0, bytes.Length);
                    File.Delete(journal);
                    var temporary = Path.Combine(agent, ".event-checkpoints." + Guid.NewGuid().ToString("N") + ".tmp");
                    try {
                        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                            stream.Write(bytes, 0, bytes.Length);
                            stream.Flush(true);
                        }
                        File.Move(temporary, Path.Combine(agent, "event-checkpoints"), true);
                    } finally { if (File.Exists(temporary)) File.Delete(temporary); }
                    Interlocked.Increment(ref Cycles);
                } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        public void Dispose() { stopping = true; thread.Join(); }
    }
}
'@
    $fixture = New-TrustedPathTestFixture
    [IO.File]::Delete($fixture.Journal); [IO.File]::Delete($fixture.Checkpoint)
    $script:owners = @{}
    $script:listedTransient = 0
    $script:hook = { param($Stage, $Path) if ($Stage -ceq 'listed' -and [IO.Path]::GetFileName($Path) -cmatch $script:transientName) { $script:listedTransient++ } }
    $scans = 0
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $churn = New-Object SentinelAI.Tests.TransientChurn($fixture.Core, $fixture.Agent)
    try {
        while ($scans -lt 200 -and $elapsed.Elapsed.TotalSeconds -lt 10) {
            Assert-TrustedPathTestCore $fixture
            Assert-TrustedPathTestAgent $fixture
            $scans += 2
        }
    } finally { $churn.Dispose() }
    $inspectedTransient = @($script:inspected | Where-Object { [IO.Path]::GetFileName($_) -cmatch $script:transientName }).Count
    Assert-TrustedPathTest ($scans -gt 0 -and $churn.Cycles -gt 0) 'The live churn scan did not run.'
    Write-Output ('Live churn: {0} scans passed over {1} writer cycles; {2} transient entries were listed, {3} of them vanished before inspection.' -f
        $scans, $churn.Cycles, $script:listedTransient, ($script:listedTransient - $inspectedTransient))
    Write-Output ('Setup trusted path portable tests passed: ' + $script:checks + ' assertions.')
} finally {
    $script:hook = $null
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
