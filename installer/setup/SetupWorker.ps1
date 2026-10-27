# Trusted Setup bootstrap, loaded as an in-memory ScriptBlock by the Setup EXE.
# It does not change PowerShell execution, application-control or language policy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# The installer reports its own fixed progress markers. Suppress PowerShell's
# module-initialization progress, which WinPS can otherwise serialize to stderr.
$ProgressPreference = 'SilentlyContinue'
$script:SetupPhase = 'validate'

function Write-SetupProgress {
    param([ValidateSet('validate','core','services','network','agent','desktop','shortcut','inspect','replace','health','rollback','uninstall','updater','apps','enroll')][string]$Phase)
    $script:SetupPhase = $Phase
    Write-Output ('PROGRESS|' + $Phase)
}

function Read-SetupRequest {
    $builder = New-Object Text.StringBuilder
    while ($true) {
        $next = [Console]::In.Read()
        if ($next -eq -1 -or $next -eq 10) { break }
        if ($builder.Length -ge 8192) { throw 'Invalid request.' }
        [void]$builder.Append([char]$next)
    }
    if ($builder.Length -eq 0) { throw 'Invalid request.' }
    return $builder.ToString()
}

function Assert-SetupBootstrapDirectory {
    param([string]$Path)
    $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI-Setup'
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -cne [IO.Path]::GetFullPath($Path) -or
        [IO.Path]::GetDirectoryName($Path) -ine $root -or [IO.Path]::GetFileName($Path) -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Invalid staging path.' }
    foreach ($current in @($root, $Path)) {
        $item = Get-Item -LiteralPath $current -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid staging path.' }
        $acl = Get-Acl -LiteralPath $current
        if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Invalid staging owner.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Invalid staging ACL.' }
        }
    }
}

function Import-SetupInstallerModules {
    param([string]$WorkDirectory)
    foreach ($part in @('bundle\installer\PilotInstaller.psm1', 'bundle\installer\CoreServiceInstaller.psm1')) {
        $path = Join-Path $WorkDirectory $part
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or $item.Length -gt 262144 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid bootstrap module.' }
    }
    $pilotSource = [IO.File]::ReadAllText((Join-Path $WorkDirectory 'bundle\installer\PilotInstaller.psm1'))
    # Administrators only: Setup's installations name no Windows account in their ACLs and trust none.
    $pilot = New-Module -Name SentinelAISetupPilot -ArgumentList @($true) -ScriptBlock ([ScriptBlock]::Create($pilotSource))
    Import-Module $pilot -Global -DisableNameChecking
    # Pass the already authenticated bootstrap module object, not a file-selected import.
    $coreSource = [IO.File]::ReadAllText((Join-Path $WorkDirectory 'bundle\installer\CoreServiceInstaller.psm1'))
    $core = New-Module -Name SentinelAISetupCore -ArgumentList @($pilot) -ScriptBlock ([ScriptBlock]::Create($coreSource))
    Import-Module $core -Global -DisableNameChecking
    $lifecyclePath = Join-Path $WorkDirectory 'setup\SetupLifecycle.ps1'
    $item = Get-Item -LiteralPath $lifecyclePath -Force
    if ($item.PSIsContainer -or $item.Length -gt 262144 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid lifecycle worker.' }
    # This script is embedded with the same authenticated payload as the modules.
    . ([ScriptBlock]::Create([IO.File]::ReadAllText($lifecyclePath)))
    foreach ($command in Get-Command -Name '*-SetupLifecycle*') { Set-Item -Path ('Function:global:' + $command.Name) -Value $command.ScriptBlock }
}

function Get-SetupLocations {
    $code = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'SentinelAI'
    $data = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI'
    $menu = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'SentinelAI'
    return @{ CodeRoot = $code; DataRoot = $data; CoreCode = Join-Path $code 'Core'; CoreData = Join-Path $data 'Core';
        AgentCode = Join-Path $code 'Agent'; AgentData = Join-Path $data 'Agent';
        DesktopCode = Join-Path $code 'Desktop'; UpdaterCode = Join-Path $code 'Updater';
        SetupData = Join-Path $data 'Setup'; Menu = $menu;
        InstallerCode = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'SentinelAI Setup' }
}

function Assert-SetupFreshTargets {
    param($Locations, [switch]$AllowPreparedCore, [switch]$AllowStartedCore)
    foreach ($name in @('CoreCode','CoreData','AgentCode','AgentData','DesktopCode','UpdaterCode','SetupData','Menu')) {
        if ($AllowPreparedCore -and $name -in @('CoreCode','CoreData')) { continue }
        $path = Assert-PilotPath -Path $Locations[$name]
        Assert-PilotTrustedPath -Path $path -Tree
        if (Test-Path -LiteralPath $path) { throw 'Existing installation requires separate inspection.' }
    }
    if ($null -ne (Get-PilotService)) { throw 'Existing Agent service.' }
    # The completion phase follows the start phase, which added the owned rule of the central role.
    if (-not $AllowStartedCore -and $null -ne (Get-CoreServiceFirewallRule)) { throw 'Existing Core firewall rule.' }
    $core = Get-CoreService
    if (-not $AllowStartedCore -and $null -ne $core) { throw 'Existing Core service.' }
    if ($AllowStartedCore -and ($null -eq $core -or $core.State -cne 'Running')) { throw 'Prepared Core service unavailable.' }
}

function Set-SetupCodeAcl {
    param([string]$Path, [switch]$PublicRead)
    $item = Get-Item -LiteralPath $Path -Force
    $acl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-32-544','S-1-5-18')) {
        $args = if ($item.PSIsContainer) { @((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow') }
                else { @((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow') }
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList $args))
    }
    if ($PublicRead) {
        $args = if ($item.PSIsContainer) { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow') }
                else { @((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', 'Allow') }
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList $args))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Install-SetupAuxiliaryCode {
    param([string]$Source, [string]$Destination, [string]$Executable, [switch]$PublicRead)
    $Source = Assert-PilotPath -Path $Source -MustExist
    Assert-PilotTrustedPath -Path $Source -Tree
    [void](Assert-PilotPath -Path (Join-Path $Source $Executable) -MustExist -File)
    Assert-PilotTrustedPath -Path $Destination
    if (Test-Path -LiteralPath $Destination) { throw 'Existing code will not be overwritten.' }
    Ensure-PilotProtectedParent -Path ([IO.Path]::GetDirectoryName($Destination))
    New-PilotDirectoryWithAcl -Path $Destination -Kind Container
    foreach ($entry in @(Get-ChildItem -LiteralPath $Source -Recurse -Force | Sort-Object { $_.FullName.Length })) {
        $relative = $entry.FullName.Substring($Source.TrimEnd('\').Length + 1)
        $target = Join-Path $Destination $relative
        if ($entry.PSIsContainer) { New-PilotDirectoryWithAcl -Path $target -Kind Container; continue }
        $input = [IO.File]::Open($entry.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
        } finally { $input.Dispose() }
    }
    # Copy content only. Source/inherited ACLs never become installation authority.
    Set-SetupCodeAcl -Path $Destination -PublicRead:$PublicRead
    foreach ($entry in @(Get-ChildItem -LiteralPath $Destination -Recurse -Force)) { Set-SetupCodeAcl -Path $entry.FullName -PublicRead:$PublicRead }
    Assert-PilotTrustedPath -Path $Destination -Tree
}

function Install-SetupShortcut {
    param([string]$Directory, [string]$DesktopDirectory)
    Assert-PilotTrustedPath -Path $Directory
    if (Test-Path -LiteralPath $Directory) { throw 'Existing Start Menu entry.' }
    New-PilotDirectoryWithAcl -Path $Directory -Kind Container
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $path = Join-Path $Directory 'SentinelAI.lnk'
        $shortcut = $shell.CreateShortcut($path)
        $shortcut.TargetPath = Join-Path $DesktopDirectory 'SentinelAI.Desktop.exe'
        $shortcut.Arguments = ''
        $shortcut.WorkingDirectory = $DesktopDirectory
        $shortcut.Description = 'SentinelAI'
        $shortcut.Save()
        Set-SetupCodeAcl -Path $path -PublicRead
        Set-SetupCodeAcl -Path $Directory -PublicRead
        Assert-PilotTrustedPath -Path $Directory -Tree
    } finally {
        if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
}

# Windows Apps ("Installed apps") entries. Each one runs an installed copy of the very Setup EXE that installed the
# product, kept in an administrator-only folder, with /uninstall.
function Get-SetupAppsKeyPath {
    param([ValidateSet('SentinelAI','SentinelAIAgent')][string]$Key)
    return 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + $Key
}

function Register-SetupDeleteAtRestart {
    param([string]$Path)
    if ($null -eq ('SentinelAI.Setup.RestartDelete' -as [type])) {
        Add-Type -Namespace SentinelAI.Setup -Name RestartDelete -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool MoveFileExW(string existing, string replacement, int flags);'
    }
    # MOVEFILE_DELAY_UNTIL_REBOOT with no new name: Windows deletes the entry at the next restart.
    if (-not [SentinelAI.Setup.RestartDelete]::MoveFileExW($Path, [NullString]::Value, 4)) { throw 'Delayed removal unavailable.' }
}

function Remove-SetupOwnedTree {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Recurse -Force; return } catch { }
    # Only the installed Setup that Windows Apps started stays locked while it runs. A running program can be
    # renamed: it moves under a unique name into Setup's administrator-only folder, where Windows deletes it at
    # restart, so the product folders go now and nothing ever deletes a path a later installation reuses.
    $pending = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'SentinelAI-Setup'
    foreach ($entry in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File)) {
        if (-not (Test-Path -LiteralPath $entry.FullName)) { continue }
        try { Remove-Item -LiteralPath $entry.FullName -Force; continue } catch { }
        $target = Join-Path $pending ('removed-' + [Guid]::NewGuid().ToString('N') + '.exe')
        try {
            Assert-PilotTrustedPath -Path $pending
            Move-Item -LiteralPath $entry.FullName -Destination $target
            Register-SetupDeleteAtRestart -Path $target
        } catch { Register-SetupDeleteAtRestart -Path $entry.FullName }
    }
    try { Remove-Item -LiteralPath $Path -Recurse -Force }
    catch {
        foreach ($directory in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory | Sort-Object { $_.FullName.Length } -Descending)) {
            Register-SetupDeleteAtRestart -Path $directory.FullName
        }
        Register-SetupDeleteAtRestart -Path $Path
    }
}

function Install-SetupCachedInstaller {
    param([string]$Source, [string]$Directory, [string]$Name)
    $Source = Assert-PilotPath -Path $Source -MustExist -File
    Assert-PilotTrustedPath -Path $Source
    Assert-PilotTrustedPath -Path $Directory
    if (Test-Path -LiteralPath $Directory) {
        Assert-PilotTrustedPath -Path $Directory -Tree
        foreach ($entry in @(Get-ChildItem -LiteralPath $Directory -Force)) {
            if ($entry.PSIsContainer -or ($entry.Name -cne $Name -and $entry.Name -cnotmatch ('\A' + [Regex]::Escape($Name) + '\.[0-9a-f]{32}\.old\z'))) { throw 'Foreign installed Setup content.' }
        }
    } else {
        Ensure-PilotProtectedParent -Path ([IO.Path]::GetDirectoryName($Directory))
        New-PilotDirectoryWithAcl -Path $Directory -Kind Container
    }
    $target = Join-Path $Directory $Name
    # The complete new copy is written under a unique name first, so the installed Setup is never missing or partial.
    $next = $target + '.' + [Guid]::NewGuid().ToString('N') + '.old'
    $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $output = [IO.File]::Open($next, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $input.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
    } catch { if (Test-Path -LiteralPath $next) { Remove-Item -LiteralPath $next -Force }; throw }
    finally { $input.Dispose() }
    if (Test-Path -LiteralPath $target) {
        # A running installed Setup cannot be overwritten, only renamed: the old copy goes at restart if it is still in use.
        $aside = $target + '.' + [Guid]::NewGuid().ToString('N') + '.old'
        Move-Item -LiteralPath $target -Destination $aside
        try { Remove-Item -LiteralPath $aside -Force } catch { Register-SetupDeleteAtRestart -Path $aside }
    }
    Move-Item -LiteralPath $next -Destination $target
    Set-SetupCodeAcl -Path $target -PublicRead
    Set-SetupCodeAcl -Path $Directory -PublicRead
    Assert-PilotTrustedPath -Path $Directory -Tree
    return $target
}

function Register-SetupApps {
    param([ValidateSet('SentinelAI','SentinelAIAgent')][string]$Key, [string]$DisplayName, [string]$Version, [string]$Installer,
          [string]$InstallLocation, [string]$Icon, [switch]$QuietUninstall)
    $size = 0L
    $installerDirectory = [IO.Path]::GetDirectoryName($Installer)
    $roots = if ($installerDirectory.StartsWith($InstallLocation + '\', [StringComparison]::OrdinalIgnoreCase)) { @($InstallLocation) } else { @($InstallLocation, $installerDirectory) }
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) { foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Force -File)) { $size += $file.Length } }
    }
    $path = Get-SetupAppsKeyPath $Key
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    $item = New-Item -Path $path -Force
    $quoted = '"' + $Installer + '"'
    foreach ($value in @(@('DisplayName', $DisplayName), @('DisplayVersion', $Version), @('Publisher', 'SentinelAI'),
        @('InstallLocation', $InstallLocation), @('DisplayIcon', $Icon), @('UninstallString', ($quoted + ' /uninstall')))) {
        [void](New-ItemProperty -LiteralPath $path -Name $value[0] -Value $value[1] -PropertyType String)
    }
    if ($QuietUninstall) { [void](New-ItemProperty -LiteralPath $path -Name 'QuietUninstallString' -Value ($quoted + ' /uninstall /quiet') -PropertyType String) }
    foreach ($flag in @('NoModify','NoRepair')) { [void](New-ItemProperty -LiteralPath $path -Name $flag -Value 1 -PropertyType DWord) }
    [void](New-ItemProperty -LiteralPath $path -Name 'EstimatedSize' -Value ([int][Math]::Min([int]::MaxValue, [Math]::Ceiling($size / 1KB))) -PropertyType DWord)
    $item.Dispose()
}

function Unregister-SetupApps {
    param([ValidateSet('SentinelAI','SentinelAIAgent')][string]$Key)
    $path = Get-SetupAppsKeyPath $Key
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}

function Register-SetupFullApps {
    param($Locations, [string]$WorkDirectory, [string]$Version)
    $installer = Install-SetupCachedInstaller -Source (Join-Path $WorkDirectory 'installer\setup.exe') -Directory $Locations.InstallerCode -Name 'SentinelAI-Setup.exe'
    Register-SetupApps -Key SentinelAI -DisplayName 'SentinelAI' -Version $Version -Installer $installer -InstallLocation $Locations.CodeRoot `
        -Icon (Join-Path $Locations.DesktopCode 'SentinelAI.Desktop.exe')
}

function Unregister-SetupFullApps {
    param($Locations)
    Unregister-SetupApps -Key SentinelAI
    Assert-PilotTrustedPath -Path $Locations.InstallerCode -Tree
    if (Test-Path -LiteralPath $Locations.InstallerCode) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $Locations.InstallerCode -Force)) {
            if ($entry.PSIsContainer -or $entry.Name -cnotmatch '\ASentinelAI-Setup\.exe(\.[0-9a-f]{32}\.old)?\z') { throw 'Foreign installed Setup content.' }
        }
    }
    Remove-SetupOwnedTree -Path $Locations.InstallerCode
}

# MVP-7: SentinelAI's update tasks live in Task Scheduler's \SentinelAI folder and run as SYSTEM by SID.
$script:SetupTaskFolder = 'SentinelAI'
$script:CentralUpdateTaskName = 'SentinelAI Update'

function Get-SetupTaskRoot {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    return $scheduler.GetFolder('\')
}

function Get-SetupScheduledTask {
    param([string]$Name)
    $root = Get-SetupTaskRoot
    try { return $root.GetFolder($script:SetupTaskFolder).GetTask($Name) } catch { return $null }
}

function Register-SetupScheduledTask {
    param([string]$Name, [string]$Definition)
    $root = Get-SetupTaskRoot
    try { $folder = $root.GetFolder($script:SetupTaskFolder) } catch { $folder = $root.CreateFolder($script:SetupTaskFolder, $null) }
    # TASK_CREATE_OR_UPDATE (6) with TASK_LOGON_SERVICE_ACCOUNT (5).
    [void]$folder.RegisterTask($Name, $Definition, 6, $null, $null, 5)
}

# No new run starts; a running one gets two minutes to finish or roll back before it is stopped (state 4 = running).
function Suspend-SetupScheduledTask {
    param([string]$Name)
    $task = Get-SetupScheduledTask $Name
    if ($null -eq $task) { return $false }
    $task.Enabled = $false
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    while ((Get-SetupScheduledTask $Name).State -eq 4 -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if ((Get-SetupScheduledTask $Name).State -eq 4) { $task.Stop(0) }
    return $true
}

function Resume-SetupScheduledTask {
    param([string]$Name)
    $task = Get-SetupScheduledTask $Name
    if ($null -ne $task) { $task.Enabled = $true }
}

# The registered task runs exactly this Updater command, is enabled and runs as SYSTEM.
function Test-SetupScheduledTask {
    param([string]$Name, [string]$Updater, [string]$Arguments)
    $task = Get-SetupScheduledTask $Name
    if ($null -eq $task -or -not $task.Enabled) { return $false }
    $definition = $task.Definition
    if ($definition.Actions.Count -ne 1 -or $definition.Principal.UserId -notin @('S-1-5-18', 'SYSTEM', 'NT AUTHORITY\SYSTEM')) { return $false }
    $action = $definition.Actions.Item(1)
    return [string]$action.Path -ceq ('"' + $Updater + '"') -and [string]$action.Arguments -ceq $Arguments
}

function Unregister-SetupScheduledTask {
    param([string]$Name)
    $root = Get-SetupTaskRoot
    try { $folder = $root.GetFolder($script:SetupTaskFolder) } catch { return }
    if ($null -ne (Get-SetupScheduledTask $Name)) { $folder.DeleteTask($Name, 0) }
    if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) { $root.DeleteFolder($script:SetupTaskFolder, 0) }
}

# SYSTEM by SID, quoted command (the path has spaces), never two at once, bounded; the action is the installed Updater.
function New-SetupUpdateTaskDefinition {
    param([string]$Description, [string]$Triggers, [string]$Updater, [string]$Arguments, [bool]$CatchUp)
    $command = [Security.SecurityElement]::Escape('"' + $Updater + '"')
    $catchUp = if ($CatchUp) { 'true' } else { 'false' }
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$Description</Description></RegistrationInfo>
  <Triggers>$Triggers</Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>$catchUp</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="System"><Exec><Command>$command</Command><Arguments>$Arguments</Arguments></Exec></Actions>
</Task>
"@
}

# Held first, so it never starts a Setup during or after uninstall, then deleted.
function Remove-SetupCentralUpdateTask {
    [void](Suspend-SetupScheduledTask $script:CentralUpdateTaskName)
    Unregister-SetupScheduledTask $script:CentralUpdateTaskName
}

# MVP-7: a build with the owner's update server gets the nightly task that installs a downloaded newer SentinelAI
# (between 02:00 and 04:00, only while an administrator keeps automatic installation on); a build without one has none.
function Sync-SetupCentralUpdateTask {
    param($Locations)
    if (-not (Test-Path -LiteralPath (Join-Path $Locations.CoreCode 'update-server.json') -PathType Leaf)) {
        Unregister-SetupScheduledTask $script:CentralUpdateTaskName
        return
    }
    # An unchanged task is left as it is: each re-registration is an audited change on this monitored computer.
    $updater = Join-Path $Locations.UpdaterCode 'SentinelAI.Updater.exe'
    if (Test-SetupScheduledTask $script:CentralUpdateTaskName $updater 'apply-central-update') { return }
    $triggers = '<CalendarTrigger><StartBoundary>2026-01-01T02:00:00</StartBoundary><RandomDelay>PT2H</RandomDelay><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay><Enabled>true</Enabled></CalendarTrigger>'
    Register-SetupScheduledTask $script:CentralUpdateTaskName (New-SetupUpdateTaskDefinition -Description 'Installs a SentinelAI update downloaded from the provider''s update server.' `
        -Triggers $triggers -Updater $updater -Arguments 'apply-central-update' -CatchUp $false)
}

function Invoke-SetupInstallation {
    param($Request)
    $locations = Get-SetupLocations
    $bundle = Join-Path $Request.workDirectory 'bundle'
    $root = Join-Path $Request.workDirectory 'trust\root.pem'
    Assert-PilotSupportedHost
    Assert-PilotTrustedPath -Path $Request.workDirectory -Tree
    $policy = @{ BundleDirectory = $bundle; PublicKeyPath = $root; KeyId = $Request.keyId; Environment = 'development'; Channel = $Request.channel }
    Write-SetupProgress 'validate'
    Assert-SetupFreshTargets -Locations $locations -AllowPreparedCore:($Request.action -ne 'prepare-core') -AllowStartedCore:($Request.action -eq 'complete')
    if ($Request.action -eq 'prepare-core') {
        Write-SetupProgress 'core'
        $network = @{}
        if ($Request.localNetworkCertificateSha256.Length -ne 0) {
            # The Setup host created Core's certificate; only its public SHA-256 crosses this boundary.
            if (-not (Test-CoreServiceCertificate -Sha256 $Request.localNetworkCertificateSha256)) { throw 'Core certificate unavailable.' }
            $network.LocalNetworkCertificateSha256 = $Request.localNetworkCertificateSha256
        }
        $installed = Invoke-PilotInstall -Component Core @policy @network -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData
        if ($installed.component -cne 'Core') { throw 'Core preparation failed.' }
        Write-Output 'DONE'
        return
    }
    if ($Request.action -eq 'start-core') {
        Write-SetupProgress 'services'
        $started = Invoke-CoreServiceManagement -Action Install @policy -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData -TimeoutSeconds 60
        if ($started.component -cne 'Core') { throw 'Core service failed.' }
        $network = Get-CoreServiceLocalNetwork -DataDirectory $locations.CoreData
        if ($null -ne $network) {
            Write-SetupProgress 'network'
            Set-CoreServiceFirewallRule -ExecutablePath (Join-Path $locations.CoreCode 'SentinelAI.Core.exe') -Port $network.Port
        }
        Write-Output 'DONE'
        return
    }
    try {
        # Recheck the exact owned registration and PID-bound health after token
        # issuance. No reusable administrator credential enters this process.
        Write-SetupProgress 'services'
        $started = Invoke-CoreServiceManagement -Action Start -CodeDirectory $locations.CoreCode -DataDirectory $locations.CoreData -TimeoutSeconds 60
        if ($started.component -cne 'Core') { throw 'Core service failed.' }
        # Registered before the Agent first starts, so the task's own creation is not reported as a finding.
        Sync-SetupCentralUpdateTask $locations
        Write-SetupProgress 'agent'
        $agent = Invoke-PilotInstall -Component Agent @policy -CodeDirectory $locations.AgentCode -DataDirectory $locations.AgentData -EnrollmentToken $Request.enrollmentToken -TimeoutSeconds 180
        if ($agent.component -cne 'Agent') { throw 'Agent service failed.' }
        Write-SetupProgress 'desktop'
        Install-SetupAuxiliaryCode -Source (Join-Path $Request.workDirectory 'desktop') -Destination $locations.DesktopCode -Executable 'SentinelAI.Desktop.exe' -PublicRead
        # MVP-7: Desktop's Install now checks the Updater before Windows elevates it, so Users may read and run it.
        Install-SetupAuxiliaryCode -Source (Join-Path $bundle 'updater') -Destination $locations.UpdaterCode -Executable 'SentinelAI.Updater.exe' -PublicRead
        New-PilotProtectedDirectory -Path $locations.SetupData -Kind Container
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'public-key.pem') -Content ([IO.File]::ReadAllText($root)) -Kind Receipt
        $receipt = @{ format = 'sentinelai-setup-v1'; keyId = $Request.keyId; environment = 'development'; channel = $Request.channel;
            desktopDirectory = $locations.DesktopCode; updaterDirectory = $locations.UpdaterCode;
            desktopSha256 = (Get-FileHash -LiteralPath (Join-Path $locations.DesktopCode 'SentinelAI.Desktop.exe') -Algorithm SHA256).Hash;
            updaterSha256 = (Get-FileHash -LiteralPath (Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe') -Algorithm SHA256).Hash }
        Write-PilotProtectedFile -Path (Join-Path $locations.SetupData 'setup-installation.json') -Content ($receipt | ConvertTo-Json -Compress) -Kind Receipt
        Write-SetupProgress 'shortcut'
        Install-SetupShortcut -Directory $locations.Menu -DesktopDirectory $locations.DesktopCode
        Write-SetupProgress 'apps'
        Register-SetupFullApps -Locations $locations -WorkDirectory $Request.workDirectory -Version $Request.version
        Write-Output 'DONE'
    } finally { $Request.enrollmentToken = $null }
}

function Assert-SetupRequest {
    param($Request)
    Assert-PilotObjectProperties -Object $Request -Names @('action','workDirectory','keyId','channel','enrollmentToken','version','preserveData','localNetworkCertificateSha256')
    # Only the fresh Core preparation carries the public SHA-256 of the certificate the Setup host created.
    if ($Request.localNetworkCertificateSha256 -isnot [string] -or ($Request.localNetworkCertificateSha256.Length -ne 0 -and
        ($Request.action -cne 'prepare-core' -or $Request.localNetworkCertificateSha256 -cnotmatch '\A[0-9A-F]{64}\z'))) { throw 'Invalid local-network policy.' }
    if ($Request.action -cnotin @('prepare-core','start-core','complete','inspect','lifecycle-stop','lifecycle-start','lifecycle-health','lifecycle-context','lifecycle-cleanup','lifecycle-reconcile','uninstall','apps-register') -or $Request.keyId -isnot [string] -or
        $Request.keyId -cnotmatch '\Adev-[A-Za-z0-9_-]{1,48}\z' -or $Request.channel -cnotin @('stable','pilot','beta')) { throw 'Invalid policy.' }
    if ($Request.version -isnot [string] -or $Request.version -cnotmatch '\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z' -or
        @($Request.version.Split('.') | Where-Object { [int]$_ -gt 65535 }).Count -ne 0 -or
        $Request.preserveData -cnotin @('true','false') -or ($Request.action -cne 'uninstall' -and $Request.preserveData -cne 'true')) { throw 'Invalid lifecycle policy.' }
    if ($Request.action -ne 'complete') {
        # The private wire uses an empty string, keeping the existing strict
        # Pilot JSON grammar limited to strings/objects without accepting null.
        if ($Request.enrollmentToken -isnot [string] -or $Request.enrollmentToken.Length -ne 0) { throw 'Unexpected enrollment token.' }
    } elseif ($Request.enrollmentToken -isnot [string] -or $Request.enrollmentToken -cnotmatch '\A[0-9a-fA-F]{64}\z') { throw 'Invalid enrollment token.' }
}

function Invoke-SetupWorkerMain {
    $raw = $null
    $request = $null
    try {
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Unsupported execution policy.' }
        [Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        $raw = Read-SetupRequest
        # Locate trusted resources before importing any in-memory module; strict JSON
        # is applied again using the existing parser before any installation mutation.
        $locator = $raw | ConvertFrom-Json
        if ($locator.workDirectory -isnot [string]) { throw 'Invalid request.' }
        Assert-SetupBootstrapDirectory -Path $locator.workDirectory
        Import-SetupInstallerModules -WorkDirectory $locator.workDirectory
        $request = Read-PilotStrictJson -Json $raw
        Assert-SetupRequest -Request $request
        if ($request.action -cin @('prepare-core','start-core','complete')) { Invoke-SetupInstallation -Request $request }
        else { Invoke-SetupLifecycleWorker -Request $request }
        exit 0
    } catch {
        # Component output, exception text, paths and credentials are never UI/log data.
        Write-Output ('FAILED|' + $script:SetupPhase)
        exit 1
    } finally { if ($null -ne $request -and $null -ne $request.PSObject.Properties['enrollmentToken']) { $request.enrollmentToken = $null }; $raw = $null }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-SetupWorkerMain }
