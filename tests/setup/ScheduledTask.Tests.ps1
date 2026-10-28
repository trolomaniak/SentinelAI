# Windows-only (MVP-7): the Setup's real update task definitions are registered with Task Scheduler in a throwaway
# folder, read back and removed, and the download folder Core fills is provided with Core's data rights. Synthetic paths
# only; nothing runs. Requires an elevated Windows PowerShell 5.1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $repo 'installer/setup/SetupWorker.ps1')
. (Join-Path $repo 'installer/setup/AgentSetupWorker.ps1')
Import-Module (Join-Path $repo 'installer/pilot/CoreServiceInstaller.psm1') -Force -DisableNameChecking
$coreSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'
function Get-SetupLifecycleCoreSid { return $coreSid }
# The Start Menu account record is covered by the Setup acceptance; here it stays out of the runner's own folders.
function Sync-SetupProgramsWriter { }
function Remove-SetupProgramsWriter { }
# The temporary tree belongs to the runner's account, which the installed tree never trusts; removal is covered on the
# installed tree by the Setup acceptance.
function Assert-PilotTrustedPath { param($Path, [switch]$Tree, [switch]$AllowServiceWrite, $ServiceWriteSid, $ServiceWriteRoot)
    if ($ServiceWriteSid -cne $coreSid -or -not $Tree) { throw 'The download folder was not checked as Core data.' } }
$script:SetupTaskFolder = 'SentinelAI-Tests-' + [Guid]::NewGuid().ToString('N')
$script:checks = 0
function Assert-TaskTest([bool]$Condition, [string]$Label) { $script:checks++; if (-not $Condition) { throw ('Scheduled task regression: ' + $Label) } }

$work = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-task-tests-' + [Guid]::NewGuid().ToString('N'))
$locations = @{ CoreCode = (Join-Path $work 'Core'); CoreData = (Join-Path $work 'Data\Core'); UpdaterCode = (Join-Path $work 'Program Files\SentinelAI\Updater') }
[void][IO.Directory]::CreateDirectory($locations.CoreCode)
[void][IO.Directory]::CreateDirectory($locations.CoreData)
$downloads = Join-Path $locations.CoreData 'central-update'
$updater = Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe'
try {
    # Without update-server.json there is no nightly task.
    Sync-SetupCentralUpdateTask $locations
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:CentralUpdateTaskName) -and -not (Test-Path -LiteralPath $downloads)) 'a build without an update server registered the nightly task or a download folder'

    [IO.File]::WriteAllText((Join-Path $locations.CoreCode 'update-server.json'), '{"url":"https://updates.example.invalid/sentinelai/pilot","channel":"pilot"}')
    Sync-SetupCentralUpdateTask $locations
    $acl = Get-Acl -LiteralPath $downloads
    $core = @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ceq $coreSid })
    $folder = @($core | Where-Object { ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 })
    $files = @($core | Where-Object { ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0 })
    # Core creates files and changes its own; it never removes the folder, creates folders or changes its rights.
    Assert-TaskTest ($acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq 'S-1-5-32-544' -and
        $folder.Count -eq 1 -and ($folder[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0 -and
        ($folder[0].FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions)) -eq 0 -and
        $files.Count -eq 1 -and ($files[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify -and
        ($files[0].InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -eq 0) 'the download folder does not carry Core''s data rights'
    [IO.File]::WriteAllBytes((Join-Path $downloads 'SentinelAI-Setup.exe'), [byte[]](1, 2, 3))
    $task = Get-SetupScheduledTask $script:CentralUpdateTaskName
    Assert-TaskTest ($null -ne $task -and (Test-SetupScheduledTask $script:CentralUpdateTaskName $updater 'apply-central-update')) 'the nightly task was not registered as SYSTEM running the Updater'
    $trigger = $task.Definition.Triggers.Item(1)
    # TASK_TRIGGER_DAILY (2), between 02:00 and 04:00, not caught up after a missed night.
    Assert-TaskTest ($task.Definition.Triggers.Count -eq 1 -and $trigger.Type -eq 2 -and $trigger.DaysInterval -eq 1 -and $trigger.RandomDelay -ceq 'PT2H' -and
        $trigger.StartBoundary -like '*T02:00:00*' -and -not $task.Definition.Settings.StartWhenAvailable -and
        $task.Definition.Settings.MultipleInstances -eq 2) 'the nightly schedule is not daily at 02:00 with a two-hour window'
    Sync-SetupCentralUpdateTask $locations
    Assert-TaskTest (Test-SetupScheduledTask $script:CentralUpdateTaskName $updater 'apply-central-update') 'syncing an unchanged nightly task broke it'

    Register-AgentSetupUpdateTask $locations
    Assert-TaskTest (Test-SetupScheduledTask $script:AgentUpdateTaskName $updater 'apply-agent-update') 'the Agent update task was not registered as SYSTEM running the Updater'
    Unregister-AgentSetupUpdateTask
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:AgentUpdateTaskName) -and $null -ne (Get-SetupScheduledTask $script:CentralUpdateTaskName)) 'removing the Agent task touched the nightly task'

    # A build without an update server removes both the task and anything downloaded.
    Remove-Item -LiteralPath (Join-Path $locations.CoreCode 'update-server.json')
    Sync-SetupCentralUpdateTask $locations
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:CentralUpdateTaskName) -and -not (Test-Path -LiteralPath $downloads)) 'the nightly task or the download survived a build without an update server'
    [IO.File]::WriteAllText((Join-Path $locations.CoreCode 'update-server.json'), '{"url":"https://updates.example.invalid/sentinelai/pilot","channel":"pilot"}')
    Sync-SetupCentralUpdateTask $locations
    Remove-SetupCentralUpdateTask
    Remove-SetupCentralUpdateDownloads $locations
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:CentralUpdateTaskName) -and -not (Test-Path -LiteralPath $downloads)) 'the nightly task or the download folder survived uninstall'
    $folderRemoved = $false
    try { [void](Get-SetupTaskRoot).GetFolder($script:SetupTaskFolder) } catch { $folderRemoved = $true }
    Assert-TaskTest $folderRemoved 'the empty task folder was kept'

    # The nightly Updater starts SentinelAI Setup and exits, because the upgrade replaces the Updater too. This probe
    # shows whether a process started that way outlives a SYSTEM task, directly and through WMI (synthetic scripts only).
    $probe = Join-Path $work 'probe'
    [void][IO.Directory]::CreateDirectory($probe)
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    [IO.File]::WriteAllText((Join-Path $probe 'child.ps1'), 'param([string]$Marker) Start-Sleep -Seconds 15; [IO.File]::WriteAllText($Marker, ''alive'')')
    $child = '"' + $powershell + '" -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $probe 'child.ps1') + '" -Marker "'
    [IO.File]::WriteAllText((Join-Path $probe 'parent.ps1'), (
        '$start = New-Object Diagnostics.ProcessStartInfo(''' + $powershell + ''', ''-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $probe 'child.ps1') + '" -Marker "' + (Join-Path $probe 'direct') + '"'')' + "`r`n" +
        '$start.UseShellExecute = $false; [void][Diagnostics.Process]::Start($start)' + "`r`n" +
        '[void](Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = ''' + $child + (Join-Path $probe 'wmi') + '"'' })'))
    $triggers = '<TimeTrigger><StartBoundary>2099-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>'
    Register-SetupScheduledTask 'SentinelAI Child Probe' (New-SetupUpdateTaskDefinition -Description 'Synthetic probe.' -Triggers $triggers -Updater $powershell `
        -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $probe 'parent.ps1') + '"') -CatchUp $false)
    [void](Get-SetupScheduledTask 'SentinelAI Child Probe').Run($null)
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline -and -not ((Test-Path -LiteralPath (Join-Path $probe 'direct')) -and (Test-Path -LiteralPath (Join-Path $probe 'wmi')))) { Start-Sleep -Seconds 1 }
    $probeTask = Get-SetupScheduledTask 'SentinelAI Child Probe'
    Write-Output ('SetupTaskChildProbe: TaskState={0}; TaskResult={1}; DirectChildSurvived={2}; WmiChildSurvived={3}' -f $probeTask.State, $probeTask.LastTaskResult,
        (Test-Path -LiteralPath (Join-Path $probe 'direct')), (Test-Path -LiteralPath (Join-Path $probe 'wmi')))
    Unregister-SetupScheduledTask 'SentinelAI Child Probe'
} finally {
    try {
        $folder = (Get-SetupTaskRoot).GetFolder($script:SetupTaskFolder)
        foreach ($name in @($script:CentralUpdateTaskName, $script:AgentUpdateTaskName, 'SentinelAI Child Probe')) { try { $folder.DeleteTask($name, 0) } catch { } }
        (Get-SetupTaskRoot).DeleteFolder($script:SetupTaskFolder, 0)
    } catch { }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output ('Setup scheduled task assertions passed: ' + $script:checks)
