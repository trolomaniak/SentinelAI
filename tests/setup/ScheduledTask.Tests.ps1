# Windows-only (MVP-7): the Setup's real update task definitions are registered with Task Scheduler in a throwaway
# folder, read back and removed. Synthetic paths only; nothing runs. Requires an elevated Windows PowerShell 5.1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $repo 'installer/setup/SetupWorker.ps1')
. (Join-Path $repo 'installer/setup/AgentSetupWorker.ps1')
$script:SetupTaskFolder = 'SentinelAI-Tests-' + [Guid]::NewGuid().ToString('N')
$script:checks = 0
function Assert-TaskTest([bool]$Condition, [string]$Label) { $script:checks++; if (-not $Condition) { throw ('Scheduled task regression: ' + $Label) } }

$work = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-task-tests-' + [Guid]::NewGuid().ToString('N'))
$locations = @{ CoreCode = (Join-Path $work 'Core'); UpdaterCode = (Join-Path $work 'Program Files\SentinelAI\Updater') }
[void][IO.Directory]::CreateDirectory($locations.CoreCode)
$updater = Join-Path $locations.UpdaterCode 'SentinelAI.Updater.exe'
try {
    # Without update-server.json there is no nightly task.
    Sync-SetupCentralUpdateTask $locations
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:CentralUpdateTaskName)) 'a build without an update server registered the nightly task'

    [IO.File]::WriteAllText((Join-Path $locations.CoreCode 'update-server.json'), '{"url":"https://updates.example.invalid/sentinelai/pilot","channel":"pilot"}')
    Sync-SetupCentralUpdateTask $locations
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

    Remove-SetupCentralUpdateTask
    Assert-TaskTest ($null -eq (Get-SetupScheduledTask $script:CentralUpdateTaskName)) 'the nightly task survived its removal'
    $folderRemoved = $false
    try { [void](Get-SetupTaskRoot).GetFolder($script:SetupTaskFolder) } catch { $folderRemoved = $true }
    Assert-TaskTest $folderRemoved 'the empty task folder was kept'
} finally {
    try {
        $folder = (Get-SetupTaskRoot).GetFolder($script:SetupTaskFolder)
        foreach ($name in @($script:CentralUpdateTaskName, $script:AgentUpdateTaskName)) { try { $folder.DeleteTask($name, 0) } catch { } }
        (Get-SetupTaskRoot).DeleteFolder($script:SetupTaskFolder, 0)
    } catch { }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output ('Setup scheduled task assertions passed: ' + $script:checks)
