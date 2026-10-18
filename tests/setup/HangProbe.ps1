# CI-only probes for Setup steps that stop making visible progress. Each probe samples a process
# twice, ten seconds apart, so slow progress (counters and staged files growing) can be told apart
# from a stall (nothing moves). Output is numbers and allowlisted words only: never paths, file
# names, command lines, exception text, memory or credentials. Dot-sourced by the acceptance scripts.
$script:SetupProbeWaitReasons = @('Executive', 'FreePage', 'PageIn', 'SystemAllocation', 'ExecutionDelay', 'Suspended', 'UserRequest',
    'EventPairHigh', 'EventPairLow', 'LpcReceive', 'LpcReply', 'VirtualMemory', 'PageOut', 'Unknown')
$script:SetupProbedUpdaters = New-Object 'System.Collections.Generic.HashSet[int]'
$script:SetupProbeWatch = $null
$script:LifecycleProbeReasons = New-Object 'System.Collections.Generic.HashSet[string]'

function ConvertTo-SetupProbeValue($Value) {
    $text = [string]$Value
    if ($text -cmatch '\A[A-Za-z0-9.:/+,-]{1,64}\z') { return $text }
    return 'Invalid'
}
function Format-SetupProbe($Fields) {
    $parts = foreach ($key in @($Fields.Keys)) {
        if ([string]$key -cnotmatch '\A[A-Za-z][A-Za-z0-9.]{0,40}\z') { throw 'Probe field names are fixed literals.' }
        [string]$key + '=' + (ConvertTo-SetupProbeValue $Fields[$key])
    }
    $line = $parts -join '; '
    if ($line.Length -gt 1800) { $line = $line.Substring(0, 1800) }
    return $line
}
function Add-SetupProbeFields($Target, [string]$Prefix, $Source) {
    foreach ($key in @($Source.Keys)) { $Target[$Prefix + [string]$key] = $Source[$key] }
}
function Get-SetupProbeThreadSummary($Threads) {
    $counts = [ordered]@{ Threads = 0; Running = 0; Ready = 0; Other = 0 }
    foreach ($reason in $script:SetupProbeWaitReasons) { $counts['Wait.' + $reason] = 0 }
    $counts['Wait.Other'] = 0
    foreach ($thread in @($Threads)) {
        $counts.Threads++
        $state = 'Other'; try { $state = [string]$thread.ThreadState } catch { }
        if ($state -ceq 'Running') { $counts.Running++ }
        elseif ($state -ceq 'Ready' -or $state -ceq 'Standby') { $counts.Ready++ }
        elseif ($state -ceq 'Wait') {
            $reason = 'Other'; try { $reason = [string]$thread.WaitReason } catch { }
            if ($script:SetupProbeWaitReasons -ccontains $reason) { $counts['Wait.' + $reason]++ } else { $counts['Wait.Other']++ }
        } else { $counts.Other++ }
    }
    $result = [ordered]@{}
    foreach ($key in $counts.Keys) { if ($counts[$key] -ne 0 -or $key -ceq 'Threads') { $result[$key] = $counts[$key] } }
    return $result
}
function Measure-SetupProbeTree([string]$Root, [int]$Maximum = 8192) {
    $result = [ordered]@{ Present = $false; Files = 0; Directories = 0; KB = 0; Truncated = $false }
    if (-not [IO.Directory]::Exists($Root)) { return $result }
    $result.Present = $true; [long]$bytes = 0; $seen = 0
    $pending = New-Object 'System.Collections.Generic.Stack[string]'; $pending.Push($Root)
    while ($pending.Count -gt 0 -and -not $result.Truncated) {
        $current = $pending.Pop()
        try {
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($current)) {
                $seen++
                if ($seen -gt $Maximum) { $result.Truncated = $true; break }
                # FileInfo refreshes with an attributes query: no sharing conflict with the writer.
                $info = New-Object IO.FileInfo -ArgumentList $entry
                $attributes = $info.Attributes
                if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                    $result.Directories++
                    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $pending.Push($entry) }
                } else { $result.Files++; $bytes += $info.Length }
            }
        } catch { }  # entries vanish while the observed writer runs
    }
    $result.KB = [long][Math]::Floor($bytes / 1024)
    return $result
}
function Find-SetupProbeEntries([string]$Root, [string[]]$Patterns, [int]$MaximumDepth, [int]$Maximum = 4096) {
    # Internal only: the matched paths are measured, never emitted.
    $found = New-Object 'System.Collections.Generic.List[string]'
    if (-not [IO.Directory]::Exists($Root)) { return ,$found }
    $pending = New-Object 'System.Collections.Generic.Stack[object]'; $pending.Push(@($Root, 0)); $seen = 0
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        try {
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries([string]$current[0])) {
                if (++$seen -gt $Maximum) { return ,$found }
                $name = [IO.Path]::GetFileName($entry)
                foreach ($pattern in $Patterns) { if ($name -clike $pattern) { $found.Add($entry); break } }
                $attributes = [IO.File]::GetAttributes($entry)
                if (($attributes -band [IO.FileAttributes]::Directory) -ne 0 -and ($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
                    [int]$current[1] + 1 -lt $MaximumDepth) { $pending.Push(@($entry, [int]$current[1] + 1)) }
            }
        } catch { }
    }
    return ,$found
}
function Measure-SetupProbeEntries($Paths) {
    $result = [ordered]@{ Count = 0; Files = 0; KB = 0 }
    foreach ($path in @($Paths)) {
        $result.Count++
        if ([IO.Directory]::Exists($path)) {
            $tree = Measure-SetupProbeTree $path
            $result.Files += $tree.Files; $result.KB += $tree.KB
        } elseif ([IO.File]::Exists($path)) {
            $result.Files++
            try { $result.KB += [long][Math]::Floor((New-Object IO.FileInfo -ArgumentList $path).Length / 1024) } catch { }
        }
    }
    return $result
}
function Get-SetupProbeStaging([string]$ProgramFiles = $env:ProgramFiles, [string]$ProgramData = $env:ProgramData) {
    $fields = [ordered]@{}
    $codeParent = if ([string]::IsNullOrEmpty($ProgramFiles)) { '' } else { Join-Path $ProgramFiles 'SentinelAI' }
    $hostRoot = if ([string]::IsNullOrEmpty($ProgramData)) { '' } else { Join-Path $ProgramData 'SentinelAI-SetupHost' }
    # Pilot Updater prepare output, its private verified copy, the retained-restore candidate and the transaction work tree.
    Add-SetupProbeFields $fields 'Prepare.' (Measure-SetupProbeEntries (Find-SetupProbeEntries $codeParent @('.sentinelai-pilot-*', '.sentinelai-core-service-*') 1))
    Add-SetupProbeFields $fields 'Verify.' (Measure-SetupProbeEntries (Find-SetupProbeEntries $hostRoot @('sentinelai-update-verify-*') 3))
    Add-SetupProbeFields $fields 'Retained.' (Measure-SetupProbeEntries (Find-SetupProbeEntries $hostRoot @('retained-candidate', 'retained-candidate.zip') 4))
    Add-SetupProbeFields $fields 'Work.' (Measure-SetupProbeEntries (Find-SetupProbeEntries $ProgramFiles @('.SentinelAI.sentinelai-update-*') 1))
    return $fields
}
function Get-SetupProbeProcessCounters([int]$Id) {
    $result = [ordered]@{ Alive = $false }
    try {
        $record = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $Id) -OperationTimeoutSec 10 -ErrorAction Stop
        if ($null -eq $record) { return $result }
        $result.Alive = $true
        $result.AgeS = [int]([DateTime]::Now - $record.CreationDate).TotalSeconds
        $result.CpuMs = [long](([double]$record.KernelModeTime + [double]$record.UserModeTime) / 10000)
        $result.ReadOps = [long]$record.ReadOperationCount; $result.WriteOps = [long]$record.WriteOperationCount
        $result.OtherOps = [long]$record.OtherOperationCount
        $result.ReadKB = [long]([double]$record.ReadTransferCount / 1024); $result.WriteKB = [long]([double]$record.WriteTransferCount / 1024)
        $result.Handles = [long]$record.HandleCount; $result.WorkingSetMB = [long]([double]$record.WorkingSetSize / 1MB)
    } catch { $result.Counters = 'Unavailable' }
    return $result
}
function Get-SetupProbeDefenderCpuMs {
    try {
        $records = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='MsMpEng.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)
        if ($records.Count -eq 0) { return 'Absent' }
        return [long](($records | Measure-Object -Property KernelModeTime -Sum).Sum / 10000 + ($records | Measure-Object -Property UserModeTime -Sum).Sum / 10000)
    } catch { return 'Unavailable' }
}
function Get-SetupProbeMachine {
    $result = [ordered]@{}
    try {
        $paths = @('\PhysicalDisk(_Total)\Avg. Disk sec/Write', '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
            '\PhysicalDisk(_Total)\Current Disk Queue Length', '\Processor(_Total)\% Processor Time')
        $samples = @((Get-Counter -Counter $paths -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop).CounterSamples)
        foreach ($sample in $samples) {
            $path = [string]$sample.Path
            if ($path -like '*disk sec/write') { $result.DiskWriteMs = [int]($sample.CookedValue * 1000) }
            elseif ($path -like '*disk sec/read') { $result.DiskReadMs = [int]($sample.CookedValue * 1000) }
            elseif ($path -like '*queue length') { $result.DiskQueue = [int]$sample.CookedValue }
            elseif ($path -like '*processor time') { $result.CpuPct = [int]$sample.CookedValue }
        }
    } catch { $result.Machine = 'Unavailable' }
    return $result
}
function Invoke-SetupProcessProbe([string]$Role, [int]$Id, [string]$Reason, [int]$IntervalSeconds = 10) {
    # Fixed literals only for Role and Reason; every value passes through the probe grammar.
    if ($Role -cnotin @('Updater', 'Host') -or $Reason -cnotmatch '\A[a-z0-9]{1,16}\z') { throw 'Probe roles and reasons are fixed literals.' }
    $first = Get-SetupProbeProcessCounters $Id
    $firstStaging = Get-SetupProbeStaging
    $firstDefender = Get-SetupProbeDefenderCpuMs
    Start-Sleep -Seconds $IntervalSeconds
    $second = Get-SetupProbeProcessCounters $Id
    $secondStaging = Get-SetupProbeStaging
    $secondDefender = Get-SetupProbeDefenderCpuMs
    $fields = [ordered]@{ Role = $Role; Reason = $Reason; IntervalS = $IntervalSeconds }
    Add-SetupProbeFields $fields '' $second
    foreach ($counter in @('CpuMs', 'ReadOps', 'WriteOps', 'OtherOps', 'ReadKB', 'WriteKB')) {
        if ($first.Contains($counter) -and $second.Contains($counter)) { $fields['Delta.' + $counter] = [long]$second[$counter] - [long]$first[$counter] }
    }
    foreach ($key in @($secondStaging.Keys)) {
        $fields[$key] = $secondStaging[$key]
        if ($key -like '*.Files' -or $key -like '*.KB') { $fields['Delta.' + $key] = [long]$secondStaging[$key] - [long]$firstStaging[$key] }
    }
    if ($firstDefender -is [long] -and $secondDefender -is [long]) { $fields['Defender.DeltaCpuMs'] = $secondDefender - $firstDefender }
    else { $fields['Defender'] = $secondDefender }
    try {
        $process = [Diagnostics.Process]::GetProcessById($Id)
        try { Add-SetupProbeFields $fields '' (Get-SetupProbeThreadSummary $process.Threads) } finally { $process.Dispose() }
    } catch { $fields['Threads'] = 'Unavailable' }
    Add-SetupProbeFields $fields '' (Get-SetupProbeMachine)
    $line = 'SetupHangProbe: ' + (Format-SetupProbe $fields)
    Write-Host $line
    return $line
}
function Invoke-SetupHangWatch([int]$MinimumAgeSeconds = 45) {
    # Fresh install: probe each Updater once when it is older than any normal preparation, before its
    # own deadline (90 s) and its caller's limit (120 s) remove it.
    if ($null -ne $script:SetupProbeWatch -and $script:SetupProbeWatch.Elapsed.TotalSeconds -lt 5) { return }
    $script:SetupProbeWatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        foreach ($record in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='SentinelAI.Updater.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)) {
            $id = [int]$record.ProcessId
            if (([DateTime]::Now - $record.CreationDate).TotalSeconds -ge $MinimumAgeSeconds -and $script:SetupProbedUpdaters.Add($id)) {
                [void](Invoke-SetupProcessProbe 'Updater' $id 'age')
            }
        }
    } catch { Write-Host 'SetupHangProbe: Role=Updater; Probe=Unavailable' }
}
function Reset-LifecycleHangWatch { $script:LifecycleProbeReasons.Clear(); $script:SetupProbeWatch = $null }
function Invoke-LifecycleHangWatch([Diagnostics.Process]$HostProcess, [double]$OperationSeconds) {
    # Lifecycle: probe the Setup host once when a transaction work tree has existed for 90 s, and once
    # when an operation has run for 420 s; a normal operation finishes well before either.
    if ($null -eq $HostProcess -or $HostProcess.HasExited) { return }
    if ($null -ne $script:SetupProbeWatch -and $script:SetupProbeWatch.Elapsed.TotalSeconds -lt 5) { return }
    $script:SetupProbeWatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $oldestSeconds = 0
        foreach ($path in (Find-SetupProbeEntries $env:ProgramFiles @('.SentinelAI.sentinelai-update-*') 1)) {
            try {
                $age = ([DateTime]::UtcNow - [IO.Directory]::GetCreationTimeUtc($path)).TotalSeconds
                if ($age -gt $oldestSeconds) { $oldestSeconds = $age }
            } catch { }
        }
        if ($oldestSeconds -ge 90 -and $script:LifecycleProbeReasons.Add('work')) {
            [void](Invoke-SetupProcessProbe 'Host' $HostProcess.Id 'work')
        }
        if ($OperationSeconds -ge 420 -and $script:LifecycleProbeReasons.Add('long')) {
            [void](Invoke-SetupProcessProbe 'Host' $HostProcess.Id 'long')
        }
    } catch { Write-Host 'SetupHangProbe: Role=Host; Probe=Unavailable' }
}
