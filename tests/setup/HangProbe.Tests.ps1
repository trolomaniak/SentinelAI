# Portable tests for the CI-only hang probes: fixed grammar, no secrets or paths, exact counts.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'HangProbe.ps1')
$script:checks = 0
function Assert-Probe([bool]$Condition, [string]$Label) { if (-not $Condition) { throw ('Probe regression: ' + $Label) }; $script:checks++ }
$field = '[A-Za-z][A-Za-z0-9.]{0,40}=[A-Za-z0-9.:/+,-]{1,64}'
$grammar = '\A' + $field + '(?:; ' + $field + ')*\z'
$secret = 'synthetic-secret-' + [Guid]::NewGuid().ToString('N')
$root = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-probe-tests-' + [Guid]::NewGuid().ToString('N'))
try {
    $line = Format-SetupProbe ([ordered]@{ Role = 'Updater'; AgeS = 46; Path = ('C:\Program Files\' + $secret); Text = 'a b'; Delta = -5 })
    Assert-Probe ($line -cmatch $grammar -and -not $line.Contains($secret) -and $line.Contains('Path=Invalid') -and
        $line.Contains('Text=Invalid') -and $line.Contains('Delta=-5')) 'Values outside the fixed grammar are neutralized.'
    $rejected = $false; try { Format-SetupProbe ([ordered]@{ ('Bad Key ' + $secret) = 1 }) | Out-Null } catch { $rejected = $true }
    Assert-Probe $rejected 'Field names must be fixed literals.'
    $rejected = $false; try { Invoke-SetupProcessProbe ('Role' + $secret) $PID 'age' 0 | Out-Null } catch { $rejected = $true }
    Assert-Probe $rejected 'Probe roles are fixed literals.'

    $threads = @(
        [pscustomobject]@{ ThreadState = 'Wait'; WaitReason = 'Executive' }, [pscustomobject]@{ ThreadState = 'Wait'; WaitReason = 'UserRequest' },
        [pscustomobject]@{ ThreadState = 'Wait'; WaitReason = $secret }, [pscustomobject]@{ ThreadState = 'Running' },
        [pscustomobject]@{ ThreadState = $secret })
    $line = Format-SetupProbe (Get-SetupProbeThreadSummary $threads)
    Assert-Probe ($line -ceq 'Threads=5; Running=1; Other=1; Wait.Executive=1; Wait.UserRequest=1; Wait.Other=1') ('Thread states are counted by allowlist: ' + $line)

    [void][IO.Directory]::CreateDirectory((Join-Path $root 'sub'))
    [IO.File]::WriteAllBytes((Join-Path $root ($secret + '.dll')), (New-Object byte[] 2048))
    [IO.File]::WriteAllBytes((Join-Path $root 'sub/b.dll'), (New-Object byte[] 1024))
    $tree = Measure-SetupProbeTree $root
    Assert-Probe ($tree.Present -and $tree.Files -eq 2 -and $tree.Directories -eq 1 -and $tree.KB -eq 3 -and -not $tree.Truncated) 'Tree counts are exact.'
    $line = Format-SetupProbe $tree
    Assert-Probe ($line -cmatch $grammar -and -not $line.Contains($secret)) 'Tree probes carry counts only.'
    Assert-Probe ((Measure-SetupProbeTree $root -Maximum 2).Truncated) 'Tree probes are bounded.'
    $absent = Join-Path $root 'absent'
    Assert-Probe (-not (Measure-SetupProbeTree $absent).Present -and -not [IO.Directory]::Exists($absent)) 'Absent staging is reported, not created.'

    # Synthetic Program Files and ProgramData layouts: every staging kind is found and counted, nothing else.
    $programFiles = Join-Path $root 'Program Files'; $programData = Join-Path $root 'ProgramData'
    $prepare = Join-Path $programFiles ('SentinelAI/.sentinelai-pilot-' + $secret)
    $work = Join-Path $programFiles ('.SentinelAI.sentinelai-update-' + $secret)
    $session = Join-Path $programData ('SentinelAI-SetupHost/' + $secret)
    foreach ($directory in @($prepare, (Join-Path $work 'replacement'), (Join-Path $session 'temp/sentinelai-update-verify-a'),
        (Join-Path $session 'bundle/retained-candidate'), (Join-Path $programFiles 'SentinelAI/Core'))) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    [IO.File]::WriteAllBytes((Join-Path $prepare 'SentinelAI.Agent.exe'), (New-Object byte[] 4096))
    [IO.File]::WriteAllBytes((Join-Path $work 'package.zip'), (New-Object byte[] 8192))
    [IO.File]::WriteAllBytes((Join-Path $work 'replacement/a.dll'), (New-Object byte[] 1024))
    [IO.File]::WriteAllBytes((Join-Path $session 'temp/sentinelai-update-verify-a/verified.zip'), (New-Object byte[] 2048))
    [IO.File]::WriteAllBytes((Join-Path $session 'bundle/retained-candidate.zip'), (New-Object byte[] 3072))
    [IO.File]::WriteAllBytes((Join-Path $session 'bundle/retained-candidate/b.dll'), (New-Object byte[] 1024))
    [IO.File]::WriteAllBytes((Join-Path $programFiles 'SentinelAI/Core/SentinelAI.Core.exe'), (New-Object byte[] 1024))
    $staging = Get-SetupProbeStaging -ProgramFiles $programFiles -ProgramData $programData
    $line = Format-SetupProbe $staging
    Assert-Probe ($line -ceq 'Prepare.Count=1; Prepare.Files=1; Prepare.KB=4; Verify.Count=1; Verify.Files=1; Verify.KB=2; Retained.Count=2; Retained.Files=2; Retained.KB=4; Work.Count=1; Work.Files=2; Work.KB=9') ('Staging counts are exact: ' + $line)
    Assert-Probe (-not $line.Contains($secret)) 'Staging probes never name paths.'
    $empty = Format-SetupProbe (Get-SetupProbeStaging -ProgramFiles (Join-Path $root 'none') -ProgramData (Join-Path $root 'none'))
    Assert-Probe ($empty -ceq 'Prepare.Count=0; Prepare.Files=0; Prepare.KB=0; Verify.Count=0; Verify.Files=0; Verify.KB=0; Retained.Count=0; Retained.Files=0; Retained.KB=0; Work.Count=0; Work.Files=0; Work.KB=0') 'Missing staging is all zero.'

    # A real two-sample probe of this process stays inside the grammar on every platform.
    $probe = Invoke-SetupProcessProbe 'Host' $PID 'test' 1 6>$null
    Assert-Probe ($probe.StartsWith('SetupHangProbe: Role=Host; Reason=test; IntervalS=1; ') -and
        $probe.Substring('SetupHangProbe: '.Length) -cmatch $grammar -and -not $probe.Contains($secret)) ('A live probe stays inside the grammar: ' + $probe)
    $gone = Invoke-SetupProcessProbe 'Updater' 2147483646 'test' 0 6>$null
    Assert-Probe ($gone.Contains('Alive=False') -and $gone.Substring('SetupHangProbe: '.Length) -cmatch $grammar) 'An exited process is reported, not an error.'

    "Setup hang probe tests passed ($script:checks checks)."
} finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}
