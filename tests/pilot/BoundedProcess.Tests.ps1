# Portable tests for the bounded child-process helper used by Updater preparation.
# Runs under PowerShell 7 (all platforms) and Windows PowerShell 5.1; children are this PowerShell.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'installer/pilot/PilotInstaller.psm1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-bounded-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:assertionCount = 0
$powershell = (Get-Process -Id $PID).Path

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}
function Invoke-Child {
    param([string]$Command, [int]$TimeoutSeconds = 60)
    return Invoke-PilotBoundedProcess -FilePath $powershell -Arguments @('-NoProfile', '-NonInteractive', '-Command', $Command) `
        -WorkingDirectory $testRoot -TimeoutSeconds $TimeoutSeconds
}
function Test-ProcessAlive {
    param([int]$Id)
    $process = Get-Process -Id $Id -ErrorAction SilentlyContinue
    return $null -ne $process -and -not $process.HasExited
}

try {
    $module = Import-Module $modulePath -Force -DisableNameChecking -PassThru

    # One line of output and exit code 0 are returned exactly.
    $result = Invoke-Child "Write-Output '{""version"":""1.0.0""}'"
    Assert-Test ($result.Outcome -ceq 'Exited' -and $result.ExitCode -eq 0 -and
        $result.Output -cmatch '\A\{"version":"1\.0\.0"\}\r?\n\z') 'A completed child did not return its exact output.'

    $result = Invoke-Child 'exit 3'
    Assert-Test ($result.Outcome -ceq 'Exited' -and $result.ExitCode -eq 3) 'A non-zero exit code was not returned.'

    # Arguments with spaces, quotes and backslashes reach the child intact.
    $values = @('two words', 'quote " inside', 'C:\Program Files\SentinelAI\', 'trailing\\', 'plain')
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($values | ConvertTo-Json -Compress)))
    $echo = '$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $encoded + ''')) | ConvertFrom-Json; ' +
        'if (@(Compare-Object @($expected) @($args) -SyncWindow 0 -CaseSensitive).Count -eq 0 -and $args.Count -eq ' + $values.Count + ') { exit 0 } else { exit 9 }'
    $script = Join-Path $testRoot 'echo-arguments.ps1'
    Set-Content -LiteralPath $script -Value $echo -Encoding UTF8
    $result = Invoke-PilotBoundedProcess -FilePath $powershell -Arguments (@('-NoProfile', '-NonInteractive', '-File', $script) + $values) `
        -WorkingDirectory $testRoot -TimeoutSeconds 60
    Assert-Test ($result.Outcome -ceq 'Exited' -and $result.ExitCode -eq 0) 'Arguments did not reach the child exactly.'

    # A child that does not finish is killed at its time limit.
    $pidFile = Join-Path $testRoot 'sleeper.pid'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Child ("Set-Content -LiteralPath '" + $pidFile + "' -Value `$PID; Start-Sleep -Seconds 120") 3
    Assert-Test ($result.Outcome -ceq 'Timeout' -and $result.ExitCode -eq -1 -and $result.Output -ceq '') 'A stalled child did not time out.'
    Assert-Test ($watch.Elapsed.TotalSeconds -lt 30) 'The time limit was not enforced promptly.'
    $sleeper = [int](Get-Content -LiteralPath $pidFile)
    Assert-Test (-not (Test-ProcessAlive $sleeper)) 'A timed-out child was left running.'

    # A grandchild that keeps the inherited output pipe open cannot hold the caller after the child exits.
    $holderFile = Join-Path $testRoot 'holder.pid'
    $spawn = '$s = New-Object Diagnostics.ProcessStartInfo; $s.FileName = ''' + $powershell + '''; ' +
        '$s.Arguments = ''-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60''; $s.UseShellExecute = $false; ' +
        '$p = [Diagnostics.Process]::Start($s); Set-Content -LiteralPath ''' + $holderFile + ''' -Value $p.Id; Write-Output ok'
    $watch.Restart()
    $result = Invoke-Child $spawn
    try {
        Assert-Test ($result.Outcome -ceq 'OutputHeld' -and $result.ExitCode -eq 0) 'Held output was not reported.'
        Assert-Test ($watch.Elapsed.TotalSeconds -lt 40) 'Held output blocked the caller.'
    } finally {
        if (Test-Path -LiteralPath $holderFile) { Stop-Process -Id ([int](Get-Content -LiteralPath $holderFile)) -Force -ErrorAction SilentlyContinue }
    }

    # Invoke-PilotPrepare maps each outcome to its fixed message without exposing output.
    & $module {
        function script:Assert-PilotPath { param($Path) return [IO.Path]::GetFullPath($Path) }
        function script:Assert-PilotTrustedPath { }
    }
    $cases = @(
        @{ Result = [pscustomobject]@{ Outcome = 'Timeout'; ExitCode = -1; Output = '' }; Message = 'The signed pilot package preparation did not finish within its time limit.' },
        @{ Result = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 2; Output = '' }; Message = 'The signed pilot package preparation did not finish within its time limit.' },
        @{ Result = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 1; Output = '' }; Message = 'The signed pilot package was rejected.' },
        @{ Result = [pscustomobject]@{ Outcome = 'OutputHeld'; ExitCode = 0; Output = '' }; Message = 'The signed pilot package was rejected.' },
        @{ Result = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 0; Output = "{}`n{}`n" }; Message = 'The signed pilot package was rejected.' },
        @{ Result = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 0; Output = ('x' * 1025) + "`n" }; Message = 'The signed pilot package was rejected.' },
        @{ Result = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 0; Output = "not json`n" }; Message = 'The signed pilot package metadata is invalid.' }
    )
    $bundle = Join-Path $testRoot 'bundle'
    foreach ($case in $cases) {
        & $module { param($Result) $script:BoundedTestResult = $Result
            function script:Invoke-PilotBoundedProcess { return $script:BoundedTestResult } } $case.Result
        $message = $null
        try {
            Invoke-PilotPrepare -BundleDirectory $bundle -PublicKeyPath (Join-Path $testRoot 'public.pem') -KeyId 'dev-test' `
                -Environment 'development' -Channel 'pilot' -Component Agent -OutputDirectory (Join-Path $testRoot 'prepared') | Out-Null
        } catch { $message = $_.Exception.Message }
        Assert-Test ($message -ceq $case.Message) ("Outcome {0}/{1} was not mapped to its fixed message." -f $case.Result.Outcome, $case.Result.ExitCode)
    }
    $valid = [pscustomobject]@{ Outcome = 'Exited'; ExitCode = 0
        Output = '{"version":"1.2.3","artifactId":"sentinelai-agent-win-x64","channel":"pilot","environment":"development"}' + "`r`n" }
    & $module { param($Result) $script:BoundedTestResult = $Result } $valid
    $metadata = Invoke-PilotPrepare -BundleDirectory $bundle -PublicKeyPath (Join-Path $testRoot 'public.pem') -KeyId 'dev-test' `
        -Environment 'development' -Channel 'pilot' -Component Agent -OutputDirectory (Join-Path $testRoot 'prepared')
    Assert-Test ($metadata.version -ceq '1.2.3' -and $metadata.artifactId -ceq 'sentinelai-agent-win-x64') 'Valid preparation metadata was not returned.'
    Assert-Test ((& $module { $script:PilotPrepareTimeoutSeconds }) -eq 120) 'The preparation time limit changed unexpectedly.'

    Write-Output "Bounded process tests passed ($script:assertionCount assertions)."
} finally {
    Remove-Module PilotInstaller -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
