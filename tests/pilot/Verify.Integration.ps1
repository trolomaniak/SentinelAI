# Test-only secure input adapter; no credential appears in process arguments/output.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CoreUrl,
    [Parameter(Mandatory = $true)][string]$AgentDataDirectory,
    [Parameter(Mandatory = $true)][DateTimeOffset]$SinceUtc
)
$ErrorActionPreference = 'Stop'
try {
    $username = [Environment]::GetEnvironmentVariable('SENTINELAI_PILOT_TEST_USERNAME')
    $password = [Environment]::GetEnvironmentVariable('SENTINELAI_PILOT_TEST_PASSWORD') | ConvertTo-SecureString -AsPlainText -Force
    [Environment]::SetEnvironmentVariable('SENTINELAI_PILOT_TEST_USERNAME', $null)
    [Environment]::SetEnvironmentVariable('SENTINELAI_PILOT_TEST_PASSWORD', $null)
    $credential = New-Object Management.Automation.PSCredential($username, $password)
    $verify = Join-Path $PSScriptRoot '../../installer/pilot/Verify-SentinelAIPilot.ps1'
    & $verify -CoreUrl $CoreUrl -AgentDataDirectory $AgentDataDirectory -AdminCredential $credential -SinceUtc $SinceUtc -TimeoutSeconds 10 | ConvertTo-Json -Compress
} catch { throw 'The test-only pilot verification did not succeed.' }
