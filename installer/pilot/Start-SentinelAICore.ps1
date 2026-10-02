#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$CodeDirectory,
    [string]$DataDirectory,
    [System.Management.Automation.PSCredential]$AdminCredential,
    [switch]$InitializeAdministrator,
    [ValidateRange(10, 180)][int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'PilotInstaller.psm1') -Force -DisableNameChecking
$child = $null
$client = $null
$ready = $false
try {
    Assert-PilotSupportedHost -RequireElevation $false
    if ([string]::IsNullOrWhiteSpace($CodeDirectory)) { $CodeDirectory = Join-Path $env:ProgramFiles 'SentinelAI\Core' }
    if ([string]::IsNullOrWhiteSpace($DataDirectory)) { $DataDirectory = Join-Path $env:ProgramData 'SentinelAI\Core' }
    $CodeDirectory = Assert-PilotPath $CodeDirectory
    $DataDirectory = Assert-PilotPath $DataDirectory
    Assert-PilotPathLayout $CodeDirectory $DataDirectory
    Assert-PilotTrustedPath $CodeDirectory
    Assert-PilotTrustedPath $DataDirectory
    $exe = Join-Path $CodeDirectory 'SentinelAI.Core.exe'
    $configPath = Join-Path $DataDirectory 'pilot-config.json'
    Assert-PilotTrustedPath $exe
    Assert-PilotTrustedPath $configPath
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf) -or -not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw 'Core has not been installed.' }
    if ((Get-Item -LiteralPath $configPath).Length -gt 16384) { throw 'Invalid configuration.' }
    $config = [IO.File]::ReadAllText($configPath) | ConvertFrom-Json
    $origin = Assert-PilotCoreOrigin ([string]$config.urls)
    if (-not $origin.IsLoopback -or $origin.Scheme -ne 'http' -or
        (Assert-PilotPath ([string]$config.SentinelAI.DataDirectory)) -ne $DataDirectory) { throw 'Invalid local Core configuration.' }
    # Fail before prompting/sending credentials if a different process owns this listener.
    $address = [Net.IPAddress]::Loopback
    if ($origin.Host -eq '[::1]' -or $origin.Host -eq '::1') { $address = [Net.IPAddress]::IPv6Loopback }
    $probe = New-Object Net.Sockets.TcpListener($address, $origin.Port)
    try { $probe.Start() } finally { $probe.Stop() }
    if (($InitializeAdministrator -or -not (Test-Path -LiteralPath (Join-Path $DataDirectory 'sentinelai.db') -PathType Leaf)) -and $null -eq $AdminCredential) {
        $username = Read-Host 'Initial Core administrator username'
        $password = Read-Host 'Initial Core administrator password (at least 12 characters)' -AsSecureString
        $AdminCredential = New-Object System.Management.Automation.PSCredential($username, $password)
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $exe
    $start.WorkingDirectory = $CodeDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $false
    $start.Arguments = '--config "' + $configPath + '"'
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_USERNAME')
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_PASSWORD')
    if ($null -ne $AdminCredential) {
        if ([string]::IsNullOrWhiteSpace($AdminCredential.UserName) -or $AdminCredential.Password.Length -lt 12) { throw 'Invalid initial administrator credential.' }
        $start.EnvironmentVariables['SENTINELAI_BOOTSTRAP_USERNAME'] = $AdminCredential.UserName
        $start.EnvironmentVariables['SENTINELAI_BOOTSTRAP_PASSWORD'] = $AdminCredential.GetNetworkCredential().Password
    }
    $child = [Diagnostics.Process]::Start($start)
    # The launcher never changes its own environment or persists the bootstrap password.
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_USERNAME')
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_PASSWORD')
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(5)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $child.Refresh()
        if ($child.HasExited) { throw 'Core exited before it became ready.' }
        $response = $null
        try {
            $response = $client.GetAsync((New-Object Uri($origin, '/api/health'))).GetAwaiter().GetResult()
            if ($response.IsSuccessStatusCode -and
                ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json).status -eq 'healthy') {
                Start-Sleep -Milliseconds 300
                $child.Refresh()
                if ($child.HasExited) { throw 'Core exited before it became ready.' }
                $ready = $true
                break
            }
        } catch { if ($child.HasExited) { throw 'Core exited before it became ready.' } }
        finally { if ($null -ne $response) { $response.Dispose() } }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw 'Core did not become ready within its deadline.' }
    [pscustomobject]@{ ProcessId = $child.Id; CoreUrl = $origin.AbsoluteUri; CodeDirectory = $CodeDirectory; DataDirectory = $DataDirectory }
} catch {
    if ($null -ne $child -and -not $ready) {
        try { if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit(10000) | Out-Null } } catch { }
    }
    throw 'Core startup failed. Check installed files, private configuration and local port availability. If first-run setup was interrupted, retry with -InitializeAdministrator; preserve the database.'
} finally {
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $child) { $child.Dispose() }
}
