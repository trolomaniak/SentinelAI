#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CoreUrl,
    [Parameter(Mandatory = $true)][string]$AgentDataDirectory,
    [System.Management.Automation.PSCredential]$AdminCredential,
    [DateTimeOffset]$SinceUtc = [DateTimeOffset]::UtcNow,
    [ValidateRange(10, 600)][int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'PilotInstaller.psm1') -Force -DisableNameChecking
Add-Type -AssemblyName System.Net.Http
$client = $null

function ConvertTo-PilotObservationTime {
    param($Value)
    # PowerShell 7 parses JSON dates as DateTime; 5.1 leaves ISO strings.
    # Casting a DateTime to string would discard fractions and its UTC offset.
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [DateTime]) { return [DateTimeOffset]$Value }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)) { throw 'Invalid observation timestamp.' }
    return $parsed
}

function Invoke-PilotVerificationRequest {
    param([string]$Path, [string]$Method = 'GET', [string]$Body, [string]$Bearer)
    $request = New-Object System.Net.Http.HttpRequestMessage((New-Object System.Net.Http.HttpMethod($Method)), (New-Object Uri($script:origin, $Path)))
    $response = $null
    $stream = $null
    $memory = New-Object IO.MemoryStream
    $timeout = New-Object Threading.CancellationTokenSource
    $timeout.CancelAfter(10000)
    try {
        if (-not [string]::IsNullOrEmpty($Bearer)) { $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $Bearer) }
        if ($Method -eq 'POST') { $request.Content = New-Object System.Net.Http.StringContent($Body, [Text.Encoding]::UTF8, 'application/json') }
        $response = $script:client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $timeout.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw 'The Core request was rejected.' }
        if ($response.Content.Headers.ContentLength -gt 2097152) { throw 'The Core reply exceeds the verification limit.' }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = New-Object byte[] 8192
        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $timeout.Token).GetAwaiter().GetResult()) -gt 0) {
            if ($memory.Length + $count -gt 2097152) { throw 'The Core reply exceeds the verification limit.' }
            $memory.Write($buffer, 0, $count)
        }
        return [Text.Encoding]::UTF8.GetString($memory.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $memory.Dispose(); $timeout.Dispose(); $request.Dispose()
    }
}

try {
    $script:origin = Assert-PilotCoreOrigin $CoreUrl
    if (-not [IO.Path]::IsPathRooted($AgentDataDirectory)) { throw 'An absolute Agent data path is required.' }
    $AgentDataDirectory = [IO.Path]::GetFullPath($AgentDataDirectory)
    if ($env:OS -eq 'Windows_NT') { $AgentDataDirectory = Assert-PilotPath $AgentDataDirectory; Assert-PilotTrustedPath $AgentDataDirectory -AllowServiceWrite }
    $endpointPath = Join-Path $AgentDataDirectory 'endpoint-id'
    if (-not (Test-Path -LiteralPath $endpointPath -PathType Leaf) -or
        (Get-Item -LiteralPath $endpointPath).Length -gt 128 -or
        ((Get-Item -LiteralPath $endpointPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The enrolled endpoint receipt is missing or invalid.' }
    $endpointId = [Guid]::Empty
    if (-not [Guid]::TryParseExact([IO.File]::ReadAllText($endpointPath).Trim(), 'D', [ref]$endpointId) -or $endpointId -eq [Guid]::Empty) { throw 'Invalid endpoint receipt.' }
    if ($null -eq $AdminCredential) {
        $username = Read-Host 'Core administrator username'
        $password = Read-Host 'Core administrator password' -AsSecureString
        $AdminCredential = New-Object System.Management.Automation.PSCredential($username, $password)
    }
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $script:client = New-Object System.Net.Http.HttpClient($handler)
    $script:client.Timeout = [TimeSpan]::FromSeconds(10)
    $health = Invoke-PilotVerificationRequest '/api/health' | ConvertFrom-Json
    if ($health.status -ne 'healthy') { throw 'Core is not healthy.' }
    $loginBody = @{ username = $AdminCredential.UserName; password = $AdminCredential.GetNetworkCredential().Password } | ConvertTo-Json -Compress
    $login = Invoke-PilotVerificationRequest '/api/auth/login' 'POST' $loginBody | ConvertFrom-Json
    $loginBody = $null
    $accessToken = [string]$login.accessToken
    if ([string]::IsNullOrWhiteSpace($accessToken)) { throw 'Administrator authentication failed.' }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $detail = $null
    $seen = [DateTimeOffset]::MinValue
    $inventory = [DateTimeOffset]::MinValue
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $detail = Invoke-PilotVerificationRequest ('/api/admin/devices/' + $endpointId.ToString('D')) 'GET' $null $accessToken | ConvertFrom-Json
            $seen = ConvertTo-PilotObservationTime $detail.device.lastSeenUtc
            $inventory = ConvertTo-PilotObservationTime $detail.inventoryCollectedUtc
            if ([string]$detail.device.endpointId -eq $endpointId.ToString('D') -and
                $detail.device.healthState -eq 'healthy' -and
                -not [string]::IsNullOrWhiteSpace([string]$detail.device.name) -and
                -not [string]::IsNullOrWhiteSpace([string]$detail.device.agentVersion) -and
                $seen -ge $SinceUtc -and $inventory -ge $SinceUtc) { break }
            $detail = $null
        } catch { $detail = $null }
        Start-Sleep -Milliseconds 500
    }
    if ($null -eq $detail) { throw 'A fresh authenticated heartbeat and inventory were not received.' }
    $devices = @(Invoke-PilotVerificationRequest '/api/admin/devices' 'GET' $null $accessToken | ConvertFrom-Json)
    if (-not @($devices | Where-Object { [string]$_.endpointId -eq $endpointId.ToString('D') }).Count) { throw 'The enrolled endpoint is absent from Devices.' }
    $page = Invoke-PilotVerificationRequest '/'
    if (-not $page.Contains('./assets/app.js')) { throw 'The dashboard page is missing.' }
    $null = Invoke-PilotVerificationRequest '/assets/app.js'
    [pscustomobject]@{ EndpointId = $endpointId.ToString('D'); LastSeenUtc = $seen; InventoryCollectedUtc = $inventory; DashboardUrl = $script:origin.AbsoluteUri }
} catch {
    throw 'Pilot verification failed. Check the administrator credential, exact enrolled endpoint, Core connectivity and fresh heartbeat/inventory.'
} finally {
    if ($null -ne $client) { $client.Dispose() }
    $accessToken = $null; $loginBody = $null; $login = $null
}
