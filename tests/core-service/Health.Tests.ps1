# Portable transport tests for the real Core service health probe. The local
# server runs on a native thread so it can answer while PowerShell is blocked
# inside Read-CoreServiceHealth, including on Windows PowerShell hosts.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$modulePath = Join-Path $repositoryRoot 'installer/pilot/CoreServiceInstaller.psm1'
Import-Module $modulePath -Force -DisableNameChecking
$script:assertionCount = 0

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class CoreHealthHttpFixture : IDisposable
{
    private readonly TcpListener listener;
    private readonly Thread worker;
    private readonly ManualResetEvent stop = new ManualResetEvent(false);
    private readonly string[] parts;
    private readonly int[] delays;
    private readonly object gate = new object();
    private TcpClient accepted;
    private int connections;
    private string requestLine;

    public int Port { get; private set; }
    public int Connections { get { return Volatile.Read(ref connections); } }
    public string RequestLine { get { return requestLine; } }

    public CoreHealthHttpFixture(string[] parts, int[] delays)
    {
        if (parts == null || delays == null || parts.Length != delays.Length)
            throw new ArgumentException("Every response part needs one delay.");
        this.parts = parts;
        this.delays = delays;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = new Thread(Serve);
        worker.IsBackground = true;
        worker.Start();
    }

    private void Serve()
    {
        try
        {
            using (TcpClient client = listener.AcceptTcpClient())
            {
                lock (gate) accepted = client;
                Interlocked.Increment(ref connections);
                client.ReceiveTimeout = 3000;
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] request = new byte[4096];
                    int length = 0;
                    while (length < request.Length)
                    {
                        int count = stream.Read(request, length, request.Length - length);
                        if (count == 0) return;
                        length += count;
                        string received = Encoding.ASCII.GetString(request, 0, length);
                        if (received.Contains("\r\n\r\n"))
                        {
                            requestLine = received.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
                            break;
                        }
                    }
                    for (int i = 0; i < parts.Length; i++)
                    {
                        if (stop.WaitOne(delays[i])) return;
                        byte[] bytes = Encoding.ASCII.GetBytes(parts[i]);
                        stream.Write(bytes, 0, bytes.Length);
                        stream.Flush();
                    }
                    // Keep an incomplete response open until the probe times out.
                    stop.WaitOne(3000);
                }
            }
        }
        catch (SocketException) { }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    public void Dispose()
    {
        stop.Set();
        listener.Stop();
        lock (gate) if (accepted != null) accepted.Close();
        if (!worker.Join(3000)) throw new Exception("The local health fixture did not stop.");
        stop.Dispose();
    }
}
'@

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$Message)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Test $rejected $Message
}

function New-Response {
    param([int]$Status = 200, [string]$ContentType = 'application/json', [string]$Body = '{"status":"healthy"}')
    $reason = if ($Status -eq 200) { 'OK' } else { 'Unavailable' }
    return "HTTP/1.1 $Status $reason`r`nContent-Type: $ContentType`r`nContent-Length: $([Text.Encoding]::ASCII.GetByteCount($Body))`r`nConnection: close`r`n`r`n$Body"
}

function New-Fixture {
    param([string[]]$Parts, [int[]]$Delays)
    if ($null -eq $Delays) { $Delays = @(0) * $Parts.Length }
    return [CoreHealthHttpFixture]::new($Parts, $Delays)
}

function Invoke-Probe {
    param([CoreHealthHttpFixture]$Fixture, [int]$TimeoutMilliseconds = 1000)
    $origin = [Uri]::new('http://127.0.0.1:' + $Fixture.Port + '/')
    Read-CoreServiceHealth -Origin $origin -TimeoutMilliseconds $TimeoutMilliseconds
}

function Assert-RejectedResponse {
    param([string]$Response, [string]$Message)
    $fixture = New-Fixture -Parts @($Response)
    try {
        Assert-Rejected { Invoke-Probe -Fixture $fixture } $Message
        Assert-Test ($fixture.Connections -eq 1) ('Health request did not reach local fixture: ' + $Message)
    } finally { $fixture.Dispose() }
}

function Assert-Deadline {
    param([CoreHealthHttpFixture]$Fixture, [string]$Message)
    try {
        $watch = [Diagnostics.Stopwatch]::StartNew()
        Assert-Rejected { Invoke-Probe -Fixture $Fixture -TimeoutMilliseconds 300 } $Message
        $watch.Stop()
        Assert-Test ($watch.ElapsedMilliseconds -lt 1600) ($Message + ': total deadline was not enforced; elapsed ' + $watch.ElapsedMilliseconds + ' ms')
        Assert-Test ($Fixture.Connections -eq 1) ($Message + ': no local request reached the fixture')
    } finally { $Fixture.Dispose() }
}

$healthy = New-Fixture -Parts @((New-Response))
try {
    $result = Invoke-Probe -Fixture $healthy
    Assert-Test ($result.status -ceq 'healthy') 'A valid local Core health response was not returned.'
    Assert-Test (@($result.PSObject.Properties).Count -eq 1) 'The health response gained unexpected fields.'
    Assert-Test ($healthy.RequestLine -ceq 'GET /api/health HTTP/1.1') 'The probe requested an unexpected route or method.'
} finally { $healthy.Dispose() }

Assert-RejectedResponse (New-Response -Status 503) 'An HTTP error was accepted as healthy.'
Assert-RejectedResponse (New-Response -ContentType 'text/plain') 'A non-JSON content type was accepted.'
Assert-RejectedResponse (New-Response -Body '{"status":') 'Malformed JSON was accepted.'
Assert-RejectedResponse (New-Response -Body '{"status":"healthy","extra":"value"}') 'Extra health fields were accepted.'
Assert-RejectedResponse (New-Response -Body ('x' * 1025)) 'An oversized declared health body was accepted.'

# The second listener makes an accidental redirect observable without using any
# external destination or relying on network policy.
$redirectTarget = New-Fixture -Parts @((New-Response))
$redirectSource = New-Fixture -Parts @("HTTP/1.1 302 Found`r`nLocation: http://127.0.0.1:$($redirectTarget.Port)/api/health`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
try {
    Assert-Rejected { Invoke-Probe -Fixture $redirectSource } 'A redirect was followed or accepted as healthy.'
    Assert-Test ($redirectSource.Connections -eq 1) 'The redirect source received no request.'
    Assert-Test ($redirectTarget.Connections -eq 0) 'The health probe followed the redirect.'
} finally { $redirectSource.Dispose(); $redirectTarget.Dispose() }

# An unadvertised chunked body must be bounded after transport decoding too.
$largeBody = 'x' * 1100
$chunkSize = $largeBody.Length.ToString('X')
$chunked = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n$chunkSize`r`n$largeBody`r`n0`r`n`r`n"
Assert-RejectedResponse $chunked 'An oversized streamed health body was accepted.'

# A continuously active peer cannot extend the one absolute request deadline.
Assert-Deadline (New-Fixture -Parts @() -Delays @()) 'Stalled response headers'
$slowHeaders = @("HTTP/1.1 200 OK`r`n") + @(1..20 | ForEach-Object { 'X' })
$headerDelays = @(0) + @(1..20 | ForEach-Object { 150 })
Assert-Deadline (New-Fixture -Parts $slowHeaders -Delays $headerDelays) 'Slow-drip response headers'
$body = '{"status":"healthy"}'
$slowBody = @("HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: 20`r`nConnection: close`r`n`r`n") + @($body.ToCharArray() | ForEach-Object { [string]$_ })
$bodyDelays = @(0) + @(1..$body.Length | ForEach-Object { 150 })
Assert-Deadline (New-Fixture -Parts $slowBody -Delays $bodyDelays) 'Slow-drip response body'

Assert-Rejected { Read-CoreServiceHealth -Origin ([Uri]'http://example.test/') -TimeoutMilliseconds 100 } 'A non-loopback origin was accepted.'
Assert-Rejected { Read-CoreServiceHealth -Origin ([Uri]'https://127.0.0.1:5000/') -TimeoutMilliseconds 100 } 'A non-HTTP origin was accepted.'

Write-Output "Core service health transport tests passed ($script:assertionCount assertions)."
