# Real published Desktop activation and lifetime against installer-owned Core.
# Dot-source from Authentication.Acceptance.ps1; no browser or new login is used.
#requires -Version 5.1
function Invoke-NativeBrowserlessAcceptance {
    Add-Type -AssemblyName System.Net.Http
    if (Test-AuthenticationControl 'SignOutButton') {
        Invoke-AuthenticationControl 'SignOutButton'
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Browserless acceptance could not sign out.'
    }
    Assert-SignedOut
    if ($null -eq ('SentinelAIDesktopBrowserlessAcceptance.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace SentinelAIDesktopBrowserlessAcceptance {
    public static class Native {
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool ShowWindow(IntPtr handle, int command);
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool IsIconic(IntPtr handle);
    }
}
'@
    }
    $primaryId = $script:desktop.Id
    $sessionId = $script:desktop.SessionId
    $agentBefore = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAIAgent'"
    $agentState = if ($null -ne $agentBefore) { [string]$agentBefore.State } else { $null }
    $agentId = if ($null -ne $agentBefore) { [uint32]$agentBefore.ProcessId } else { 0 }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false; $handler.Credentials = $null
    $healthClient = [Net.Http.HttpClient]::new($handler)
    $healthClient.Timeout = [TimeSpan]::FromSeconds(5)
    $healthClient.MaxResponseContentBufferSize = 1024

    function Assert-BrowserlessServices {
        $held = Get-OwnedCoreProcess
        try { Assert-AuthenticationAcceptance ($held.Id -eq $script:coreProcess.Id -and -not $script:coreProcess.HasExited) 'Desktop operation changed the independent Core process.' }
        finally { $held.Dispose() }
        $agent = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAIAgent'"
        if ($null -ne $agentBefore) {
            Assert-AuthenticationAcceptance ($null -ne $agent -and $agent.State -ceq $agentState -and $agent.ProcessId -eq $agentId) 'Desktop operation changed the existing Agent service.'
        } else {
            Assert-AuthenticationAcceptance ($null -eq $agent) 'Desktop operation unexpectedly registered an Agent service.'
        }
        $response = $healthClient.GetAsync('http://127.0.0.1:5000/api/health').GetAwaiter().GetResult()
        try {
            Assert-AuthenticationAcceptance ($response.IsSuccessStatusCode -and
                $response.Content.Headers.ContentType.MediaType -ceq 'application/json') 'Core health was unavailable after Desktop operation.'
            try { $health = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json }
            catch { throw 'Core returned an invalid bounded health projection.' }
            Assert-AuthenticationAcceptance ($health.status -ceq 'healthy') 'Core was unhealthy after Desktop operation.'
        } finally { $response.Dispose() }
    }
    function Assert-OneBrowserlessDesktop {
        $instances = @(Get-CimInstance -ClassName Win32_Process -Filter ("Name='SentinelAI.Desktop.exe' AND SessionId=" + $sessionId) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
                [IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq $script:ExecutablePath })
        Assert-AuthenticationAcceptance ($instances.Count -eq 1 -and $instances[0].ProcessId -eq $primaryId) 'Duplicate launch did not preserve exactly one existing Desktop process.'
    }
    function Start-BrowserlessDesktop {
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $script:ExecutablePath
        $start.WorkingDirectory = Split-Path -Parent $script:ExecutablePath
        $start.UseShellExecute = $false
        $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_USERNAME')
        $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_PASSWORD')
        return [Diagnostics.Process]::Start($start)
    }
    function Assert-BrowserlessServiceDisplay {
        $agentLabel = switch ($agentState) {
            'Running' { 'Running'; break }
            'Stopped' { 'Stopped'; break }
            'Start Pending' { 'Starting'; break }
            'Stop Pending' { 'Stopping'; break }
            default { if ($null -eq $agentBefore) { 'Not installed' } else { 'Unknown' } }
        }
        Wait-AuthenticationAcceptance {
            $status = Find-AuthenticationControl 'DesktopServiceStatus'
            return $null -ne $status -and -not $status.Current.IsOffscreen -and
                $status.Current.Name -ceq ('Core service: Running ' + [char]0x00b7 + ' Agent service: ' + $agentLabel)
        } 'The native connection strip did not show the observed Core and Agent service states.'
    }
    try {
        Assert-BrowserlessServices
        Assert-BrowserlessServiceDisplay
        [void][SentinelAIDesktopBrowserlessAcceptance.Native]::ShowWindow($script:desktop.MainWindowHandle, 6)
        Wait-AuthenticationAcceptance { [SentinelAIDesktopBrowserlessAcceptance.Native]::IsIconic($script:desktop.MainWindowHandle) } 'The existing native window did not minimize.'
        $duplicate = Start-BrowserlessDesktop
        try {
            Assert-AuthenticationAcceptance ($duplicate.WaitForExit(15000) -and $duplicate.ExitCode -eq 0) 'Duplicate Desktop activation did not exit successfully within its deadline.'
        } finally {
            if (-not $duplicate.HasExited) { $duplicate.Kill(); [void]$duplicate.WaitForExit(10000) }
            $duplicate.Dispose()
        }
        Wait-AuthenticationAcceptance { -not [SentinelAIDesktopBrowserlessAcceptance.Native]::IsIconic($script:desktop.MainWindowHandle) } 'Duplicate launch did not restore the existing minimized native window.'
        Assert-AuthenticationAcceptance ($script:desktop.Id -eq $primaryId -and -not $script:desktop.HasExited) 'Duplicate activation replaced the original Desktop.'
        Assert-OneBrowserlessDesktop
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Activated Desktop did not preserve its signed-out native interface.'
        Assert-SignedOut
        Assert-BrowserlessServices

        [void][SentinelAIDesktopAuthenticationAcceptance.Native]::PostMessage($script:desktop.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
        Assert-AuthenticationAcceptance ($script:desktop.WaitForExit(30000) -and $script:desktop.ExitCode -eq 0) 'Desktop close did not fully exit the native process.'
        Assert-BrowserlessServices
        $script:root = $null
        $script:desktop.Dispose()
        $script:desktop = Start-BrowserlessDesktop
        $null = $script:desktop.Handle
        $primaryId = $script:desktop.Id
        Wait-AuthenticationAcceptance { $script:desktop.Refresh(); $script:desktop.MainWindowHandle -ne [IntPtr]::Zero } 'Reopened Desktop did not create its native window.'
        $script:root = [System.Windows.Automation.AutomationElement]::FromHandle($script:desktop.MainWindowHandle)
        Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Reopened Desktop did not reconnect to the initialized local Core.'
        Assert-SignedOut
        Assert-OneBrowserlessDesktop
        Assert-NoCredentialArguments $script:desktop
        Assert-BrowserlessServices
        Assert-BrowserlessServiceDisplay
    } finally { $healthClient.Dispose() }
}
