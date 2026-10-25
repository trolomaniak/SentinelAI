# Actual single-EXE first installation on a fresh, elevated interactive Windows
# x64 machine. Credentials enter protected native controls only. The fixture
# retains installed files/state and removes only its proven installer-owned
# services. Secure-desktop UAC consent is a separate manual check.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [ValidateRange(60, 900)][int]$TimeoutSeconds = 300,
    [switch]$PreserveInstallation,
    [ref]$InstallationContext,
    # MVP-3: a development pilot license key for a Setup built with development pilot public keys.
    [string]$PilotLicenseKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or
    -not [Environment]::UserInteractive -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Setup acceptance requires elevated interactive x64 Windows PowerShell 5.1.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $operatorSid = $identity.User.Value
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Setup acceptance must run already elevated; it never approves or bypasses UAC.'
    }
} finally { $identity.Dispose() }

$ExecutablePath = (Resolve-Path -LiteralPath $ExecutablePath).ProviderPath
$pilotLicenseKey = $null
if (-not [string]::IsNullOrWhiteSpace($PilotLicenseKeyPath)) {
    $pilotLicenseKey = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $PilotLicenseKeyPath).ProviderPath).Trim()
    if ($pilotLicenseKey.Length -gt 1024 -or $pilotLicenseKey -cnotmatch '\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z') { throw 'A development pilot license key is required.' }
}
if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf) -or
    [IO.Path]::GetFileName($ExecutablePath) -cne 'SentinelAI-Setup.exe') { throw 'The actual published Setup executable is required.' }
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$programRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelAI'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SentinelAI'
$shortcutRoot = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'SentinelAI'
$shortcutPath = Join-Path $shortcutRoot 'SentinelAI.lnk'
$coreCode = Join-Path $programRoot 'Core'
$coreData = Join-Path $dataRoot 'Core'
$agentCode = Join-Path $programRoot 'Agent'
$agentData = Join-Path $dataRoot 'Agent'
$desktopCode = Join-Path $programRoot 'Desktop'
$updaterCode = Join-Path $programRoot 'Updater'
$setupData = Join-Path $dataRoot 'Setup'
$setupHostRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SentinelAI-SetupHost'
$desktopExecutable = Join-Path $desktopCode 'SentinelAI.Desktop.exe'
$coreSid = 'S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900'
$localServiceSid = 'S-1-5-19'
foreach ($path in @($programRoot, $dataRoot, $shortcutRoot)) {
    if (Test-Path -LiteralPath $path) { throw 'Setup acceptance requires absent default installation directories; existing state will not be adopted or removed.' }
}
foreach ($name in @('SentinelAICore', 'SentinelAIAgent')) {
    if ($null -ne (Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $name + "'"))) {
        throw 'Setup acceptance requires no existing SentinelAI services.'
    }
}
$portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 5000)
try { $portProbe.Start() } finally { $portProbe.Stop() }

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Net.Http, System.Security
if ($null -eq ('SentinelAI.Setup.Acceptance.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace SentinelAI.Setup.Acceptance {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] private struct KeyboardInput {
            public ushort Key, Scan; public uint Flags, Time; public IntPtr Extra;
        }
        [StructLayout(LayoutKind.Explicit, Size = 32)] private struct InputData {
            [FieldOffset(0)] public KeyboardInput Keyboard;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Input { public uint Type; public InputData Data; }
        [DllImport("user32.dll", SetLastError=true)] private static extern uint SendInput(uint count, Input[] input, int size);
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool SetForegroundWindow(IntPtr handle);
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
        public static void TypePassword(string password, IntPtr expectedWindow) {
            if (String.IsNullOrEmpty(password) || password.Length > 256 || expectedWindow == IntPtr.Zero)
                throw new InvalidOperationException("Synthetic native input is invalid.");
            var inputs = new Input[2];
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            try {
                foreach (char character in password) {
                    if (elapsed.Elapsed.TotalSeconds >= 10 || GetForegroundWindow() != expectedWindow)
                        throw new InvalidOperationException("Protected native input lost foreground ownership or exceeded its deadline.");
                    inputs[0].Type = 1; inputs[0].Data.Keyboard.Scan = character; inputs[0].Data.Keyboard.Flags = 4;
                    inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 6;
                    if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                        throw new InvalidOperationException("Protected native input was incomplete.");
                    System.Threading.Thread.Sleep(20);
                }
                PressKey(9, expectedWindow);
            } finally { Array.Clear(inputs, 0, inputs.Length); }
        }
        public static void PressKey(ushort key, IntPtr expectedWindow) {
            if (GetForegroundWindow() != expectedWindow)
                throw new InvalidOperationException("Native action lost foreground ownership.");
            var inputs = new Input[2];
            try {
                inputs[0].Type = 1; inputs[0].Data.Keyboard.Key = key;
                inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 2;
                if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                    throw new InvalidOperationException("Native action input was incomplete.");
            } finally { Array.Clear(inputs, 0, inputs.Length); }
        }
    }
}
'@ | Out-Null
}

if ($null -eq ('SentinelAI.Setup.Acceptance.LocalNetwork' -as [type])) {
    # Raw HTTPS over the local-network listener with pin-only trust, like an Agent on another computer.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace SentinelAI.Setup.Acceptance {
    public static class LocalNetwork {
        public static string Sha256(byte[] data) {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "");
        }
        // Returns the negotiated protocol, cipher, key exchange and the bounded raw HTTP response. Each call uses
        // its own TLS target name, so SChannel never resumes a session from another call's trust decision.
        public static string[] Request(string address, int port, string pin, int protocols, string method, string path, string bearer, string body) {
            return Request(address, port, "sentinelai-core-" + Guid.NewGuid().ToString("N"), pin, protocols, method, path, bearer, body);
        }
        public static string[] Request(string address, int port, string target, string pin, int protocols, string method, string path, string bearer, string body) {
            using (var tcp = new TcpClient()) {
                if (!tcp.ConnectAsync(address, port).Wait(10000)) throw new IOException("The local-network listener did not accept a connection.");
                tcp.ReceiveTimeout = 10000; tcp.SendTimeout = 10000;
                RemoteCertificateValidationCallback pinned = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
                    return certificate != null && String.Equals(Sha256(certificate.GetRawCertData()), pin, StringComparison.Ordinal);
                };
                using (var tls = new SslStream(tcp.GetStream(), false, pinned)) {
                    try { tls.AuthenticateAsClient(target, null, (SslProtocols)protocols, false); }
                    catch (IOException error) { throw new IOException("TLS handshake failed: " + Describe(error), error); }
                    var content = body == null ? new byte[0] : Encoding.UTF8.GetBytes(body);
                    var head = new StringBuilder();
                    head.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\nHost: sentinelai-core\r\nConnection: close\r\n");
                    if (!String.IsNullOrEmpty(bearer)) head.Append("Authorization: Bearer ").Append(bearer).Append("\r\n");
                    if (body != null) head.Append("Content-Type: application/json\r\n");
                    head.Append("Content-Length: ").Append(content.Length).Append("\r\n\r\n");
                    var bytes = Encoding.ASCII.GetBytes(head.ToString());
                    var buffer = new byte[8192]; int total = 0, read;
                    try {
                        tls.Write(bytes, 0, bytes.Length); tls.Write(content, 0, content.Length); tls.Flush();
                        while (total < buffer.Length && (read = tls.Read(buffer, total, buffer.Length - total)) > 0) total += read;
                    } catch (IOException error) {
                        throw new IOException("HTTP exchange failed after TLS " + tls.SslProtocol + " " + tls.CipherAlgorithm + " " +
                            (int)tls.KeyExchangeAlgorithm + " with " + total + " response bytes: " + Describe(error), error);
                    }
                    return new[] { tls.SslProtocol.ToString(), tls.CipherAlgorithm.ToString(), ((int)tls.KeyExchangeAlgorithm).ToString(), Encoding.ASCII.GetString(buffer, 0, total) };
                }
            }
        }
        private static string Describe(IOException error) {
            var socket = error.InnerException as SocketException;
            return error.Message + (socket == null ? "" : " (" + socket.SocketErrorCode + ")");
        }
    }
}
'@ | Out-Null
}

$username = 'setup-test-' + [Guid]::NewGuid().ToString('N')
$passwordBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($passwordBytes) } finally { $random.Dispose() }
$password = [Convert]::ToBase64String($passwordBytes)
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
$assertionCount = 0
$setup = $null; $rerun = $null; $setupOuter = $null; $rerunOuter = $null
$desktop = $null; $coreProcess = $null; $agentProcess = $null
$activeProcess = $null; $activeRoot = $null; $client = $null; $accessToken = $null
$pendingOuter = $null; $pendingChild = $null
$installationStarted = $false
$installationCompleted = $false
$acceptancePassed = $false
$manualShortcutOpened = $false
$poisonedCaller = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-setup-untrusted-' + [Guid]::NewGuid().ToString('N'))
$poisonedExtraction = Join-Path $poisonedCaller 'runtime-cache'
$poisonedTemp = Join-Path $poisonedCaller 'temp'

# CI-only, fixed-category probes of Setup steps that stop making visible progress.
. (Join-Path $PSScriptRoot 'HangProbe.ps1')
function Assert-SetupAcceptance([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}
function Wait-SetupAcceptance([scriptblock]$Condition, [string]$Message, [int]$Seconds = 30) {
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    while ($elapsed.Elapsed.TotalSeconds -lt $Seconds) {
        if (& $Condition) { $script:assertionCount++; return }
        Start-Sleep -Milliseconds 100
    }
    throw $Message
}
function Find-SetupControl([string]$Id) {
    if ($null -eq $script:activeRoot) { return $null }
    $condition = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
    return $script:activeRoot.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
}
function Test-SetupControl([string]$Id, [bool]$Enabled = $true) {
    $control = Find-SetupControl $Id
    return $null -ne $control -and -not $control.Current.IsOffscreen -and (-not $Enabled -or $control.Current.IsEnabled)
}
function Show-SetupControl([string]$Id) {
    Wait-SetupAcceptance { $null -ne (Find-SetupControl $Id) } 'A required native control was absent.'
    if ((Find-SetupControl $Id).Current.IsOffscreen) {
        $condition = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::IsScrollPatternAvailableProperty, $true)
        $scroll = $script:activeRoot.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
        Assert-SetupAcceptance ($null -ne $scroll) 'A native action outside the viewport had no scrollable surface.'
        $pattern = [Windows.Automation.ScrollPattern]$scroll.GetCurrentPattern([Windows.Automation.ScrollPattern]::Pattern)
        Assert-SetupAcceptance $pattern.Current.VerticallyScrollable 'A native action could not be brought into view.'
        $pattern.SetScrollPercent([Windows.Automation.ScrollPattern]::NoScroll, 100)
    }
    Wait-SetupAcceptance { Test-SetupControl $Id $false } 'A required native control remained outside the visible viewport.'
}
function Use-SetupWindow([Diagnostics.Process]$Process) {
    $script:activeProcess = $Process
    Wait-SetupAcceptance {
        if ($Process.HasExited) { throw 'The tested native executable exited before opening its window.' }
        $Process.Refresh(); return $Process.MainWindowHandle -ne [IntPtr]::Zero
    } 'The tested executable did not open a native window.'
    $script:activeRoot = [Windows.Automation.AutomationElement]::FromHandle($Process.MainWindowHandle)
}
function Start-TestSetup([string]$SetupExecutable = $script:ExecutablePath) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $SetupExecutable; $start.WorkingDirectory = Split-Path -Parent $SetupExecutable
    # The requireAdministrator manifest is exercised under an already elevated
    # token. No silent installation, extracted installer script or UAC bypass.
    $start.UseShellExecute = $false
    foreach ($name in @($start.EnvironmentVariables.Keys)) {
        if ([string]$name -ieq 'SENTINELAI_BOOTSTRAP_USERNAME' -or [string]$name -ieq 'SENTINELAI_BOOTSTRAP_PASSWORD' -or
            [string]$name -ieq 'DOTNET_BUNDLE_EXTRACT_BASE_DIR') { $start.EnvironmentVariables.Remove([string]$name) }
    }
    # The native wrapper must establish its own protected runtime and child
    # temporary directory before CLR starts. Mixed-case caller overrides and a
    # writable synthetic cache must remain unused, including by embedded CLIs.
    $start.EnvironmentVariables.Add('DoTnEt_BuNdLe_ExTrAcT_BaSe_DiR', $script:poisonedExtraction)
    $start.EnvironmentVariables['TEMP'] = $script:poisonedTemp
    $start.EnvironmentVariables['TMP'] = $script:poisonedTemp
    $outer = [Diagnostics.Process]::Start($start); $null = $outer.Handle
    $child = $null
    try {
        $script:pendingOuter = $outer
        Wait-SetupAcceptance {
            if ($outer.HasExited) { throw 'The native Setup wrapper exited before starting its protected host.' }
            $records = @(Get-CimInstance -ClassName Win32_Process -Filter ('ParentProcessId=' + $outer.Id + " AND Name='SentinelAI.Setup.Host.exe'"))
            if ($records.Count -gt 1) { throw 'The native Setup wrapper started more than one private host.' }
            if ($records.Count -eq 0) { return $false }
            $image = [string]$records[0].ExecutablePath
            $pattern = '^' + [Regex]::Escape($script:setupHostRoot) + '\\[0-9a-f]{32}\\SentinelAI\.Setup\.Host\.exe$'
            if ($image -cnotmatch $pattern) { throw 'The native Setup wrapper started an unexpected host image.' }
            $script:pendingChild = [Diagnostics.Process]::GetProcessById([int]$records[0].ProcessId)
            $null = $script:pendingChild.Handle
            Assert-SetupAcceptance ([IO.Path]::GetFullPath($script:pendingChild.MainModule.FileName) -ceq $image) 'The held Setup host runs different code.'
            return $true
        } 'The native Setup wrapper did not start its exact protected host.' 90
        $child = $script:pendingChild
        $directory = Split-Path -Parent $child.MainModule.FileName
        Assert-PrivateSetupRuntime $script:setupHostRoot
        Assert-PrivateSetupRuntime $directory
        Assert-NoCredentialArguments $outer
        Assert-NoCredentialArguments $child
        $script:pendingOuter = $null; $script:pendingChild = $null
        return [pscustomobject]@{ Outer = $outer; Host = $child; Directory = $directory }
    } catch {
        if ($null -ne $script:pendingChild) {
            try { if (-not $script:pendingChild.HasExited) { $script:pendingChild.Kill(); [void]$script:pendingChild.WaitForExit(10000) } }
            finally { $script:pendingChild.Dispose(); $script:pendingChild = $null }
        }
        try { if (-not $outer.HasExited) { $outer.Kill(); [void]$outer.WaitForExit(10000) } }
        finally { $outer.Dispose(); $script:pendingOuter = $null }
        throw
    }
}
function Set-NativePassword([string]$Id, [string]$NextId) {
    Wait-SetupAcceptance { Test-SetupControl $Id } 'A required protected native password input was unavailable.'
    $control = Find-SetupControl $Id
    Assert-SetupAcceptance $control.Current.IsPassword 'A native password control exposed an ordinary text input.'
    $pattern = $null
    if ($control.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
        $value = ''
        try { $value = ([Windows.Automation.ValuePattern]$pattern).Current.Value } catch [InvalidOperationException] { }
        Assert-SetupAcceptance ([string]::IsNullOrEmpty($value)) 'A native password control exposed a readable automation value.'
    }
    [void][SentinelAI.Setup.Acceptance.Native]::SetForegroundWindow($script:activeProcess.MainWindowHandle)
    $control.SetFocus()
    Wait-SetupAcceptance {
        $focused = Find-SetupControl $Id
        return $null -ne $focused -and $focused.Current.HasKeyboardFocus -and
            [SentinelAI.Setup.Acceptance.Native]::GetForegroundWindow() -eq $script:activeProcess.MainWindowHandle
    } 'Protected password input did not own foreground focus.'
    [SentinelAI.Setup.Acceptance.Native]::TypePassword($script:password, $script:activeProcess.MainWindowHandle)
    Wait-SetupAcceptance {
        $next = Find-SetupControl $NextId
        return $null -ne $next -and $next.Current.HasKeyboardFocus -and
            [SentinelAI.Setup.Acceptance.Native]::GetForegroundWindow() -eq $script:activeProcess.MainWindowHandle
    } 'Native password input did not finish processing at its next control.'
}
function Set-SetupPilotLicenseKey([string]$Key) {
    Wait-SetupAcceptance { Test-SetupControl 'SetupPilotLicenseKey' } 'Setup did not ask for the pilot license key.'
    $pilot = Find-SetupControl 'SetupPilotLicenseKey'
    ([Windows.Automation.ValuePattern]$pilot.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).SetValue($Key)
}
function Set-SetupCredentials {
    if ($null -ne $script:pilotLicenseKey) { Set-SetupPilotLicenseKey $script:pilotLicenseKey }
    Wait-SetupAcceptance { Test-SetupControl 'SetupAdministratorUsername' } 'Setup administrator input was unavailable.'
    $user = Find-SetupControl 'SetupAdministratorUsername'
    ([Windows.Automation.ValuePattern]$user.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).SetValue($script:username)
    Set-NativePassword 'SetupAdministratorPassword' 'SetupAdministratorConfirmPassword'
    Set-NativePassword 'SetupAdministratorConfirmPassword' 'SetupInstallButton'
}
function Submit-NativeAction([string]$Id) {
    Wait-SetupAcceptance { Test-SetupControl $Id } 'A required native action was unavailable.'
    $control = Find-SetupControl $Id
    Assert-SetupAcceptance ($control.Current.HasKeyboardFocus -and
        [SentinelAI.Setup.Acceptance.Native]::GetForegroundWindow() -eq $script:activeProcess.MainWindowHandle) 'The native submit action did not own foreground focus.'
    # UI Automation Invoke can overtake WPF's queued password input. Submit via
    # the same keyboard queue, as the existing native authentication fixture.
    [SentinelAI.Setup.Acceptance.Native]::PressKey(13, $script:activeProcess.MainWindowHandle)
}
function Assert-NoSecretText([string]$Text) {
    Assert-SetupAcceptance (-not $Text.Contains($script:password) -and
        ([string]::IsNullOrEmpty($script:accessToken) -or -not $Text.Contains($script:accessToken))) 'A synthetic password or bearer appeared in public installation data.'
}
function Assert-NoCredentialArguments([Diagnostics.Process]$Process) {
    $record = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $Process.Id)
    Assert-SetupAcceptance ($null -ne $record -and -not [string]::IsNullOrWhiteSpace([string]$record.CommandLine)) 'A held process command line was unavailable.'
    Assert-NoSecretText ([string]$record.CommandLine)
    Assert-SetupAcceptance (-not $record.CommandLine.Contains('SENTINELAI_BOOTSTRAP_')) 'A service or desktop command contains bootstrap credential configuration.'
}
function Assert-SetupChildArguments {
    Assert-SetupAcceptance (-not $script:setupOuter.HasExited) 'The native wrapper stopped holding its still-running private host.'
    $hostRecord = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $script:setup.Id)
    Assert-SetupAcceptance ($null -ne $hostRecord -and $hostRecord.ParentProcessId -eq $script:setupOuter.Id) 'The held private Setup host is no longer the exact wrapper child.'
    foreach ($record in @(Get-CimInstance -ClassName Win32_Process -Filter ('ParentProcessId=' + $script:setup.Id))) {
        # A short-lived helper may exit while CIM takes its snapshot. Inspect
        # every available command without turning normal child exit into a race.
        if ([string]::IsNullOrWhiteSpace([string]$record.CommandLine)) { continue }
        Assert-NoSecretText ([string]$record.CommandLine)
        Assert-SetupAcceptance (-not $record.CommandLine.Contains('SENTINELAI_BOOTSTRAP_')) 'A running Setup child command contains bootstrap credential configuration.'
    }
}
function Get-SetupService([string]$Name) { return Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $Name + "'") -OperationTimeoutSec 15 }
function Stop-SetupDescendantProcesses([object[]]$Roots) {
    # After a failure, the Setup worker and its Updater outlive the killed host and race the
    # cleanup. Stop every descendant created after its parent (no reused PIDs), deepest first,
    # and report counts only: no names beyond fixed categories, no command lines or paths.
    try {
        $records = @(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 15)
        $byParent = @{}
        foreach ($record in $records) {
            $key = [int]$record.ParentProcessId
            if (-not $byParent.ContainsKey($key)) { $byParent[$key] = New-Object 'System.Collections.Generic.List[object]' }
            $byParent[$key].Add($record)
        }
        $queue = New-Object 'System.Collections.Generic.Queue[object]'
        foreach ($root in @($Roots | Where-Object { $null -ne $_ })) {
            $self = @($records | Where-Object { [int]$_.ProcessId -eq $root.Id })
            $created = if ($self.Count -eq 1) { $self[0].CreationDate } else { try { $root.StartTime } catch { $null } }
            if ($null -ne $created) { $queue.Enqueue([pscustomobject]@{ Id = $root.Id; Created = $created; Depth = 0 }) }
        }
        $found = New-Object 'System.Collections.Generic.List[object]'
        $seen = New-Object 'System.Collections.Generic.HashSet[int]'
        while ($queue.Count -gt 0) {
            $parent = $queue.Dequeue()
            if (-not $byParent.ContainsKey($parent.Id)) { continue }
            foreach ($child in $byParent[$parent.Id]) {
                if ($null -eq $child.CreationDate -or $child.CreationDate -lt $parent.Created -or -not $seen.Add([int]$child.ProcessId)) { continue }
                $entry = [pscustomobject]@{ Id = [int]$child.ProcessId; Name = [string]$child.Name; Created = $child.CreationDate; Depth = $parent.Depth + 1 }
                $found.Add($entry); $queue.Enqueue($entry)
            }
        }
        $counts = @{ powershell = 0; conhost = 0; updater = 0; other = 0 }
        foreach ($entry in $found) {
            switch -Exact ($entry.Name.ToLowerInvariant()) {
                'powershell.exe' { $counts.powershell++ } 'conhost.exe' { $counts.conhost++ }
                'sentinelai.updater.exe' { $counts.updater++ } default { $counts.other++ }
            }
        }
        foreach ($entry in @($found | Sort-Object -Property Depth -Descending)) {
            try { Stop-Process -Id $entry.Id -Force -ErrorAction Stop } catch { }
        }
        Write-Host ('SetupOrphans: Powershell={0}; Conhost={1}; Updater={2}; Other={3}' -f $counts.powershell, $counts.conhost, $counts.updater, $counts.other)
    } catch { Write-Host 'SetupOrphans: ProbeFailed=True' }
}
function Get-SetupFailureSummary {
    # Only exact known public UI literals and fixed presence flags may enter CI
    # diagnostics. Never include native error text, exceptions, stdin or secrets.
    $stage = 'Unknown'
    try {
        $progress = Find-SetupControl 'SetupProgressText'
        if ($null -ne $progress) {
            foreach ($known in @('Validating installation files...', 'Preparing Core...',
                'Creating the local administrator...', 'Starting Core...', 'Enrolling Agent...',
                'Installing Windows services and Desktop...', 'Starting Windows services...',
                "Creating Core's local-network certificate...", 'Allowing Agents on the local network...',
                'Installing and enrolling Agent...', 'Installing Desktop and Updater...',
                'Creating Start Menu shortcuts...', 'Installation finished.', 'Stopping setup...',
                'Checking the installed deployment...', 'Replacing verified program files...',
                'Verifying installation health...', 'Restoring the previous working version...',
                'Removing the owned installation...', 'Recovering the interrupted installation...', 'Operation finished.')) {
                if ([string]$progress.Current.Name -ceq $known) { $stage = $known; break }
            }
        }
    } catch { }
    $serviceProbeSucceeded = $true; $corePresent = $false; $agentPresent = $false
    try {
        $corePresent = $null -ne (Get-SetupService 'SentinelAICore')
        $agentPresent = $null -ne (Get-SetupService 'SentinelAIAgent')
    } catch { $serviceProbeSucceeded = $false }
    return ('The actual Setup executable reported a safe installation failure. Stage="{0}"; ServiceProbeSucceeded={1}; CoreServicePresent={2}; AgentServicePresent={3}; CoreCodePresent={4}; CoreDataPresent={5}; AgentCodePresent={6}; AgentDataPresent={7}; DesktopCodePresent={8}; UpdaterCodePresent={9}.' -f
        $stage, $serviceProbeSucceeded, $corePresent, $agentPresent,
        (Test-Path -LiteralPath $script:coreCode -PathType Container), (Test-Path -LiteralPath $script:coreData -PathType Container),
        (Test-Path -LiteralPath $script:agentCode -PathType Container), (Test-Path -LiteralPath $script:agentData -PathType Container),
        (Test-Path -LiteralPath $script:desktopCode -PathType Container), (Test-Path -LiteralPath $script:updaterCode -PathType Container))
}
function Get-SetupTimeoutSummary {
    # Same disclosure rule as Get-SetupFailureSummary: fixed literals, service
    # states, presence flags and counts only. Never native text, paths or secrets.
    $states = foreach ($name in @('SentinelAICore', 'SentinelAIAgent')) {
        try {
            $service = Get-SetupService $name
            if ($null -eq $service) { 'Absent' }
            elseif ([string]$service.State -in @('Running', 'Stopped', 'Start Pending', 'Stop Pending', 'Paused')) { [string]$service.State }
            else { 'Other' }
        } catch { 'ProbeFailed' }
    }
    $enrollment = foreach ($file in @('endpoint-id', 'installation-id', 'enrollment-state', 'pilot-enrollment-token')) {
        Test-Path -LiteralPath (Join-Path $script:agentData $file) -PathType Leaf
    }
    $updaters = @(Get-Process -Name 'SentinelAI.Updater' -ErrorAction SilentlyContinue).Count
    return ('{0} CoreService={1}; AgentService={2}; AgentEndpointId={3}; AgentInstallationId={4}; AgentEnrollmentState={5}; AgentEnrollmentTokenPending={6}; UpdaterProcesses={7}; ElapsedSeconds={8}; {9}.' -f
        ((Get-SetupFailureSummary) -replace '\AThe actual Setup executable reported a safe installation failure\. ', 'The actual Setup executable did not complete installation. '),
        $states[0], $states[1], $enrollment[0], $enrollment[1], $enrollment[2], $enrollment[3], $updaters,
        [int]([DateTimeOffset]::UtcNow - $script:installationSince).TotalSeconds, (Get-SetupProductEventSummary $script:installationSince))
}
function Get-SetupProductEventSummary([DateTimeOffset]$Since) {
    # Fixed identifiers only: level, SentinelAI log source, logger category, event ID and
    # exception type name of SentinelAI's own Application log entries. Never message text.
    $signatures = [ordered]@{}
    $crashes = 'Unknown'; $serviceErrors = 'Unknown'
    try {
        $start = $Since.LocalDateTime
        $entries = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = @(1, 2, 3); StartTime = $start } -ErrorAction SilentlyContinue)
        foreach ($entry in @($entries | Where-Object { $_.ProviderName -like 'SentinelAI*' } | Sort-Object TimeCreated)) {
            $text = [string]$entry.Message
            if ([string]::IsNullOrEmpty($text)) { $text = @($entry.Properties | ForEach-Object { [string]$_.Value }) -join "`n" }
            $provider = 'SentinelAI-other'; $category = 'unknown'; $eventId = 'unknown'; $exception = 'none'
            if ([string]$entry.ProviderName -cmatch '\ASentinelAI[A-Za-z0-9_.]{0,64}\z') { $provider = [string]$entry.ProviderName }
            if ($text -cmatch '(?m)^Category: ([A-Za-z0-9_.]{1,128})\r?$') { $category = $Matches[1] }
            if ($text -cmatch '(?m)^EventId: ([0-9]{1,9})\r?$') { $eventId = $Matches[1] }
            if ($text -cmatch '(?m)^Exception:[ ]*\r?\n([A-Za-z0-9_.]{1,160})(?::|\r?$)') { $exception = $Matches[1] }
            $level = switch ([int]$entry.Level) { 1 { 'C' } 2 { 'E' } 3 { 'W' } default { 'O' } }
            $key = $level + '/' + $provider + '/' + $category + '/' + $eventId + '/' + $exception
            if ($signatures.Contains($key)) { $signatures[$key] = [int]$signatures[$key] + 1 } else { $signatures[$key] = 1 }
        }
        $crashes = @($entries | Where-Object { $_.ProviderName -in @('.NET Runtime', 'Application Error') -and [string]$_.Message -like '*SentinelAI*' }).Count
        $serviceErrors = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager';
            Id = @(7000, 7009, 7011, 7022, 7023, 7024, 7031, 7034); StartTime = $start } -ErrorAction SilentlyContinue).Count
    } catch { }
    $listed = @($signatures.Keys | Select-Object -Last 12 | ForEach-Object { $_ + ' x' + $signatures[$_] })
    return ('ProductEvents=[{0}]; SentinelAICrashEvents={1}; ServiceControlErrors={2}' -f ($listed -join ', '), $crashes, $serviceErrors)
}
function Get-HeldInstalledProcess([string]$Name, [string]$Executable, [string]$Account) {
    $service = Get-SetupService $Name
    $expectedImage = '"' + $Executable + '" --config "' + (Join-Path $(if ($Name -eq 'SentinelAICore') { $script:coreData } else { $script:agentData }) 'pilot-config.json') + '"'
    Assert-SetupAcceptance ($null -ne $service -and $service.State -ceq 'Running' -and $service.ProcessId -gt 0) 'An installed Windows service was not running.'
    Assert-SetupAcceptance ($service.PathName -ceq $expectedImage -and $service.StartName -ieq $Account -and $service.StartMode -ceq 'Auto') 'An installed service has an unexpected image, identity or startup mode.'
    Assert-NoSecretText ([string]$service.PathName)
    $process = [Diagnostics.Process]::GetProcessById([int]$service.ProcessId)
    try {
        $null = $process.Handle
        Assert-SetupAcceptance ([IO.Path]::GetFullPath($process.MainModule.FileName) -ieq $Executable) 'A service registration runs different code.'
        Assert-NoCredentialArguments $process
        return $process
    } catch { $process.Dispose(); throw }
}
function Assert-CoreListener {
    $service = Get-SetupService 'SentinelAICore'
    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue)
    Assert-SetupAcceptance (-not $script:coreProcess.HasExited -and $service.State -ceq 'Running' -and
        $service.ProcessId -eq $script:coreProcess.Id -and $listeners.Count -eq 1 -and
        $listeners[0].OwningProcess -eq $script:coreProcess.Id) 'The local Core origin is not owned exclusively by the held installed service.'
}
function Invoke-SetupCoreRequest([string]$Path, [string]$Method = 'GET', [string]$Body, [string]$Bearer) {
    Assert-CoreListener
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), [Uri]::new([Uri]'http://127.0.0.1:5000/', $Path))
    $timeout = [Threading.CancellationTokenSource]::new(10000)
    $response = $null; $stream = $null; $memory = [IO.MemoryStream]::new()
    try {
        if ($Bearer) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Bearer) }
        if ($Method -eq 'POST') { $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json') }
        $response = $script:client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $timeout.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode -or $response.Content.Headers.ContentLength -gt 2097152) { throw 'Core rejected an acceptance request or exceeded the response bound.' }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = New-Object byte[] 8192
        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $timeout.Token).GetAwaiter().GetResult()) -gt 0) {
            if ($memory.Length + $count -gt 2097152) { throw 'Core acceptance response exceeded its bound.' }
            $memory.Write($buffer, 0, $count)
        }
        Assert-CoreListener
        return [Text.Encoding]::UTF8.GetString($memory.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }; if ($null -ne $response) { $response.Dispose() }
        $request.Dispose(); $timeout.Dispose(); $memory.Dispose()
    }
}
function Get-EffectiveAllowRights([string]$Path, [string]$Sid) {
    $rights = 0
    foreach ($rule in (Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ceq $Sid -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) { $rights = $rights -bor [int]$rule.FileSystemRights }
    }
    return $rights
}
function Assert-ProtectedTree([string]$Root, [string[]]$AllowedWriters) {
    $items = @((Get-Item -LiteralPath $Root -Force)) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
    Assert-SetupAcceptance ($items.Count -le 8192) 'An installed tree exceeded the acceptance inspection bound.'
    $mutation = [int]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($item in $items) {
        Assert-SetupAcceptance (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'An installed file or directory is a link.'
        try {
            $acl = Get-Acl -LiteralPath $item.FullName
        } catch {
            # The running Agent replaces its event checkpoint through a temporary file and a rename, so
            # that file can vanish between enumeration and inspection. Only a path that no longer exists
            # is skipped; every ownership, ACL or link violation on an existing path still fails.
            if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or
                (Test-Path -LiteralPath $item.FullName)) { throw }
            continue
        }
        Assert-SetupAcceptance ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cin $AllowedWriters) 'An untrusted identity owns an installed path.'
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ([int]$rule.FileSystemRights -band $mutation) -ne 0) {
                Assert-SetupAcceptance ($rule.IdentityReference.Value -cin $AllowedWriters) 'An untrusted identity can mutate installation code or state.'
            }
        }
    }
}
function Assert-PrivateSetupRuntime([string]$Root) {
    # CLR/PowerShell can remove an ephemeral private temp entry while its live
    # tree is inspected. Repeat the complete inspection only for missing items;
    # every ownership/ACL/link violation still fails immediately.
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            Assert-ProtectedTree $Root @('S-1-5-32-544', 'S-1-5-18')
            Assert-SetupAcceptance (Get-Acl -LiteralPath $Root).AreAccessRulesProtected 'The native private runtime root inherits permissions.'
            foreach ($item in @((Get-Item -LiteralPath $Root -Force)) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
                foreach ($rule in (Get-Acl -LiteralPath $item.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0) {
                        Assert-SetupAcceptance ($rule.IdentityReference.Value -cin @('S-1-5-32-544', 'S-1-5-18')) 'The native runtime cache admits an untrusted reader or writer.'
                    }
                }
            }
            return
        } catch {
            if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or $attempt -eq 2) { throw }
            Start-Sleep -Milliseconds 25
        }
    }
}
function Assert-NativeSetupRuntime([Diagnostics.Process]$HostProcess, [Diagnostics.Process]$OuterProcess) {
    Assert-SetupAcceptance (-not $OuterProcess.HasExited -and -not $HostProcess.HasExited) 'The native wrapper did not retain its running WPF host.'
    $coreClr = @($HostProcess.Modules | Where-Object { $_.ModuleName -ieq 'coreclr.dll' })
    Assert-SetupAcceptance ($coreClr.Count -eq 1 -and [IO.Path]::GetFullPath($coreClr[0].FileName) -ieq
        (Join-Path (Split-Path -Parent $HostProcess.MainModule.FileName) 'coreclr.dll')) 'The WPF host loaded CLR outside its private native extraction directory.'
}
function Assert-InstalledServiceRuntime([Diagnostics.Process]$ServiceProcess, [string]$CodeDirectory) {
    $coreClr = @($ServiceProcess.Modules | Where-Object { $_.ModuleName -ieq 'coreclr.dll' })
    Assert-SetupAcceptance ($coreClr.Count -eq 1 -and [IO.Path]::GetFullPath($coreClr[0].FileName) -ieq
        (Join-Path $CodeDirectory 'coreclr.dll')) 'An installed service loaded CLR outside its protected self-contained code directory.'
}
function Assert-PoisonedCallerUntouched {
    $items = @(Get-ChildItem -LiteralPath $script:poisonedCaller -Recurse -Force)
    Assert-SetupAcceptance ($items.Count -eq 4) 'Setup or an embedded CLI used caller-controlled temporary/runtime extraction directories.'
    foreach ($directory in @($script:poisonedExtraction, $script:poisonedTemp)) {
        $sentinel = Join-Path $directory 'sentinel.txt'
        Assert-SetupAcceptance ((Test-Path -LiteralPath $sentinel -PathType Leaf) -and
            [IO.File]::ReadAllText($sentinel) -ceq 'Synthetic caller-controlled runtime sentinel.') 'Setup changed caller-controlled runtime sentinels.'
    }
}
function Assert-ServiceAcl([string]$Path, [string]$Sid, [int]$Required, [int]$Forbidden) {
    $rights = Get-EffectiveAllowRights $Path $Sid
    Assert-SetupAcceptance (($rights -band $Required) -eq $Required -and ($rights -band $Forbidden) -eq 0) 'A service ACL does not preserve its required limited rights.'
}
function Read-SetupStateDigest([string]$Path) {
    Assert-SetupAcceptance (Test-Path -LiteralPath $Path -PathType Leaf) 'Expected installed state is missing.'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
function Wait-ExactEndpoint([Guid]$EndpointId, [DateTimeOffset]$SinceUtc) {
    Wait-SetupAcceptance {
        $detail = Invoke-SetupCoreRequest ('/api/admin/devices/' + $EndpointId.ToString('D')) 'GET' $null $script:accessToken | ConvertFrom-Json
        $heartbeat = [DateTimeOffset]::MinValue; $inventory = [DateTimeOffset]::MinValue
        return [string]$detail.device.endpointId -ceq $EndpointId.ToString('D') -and
            [string]$detail.device.healthState -ceq 'healthy' -and
            [DateTimeOffset]::TryParse([string]$detail.device.lastSeenUtc, [ref]$heartbeat) -and
            [DateTimeOffset]::TryParse([string]$detail.inventoryCollectedUtc, [ref]$inventory) -and
            $heartbeat -ge $SinceUtc -and $inventory -ge $SinceUtc
    } 'The exact enrolled Agent did not deliver fresh authenticated heartbeat and inventory.' $script:TimeoutSeconds
}
function Get-AgentTelemetry([Guid]$EndpointId) {
    # The device view's telemetry projection: availabilities and observed states, never the application list.
    $detail = Invoke-SetupCoreRequest ('/api/admin/devices/' + $EndpointId.ToString('D')) 'GET' $null $script:accessToken | ConvertFrom-Json
    return $detail.securityTelemetry
}
function Get-AgentEventSources([Guid]$EndpointId) {
    # Status only: channel states, counters and record numbers, never event content.
    $view = Invoke-SetupCoreRequest ('/api/admin/devices/' + $EndpointId.ToString('D') + '/event-sources') 'GET' $null $script:accessToken | ConvertFrom-Json
    return @($view.sources)
}

$localNetworkPort = 5443
$firewallRuleName = 'SentinelAI-Core-LocalNetwork'
function Get-SetupLocalNetworkPin {
    # The pin Setup configured for Core; Agents receive the same value.
    $config = [IO.File]::ReadAllText((Join-Path $script:coreData 'pilot-config.json')) | ConvertFrom-Json
    Assert-SetupAcceptance ([string]$config.SentinelAI.LocalNetworkPort -ceq [string]$script:localNetworkPort -and
        [string]$config.SentinelAI.LocalNetworkCertificateSha256 -cmatch '\A[0-9A-F]{64}\z') 'Setup did not configure the default local-network listener and certificate pin.'
    return [string]$config.SentinelAI.LocalNetworkCertificateSha256
}
function Get-SetupLocalNetworkCertificate([string]$Pin) {
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
    try {
        return @($store.Certificates | Where-Object { [SentinelAI.Setup.Acceptance.LocalNetwork]::Sha256($_.RawData) -ceq $Pin })
    } finally { $store.Close() }
}
function Assert-SetupLocalNetworkCertificate([string]$Pin) {
    $certificates = @(Get-SetupLocalNetworkCertificate $Pin)
    Assert-SetupAcceptance ($certificates.Count -eq 1 -and $certificates[0].HasPrivateKey -and
        $certificates[0].FriendlyName -ceq 'SentinelAI Core local network') "Core's pinned certificate is not in LocalMachine\My with its key."
    $certificate = $certificates[0]
    $names = @($certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.17' } | ForEach-Object { $_.Format($false) })
    Assert-SetupAcceptance ($names.Count -eq 1 -and $names[0] -match ('(?i)DNS Name=' + [Regex]::Escape([Net.Dns]::GetHostName()))) "Core's certificate does not name this computer."
    Assert-SetupAcceptance ($certificate.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow.AddYears(10).AddDays(-2) -and
        $certificate.PublicKey.Oid.Value -ceq '1.2.840.10045.2.1') "Core's certificate is not an ECDSA certificate valid for ten years."
    foreach ($storeName in @('Root', 'CA', 'TrustedPeople')) {
        $trusted = New-Object Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
        $trusted.Open([Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly')
        try {
            Assert-SetupAcceptance (@($trusted.Certificates | Where-Object { [SentinelAI.Setup.Acceptance.LocalNetwork]::Sha256($_.RawData) -ceq $Pin }).Count -eq 0) 'Setup added Core''s certificate to a trusted store.'
        } finally { $trusted.Close() }
    }
    # The private key is usable only by Core's service account, SYSTEM and Administrators, and is not exportable.
    $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
    try {
        Assert-SetupAcceptance ($key -is [Security.Cryptography.ECDsaCng] -and $key.Key.IsMachineKey -and
            [string]$key.Key.ExportPolicy -ceq 'None' -and $key.KeySize -eq 256) "Core's private key is not a non-exportable P-256 machine key."
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList @($key.Key.GetProperty('Security Descr', [Security.Cryptography.CngPropertyOptions]4).GetValue(), 0)
        $entries = @($descriptor.DiscretionaryAcl | ForEach-Object {
            $common = $_ -is [Security.AccessControl.CommonAce]
            [pscustomobject]@{
                Allowed = ($common -and [string]$_.AceQualifier -ceq 'AccessAllowed')
                Sid = $(if ($common) { [string]$_.SecurityIdentifier.Value } else { '' })
                Mask = $(if ($common) { [int64]$_.AccessMask -band 4294967295 } else { [int64]0 })
            }
        })
        Assert-SetupAcceptance (Test-SetupKeyAccess (($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0) $entries) ("Core's private key is usable outside Core's service account, SYSTEM and Administrators: " + $descriptor.GetSddlForm('Access'))
    } finally { if ($null -ne $key) { $key.Dispose() } }
    foreach ($certificate in $certificates) { $certificate.Dispose() }
}
# Microsoft Software KSP reports each granted right with its generic equivalent (0xD01F01FF for full
# control, 0x80120089 for read): a protected DACL allowing exactly SYSTEM and Administrators full
# control and Core's service account read access (FILE_GENERIC_READ, GENERIC_READ) and nothing else.
function Test-SetupKeyAccess([bool]$Protected, [object[]]$Entries) {
    if (-not $Protected -or $Entries.Count -ne 3 -or @($Entries | ForEach-Object { $_.Sid } | Sort-Object -Unique).Count -ne 3) { return $false }
    foreach ($entry in $Entries) {
        if (-not $entry.Allowed) { return $false }
        if ($entry.Sid -ceq 'S-1-5-18' -or $entry.Sid -ceq 'S-1-5-32-544') {
            if (($entry.Mask -band 2032127) -ne 2032127) { return $false }
        } elseif ($entry.Sid -ceq $script:coreSid) {
            if (($entry.Mask -band 1179785) -ne 1179785 -or ($entry.Mask -band (-bnot [int64]2148663433)) -ne 0) { return $false }
        } else { return $false }
    }
    return $true
}
function Assert-SetupFirewallRule {
    $rule = @(Get-NetFirewallRule -Name $script:firewallRuleName -ErrorAction SilentlyContinue)
    Assert-SetupAcceptance ($rule.Count -eq 1) 'Setup did not add its owned Core firewall rule.'
    $ports = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule[0]
    $addresses = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule[0]
    $application = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule[0]
    Assert-SetupAcceptance ([string]$rule[0].Enabled -ceq 'True' -and [string]$rule[0].Direction -ceq 'Inbound' -and [string]$rule[0].Action -ceq 'Allow' -and
        [int]$rule[0].Profile -eq 3 -and [string]$ports.Protocol -ceq 'TCP' -and (@($ports.LocalPort) -join ',') -ceq [string]$script:localNetworkPort -and
        (@($addresses.RemoteAddress) -join ',') -ceq 'LocalSubnet' -and
        [string]::Equals([Environment]::ExpandEnvironmentVariables([string]$application.Program), (Join-Path $script:coreCode 'SentinelAI.Core.exe'), [StringComparison]::OrdinalIgnoreCase)) 'The Core firewall rule is not limited to Core, TCP 5443, LocalSubnet and the Domain/Private profiles.'
    Write-Output ('Core firewall rule: Profile=' + [string]$rule[0].Profile + '; RemoteAddress=' + (@($addresses.RemoteAddress) -join ',') + '; LocalPort=' + (@($ports.LocalPort) -join ','))
}
function Assert-SetupLocalNetworkListener {
    $service = Get-SetupService 'SentinelAICore'
    $listeners = @(Get-NetTCPConnection -LocalPort $script:localNetworkPort -State Listen -ErrorAction SilentlyContinue)
    Assert-SetupAcceptance ($listeners.Count -gt 0 -and @($listeners | Where-Object {
        $_.OwningProcess -ne $service.ProcessId -or $_.LocalAddress -notin @('0.0.0.0', '::') }).Count -eq 0) 'The local-network listener is not owned by the Core service on every interface.'
}
function Get-SetupDeviceCount {
    # Windows PowerShell 5.1 returns a JSON array as one object; count its elements.
    $devices = Invoke-SetupCoreRequest '/api/admin/devices' 'GET' $null $script:accessToken | ConvertFrom-Json
    return @($devices).Count
}
function Get-SetupLocalNetworkView {
    return Invoke-SetupCoreRequest '/api/admin/local-network' 'GET' $null $script:accessToken | ConvertFrom-Json
}
function Invoke-SetupLocalNetworkRequest([string]$Address, [string]$Pin, [int]$Protocols, [string]$Method, [string]$Path, [string]$Bearer, [string]$Body) {
    return [SentinelAI.Setup.Acceptance.LocalNetwork]::Request($Address, $script:localNetworkPort, $Pin, $Protocols, $Method, $Path, $Bearer, $Body)
}
function Start-SetupNetworkAgent([string]$Address, [string]$Pin, [string]$Token, [string]$DataDirectory) {
    # The installed Agent as a second endpoint: it reaches Core only through the runner's own non-loopback address.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $script:agentCode 'SentinelAI.Agent.exe'; $start.WorkingDirectory = $DataDirectory
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.EnvironmentVariables['Agent__CoreUrl'] = 'https://' + $Address + ':' + $script:localNetworkPort
    $start.EnvironmentVariables['Agent__CoreCertificateSha256'] = $Pin
    $start.EnvironmentVariables['Agent__DataDirectory'] = $DataDirectory
    $start.EnvironmentVariables['Agent__EnrollmentToken'] = $Token
    $start.EnvironmentVariables['Agent__HeartbeatInterval'] = '00:00:05'
    $start.EnvironmentVariables['Agent__RetryDelay'] = '00:00:01'
    $start.EnvironmentVariables['Agent__MaxRetryDelay'] = '00:00:02'
    $process = [Diagnostics.Process]::Start($start)
    # Drain the console logs without keeping them.
    [void]$process.StandardOutput.ReadToEndAsync(); [void]$process.StandardError.ReadToEndAsync()
    return $process
}
function Stop-SetupNetworkAgent([Diagnostics.Process]$Process) {
    if ($null -eq $Process) { return }
    try { if (-not $Process.HasExited) { $Process.Kill(); [void]$Process.WaitForExit(15000) } } finally { $Process.Dispose() }
}
function Test-SetupLocalNetwork {
    $pin = Get-SetupLocalNetworkPin
    Assert-SetupLocalNetworkCertificate $pin
    Assert-SetupFirewallRule
    Assert-SetupLocalNetworkListener
    # The pin Desktop shows is exactly the configured certificate's SHA-256.
    $view = Get-SetupLocalNetworkView
    $addresses = @($view.addresses | ForEach-Object { [string]$_ })
    Assert-SetupAcceptance ($view.enabled -eq $true -and $view.listening -eq $true -and [int]$view.port -eq $script:localNetworkPort -and
        [string]$view.certificateSha256 -ceq $pin -and $addresses.Count -gt 0) 'Core did not export its local-network address, port and certificate pin.'
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
    $address = $addresses[0]
    Assert-SetupAcceptance ($address -cne '127.0.0.1' -and $local -ccontains $address) 'The exported address is not one of this computer''s own non-loopback IPv4 addresses.'
    Write-Output ('Local network: address=' + $address + '; port=' + $script:localNetworkPort + '; pin=' + $pin)

    # TLS 1.2 is the Windows 10 case; SChannel negotiates ECDHE with AES-GCM, which Core admits.
    $tls12 = Invoke-SetupLocalNetworkRequest $address $pin 3072 'GET' '/api/health' $null $null
    Assert-SetupAcceptance ($tls12[0] -ceq 'Tls12' -and $tls12[1] -match '\AAes(128|256)\z' -and $tls12[3].StartsWith('HTTP/1.1 404', [StringComparison]::Ordinal)) 'Core did not admit TLS 1.2 with ECDHE and AES-GCM from Windows.'
    Write-Output ('Local network TLS 1.2 client: protocol=' + $tls12[0] + '; cipher=' + $tls12[1] + '; keyExchange=' + $tls12[2])
    # Administrator, authentication, health, dashboard and Desktop routes are refused on the local-network listener.
    $loginBody = @{ username = $script:username; password = $script:password } | ConvertTo-Json -Compress
    foreach ($route in @(@('GET','/api/health',$false,$null), @('GET','/',$false,$null), @('GET','/assets/app.js',$false,$null),
        @('POST','/api/auth/login',$false,$loginBody), @('GET','/api/admin/me',$true,$null), @('GET','/api/admin/devices',$true,$null),
        @('GET','/api/admin/local-network',$true,$null), @('POST','/api/admin/enrollment-tokens',$true,''))) {
        $response = (Invoke-SetupLocalNetworkRequest $address $pin 3072 $route[0] $route[1] $(if ($route[2]) { $script:accessToken } else { $null }) $route[3])[3]
        $separator = $response.IndexOf("`r`n`r`n", [StringComparison]::Ordinal)
        Assert-SetupAcceptance ($response.StartsWith('HTTP/1.1 404', [StringComparison]::Ordinal) -and $separator -gt 0 -and
            $response.Length -eq $separator + 4) ('The local-network listener served a non-Agent route: ' + $route[1])
        Assert-NoSecretText $response
    }
    $loginBody = $null
    # A client with a different pin never completes TLS with Core.
    $wrongPin = 'F' * 64
    $refused = $false
    try { [void](Invoke-SetupLocalNetworkRequest $address $wrongPin 3072 'GET' '/api/health' $null $null) } catch { $refused = $true }
    Assert-SetupAcceptance $refused 'A client accepted Core''s certificate under a different pin.'
    # A Windows 10 Agent reconnects over TLS 1.2 under one target name, so SChannel resumes its session: Core admits it.
    # The outcome under the same name right after a refused pin is reported for diagnosis.
    $target = 'sentinelai-core-reuse-' + [Guid]::NewGuid().ToString('N')
    foreach ($attempt in 1..3) {
        $reused = [SentinelAI.Setup.Acceptance.LocalNetwork]::Request($address, $script:localNetworkPort, $target, $pin, 3072, 'GET', '/api/health', $null, $null)
        Assert-SetupAcceptance ($reused[3].StartsWith('HTTP/1.1 404', [StringComparison]::Ordinal)) 'Core did not admit a reconnecting TLS 1.2 client.'
    }
    try { [void][SentinelAI.Setup.Acceptance.LocalNetwork]::Request($address, $script:localNetworkPort, $target, $wrongPin, 3072, 'GET', '/api/health', $null, $null) } catch { }
    $afterRefusal = 'admitted'
    try { [void][SentinelAI.Setup.Acceptance.LocalNetwork]::Request($address, $script:localNetworkPort, $target, $pin, 3072, 'GET', '/api/health', $null, $null) }
    catch { $afterRefusal = [string]$_.Exception.InnerException.Message }
    Write-Output ('Local network TLS 1.2 reconnection: resumed=admitted; sameTargetAfterRefusedPin=' + $afterRefusal)
    $after = Invoke-SetupLocalNetworkRequest $address $pin 3072 'GET' '/api/health' $null $null
    Assert-SetupAcceptance ($after[3].StartsWith('HTTP/1.1 404', [StringComparison]::Ordinal)) 'A pinned client failed after another client''s refused pin.'

    # An Agent configured with this computer's own non-loopback address: a wrong pin is refused before the one-use
    # token is sent, then the exact pin enrolls with the same token and reports over the local-network listener.
    $issued = Invoke-SetupCoreRequest '/api/admin/enrollment-tokens' 'POST' '' $script:accessToken | ConvertFrom-Json
    $token = [string]$issued.token
    $before = Get-SetupDeviceCount
    $wrongData = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-network-agent-wrong-' + [Guid]::NewGuid().ToString('N'))
    $networkData = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-network-agent-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $wrongData, $networkData | Out-Null
    $agent = $null
    try {
        $agent = Start-SetupNetworkAgent $address $wrongPin $token $wrongData
        Start-Sleep -Seconds 15
        Assert-SetupAcceptance (-not $agent.HasExited) 'The Agent with a wrong pin stopped instead of retrying.'
        Stop-SetupNetworkAgent $agent; $agent = $null
        $after = Get-SetupDeviceCount
        Assert-SetupAcceptance (-not (Test-Path -LiteralPath (Join-Path $wrongData 'enrollment-state')) -and $after -eq $before) 'An Agent with a wrong pin enrolled with Core.'
        $since = [DateTimeOffset]::UtcNow
        $agent = Start-SetupNetworkAgent $address $pin $token $networkData
        $endpointFile = Join-Path $networkData 'endpoint-id'
        Wait-SetupAcceptance { (Test-Path -LiteralPath $endpointFile) -and (Test-Path -LiteralPath (Join-Path $networkData 'enrollment-state')) } 'The pinned Agent did not enroll over the local-network listener.' $script:TimeoutSeconds
        $networkEndpoint = [Guid]::ParseExact([IO.File]::ReadAllText($endpointFile).Trim(), 'D')
        Wait-ExactEndpoint $networkEndpoint $since
        Wait-SetupAcceptance { $null -ne (Get-AgentTelemetry $networkEndpoint) } 'The pinned Agent did not deliver endpoint telemetry over the local-network listener.' $script:TimeoutSeconds
        Wait-SetupAcceptance { @(Get-AgentEventSources $networkEndpoint).Count -gt 0 } 'The pinned Agent did not deliver security events over the local-network listener.' $script:TimeoutSeconds
        Assert-SetupAcceptance ((Get-SetupDeviceCount) -eq $before + 1) 'The local-network Agent did not appear as one more endpoint.'
        Write-Output ('Local-network Agent enrolled and reported through ' + $address + ':' + $script:localNetworkPort)
    } finally {
        Stop-SetupNetworkAgent $agent
        foreach ($directory in @($wrongData, $networkData)) { if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force } }
        $token = $null
    }
}

try {
    foreach ($directory in @($poisonedExtraction, $poisonedTemp)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $acl = Get-Acl -LiteralPath $directory
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
            [Security.AccessControl.FileSystemRights]::Modify, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        Set-Acl -LiteralPath $directory -AclObject $acl
        [IO.File]::WriteAllText((Join-Path $directory 'sentinel.txt'), 'Synthetic caller-controlled runtime sentinel.')
    }
    $launch = Start-TestSetup; $setup = $launch.Host; $setupOuter = $launch.Outer; $launch = $null
    Use-SetupWindow $setup
    Assert-NativeSetupRuntime $setup $setupOuter
    Assert-PoisonedCallerUntouched
    Wait-SetupAcceptance { Test-SetupControl 'SetupInstallButton' } 'The actual installer did not expose its normal install action.'
    ([Windows.Automation.InvokePattern](Find-SetupControl 'SetupInstallButton').GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()
    Wait-SetupAcceptance { Test-SetupControl 'SetupErrorText' $false } 'Setup did not reject empty administrator credentials.'
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath $programRoot) -and -not (Test-Path -LiteralPath $dataRoot) -and
        $null -eq (Get-SetupService 'SentinelAICore') -and $null -eq (Get-SetupService 'SentinelAIAgent')) 'Invalid administrator input created installation files or services.'
    if ($null -ne $pilotLicenseKey) {
        # MVP-3: the key is verified offline before anything is installed; a tampered key is refused.
        $parts = $pilotLicenseKey.Split('.')
        $tampered = $parts[0] + '.' + $(if ($parts[1][0] -ceq 'A') { 'B' } else { 'A' }) + $parts[1].Substring(1) + '.' + $parts[2]
        Set-SetupPilotLicenseKey $tampered
        ([Windows.Automation.InvokePattern](Find-SetupControl 'SetupInstallButton').GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()
        Wait-SetupAcceptance { (Find-SetupControl 'SetupErrorText').Current.Name.Contains('SETUP-PILOT-KEY') } 'Setup did not refuse a tampered pilot license key.'
        Assert-SetupAcceptance (-not (Test-Path -LiteralPath $programRoot) -and -not (Test-Path -LiteralPath $dataRoot) -and
            $null -eq (Get-SetupService 'SentinelAICore')) 'A refused pilot license key created installation files or services.'
    }
    Wait-SetupAcceptance { Test-SetupControl 'SetupLocalNetworkAccess' } 'Setup did not offer local-network access for the central computer.'
    $localNetworkOption = [Windows.Automation.TogglePattern](Find-SetupControl 'SetupLocalNetworkAccess').GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
    Assert-SetupAcceptance ([string]$localNetworkOption.Current.ToggleState -ceq 'On') 'Setup did not enable local-network access by default.'
    Set-SetupCredentials
    Assert-NoCredentialArguments $setup
    $installationSince = [DateTimeOffset]::UtcNow
    $installationStarted = $true
    Submit-NativeAction 'SetupInstallButton'
    Wait-SetupAcceptance { -not (Test-SetupControl 'SetupInstallButton') } 'Setup did not begin processing the submitted valid credentials.'
    $clearedUsername = Find-SetupControl 'SetupAdministratorUsername'
    Assert-SetupAcceptance ([string]::IsNullOrEmpty(([Windows.Automation.ValuePattern]$clearedUsername.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).Current.Value)) 'Working Setup retained the administrator input in its visible control.'
    Wait-SetupAcceptance {
        $progress = Find-SetupControl 'SetupProgressText'
        return $null -ne $progress -and -not $progress.Current.IsOffscreen -and
            -not [string]::IsNullOrWhiteSpace($progress.Current.Name) -and
            $progress.Current.Name -cne 'Ready to install a fresh local deployment. Existing installations are preserved and will be refused.'
    } 'Setup did not display native installation progress.'
    $completion = [Diagnostics.Stopwatch]::StartNew()
    $finished = $false
    while (-not $finished -and $completion.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Assert-SetupChildArguments
        if (Test-SetupControl 'SetupErrorText' $false) {
            $errorText = Find-SetupControl 'SetupErrorText'
            if (-not [string]::IsNullOrWhiteSpace($errorText.Current.Name)) { throw (Get-SetupFailureSummary) }
        }
        $finished = Test-SetupControl 'SetupFinishedText' $false
        if (-not $finished) { Invoke-SetupHangWatch; Start-Sleep -Milliseconds 100 }
    }
    # A hang reports the visible stage and bounded service/enrollment state instead of a bare timeout.
    if (-not $finished) { throw (Get-SetupTimeoutSummary) }
    $assertionCount++
    Assert-SetupAcceptance (-not (Test-SetupControl 'SetupInstallButton')) 'Completed Setup unexpectedly allowed another installation.'
    Assert-NativeSetupRuntime $setup $setupOuter
    Assert-PoisonedCallerUntouched
    foreach ($id in @('SetupProgressText', 'SetupFinishedText')) {
        $control = Find-SetupControl $id
        Assert-NoSecretText ([string]$control.Current.Name)
    }
    $coreProcess = Get-HeldInstalledProcess 'SentinelAICore' (Join-Path $coreCode 'SentinelAI.Core.exe') 'NT SERVICE\SentinelAICore'
    $agentProcess = Get-HeldInstalledProcess 'SentinelAIAgent' (Join-Path $agentCode 'SentinelAI.Agent.exe') 'NT AUTHORITY\LocalService'
    Assert-InstalledServiceRuntime $coreProcess $coreCode
    Assert-InstalledServiceRuntime $agentProcess $agentCode
    Assert-CoreListener
    foreach ($path in @($desktopExecutable, (Join-Path $updaterCode 'SentinelAI.Updater.exe'),
        (Join-Path $coreCode 'coreclr.dll'), (Join-Path $agentCode 'coreclr.dll'), (Join-Path $updaterCode 'coreclr.dll'),
        (Join-Path $coreData 'pilot-config.json'), (Join-Path $agentData 'pilot-config.json'),
        (Join-Path $coreData 'pilot-installation.json'), (Join-Path $coreData 'core-service-installation.json'),
        (Join-Path $agentData 'pilot-installation.json'), (Join-Path $coreData 'sentinelai.db'),
        (Join-Path $setupData 'public-key.pem'), (Join-Path $setupData 'setup-installation.json'), $shortcutPath)) {
        Assert-SetupAcceptance (Test-Path -LiteralPath $path -PathType Leaf) 'A required component, configuration, ownership receipt, state or Start Menu shortcut was not installed.'
    }
    $writers = @('S-1-5-32-544', 'S-1-5-18', $operatorSid)
    Assert-ProtectedTree $programRoot $writers
    Assert-ProtectedTree $dataRoot ($writers + @($coreSid, $localServiceSid))
    Assert-ProtectedTree $coreData ($writers + @($coreSid))
    Assert-ProtectedTree $agentData ($writers + @($localServiceSid))
    Assert-ProtectedTree $setupData $writers
    Assert-ProtectedTree $shortcutRoot $writers
    $readExecute = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    $read = [int][Security.AccessControl.FileSystemRights]::Read
    $modify = [int][Security.AccessControl.FileSystemRights]::Modify
    $mutation = [int]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    Assert-ServiceAcl $desktopCode 'S-1-5-32-545' $readExecute $mutation
    Assert-ServiceAcl $desktopExecutable 'S-1-5-32-545' $readExecute $mutation
    Assert-ServiceAcl $coreCode $coreSid $readExecute $mutation
    Assert-ServiceAcl $agentCode $localServiceSid $readExecute $mutation
    Assert-ServiceAcl (Join-Path $coreCode 'coreclr.dll') $coreSid $readExecute $mutation
    Assert-ServiceAcl (Join-Path $agentCode 'coreclr.dll') $localServiceSid $readExecute $mutation
    Assert-ServiceAcl (Join-Path $updaterCode 'coreclr.dll') 'S-1-5-32-545' 0 $mutation
    Assert-ServiceAcl $agentData $localServiceSid $modify 0
    Assert-ServiceAcl (Join-Path $coreData 'sentinelai.db') $coreSid $modify 0
    $parentMutation = [int]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    Assert-ServiceAcl $coreData $coreSid ($readExecute -bor [int][Security.AccessControl.FileSystemRights]::CreateFiles) $parentMutation
    foreach ($name in @('pilot-config.json', 'pilot-installation.json', 'core-service-installation.json')) {
        $path = Join-Path $coreData $name
        Assert-SetupAcceptance ((Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value -cin $writers) 'A Core configuration or ownership receipt has a service-controlled owner.'
        Assert-ServiceAcl $path $coreSid $read $mutation
        Assert-NoSecretText ([IO.File]::ReadAllText($path))
    }
    foreach ($name in @('pilot-config.json', 'pilot-installation.json')) {
        $path = Join-Path $agentData $name
        Assert-SetupAcceptance ((Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value -cin $writers) 'An Agent configuration or ownership receipt has a service-controlled owner.'
        Assert-NoSecretText ([IO.File]::ReadAllText($path))
    }
    Assert-NoSecretText ([IO.File]::ReadAllText((Join-Path $setupData 'setup-installation.json')))
    Assert-ServiceAcl (Join-Path $agentData 'pilot-config.json') $localServiceSid $read $mutation
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath (Join-Path $agentData 'pilot-enrollment-token'))) 'Setup retained a consumed enrollment token handoff.'
    $statePath = Join-Path $agentData 'enrollment-state'
    Assert-SetupAcceptance ((Get-Item -LiteralPath $statePath).Length -gt 0 -and (Get-Item -LiteralPath $statePath).Length -le 65536) 'Agent protected enrollment state is missing or oversized.'
    $protectedBytes = [IO.File]::ReadAllBytes($statePath)
    $unprotected = $null; $operatorCouldDecrypt = $false
    try {
        try { $unprotected = [Security.Cryptography.ProtectedData]::Unprotect($protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); $operatorCouldDecrypt = $true }
        catch [Security.Cryptography.CryptographicException] { }
        Assert-SetupAcceptance (-not $operatorCouldDecrypt) 'Agent state is decryptable as the installing operator instead of LocalService.'
    } finally {
        [Array]::Clear($protectedBytes, 0, $protectedBytes.Length)
        if ($null -ne $unprotected) { [Array]::Clear($unprotected, 0, $unprotected.Length) }
    }
    $endpointId = [Guid]::Empty
    Assert-SetupAcceptance ([Guid]::TryParseExact([IO.File]::ReadAllText((Join-Path $agentData 'endpoint-id')).Trim(), 'D', [ref]$endpointId) -and
        $endpointId -ne [Guid]::Empty) 'Agent did not persist its exact nonsecret endpoint receipt.'
    $shell = New-Object -ComObject WScript.Shell
    try {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        try {
            Assert-SetupAcceptance ($shortcut.TargetPath -ieq $desktopExecutable -and [string]::IsNullOrEmpty($shortcut.Arguments) -and
                $shortcut.WorkingDirectory -ieq $desktopCode) 'The Start Menu shortcut does not point to normal installed Desktop.'
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(10)
    $health = Invoke-SetupCoreRequest '/api/health' | ConvertFrom-Json
    Assert-SetupAcceptance ($health.status -ceq 'healthy') 'Installed Core is not healthy.'
    $loginBody = @{ username = $username; password = $password } | ConvertTo-Json -Compress
    try { $session = Invoke-SetupCoreRequest '/api/auth/login' 'POST' $loginBody | ConvertFrom-Json } finally { $loginBody = $null }
    $accessToken = [string]$session.accessToken; $session = $null
    Assert-SetupAcceptance (-not [string]::IsNullOrWhiteSpace($accessToken) -and $accessToken.Length -le 8192) 'The administrator created by actual Setup cannot authenticate.'
    if ($null -ne $pilotLicenseKey) {
        # Setup handed the verified key to Core, which reports it with the build-time contact; only public keys are deployed.
        $pilotStatus = Invoke-SetupCoreRequest '/api/admin/license/pilot' 'GET' $null $accessToken | ConvertFrom-Json
        Assert-SetupAcceptance ([string]$pilotStatus.state -cin @('active', 'ending') -and -not [string]::IsNullOrEmpty([string]$pilotStatus.customer) -and
            $null -ne $pilotStatus.contact -and -not [string]::IsNullOrEmpty([string]$pilotStatus.contact.company)) 'Core did not report the pilot license entered in Setup.'
        $pilotFiles = @(Get-ChildItem -LiteralPath (Join-Path $coreCode 'pilot-license') -Recurse -File -Force)
        Assert-SetupAcceptance ($pilotFiles.Count -ge 2 -and @($pilotFiles | Where-Object { [IO.File]::ReadAllText($_.FullName).Contains('PRIVATE KEY') }).Count -eq 0) 'Core was deployed without pilot public keys or with a private key.'
        Write-Output ('Pilot license: state=' + [string]$pilotStatus.state + '; daysLeft=' + [string]$pilotStatus.daysLeft)
        $pilotStatus = $null
    }
    Wait-ExactEndpoint $endpointId $installationSince
    $stateDigest = Read-SetupStateDigest $statePath
    $identityDigest = Read-SetupStateDigest (Join-Path $agentData 'installation-id')
    $agentService = Get-Service 'SentinelAIAgent'
    try {
        $agentService.Stop(); $agentService.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60))
        Assert-SetupAcceptance ($agentProcess.WaitForExit(10000)) 'The installed Agent did not stop for native DPAPI restart validation.'
        $agentProcess.Dispose(); $agentProcess = $null
        $restartSince = [DateTimeOffset]::UtcNow
        $agentService.Start(); $agentService.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
    } finally { $agentService.Dispose() }
    $agentProcess = Get-HeldInstalledProcess 'SentinelAIAgent' (Join-Path $agentCode 'SentinelAI.Agent.exe') 'NT AUTHORITY\LocalService'
    Assert-InstalledServiceRuntime $agentProcess $agentCode
    Wait-ExactEndpoint $endpointId $restartSince
    Assert-SetupAcceptance ((Read-SetupStateDigest $statePath) -ceq $stateDigest -and
        (Read-SetupStateDigest (Join-Path $agentData 'installation-id')) -ceq $identityDigest) 'The Agent restart changed persistent enrollment or installation identity.'
    # Under LocalService the Agent collects System end to end and is denied Security (the unchanged boundary);
    # the real PowerShell and Defender readability is printed rather than assumed.
    Wait-SetupAcceptance {
        $sources = @(Get-AgentEventSources $endpointId)
        $system = @($sources | Where-Object { [string]$_.channel -ceq 'System' })
        $security = @($sources | Where-Object { [string]$_.channel -ceq 'Security' })
        $system.Count -eq 1 -and [string]$system[0].state -ceq 'collecting' -and $null -ne $system[0].checkpointRecordId -and
            $security.Count -eq 1 -and [string]$security[0].state -ceq 'accessDenied'
    } 'The installed LocalService Agent did not report System collecting and Security access denied.' $script:TimeoutSeconds
    $systemStoredBefore = [long]@(Get-AgentEventSources $endpointId | Where-Object { [string]$_.channel -ceq 'System' })[0].storedObservations
    $eventProbe = 'SentinelAIEventProbe' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    try {
        # Never started; its installation is logged as System 7045.
        & sc.exe create $eventProbe binPath= 'C:\Windows\System32\cmd.exe /c exit 0' start= demand | Out-Null
        Assert-SetupAcceptance ($LASTEXITCODE -eq 0) 'Could not create the event marker service.'
    } finally { & sc.exe delete $eventProbe | Out-Null }
    Assert-SetupAcceptance ($LASTEXITCODE -eq 0) 'Could not delete the event marker service.'
    Wait-SetupAcceptance {
        [long]@(Get-AgentEventSources $endpointId | Where-Object { [string]$_.channel -ceq 'System' })[0].storedObservations -ge $systemStoredBefore + 1
    } 'The installed LocalService Agent did not deliver the marker service installation.' $script:TimeoutSeconds
    $eventCheckpoint = Get-Item -LiteralPath (Join-Path $agentData 'event-checkpoints')
    Assert-SetupAcceptance ($eventCheckpoint.Length -gt 0 -and $eventCheckpoint.Length -le 4096 -and -not $eventCheckpoint.LinkType) 'The Agent event checkpoint is invalid.'
    Write-Output ('Installed Agent event channels: ' + ((@(Get-AgentEventSources $endpointId) | ForEach-Object { [string]$_.channel + '=' + [string]$_.state }) -join ', '))
    # The installed LocalService Agent delivers endpoint telemetry. Service states and machine-wide applications are
    # readable by that account; what else it can read is printed rather than assumed.
    Wait-SetupAcceptance {
        $telemetry = Get-AgentTelemetry $endpointId
        $null -ne $telemetry -and [int]$telemetry.schemaVersion -eq 1 -and
            [string]$telemetry.services.availability -ceq 'collected' -and [string]$telemetry.software.availability -ceq 'collected'
    } 'The installed LocalService Agent did not deliver endpoint telemetry with services and applications collected.' $script:TimeoutSeconds
    $telemetry = Get-AgentTelemetry $endpointId
    Write-Output ('Installed Agent telemetry sources: ' + ((@('bitLocker', 'antivirus', 'defender', 'localAdministrators', 'pendingReboot', 'services', 'software') |
        ForEach-Object { $_ + '=' + [string]$telemetry.$_.availability }) -join ', ') + ', updatePolicy=' + [string]$telemetry.windowsUpdate.policyAvailability +
        ', updateResults=' + [string]$telemetry.windowsUpdate.resultsAvailability)
    Test-SetupLocalNetwork

    Use-SetupWindow $setup
    Show-SetupControl 'SetupOpenDesktopButton'
    Wait-SetupAcceptance { Test-SetupControl 'SetupOpenDesktopButton' } 'Completed Setup did not offer native Desktop opening.'
    ([Windows.Automation.InvokePattern](Find-SetupControl 'SetupOpenDesktopButton').GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    Wait-SetupAcceptance {
        $instances = @(Get-CimInstance -ClassName Win32_Process -Filter ("Name='SentinelAI.Desktop.exe' AND SessionId=" + $sessionId) |
            Where-Object { [string]$_.ExecutablePath -ieq $desktopExecutable })
        if ($instances.Count -gt 1) { throw 'Setup created more than one normal Desktop instance.' }
        if ($instances.Count -ne 1) {
            if (-not $script:setup.HasExited -and -not $script:manualShortcutOpened) {
                $script:activeRoot = [Windows.Automation.AutomationElement]::FromHandle($script:setup.MainWindowHandle)
                $progress = Find-SetupControl 'SetupProgressText'
                if ($null -ne $progress -and $progress.Current.Name -ceq 'Open SentinelAI from the Windows Start Menu to sign in. Setup does not launch an elevated Desktop.') {
                    # Production explicitly requests this ordinary shortcut
                    # action if an interactive Explorer shell is absent. Hosted
                    # acceptance runs elevated; no UAC/token policy is changed.
                    # The shortcut target/blank arguments/working directory
                    # were verified above. Hosted runners may have no ordinary
                    # Explorer token; launch that exact target as the elevated
                    # acceptance operator and explicitly report this fallback.
                    $start = [Diagnostics.ProcessStartInfo]::new()
                    $start.FileName = $desktopExecutable; $start.WorkingDirectory = $desktopCode
                    $start.UseShellExecute = $false
                    $launched = [Diagnostics.Process]::Start($start)
                    if ($null -ne $launched) { $launched.Dispose() }
                    $script:manualShortcutOpened = $true
                }
            }
            return $false
        }
        $script:desktop = [Diagnostics.Process]::GetProcessById([int]$instances[0].ProcessId); $null = $script:desktop.Handle
        return $true
    } 'Setup did not open the installed native Desktop through its normal shortcut.'
    Use-SetupWindow $desktop
    $desktopClr = @($desktop.Modules | Where-Object { $_.ModuleName -ieq 'coreclr.dll' })
    Assert-SetupAcceptance ($desktopClr.Count -eq 1 -and [IO.Path]::GetFullPath($desktopClr[0].FileName) -ieq
        (Join-Path $desktopCode 'coreclr.dll')) 'Installed Desktop loaded CLR outside its self-contained protected installation.'
    Wait-SetupAcceptance { Test-SetupControl 'SignInButton' $false } 'Installed Desktop did not offer native administrator sign-in.'
    # The sign-in button is visible before the initial Core trust check finishes,
    # and stays disabled until a valid username is entered. Wait for the actual
    # input controls to become enabled rather than racing their busy state.
    Wait-SetupAcceptance { (Test-SetupControl 'AuthenticationUsername') -and (Test-SetupControl 'AuthenticationPassword') } 'Installed Desktop did not enable administrator inputs after its initial Core check.'
    $user = Find-SetupControl 'AuthenticationUsername'
    $userValue = [Windows.Automation.ValuePattern]$user.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
    Assert-SetupAcceptance ([string]::IsNullOrEmpty($userValue.Current.Value)) 'Installed Desktop restored Setup credentials instead of requiring fresh sign-in.'
    $userValue.SetValue($username)
    Set-NativePassword 'AuthenticationPassword' 'SignInButton'
    Submit-NativeAction 'SignInButton'
    Wait-SetupAcceptance { Test-SetupControl 'SignOutButton' } 'Installed Desktop could not authenticate with the administrator created by Setup.'
    Assert-SetupAcceptance (Test-SetupControl 'NavigationList') 'Installed Desktop did not expose authenticated native workspace navigation.'
    $administrator = Find-SetupControl 'AdministratorNameText'
    Assert-SetupAcceptance ($null -ne $administrator -and $administrator.Current.Name.Contains($username)) 'Desktop did not show Core-authoritative administrator identity.'
    Assert-NoCredentialArguments $desktop
    [void][SentinelAI.Setup.Acceptance.Native]::PostMessage($desktop.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-SetupAcceptance ($desktop.WaitForExit(30000) -and $desktop.ExitCode -eq 0) 'Installed Desktop did not close gracefully.'
    $desktop.Dispose(); $desktop = $null
    Assert-CoreListener
    Assert-SetupAcceptance (-not $agentProcess.HasExited -and (Get-SetupService 'SentinelAIAgent').ProcessId -eq $agentProcess.Id) 'Closing Desktop stopped or replaced the independent Agent.'

    if (-not $setup.HasExited) {
        [void][SentinelAI.Setup.Acceptance.Native]::PostMessage($setup.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    Assert-SetupAcceptance ($setup.WaitForExit(30000) -and $setup.ExitCode -eq 0) 'Completed Setup did not exit successfully.'
    Assert-SetupAcceptance ($setupOuter.WaitForExit(30000) -and $setupOuter.ExitCode -eq 0) 'The actual single-EXE wrapper did not propagate successful completion.'
    Assert-PoisonedCallerUntouched
    $preservedPaths = @((Join-Path $coreData 'pilot-config.json'), (Join-Path $coreData 'pilot-installation.json'),
        (Join-Path $coreData 'core-service-installation.json'), (Join-Path $agentData 'pilot-config.json'),
        (Join-Path $agentData 'pilot-installation.json'), (Join-Path $setupData 'public-key.pem'),
        (Join-Path $setupData 'setup-installation.json'), $statePath, (Join-Path $agentData 'installation-id'), $shortcutPath)
    $preserved = @{}
    foreach ($path in $preservedPaths) { $preserved[$path] = Read-SetupStateDigest $path }
    $launch = Start-TestSetup; $rerun = $launch.Host; $rerunOuter = $launch.Outer; $launch = $null
    Use-SetupWindow $rerun
    Assert-NativeSetupRuntime $rerun $rerunOuter
    Wait-SetupAcceptance { Test-SetupControl 'SetupLifecycleAction' } 'Repeated Setup did not detect the owned installation and offer maintenance.'
    $version = Find-SetupControl 'SetupInstallationVersion'
    Assert-SetupAcceptance ($null -ne $version -and -not [string]::IsNullOrWhiteSpace($version.Current.Name)) 'Maintenance did not display the installed version.'
    Assert-NoSecretText ([string]$version.Current.Name)
    Assert-SetupAcceptance (-not (Test-SetupControl 'SetupInstallButton')) 'Existing installation incorrectly offered fresh administrator creation.'
    Assert-SetupAcceptance (-not (Test-SetupControl 'SetupFinishedText' $false)) 'Detection without an explicit action incorrectly reported a second installation.'
    foreach ($path in $preservedPaths) { Assert-SetupAcceptance ((Read-SetupStateDigest $path) -ceq $preserved[$path]) 'Refused Setup changed existing installation state.' }
    Assert-CoreListener
    Assert-SetupAcceptance (-not $agentProcess.HasExited -and (Get-SetupService 'SentinelAIAgent').ProcessId -eq $agentProcess.Id) 'Refused Setup changed the existing Agent service.'
    [void][SentinelAI.Setup.Acceptance.Native]::PostMessage($rerun.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-SetupAcceptance ($rerun.WaitForExit(30000)) 'Unsubmitted maintenance did not close.'
    Assert-SetupAcceptance ($rerunOuter.WaitForExit(30000) -and $rerunOuter.ExitCode -eq $rerun.ExitCode) 'The actual single-EXE wrapper did not propagate maintenance closure.'
    Assert-PoisonedCallerUntouched
    if ($PreserveInstallation -and $null -ne $InstallationContext) {
        # Private in-process synthetic fixture handoff; never emit this object.
        $InstallationContext.Value = [pscustomobject]@{ Username = $username; Password = $password; EndpointId = $endpointId }
    }
    $installationCompleted = $true
    $acceptancePassed = $true
    [pscustomobject]@{ Result = 'Passed'; Assertions = $assertionCount; Installation = $programRoot; DesktopShortcutFallback = $manualShortcutOpened;
        NativeSetup = 'Single native EXE, private CLR, unused caller caches, protected layout, administrator, services, enrollment, Desktop sign-in and nonmutating maintenance detection' }
} finally {
    if (-not $acceptancePassed) { Stop-SetupDescendantProcesses @($setupOuter, $setup, $rerunOuter, $rerun) }
    foreach ($process in @($desktop, $rerun, $setup, $rerunOuter, $setupOuter)) {
        if ($null -ne $process) {
            try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(10000) } } finally { $process.Dispose() }
        }
    }
    # Cleanup alone may call existing managers. Their protected receipts and
    # exact SCM identity checks reject unknown registrations; install itself was
    # exclusively performed by the actual Setup executable above.
    try {
        try {
            if ($installationStarted -and -not ($PreserveInstallation -and $installationCompleted)) {
                $installer = Join-Path $repositoryRoot 'installer/pilot'
                Import-Module (Join-Path $installer 'PilotInstaller.psm1') -Force -DisableNameChecking
                try {
                    if ($null -ne (Get-SetupService 'SentinelAIAgent')) {
                        Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -TimeoutSeconds 60 | Out-Null
                    }
                } finally {
                    if ($null -ne (Get-SetupService 'SentinelAICore')) {
                        & (Join-Path $installer 'Manage-SentinelAICoreService.ps1') -Action Uninstall -CodeDirectory $coreCode -DataDirectory $coreData -TimeoutSeconds 60 | Out-Null
                    }
                }
                Assert-SetupAcceptance ($null -eq (Get-SetupService 'SentinelAIAgent') -and $null -eq (Get-SetupService 'SentinelAICore')) 'An owned acceptance service remained registered after cleanup.'
            }
        } catch {
            # A cleanup failure after a failed acceptance must never replace the failure being reported.
            if ($acceptancePassed) { throw }
            Write-Host 'SetupCleanup: Failed=True; the original acceptance failure is reported instead.'
        }
    } finally {
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $coreProcess) { $coreProcess.Dispose() }
        if ($null -ne $agentProcess) { $agentProcess.Dispose() }
        $password = $null; $accessToken = $null
    }
}
