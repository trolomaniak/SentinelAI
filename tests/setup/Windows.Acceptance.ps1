# Actual single-EXE first installation on a fresh, elevated interactive Windows
# x64 machine. Credentials enter protected native controls only. The fixture
# retains installed files/state and removes only its proven installer-owned
# services. Secure-desktop UAC consent is a separate manual check.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [ValidateRange(60, 900)][int]$TimeoutSeconds = 300
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
$manualShortcutOpened = $false
$poisonedCaller = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-setup-untrusted-' + [Guid]::NewGuid().ToString('N'))
$poisonedExtraction = Join-Path $poisonedCaller 'runtime-cache'
$poisonedTemp = Join-Path $poisonedCaller 'temp'

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
function Start-TestSetup {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:ExecutablePath; $start.WorkingDirectory = Split-Path -Parent $script:ExecutablePath
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
function Set-SetupCredentials {
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
function Get-SetupService([string]$Name) { return Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $Name + "'") }
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
                'Installing and enrolling Agent...', 'Installing Desktop and Updater...',
                'Creating Start Menu shortcuts...', 'Installation finished.', 'Stopping setup...')) {
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
        $acl = Get-Acl -LiteralPath $item.FullName
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
    Assert-ProtectedTree $Root @('S-1-5-32-544', 'S-1-5-18')
    Assert-SetupAcceptance (Get-Acl -LiteralPath $Root).AreAccessRulesProtected 'The native private runtime root inherits permissions.'
    foreach ($item in @((Get-Item -LiteralPath $Root -Force)) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
        foreach ($rule in (Get-Acl -LiteralPath $item.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and [int]$rule.FileSystemRights -ne 0) {
                Assert-SetupAcceptance ($rule.IdentityReference.Value -cin @('S-1-5-32-544', 'S-1-5-18')) 'The native runtime cache admits an untrusted reader or writer.'
            }
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
    Wait-SetupAcceptance {
        Assert-SetupChildArguments
        if (Test-SetupControl 'SetupErrorText' $false) {
            $errorText = Find-SetupControl 'SetupErrorText'
            if (-not [string]::IsNullOrWhiteSpace($errorText.Current.Name)) { throw (Get-SetupFailureSummary) }
        }
        return Test-SetupControl 'SetupFinishedText' $false
    } 'The actual Setup executable did not complete installation.' $TimeoutSeconds
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
    Set-SetupCredentials
    Submit-NativeAction 'SetupInstallButton'
    Wait-SetupAcceptance { -not (Test-SetupControl 'SetupInstallButton') } 'Repeated Setup did not process its submitted credentials.'
    Wait-SetupAcceptance {
        $control = Find-SetupControl 'SetupErrorText'
        return $null -ne $control -and -not $control.Current.IsOffscreen -and -not [string]::IsNullOrWhiteSpace($control.Current.Name)
    } 'Actual Setup did not refuse an existing installation.' $TimeoutSeconds
    Assert-SetupAcceptance (-not (Test-SetupControl 'SetupFinishedText' $false)) 'Setup incorrectly reported a successful second installation.'
    Assert-NoSecretText ([string](Find-SetupControl 'SetupErrorText').Current.Name)
    foreach ($path in $preservedPaths) { Assert-SetupAcceptance ((Read-SetupStateDigest $path) -ceq $preserved[$path]) 'Refused Setup changed existing installation state.' }
    Assert-CoreListener
    Assert-SetupAcceptance (-not $agentProcess.HasExited -and (Get-SetupService 'SentinelAIAgent').ProcessId -eq $agentProcess.Id) 'Refused Setup changed the existing Agent service.'
    [void][SentinelAI.Setup.Acceptance.Native]::PostMessage($rerun.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-SetupAcceptance ($rerun.WaitForExit(30000) -and $rerun.ExitCode -ne 0) 'Refused Setup did not exit with failure.'
    Assert-SetupAcceptance ($rerunOuter.WaitForExit(30000) -and $rerunOuter.ExitCode -eq $rerun.ExitCode) 'The actual single-EXE wrapper did not propagate first-install refusal.'
    Assert-PoisonedCallerUntouched
    [pscustomobject]@{ Result = 'Passed'; Assertions = $assertionCount; Installation = $programRoot; DesktopShortcutFallback = $manualShortcutOpened;
        NativeSetup = 'Single native EXE, private CLR, unused caller caches, protected layout, administrator, services, enrollment, Desktop sign-in and first-install refusal' }
} finally {
    foreach ($process in @($desktop, $rerun, $setup, $rerunOuter, $setupOuter)) {
        if ($null -ne $process) {
            try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(10000) } } finally { $process.Dispose() }
        }
    }
    # Cleanup alone may call existing managers. Their protected receipts and
    # exact SCM identity checks reject unknown registrations; install itself was
    # exclusively performed by the actual Setup executable above.
    try {
        if ($installationStarted) {
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
    } finally {
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $coreProcess) { $coreProcess.Dispose() }
        if ($null -ne $agentProcess) { $agentProcess.Dispose() }
        $password = $null; $accessToken = $null
    }
}
