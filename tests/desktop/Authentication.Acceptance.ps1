# Opt-in live Desktop/Core authentication acceptance on a fresh elevated,
# interactive Windows x64 machine. Synthetic passwords enter only native
# password controls through SendInput; no clipboard, arguments or secret files.
# This fixture retains its protected installation/state and removes only its
# installer-owned Core service. Existing installations are never adopted.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDirectory,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$KeyId,
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [ValidateSet('development', 'production')][string]$Environment = 'development',
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [ValidateRange(30, 600)][int]$TimeoutSeconds = 180,
    [switch]$VerifyDevices,
    [switch]$VerifyAlerts,
    [switch]$VerifyRiskReports
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem -or
    -not [Environment]::UserInteractive) { throw 'Authentication acceptance requires an elevated interactive Windows x64 desktop.' }

# UI Automation is hosted in Windows PowerShell's native Desktop framework.
# The relaunch carries only public paths/policy; credentials are generated later.
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    $nativeHost = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/powershell.exe'
    function Quote-Argument([string]$Value) {
        if ($Value.Contains('"') -or $Value.Contains([char]0) -or $Value.Contains("`r") -or $Value.Contains("`n")) {
            throw 'Acceptance paths and policy must be simple literal arguments.'
        }
        return '"' + $Value.TrimEnd('\') + '"'
    }
    $arguments = '-NoLogo -NoProfile -NonInteractive -STA -File ' + (Quote-Argument $PSCommandPath)
    foreach ($pair in @(@('BundleDirectory', $BundleDirectory), @('PublicKeyPath', $PublicKeyPath),
                       @('KeyId', $KeyId), @('ExecutablePath', $ExecutablePath), @('Environment', $Environment), @('Channel', $Channel))) {
        $arguments += ' -' + $pair[0] + ' ' + (Quote-Argument $pair[1])
    }
    $arguments += ' -TimeoutSeconds ' + $TimeoutSeconds
    if ($VerifyDevices) { $arguments += ' -VerifyDevices' }
    if ($VerifyAlerts) { $arguments += ' -VerifyAlerts' }
    if ($VerifyRiskReports) { $arguments += ' -VerifyRiskReports' }
    $nativeStart = [Diagnostics.ProcessStartInfo]::new()
    $nativeStart.FileName = $nativeHost; $nativeStart.Arguments = $arguments
    $nativeStart.UseShellExecute = $false
    $native = [Diagnostics.Process]::Start($nativeStart)
    try {
        if (-not $native.WaitForExit(($TimeoutSeconds * 5 + 120) * 1000)) {
            $native.Kill(); [void]$native.WaitForExit(10000)
            throw 'The native authentication acceptance host exceeded its bounded deadline.'
        }
        if ($native.ExitCode -ne 0) { throw 'Native Desktop/Core authentication acceptance failed.' }
    } finally { $native.Dispose() }
    return
}

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$installerDirectory = Join-Path $repositoryRoot 'installer/pilot'
$managementScript = Join-Path $installerDirectory 'Manage-SentinelAICoreService.ps1'
Import-Module (Join-Path $installerDirectory 'PilotInstaller.psm1') -Force -DisableNameChecking
Assert-PilotSupportedHost
$BundleDirectory = (Resolve-Path -LiteralPath $BundleDirectory).ProviderPath
$PublicKeyPath = (Resolve-Path -LiteralPath $PublicKeyPath).ProviderPath
$ExecutablePath = (Resolve-Path -LiteralPath $ExecutablePath).ProviderPath
$coreCode = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelAI\Core'
$coreData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SentinelAI\Core'
foreach ($path in @($coreCode, $coreData)) {
    if (Test-Path -LiteralPath $path) { throw 'Authentication acceptance requires absent default Core directories; existing files will not be adopted or removed.' }
}
if ($null -ne (Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'")) {
    throw 'Authentication acceptance requires no existing SentinelAICore service.'
}
$portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 5000)
try { $portProbe.Start() } finally { $portProbe.Stop() }
$workDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('SentinelAI-Desktop-Auth-Acceptance-' + [Guid]::NewGuid().ToString('N'))
New-PilotProtectedDirectory -Path $workDirectory -Kind Container

# Fixture-local equivalent of TASK-017's protected staging. Copy exact generated
# bytes into create-new files without inheriting build-checkout/temp ACLs.
function Copy-AuthenticationAcceptanceFile {
    param([string]$Source, [string]$Destination)
    $Source = Assert-PilotPath -Path $Source -MustExist -File
    [void](Assert-PilotPath -Path $Destination -File)
    if (Test-Path -LiteralPath $Destination) { throw 'Authentication staging never overwrites or adopts existing files.' }
    Assert-PilotTrustedPath -Path $Destination
    $digest = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
    $inputStream = $null; $outputStream = $null
    try {
        $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $inputStream.CopyTo($outputStream); $outputStream.Flush($true)
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
    }
    if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -cne $digest -or
        (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -cne $digest) { throw 'Authentication staging changed build bytes.' }
    Assert-PilotTrustedPath -Path $Destination
}
function Copy-AuthenticationAcceptanceTree {
    param([string]$Source, [string]$Destination)
    $Source = Assert-PilotPath -Path $Source -MustExist
    if (Test-Path -LiteralPath $Destination) { throw 'Authentication staging requires a new verifier directory.' }
    New-PilotDirectoryWithAcl -Path $Destination -Kind Container
    $pending = New-Object 'System.Collections.Generic.Queue[object]'
    $pending.Enqueue([pscustomobject]@{ Source = $Source; Destination = $Destination })
    $count = 0
    while ($pending.Count -ne 0) {
        $directory = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory.Source -Force) {
            if (++$count -gt 8192) { throw 'The acceptance verifier tree exceeded its bound.' }
            $target = Join-Path $directory.Destination $item.Name
            if ($item.PSIsContainer) {
                [void](Assert-PilotPath -Path $item.FullName -MustExist)
                New-PilotDirectoryWithAcl -Path $target -Kind Container
                $pending.Enqueue([pscustomobject]@{ Source = $item.FullName; Destination = $target })
            } else { Copy-AuthenticationAcceptanceFile $item.FullName $target }
        }
    }
    Assert-PilotTrustedPath -Path $Destination -Tree
}
$stagedBundle = Join-Path $workDirectory 'Bundle'
$stagedTrust = Join-Path $workDirectory 'Trust'
New-PilotDirectoryWithAcl -Path $stagedBundle -Kind Container
New-PilotDirectoryWithAcl -Path $stagedTrust -Kind Container
foreach ($name in @('core.zip', 'core.manifest.json')) {
    Copy-AuthenticationAcceptanceFile (Join-Path $BundleDirectory $name) (Join-Path $stagedBundle $name)
}
Copy-AuthenticationAcceptanceTree (Join-Path $BundleDirectory 'updater') (Join-Path $stagedBundle 'updater')
$stagedKey = Join-Path $stagedTrust 'desktop-auth.public.pem'
Copy-AuthenticationAcceptanceFile $PublicKeyPath $stagedKey
Set-PilotFileAcl -Path $stagedKey -Kind Receipt
Assert-PilotTrustedPath -Path $stagedBundle -Tree
Assert-PilotTrustedPath -Path $stagedKey
$BundleDirectory = $stagedBundle; $PublicKeyPath = $stagedKey
$coreExecutable = Join-Path $coreCode 'SentinelAI.Core.exe'
$configurationPath = Join-Path $coreData 'pilot-config.json'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
if ($null -eq ('SentinelAIDesktopAuthenticationAcceptance.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace SentinelAIDesktopAuthenticationAcceptance {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] private struct KeyboardInput {
            public ushort Key, Scan; public uint Flags, Time; public IntPtr Extra;
        }
        [StructLayout(LayoutKind.Explicit, Size = 32)] private struct InputData {
            [FieldOffset(0)] public KeyboardInput Keyboard;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Input {
            public uint Type; public InputData Data;
        }
        [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint count, Input[] input, int size);
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool SetForegroundWindow(IntPtr handle);
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
        public static void TypePassword(string password, IntPtr expectedWindow) {
            if (String.IsNullOrEmpty(password) || password.Length > 256 || expectedWindow == IntPtr.Zero)
                throw new InvalidOperationException("Synthetic input is invalid.");
            // Pace native Unicode pairs to allow normal text-input processing,
            // rather than flooding the interactive runner with one burst. The
            // 256-character bound requests at most 5.12 seconds of pacing;
            // a ten-second input deadline also bounds slow scheduling. Never resend.
            var inputs = new Input[2];
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            try {
                for (int index = 0; index < password.Length; index++) {
                    if (elapsed.Elapsed.TotalSeconds >= 10)
                        throw new InvalidOperationException("Native password input exceeded its deadline.");
                    if (GetForegroundWindow() != expectedWindow)
                        throw new InvalidOperationException("Native password input lost foreground ownership.");
                    inputs[0].Type = 1;
                    inputs[0].Data.Keyboard.Scan = password[index];
                    inputs[0].Data.Keyboard.Flags = 4;
                    inputs[1] = inputs[0];
                    inputs[1].Data.Keyboard.Flags = 6;
                    if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                        throw new InvalidOperationException("Native protected password input was incomplete.");
                    System.Threading.Thread.Sleep(20);
                }
                if (elapsed.Elapsed.TotalSeconds >= 10)
                    throw new InvalidOperationException("Native password input exceeded its deadline.");
                if (GetForegroundWindow() != expectedWindow)
                    throw new InvalidOperationException("Native password input lost foreground ownership.");
                Array.Clear(inputs, 0, inputs.Length);
                inputs[0].Type = 1; inputs[0].Data.Keyboard.Key = 9;
                inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 2;
                if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                    throw new InvalidOperationException("Native password focus transfer was incomplete.");
            } finally { Array.Clear(inputs, 0, inputs.Length); }
        }
        public static void SubmitFocusedAction() {
            var inputs = new Input[2];
            inputs[0].Type = 1; inputs[0].Data.Keyboard.Key = 13;
            inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 2;
            if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                throw new InvalidOperationException("Native authentication submit input was incomplete.");
        }
        private static void SendFileNameChord(ushort modifier, ushort key, IntPtr expectedWindow) {
            if (GetForegroundWindow() != expectedWindow)
                throw new InvalidOperationException("Native filename input lost foreground ownership.");
            var inputs = new Input[4];
            try {
                inputs[0].Type = 1; inputs[0].Data.Keyboard.Key = modifier;
                inputs[1].Type = 1; inputs[1].Data.Keyboard.Key = key;
                inputs[2] = inputs[1]; inputs[2].Data.Keyboard.Flags = 2;
                inputs[3] = inputs[0]; inputs[3].Data.Keyboard.Flags = 2;
                if (SendInput(4, inputs, Marshal.SizeOf(typeof(Input))) != 4)
                    throw new InvalidOperationException("Native filename shortcut input was incomplete.");
            } finally { Array.Clear(inputs, 0, inputs.Length); }
        }
        public static void FocusFileName(IntPtr expectedWindow) {
            // The standard English Windows common-dialog filename access key.
            // The caller verifies actual filename focus before entering any text.
            SendFileNameChord(18, 0x4E, expectedWindow);
        }
        public static void SaveFileName(IntPtr expectedWindow) {
            // The standard Save access key still respects the dialog's actual
            // enabled state, even if its UIA provider reports inherited state.
            SendFileNameChord(18, 0x53, expectedWindow);
        }
        public static void EnterFileName(string destination, IntPtr expectedWindow) {
            if (String.IsNullOrEmpty(destination) || destination.Length > 256 || expectedWindow == IntPtr.Zero ||
                !System.IO.Path.IsPathRooted(destination) || destination.IndexOf('"') >= 0 ||
                destination.IndexOf('\0') >= 0 || destination.IndexOf('\r') >= 0 || destination.IndexOf('\n') >= 0)
                throw new InvalidOperationException("Synthetic filename input is invalid.");
            foreach (char character in destination)
                if (Char.IsControl(character))
                    throw new InvalidOperationException("Synthetic filename input contains a control character.");
            SendFileNameChord(17, 0x41, expectedWindow); // Ctrl+A in the verified filename input.
            var inputs = new Input[2];
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            try {
                foreach (char character in destination) {
                    if (elapsed.Elapsed.TotalSeconds >= 10)
                        throw new InvalidOperationException("Native filename input exceeded its deadline.");
                    if (GetForegroundWindow() != expectedWindow)
                        throw new InvalidOperationException("Native filename input lost foreground ownership.");
                    inputs[0].Type = 1; inputs[0].Data.Keyboard.Scan = character; inputs[0].Data.Keyboard.Flags = 4;
                    inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 6;
                    if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                        throw new InvalidOperationException("Native filename text input was incomplete.");
                    System.Threading.Thread.Sleep(20);
                }
                if (elapsed.Elapsed.TotalSeconds >= 10 || GetForegroundWindow() != expectedWindow)
                    throw new InvalidOperationException("Native filename input did not finish within its owned deadline.");
                Array.Clear(inputs, 0, inputs.Length);
                inputs[0].Type = 1; inputs[0].Data.Keyboard.Key = 9;
                inputs[1] = inputs[0]; inputs[1].Data.Keyboard.Flags = 2;
                if (SendInput(2, inputs, Marshal.SizeOf(typeof(Input))) != 2)
                    throw new InvalidOperationException("Native filename focus transfer was incomplete.");
            } finally { Array.Clear(inputs, 0, inputs.Length); }
        }
    }
}
'@
}

$assertionCount = 0
$desktop = $null; $coreProcess = $null; $serviceInstalled = $false
$client = $null; $root = $null; $foreignListener = $null
$username = 'desktop-auth-test-' + [Guid]::NewGuid().ToString('N')
$passwordBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($passwordBytes) } finally { $random.Dispose() }
$password = [Convert]::ToBase64String($passwordBytes)
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
$wrongPassword = 'invalid-test-' + [Guid]::NewGuid().ToString('N')
function Assert-AuthenticationAcceptance([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}
function Wait-AuthenticationAcceptance([scriptblock]$Condition, [string]$Message, [int]$Seconds = 30) {
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while ($wait.Elapsed.TotalSeconds -lt $Seconds) {
        if (& $Condition) { $script:assertionCount++; return }
        if ($null -ne $script:desktop -and $script:desktop.HasExited) { throw 'The tested Desktop exited during authentication.' }
        Start-Sleep -Milliseconds 100
    }
    # Only fixed, locally rendered errors become diagnostic categories. Never
    # include response bodies, passwords, token material or arbitrary UI strings.
    $category = switch (Get-AuthenticationError) {
        'The username or password is incorrect.' { 'credentials_rejected'; break }
        'The local Core connection could not be trusted.' { 'untrusted_core'; break }
        'Local Core is unavailable. Start or restore Core, then try again.' { 'core_unavailable'; break }
        'Too many sign-in attempts. Try again later.' { 'throttled'; break }
        'Your session has expired. Sign in again.' { 'session_expired'; break }
        default { 'no_safe_error' }
    }
    throw ($Message + ' Authentication result: ' + $category + '.')
}
function Find-AuthenticationControl([string]$Id) {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
    return $script:root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function Test-AuthenticationControl([string]$Id, [bool]$RequireEnabled = $true) {
    $control = Find-AuthenticationControl $Id
    return $null -ne $control -and -not $control.Current.IsOffscreen -and (-not $RequireEnabled -or $control.Current.IsEnabled)
}
function Invoke-AuthenticationControl([string]$Id) {
    Wait-AuthenticationAcceptance { Test-AuthenticationControl $Id } 'A required native authentication action was unavailable.'
    $control = Find-AuthenticationControl $Id
    if ($Id -in @('SignInButton', 'CreateAdministratorButton')) {
        # UIA Invoke runs at dispatcher Send priority and can overtake queued
        # native text input. Submit through the same keyboard path instead.
        Assert-AuthenticationAcceptance ($control.Current.HasKeyboardFocus -and
            [SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $script:desktop.MainWindowHandle) 'The native authentication submit action did not own foreground focus.'
        [SentinelAIDesktopAuthenticationAcceptance.Native]::SubmitFocusedAction()
        return
    }
    $invoke = [System.Windows.Automation.InvokePattern]$control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $invoke.Invoke()
}
function Set-AuthenticationCredential([string]$Name, [string]$Secret) {
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'AuthenticationPassword' } 'The protected native password input was unavailable.'
    $user = Find-AuthenticationControl 'AuthenticationUsername'
    $value = [System.Windows.Automation.ValuePattern]$user.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $value.SetValue($Name)
    Assert-AuthenticationAcceptance ($value.Current.Value -ceq $Name) 'Native administrator input did not retain the supplied username.'
    $secretControl = Find-AuthenticationControl 'AuthenticationPassword'
    Assert-AuthenticationAcceptance $secretControl.Current.IsPassword 'Authentication input exposed a non-password control.'
    $pattern = $null
    if ($secretControl.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
        $protectedValue = ''
        try { $protectedValue = ([System.Windows.Automation.ValuePattern]$pattern).Current.Value }
        catch [System.InvalidOperationException] { } # Framework compatibility mode may refuse the value getter.
        Assert-AuthenticationAcceptance ([string]::IsNullOrEmpty($protectedValue)) 'The password control exposed a readable UI Automation value.'
    }
    [void][SentinelAIDesktopAuthenticationAcceptance.Native]::SetForegroundWindow($script:desktop.MainWindowHandle)
    $secretControl.SetFocus()
    Wait-AuthenticationAcceptance {
        $focusedPassword = Find-AuthenticationControl 'AuthenticationPassword'
        return [SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -eq $script:desktop.MainWindowHandle -and
            $null -ne $focusedPassword -and $focusedPassword.Current.HasKeyboardFocus
    } 'The tested password input did not own foreground keyboard focus.'
    [SentinelAIDesktopAuthenticationAcceptance.Native]::TypePassword($Secret, $script:desktop.MainWindowHandle)
    Wait-AuthenticationAcceptance {
        if ([SentinelAIDesktopAuthenticationAcceptance.Native]::GetForegroundWindow() -ne $script:desktop.MainWindowHandle) { return $false }
        foreach ($id in @('SignInButton', 'CreateAdministratorButton')) {
            $action = Find-AuthenticationControl $id
            if ($null -ne $action -and -not $action.Current.IsOffscreen -and $action.Current.HasKeyboardFocus) { return $true }
        }
        return $false
    } 'Native credential input did not finish at the submit action.'
}
function Get-AuthenticationError {
    if ($null -eq $script:root) { return '' }
    $control = Find-AuthenticationControl 'AuthenticationErrorText'
    if ($null -eq $control -or $control.Current.IsOffscreen) { return '' }
    return $control.Current.Name
}
function Assert-SignedOut {
    $navigation = Find-AuthenticationControl 'NavigationList'
    Assert-AuthenticationAcceptance ($null -eq $navigation -or $navigation.Current.IsOffscreen -or -not $navigation.Current.IsEnabled) 'Protected navigation remained available without a session.'
    $identity = Find-AuthenticationControl 'AdministratorNameText'
    Assert-AuthenticationAcceptance ($null -eq $identity -or $identity.Current.IsOffscreen -or [string]::IsNullOrWhiteSpace($identity.Current.Name)) 'The signed-out Desktop retained its administrator display.'
}
function Assert-NoCredentialArguments([Diagnostics.Process]$Process) {
    $record = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $Process.Id)
    Assert-AuthenticationAcceptance ($null -ne $record -and -not [string]::IsNullOrWhiteSpace([string]$record.CommandLine)) 'A held test process command line was unavailable.'
    Assert-AuthenticationAcceptance (-not $record.CommandLine.Contains($script:password) -and -not $record.CommandLine.Contains($script:wrongPassword)) 'A synthetic password appeared in a held process command line.'
}
function Read-CoreAdministratorState {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:coreExecutable
    $start.Arguments = '--administrator-state --config "' + $script:configurationPath + '"'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_USERNAME')
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_PASSWORD')
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync(); $error = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Core administrator state inspection exceeded its deadline.' }
        if ($process.ExitCode -ne 0 -or $output.Result.Length -gt 256 -or -not [string]::IsNullOrWhiteSpace($error.Result)) { throw 'Core administrator state inspection failed.' }
        $state = $output.Result | ConvertFrom-Json
        if (@($state.PSObject.Properties).Count -ne 1 -or $state.status -notin @('required', 'initialized')) { throw 'Core administrator state returned an invalid coarse response.' }
        return $state.status
    } finally { $process.Dispose() }
}
function Invoke-OwnedServiceAction([string]$Action) {
    & $script:managementScript -Action $Action -CodeDirectory $script:coreCode -DataDirectory $script:coreData -TimeoutSeconds $script:TimeoutSeconds | Out-Null
}
function Get-OwnedCoreProcess {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'"
    Assert-AuthenticationAcceptance ($null -ne $service -and $service.State -eq 'Running' -and $service.ProcessId -gt 0) 'The installer-owned Core service was not running.'
    $process = [Diagnostics.Process]::GetProcessById([int]$service.ProcessId)
    try {
        $null = $process.Handle
        Assert-AuthenticationAcceptance ([IO.Path]::GetFullPath($process.MainModule.FileName) -ieq $script:coreExecutable) 'SCM selected a different executable.'
        Assert-AuthenticationAcceptance ($service.StartName -ieq 'NT SERVICE\SentinelAICore') 'Core changed its declared limited service identity.'
        $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 5000 -State Listen)
        Assert-AuthenticationAcceptance ($listeners.Count -eq 1 -and $listeners[0].OwningProcess -eq $process.Id) 'The fixed Core authentication origin was not owned by its exact service process.'
        Assert-NoCredentialArguments $process
        return $process
    } catch { $process.Dispose(); throw }
}

try {
    Invoke-PilotInstall -Component Core -BundleDirectory $BundleDirectory -PublicKeyPath $PublicKeyPath -KeyId $KeyId `
        -Environment $Environment -Channel $Channel -CodeDirectory $coreCode -DataDirectory $coreData -CoreUrl 'http://127.0.0.1:5000' -TimeoutSeconds $TimeoutSeconds | Out-Null
    Assert-AuthenticationAcceptance ((Read-CoreAdministratorState) -eq 'required') 'Fresh Core unexpectedly had an administrator.'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $ExecutablePath; $start.WorkingDirectory = Split-Path -Parent $ExecutablePath; $start.UseShellExecute = $false
    $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_USERNAME'); $start.EnvironmentVariables.Remove('SENTINELAI_BOOTSTRAP_PASSWORD')
    $desktop = [Diagnostics.Process]::Start($start); $null = $desktop.Handle
    Wait-AuthenticationAcceptance { $script:desktop.Refresh(); $script:desktop.MainWindowHandle -ne [IntPtr]::Zero } 'Desktop did not open its native authentication window.'
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($desktop.MainWindowHandle)
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'CreateAdministratorButton' $false } 'Fresh Desktop did not detect first-run administrator setup.'
    Assert-SignedOut
    Set-AuthenticationCredential $username $password
    Invoke-AuthenticationControl 'CreateAdministratorButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Desktop administrator creation did not transition to sign-in.'
    Assert-AuthenticationAcceptance ((Read-CoreAdministratorState) -eq 'initialized') 'The real Core helper did not create its administrator from Desktop.'
    Assert-SignedOut
    Assert-NoCredentialArguments $desktop

    & $managementScript -Action Install -CodeDirectory $coreCode -DataDirectory $coreData -BundleDirectory $BundleDirectory `
        -PublicKeyPath $PublicKeyPath -KeyId $KeyId -Environment $Environment -Channel $Channel -TimeoutSeconds $TimeoutSeconds | Out-Null
    $serviceInstalled = $true
    Invoke-OwnedServiceAction Start
    $coreProcess = Get-OwnedCoreProcess

    # Four requests before restart stay below Core's five-per-minute limiter:
    # wrong password, unknown username, successful sign-in, sign-in after logout.
    Set-AuthenticationCredential $username $wrongPassword
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { -not [string]::IsNullOrWhiteSpace((Get-AuthenticationError)) -and (Test-AuthenticationControl 'SignInButton') } 'Wrong credentials did not show an explicit safe error.'
    $wrongError = Get-AuthenticationError
    Assert-SignedOut
    Set-AuthenticationCredential ('missing-' + [Guid]::NewGuid().ToString('N')) $wrongPassword
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { -not [string]::IsNullOrWhiteSpace((Get-AuthenticationError)) -and (Test-AuthenticationControl 'SignInButton') } 'Unknown credentials did not show an explicit safe error.'
    Assert-AuthenticationAcceptance ((Get-AuthenticationError) -ceq $wrongError) 'Invalid authentication revealed whether the administrator existed.'
    Assert-AuthenticationAcceptance (-not $wrongError.Contains($password) -and -not $wrongError.Contains($wrongPassword)) 'The generic authentication error disclosed a password.'
    Set-AuthenticationCredential $username $password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'The real Core administrator could not sign in from Desktop.'
    $identity = Find-AuthenticationControl 'AdministratorNameText'
    Assert-AuthenticationAcceptance ($null -ne $identity -and $identity.Current.Name.Contains($username)) 'Desktop did not display Core-authoritative administrator identity.'
    Assert-AuthenticationAcceptance (Test-AuthenticationControl 'NavigationList') 'A valid Core session did not expose native workspace navigation.'
    $navigation = Find-AuthenticationControl 'NavigationList'
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ListItem)
    $items = $navigation.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    Assert-AuthenticationAcceptance ($items.Count -gt 1) 'The authenticated workspace lacked native placeholder pages.'
    for ($index = 0; $index -lt $items.Count; $index++) {
        $item = $items[$index]; $expectedHeading = $item.Current.Name
        ([System.Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Wait-AuthenticationAcceptance { $heading = Find-AuthenticationControl 'PageHeading'; $null -ne $heading -and $heading.Current.Name -ceq $expectedHeading } 'Authenticated native navigation did not update its placeholder heading.'
    }
    Invoke-AuthenticationControl 'SignOutButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' $false } 'Sign-out did not return Desktop to sign-in.'
    Assert-SignedOut
    # A stopped Core port may be occupied by an unrelated local process. The
    # desktop must verify its service peer before any HTTP credential bytes.
    Invoke-OwnedServiceAction Stop
    Assert-AuthenticationAcceptance ($coreProcess.WaitForExit(10000)) 'The owned Core did not stop before the foreign-listener check.'
    $coreProcess.Dispose(); $coreProcess = $null
    $foreignListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 5000)
    $foreignListener.Start()
    Set-AuthenticationCredential $username $password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { -not [string]::IsNullOrWhiteSpace((Get-AuthenticationError)) -and (Test-AuthenticationControl 'SignInButton') } 'Desktop did not safely reject an unrelated process on Core port.'
    Assert-AuthenticationAcceptance (-not $foreignListener.Pending()) 'Desktop connected to an unrelated process before verifying Core.'
    Assert-SignedOut
    $foreignListener.Stop(); $foreignListener = $null
    Invoke-OwnedServiceAction Start
    $coreProcess = Get-OwnedCoreProcess
    Set-AuthenticationCredential $username $password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'Explicit sign-in after logout did not establish a new session.'
    $previousCore = $coreProcess
    Invoke-OwnedServiceAction Restart
    Assert-AuthenticationAcceptance ($previousCore.WaitForExit(10000) -and $previousCore.ExitCode -eq 0) 'Core restart did not gracefully exit its held previous process.'
    $previousCore.Dispose(); $coreProcess = Get-OwnedCoreProcess
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignInButton' } 'Core restart did not clear Desktop session within its bounded revalidation interval.' 45
    Assert-SignedOut
    Set-AuthenticationCredential $username $password
    Invoke-AuthenticationControl 'SignInButton'
    Wait-AuthenticationAcceptance { Test-AuthenticationControl 'SignOutButton' } 'Desktop could not explicitly reconnect after Core restart.'
    if ($VerifyDevices) {
        . (Join-Path $PSScriptRoot 'Devices.Acceptance.ps1')
        Invoke-NativeDevicesAcceptance
    }
    if ($VerifyAlerts) {
        . (Join-Path $PSScriptRoot 'Alerts.Acceptance.ps1')
        Invoke-NativeAlertsAcceptance
    }
    if ($VerifyRiskReports) {
        . (Join-Path $PSScriptRoot 'RiskReports.Acceptance.ps1')
        Invoke-NativeRiskReportsAcceptance
    }
    Assert-NoCredentialArguments $desktop
    Assert-NoCredentialArguments $coreProcess

    [void][SentinelAIDesktopAuthenticationAcceptance.Native]::PostMessage($desktop.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-AuthenticationAcceptance ($desktop.WaitForExit(30000) -and $desktop.ExitCode -eq 0) 'Authenticated Desktop did not close gracefully.'
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'"
    Assert-AuthenticationAcceptance (-not $coreProcess.HasExited -and $service.ProcessId -eq $coreProcess.Id -and $service.State -eq 'Running') 'Desktop close changed independent Core service lifetime.'
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(5)
    $health = $client.GetAsync('http://127.0.0.1:5000/api/health').GetAwaiter().GetResult()
    try {
        Assert-AuthenticationAcceptance ($health.IsSuccessStatusCode -and ($health.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json).status -eq 'healthy') 'Core was unhealthy after authenticated Desktop exit.'
    } finally { $health.Dispose() }
    [pscustomobject]@{ Result = 'Passed'; Assertions = $assertionCount; Installation = $coreData; NativeAuthentication = 'Bootstrap, credentials, sign-out, restart and reconnect' }
} finally {
    if ($null -ne $foreignListener) { $foreignListener.Stop() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $desktop) {
        try { if (-not $desktop.HasExited) { $desktop.Kill(); [void]$desktop.WaitForExit(10000) } } finally { $desktop.Dispose() }
    }
    if ($serviceInstalled) {
        # The existing manager validates this exact fixture's ownership receipt,
        # configuration and SCM executable before removing only its service.
        Invoke-OwnedServiceAction Uninstall
        if ($null -ne (Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'")) { throw 'The owned acceptance service was not removed.' }
    }
    if ($null -ne $coreProcess) { $coreProcess.Dispose() }
    $password = $null; $wrongPassword = $null
}
