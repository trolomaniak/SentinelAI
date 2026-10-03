# Native acceptance of the published GUI. Run on an interactive Windows x64
# desktop; a live Core, administrator credentials and a browser are unnecessary.
# Authentication protects production navigation; signed-in page navigation is
# exercised separately by the focused WPF and live authentication acceptance.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [ValidateRange(5, 60)][int]$TimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'Native desktop acceptance requires Windows x64.'
}
if (-not [Environment]::UserInteractive) {
    throw 'Native desktop acceptance requires an interactive Windows desktop session.'
}
$ExecutablePath = (Resolve-Path -LiteralPath $ExecutablePath -ErrorAction Stop).ProviderPath
if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) { throw 'The published executable is missing.' }

$assertionCount = 0
function Assert-DesktopAcceptance {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}

# Check the actual apphost, rather than inferring native output from a csproj.
$stream = [IO.File]::OpenRead($ExecutablePath)
$reader = [IO.BinaryReader]::new($stream)
try {
    Assert-DesktopAcceptance ($stream.Length -ge 256) 'The apphost has no valid PE header.'
    Assert-DesktopAcceptance ($reader.ReadUInt16() -eq 0x5a4d) 'The apphost is not a Windows executable.'
    $stream.Position = 0x3c
    $peOffset = $reader.ReadInt32()
    Assert-DesktopAcceptance ($peOffset -ge 64 -and $peOffset + 94 -le $stream.Length) 'The PE header offset is invalid.'
    $stream.Position = $peOffset
    Assert-DesktopAcceptance ($reader.ReadUInt32() -eq 0x00004550) 'The apphost PE signature is invalid.'
    Assert-DesktopAcceptance ($reader.ReadUInt16() -eq 0x8664) 'The published apphost is not Windows x64.'
    $stream.Position = $peOffset + 24
    Assert-DesktopAcceptance ($reader.ReadUInt16() -eq 0x20b) 'The published apphost is not a PE32+ executable.'
    $stream.Position = $peOffset + 24 + 68
    Assert-DesktopAcceptance ($reader.ReadUInt16() -eq 2) 'The desktop must use the GUI Windows subsystem.'
} finally {
    $reader.Dispose()
}

if ($null -eq ('SentinelAIDesktopAcceptance.NativeWindow' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace SentinelAIDesktopAcceptance {
    public static class NativeWindow {
        private delegate bool EnumWindowCallback(IntPtr handle, IntPtr data);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowCallback callback, IntPtr data);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr handle, StringBuilder title, int maximum);
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool IsWindowVisible(IntPtr handle);
        [DllImport("user32.dll")] public static extern IntPtr GetWindowDpiAwarenessContext(IntPtr handle);
        [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool AreDpiAwarenessContextsEqual(IntPtr first, IntPtr second);
        [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr handle);
        [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
        public static IntPtr FindVisibleSentinelWindow(int processId) {
            IntPtr result = IntPtr.Zero;
            EnumWindows((handle, data) => {
                uint owner;
                GetWindowThreadProcessId(handle, out owner);
                if (owner != processId || !IsWindowVisible(handle)) return true;
                var title = new StringBuilder(256);
                GetWindowText(handle, title, title.Capacity);
                if (title.ToString() != "SentinelAI") return true;
                result = handle;
                return false;
            }, IntPtr.Zero);
            return result;
        }
    }
}
'@
}

$desktop = $null
$probeProcess = $null
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $ExecutablePath
    $start.WorkingDirectory = Split-Path -Parent $ExecutablePath
    $start.UseShellExecute = $false
    $desktop = [Diagnostics.Process]::Start($start)
    # Retain the exact child process handle rather than trusting a reusable PID.
    $null = $desktop.Handle
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $windowHandle = [IntPtr]::Zero
    while ($deadline.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ($desktop.HasExited) { throw ('Desktop exited before showing a native window; exit code ' + $desktop.ExitCode + '.') }
        $windowHandle = [SentinelAIDesktopAcceptance.NativeWindow]::FindVisibleSentinelWindow($desktop.Id)
        if ($windowHandle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    Assert-DesktopAcceptance ($windowHandle -ne [IntPtr]::Zero) 'No visible SentinelAI HWND appeared before the deadline.'
    Assert-DesktopAcceptance ([SentinelAIDesktopAcceptance.NativeWindow]::AreDpiAwarenessContextsEqual(
        [SentinelAIDesktopAcceptance.NativeWindow]::GetWindowDpiAwarenessContext($windowHandle), [IntPtr]::new(-4))) 'The published native window is not PerMonitorV2 DPI aware.'
    $windowDpi = [SentinelAIDesktopAcceptance.NativeWindow]::GetDpiForWindow($windowHandle)
    Assert-DesktopAcceptance ($windowDpi -gt 0) 'The actual native window DPI could not be observed.'

    # Windows PowerShell uses the installed Windows UI Automation assemblies.
    # Keeping this probe in its own STA host also works when the invoking pwsh
    # process does not include the Windows Desktop framework.
    $probe = '$windowHandle = [long]' + $windowHandle.ToInt64() + '; $desktopProcessId = ' + $desktop.Id + ';' + @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]::new($windowHandle))
if ($null -eq $root -or $root.Current.ProcessId -ne $desktopProcessId) { throw 'UI Automation did not attach to the exact desktop child.' }
function Find-Control([string]$id) {
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
    return $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
$wait = [Diagnostics.Stopwatch]::StartNew()
while ($wait.Elapsed.TotalSeconds -lt 10 -and $null -eq (Find-Control 'AuthenticationView')) { Start-Sleep -Milliseconds 50 }
$authentication = Find-Control 'AuthenticationView'
if ($null -eq $authentication -or $authentication.Current.IsOffscreen) { throw 'The published window did not show native authentication.' }
$password = Find-Control 'AuthenticationPassword'
if ($null -eq $password -or -not $password.Current.IsPassword) { throw 'Native authentication has no protected password control.' }
$navigation = Find-Control 'NavigationList'
if ($null -ne $navigation -and -not $navigation.Current.IsOffscreen -and $navigation.Current.IsEnabled) {
    throw 'Production navigation was available without a Core-authenticated desktop session.'
}
$identity = Find-Control 'AdministratorNameText'
if ($null -ne $identity -and -not $identity.Current.IsOffscreen -and -not [string]::IsNullOrWhiteSpace($identity.Current.Name)) {
    throw 'The unauthenticated desktop displayed an administrator session.'
}
Write-Output 'Native UI Automation verified protected authentication and signed-out navigation.'
'@
    $probeHost = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/powershell.exe'
    Assert-DesktopAcceptance (Test-Path -LiteralPath $probeHost -PathType Leaf) 'The native Windows UI Automation probe host is unavailable.'
    $probeStart = [Diagnostics.ProcessStartInfo]::new()
    $probeStart.FileName = $probeHost
    $probeStart.Arguments = '-NoProfile -NonInteractive -STA -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $probeStart.UseShellExecute = $false
    $probeStart.CreateNoWindow = $true
    $probeProcess = [Diagnostics.Process]::Start($probeStart)
    $null = $probeProcess.Handle
    Assert-DesktopAcceptance ($probeProcess.WaitForExit($TimeoutSeconds * 1000)) 'Native UI Automation did not finish before the deadline.'
    Assert-DesktopAcceptance ($probeProcess.ExitCode -eq 0) 'Published signed-out authentication UI Automation failed.'
    Assert-DesktopAcceptance (-not $desktop.HasExited) 'The published desktop exited during native authentication checks.'

    Assert-DesktopAcceptance ([SentinelAIDesktopAcceptance.NativeWindow]::PostMessage($windowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)) 'The native close request failed.'
    Assert-DesktopAcceptance ($desktop.WaitForExit($TimeoutSeconds * 1000)) 'Desktop did not shut down gracefully before the deadline.'
    Assert-DesktopAcceptance ($desktop.ExitCode -eq 0) 'Graceful desktop close returned a nonzero exit code.'
    [PSCustomObject]@{ Result = 'Passed'; Assertions = $assertionCount; NativeWindowDpi = $windowDpi; Executable = $ExecutablePath }
} finally {
    foreach ($child in @($probeProcess, $desktop)) {
        if ($null -ne $child) {
            try {
                if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
            } finally {
                $child.Dispose()
            }
        }
    }
}
