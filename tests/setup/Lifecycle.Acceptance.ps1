# Real native single-EXE lifecycle, on the same fresh isolated Windows machine.
# All three artifacts share an external development key. Credentials stay in
# this PowerShell process and protected native controls; no silent setup path.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InitialExecutablePath,
    [Parameter(Mandatory = $true)][string]$UpgradeExecutablePath,
    [Parameter(Mandatory = $true)][string]$UnhealthyExecutablePath,
    [ValidateRange(60, 900)][int]$TimeoutSeconds = 300
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($name in @('InitialExecutablePath', 'UpgradeExecutablePath', 'UnhealthyExecutablePath')) {
    $path = (Resolve-Path -LiteralPath (Get-Variable -Name $name -ValueOnly)).ProviderPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or [IO.Path]::GetFileName($path) -cne 'SentinelAI-Setup.exe') {
        throw 'Lifecycle acceptance requires the three actual published Setup executables.'
    }
    Set-Variable -Name $name -Value $path
}
$context = $null
. (Join-Path $PSScriptRoot 'Windows.Acceptance.ps1') -ExecutablePath $InitialExecutablePath -TimeoutSeconds $TimeoutSeconds `
    -PreserveInstallation -InstallationContext ([ref]$context)
if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.Password)) { throw 'Fresh native acceptance did not provide its private synthetic context.' }
$username = $context.Username; $password = $context.Password; $endpointId = $context.EndpointId
$context = $null; $coreProcess = $null; $agentProcess = $null; $client = $null; $accessToken = $null
$nativeSqlite = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\winsqlite3.dll'
$databasePath = Join-Path $coreData 'sentinelai.db'
$lifecycleHosts = New-Object 'System.Collections.Generic.List[object]'
$baseline = $null

if ($null -eq ('SentinelAI.Setup.Lifecycle.Sqlite' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace SentinelAI.Setup.Lifecycle {
 public static class Sqlite {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string name);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Open(IntPtr name,out IntPtr database,int flags,IntPtr vfs);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Close(IntPtr database);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Busy(IntPtr database,int milliseconds);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi)] delegate int Prepare(IntPtr database,string query,int bytes,out IntPtr statement,IntPtr tail);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Step(IntPtr statement);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr Text(IntPtr statement,int column);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Finalize(IntPtr statement);
  static T Function<T>(IntPtr module,string name) where T:class {
   IntPtr address=GetProcAddress(module,name);
   if(address==IntPtr.Zero) throw new InvalidOperationException("Native SQLite is unavailable.");
   return (T)(object)Marshal.GetDelegateForFunctionPointer(address,typeof(T));
  }
  static string Query(IntPtr database,Prepare prepare,Step step,Text text,Finalize finalize,string sql,bool required) {
   IntPtr statement=IntPtr.Zero; var result=new StringBuilder(); int rows=0;
   try {
    if(prepare(database,sql,-1,out statement,IntPtr.Zero)!=0) throw new InvalidOperationException("Retained state query failed.");
    int status;
    while((status=step(statement))==100) {
     string value=Marshal.PtrToStringAnsi(text(statement,0));
     if(value==null || value.Length>65536 || ++rows>1024 || result.Length+value.Length>1048576)
      throw new InvalidOperationException("Retained state exceeds fixture bounds.");
     result.Append(value).Append('\n');
    }
    if(status!=101 || required && rows==0) throw new InvalidOperationException("Required retained state is missing.");
    return result.ToString();
   } finally {if(statement!=IntPtr.Zero)finalize(statement);}
  }
  static string Digest(string value) {
   using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-","");
  }
  public static string[] Snapshot(string libraryPath,string databasePath) {
   IntPtr module=LoadLibraryEx(libraryPath,IntPtr.Zero,0x00000100|0x00001000);
   if(module==IntPtr.Zero) throw new InvalidOperationException("The system SQLite library is unavailable.");
   IntPtr database=IntPtr.Zero,name=IntPtr.Zero; Close close=null;
   try {
    byte[] encoded=Encoding.UTF8.GetBytes(databasePath+"\0");name=Marshal.AllocHGlobal(encoded.Length);Marshal.Copy(encoded,0,name,encoded.Length);
    close=Function<Close>(module,"sqlite3_close");
    if(Function<Open>(module,"sqlite3_open_v2")(name,out database,0x00000001|0x00010000,IntPtr.Zero)!=0)
     throw new InvalidOperationException("Retained SQLite cannot be opened read-only.");
    Function<Busy>(module,"sqlite3_busy_timeout")(database,5000);
    var prepare=Function<Prepare>(module,"sqlite3_prepare_v2");var step=Function<Step>(module,"sqlite3_step");
    var text=Function<Text>(module,"sqlite3_column_text");var finalize=Function<Finalize>(module,"sqlite3_finalize");
    Query(database,prepare,step,text,finalize,"BEGIN;",false);
    var fingerprints=new List<string>();
    foreach(string sql in new[]{
     "SELECT Username || '|' || PasswordHash FROM Administrators ORDER BY Username;",
     "SELECT CoreInstallationId || '|' || OrganizationId FROM CoreIdentity WHERE Singleton=1;",
     "SELECT InstallationId || '|' || EndpointId || '|' || CoreInstallationId || '|' || OrganizationId || '|' || hex(CredentialHash) FROM EndpointEnrollments ORDER BY InstallationId;",
     "SELECT COALESCE(Lease,'NULL') || '|' || COALESCE(LastSuccessfulValidationUtcTicks,'NULL') || '|' || LastAttemptSucceeded || '|' || ClockRollbackDetected FROM LicenseState WHERE Singleton=1;"})
     fingerprints.Add(Digest(Query(database,prepare,step,text,finalize,sql,true)));
    // Inventory refresh legitimately updates alert observation/version fields.
    // First observations, identities and retained status history must survive.
    string highWater=Query(database,prepare,step,text,finalize,"SELECT HighWaterUtcTicks FROM LicenseState WHERE Singleton=1;",true).Trim();
    fingerprints.Add(highWater);
    foreach(string sql in new[]{
     "SELECT AlertId || '|' || EndpointId || '|' || RuleId || '|' || FirstObservedUtcTicks || '|' || CreatedUtcTicks FROM TrackedAlerts ORDER BY AlertId;",
     "SELECT SequenceId || '|' || AlertId || '|' || COALESCE(PreviousStatus,'NULL') || '|' || Status || '|' || ChangedUtcTicks || '|' || ChangedBy FROM AlertStatusHistory ORDER BY SequenceId;"}) {
     foreach(string row in Query(database,prepare,step,text,finalize,sql,false).Split('\n'))
      if(row.Length!=0) fingerprints.Add(Digest(row));
    }
    return fingerprints.ToArray();
   } finally {if(database!=IntPtr.Zero && close!=null)close(database);if(name!=IntPtr.Zero)Marshal.FreeHGlobal(name);FreeLibrary(module);}
  }
 }
}
'@ | Out-Null
}

function Open-LifecycleCore {
    foreach ($held in @($script:coreProcess, $script:agentProcess)) { if ($null -ne $held) { $held.Dispose() } }
    $script:coreProcess = Get-HeldInstalledProcess 'SentinelAICore' (Join-Path $script:coreCode 'SentinelAI.Core.exe') 'NT SERVICE\SentinelAICore'
    $script:agentProcess = Get-HeldInstalledProcess 'SentinelAIAgent' (Join-Path $script:agentCode 'SentinelAI.Agent.exe') 'NT AUTHORITY\LocalService'
    Assert-InstalledServiceRuntime $script:coreProcess $script:coreCode
    Assert-InstalledServiceRuntime $script:agentProcess $script:agentCode
    if ($null -eq $script:client) {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false
        $script:client = [Net.Http.HttpClient]::new($handler); $script:client.Timeout = [TimeSpan]::FromSeconds(10)
    }
    $body = @{ username = $script:username; password = $script:password } | ConvertTo-Json -Compress
    try { $session = Invoke-SetupCoreRequest '/api/auth/login' 'POST' $body | ConvertFrom-Json } finally { $body = $null }
    $script:accessToken = [string]$session.accessToken; $session = $null
    Assert-SetupAcceptance (-not [string]::IsNullOrWhiteSpace($script:accessToken)) 'Maintenance lost the existing administrator authentication.'
    $license = Invoke-SetupCoreRequest '/api/admin/license' 'GET' $null $script:accessToken | ConvertFrom-Json
    Assert-SetupAcceptance ($license.mode -ceq 'SAFE_MODE') 'The development lifecycle changed the retained local license mode.'
}
function Read-LifecyclePreservedState {
    $sqlite = [SentinelAI.Setup.Lifecycle.Sqlite]::Snapshot($script:nativeSqlite, $script:databasePath)
    $hashes = @{}
    foreach ($path in @((Join-Path $script:coreData 'pilot-config.json'), (Join-Path $script:agentData 'pilot-config.json'),
        (Join-Path $script:agentData 'enrollment-state'), (Join-Path $script:agentData 'installation-id'), (Join-Path $script:agentData 'endpoint-id'))) {
        $hashes[$path] = Read-SetupStateDigest $path
    }
    return [pscustomobject]@{ Fingerprints = @($sqlite[0..3]); HighWater = [long]$sqlite[4]; History = @($sqlite | Select-Object -Skip 5); Files = $hashes }
}
function Assert-LifecyclePreserved {
    $current = Read-LifecyclePreservedState
    $categories = @('administrator','Core identity','endpoint enrollment','license metadata')
    for ($index = 0; $index -lt $categories.Count; $index++) {
        Assert-SetupAcceptance ($current.Fingerprints[$index] -ceq $script:baseline.Fingerprints[$index]) ('Lifecycle changed retained ' + $categories[$index] + '.')
    }
    # Fresh telemetry may add findings/history. Every baseline observation and
    # status transition must survive unchanged; additional rows are permitted.
    $history = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($fingerprint in $current.History) { [void]$history.Add($fingerprint) }
    foreach ($fingerprint in $script:baseline.History) {
        Assert-SetupAcceptance ($history.Contains($fingerprint)) 'Lifecycle deleted or reset a retained security-history row.'
    }
    Assert-SetupAcceptance ($current.HighWater -ge $script:baseline.HighWater) 'Lifecycle reset the persisted license clock high-water.'
    foreach ($path in $script:baseline.Files.Keys) { Assert-SetupAcceptance ($current.Files[$path] -ceq $script:baseline.Files[$path]) 'Lifecycle reset protected configuration, Agent identity or DPAPI enrollment state.' }
}
function Assert-LifecycleAcls {
    $writers = @('S-1-5-32-544', 'S-1-5-18', $script:operatorSid)
    Assert-ProtectedTree $script:programRoot $writers
    Assert-ProtectedTree $script:coreData ($writers + @($script:coreSid))
    Assert-ProtectedTree $script:agentData ($writers + @($script:localServiceSid))
    Assert-ProtectedTree $script:setupData $writers
    $mutation = [int]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    $read = [int][Security.AccessControl.FileSystemRights]::Read
    $execute = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    Assert-ServiceAcl (Join-Path $script:coreCode 'coreclr.dll') $script:coreSid $execute $mutation
    Assert-ServiceAcl (Join-Path $script:agentCode 'coreclr.dll') $script:localServiceSid $execute $mutation
    Assert-ServiceAcl (Join-Path $script:desktopCode 'SentinelAI.Desktop.exe') 'S-1-5-32-545' $execute $mutation
    Assert-ServiceAcl (Join-Path $script:coreData 'pilot-config.json') $script:coreSid $read $mutation
    Assert-ServiceAcl (Join-Path $script:agentData 'pilot-config.json') $script:localServiceSid $read $mutation
}
function Read-LifecycleCodeFingerprint {
    $items = @(Get-ChildItem -LiteralPath $script:programRoot -Recurse -File -Force | Sort-Object FullName)
    Assert-SetupAcceptance ($items.Count -gt 0 -and $items.Count -le 4096) 'Lifecycle code tree inspection exceeded its bound.'
    $builder = [Text.StringBuilder]::new()
    foreach ($item in $items) {
        Assert-SetupAcceptance (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Lifecycle code contains a link.'
        [void]$builder.Append($item.FullName.Substring($script:programRoot.Length)).Append('|').Append((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash).Append("`n")
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($builder.ToString()))).Replace('-', '') }
    finally { $sha.Dispose() }
}
function Assert-LifecycleVersion([string]$Version, [switch]$AllowLegacy) {
    $markerPath = Join-Path $script:programRoot 'deployment-version.json'
    $receiptPath = Join-Path $script:programRoot '.sentinelai-update-receipt.json'
    # The supported TASK-024 fresh layout has protected component/service
    # receipts but no whole-deployment marker or signed transaction receipt.
    # Only the initial baseline may use that legacy version authority.
    if (-not $AllowLegacy -or (Test-Path -LiteralPath $markerPath)) {
        $metadata = [IO.File]::ReadAllText($markerPath) | ConvertFrom-Json
        Assert-SetupAcceptance ($metadata.format -ceq 'sentinelai-deployment-v1' -and $metadata.version -ceq $Version) 'Deployment version does not match the healthy committed build.'
    }
    if (-not $AllowLegacy -or (Test-Path -LiteralPath $receiptPath)) {
        Assert-SetupAcceptance ((Get-Item -LiteralPath $receiptPath).Length -le 8192) 'Installed transaction receipt exceeded its metadata bound.'
        $receipt = [IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json
        Assert-SetupAcceptance ($receipt.format -ceq 'sentinelai-update-v1' -and $receipt.manifest.version -ceq $Version -and
            $receipt.manifest.artifactId -ceq 'sentinelai-deployment-win-x64' -and $receipt.manifest.environment -ceq 'development' -and
            $receipt.manifest.channel -ceq 'pilot' -and $receipt.keyId -ceq 'dev-ci-lifecycle' -and $receipt.signature.Length -eq 86) 'The healthy whole deployment did not retain its signed transaction receipt.'
    }
    foreach ($path in @((Join-Path $script:coreData 'pilot-installation.json'), (Join-Path $script:agentData 'pilot-installation.json'),
        (Join-Path $script:coreData 'core-service-installation.json'))) {
        $ownership = [IO.File]::ReadAllText($path) | ConvertFrom-Json
        Assert-SetupAcceptance ($ownership.version -ceq $Version) 'Protected component/service ownership retained a different version.'
    }
    foreach ($entry in @(@($script:coreCode, 'SentinelAI.Core.exe'), @($script:agentCode, 'SentinelAI.Agent.exe'),
        @($script:desktopCode, 'SentinelAI.Desktop.exe'), @($script:updaterCode, 'SentinelAI.Updater.exe'))) {
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $entry[0] $entry[1]))
        Assert-SetupAcceptance ($info.FileMajorPart -eq 1 -and $info.FileMinorPart -eq [int]$Version.Split('.')[1] -and $info.FileBuildPart -eq 0) 'A lifecycle component was left on a different build.'
    }
}
function Select-LifecycleAction([string]$Name) {
    Wait-SetupAcceptance { Test-SetupControl 'SetupLifecycleAction' } 'Setup did not expose detected lifecycle actions.'
    $control = Find-SetupControl 'SetupLifecycleAction'
    $expand = [Windows.Automation.ExpandCollapsePattern]$control.GetCurrentPattern([Windows.Automation.ExpandCollapsePattern]::Pattern)
    $expand.Expand()
    $condition = [Windows.Automation.AndCondition]::new(
        [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, $Name),
        [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::ListItem))
    $item = $control.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
    Assert-SetupAcceptance ($null -ne $item) 'A required detected lifecycle action was unavailable.'
    ([Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    $expand.Collapse()
}
function Invoke-LifecycleSetup([string]$Executable, [string]$Action, [bool]$ExpectFailure = $false, [bool]$RemoveData = $false) {
    $launch = Start-TestSetup $Executable; $script:lifecycleHosts.Add($launch)
    $script:setup = $launch.Host; $script:setupOuter = $launch.Outer
    Use-SetupWindow $launch.Host
    Assert-NativeSetupRuntime $launch.Host $launch.Outer
    Select-LifecycleAction $Action
    $version = Find-SetupControl 'SetupInstallationVersion'
    Assert-SetupAcceptance ($null -ne $version -and -not [string]::IsNullOrWhiteSpace($version.Current.Name)) 'Lifecycle did not display detected installation version.'
    Assert-NoSecretText ([string]$version.Current.Name)
    if ($Action -ceq 'Uninstall') {
        $keep = Find-SetupControl 'SetupPreserveData'
        Assert-SetupAcceptance ($null -ne $keep) 'Uninstall did not expose explicit data-retention choice.'
        $toggle = [Windows.Automation.TogglePattern]$keep.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
        Assert-SetupAcceptance ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::On) 'Uninstall did not preserve security history/configuration by default.'
        if ($RemoveData) {
            $toggle.Toggle()
            Wait-SetupAcceptance { Test-SetupControl 'SetupDataRemovalConfirmation' } 'Explicit data removal had no confirmation input.'
            Assert-SetupAcceptance (-not (Test-SetupControl 'SetupLifecycleButton')) 'Uninstall allowed data deletion before explicit confirmation.'
            $confirmation = Find-SetupControl 'SetupDataRemovalConfirmation'
            ([Windows.Automation.ValuePattern]$confirmation.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)).SetValue('DELETE')
        }
    }
    Show-SetupControl 'SetupLifecycleButton'
    Wait-SetupAcceptance { Test-SetupControl 'SetupLifecycleButton' } 'Selected lifecycle operation never became ready.'
    ([Windows.Automation.InvokePattern](Find-SetupControl 'SetupLifecycleButton').GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)).Invoke()
    Wait-SetupAcceptance { -not (Test-SetupControl 'SetupLifecycleButton') } 'Lifecycle did not begin its explicit operation.'
    $script:observedUnhealthyRunning = $false
    Wait-SetupAcceptance {
        Assert-SetupChildArguments
        if ($ExpectFailure -and -not $script:observedUnhealthyRunning) {
            # Prove this candidate actually ran under SCM and reached Running.
            # A mere invalid package/start failure is weaker than health rollback.
            $service = Get-SetupService 'SentinelAICore'
            if ($null -ne $service -and $service.State -ceq 'Running' -and $service.ProcessId -gt 0 -and
                $service.ProcessId -ne $script:coreProcess.Id -and $service.StartName -ieq 'NT SERVICE\SentinelAICore') {
                try {
                    $metadata = [IO.File]::ReadAllText((Join-Path $script:programRoot 'deployment-version.json')) | ConvertFrom-Json
                    if ($metadata.version -ceq '1.2.0') { $script:observedUnhealthyRunning = $true }
                } catch { }
            }
        }
        $errorControl = Find-SetupControl 'SetupErrorText'
        if ($null -ne $errorControl -and -not $errorControl.Current.IsOffscreen -and -not [string]::IsNullOrWhiteSpace($errorControl.Current.Name)) {
            Assert-NoSecretText ([string]$errorControl.Current.Name)
            if (-not $ExpectFailure) { throw (Get-SetupFailureSummary) }
            return $true
        }
        if (Test-SetupControl 'SetupFinishedText' $false) {
            if ($ExpectFailure) { throw 'Unhealthy signed deployment incorrectly reported successful upgrade.' }
            return $true
        }
        return $false
    } 'Native lifecycle operation did not complete within its deadline.' $script:TimeoutSeconds
    if ($ExpectFailure) { Assert-SetupAcceptance $script:observedUnhealthyRunning 'Signed unhealthy candidate never reached actual SCM Running for health verification.' }
    [void][SentinelAI.Setup.Acceptance.Native]::PostMessage($launch.Host.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    Assert-SetupAcceptance ($launch.Host.WaitForExit(30000)) 'Completed lifecycle window did not close.'
    Assert-SetupAcceptance (($launch.Host.ExitCode -eq 0) -eq (-not $ExpectFailure)) 'Lifecycle process exit did not match its visible result.'
    Assert-SetupAcceptance ($launch.Outer.WaitForExit(30000) -and $launch.Outer.ExitCode -eq $launch.Host.ExitCode) 'Native lifecycle wrapper did not propagate its private host result.'
    Assert-PoisonedCallerUntouched
}

try {
    Open-LifecycleCore
    $baseline = Read-LifecyclePreservedState
    Assert-LifecycleVersion '1.0.0' -AllowLegacy
    $since = [DateTimeOffset]::UtcNow
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Upgrade'
    Open-LifecycleCore; Wait-ExactEndpoint $endpointId $since
    Assert-LifecycleVersion '1.1.0'; Assert-LifecyclePreserved
    Assert-LifecycleAcls
    $healthyCode = Read-LifecycleCodeFingerprint
    $since = [DateTimeOffset]::UtcNow
    Invoke-LifecycleSetup $UnhealthyExecutablePath 'Upgrade' $true
    Open-LifecycleCore; Wait-ExactEndpoint $endpointId $since
    Assert-LifecycleVersion '1.1.0'; Assert-LifecyclePreserved
    Assert-SetupAcceptance ((Read-LifecycleCodeFingerprint) -ceq $healthyCode) 'Health-failed upgrade did not restore the exact previous whole deployment.'
    Assert-LifecycleAcls

    # Damage only proven, fixture-owned program files. Persistent directories,
    # identities and protected configuration are untouched by fault injection.
    foreach ($name in @('SentinelAIAgent', 'SentinelAICore')) {
        $service = Get-Service -Name $name
        try { $service.Stop(); $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60)) }
        finally { $service.Dispose() }
    }
    foreach ($held in @($coreProcess, $agentProcess)) { Assert-SetupAcceptance ($held.WaitForExit(10000)) 'An owned service did not stop before program-file damage.' }
    $damaged = @{}
    foreach ($path in @((Join-Path $coreCode 'SentinelAI.Core.dll'), (Join-Path $agentCode 'SentinelAI.Agent.dll'), (Join-Path $desktopCode 'SentinelAI.Desktop.dll'))) {
        $damaged[$path] = Read-SetupStateDigest $path
        Remove-Item -LiteralPath $path -Force
    }
    $since = [DateTimeOffset]::UtcNow
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Repair'
    Open-LifecycleCore; Wait-ExactEndpoint $endpointId $since
    Assert-LifecycleVersion '1.1.0'; Assert-LifecyclePreserved
    foreach ($path in $damaged.Keys) { Assert-SetupAcceptance ((Read-SetupStateDigest $path) -ceq $damaged[$path]) 'Repair did not restore an actual damaged program assembly.' }
    Assert-LifecycleAcls
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Uninstall'
    Assert-SetupAcceptance ($null -eq (Get-SetupService 'SentinelAICore') -and $null -eq (Get-SetupService 'SentinelAIAgent')) 'Uninstall retained an owned service registration.'
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath $programRoot) -and -not (Test-Path -LiteralPath $shortcutRoot)) 'Uninstall retained owned code or Start Menu shortcuts.'
    Assert-SetupAcceptance (Test-Path -LiteralPath $databasePath -PathType Leaf) 'Default uninstall deleted security history.'
    Assert-LifecyclePreserved
    # Explicit restore reuses the same protected administrator, enrollment and
    # LocalService DPAPI identity; it cannot re-enroll or reset retained history.
    $since = [DateTimeOffset]::UtcNow
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Repair'
    Open-LifecycleCore; Wait-ExactEndpoint $endpointId $since
    Assert-LifecycleVersion '1.1.0'; Assert-LifecyclePreserved
    Assert-LifecycleAcls
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Uninstall'
    Assert-SetupAcceptance ($null -eq (Get-SetupService 'SentinelAICore') -and $null -eq (Get-SetupService 'SentinelAIAgent')) 'Restored services were not removed by a subsequent owned uninstall.'
    Assert-LifecyclePreserved
    Invoke-LifecycleSetup $UpgradeExecutablePath 'Uninstall' $false $true
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath $dataRoot)) 'Explicit confirmed data removal retained owned application data.'
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath $programRoot) -and -not (Test-Path -LiteralPath $shortcutRoot) -and
        $null -eq (Get-SetupService 'SentinelAICore') -and $null -eq (Get-SetupService 'SentinelAIAgent')) 'Explicit removal recreated code, shortcuts or services.'
    [pscustomobject]@{ Result = 'Passed'; Assertions = $assertionCount; NativeLifecycle = 'Fresh 1.0.0, upgrade 1.1.0, actual signed unhealthy 1.2.0 rollback, damaged-file repair, default retained-data uninstall, identity-preserving restore and explicit confirmed removal' }
} finally {
    foreach ($launch in $lifecycleHosts) {
        foreach ($process in @($launch.Host, $launch.Outer)) {
            try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(10000) } } finally { $process.Dispose() }
        }
    }
    # Failure retains owned data/code for diagnosis. Never erase unknown state.
    # The disposable runner owns any remaining registrations until teardown.
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $coreProcess) { $coreProcess.Dispose() }
    if ($null -ne $agentProcess) { $agentProcess.Dispose() }
    $context = $null; $password = $null; $accessToken = $null
}
