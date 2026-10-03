# Opt-in native acceptance: use an elevated, interactive Windows 11 x64 test
# machine with no SentinelAICore installation. Retain isolated data for review.
# Portable tests do not establish SCM, virtual-account or NTFS acceptance.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDirectory,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$KeyId,
    [Parameter(Mandatory = $true)][string]$DesktopExecutablePath,
    [ValidateSet('development', 'production')][string]$Environment = 'development',
    [ValidateSet('stable', 'pilot', 'beta')][string]$Channel = 'pilot',
    [string]$WorkDirectory,
    [ValidateRange(30, 600)][int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$installerDirectory = Join-Path $repositoryRoot 'installer/pilot'
$managementScript = Join-Path $installerDirectory 'Manage-SentinelAICoreService.ps1'
Import-Module (Join-Path $installerDirectory 'PilotInstaller.psm1') -Force -DisableNameChecking
Assert-PilotSupportedHost
if (-not [Environment]::UserInteractive) { throw 'Desktop-exit acceptance requires an interactive Windows session.' }
$BundleDirectory = (Resolve-Path -LiteralPath $BundleDirectory).ProviderPath
$PublicKeyPath = (Resolve-Path -LiteralPath $PublicKeyPath).ProviderPath
$DesktopExecutablePath = (Resolve-Path -LiteralPath $DesktopExecutablePath).ProviderPath
if (-not (Test-Path -LiteralPath $DesktopExecutablePath -PathType Leaf)) { throw 'The published native desktop is required for full service acceptance.' }
if ($null -ne (Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'")) {
    throw 'Acceptance requires a Windows test machine without SentinelAICore installed; an existing service will not be changed.'
}
if ([string]::IsNullOrWhiteSpace($WorkDirectory)) {
    $WorkDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('SentinelAI-Core-Service-Acceptance-' + [Guid]::NewGuid().ToString('N'))
}
$WorkDirectory = Assert-PilotPath $WorkDirectory
if (Test-Path -LiteralPath $WorkDirectory) { throw 'Acceptance requires a new work directory; existing files will not be adopted.' }
New-PilotProtectedDirectory -Path $WorkDirectory -Kind Container

# Hosted runners build in shared checkout/temp ancestors. Stage only this
# trusted test build's public verifier, signed payload and separately supplied
# public key into fresh protected locations; production installer checks stay
# unchanged. Stream bytes into create-new files rather than copying source ACLs.
function Copy-CoreServiceAcceptanceFile {
    param([string]$Source, [string]$Destination)
    $Source = Assert-PilotPath -Path $Source -MustExist -File
    [void](Assert-PilotPath -Path $Destination -File)
    if (Test-Path -LiteralPath $Destination) { throw 'Acceptance staging never adopts or overwrites existing files.' }
    Assert-PilotTrustedPath -Path $Destination
    $expectedHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
    $sourceStream = $null; $destinationStream = $null
    try {
        $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $destinationStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $sourceStream.CopyTo($destinationStream)
        $destinationStream.Flush($true)
    } finally {
        if ($null -ne $destinationStream) { $destinationStream.Dispose() }
        if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    }
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -cne $expectedHash -or
        (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -cne $expectedHash) {
        throw 'Acceptance staging changed generated build bytes.'
    }
    Assert-PilotTrustedPath -Path $Destination
}

function Copy-CoreServiceAcceptanceTree {
    param([string]$Source, [string]$Destination)
    $Source = Assert-PilotPath -Path $Source -MustExist
    if (Test-Path -LiteralPath $Destination) { throw 'Acceptance staging requires a new verifier directory.' }
    New-PilotDirectoryWithAcl -Path $Destination -Kind Container
    $pending = New-Object 'System.Collections.Generic.Queue[object]'
    $pending.Enqueue([pscustomobject]@{ Source = $Source; Destination = $Destination })
    $count = 0
    while ($pending.Count -ne 0) {
        $directory = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory.Source -Force) {
            if (++$count -gt 8192) { throw 'The acceptance verifier tree is too large.' }
            $target = Join-Path $directory.Destination $item.Name
            if ($item.PSIsContainer) {
                # Check links before descending, including on Windows PowerShell.
                [void](Assert-PilotPath -Path $item.FullName -MustExist)
                New-PilotDirectoryWithAcl -Path $target -Kind Container
                $pending.Enqueue([pscustomobject]@{ Source = $item.FullName; Destination = $target })
            } else { Copy-CoreServiceAcceptanceFile -Source $item.FullName -Destination $target }
        }
    }
    Assert-PilotTrustedPath -Path $Destination -Tree
}

$stagedBundle = Join-Path $WorkDirectory 'Bundle'
$stagedTrust = Join-Path $WorkDirectory 'Trust'
New-PilotDirectoryWithAcl -Path $stagedBundle -Kind Container
New-PilotDirectoryWithAcl -Path $stagedTrust -Kind Container
foreach ($name in @('core.zip', 'core.manifest.json')) {
    Copy-CoreServiceAcceptanceFile -Source (Join-Path $BundleDirectory $name) -Destination (Join-Path $stagedBundle $name)
}
Copy-CoreServiceAcceptanceTree -Source (Join-Path $BundleDirectory 'updater') -Destination (Join-Path $stagedBundle 'updater')
$stagedPublicKey = Join-Path $stagedTrust 'core-service.public.pem'
Copy-CoreServiceAcceptanceFile -Source $PublicKeyPath -Destination $stagedPublicKey
Set-PilotFileAcl -Path $stagedPublicKey -Kind Receipt
Assert-PilotTrustedPath -Path $stagedBundle -Tree
Assert-PilotTrustedPath -Path $stagedPublicKey
$BundleDirectory = $stagedBundle
$PublicKeyPath = $stagedPublicKey

$coreCode = Join-Path $WorkDirectory 'Core Code'
$coreData = Join-Path $WorkDirectory 'Core Data'
$configurationPath = Join-Path $coreData 'pilot-config.json'
$pilotReceiptPath = Join-Path $coreData 'pilot-installation.json'
$serviceReceiptPath = Join-Path $coreData 'core-service-installation.json'
$coreExecutable = Join-Path $coreCode 'SentinelAI.Core.exe'
$databasePath = Join-Path $coreData 'sentinelai.db'
$nativeSqlitePath = Join-Path ([Environment]::GetFolderPath('System')) 'winsqlite3.dll'
$expectedImagePath = '"' + $coreExecutable + '" --config "' + $configurationPath + '"'

# Windows 11's existing System32 SQLite library reads only this test database.
# Return fingerprints rather than outputting password hashes or persistent IDs.
if ($null -eq ('SentinelAI.CoreService.Acceptance.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace SentinelAI.CoreService.Acceptance {
    public static class Native {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr library, string name);
        [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr library);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int OpenSqlite(IntPtr filename, out IntPtr database, int flags, IntPtr vfs);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int CloseSqlite(IntPtr database);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BusyTimeout(IntPtr database, int milliseconds);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)] private delegate int Prepare(IntPtr database, string sql, int bytes, out IntPtr statement, IntPtr tail);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Step(IntPtr statement);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr ColumnText(IntPtr statement, int column);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int FinalizeStatement(IntPtr statement);
        private static T Function<T>(IntPtr library, string name) where T : class {
            IntPtr address = GetProcAddress(library, name);
            if (address == IntPtr.Zero) throw new InvalidOperationException("The Windows SQLite library is incomplete.");
            return (T)(object)Marshal.GetDelegateForFunctionPointer(address, typeof(T));
        }
        public static string ReadStateFingerprint(string libraryPath, string databasePath) {
            IntPtr library = LoadLibraryEx(libraryPath, IntPtr.Zero, 0x00000100 | 0x00001000);
            if (library == IntPtr.Zero) throw new InvalidOperationException("The Windows SQLite library could not be loaded.");
            IntPtr database = IntPtr.Zero;
            IntPtr filename = IntPtr.Zero;
            CloseSqlite close = null;
            try {
                var open = Function<OpenSqlite>(library, "sqlite3_open_v2");
                close = Function<CloseSqlite>(library, "sqlite3_close");
                byte[] encodedPath = Encoding.UTF8.GetBytes(databasePath + "\0");
                filename = Marshal.AllocHGlobal(encodedPath.Length);
                Marshal.Copy(encodedPath, 0, filename, encodedPath.Length);
                // SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX; never migrate/write.
                if (open(filename, out database, 0x00000001 | 0x00010000, IntPtr.Zero) != 0)
                    throw new InvalidOperationException("Persistent test state could not be opened read-only.");
                Function<BusyTimeout>(library, "sqlite3_busy_timeout")(database, 5000);
                var prepare = Function<Prepare>(library, "sqlite3_prepare_v2");
                var step = Function<Step>(library, "sqlite3_step");
                var column = Function<ColumnText>(library, "sqlite3_column_text");
                var finalize = Function<FinalizeStatement>(library, "sqlite3_finalize");
                var material = new StringBuilder();
                foreach (string query in new[] {
                    "SELECT Username || '|' || PasswordHash FROM Administrators ORDER BY Username;",
                    "SELECT CoreInstallationId || '|' || OrganizationId FROM CoreIdentity WHERE Singleton = 1;"
                }) {
                    IntPtr statement = IntPtr.Zero;
                    try {
                        if (prepare(database, query, -1, out statement, IntPtr.Zero) != 0 || step(statement) != 100)
                            throw new InvalidOperationException("A required persisted administrator or Core identity row is missing.");
                        string value = Marshal.PtrToStringAnsi(column(statement, 0));
                        if (String.IsNullOrWhiteSpace(value) || value.Length > 4096 || step(statement) != 101)
                            throw new InvalidOperationException("Persistent administrator or Core identity state is invalid.");
                        material.Append(value).Append('\n');
                    } finally { if (statement != IntPtr.Zero) finalize(statement); }
                }
                using (var sha = SHA256.Create()) {
                    return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(material.ToString()))).Replace("-", "");
                }
            } finally {
                if (database != IntPtr.Zero && close != null) close(database);
                if (filename != IntPtr.Zero) Marshal.FreeHGlobal(filename);
                FreeLibrary(library);
            }
        }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig2(IntPtr service, uint level, IntPtr buffer, uint size, out uint required);
        [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
        [StructLayout(LayoutKind.Sequential)] private struct FailureActions {
            public uint ResetPeriod;
            public IntPtr RebootMessage;
            public IntPtr Command;
            public uint Count;
            public IntPtr Actions;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ServiceAction { public uint Type; public uint Delay; }
        private static IntPtr Query(IntPtr service, uint level) {
            uint required;
            QueryServiceConfig2(service, level, IntPtr.Zero, 0, out required);
            if (required == 0 || required > 65536) throw new InvalidOperationException("SCM policy could not be inspected.");
            IntPtr buffer = Marshal.AllocHGlobal((int)required);
            if (!QueryServiceConfig2(service, level, buffer, required, out required)) {
                Marshal.FreeHGlobal(buffer);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return buffer;
        }
        public static void AssertRecoveryPolicy() {
            IntPtr manager = OpenSCManager(null, null, 1);
            if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr service = IntPtr.Zero;
            try {
                service = OpenService(manager, "SentinelAICore", 1);
                if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                IntPtr actionsBuffer = Query(service, 2);
                try {
                    var actions = (FailureActions)Marshal.PtrToStructure(actionsBuffer, typeof(FailureActions));
                    if (actions.ResetPeriod != 86400 || actions.Count != 3 || actions.Actions == IntPtr.Zero ||
                        !String.IsNullOrEmpty(Marshal.PtrToStringUni(actions.Command)) || !String.IsNullOrEmpty(Marshal.PtrToStringUni(actions.RebootMessage)))
                        throw new InvalidOperationException("SCM failure policy differs from the declared bounded restart policy.");
                    uint[] delays = { 5000, 15000, 60000 };
                    int stride = Marshal.SizeOf(typeof(ServiceAction));
                    for (int index = 0; index < delays.Length; index++) {
                        var action = (ServiceAction)Marshal.PtrToStructure(IntPtr.Add(actions.Actions, index * stride), typeof(ServiceAction));
                        if (action.Type != 1 || action.Delay != delays[index])
                            throw new InvalidOperationException("SCM restart action/delay differs from declared policy.");
                    }
                } finally { Marshal.FreeHGlobal(actionsBuffer); }
                foreach (uint level in new uint[] { 3, 4 }) {
                    IntPtr flag = Query(service, level);
                    try {
                        if (Marshal.ReadInt32(flag) == 0)
                            throw new InvalidOperationException("SCM delayed automatic start or failure recovery flag is missing.");
                    } finally { Marshal.FreeHGlobal(flag); }
                }
            } finally {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                CloseServiceHandle(manager);
            }
        }
    }
}
'@
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try { $listener.Start(); $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
$coreUrl = 'http://127.0.0.1:' + $port
$passwordBytes = [byte[]]::new(32)
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($passwordBytes) } finally { $random.Dispose() }
$securePassword = ConvertTo-SecureString -String ([Convert]::ToBase64String($passwordBytes)) -AsPlainText -Force
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
$credential = [PSCredential]::new('core-service-test-' + [Guid]::NewGuid().ToString('N'), $securePassword)
$sensitiveValues = [Collections.Generic.List[string]]::new()
$sensitiveValues.Add($credential.GetNetworkCredential().Password)
$consoleProcess = $null
$serviceProcess = $null
$serviceInstalled = $false
$client = $null
$assertionCount = 0
$startedUtc = [DateTime]::UtcNow
$stateFingerprint = $null

function Assert-CoreServiceAcceptance {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:assertionCount++
}
function Get-TestCoreService {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='SentinelAICore'"
}
function Invoke-TestServiceAction {
    param([string]$Action)
    & $script:managementScript -Action $Action -CodeDirectory $script:coreCode -DataDirectory $script:coreData -TimeoutSeconds $script:TimeoutSeconds | Out-Null
}
function Assert-NoTestSecrets {
    param([string]$Text)
    foreach ($value in $script:sensitiveValues) {
        Assert-CoreServiceAcceptance (-not $Text.Contains($value)) 'A synthetic credential/token appeared in service arguments, configuration or diagnostic messages.'
    }
}
function Get-ServiceAllowRights {
    param([string]$Path, [string]$Sid)
    $rights = 0
    foreach ($rule in (Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -eq $Sid -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) {
            $rights = $rights -bor [int]$rule.FileSystemRights
        }
    }
    return $rights
}
function Invoke-TestCoreRequest {
    param([string]$Path, [string]$Method = 'GET', [string]$Body, [string]$Bearer)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), [Uri]::new([Uri]$script:coreUrl, $Path))
    $response = $null
    $stream = $null
    $memory = [IO.MemoryStream]::new()
    $timeout = [Threading.CancellationTokenSource]::new(10000)
    try {
        if (-not [string]::IsNullOrEmpty($Bearer)) { $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Bearer) }
        if ($Method -eq 'POST') { $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json') }
        $response = $script:client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $timeout.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw 'Core rejected an acceptance request.' }
        if ($response.Content.Headers.ContentLength -gt 16384) { throw 'Core acceptance response exceeded the bound.' }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = [byte[]]::new(4096)
        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $timeout.Token).GetAwaiter().GetResult()) -gt 0) {
            if ($memory.Length + $count -gt 16384) { throw 'Core acceptance response exceeded the bound.' }
            $memory.Write($buffer, 0, $count)
        }
        return [Text.Encoding]::UTF8.GetString($memory.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $memory.Dispose(); $timeout.Dispose(); $request.Dispose()
    }
}
function Assert-CoreListenerOwner {
    param([int]$ExpectedProcessId)
    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $script:port -State Listen -ErrorAction SilentlyContinue)
    Assert-CoreServiceAcceptance ($ExpectedProcessId -gt 0 -and $listeners.Count -eq 1 -and $listeners[0].OwningProcess -eq $ExpectedProcessId) 'The health origin is not exclusively owned by the exact Core process.'
}
function Assert-PersistedCoreState {
    param([int]$ExpectedProcessId = 0)
    $loginBody = $null
    $session = $null
    $token = $null
    try {
        if ($ExpectedProcessId -eq 0) { $ExpectedProcessId = [int](Get-TestCoreService).ProcessId }
        Assert-CoreListenerOwner $ExpectedProcessId
        $health = Invoke-TestCoreRequest '/api/health' | ConvertFrom-Json
        Assert-CoreServiceAcceptance ($health.status -eq 'healthy') 'Core is not healthy.'
        Assert-CoreListenerOwner $ExpectedProcessId
        $loginBody = @{ username = $script:credential.UserName; password = $script:credential.GetNetworkCredential().Password } | ConvertTo-Json -Compress
        $session = Invoke-TestCoreRequest '/api/auth/login' 'POST' $loginBody | ConvertFrom-Json
        $token = [string]$session.accessToken
        Assert-CoreServiceAcceptance (-not [string]::IsNullOrWhiteSpace($token)) 'The original administrator could not authenticate after a host transition.'
        $script:sensitiveValues.Add($token)
        $administrator = Invoke-TestCoreRequest '/api/admin/me' 'GET' $null $token | ConvertFrom-Json
        Assert-CoreServiceAcceptance ($administrator.username -ceq $script:credential.UserName -and $administrator.role -eq 'administrator') 'The persisted administrator identity changed.'
        $fingerprint = [SentinelAI.CoreService.Acceptance.Native]::ReadStateFingerprint($script:nativeSqlitePath, $script:databasePath)
        if ($null -eq $script:stateFingerprint) { $script:stateFingerprint = $fingerprint }
        Assert-CoreServiceAcceptance ($fingerprint -ceq $script:stateFingerprint) 'The administrator password hash or persistent Core/organization identity changed.'
    } finally { $loginBody = $null; $session = $null; $token = $null }
}
function Get-OwnedCoreProcess {
    $service = Get-TestCoreService
    Assert-CoreServiceAcceptance ($null -ne $service -and $service.State -eq 'Running' -and $service.ProcessId -gt 0) 'The actual Core service is not running.'
    Assert-CoreServiceAcceptance ($service.PathName -ceq $script:expectedImagePath -and $service.StartName -ieq 'NT SERVICE\SentinelAICore') 'The service image/account no longer matches this acceptance installation.'
    $process = [Diagnostics.Process]::GetProcessById([int]$service.ProcessId)
    try {
        $null = $process.Handle
        Assert-CoreServiceAcceptance ([IO.Path]::GetFullPath($process.MainModule.FileName) -ieq $script:coreExecutable) 'The SCM process is not the exact installed Core executable.'
        $metadata = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId=' + $process.Id)
        Assert-CoreServiceAcceptance ($null -ne $metadata -and -not [string]::IsNullOrWhiteSpace([string]$metadata.CommandLine)) 'The exact Core service command line could not be inspected.'
        Assert-NoTestSecrets ([string]$metadata.CommandLine)
        return $process
    } catch { $process.Dispose(); throw }
}

$installOptions = @{
    BundleDirectory = $BundleDirectory; PublicKeyPath = $PublicKeyPath; KeyId = $KeyId
    Environment = $Environment; Channel = $Channel; CoreUrl = $coreUrl; TimeoutSeconds = $TimeoutSeconds
}
try {
    Invoke-PilotInstall -Component Core -CodeDirectory $coreCode -DataDirectory $coreData @installOptions | Out-Null
    Assert-CoreServiceAcceptance (Test-Path -LiteralPath $nativeSqlitePath -PathType Leaf) 'The Windows System32 SQLite library is unavailable.'
    $configDigest = (Get-FileHash -LiteralPath $configurationPath -Algorithm SHA256).Hash
    $receiptDigest = (Get-FileHash -LiteralPath $pilotReceiptPath -Algorithm SHA256).Hash
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(10)

    $console = & (Join-Path $installerDirectory 'Start-SentinelAICore.ps1') -CodeDirectory $coreCode -DataDirectory $coreData -AdminCredential $credential -TimeoutSeconds ([Math]::Min(180, $TimeoutSeconds))
    $consoleProcess = [Diagnostics.Process]::GetProcessById($console.ProcessId)
    $null = $consoleProcess.Handle
    Assert-CoreServiceAcceptance ([IO.Path]::GetFullPath($consoleProcess.MainModule.FileName) -ieq $coreExecutable) 'The bootstrap child is not the installed Core executable.'
    Assert-PersistedCoreState -ExpectedProcessId $consoleProcess.Id
    # The console bootstrap is our exact retained child; no other listener or PID
    # is adopted. Service start exercises SQLite recovery after this termination.
    $consoleProcess.Kill()
    Assert-CoreServiceAcceptance ($consoleProcess.WaitForExit(10000)) 'The bootstrap console child did not exit.'
    $consoleProcess.Dispose(); $consoleProcess = $null

    & $managementScript -Action Install -CodeDirectory $coreCode -DataDirectory $coreData -BundleDirectory $BundleDirectory -PublicKeyPath $PublicKeyPath -KeyId $KeyId -Environment $Environment -Channel $Channel -TimeoutSeconds $TimeoutSeconds | Out-Null
    $serviceInstalled = $true
    Invoke-TestServiceAction Start
    $serviceProcess = Get-OwnedCoreProcess
    Assert-PersistedCoreState
    $service = Get-TestCoreService
    Assert-CoreServiceAcceptance ($service.StartMode -eq 'Auto') 'Core is not configured for automatic service startup.'
    [SentinelAI.CoreService.Acceptance.Native]::AssertRecoveryPolicy()
    $assertionCount++
    Assert-NoTestSecrets ([string]$service.PathName)
    Assert-CoreServiceAcceptance (-not $service.PathName.Contains($credential.UserName) -and -not $service.PathName.Contains('SENTINELAI_BOOTSTRAP_')) 'The SCM command line contains administrator/bootstrap settings.'

    $serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE\SentinelAICore')).Translate([Security.Principal.SecurityIdentifier]).Value
    $readExecute = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    $writeOrControl = [int]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    $codeRights = Get-ServiceAllowRights $coreCode $serviceSid
    Assert-CoreServiceAcceptance (($codeRights -band $readExecute) -eq $readExecute -and ($codeRights -band $writeOrControl) -eq 0) 'The virtual service account must have code read/execute without mutation rights.'
    $dataRights = Get-ServiceAllowRights $coreData $serviceSid
    Assert-CoreServiceAcceptance (($dataRights -band $readExecute) -eq $readExecute -and ($dataRights -band [int][Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0) 'The virtual account cannot read/create required SQLite state.'
    $parentControl = [int]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    Assert-CoreServiceAcceptance (($dataRights -band $parentControl) -eq 0) 'The virtual account can delete/change protected configuration through its parent.'
    $databaseRights = Get-ServiceAllowRights $databasePath $serviceSid
    Assert-CoreServiceAcceptance (($databaseRights -band [int][Security.AccessControl.FileSystemRights]::Modify) -eq [int][Security.AccessControl.FileSystemRights]::Modify) 'The virtual account cannot maintain the SQLite database.'
    foreach ($path in @($configurationPath, $pilotReceiptPath, $serviceReceiptPath)) {
        $rights = Get-ServiceAllowRights $path $serviceSid
        Assert-CoreServiceAcceptance (($rights -band [int][Security.AccessControl.FileSystemRights]::Read) -eq [int][Security.AccessControl.FileSystemRights]::Read -and ($rights -band $writeOrControl) -eq 0) 'A configuration/ownership file is not service-readable and protected against service mutation.'
        Assert-NoTestSecrets ([IO.File]::ReadAllText($path))
    }
    Assert-CoreServiceAcceptance ((Get-FileHash -LiteralPath $configurationPath -Algorithm SHA256).Hash -ceq $configDigest) 'Service installation modified the existing pilot configuration.'
    Assert-CoreServiceAcceptance ((Get-FileHash -LiteralPath $pilotReceiptPath -Algorithm SHA256).Hash -ceq $receiptDigest) 'Service installation modified the existing signed pilot receipt.'

    Invoke-TestServiceAction Stop
    Assert-CoreServiceAcceptance ((Get-TestCoreService).State -eq 'Stopped') 'SCM did not report a stopped Core after graceful stop.'
    Assert-CoreServiceAcceptance ($serviceProcess.WaitForExit(10000) -and $serviceProcess.ExitCode -eq 0) 'Graceful Core service stop did not exit successfully.'
    $serviceProcess.Dispose(); $serviceProcess = $null
    Invoke-TestServiceAction Start
    $serviceProcess = Get-OwnedCoreProcess
    Assert-PersistedCoreState
    Invoke-TestServiceAction Restart
    Assert-CoreServiceAcceptance ($serviceProcess.WaitForExit(10000) -and $serviceProcess.ExitCode -eq 0) 'Service restart did not gracefully stop the previous Core process.'
    $serviceProcess.Dispose(); $serviceProcess = Get-OwnedCoreProcess
    Assert-PersistedCoreState

    $desktopResult = & (Join-Path $repositoryRoot 'tests/desktop/Windows.Acceptance.ps1') -ExecutablePath $DesktopExecutablePath -TimeoutSeconds ([Math]::Min(60, $TimeoutSeconds))
    Assert-CoreServiceAcceptance ($desktopResult.Result -eq 'Passed') 'The native desktop did not open/navigate/close successfully.'
    Assert-CoreServiceAcceptance (-not $serviceProcess.HasExited -and (Get-TestCoreService).ProcessId -eq $serviceProcess.Id) 'Closing the native desktop stopped or restarted Core.'
    Assert-PersistedCoreState

    # Force only the held, validated service process to terminate, then observe
    # a new SCM-owned process without issuing Start ourselves.
    $previousStart = $serviceProcess.StartTime
    $serviceProcess.Kill()
    Assert-CoreServiceAcceptance ($serviceProcess.WaitForExit(10000)) 'The simulated Core failure did not terminate its exact process.'
    $serviceProcess.Dispose(); $serviceProcess = $null
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $candidate = Get-TestCoreService
        if ($null -ne $candidate -and $candidate.State -eq 'Running' -and $candidate.ProcessId -gt 0) {
            try {
                $serviceProcess = Get-OwnedCoreProcess
                if ($serviceProcess.StartTime -gt $previousStart) { break }
                $serviceProcess.Dispose(); $serviceProcess = $null
            } catch { $serviceProcess = $null }
        }
        Start-Sleep -Milliseconds 250
    }
    Assert-CoreServiceAcceptance ($null -ne $serviceProcess) 'SCM did not automatically recover Core after the simulated failure.'
    # SCM Running can precede HTTP binding during automatic recovery.
    $deadline.Restart()
    $healthy = $false
    while ($deadline.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try { $healthy = (Invoke-TestCoreRequest '/api/health' | ConvertFrom-Json).status -eq 'healthy' } catch { $healthy = $false }
        if ($healthy) { break }
        Start-Sleep -Milliseconds 250
    }
    Assert-CoreServiceAcceptance $healthy 'The automatically recovered Core did not become healthy.'
    Assert-PersistedCoreState

    # Core retains its sanitized console JSON logging policy. SCM event fields
    # are inspected in memory only; no event messages or test secrets are emitted.
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $startedUtc } -MaxEvents 256 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw 'SCM diagnostic messages could not be inspected.' }
    }
    foreach ($event in $events) {
        Assert-NoTestSecrets ([string]$event.Message)
        foreach ($property in $event.Properties) { Assert-NoTestSecrets ([string]$property.Value) }
    }
    Invoke-TestServiceAction Uninstall
    $serviceInstalled = $false
    Assert-CoreServiceAcceptance ($null -eq (Get-TestCoreService)) 'Service-only uninstall left SentinelAICore registered.'
    Assert-CoreServiceAcceptance ($serviceProcess.WaitForExit(10000) -and $serviceProcess.ExitCode -eq 0) 'Service uninstall did not stop Core gracefully.'
    Assert-CoreServiceAcceptance ([SentinelAI.CoreService.Acceptance.Native]::ReadStateFingerprint($nativeSqlitePath, $databasePath) -ceq $stateFingerprint) 'Service uninstall changed administrator/Core identity state.'
    Assert-CoreServiceAcceptance (Test-Path -LiteralPath $databasePath -PathType Leaf) 'Service uninstall removed persistent SQLite state.'
    [PSCustomObject]@{ Result = 'Passed'; Assertions = $assertionCount; TestArtifactsDirectory = $WorkDirectory; ServiceAccount = 'NT SERVICE\SentinelAICore' }
} finally {
    try {
        if ($serviceInstalled) { Invoke-TestServiceAction Uninstall }
    } finally {
        if ($null -ne $serviceProcess) { $serviceProcess.Dispose() }
        if ($null -ne $consoleProcess) {
            try { if (-not $consoleProcess.HasExited) { $consoleProcess.Kill(); [void]$consoleProcess.WaitForExit(10000) } }
            finally { $consoleProcess.Dispose() }
        }
        if ($null -ne $client) { $client.Dispose() }
        $sensitiveValues.Clear()
        $credential = $null
        $securePassword.Dispose()
    }
    # Preserve the newly created protected code/configuration/state directory.
}
