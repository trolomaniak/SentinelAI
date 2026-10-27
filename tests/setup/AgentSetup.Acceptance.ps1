# MVP-2: the actual SentinelAI-Agent-Setup.exe, silent, on the same fresh Windows runner as a central SentinelAI
# installation. Codes come from Core's administrator API; the Agent enrolls over this runner's own non-loopback
# address. Synthetic data only: the codes are issued for this run and never printed.
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExecutablePath,
    [Parameter(Mandatory = $true)][string]$AgentExecutablePath,
    [ValidateRange(60, 900)][int]$TimeoutSeconds = 300,
    [string]$PilotLicenseKeyPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$AgentExecutablePath = (Resolve-Path -LiteralPath $AgentExecutablePath).ProviderPath
if (-not (Test-Path -LiteralPath $AgentExecutablePath -PathType Leaf) -or [IO.Path]::GetFileName($AgentExecutablePath) -cne 'SentinelAI-Agent-Setup.exe') {
    throw 'Agent Setup acceptance requires the actual published SentinelAI-Agent-Setup.exe.'
}
$context = $null
. (Join-Path $PSScriptRoot 'Windows.Acceptance.ps1') -ExecutablePath $ExecutablePath -TimeoutSeconds $TimeoutSeconds `
    -PreserveInstallation -InstallationContext ([ref]$context) -PilotLicenseKeyPath $PilotLicenseKeyPath
if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.Password)) { throw 'Fresh native acceptance did not provide its private synthetic context.' }
$username = $context.Username; $password = $context.Password
$context = $null; $coreProcess = $null; $agentProcess = $null; $client = $null; $accessToken = $null
$agentSetupPassed = $false
$codeDirectory = Join-Path ([IO.Path]::GetTempPath()) ('sentinelai-agent-setup-codes-' + [Guid]::NewGuid().ToString('N'))
$agentProductCode = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelAI Agent'
$agentProductData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SentinelAI Agent'
$agentProductExecutable = Join-Path $agentProductCode 'Agent\SentinelAI.Agent.exe'
$agentProductConfiguration = Join-Path $agentProductData 'Agent\pilot-config.json'
$installedAgentSetup = Join-Path $agentProductCode 'Setup\SentinelAI-Agent-Setup.exe'
$appsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAIAgent'
$fullAppsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAI'

if ($null -eq ('SentinelAI.Setup.Acceptance.AgentCodes' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace SentinelAI.Setup.Acceptance {
 // Rewrites a synthetic code issued for this run in the documented v1 format, with a valid checksum.
 public static class AgentCodes {
  const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  public static string Rewrite(string text, int port, bool otherPin) {
   string compact = text.Replace("-", "").ToUpperInvariant();
   if (!compact.StartsWith("SAI1")) throw new ArgumentException("Not an enrollment code.");
   byte[] bytes = Decode(compact.Substring(4));
   if (port > 0) { bytes[1] = (byte)(port >> 8); bytes[2] = (byte)port; }
   if (otherPin) bytes[3] ^= 0x5A;
   int length = bytes.Length - 4;
   byte[] input = new byte[4 + length];
   Encoding.ASCII.GetBytes("SAIE").CopyTo(input, 0);
   Array.Copy(bytes, 0, input, 4, length);
   using (SHA256 sha = SHA256.Create()) Array.Copy(sha.ComputeHash(input), 0, bytes, length, 4);
   string encoded = Encode(bytes);
   StringBuilder result = new StringBuilder("SAI1");
   for (int index = 0; index < encoded.Length; index += 5) result.Append('-').Append(encoded.Substring(index, Math.Min(5, encoded.Length - index)));
   return result.ToString();
  }
  static byte[] Decode(string text) {
   var output = new System.Collections.Generic.List<byte>();
   int buffer = 0, bits = 0;
   foreach (char character in text) {
    int value = Alphabet.IndexOf(character);
    if (value < 0) throw new ArgumentException("Not an enrollment code.");
    buffer = (buffer << 5) | value; bits += 5;
    if (bits >= 8) { output.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
    buffer &= (1 << bits) - 1;
   }
   return output.ToArray();
  }
  static string Encode(byte[] bytes) {
   StringBuilder text = new StringBuilder();
   int buffer = 0, bits = 0;
   foreach (byte value in bytes) {
    buffer = ((buffer << 8) | value) & 0xFFFF; bits += 8;
    while (bits >= 5) { text.Append(Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
   }
   if (bits > 0) text.Append(Alphabet[(buffer << (5 - bits)) & 31]);
   return text.ToString();
  }
 }
 // Test-only: moves one synthetic code's expiry into the past in Core's own database, as the Core tests do.
 public static class CoreDatabase {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string name);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Open(IntPtr name, out IntPtr database, int flags, IntPtr vfs);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Close(IntPtr database);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Busy(IntPtr database, int milliseconds);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet=CharSet.Ansi)] delegate int Exec(IntPtr database, string sql, IntPtr callback, IntPtr argument, IntPtr error);
  [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Changes(IntPtr database);
  static T Function<T>(IntPtr module, string name) where T : class {
   IntPtr address = GetProcAddress(module, name);
   if (address == IntPtr.Zero) throw new InvalidOperationException("Native SQLite is unavailable.");
   return (T)(object)Marshal.GetDelegateForFunctionPointer(address, typeof(T));
  }
  public static int Expire(string library, string path, string tokenId) {
   Guid id = Guid.ParseExact(tokenId, "D");
   IntPtr module = LoadLibraryEx(library, IntPtr.Zero, 0x800);
   if (module == IntPtr.Zero) throw new InvalidOperationException("Native SQLite is unavailable.");
   byte[] utf8 = Encoding.UTF8.GetBytes(path + "\0");
   IntPtr name = Marshal.AllocHGlobal(utf8.Length);
   IntPtr database = IntPtr.Zero;
   try {
    Marshal.Copy(utf8, 0, name, utf8.Length);
    if (Function<Open>(module, "sqlite3_open_v2")(name, out database, 2, IntPtr.Zero) != 0) throw new InvalidOperationException("Core database unavailable.");
    Function<Busy>(module, "sqlite3_busy_timeout")(database, 10000);
    long past = DateTime.UtcNow.AddMinutes(-1).Ticks;
    string sql = "UPDATE EnrollmentTokens SET ExpiresUtcTicks = " + past + " WHERE TokenId = '" + id.ToString("D") + "' AND ConsumedUtcTicks IS NULL;";
    if (Function<Exec>(module, "sqlite3_exec")(database, sql, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) != 0) throw new InvalidOperationException("Synthetic expiry failed.");
    return Function<Changes>(module, "sqlite3_changes")(database);
   } finally {
    if (database != IntPtr.Zero) Function<Close>(module, "sqlite3_close")(database);
    Marshal.FreeHGlobal(name);
    FreeLibrary(module);
   }
  }
 }
}
'@ | Out-Null
}

function Open-AgentSetupCore {
    $script:coreProcess = Get-HeldInstalledProcess 'SentinelAICore' (Join-Path $script:coreCode 'SentinelAI.Core.exe') 'NT SERVICE\SentinelAICore'
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false; $handler.UseDefaultCredentials = $false
    $script:client = [Net.Http.HttpClient]::new($handler); $script:client.Timeout = [TimeSpan]::FromSeconds(10)
    $body = @{ username = $script:username; password = $script:password } | ConvertTo-Json -Compress
    try { $session = Invoke-SetupCoreRequest '/api/auth/login' 'POST' $body | ConvertFrom-Json } finally { $body = $null }
    $script:accessToken = [string]$session.accessToken; $session = $null
    Assert-SetupAcceptance (-not [string]::IsNullOrWhiteSpace($script:accessToken)) 'The central administrator could not sign in for Agent Setup acceptance.'
}

function Get-UnusedCodeIds {
    return @((Invoke-SetupCoreRequest '/api/admin/enrollment-codes' 'GET' $null $script:accessToken | ConvertFrom-Json).codes | ForEach-Object { [string]$_.id })
}

function Write-AgentSetupCode([string]$Name, [string]$Code) {
    $path = Join-Path $script:codeDirectory ($Name + '.sentinelai-enroll')
    [IO.File]::WriteAllText($path, $Code + "`r`n", (New-Object Text.UTF8Encoding($false)))
    return $path
}

function Invoke-AgentSetup([string[]]$Arguments, [string]$Executable = $script:AgentExecutablePath) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.Arguments = (@($Arguments | ForEach-Object { if ($_.Contains(' ')) { '"' + $_ + '"' } else { $_ } }) -join ' ')
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($script:TimeoutSeconds * 1000)) { $process.Kill(); throw 'Agent Setup did not finish in time.' }
        # Options and the code file's name only: never the code.
        $shown = @($Arguments | ForEach-Object { if ($_.StartsWith('/')) { $_ } else { [IO.Path]::GetFileName($_) } }) -join ' '
        Write-Host ('AgentSetup: ' + [IO.Path]::GetFileName($Executable) + ' ' + $shown + ' -> exit ' + $process.ExitCode)
        return $process.ExitCode
    } finally { $process.Dispose() }
}

function Assert-AgentSetupAbsent([string]$Label, [int]$Devices = -1) {
    Assert-SetupAcceptance ($null -eq (Get-SetupService 'SentinelAIAgent')) ($Label + ': an Agent service exists.')
    Assert-SetupSecurityLogAccess $false $Label
    foreach ($path in @($script:agentProductCode, $script:agentProductData, $script:appsKey)) {
        Assert-SetupAcceptance (-not (Test-Path -LiteralPath $path)) ($Label + ': Agent Setup left ' + $path)
    }
    if ($Devices -ge 0) { Assert-SetupAcceptance ((Get-SetupDeviceCount) -eq $Devices) ($Label + ': Core gained an endpoint.') }
}

function Assert-AgentSetupInstalled([string]$Address, [string]$Pin, [DateTimeOffset]$Since) {
    $service = Get-SetupService 'SentinelAIAgent'
    $expectedImage = '"' + $script:agentProductExecutable + '" --config "' + $script:agentProductConfiguration + '"'
    Assert-SetupAcceptance ($null -ne $service -and $service.State -ceq 'Running' -and $service.PathName -ceq $expectedImage -and
        $service.StartName -ieq 'NT AUTHORITY\LocalService' -and $service.StartMode -ceq 'Auto') 'Agent Setup did not install the automatic LocalService Agent.'
    $configuration = [IO.File]::ReadAllText($script:agentProductConfiguration) | ConvertFrom-Json
    Assert-SetupAcceptance ([string]$configuration.Agent.CoreUrl -ceq ('https://' + $Address + ':' + $script:localNetworkPort) -and
        [string]$configuration.Agent.CoreCertificateSha256 -ceq $Pin) 'The Agent is not configured with the code''s Core address and pin.'
    Assert-SetupAcceptance (-not (Test-Path -LiteralPath (Join-Path $script:agentProductData 'Agent\pilot-enrollment-token'))) 'The one-use handoff file remained.'
    $apps = Get-ItemProperty -LiteralPath $script:appsKey
    Assert-SetupAcceptance ([string]$apps.DisplayName -ceq 'SentinelAI Agent' -and [string]$apps.UninstallString -ceq ('"' + $script:installedAgentSetup + '" /uninstall') -and
        [string]$apps.QuietUninstallString -ceq ('"' + $script:installedAgentSetup + '" /uninstall /quiet') -and
        (Test-Path -LiteralPath $script:installedAgentSetup -PathType Leaf)) 'Agent Setup did not register a working Windows Apps entry.'
    Assert-ProtectedTree $script:agentProductCode $script:writers
    Assert-ProtectedTree $script:agentProductData ($script:writers + @($script:localServiceSid))
    # No entry names the installing account, so any administrator or SYSTEM can later verify and uninstall the Agent.
    foreach ($root in @($script:agentProductCode, $script:agentProductData)) {
        foreach ($item in @((Get-Item -LiteralPath $root -Force)) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)) {
            # The running Agent replaces files through temporaries that can vanish before inspection.
            try { $acl = Get-Acl -LiteralPath $item.FullName } catch { if (Test-Path -LiteralPath $item.FullName) { throw }; continue }
            Assert-SetupAcceptance (@($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -ceq $script:operatorSid }).Count -eq 0) 'Agent Setup granted the installing account its own access entry.'
        }
    }
    Assert-SetupSecurityLogAccess $true 'Agent Setup'
    $endpointId = [Guid]::ParseExact([IO.File]::ReadAllText((Join-Path $script:agentProductData 'Agent\endpoint-id')).Trim(), 'D')
    Wait-ExactEndpoint $endpointId $Since
    Wait-SetupAcceptance { $null -ne (Get-AgentTelemetry $endpointId) } 'The Agent installed by Agent Setup did not report endpoint telemetry.' $script:TimeoutSeconds
    return $endpointId
}

try {
    New-Item -ItemType Directory -Path $codeDirectory | Out-Null
    Open-AgentSetupCore
    $pin = Get-SetupLocalNetworkPin
    $options = Invoke-SetupCoreRequest '/api/admin/enrollment-options' 'GET' $null $accessToken | ConvertFrom-Json
    $ipv4 = @($options.addresses | Where-Object { [string]$_.kind -ceq 'ipv4' } | ForEach-Object { [string]$_.value })
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
    Assert-SetupAcceptance ($options.available -eq $true -and $options.listening -eq $true -and [int]$options.port -eq $localNetworkPort -and
        $ipv4.Count -gt 0 -and $ipv4[0] -cne '127.0.0.1' -and $local -ccontains $ipv4[0]) 'Core did not offer this runner''s non-loopback address for enrollment codes.'
    $address = $ipv4[0]
    $request = @{ count = 5; validityHours = 1; address = $address } | ConvertTo-Json -Compress
    $issued = @((Invoke-SetupCoreRequest '/api/admin/enrollment-codes' 'POST' $request $accessToken | ConvertFrom-Json).codes)
    Assert-SetupAcceptance ($issued.Count -eq 5) 'Core did not issue the requested batch of enrollment codes.'
    $first = $issued[0]; $revoked = $issued[1]; $expired = $issued[2]; $second = $issued[3]; $third = $issued[4]

    # One Agent service per computer: this test-only step removes the central installation's own Agent service,
    # so Agent Setup can install the Agent product beside Core on this single runner.
    $installer = Join-Path $repositoryRoot 'installer/pilot'
    Import-Module (Join-Path $installer 'PilotInstaller.psm1') -Force -DisableNameChecking
    Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -TimeoutSeconds 60 | Out-Null
    $devices = Get-SetupDeviceCount
    Assert-AgentSetupAbsent 'Before Agent Setup' $devices

    # Invalid options and an invalid code change nothing.
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet')) -eq 2 -and (Invoke-AgentSetup @('/quiet', '/codefile')) -eq 2 -and
        (Invoke-AgentSetup @('/quiet', '/repair')) -eq 2) 'Agent Setup accepted options outside its allow-list.'
    $garbage = Write-AgentSetupCode 'garbage' 'SAI1-NOT-A-CODE'
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $garbage)) -eq 3) 'Agent Setup accepted an invalid code file.'
    Assert-AgentSetupAbsent 'Invalid code' $devices

    # A wrong pin and an unreachable Core: refused before anything changes; the token is never sent.
    $wrongPin = Write-AgentSetupCode 'wrong-pin' ([SentinelAI.Setup.Acceptance.AgentCodes]::Rewrite([string]$first.code, 0, $true))
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $wrongPin)) -eq 5) 'Agent Setup did not refuse a code whose pin is not Core''s certificate.'
    Assert-AgentSetupAbsent 'Wrong pin' $devices
    $unreachable = Write-AgentSetupCode 'unreachable' ([SentinelAI.Setup.Acceptance.AgentCodes]::Rewrite([string]$first.code, 9, $false))
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $unreachable)) -eq 4) 'Agent Setup did not report an unreachable Core.'
    Assert-AgentSetupAbsent 'Unreachable Core' $devices
    Assert-SetupAcceptance ((Get-UnusedCodeIds) -ccontains [string]$first.id) 'A refused pin or unreachable Core consumed the code.'

    # Revoked and expired codes: Core refuses them during the pre-check.
    [void](Invoke-SetupCoreRequest ('/api/admin/enrollment-codes/' + [string]$revoked.id) 'DELETE' $null $accessToken)
    $path = Write-AgentSetupCode 'revoked' ([string]$revoked.code)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $path)) -eq 6) 'Agent Setup did not refuse a revoked code.'
    Assert-AgentSetupAbsent 'Revoked code' $devices
    $nativeSqlite = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\winsqlite3.dll'
    Assert-SetupAcceptance ([SentinelAI.Setup.Acceptance.CoreDatabase]::Expire($nativeSqlite, (Join-Path $coreData 'sentinelai.db'), [string]$expired.id) -eq 1) 'The synthetic expiry could not be applied.'
    $path = Write-AgentSetupCode 'expired' ([string]$expired.code)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $path)) -eq 6) 'Agent Setup did not refuse an expired code.'
    Assert-AgentSetupAbsent 'Expired code' $devices

    # The code enrolls over the non-loopback address; success is reported only after Core acknowledged it.
    $since = [DateTimeOffset]::UtcNow
    $firstPath = Write-AgentSetupCode 'first' ([string]$first.code)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $firstPath)) -eq 0) 'Silent Agent Setup did not install and enroll the Agent.'
    $endpointId = Assert-AgentSetupInstalled $address $pin $since
    Assert-SetupAcceptance ((Get-SetupDeviceCount) -eq $devices + 1 -and -not ((Get-UnusedCodeIds) -ccontains [string]$first.id)) 'The enrolled code was not consumed exactly once.'
    Write-Output ('Agent Setup enrolled endpoint ' + $endpointId.ToString('D') + ' through ' + $address + ':' + $localNetworkPort)
    $held = (Get-SetupService 'SentinelAIAgent').ProcessId
    $secondPath = Write-AgentSetupCode 'second' ([string]$second.code)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $secondPath)) -eq 7 -and (Get-SetupService 'SentinelAIAgent').ProcessId -eq $held -and
        (Get-UnusedCodeIds) -ccontains [string]$second.id) 'A second Agent Setup changed the installed Agent or consumed its code.'

    # Uninstall with the downloaded Setup removes the service, code, credential and data, and the Apps entry.
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/uninstall', '/quiet')) -eq 0) 'Silent Agent uninstall failed.'
    Assert-AgentSetupAbsent 'Uninstall'
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/uninstall', '/quiet')) -eq 11) 'Agent uninstall did not report that nothing was installed.'
    # The used code: refused by Core before anything changes.
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $firstPath)) -eq 6) 'Agent Setup did not refuse a used code.'
    Assert-AgentSetupAbsent 'Used code'

    # Windows Apps: the registered quiet uninstall runs the installed Setup copy. Still running, that copy moves out of
    # the product folder into Setup's protected folder, where Windows deletes it at restart; everything else goes now.
    $since = [DateTimeOffset]::UtcNow
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $secondPath)) -eq 0) 'Agent Setup did not reinstall with a new code.'
    [void](Assert-AgentSetupInstalled $address $pin $since)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/uninstall', '/quiet') $installedAgentSetup) -eq 0) 'The Windows Apps quiet uninstall failed.'
    Assert-AgentSetupAbsent 'Windows Apps uninstall'
    $pending = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    $setupFolder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SentinelAI-Setup'
    Assert-SetupAcceptance (@($pending | Where-Object { [string]$_ -like ('*' + $setupFolder + '\removed-*.exe') }).Count -ge 1 -and
        @($pending | Where-Object { [string]$_ -like ('*' + $agentProductCode + '*') }).Count -eq 0) 'The running installed Setup was not moved out for removal at restart.'
    # No restart is needed before installing again.
    $since = [DateTimeOffset]::UtcNow
    $thirdPath = Write-AgentSetupCode 'third' ([string]$third.code)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/quiet', '/codefile', $thirdPath)) -eq 0) 'Agent Setup did not install again right after the Windows Apps uninstall.'
    [void](Assert-AgentSetupInstalled $address $pin $since)
    Assert-SetupAcceptance ((Invoke-AgentSetup @('/uninstall', '/quiet')) -eq 0) 'The final silent Agent uninstall failed.'
    Assert-AgentSetupAbsent 'Final uninstall'

    # The full Setup registered its own Windows Apps entry that opens the existing uninstall flow.
    $full = Get-ItemProperty -LiteralPath $fullAppsKey
    $fullSetup = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelAI Setup\SentinelAI-Setup.exe'
    Assert-SetupAcceptance ([string]$full.DisplayName -ceq 'SentinelAI' -and [string]$full.UninstallString -ceq ('"' + $fullSetup + '" /uninstall') -and
        (Test-Path -LiteralPath $fullSetup -PathType Leaf) -and $null -eq $full.PSObject.Properties['QuietUninstallString']) 'The full Setup did not register its Windows Apps entry.'
    $agentSetupPassed = $true
    [pscustomobject]@{ Result = 'Passed'; Assertions = $assertionCount
        AgentSetup = 'Silent install over the non-loopback address with telemetry; invalid options, invalid code, wrong pin, unreachable Core, revoked, expired and used codes refused without changes; second install refused; uninstall from the download and from Windows Apps' }
} finally {
    if (Test-Path -LiteralPath $codeDirectory) { Remove-Item -LiteralPath $codeDirectory -Recurse -Force }
    try {
        if ($null -ne (Get-SetupService 'SentinelAIAgent') -and (Test-Path -LiteralPath $agentProductData)) { [void](Invoke-AgentSetup @('/uninstall', '/quiet')) }
        if ($null -ne (Get-SetupService 'SentinelAIAgent')) {
            Invoke-PilotInstall -Component UninstallAgent -CodeDirectory $agentCode -DataDirectory $agentData -TimeoutSeconds 60 | Out-Null
        }
        if ($null -ne (Get-SetupService 'SentinelAICore')) {
            & (Join-Path $repositoryRoot 'tests/core-service/Manage-SentinelAICoreService.ps1') -Action Uninstall -CodeDirectory $coreCode -DataDirectory $coreData -TimeoutSeconds 60 | Out-Null
        }
    } catch {
        if ($agentSetupPassed) { throw }
        Write-Host 'AgentSetupCleanup: Failed=True; the original acceptance failure is reported instead.'
    }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $coreProcess) { $coreProcess.Dispose() }
    $password = $null; $accessToken = $null
}
