using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using SentinelAI.Contracts.EndpointTelemetry;

namespace SentinelAI.Agent;

/// <summary>
/// Reads the fixed telemetry sources through documented Windows interfaces: WMI (BitLocker, Defender) and the
/// Windows Update Agent through late-bound automation, Windows Security Center and the local group API through
/// P/Invoke, and the registry and Service Control Manager. Nothing is written, no process is started, and only the
/// values named here are read. Each method may throw; the collector classifies the failure.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEndpointTelemetrySource : IEndpointTelemetrySource
{
    internal const string BitLockerNamespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";
    internal const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    internal const string UpdatePolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    internal const string ComponentServicingRebootKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
    internal const string WindowsUpdateRebootKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
    internal const string SessionManagerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    internal const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    internal const string AdministratorsSid = "S-1-5-32-544";
    private const int MaximumUninstallKeysPerView = 8192;
    private const int WscSecurityProviderAntivirus = 0x4;
    private const int ErrorAccessDenied = 5;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int MaximumPreferredLength = -1;

    public BitLockerTelemetry ReadBitLocker()
    {
        // Win32_EncryptableVolume requires packet privacy; only the protection and conversion status are read.
        var rows = WmiQuery.Run(BitLockerNamespace,
            $"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '{OperatingSystemDrive()}'",
            ["ProtectionStatus", "ConversionStatus"], maximumRows: 1, packetPrivacy: true);
        return rows.Count == 0
            ? new BitLockerTelemetry(TelemetryAvailability.Unsupported)
            : new BitLockerTelemetry(TelemetryAvailability.Collected,
                EndpointTelemetryNormalizer.BitLockerProtection(rows[0]["ProtectionStatus"]),
                EndpointTelemetryNormalizer.BitLockerConversion(rows[0]["ConversionStatus"]));
    }

    public AntivirusTelemetry ReadAntivirus()
    {
        // Windows Security Center exists on client editions only; a server has no aggregate antivirus health.
        if (ReadService("wscsvc").State == ServiceRunStates.NotInstalled)
        {
            return new AntivirusTelemetry(TelemetryAvailability.Unsupported);
        }

        var result = WscGetSecurityProviderHealth(WscSecurityProviderAntivirus, out var health);
        return result switch
        {
            0 => new AntivirusTelemetry(TelemetryAvailability.Collected, EndpointTelemetryNormalizer.SecurityCenterHealth(health)),
            unchecked((int)0x80070005) => new AntivirusTelemetry(TelemetryAvailability.AccessDenied),
            _ => new AntivirusTelemetry(TelemetryAvailability.Unavailable)
        };
    }

    public DefenderTelemetry ReadDefender()
    {
        var rows = WmiQuery.Run(DefenderNamespace, "SELECT * FROM MSFT_MpComputerStatus",
            ["AMRunningMode", "AntivirusEnabled", "RealTimeProtectionEnabled", "IsTamperProtected", "AntivirusSignatureAge"],
            maximumRows: 1, packetPrivacy: false);
        if (rows.Count == 0)
        {
            return new DefenderTelemetry(TelemetryAvailability.Unavailable);
        }

        var row = rows[0];
        return new DefenderTelemetry(TelemetryAvailability.Collected,
            EndpointTelemetryNormalizer.DefenderRunningMode(row["AMRunningMode"]),
            EndpointTelemetryNormalizer.Boolean(row["AntivirusEnabled"]),
            EndpointTelemetryNormalizer.Boolean(row["RealTimeProtectionEnabled"]),
            EndpointTelemetryNormalizer.Boolean(row["IsTamperProtected"]),
            EndpointTelemetryNormalizer.SignatureAgeDays(row["AntivirusSignatureAge"]));
    }

    public LocalAdministratorsTelemetry ReadLocalAdministrators()
    {
        // The group's name is localized; resolve it from its well-known SID. Member names are never read.
        var account = new SecurityIdentifier(AdministratorsSid).Translate(typeof(NTAccount)).Value;
        var groupName = account[(account.LastIndexOf('\\') + 1)..];
        var resume = IntPtr.Zero;
        var status = NetLocalGroupGetMembers(null, groupName, 1, out var buffer, MaximumPreferredLength,
            out var read, out var total, ref resume);
        var members = new List<RawAdministratorMember>();
        try
        {
            if (status == ErrorAccessDenied)
            {
                throw new UnauthorizedAccessException();
            }

            if (status != 0)
            {
                throw new Win32Exception(status);
            }

            var size = Marshal.SizeOf<LocalGroupMembersInfo1>();
            for (var index = 0; index < read; index++)
            {
                var entry = Marshal.PtrToStructure<LocalGroupMembersInfo1>(buffer + index * size);
                members.Add(new RawAdministratorMember(new SecurityIdentifier(entry.Sid).Value, entry.SidUsage));
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }

        return EndpointTelemetryNormalizer.Administrators(members, total, ReadAccountDomainSid());
    }

    public WindowsUpdateTelemetry ReadWindowsUpdate(DateTimeOffset collectedUtc)
    {
        string policyAvailability;
        string? policy = null;
        bool? managedServer = null;
        try
        {
            policy = EndpointTelemetryNormalizer.AutomaticUpdatesPolicy(
                ReadLocalMachineValue(UpdatePolicyKey, "NoAutoUpdate"), ReadLocalMachineValue(UpdatePolicyKey, "AUOptions"));
            managedServer = EndpointTelemetryNormalizer.ManagedUpdateServer(ReadLocalMachineValue(UpdatePolicyKey, "UseWUServer"));
            policyAvailability = TelemetryAvailability.Collected;
        }
        catch (Exception exception)
        {
            policyAvailability = EndpointTelemetryNormalizer.Classify(exception);
            policy = null;
            managedServer = null;
        }

        string resultsAvailability;
        DateTimeOffset? lastSearch = null;
        DateTimeOffset? lastInstallation = null;
        object? updates = null;
        object? results = null;
        try
        {
            updates = ComAutomation.Create("Microsoft.Update.AutoUpdate");
            results = ComAutomation.Get(updates, "Results");
            if (results is null)
            {
                throw new COMException("No Windows Update Agent results.", unchecked((int)0x80004005));
            }

            lastSearch = EndpointTelemetryNormalizer.UpdateResultDate(ComAutomation.Get(results, "LastSearchSuccessDate"), collectedUtc);
            lastInstallation = EndpointTelemetryNormalizer.UpdateResultDate(
                ComAutomation.Get(results, "LastInstallationSuccessDate"), collectedUtc);
            resultsAvailability = TelemetryAvailability.Collected;
        }
        catch (Exception exception)
        {
            resultsAvailability = EndpointTelemetryNormalizer.Classify(exception);
            lastSearch = null;
            lastInstallation = null;
        }
        finally
        {
            ComAutomation.Release(results);
            ComAutomation.Release(updates);
        }

        return new WindowsUpdateTelemetry(policyAvailability, resultsAvailability, policy, managedServer, lastSearch,
            lastInstallation);
    }

    public PendingRebootTelemetry ReadPendingReboot()
    {
        Exception? failure = null;
        bool? Probe(Func<bool> read)
        {
            try
            {
                return read();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                                   System.Security.SecurityException)
            {
                failure ??= exception;
                return null;
            }
        }

        var servicing = Probe(() => KeyExists(ComponentServicingRebootKey));
        var update = Probe(() => KeyExists(WindowsUpdateRebootKey));
        // Only the value names are listed; the pending file paths are never read.
        var renames = Probe(() => ValueNames(SessionManagerKey).Any(name =>
            name.Equals("PendingFileRenameOperations", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("PendingFileRenameOperations2", StringComparison.OrdinalIgnoreCase)));
        return failure is not null && servicing is null && update is null && renames is null
            ? new PendingRebootTelemetry(EndpointTelemetryNormalizer.Classify(failure))
            : new PendingRebootTelemetry(TelemetryAvailability.Collected, servicing, update, renames);
    }

    public SecurityServicesTelemetry ReadServices()
    {
        var items = EndpointTelemetryContract.MonitoredServices.Select(ReadService).ToArray();
        // When the Service Control Manager answered nothing at all, the section was not observed.
        return items.All(item => item.State is null && item.StartType is null)
            ? new SecurityServicesTelemetry(TelemetryAvailability.Unavailable)
            : new SecurityServicesTelemetry(TelemetryAvailability.Collected, items);
    }

    public InstalledSoftwareTelemetry ReadSoftware()
    {
        var nativeArchitecture = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x64",
            // ARM64 Windows keeps x64 and ARM64 applications in the same native view, so their architecture is Unknown.
            Architecture.Arm64 => string.Empty,
            Architecture.X86 => "x86",
            _ => string.Empty
        };
        (RegistryView View, string Architecture)[] views = Environment.Is64BitOperatingSystem
            ? [(RegistryView.Registry64, nativeArchitecture), (RegistryView.Registry32, "x86")]
            : [(RegistryView.Registry32, nativeArchitecture)];
        var entries = new List<RawSoftwareEntry>();
        var unreadable = 0;
        foreach (var (view, architecture) in views)
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var uninstall = hive.OpenSubKey(UninstallKey);
            if (uninstall is null)
            {
                continue;
            }

            foreach (var name in uninstall.GetSubKeyNames().Take(MaximumUninstallKeysPerView))
            {
                try
                {
                    using var entry = uninstall.OpenSubKey(name);
                    if (entry is null)
                    {
                        continue;
                    }

                    entries.Add(new RawSoftwareEntry(Text(entry, "DisplayName"), Text(entry, "DisplayVersion"),
                        Text(entry, "Publisher"), entry.GetValue("SystemComponent"), Text(entry, "ParentKeyName"),
                        Text(entry, "ReleaseType"), architecture));
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                                       System.Security.SecurityException)
                {
                    unreadable++;
                }
            }
        }

        return EndpointTelemetryNormalizer.Software(entries, unreadableEntries: unreadable);
    }

    internal static SecurityServiceObservation ReadService(string name)
    {
        using var controller = new ServiceController(name);
        string? state;
        try
        {
            state = EndpointTelemetryNormalizer.ServiceState((int)controller.Status);
        }
        catch (InvalidOperationException exception) when (exception.InnerException is Win32Exception
                                                           {
                                                               NativeErrorCode: ErrorServiceDoesNotExist
                                                           })
        {
            return new SecurityServiceObservation(name, ServiceRunStates.NotInstalled);
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
            state = null;
        }

        string? startType;
        try
        {
            startType = EndpointTelemetryNormalizer.ServiceStartType((int)controller.StartType);
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
            startType = null;
        }

        return new SecurityServiceObservation(name, state, startType);
    }

    private static string OperatingSystemDrive()
    {
        var root = Path.GetPathRoot(Environment.SystemDirectory) ?? string.Empty;
        // Only "X:" can reach the WQL text.
        return root.Length >= 2 && char.IsAsciiLetter(root[0]) && root[1] == ':'
            ? char.ToUpperInvariant(root[0]) + ":"
            : throw new PlatformNotSupportedException("The operating system volume has no drive letter.");
    }

    private static string? ReadAccountDomainSid()
    {
        var status = NetUserModalsGet(null, 2, out var buffer);
        try
        {
            return status == 0 && buffer != IntPtr.Zero && Marshal.PtrToStructure<UserModalsInfo2>(buffer) is var info &&
                   info.DomainId != IntPtr.Zero
                ? new SecurityIdentifier(info.DomainId).Value
                : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NetApiBufferFree(buffer);
            }
        }
    }

    private static object? ReadLocalMachineValue(string keyPath, string valueName)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath);
        return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }

    private static bool KeyExists(string keyPath)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath);
        return key is not null;
    }

    private static string[] ValueNames(string keyPath)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath);
        return key?.GetValueNames() ?? [];
    }

    private static string? Text(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo1
    {
        public IntPtr Sid;
        public int SidUsage;
        // lgrmi1_name is part of the structure but is never read.
        public IntPtr Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserModalsInfo2
    {
        public IntPtr DomainName;
        public IntPtr DomainId;
    }

    [DllImport("wscapi.dll")]
    private static extern int WscGetSecurityProviderHealth(int providers, out int health);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level,
        out IntPtr buffer, int preferredMaximumLength, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string? serverName, int level, out IntPtr buffer);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}

/// <summary>Late-bound OLE automation, so WMI and the Windows Update Agent need no interop package or type library.</summary>
[SupportedOSPlatform("windows")]
internal static class ComAutomation
{
    public static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false) ??
                   throw new PlatformNotSupportedException($"{progId} is not registered.");
        return Activator.CreateInstance(type) ?? throw new PlatformNotSupportedException($"{progId} could not be created.");
    }

    public static object? Get(object target, string name, params object?[] arguments) =>
        Normalize(target.GetType().InvokeMember(name, BindingFlags.GetProperty, null, target, arguments,
            CultureInfo.InvariantCulture));

    public static object? Call(object target, string name, params object?[] arguments) =>
        Normalize(target.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, target, arguments,
            CultureInfo.InvariantCulture));

    public static void Set(object target, string name, object value) =>
        target.GetType().InvokeMember(name, BindingFlags.SetProperty, null, target, [value], CultureInfo.InvariantCulture);

    public static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            Marshal.ReleaseComObject(value);
        }
    }

    private static object? Normalize(object? value) => value is DBNull ? null : value;
}

/// <summary>A local WMI query through the scripting API (SWbemLocator), returning only the named properties.</summary>
[SupportedOSPlatform("windows")]
internal static class WmiQuery
{
    private const int ImpersonationImpersonate = 3;
    private const int AuthenticationPacketPrivacy = 6;
    private const int WbemNotFound = unchecked((int)0x80041002);

    public static IReadOnlyList<IReadOnlyDictionary<string, object?>> Run(string wmiNamespace, string query,
        IReadOnlyList<string> properties, int maximumRows, bool packetPrivacy)
    {
        var owned = new Stack<object>();
        T Own<T>(T value) where T : class
        {
            owned.Push(value);
            return value;
        }

        try
        {
            var locator = Own(ComAutomation.Create("WbemScripting.SWbemLocator"));
            var services = Own(ComAutomation.Call(locator, "ConnectServer", ".", wmiNamespace) ??
                               throw new COMException("WMI connection failed.", unchecked((int)0x80004005)));
            var security = Own(ComAutomation.Get(services, "Security_")!);
            ComAutomation.Set(security, "ImpersonationLevel", ImpersonationImpersonate);
            if (packetPrivacy)
            {
                ComAutomation.Set(security, "AuthenticationLevel", AuthenticationPacketPrivacy);
            }

            // Synchronous query (flags 0): Count and ItemIndex then read the complete, bounded result.
            var results = Own(ComAutomation.Call(services, "ExecQuery", query, "WQL", 0) ??
                              throw new COMException("WMI query failed.", unchecked((int)0x80004005)));
            var count = Convert.ToInt32(ComAutomation.Get(results, "Count"), CultureInfo.InvariantCulture);
            var rows = new List<IReadOnlyDictionary<string, object?>>();
            for (var index = 0; index < Math.Min(count, maximumRows); index++)
            {
                var row = Own(ComAutomation.Call(results, "ItemIndex", index)!);
                var propertySet = Own(ComAutomation.Get(row, "Properties_")!);
                var values = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var name in properties)
                {
                    values[name] = ReadProperty(propertySet, name);
                }

                rows.Add(values);
            }

            return rows;
        }
        finally
        {
            while (owned.TryPop(out var value))
            {
                ComAutomation.Release(value);
            }
        }
    }

    private static object? ReadProperty(object propertySet, string name)
    {
        object? property = null;
        try
        {
            property = ComAutomation.Call(propertySet, "Item", name);
            return property is null ? null : ComAutomation.Get(property, "Value");
        }
        catch (Exception exception) when (IsNotFound(exception))
        {
            // A property that this platform version does not define is Unknown.
            return null;
        }
        finally
        {
            ComAutomation.Release(property);
        }
    }

    private static bool IsNotFound(Exception exception) =>
        (exception is TargetInvocationException { InnerException: COMException inner } ? inner : exception as COMException)
        ?.HResult == WbemNotFound;
}
