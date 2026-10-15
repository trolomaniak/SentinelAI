using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

/// <summary>One machine-wide uninstall registry entry as read; only these values are ever read from an entry.</summary>
public sealed record RawSoftwareEntry(
    string? DisplayName,
    string? DisplayVersion,
    string? Publisher,
    object? SystemComponent,
    string? ParentKeyName,
    string? ReleaseType,
    string Architecture);

/// <summary>A local Administrators member as returned by the Windows API: its SID and SID_NAME_USE value only.</summary>
public sealed record RawAdministratorMember(string Sid, int SidUse);

/// <summary>
/// Pure, platform-independent mapping from raw Windows values to the telemetry contract. Unknown or malformed raw
/// values map to null (Unknown) and never to a safe-looking value.
/// </summary>
public static class EndpointTelemetryNormalizer
{
    private const int MaximumSoftwareEntriesScanned = 16_384;
    private static readonly string[] PatchReleaseTypes = ["Update", "Hotfix", "Security Update", "Service Pack"];

    /// <summary>Win32_EncryptableVolume.ProtectionStatus: 0 off, 1 on, 2 unknown (for example a locked volume).</summary>
    public static string? BitLockerProtection(object? value) => AsInteger(value) switch
    {
        0 => BitLockerProtectionStates.Off,
        1 => BitLockerProtectionStates.On,
        _ => null
    };

    /// <summary>Win32_EncryptableVolume.ConversionStatus 0–5.</summary>
    public static string? BitLockerConversion(object? value) =>
        AsInteger(value) is { } status && status is >= 0 and <= 5 ? BitLockerConversionStates.All[(int)status] : null;

    /// <summary>WSC_SECURITY_PROVIDER_HEALTH: 0 good, 1 not monitored, 2 poor, 3 snooze.</summary>
    public static string? SecurityCenterHealth(int value) =>
        value is >= 0 and <= 3 ? SecurityCenterHealthStates.All[value] : null;

    /// <summary>MSFT_MpComputerStatus.AMRunningMode text.</summary>
    public static string? DefenderRunningMode(object? value) => value is string text ? text.Trim() switch
    {
        "Normal" => "normal",
        "Passive" or "Passive Mode" => "passive",
        "EDR Block Mode" => "edrBlock",
        "SxS Passive Mode" => "sxsPassive",
        _ => null
    } : null;

    public static bool? Boolean(object? value) => value is bool flag ? flag : null;

    public static int? SignatureAgeDays(object? value) =>
        AsInteger(value) is { } days && days is >= 0 and <= EndpointTelemetryContract.MaxSignatureAgeDays ? (int)days : null;

    /// <summary>
    /// Builds the bounded Administrators section. Members keep their SIDs; the scope is derived from the SID and
    /// <paramref name="accountDomainSid"/> (the machine's local account domain), never from a name.
    /// </summary>
    public static LocalAdministratorsTelemetry Administrators(IReadOnlyList<RawAdministratorMember> members,
        int totalCount, string? accountDomainSid)
    {
        ArgumentNullException.ThrowIfNull(members);
        var valid = members.Where(member => SecurityEventContract.IsValidSid(member.Sid))
            .DistinctBy(member => member.Sid, StringComparer.OrdinalIgnoreCase)
            .OrderBy(member => member.Sid, StringComparer.Ordinal)
            .ToArray();
        // An invalid or duplicate SID from the API leaves the listed members incomplete, so only the count is kept.
        var count = Math.Clamp(Math.Max(totalCount, members.Count), 0, EndpointTelemetryContract.MaxAdministratorMemberCount);
        var listed = valid.Length == members.Count
            ? valid.Take(EndpointTelemetryContract.MaxAdministratorMembers)
                .Select(member => new LocalAdministratorMember(member.Sid, AdministratorScope(member.Sid, accountDomainSid),
                    AdministratorAccountType(member.SidUse)))
                .ToArray()
            : null;
        return listed is null || listed.Length != Math.Min(count, EndpointTelemetryContract.MaxAdministratorMembers)
            ? new LocalAdministratorsTelemetry(TelemetryAvailability.Unavailable)
            : new LocalAdministratorsTelemetry(TelemetryAvailability.Collected, count, listed);
    }

    public static string? AdministratorScope(string sid, string? accountDomainSid)
    {
        if (sid.StartsWith("S-1-12-1-", StringComparison.Ordinal)) return AdministratorScopes.Entra;
        if (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
        {
            if (accountDomainSid is null || !SecurityEventContract.IsValidSid(accountDomainSid)) return null;
            return sid.StartsWith(accountDomainSid + "-", StringComparison.OrdinalIgnoreCase)
                ? AdministratorScopes.Local
                : AdministratorScopes.Domain;
        }

        return AdministratorScopes.WellKnown;
    }

    /// <summary>SID_NAME_USE: 1 user, 2 group, 4 alias, 5 well-known group, 6 deleted account, 9 computer.</summary>
    public static string? AdministratorAccountType(int sidUse) => sidUse switch
    {
        1 => "user",
        2 => "group",
        4 => "alias",
        5 => "wellKnownGroup",
        6 => "deletedAccount",
        9 => "computer",
        _ => null
    };

    /// <summary>
    /// Maps the Windows Update AU policy values. A readable but absent policy is "notConfigured"; NoAutoUpdate=1
    /// overrides AUOptions; malformed values are Unknown.
    /// </summary>
    public static string? AutomaticUpdatesPolicy(object? noAutoUpdate, object? auOptions)
    {
        switch (noAutoUpdate)
        {
            case 1:
                return "disabled";
            case null or 0:
                break;
            default:
                return null;
        }

        return auOptions switch
        {
            null => "notConfigured",
            2 => "notifyDownload",
            3 => "autoDownloadNotifyInstall",
            4 => "autoDownloadScheduledInstall",
            5 => "localAdminChooses",
            7 => "autoDownloadNotifyInstallNotifyRestart",
            _ => null
        };
    }

    /// <summary>UseWUServer: 1 uses a managed (WSUS) server; absent or 0 does not; anything else is Unknown.</summary>
    public static bool? ManagedUpdateServer(object? useWuServer) => useWuServer switch
    {
        null or 0 => false,
        1 => true,
        _ => null
    };

    /// <summary>A Windows Update Agent date (UTC VT_DATE), kept only when it is plausible for this collection.</summary>
    public static DateTimeOffset? UpdateResultDate(object? value, DateTimeOffset collectedUtc)
    {
        if (value is not DateTime date || date.Year < 2000) return null;
        var utc = new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc));
        return utc <= collectedUtc.AddDays(1) ? utc : null;
    }

    /// <summary>ServiceControllerStatus values 1–7.</summary>
    public static string? ServiceState(int status) => status switch
    {
        1 => ServiceRunStates.Stopped,
        2 => "startPending",
        3 => "stopPending",
        4 => ServiceRunStates.Running,
        5 => "continuePending",
        6 => "pausePending",
        7 => "paused",
        _ => null
    };

    /// <summary>ServiceStartMode values 0–4, in the TASK-027 start-type vocabulary.</summary>
    public static string? ServiceStartType(int startMode) => startMode switch
    {
        0 => ServiceStartTypes.Boot,
        1 => ServiceStartTypes.System,
        2 => ServiceStartTypes.Auto,
        3 => ServiceStartTypes.Demand,
        4 => ServiceStartTypes.Disabled,
        _ => null
    };

    /// <summary>
    /// Filters, deduplicates, sorts and bounds machine-wide applications. Entries without a display name, hidden
    /// system components and updates of another product are not applications and are not counted; an application
    /// whose name is unusable is counted in <see cref="InstalledSoftwareTelemetry.SkippedCount"/>. Items are added in
    /// sorted order until their serialized size reaches <paramref name="byteBudget"/>. Entries that could not be read
    /// at all are counted as skipped.
    /// </summary>
    public static InstalledSoftwareTelemetry Software(IEnumerable<RawSoftwareEntry> entries,
        int byteBudget = EndpointTelemetryContract.SoftwareByteBudget, int unreadableEntries = 0)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var skipped = Math.Max(0, unreadableEntries);
        var applications = new HashSet<InstalledSoftwareItem>();
        foreach (var entry in entries.Take(MaximumSoftwareEntriesScanned))
        {
            var name = entry.DisplayName?.Trim();
            if (string.IsNullOrEmpty(name) || AsInteger(entry.SystemComponent) == 1 ||
                !string.IsNullOrWhiteSpace(entry.ParentKeyName) ||
                entry.ReleaseType is { } releaseType && PatchReleaseTypes.Contains(releaseType.Trim(), StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!SecurityEventContract.IsBoundedText(name, EndpointTelemetryContract.MaxSoftwareNameLength))
            {
                skipped++;
                continue;
            }

            applications.Add(new InstalledSoftwareItem(name,
                BoundedOrNull(entry.DisplayVersion, EndpointTelemetryContract.MaxSoftwareVersionLength),
                BoundedOrNull(entry.Publisher, EndpointTelemetryContract.MaxSoftwarePublisherLength),
                SoftwareArchitectures.All.Contains(entry.Architecture, StringComparer.Ordinal) ? entry.Architecture : null));
        }

        var sorted = applications
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ThenBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Version, StringComparer.Ordinal).ThenBy(item => item.Publisher, StringComparer.Ordinal)
            .ThenBy(item => item.Architecture, StringComparer.Ordinal)
            .ToArray();
        var total = Math.Min(sorted.Length, EndpointTelemetryContract.MaxSoftwareTotal);
        var kept = new List<InstalledSoftwareItem>();
        var bytes = 2;
        foreach (var item in sorted.Take(Math.Min(total, EndpointTelemetryContract.MaxSoftwareItems)))
        {
            var size = JsonSerializer.SerializeToUtf8Bytes(item, EndpointTelemetryContract.Json).Length + 1;
            if (bytes + size > byteBudget) break;
            bytes += size;
            kept.Add(item);
        }

        return new InstalledSoftwareTelemetry(TelemetryAvailability.Collected, kept.AsReadOnly(), total,
            kept.Count < total, Math.Min(skipped, EndpointTelemetryContract.MaxSoftwareTotal));
    }

    /// <summary>Classifies a failed read; access failures are never reported as absent or safe.</summary>
    public static string Classify(Exception exception)
    {
        if (exception is TargetInvocationException { InnerException: { } inner }) exception = inner;
        return exception switch
        {
            UnauthorizedAccessException or System.Security.SecurityException => TelemetryAvailability.AccessDenied,
            PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException =>
                TelemetryAvailability.Unsupported,
            COMException com => com.HResult switch
            {
                // E_ACCESSDENIED, WBEM_E_ACCESS_DENIED
                unchecked((int)0x80070005) or unchecked((int)0x80041003) => TelemetryAvailability.AccessDenied,
                // REGDB_E_CLASSNOTREG, WBEM_E_INVALID_NAMESPACE, WBEM_E_INVALID_CLASS, WBEM_E_NOT_SUPPORTED
                unchecked((int)0x80040154) or unchecked((int)0x8004100E) or unchecked((int)0x80041010) or
                    unchecked((int)0x8004100C) => TelemetryAvailability.Unsupported,
                _ => TelemetryAvailability.Unavailable
            },
            System.ComponentModel.Win32Exception { NativeErrorCode: 5 } => TelemetryAvailability.AccessDenied,
            _ => TelemetryAvailability.Unavailable
        };
    }

    private static string? BoundedOrNull(string? value, int maximum)
    {
        var trimmed = value?.Trim();
        return trimmed is not null && SecurityEventContract.IsBoundedText(trimmed, maximum) ? trimmed : null;
    }

    private static long? AsInteger(object? value) => value switch
    {
        int number => number,
        uint number => number,
        long number => number,
        short number => number,
        ushort number => number,
        byte number => number,
        _ => null
    };
}
