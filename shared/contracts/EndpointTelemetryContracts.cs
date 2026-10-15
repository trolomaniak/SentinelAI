using System.Text.Json;
using System.Text.Json.Serialization;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Contracts.EndpointTelemetry;

// Wire contract for endpoint security telemetry (TASK-029), schema version 1.
// Every section states how it was observed. A null value is Unknown: it never means
// protected, compliant or absent, and a section that was not collected carries no values.
// A future schema adds a new version; Core accepts only versions it implements.

public sealed record EndpointTelemetryReport(
    int SchemaVersion,
    Guid EndpointId,
    DateTimeOffset CollectedUtc,
    BitLockerTelemetry BitLocker,
    AntivirusTelemetry Antivirus,
    DefenderTelemetry Defender,
    LocalAdministratorsTelemetry LocalAdministrators,
    WindowsUpdateTelemetry WindowsUpdate,
    PendingRebootTelemetry PendingReboot,
    SecurityServicesTelemetry Services,
    InstalledSoftwareTelemetry Software)
{
    public override string ToString() => nameof(EndpointTelemetryReport);
}

/// <summary>BitLocker on the operating system volume only (Win32_EncryptableVolume). No keys or protectors.</summary>
public sealed record BitLockerTelemetry(string Availability, string? ProtectionStatus = null, string? ConversionStatus = null);

/// <summary>The aggregate antivirus health Windows Security Center reports for registered products.</summary>
public sealed record AntivirusTelemetry(string Availability, string? SecurityCenterHealth = null);

/// <summary>Microsoft Defender Antivirus status (MSFT_MpComputerStatus). No detections, paths or exclusions.</summary>
public sealed record DefenderTelemetry(
    string Availability,
    string? RunningMode = null,
    bool? AntivirusEnabled = null,
    bool? RealTimeProtectionEnabled = null,
    bool? TamperProtectionEnabled = null,
    int? SignatureAgeDays = null);

/// <summary>
/// Members of the local Administrators group (S-1-5-32-544) as SIDs with a derived scope and account type.
/// Account, group and domain names are never collected.
/// </summary>
public sealed record LocalAdministratorsTelemetry(
    string Availability,
    int? MemberCount = null,
    IReadOnlyList<LocalAdministratorMember>? Members = null);

public sealed record LocalAdministratorMember(string Sid, string? Scope = null, string? AccountType = null)
{
    public override string ToString() => nameof(LocalAdministratorMember);
}

/// <summary>Windows Update policy (registry) and the Windows Update Agent's last successful search and installation.</summary>
public sealed record WindowsUpdateTelemetry(
    string PolicyAvailability,
    string ResultsAvailability,
    string? AutomaticUpdatesPolicy = null,
    bool? ManagedUpdateServer = null,
    DateTimeOffset? LastSuccessfulSearchUtc = null,
    DateTimeOffset? LastSuccessfulInstallationUtc = null);

/// <summary>Presence of the standard pending-restart markers. File names in pending renames are never read.</summary>
public sealed record PendingRebootTelemetry(
    string Availability,
    bool? ComponentBasedServicing = null,
    bool? WindowsUpdate = null,
    bool? PendingFileRenameOperations = null);

/// <summary>Service Control Manager state of the fixed <see cref="EndpointTelemetryContract.MonitoredServices"/> catalog.</summary>
public sealed record SecurityServicesTelemetry(string Availability, IReadOnlyList<SecurityServiceObservation>? Items = null);

public sealed record SecurityServiceObservation(string Name, string? State = null, string? StartType = null);

/// <summary>
/// Machine-wide installed applications from the Windows uninstall registry (64- and 32-bit views): name, version,
/// publisher and architecture only. Per-user and Store applications are not covered. Items are sorted; when the
/// byte budget is reached the remainder is counted in <see cref="TotalCount"/> and <see cref="Truncated"/> is set.
/// </summary>
public sealed record InstalledSoftwareTelemetry(
    string Availability,
    IReadOnlyList<InstalledSoftwareItem>? Items = null,
    int? TotalCount = null,
    bool Truncated = false,
    int SkippedCount = 0);

public sealed record InstalledSoftwareItem(string Name, string? Version = null, string? Publisher = null, string? Architecture = null)
{
    public override string ToString() => nameof(InstalledSoftwareItem);
}

public static class TelemetryAvailability
{
    /// <summary>The source was read; individual values can still be Unknown.</summary>
    public const string Collected = "collected";
    /// <summary>The platform or edition does not provide the source.</summary>
    public const string Unsupported = "unsupported";
    /// <summary>The Agent's account may not read the source.</summary>
    public const string AccessDenied = "accessDenied";
    /// <summary>The source failed, timed out or returned nothing usable.</summary>
    public const string Unavailable = "unavailable";
    public static IReadOnlyList<string> All { get; } = [Collected, Unsupported, AccessDenied, Unavailable];
}

public static class BitLockerProtectionStates
{
    public const string On = "on";
    public const string Off = "off";
    public static IReadOnlyList<string> All { get; } = [On, Off];
}

public static class BitLockerConversionStates
{
    public static IReadOnlyList<string> All { get; } =
    [
        "fullyDecrypted", "fullyEncrypted", "encryptionInProgress", "decryptionInProgress", "encryptionPaused",
        "decryptionPaused"
    ];
}

public static class SecurityCenterHealthStates
{
    public const string Good = "good";
    public const string NotMonitored = "notMonitored";
    public const string Poor = "poor";
    public const string Snooze = "snooze";
    public static IReadOnlyList<string> All { get; } = [Good, NotMonitored, Poor, Snooze];
}

public static class DefenderRunningModes
{
    public static IReadOnlyList<string> All { get; } = ["normal", "passive", "edrBlock", "sxsPassive"];
}

public static class AdministratorScopes
{
    public const string Local = "local";
    public const string Domain = "domain";
    public const string Entra = "entra";
    public const string WellKnown = "wellKnown";
    public static IReadOnlyList<string> All { get; } = [Local, Domain, Entra, WellKnown];
}

public static class AdministratorAccountTypes
{
    public static IReadOnlyList<string> All { get; } = ["user", "group", "alias", "wellKnownGroup", "deletedAccount", "computer"];
}

public static class AutomaticUpdatesPolicies
{
    public static IReadOnlyList<string> All { get; } =
    [
        "notConfigured", "disabled", "notifyDownload", "autoDownloadNotifyInstall", "autoDownloadScheduledInstall",
        "localAdminChooses", "autoDownloadNotifyInstallNotifyRestart"
    ];
}

public static class ServiceRunStates
{
    public const string Running = "running";
    public const string Stopped = "stopped";
    public const string NotInstalled = "notInstalled";
    public static IReadOnlyList<string> All { get; } =
        [Running, Stopped, "startPending", "stopPending", "paused", "pausePending", "continuePending", NotInstalled];
}

public static class SoftwareArchitectures
{
    public static IReadOnlyList<string> All { get; } = ["x64", "x86", "arm64"];
}

public static class EndpointTelemetryContract
{
    public const int CurrentSchemaVersion = 1;
    public const int MaxRequestBytes = 256 * 1024;
    /// <summary>The Agent stops adding software items once their serialized size reaches this budget.</summary>
    public const int SoftwareByteBudget = 192 * 1024;
    public const int MaxSoftwareItems = 2048;
    public const int MaxSoftwareTotal = 65_536;
    public const int MaxSoftwareNameLength = 256;
    public const int MaxSoftwareVersionLength = 64;
    public const int MaxSoftwarePublisherLength = 256;
    public const int MaxAdministratorMembers = 64;
    public const int MaxAdministratorMemberCount = 100_000;
    public const int MaxSignatureAgeDays = 36_500;

    /// <summary>
    /// Protection services named by the TASK-027 start-type rule, plus Windows Update. Each appears at most once.
    /// </summary>
    public static IReadOnlyList<string> MonitoredServices { get; } = [.. ProtectedServices.All, "wuauserv"];

    public static JsonSerializerOptions Json { get; } = CreateJson();

    /// <summary>How far a report's collection time may be ahead of Core's clock.</summary>
    public static TimeSpan MaxClockSkew { get; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Validates a report completely: version, identity, timestamps, vocabularies, bounds and that a section
    /// which was not collected carries no values. Core stores nothing that fails this check.
    /// </summary>
    public static bool IsValid(EndpointTelemetryReport? report, DateTimeOffset now) =>
        IsValidIgnoringClock(report) && report!.CollectedUtc <= now + MaxClockSkew;

    /// <summary>Everything <see cref="IsValid(EndpointTelemetryReport?, DateTimeOffset)"/> checks except the receiver's clock.</summary>
    public static bool IsValidIgnoringClock(EndpointTelemetryReport? report)
    {
        if (report is null || report.SchemaVersion != CurrentSchemaVersion || report.EndpointId == Guid.Empty ||
            report.CollectedUtc.Offset != TimeSpan.Zero || report.CollectedUtc <= DateTimeOffset.UnixEpoch)
        {
            return false;
        }

        return IsValid(report.BitLocker) && IsValid(report.Antivirus) && IsValid(report.Defender) &&
               IsValid(report.LocalAdministrators) && IsValid(report.WindowsUpdate, report.CollectedUtc) &&
               IsValid(report.PendingReboot) && IsValid(report.Services) && IsValid(report.Software);
    }

    public static bool IsValid(BitLockerTelemetry? section) => section is not null &&
        Gate(section.Availability, section.ProtectionStatus, section.ConversionStatus) &&
        NullOrIn(section.ProtectionStatus, BitLockerProtectionStates.All) &&
        NullOrIn(section.ConversionStatus, BitLockerConversionStates.All);

    public static bool IsValid(AntivirusTelemetry? section) => section is not null &&
        Gate(section.Availability, section.SecurityCenterHealth) &&
        NullOrIn(section.SecurityCenterHealth, SecurityCenterHealthStates.All);

    public static bool IsValid(DefenderTelemetry? section) => section is not null &&
        Gate(section.Availability, section.RunningMode, section.AntivirusEnabled, section.RealTimeProtectionEnabled,
            section.TamperProtectionEnabled, section.SignatureAgeDays) &&
        NullOrIn(section.RunningMode, DefenderRunningModes.All) &&
        section.SignatureAgeDays is null or (>= 0 and <= MaxSignatureAgeDays);

    public static bool IsValid(LocalAdministratorsTelemetry? section)
    {
        if (section is null || !Gate(section.Availability, section.MemberCount, section.Members))
        {
            return false;
        }

        if (section.Availability != TelemetryAvailability.Collected)
        {
            return true;
        }

        // A collected group always reports its count and the members it lists (possibly a bounded prefix).
        if (section.MemberCount is not { } count || count is < 0 or > MaxAdministratorMemberCount ||
            section.Members is not { } members || members.Count > MaxAdministratorMembers || members.Count > count ||
            members.Count < Math.Min(count, MaxAdministratorMembers))
        {
            return false;
        }

        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return members.All(member => member is not null && SecurityEventContract.IsValidSid(member.Sid) &&
                                     sids.Add(member.Sid) && NullOrIn(member.Scope, AdministratorScopes.All) &&
                                     NullOrIn(member.AccountType, AdministratorAccountTypes.All));
    }

    public static bool IsValid(WindowsUpdateTelemetry? section, DateTimeOffset collectedUtc) => section is not null &&
        Gate(section.PolicyAvailability, section.AutomaticUpdatesPolicy, section.ManagedUpdateServer) &&
        Gate(section.ResultsAvailability, section.LastSuccessfulSearchUtc, section.LastSuccessfulInstallationUtc) &&
        NullOrIn(section.AutomaticUpdatesPolicy, AutomaticUpdatesPolicies.All) &&
        IsPastUtc(section.LastSuccessfulSearchUtc, collectedUtc) &&
        IsPastUtc(section.LastSuccessfulInstallationUtc, collectedUtc);

    public static bool IsValid(PendingRebootTelemetry? section) => section is not null &&
        Gate(section.Availability, section.ComponentBasedServicing, section.WindowsUpdate, section.PendingFileRenameOperations);

    public static bool IsValid(SecurityServicesTelemetry? section)
    {
        if (section is null || !Gate(section.Availability, section.Items))
        {
            return false;
        }

        if (section.Availability != TelemetryAvailability.Collected)
        {
            return true;
        }

        if (section.Items is not { } items || items.Count > MonitoredServices.Count)
        {
            return false;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        return items.All(item => item is not null && MonitoredServices.Contains(item.Name, StringComparer.Ordinal) &&
                                 names.Add(item.Name) && NullOrIn(item.State, ServiceRunStates.All) &&
                                 NullOrIn(item.StartType, ServiceStartTypes.All) &&
                                 // An absent service has no start type.
                                 (item.State != ServiceRunStates.NotInstalled || item.StartType is null));
    }

    public static bool IsValid(InstalledSoftwareTelemetry? section)
    {
        if (section is null || !Gate(section.Availability, section.Items, section.TotalCount) ||
            section.SkippedCount is < 0 or > MaxSoftwareTotal)
        {
            return false;
        }

        if (section.Availability != TelemetryAvailability.Collected)
        {
            return !section.Truncated && section.SkippedCount == 0;
        }

        if (section.Items is not { } items || section.TotalCount is not { } total || items.Count > MaxSoftwareItems ||
            total is < 0 or > MaxSoftwareTotal || items.Count > total || section.Truncated != (items.Count < total))
        {
            return false;
        }

        return items.All(item => item is not null &&
                                 SecurityEventContract.IsBoundedText(item.Name, MaxSoftwareNameLength) &&
                                 NullOrText(item.Version, MaxSoftwareVersionLength) &&
                                 NullOrText(item.Publisher, MaxSoftwarePublisherLength) &&
                                 NullOrIn(item.Architecture, SoftwareArchitectures.All));
    }

    /// <summary>Only a collected section may carry values; anything else is Unknown in full.</summary>
    private static bool Gate(string? availability, params object?[] values) =>
        availability is not null && TelemetryAvailability.All.Contains(availability, StringComparer.Ordinal) &&
        (availability == TelemetryAvailability.Collected || values.All(value => value is null));

    // Subtraction cannot overflow at the end of the calendar, unlike collectedUtc.AddDays(1).
    private static bool IsPastUtc(DateTimeOffset? value, DateTimeOffset collectedUtc) =>
        value is not { } time || time.Offset == TimeSpan.Zero && time > DateTimeOffset.UnixEpoch && time - collectedUtc <= TimeSpan.FromDays(1);

    private static bool NullOrIn(string? value, IReadOnlyList<string> vocabulary) =>
        value is null || vocabulary.Contains(value, StringComparer.Ordinal);

    private static bool NullOrText(string? value, int max) => value is null || SecurityEventContract.IsBoundedText(value, max);

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            NumberHandling = JsonNumberHandling.Strict,
            AllowDuplicateProperties = false,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            MaxDepth = 8
        };
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
