using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SentinelAI.Contracts.SecurityEvents;

// Wire contract for continuous Windows security event observations (TASK-027).
// Discriminators are strings; new kinds and payloads are additive optional members.

public sealed record SecurityEventBatch(
    Guid EndpointId,
    string Format,
    string AgentVersion,
    DateTimeOffset SentUtc,
    DateTimeOffset CountersSinceUtc,
    IReadOnlyList<SecurityEventSourceStatus> Sources,
    IReadOnlyList<SecurityEventGap> Gaps,
    IReadOnlyList<SecurityEventObservation> Events)
{
    public override string ToString() => nameof(SecurityEventBatch);
}

/// <summary>Per-channel collection state and counters; counters are cumulative since CountersSinceUtc.</summary>
public sealed record SecurityEventSourceStatus(
    string Channel,
    string State,
    int? LastErrorCode,
    long? OldestRecordId,
    long? NewestRecordId,
    long? CheckpointRecordId,
    long? LogMaximumBytes,
    DateTimeOffset? LastReadUtc,
    long Scanned,
    long Observed,
    long Delivered,
    long DroppedUnparsed,
    long DroppedOversize,
    long FieldsDiscarded,
    long Gaps,
    long SkippedRecords,
    long SeekFallbacks);

/// <summary>A continuity notice: records that were not, or may not have been, observed.</summary>
public sealed record SecurityEventGap(
    string Channel,
    string Reason,
    long FirstRecordId,
    long? LastRecordId,
    DateTimeOffset DetectedUtc,
    string? Cause = null);

public sealed record SecurityEventObservation(
    string Channel,
    string Provider,
    int EventId,
    int EventVersion,
    int? Level,
    long RecordId,
    DateTimeOffset TimeCreatedUtc,
    string Kind,
    LogonEvent? Logon = null,
    ScheduledTaskEvent? ScheduledTask = null,
    LogClearedEvent? LogCleared = null,
    ServiceInstallEvent? ServiceInstall = null,
    ServiceStartTypeEvent? ServiceStartType = null,
    ScriptBlockEvent? ScriptBlock = null,
    MalwareEvent? Malware = null,
    DefenderSettingEvent? DefenderSetting = null)
{
    public override string ToString() => nameof(SecurityEventObservation);
}

public sealed record LogonEvent(int? LogonType, string? TargetUserSid, string? IpAddress,
    long? Status, long? SubStatus, bool? ElevatedToken)
{
    public override string ToString() => nameof(LogonEvent);
}

public sealed record ScheduledTaskEvent(string? TaskName, string? SubjectUserSid)
{
    public override string ToString() => nameof(ScheduledTaskEvent);
}

public sealed record LogClearedEvent(string? ClearedChannel);

public sealed record ServiceInstallEvent(string? ServiceName, string? ImageFileName, string? ImageLocation,
    string? ServiceType, string? StartType, string? AccountKind)
{
    public override string ToString() => nameof(ServiceInstallEvent);
}

public sealed record ServiceStartTypeEvent(string? ServiceName, string? NewStartType);

public sealed record ScriptBlockEvent(Guid? ScriptBlockId, int? PartCount);

public sealed record MalwareEvent(Guid? DetectionId, long? ThreatId, string? ThreatName,
    int? SeverityId, int? CategoryId, int? ActionId, long? ErrorCode);

public sealed record DefenderSettingEvent(string? SettingArea, string? Change);

public sealed record SecurityEventBatchResult(int Accepted, int Duplicates, int Ignored, int Rejected);

public sealed record SecurityEventSelection(string Channel, string Provider, int EventId, string Kind);

public enum SecurityEventItemValidity { Valid, Unknown, Invalid }

public static class SecurityEventChannels
{
    public const string Security = "Security";
    public const string System = "System";
    public const string PowerShell = "Microsoft-Windows-PowerShell/Operational";
    public const string Defender = "Microsoft-Windows-Windows Defender/Operational";
    public static IReadOnlyList<string> All { get; } = [Security, System, PowerShell, Defender];
}

public static class SecurityEventProviders
{
    public const string SecurityAuditing = "Microsoft-Windows-Security-Auditing";
    public const string Eventlog = "Microsoft-Windows-Eventlog";
    public const string ServiceControlManager = "Service Control Manager";
    public const string PowerShell = "Microsoft-Windows-PowerShell";
    public const string Defender = "Microsoft-Windows-Windows Defender";
}

public static class SecurityEventKinds
{
    public const string LogonSucceeded = "logonSucceeded";
    public const string LogonFailed = "logonFailed";
    public const string ScheduledTaskCreated = "scheduledTaskCreated";
    public const string LogCleared = "logCleared";
    public const string ServiceInstalled = "serviceInstalled";
    public const string ProtectionServiceStartTypeChanged = "protectionServiceStartTypeChanged";
    public const string ScriptBlockFlagged = "scriptBlockFlagged";
    public const string MalwareDetected = "malwareDetected";
    public const string MalwareActionTaken = "malwareActionTaken";
    public const string MalwareActionFailed = "malwareActionFailed";
    public const string ProtectionDisabled = "protectionDisabled";
    public const string DefenderSettingChanged = "defenderSettingChanged";
}

public static class SecurityEventSourceStates
{
    public const string Collecting = "collecting";
    public const string Disabled = "disabled";
    public const string AccessDenied = "accessDenied";
    public const string NotFound = "notFound";
    public const string Error = "error";
    public static IReadOnlyList<string> All { get; } = [Collecting, Disabled, AccessDenied, NotFound, Error];
}

public static class SecurityEventGapReasons
{
    public const string Overwritten = "overwritten";
    public const string LogReset = "logReset";
    public const string CoverageStarted = "coverageStarted";
    public const string Dropped = "dropped";
    // Core-derived only: an Agent-sent "rejected" gap is Unknown and ignored.
    public const string Rejected = "rejected";
    public static IReadOnlyList<string> AgentReasons { get; } = [Overwritten, LogReset, CoverageStarted, Dropped];
}

public static class SecurityEventCoverageCauses
{
    public const string NoCheckpoint = "noCheckpoint";
    public const string CheckpointInvalid = "checkpointInvalid";
    public const string EndpointChanged = "endpointChanged";
    public static IReadOnlyList<string> All { get; } = [NoCheckpoint, CheckpointInvalid, EndpointChanged];
}

public static class ServiceImageLocations
{
    public const string Windows = "windows";
    public const string ProgramFiles = "programFiles";
    public const string ProgramData = "programData";
    public const string UserProfile = "userProfile";
    public const string Temp = "temp";
    public const string Network = "network";
    public const string Other = "other";
    public static IReadOnlyList<string> All { get; } = [Windows, ProgramFiles, ProgramData, UserProfile, Temp, Network, Other];
}

public static class ServiceTypes
{
    public const string UserModeService = "userModeService";
    public const string KernelDriver = "kernelDriver";
    public const string FileSystemDriver = "fileSystemDriver";
    public static IReadOnlyList<string> All { get; } = [UserModeService, KernelDriver, FileSystemDriver];
}

public static class ServiceStartTypes
{
    public const string Boot = "boot";
    public const string System = "system";
    public const string Auto = "auto";
    public const string Demand = "demand";
    public const string Disabled = "disabled";
    public static IReadOnlyList<string> All { get; } = [Boot, System, Auto, Demand, Disabled];
}

public static class ServiceAccountKinds
{
    public const string LocalSystem = "localSystem";
    public const string LocalService = "localService";
    public const string NetworkService = "networkService";
    public const string VirtualAccount = "virtualAccount";
    public const string OtherAccount = "otherAccount";
    public static IReadOnlyList<string> All { get; } = [LocalSystem, LocalService, NetworkService, VirtualAccount, OtherAccount];
}

/// <summary>Protection services whose start-type changes are collected (canonical casing).</summary>
public static class ProtectedServices
{
    public static IReadOnlyList<string> All { get; } =
        ["WinDefend", "WdNisSvc", "Sense", "MpsSvc", "BFE", "EventLog", "wscsvc", "SecurityHealthService"];
}

public static class DefenderSettingAreas
{
    public const string ExclusionPath = "exclusionPath";
    public const string ExclusionProcess = "exclusionProcess";
    public const string ExclusionExtension = "exclusionExtension";
    public const string ExclusionIpAddress = "exclusionIpAddress";
    public const string RealTimeProtection = "realTimeProtection";
    public const string TamperProtection = "tamperProtection";
    public const string Other = "other";
    public static IReadOnlyList<string> All { get; } =
        [ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress, RealTimeProtection, TamperProtection, Other];
}

public static class DefenderSettingChanges
{
    public const string Added = "added";
    public const string Removed = "removed";
    public const string Modified = "modified";
    public static IReadOnlyList<string> All { get; } = [Added, Removed, Modified];
}

/// <summary>
/// Shared validation used by the Agent before sending and by Core on ingest. Unknown
/// tuples, states and reasons are forward compatible (ignored); invalid items are rejected
/// individually; only envelope or structural faults reject a whole batch.
/// </summary>
public static class SecurityEventContract
{
    public const string Format = "sentinelai-security-events-v1";
    public const int MaxEventsPerBatch = 256;
    public const int MaxGapsPerBatch = 32;
    public const int MaxSourcesPerBatch = 8;
    public const int MaxObservationBytes = 4 * 1024;
    public const int MaxBatchEventBytes = 192 * 1024;
    public const int MaxRequestBytes = 256 * 1024;
    public const int MaxResultBytes = 4 * 1024;
    private const long MaxUInt32 = 0xFFFFFFFF;
    private const int MaxSidLength = 184;
    private const int MaxIpLength = 45;

    private static readonly Regex SidPattern = new(@"^S-1-[0-9]{1,13}(-[0-9]{1,10}){0,15}\z",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, TimeSpan.FromMilliseconds(100));

    public static JsonSerializerOptions Json { get; } = CreateJson();

    public static IReadOnlyList<SecurityEventSelection> Catalog { get; } =
    [
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4624, SecurityEventKinds.LogonSucceeded),
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4625, SecurityEventKinds.LogonFailed),
        new(SecurityEventChannels.Security, SecurityEventProviders.SecurityAuditing, 4698, SecurityEventKinds.ScheduledTaskCreated),
        new(SecurityEventChannels.Security, SecurityEventProviders.Eventlog, 1102, SecurityEventKinds.LogCleared),
        new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7045, SecurityEventKinds.ServiceInstalled),
        new(SecurityEventChannels.System, SecurityEventProviders.ServiceControlManager, 7040, SecurityEventKinds.ProtectionServiceStartTypeChanged),
        new(SecurityEventChannels.System, SecurityEventProviders.Eventlog, 104, SecurityEventKinds.LogCleared),
        new(SecurityEventChannels.PowerShell, SecurityEventProviders.PowerShell, 4104, SecurityEventKinds.ScriptBlockFlagged),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 1116, SecurityEventKinds.MalwareDetected),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 1117, SecurityEventKinds.MalwareActionTaken),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 1118, SecurityEventKinds.MalwareActionFailed),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 1119, SecurityEventKinds.MalwareActionFailed),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5001, SecurityEventKinds.ProtectionDisabled),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5010, SecurityEventKinds.ProtectionDisabled),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5012, SecurityEventKinds.ProtectionDisabled),
        new(SecurityEventChannels.Defender, SecurityEventProviders.Defender, 5007, SecurityEventKinds.DefenderSettingChanged),
    ];

    private static readonly HashSet<SecurityEventSelection> CatalogSet = new(Catalog);

    public static bool IsValidEnvelope(SecurityEventBatch? batch)
    {
        if (batch is null || batch.EndpointId == Guid.Empty || !string.Equals(batch.Format, Format, StringComparison.Ordinal) ||
            !IsBoundedText(batch.AgentVersion, 64) || !IsUtcAfterEpoch(batch.SentUtc) || !IsUtcAfterEpoch(batch.CountersSinceUtc) ||
            batch.Sources is null || batch.Sources.Count > MaxSourcesPerBatch ||
            batch.Gaps is null || batch.Gaps.Count > MaxGapsPerBatch ||
            batch.Events is null || batch.Events.Count > MaxEventsPerBatch)
        {
            return false;
        }

        var channels = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in batch.Sources)
        {
            if (source is null || source.Channel is null || !channels.Add(source.Channel)) return false;
        }

        return batch.Gaps.All(gap => gap is not null) && batch.Events.All(observation => observation is not null);
    }

    public static SecurityEventItemValidity Classify(SecurityEventObservation? o)
    {
        if (o is null || o.Channel is null || o.Provider is null || o.Kind is null) return SecurityEventItemValidity.Invalid;
        if (!CatalogSet.Contains(new SecurityEventSelection(o.Channel, o.Provider, o.EventId, o.Kind)))
            return SecurityEventItemValidity.Unknown;
        if (o.EventVersion is < 0 or > 255 || o.Level is < 0 or > 255 || o.RecordId < 1 ||
            !IsUtcAfterEpoch(o.TimeCreatedUtc) || !HasExactlyKindPayload(o) || !PayloadIsValid(o))
        {
            return SecurityEventItemValidity.Invalid;
        }

        return MeasureBytes(o) <= MaxObservationBytes ? SecurityEventItemValidity.Valid : SecurityEventItemValidity.Invalid;
    }

    public static SecurityEventItemValidity Classify(SecurityEventGap? g)
    {
        if (g is null || g.Channel is null || g.Reason is null) return SecurityEventItemValidity.Invalid;
        if (!SecurityEventChannels.All.Contains(g.Channel, StringComparer.Ordinal) ||
            !SecurityEventGapReasons.AgentReasons.Contains(g.Reason, StringComparer.Ordinal))
        {
            return SecurityEventItemValidity.Unknown;
        }

        var ranged = g.Reason is SecurityEventGapReasons.Overwritten or SecurityEventGapReasons.Dropped;
        if (g.FirstRecordId < 1 || !IsUtcAfterEpoch(g.DetectedUtc) ||
            (ranged ? g.LastRecordId is not { } last || last < g.FirstRecordId : g.LastRecordId is not null))
        {
            return SecurityEventItemValidity.Invalid;
        }

        if (g.Reason == SecurityEventGapReasons.CoverageStarted)
        {
            return g.Cause is null || SecurityEventCoverageCauses.All.Contains(g.Cause, StringComparer.Ordinal)
                ? SecurityEventItemValidity.Valid
                : SecurityEventItemValidity.Invalid;
        }

        return g.Cause is null ? SecurityEventItemValidity.Valid : SecurityEventItemValidity.Invalid;
    }

    public static SecurityEventItemValidity Classify(SecurityEventSourceStatus? s)
    {
        if (s is null || s.Channel is null || s.State is null) return SecurityEventItemValidity.Invalid;
        if (!SecurityEventChannels.All.Contains(s.Channel, StringComparer.Ordinal) ||
            !SecurityEventSourceStates.All.Contains(s.State, StringComparer.Ordinal))
        {
            return SecurityEventItemValidity.Unknown;
        }

        long[] counters = [s.Scanned, s.Observed, s.Delivered, s.DroppedUnparsed, s.DroppedOversize,
            s.FieldsDiscarded, s.Gaps, s.SkippedRecords, s.SeekFallbacks];
        long?[] optional = [s.OldestRecordId, s.NewestRecordId, s.CheckpointRecordId, s.LogMaximumBytes];
        if (counters.Any(value => value < 0) || optional.Any(value => value is < 0) ||
            s.LastReadUtc is { } read && !IsUtcAfterEpoch(read))
        {
            return SecurityEventItemValidity.Invalid;
        }

        return SecurityEventItemValidity.Valid;
    }

    public static int MeasureBytes(SecurityEventObservation o) => JsonSerializer.SerializeToUtf8Bytes(o, Json).Length;

    /// <summary>Non-empty bounded text without surrounding whitespace, control, format or unpaired surrogate characters.</summary>
    public static bool IsBoundedText(string? v, int max)
    {
        if (string.IsNullOrEmpty(v) || v.Length > max || char.IsWhiteSpace(v[0]) || char.IsWhiteSpace(v[^1])) return false;
        for (var i = 0; i < v.Length; i++)
        {
            var c = v[i];
            if (char.IsControl(c) || CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format) return false;
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= v.Length || !char.IsLowSurrogate(v[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsValidSid(string? v)
    {
        if (v is null || v.Length > MaxSidLength) return false;
        try
        {
            return SidPattern.IsMatch(v);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public static bool IsCanonicalIp(string? v)
    {
        if (string.IsNullOrEmpty(v) || v.Length > MaxIpLength || !IPAddress.TryParse(v, out var address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && (address.ScopeId != 0 || address.IsIPv4MappedToIPv6))
            return false;
        return string.Equals(address.ToString(), v, StringComparison.Ordinal);
    }

    private static bool IsUtcAfterEpoch(DateTimeOffset value) =>
        value.Offset == TimeSpan.Zero && value > DateTimeOffset.UnixEpoch;

    private static bool HasExactlyKindPayload(SecurityEventObservation o)
    {
        object?[] payloads = [o.Logon, o.ScheduledTask, o.LogCleared, o.ServiceInstall, o.ServiceStartType,
            o.ScriptBlock, o.Malware, o.DefenderSetting];
        object? expected = o.Kind switch
        {
            SecurityEventKinds.LogonSucceeded or SecurityEventKinds.LogonFailed => o.Logon,
            SecurityEventKinds.ScheduledTaskCreated => o.ScheduledTask,
            SecurityEventKinds.LogCleared => o.LogCleared,
            SecurityEventKinds.ServiceInstalled => o.ServiceInstall,
            SecurityEventKinds.ProtectionServiceStartTypeChanged => o.ServiceStartType,
            SecurityEventKinds.ScriptBlockFlagged => o.ScriptBlock,
            SecurityEventKinds.MalwareDetected or SecurityEventKinds.MalwareActionTaken or
                SecurityEventKinds.MalwareActionFailed => o.Malware,
            SecurityEventKinds.DefenderSettingChanged => o.DefenderSetting,
            _ => null
        };

        var present = payloads.Count(payload => payload is not null);
        return o.Kind == SecurityEventKinds.ProtectionDisabled ? present == 0 : expected is not null && present == 1;
    }

    private static bool PayloadIsValid(SecurityEventObservation o) => o.Kind switch
    {
        SecurityEventKinds.LogonSucceeded => o.Logon is { } l &&
            (l.LogonType is null or 2 or 10 or 11) && NullOrSid(l.TargetUserSid) && NullOrIp(l.IpAddress) &&
            l.Status is null && l.SubStatus is null,
        SecurityEventKinds.LogonFailed => o.Logon is { } l &&
            (l.LogonType is null or (>= 0 and <= 15)) && NullOrSid(l.TargetUserSid) && NullOrIp(l.IpAddress) &&
            NullOrUInt32(l.Status) && NullOrUInt32(l.SubStatus) && l.ElevatedToken is null,
        SecurityEventKinds.ScheduledTaskCreated => o.ScheduledTask is { } t &&
            NullOrText(t.TaskName, 256) && NullOrSid(t.SubjectUserSid),
        SecurityEventKinds.LogCleared => o.LogCleared is { } c && NullOrText(c.ClearedChannel, 256),
        SecurityEventKinds.ServiceInstalled => o.ServiceInstall is { } s &&
            NullOrText(s.ServiceName, 256) && NullOrFileName(s.ImageFileName) &&
            NullOrIn(s.ImageLocation, ServiceImageLocations.All) && NullOrIn(s.ServiceType, ServiceTypes.All) &&
            NullOrIn(s.StartType, ServiceStartTypes.All) && NullOrIn(s.AccountKind, ServiceAccountKinds.All),
        SecurityEventKinds.ProtectionServiceStartTypeChanged => o.ServiceStartType is { } st &&
            NullOrIn(st.ServiceName, ProtectedServices.All) && NullOrIn(st.NewStartType, ServiceStartTypes.All),
        SecurityEventKinds.ScriptBlockFlagged => o.ScriptBlock is { } b && o.Level == 3 &&
            (b.PartCount is null or (>= 1 and <= 10000)),
        SecurityEventKinds.MalwareDetected => o.Malware is { } m && MalwareCommon(m) &&
            m.ActionId is null && m.ErrorCode is null,
        SecurityEventKinds.MalwareActionTaken => o.Malware is { } m && MalwareCommon(m) &&
            NullOrByte(m.ActionId) && m.ErrorCode is null,
        SecurityEventKinds.MalwareActionFailed => o.Malware is { } m && MalwareCommon(m) &&
            NullOrByte(m.ActionId) && NullOrUInt32(m.ErrorCode),
        SecurityEventKinds.DefenderSettingChanged => o.DefenderSetting is { } d &&
            NullOrIn(d.SettingArea, DefenderSettingAreas.All) && NullOrIn(d.Change, DefenderSettingChanges.All),
        SecurityEventKinds.ProtectionDisabled => true,
        _ => false
    };

    private static bool MalwareCommon(MalwareEvent m) =>
        m.ThreatId is null or >= 0 && NullOrText(m.ThreatName, 256) && NullOrByte(m.SeverityId) && NullOrByte(m.CategoryId);

    private static bool NullOrSid(string? v) => v is null || IsValidSid(v);
    private static bool NullOrIp(string? v) => v is null || IsCanonicalIp(v);
    private static bool NullOrText(string? v, int max) => v is null || IsBoundedText(v, max);
    private static bool NullOrUInt32(long? v) => v is null or (>= 0 and <= MaxUInt32);
    private static bool NullOrByte(int? v) => v is null or (>= 0 and <= 255);
    private static bool NullOrIn(string? v, IReadOnlyList<string> vocabulary) =>
        v is null || vocabulary.Contains(v, StringComparer.Ordinal);

    private static bool NullOrFileName(string? v) =>
        v is null || IsBoundedText(v, 128) && v.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) < 0;

    private static JsonSerializerOptions CreateJson()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            NumberHandling = JsonNumberHandling.Strict,
            AllowDuplicateProperties = false,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            MaxDepth = 8
        };
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
