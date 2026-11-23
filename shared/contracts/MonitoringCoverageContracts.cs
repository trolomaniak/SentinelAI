namespace SentinelAI.Contracts.Monitoring;

public static class MonitoringCoverageContract
{
    public const int MaximumPageSize = 100;
    public const int MaximumOffset = 100_000;
    public const int MaximumResponseBytes = 256 * 1024;
    public const int HeartbeatWarningMinutes = 2;
    public const int HeartbeatOfflineMinutes = 5;
    public const int TelemetryFreshHours = 3;
    public const int EventFreshHours = 2;
    public static IReadOnlyList<string> TelemetrySourceIds { get; } = Array.AsReadOnly(new[]
    {
        "bitLocker", "antivirus", "defender", "localAdministrators", "windowsUpdatePolicy", "windowsUpdateResults",
        "pendingReboot", "services", "software"
    });
}

public sealed record MonitoringEndpointSummary(Guid EndpointId, string Name, string HeartbeatState,
    DateTimeOffset? LastHeartbeatUtc, string InventoryFreshness, DateTimeOffset? InventoryCollectedUtc,
    string TelemetryFreshness, DateTimeOffset? TelemetryCollectedUtc, DateTimeOffset? TelemetryReceivedUtc,
    int CurrentTelemetrySources, int CurrentEventChannels, bool HasRetainedGaps, bool HasIssue);

public sealed record MonitoringEndpointPage(DateTimeOffset GeneratedUtc, int Total, int Matching, int Offset, int Limit,
    int InventoryFreshHours, IReadOnlyList<MonitoringEndpointSummary> Items);

// State is what the last report said. Freshness separately describes whether Core can still use it as current.
public sealed record MonitoringTelemetrySource(string SourceId, string State, string Freshness);
public sealed record MonitoringEventChannel(string Channel, string State, string Freshness,
    DateTimeOffset? ReportedUtc, DateTimeOffset? LastReadUtc, DateTimeOffset? FirstCheckpointUtc,
    long? CheckpointRecordId, DateTimeOffset? CountersSinceUtc, long? ReportedGaps, long? SkippedRecords,
    long? DroppedUnparsed, long? DroppedOversize);
public sealed record MonitoringEndpointDetail(DateTimeOffset GeneratedUtc, MonitoringEndpointSummary Endpoint,
    int InventoryFreshHours, int GapRetentionDays, IReadOnlyList<MonitoringTelemetrySource> Telemetry,
    IReadOnlyList<MonitoringEventChannel> EventChannels);

public sealed record MonitoringCoverageGap(string Channel, string Reason, string? Cause, long FirstRecordId,
    long? LastRecordId, DateTimeOffset DetectedUtc, DateTimeOffset ReceivedUtc, bool CoverageRestart);
public sealed record MonitoringGapPage(DateTimeOffset GeneratedUtc, Guid EndpointId, int Total, int Offset, int Limit,
    int RetentionDays, IReadOnlyList<MonitoringCoverageGap> Items);
