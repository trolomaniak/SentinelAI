namespace SentinelAI.Contracts.DefenderDetections;

/// <summary>
/// A bounded page of retained Microsoft Defender events. Events describe what Defender
/// reported at the recorded time; they are not a current active-infection verdict.
/// </summary>
public sealed record DefenderDetectionsView(
    Guid EndpointId,
    DateTimeOffset GeneratedUtc,
    string SourceState,
    DateTimeOffset? SourceReportedUtc,
    DateTimeOffset? LastReadUtc,
    int RetentionDays,
    int Offset,
    int Limit,
    int TotalCount,
    IReadOnlyList<DefenderDetection> Detections)
{
    public override string ToString() => nameof(DefenderDetectionsView);
}

/// <summary>Only already-collected, typed malware metadata; no paths, users or raw event text.</summary>
public sealed record DefenderDetection(
    DateTimeOffset TimeCreatedUtc,
    DateTimeOffset ReceivedUtc,
    int EventId,
    string Kind,
    Guid? DetectionId,
    long? ThreatId,
    string? ThreatName,
    int? SeverityId,
    int? CategoryId,
    int? ActionId,
    long? ErrorCode)
{
    public override string ToString() => nameof(DefenderDetection);
}

public static class DefenderDetectionContract
{
    public const int DefaultLimit = 50;
    public const int MaximumLimit = 100;
    public const int MaximumOffset = 10_000;
    public const string NotReported = "notReported";
}
