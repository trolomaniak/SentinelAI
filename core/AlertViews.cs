using SentinelAI.Rules;

namespace SentinelAI.Core;

public sealed record AlertListItem(
    Guid AlertId,
    Guid EndpointId,
    string EndpointName,
    string RuleId,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset FirstObservedUtc,
    DateTimeOffset LastObservedUtc,
    DateTimeOffset UpdatedUtc,
    long Version);

public sealed record AlertDetail(
    Guid AlertId,
    Guid EndpointId,
    string EndpointName,
    string RuleId,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset FirstObservedUtc,
    DateTimeOffset LastObservedUtc,
    DateTimeOffset UpdatedUtc,
    long Version,
    string Reason,
    IReadOnlyList<RuleEvidence> Evidence,
    string RecommendedAction,
    DateTimeOffset CreatedUtc,
    DateTimeOffset StatusChangedUtc,
    IReadOnlyList<AlertStatusChange> StatusHistory,
    long StatusHistoryCount);

public sealed record AlertStatusChange(
    string? PreviousStatus,
    string Status,
    DateTimeOffset ChangedUtc,
    string ChangedBy);

public sealed record AlertPage(IReadOnlyList<AlertListItem> Alerts, long Total, int Offset, int Limit);

public sealed record UpdateAlertStatusRequest(string? Status, long ExpectedVersion);

public sealed record IncidentExport(string Format, DateTimeOffset GeneratedAtUtc,
    IReadOnlyList<AlertDetail> Incidents, long Total, int Offset, int Limit);
