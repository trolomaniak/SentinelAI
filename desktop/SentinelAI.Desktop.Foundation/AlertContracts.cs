namespace SentinelAI.Desktop.Foundation;

/// <summary>Public tracked-alert fields only; Core owns lifecycle and versions.</summary>
public sealed record AlertSummary(Guid AlertId, Guid EndpointId, string EndpointName,
    string RuleId, string Title, string Severity, string Status,
    DateTimeOffset FirstObservedUtc, DateTimeOffset LastObservedUtc,
    DateTimeOffset UpdatedUtc, long Version);

public enum AlertEvidenceKind { Unknown, Boolean, Integer, String }

public sealed record AlertEvidence(string Field, AlertEvidenceKind Kind,
    bool? BooleanValue = null, long? IntegerValue = null, string? StringValue = null);

public sealed record AlertStatusChange(string? PreviousStatus, string Status,
    DateTimeOffset ChangedUtc, string ChangedBy);

public sealed record AlertDetail(AlertSummary Alert, string Reason,
    IReadOnlyList<AlertEvidence> Evidence, string RecommendedAction,
    DateTimeOffset CreatedUtc, DateTimeOffset StatusChangedUtc,
    IReadOnlyList<AlertStatusChange> StatusHistory, long StatusHistoryCount);

public sealed record AlertQuery(Guid? EndpointId = null, string? Severity = null,
    string? Status = null, int Offset = 0, int Limit = 50);

public sealed record AlertPage(IReadOnlyList<AlertSummary> Alerts, long Total, int Offset, int Limit);

public enum AlertOutcome
{
    Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse,
    NotFound, TooLarge, Conflict, Indeterminate
}

public sealed record AlertResult<T>(AlertOutcome Outcome, T? Value = default);

/// <summary>Authenticated public API; writes always include the reviewed version.</summary>
public interface IAlertsClient
{
    Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken cancellationToken);
    Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken cancellationToken);
    Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status,
        long expectedVersion, CancellationToken cancellationToken);
}
