namespace SentinelAI.Desktop.Foundation;

// TASK-032: the Risk Register as Core reports it. Records are administrators' business judgements; Core validates and
// versions them and keeps their history. They never change alerts, detection or the technical endpoint score.
public sealed record RiskRegisterRating(int Likelihood, int Impact, int Score, string Level);

public sealed record RiskRegisterFlags(bool ReviewOverdue, bool AcceptanceExpired, bool TargetDatePassed, bool NeedsAttention);

public sealed record RiskRegisterSummary(Guid RiskId, string Reference, string Title, string Status, string? Treatment, string? Owner,
    RiskRegisterRating Inherent, RiskRegisterRating Residual, string? ReviewDate, string? TargetDate, string? AcceptanceExpiresOn,
    RiskRegisterFlags Flags, int EndpointCount, int AlertCount, long Version, DateTimeOffset UpdatedUtc);

public sealed record RiskRegisterCounts(int Open, int Monitoring, int Closed, int NeedsAttention);

public sealed record RiskRegisterPage(IReadOnlyList<RiskRegisterSummary> Records, long Total, int Offset, int Limit, RiskRegisterCounts Counts,
    string Today);

public sealed record RiskRegisterLinkedEndpoint(Guid EndpointId, string? Name, bool Enrolled);

public sealed record RiskRegisterLinkedAlert(Guid AlertId, bool Exists, Guid? EndpointId, string? EndpointName, string? RuleId, string? Title,
    string? Severity, string? Status);

public sealed record RiskRegisterFieldChange(string Field, string? From, string? To);

public sealed record RiskRegisterHistoryEntry(long Version, DateTimeOffset ChangedUtc, string ChangedBy, string Action,
    IReadOnlyList<RiskRegisterFieldChange> Changes, string? Note);

public sealed record RiskRegisterDetail(Guid RiskId, string Reference, string Title, string? Description, string? Owner, RiskRegisterRating Inherent,
    string? Controls, RiskRegisterRating Residual, string? Treatment, string? AcceptanceRationale, string? AcceptanceExpiresOn, string? TargetDate,
    string? ReviewDate, string Status, RiskRegisterFlags Flags, IReadOnlyList<RiskRegisterLinkedEndpoint> Endpoints,
    IReadOnlyList<RiskRegisterLinkedAlert> Alerts, IReadOnlyList<string> Tickets, DateTimeOffset CreatedUtc, string CreatedBy, DateTimeOffset UpdatedUtc,
    string UpdatedBy, DateTimeOffset? LastReviewedUtc, string? LastReviewedBy, long Version, IReadOnlyList<RiskRegisterHistoryEntry> History,
    string Today);

/// <summary>A field Core refused and why, as stable codes Desktop words for the administrator.</summary>
public sealed record RiskRegisterError(string Field, string Code);

/// <summary>What an administrator saves. Dates are <c>yyyy-MM-dd</c>.</summary>
public sealed record RiskRegisterDraft(string Title, string? Description, string? Owner, int Likelihood, int Impact, string? Controls,
    int ResidualLikelihood, int ResidualImpact, string? Treatment, string? AcceptanceRationale, string? AcceptanceExpiresOn, string? TargetDate,
    string? ReviewDate, string Status, IReadOnlyList<Guid> EndpointIds, IReadOnlyList<Guid> AlertIds, IReadOnlyList<string> Tickets, string? Note);

/// <summary>Status <c>active</c> is every record that is not closed; <c>null</c> is every record.</summary>
public sealed record RiskRegisterQuery(string? Status = "active", string? Treatment = null, string? Level = null, bool AttentionOnly = false,
    Guid? EndpointId = null, Guid? AlertId = null, int Offset = 0, int Limit = 50);

public enum RiskRegisterOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge, NotFound, Conflict, Rejected }

public sealed record RiskRegisterResult<T>(RiskRegisterOutcome Outcome, T? Value = default, IReadOnlyList<RiskRegisterError>? Errors = null)
    where T : class;

public interface IRiskRegisterClient
{
    Task<RiskRegisterResult<RiskRegisterPage>> GetRiskRegisterAsync(RiskRegisterQuery query, CancellationToken cancellationToken);
    Task<RiskRegisterResult<RiskRegisterDetail>> GetRiskRecordAsync(Guid riskId, CancellationToken cancellationToken);
    /// <summary>Rejected carries Core's field errors; a lost answer is Unavailable and is never retried automatically.</summary>
    Task<RiskRegisterResult<RiskRegisterDetail>> CreateRiskRecordAsync(RiskRegisterDraft draft, CancellationToken cancellationToken);
    /// <summary>Conflict when the record changed since <paramref name="expectedVersion"/>.</summary>
    Task<RiskRegisterResult<RiskRegisterDetail>> UpdateRiskRecordAsync(Guid riskId, long expectedVersion, RiskRegisterDraft draft,
        CancellationToken cancellationToken);
    Task<RiskRegisterResult<RiskRegisterDetail>> ReviewRiskRecordAsync(Guid riskId, long expectedVersion, string nextReviewDate, string? note,
        CancellationToken cancellationToken);
}
