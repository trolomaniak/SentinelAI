using SentinelAI.Scoring;

namespace SentinelAI.Desktop.Foundation;

// Public Core projections reuse its immutable scoring records. Desktop never
// recomputes scores or guesses missing/historical observations.
public sealed record RiskCoverage(string InventoryState, string SignalCoverage,
    int KnownRuleSignals, int TotalRuleSignals, string Caution);
public sealed record RiskAlertView(Guid AlertId, string RuleId, string Title, string Severity,
    string Status, DateTimeOffset LastObservedUtc, string Reason);
public sealed record EndpointRiskDetail(Guid EndpointId, string EndpointName,
    DateTimeOffset? InventoryCollectedUtc, EndpointRiskScore Risk, RiskCoverage Coverage,
    IReadOnlyList<RiskAlertView> Alerts, ScoringPolicySnapshot Policy, int InventoryFreshForHours);
public sealed record EndpointRiskSummary(Guid EndpointId, string EndpointName,
    DateTimeOffset? InventoryCollectedUtc, int Score, decimal RawScore, RiskCoverage Coverage,
    int UnresolvedAlertCount, string HighestContributorReason, DateTimeOffset EvaluatedUtc);
public sealed record RiskAlertStatusCounts(int Open, int Investigating, int Accepted, int Resolved);
public sealed record OrganizationRiskView(int Score, int EndpointCount,
    IReadOnlyList<Guid> HighestRiskEndpointIds, int HighestRiskEndpointCount,
    bool HighestRiskEndpointIdsTruncated, string Method, string Explanation,
    DateTimeOffset EvaluatedUtc, int ObservedEndpointCount, int MissingInventoryCount,
    int UnknownSignalCount, int PartialSignalCount, int StaleInventoryCount,
    RiskAlertStatusCounts AlertStatusCounts);
public sealed record RiskPage(OrganizationRiskView Organization,
    IReadOnlyList<EndpointRiskSummary> Endpoints, long Total, int Offset, int Limit,
    ScoringPolicySnapshot Policy, int InventoryFreshForHours);

public enum RiskReadOutcome
{
    Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, NotFound, TooLarge
}
public sealed record RiskReadResult<T>(RiskReadOutcome Outcome, T? Value = default);
public interface IRiskClient
{
    Task<RiskReadResult<RiskPage>> GetRiskPageAsync(int offset, int limit, CancellationToken cancellationToken);
    Task<RiskReadResult<EndpointRiskDetail>> GetEndpointRiskDetailAsync(Guid endpointId, CancellationToken cancellationToken);
}
