namespace SentinelAI.Scoring;

public sealed record ScoringAlert(
    Guid AlertId, string RuleId, string Severity, string Status, DateTimeOffset LastObservedUtc);

/// <summary>Asset/exposure labels are operator declarations or explicit policy defaults, never inferred from posture.</summary>
public sealed record EndpointScoringContext(
    string AssetCriticality = "standard",
    string Exposure = "unknown",
    DateTimeOffset? LatestInventoryUtc = null,
    string AssetCriticalitySource = "policyDefault",
    string ExposureSource = "policyDefault");

public sealed record AlertRiskContribution(
    Guid AlertId,
    string RuleId,
    string Severity,
    string Status,
    DateTimeOffset LastObservedUtc,
    decimal AgeDays,
    string AgeBand,
    bool FutureTimestampClamped,
    decimal SeverityPoints,
    decimal DetectionConfidence,
    string ConfidenceSource,
    decimal AssetCriticalityMultiplier,
    decimal ExposureMultiplier,
    decimal AgeMultiplier,
    decimal RemainingRiskMultiplier,
    decimal PointsBeforeMitigation,
    decimal MitigationReduction,
    decimal Contribution,
    string? CorrelationGroup,
    bool LatestSnapshotConfirmed,
    bool CorrelationEligible);

public sealed record EndpointRiskScore(
    Guid EndpointId,
    int Score,
    decimal RawScore,
    bool Saturated,
    DateTimeOffset CalculatedUtc,
    EndpointScoringContext Context,
    decimal AssetCriticalityMultiplier,
    decimal ExposureMultiplier,
    IReadOnlyList<AlertRiskContribution> Contributions,
    IReadOnlyList<string> CorrelatedGroups,
    decimal CorrelationBaseBonus,
    decimal CorrelationBonus,
    string Explanation);

public sealed record OrganizationRiskScore(
    int Score,
    int EndpointCount,
    IReadOnlyList<Guid> HighestRiskEndpointIds,
    int HighestRiskEndpointCount,
    bool HighestRiskEndpointIdsTruncated,
    string Method,
    string Explanation);
