using System.Globalization;
using SentinelAI.Scoring;

namespace SentinelAI.Desktop.Foundation;

/// <summary>One Core-ranked endpoint. Rank follows server order; no client scoring or sorting occurs.</summary>
public sealed class EndpointRiskRow
{
    public EndpointRiskRow(EndpointRiskSummary endpoint, long rank)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        Summary = endpoint;
        Rank = rank;
    }

    internal EndpointRiskSummary Summary { get; }
    public long Rank { get; }
    public Guid EndpointId => Summary.EndpointId;
    public string EndpointName => Summary.EndpointName;
    public int Score => Summary.Score;
    public decimal RawScore => Summary.RawScore;
    public string RawScoreText => RiskText.Number(RawScore);
    public string InventoryState => Summary.Coverage.InventoryState;
    public string SignalCoverage => Summary.Coverage.SignalCoverage;
    public string InventoryCollectedText => RiskText.Timestamp(Summary.InventoryCollectedUtc);
    public int UnresolvedAlertCount => Summary.UnresolvedAlertCount;
    public string HighestContributorReason => Summary.HighestContributorReason;
    public string EvaluatedText => RiskText.Timestamp(Summary.EvaluatedUtc);
}

/// <summary>Literal organization explanation, coverage, status counts and the policy used by Core.</summary>
public sealed class OrganizationRiskPresentation
{
    public OrganizationRiskPresentation(RiskPage page)
    {
        ArgumentNullException.ThrowIfNull(page);
        var organization = page.Organization;
        Score = organization.Score;
        Explanation = organization.Explanation;
        Facts = RiskText.Facts(
            new("Organization score", RiskText.Number(Score)),
            new("Endpoints", RiskText.Number(organization.EndpointCount)),
            new("Observed endpoints", RiskText.Number(organization.ObservedEndpointCount)),
            new("Missing inventory", RiskText.Number(organization.MissingInventoryCount)),
            new("Unknown signal coverage", RiskText.Number(organization.UnknownSignalCount)),
            new("Partial signal coverage", RiskText.Number(organization.PartialSignalCount)),
            new("Stale inventory", RiskText.Number(organization.StaleInventoryCount)),
            new("Open alerts", RiskText.Number(organization.AlertStatusCounts.Open)),
            new("Investigating alerts", RiskText.Number(organization.AlertStatusCounts.Investigating)),
            new("Accepted alerts", RiskText.Number(organization.AlertStatusCounts.Accepted)),
            new("Resolved alerts", RiskText.Number(organization.AlertStatusCounts.Resolved)),
            new("Highest-risk endpoint count", RiskText.Number(organization.HighestRiskEndpointCount)),
            new("Highest-risk endpoint IDs", RiskText.Join(organization.HighestRiskEndpointIds.Select(id => id.ToString("D")))),
            new("Highest-risk IDs truncated", organization.HighestRiskEndpointIdsTruncated.ToString()),
            new("Method", organization.Method),
            new("Evaluated", RiskText.Timestamp(organization.EvaluatedUtc)),
            new("Score interpretation", RiskText.Interpretation));
        PolicyFacts = RiskText.PolicyFacts(page.Policy, page.InventoryFreshForHours);
    }

    public int Score { get; }
    public string Explanation { get; }
    public IReadOnlyList<DisplayFact> Facts { get; }
    public IReadOnlyList<DisplayFact> PolicyFacts { get; }
}

/// <summary>All deterministic factors supplied by Core, with the public alert's literal title/reason.</summary>
public sealed class RiskContributionRow
{
    public RiskContributionRow(AlertRiskContribution contribution, RiskAlertView? alert)
    {
        ArgumentNullException.ThrowIfNull(contribution);
        Source = contribution;
        Title = alert?.Title ?? "Unknown / not reported";
        Reason = alert?.Reason ?? "Unknown / not reported";
        Factors = RiskText.Facts(
            new("Alert ID", AlertId.ToString("D")),
            new("Rule ID", RuleId),
            new("Title", Title),
            new("Reason", Reason),
            new("Severity", Severity),
            new("Status", Status),
            new("Last positive observation", LastObservedText),
            new("Age (days)", RiskText.Number(Source.AgeDays)),
            new("Age band", Source.AgeBand),
            new("Future timestamp clamped", Source.FutureTimestampClamped.ToString()),
            new("Severity points", RiskText.Number(Source.SeverityPoints)),
            new("Confidence weight", RiskText.Number(Source.DetectionConfidence)),
            new("Confidence source", Source.ConfidenceSource),
            new("Asset multiplier", RiskText.Number(Source.AssetCriticalityMultiplier)),
            new("Exposure multiplier", RiskText.Number(Source.ExposureMultiplier)),
            new("Age multiplier", RiskText.Number(Source.AgeMultiplier)),
            new("Remaining risk multiplier", RiskText.Number(Source.RemainingRiskMultiplier)),
            new("Points before status effect", RiskText.Number(Source.PointsBeforeMitigation)),
            new("Status reduction", RiskText.Number(Source.MitigationReduction)),
            new("Contribution", ContributionText),
            new("Correlation group", Source.CorrelationGroup ?? "None"),
            new("Latest snapshot confirmed", Source.LatestSnapshotConfirmed.ToString()),
            new("Correlation eligible", Source.CorrelationEligible.ToString()));
    }

    public AlertRiskContribution Source { get; }
    public Guid AlertId => Source.AlertId;
    public string RuleId => Source.RuleId;
    public string Title { get; }
    public string Reason { get; }
    public string Severity => Source.Severity;
    public string Status => Source.Status;
    public string LastObservedText => RiskText.Timestamp(Source.LastObservedUtc);
    public decimal Contribution => Source.Contribution;
    public string ContributionText => RiskText.Number(Contribution);
    public IReadOnlyList<DisplayFact> Factors { get; }
}

/// <summary>Read-only endpoint risk explanation; decimals and Core's saturation/context are preserved.</summary>
public sealed class EndpointRiskPresentation
{
    public EndpointRiskPresentation(EndpointRiskDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        EndpointId = detail.EndpointId;
        Name = detail.EndpointName;
        Score = detail.Risk.Score;
        RawScore = detail.Risk.RawScore;
        Saturated = detail.Risk.Saturated;
        Explanation = detail.Risk.Explanation;
        var risk = detail.Risk;
        Facts = RiskText.Facts(
            new("Endpoint", Name),
            new("Endpoint ID", EndpointId.ToString("D")),
            new("Endpoint score", RiskText.Number(Score)),
            new("Raw score", RiskText.Number(RawScore)),
            new("Saturated", Saturated.ToString()),
            new("Evaluated", RiskText.Timestamp(risk.CalculatedUtc)),
            new("Asset criticality", risk.Context.AssetCriticality),
            new("Asset criticality source", risk.Context.AssetCriticalitySource),
            new("Asset criticality multiplier", RiskText.Number(risk.AssetCriticalityMultiplier)),
            new("Declared exposure", risk.Context.Exposure),
            new("Exposure source", risk.Context.ExposureSource),
            new("Exposure multiplier", RiskText.Number(risk.ExposureMultiplier)),
            new("Correlation groups", RiskText.Join(risk.CorrelatedGroups)),
            new("Correlation base bonus", RiskText.Number(risk.CorrelationBaseBonus)),
            new("Correlation bonus", RiskText.Number(risk.CorrelationBonus)),
            new("Latest scoring inventory", RiskText.Timestamp(risk.Context.LatestInventoryUtc)),
            new("Score interpretation", RiskText.Interpretation));
        CoverageFacts = RiskText.Facts(
            new("Inventory state", detail.Coverage.InventoryState),
            new("Signal coverage", detail.Coverage.SignalCoverage),
            new("Known rule signals", RiskText.Number(detail.Coverage.KnownRuleSignals)),
            new("Total rule signals", RiskText.Number(detail.Coverage.TotalRuleSignals)),
            new("Inventory collected", RiskText.Timestamp(detail.InventoryCollectedUtc)),
            new("Inventory freshness (hours)", RiskText.Number(detail.InventoryFreshForHours)),
            new("Coverage caution", detail.Coverage.Caution));
        PolicyFacts = RiskText.PolicyFacts(detail.Policy, detail.InventoryFreshForHours);
        var alerts = detail.Alerts.ToDictionary(alert => alert.AlertId);
        Contributions = Array.AsReadOnly(risk.Contributions.Select(contribution =>
            new RiskContributionRow(contribution, alerts.GetValueOrDefault(contribution.AlertId))).ToArray());
    }

    public Guid EndpointId { get; }
    public string Name { get; }
    public int Score { get; }
    public decimal RawScore { get; }
    public bool Saturated { get; }
    public string Explanation { get; }
    public IReadOnlyList<DisplayFact> Facts { get; }
    public IReadOnlyList<DisplayFact> CoverageFacts { get; }
    public IReadOnlyList<DisplayFact> PolicyFacts { get; }
    public IReadOnlyList<RiskContributionRow> Contributions { get; }
}

internal static class RiskText
{
    internal const string Interpretation = "Scores prioritize reported findings. A zero score does not establish effective protection or telemetry completeness.";
    internal static string Number(decimal value) => value.ToString(CultureInfo.InvariantCulture);
    internal static string Timestamp(DateTimeOffset? value) => value?.ToUniversalTime()
        .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? "Unknown / not reported";
    internal static string Join(IEnumerable<string> values)
    {
        var text = string.Join(", ", values);
        return text.Length == 0 ? "None" : text;
    }
    internal static IReadOnlyList<DisplayFact> Facts(params DisplayFact[] facts) => Array.AsReadOnly(facts);
    internal static IReadOnlyList<DisplayFact> PolicyFacts(ScoringPolicySnapshot policy, int inventoryFreshForHours)
    {
        var facts = new List<DisplayFact>
        {
            new("Policy version", policy.Version),
            new("Maximum score", Number(policy.MaximumScore)),
            new("Inventory freshness (hours)", Number(inventoryFreshForHours)),
            new("Fresh observation age (days)", Number(policy.FreshForDays)),
            new("Aging observation age (days)", Number(policy.AgingForDays)),
            new("Aging multiplier", Number(policy.AgingMultiplier)),
            new("Old multiplier", Number(policy.OldMultiplier)),
            new("Default confidence weight", Number(policy.DefaultConfidence)),
            new("Correlation points per extra group", Number(policy.CorrelationPointsPerExtraGroup)),
            new("Maximum correlation base bonus", Number(policy.MaximumCorrelationBaseBonus))
        };
        Add("Severity points", policy.SeverityPoints);
        Add("Confidence override", policy.ConfidenceByRule);
        Add("Asset multiplier", policy.AssetMultipliers);
        Add("Exposure multiplier", policy.ExposureMultipliers);
        Add("Remaining risk", policy.RemainingRiskByStatus);
        facts.AddRange(policy.CorrelationGroupsByRule.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new DisplayFact($"Correlation group: {pair.Key}", pair.Value)));
        return Array.AsReadOnly(facts.ToArray());

        void Add(string label, IReadOnlyDictionary<string, decimal> values) =>
            facts.AddRange(values.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new DisplayFact($"{label}: {pair.Key}", Number(pair.Value))));
    }
}
