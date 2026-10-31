using System.Globalization;
using SentinelAI.Scoring;
using static SentinelAI.Localization.Localizer;

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
        Explanation = T(organization.Explanation);
        Facts = RiskText.Facts(
            new(T("Organization score"), RiskText.Number(Score)),
            new(T("Endpoints"), RiskText.Number(organization.EndpointCount)),
            new(T("Observed endpoints"), RiskText.Number(organization.ObservedEndpointCount)),
            new(T("Missing inventory"), RiskText.Number(organization.MissingInventoryCount)),
            new(T("Unknown signal coverage"), RiskText.Number(organization.UnknownSignalCount)),
            new(T("Partial signal coverage"), RiskText.Number(organization.PartialSignalCount)),
            new(T("Stale inventory"), RiskText.Number(organization.StaleInventoryCount)),
            new(T("Open alerts"), RiskText.Number(organization.AlertStatusCounts.Open)),
            new(T("Investigating alerts"), RiskText.Number(organization.AlertStatusCounts.Investigating)),
            new(T("Accepted alerts"), RiskText.Number(organization.AlertStatusCounts.Accepted)),
            new(T("Resolved alerts"), RiskText.Number(organization.AlertStatusCounts.Resolved)),
            new(T("Highest-risk endpoint count"), RiskText.Number(organization.HighestRiskEndpointCount)),
            new("Highest-risk endpoint IDs", RiskText.Join(organization.HighestRiskEndpointIds.Select(id => id.ToString("D")))),
            new(T("Highest-risk IDs truncated"), organization.HighestRiskEndpointIdsTruncated.ToString()),
            new(T("Method"), T(organization.Method)),
            new(T("Evaluated"), RiskText.Timestamp(organization.EvaluatedUtc)),
            new(T("Score interpretation"), RiskText.Interpretation));
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
        Title = alert?.Title is { } title ? T(title) : T("Unknown / not reported");
        Reason = alert?.Reason is { } reason ? T(reason) : T("Unknown / not reported");
        Factors = RiskText.Facts(
            new(T("Alert ID"), AlertId.ToString("D")),
            new(T("Rule ID"), RuleId),
            new(T("Title"), Title),
            new(T("Reason"), Reason),
            new(T("Severity"), Severity),
            new(T("Status"), Status),
            new(T("Last positive observation"), LastObservedText),
            new(T("Age (days)"), RiskText.Number(Source.AgeDays)),
            new(T("Age band"), Source.AgeBand),
            new(T("Future timestamp clamped"), Source.FutureTimestampClamped.ToString()),
            new(T("Severity points"), RiskText.Number(Source.SeverityPoints)),
            new(T("Confidence weight"), RiskText.Number(Source.DetectionConfidence)),
            new(T("Confidence source"), Source.ConfidenceSource),
            new(T("Asset multiplier"), RiskText.Number(Source.AssetCriticalityMultiplier)),
            new(T("Exposure multiplier"), RiskText.Number(Source.ExposureMultiplier)),
            new(T("Age multiplier"), RiskText.Number(Source.AgeMultiplier)),
            new(T("Remaining risk multiplier"), RiskText.Number(Source.RemainingRiskMultiplier)),
            new(T("Points before status effect"), RiskText.Number(Source.PointsBeforeMitigation)),
            new(T("Status reduction"), RiskText.Number(Source.MitigationReduction)),
            new(T("Contribution"), ContributionText),
            new(T("Correlation group"), Source.CorrelationGroup ?? T("None")),
            new(T("Latest snapshot confirmed"), Source.LatestSnapshotConfirmed.ToString()),
            new(T("Correlation eligible"), Source.CorrelationEligible.ToString()));
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
        Explanation = T(detail.Risk.Explanation);
        var risk = detail.Risk;
        Facts = RiskText.Facts(
            new(T("Endpoint"), Name),
            new(T("Endpoint ID"), EndpointId.ToString("D")),
            new(T("Endpoint score"), RiskText.Number(Score)),
            new(T("Raw score"), RiskText.Number(RawScore)),
            new(T("Saturated"), Saturated.ToString()),
            new(T("Evaluated"), RiskText.Timestamp(risk.CalculatedUtc)),
            new(T("Asset criticality"), risk.Context.AssetCriticality),
            new(T("Asset criticality source"), risk.Context.AssetCriticalitySource),
            new(T("Asset criticality multiplier"), RiskText.Number(risk.AssetCriticalityMultiplier)),
            new(T("Declared exposure"), risk.Context.Exposure),
            new(T("Exposure source"), risk.Context.ExposureSource),
            new(T("Exposure multiplier"), RiskText.Number(risk.ExposureMultiplier)),
            new(T("Correlation groups"), RiskText.Join(risk.CorrelatedGroups)),
            new(T("Correlation base bonus"), RiskText.Number(risk.CorrelationBaseBonus)),
            new(T("Correlation bonus"), RiskText.Number(risk.CorrelationBonus)),
            new(T("Latest scoring inventory"), RiskText.Timestamp(risk.Context.LatestInventoryUtc)),
            new(T("Score interpretation"), RiskText.Interpretation));
        CoverageFacts = RiskText.Facts(
            new(T("Inventory state"), detail.Coverage.InventoryState),
            new(T("Signal coverage"), detail.Coverage.SignalCoverage),
            new(T("Known rule signals"), RiskText.Number(detail.Coverage.KnownRuleSignals)),
            new(T("Total rule signals"), RiskText.Number(detail.Coverage.TotalRuleSignals)),
            new(T("Inventory collected"), RiskText.Timestamp(detail.InventoryCollectedUtc)),
            new(T("Inventory freshness (hours)"), RiskText.Number(detail.InventoryFreshForHours)),
            new(T("Coverage caution"), T(detail.Coverage.Caution)));
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
        return text.Length == 0 ? T("None") : text;
    }
    internal static IReadOnlyList<DisplayFact> Facts(params DisplayFact[] facts) => Array.AsReadOnly(facts);
    internal static IReadOnlyList<DisplayFact> PolicyFacts(ScoringPolicySnapshot policy, int inventoryFreshForHours)
    {
        var facts = new List<DisplayFact>
        {
            new(T("Policy version"), policy.Version),
            new(T("Maximum score"), Number(policy.MaximumScore)),
            new(T("Inventory freshness (hours)"), Number(inventoryFreshForHours)),
            new(T("Fresh observation age (days)"), Number(policy.FreshForDays)),
            new(T("Aging observation age (days)"), Number(policy.AgingForDays)),
            new(T("Aging multiplier"), Number(policy.AgingMultiplier)),
            new(T("Old multiplier"), Number(policy.OldMultiplier)),
            new(T("Default confidence weight"), Number(policy.DefaultConfidence)),
            new(T("Correlation points per extra group"), Number(policy.CorrelationPointsPerExtraGroup)),
            new(T("Maximum correlation base bonus"), Number(policy.MaximumCorrelationBaseBonus))
        };
        Add(T("Severity points"), policy.SeverityPoints);
        Add(T("Confidence override"), policy.ConfidenceByRule);
        Add(T("Asset multiplier"), policy.AssetMultipliers);
        Add(T("Exposure multiplier"), policy.ExposureMultipliers);
        Add(T("Remaining risk"), policy.RemainingRiskByStatus);
        facts.AddRange(policy.CorrelationGroupsByRule.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new DisplayFact(F("Correlation group: {0}", pair.Key), T(pair.Value))));
        return Array.AsReadOnly(facts.ToArray());

        void Add(string label, IReadOnlyDictionary<string, decimal> values) =>
            facts.AddRange(values.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new DisplayFact($"{label}: {pair.Key}", Number(pair.Value))));
    }
}
