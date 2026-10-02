namespace SentinelAI.Scoring;

/// <summary>Pure deterministic scoring: time, endpoint context and tracked alerts are explicit inputs.</summary>
public sealed class RiskScorer
{
    public ScoringPolicySnapshot Policy { get; }

    public RiskScorer(ScoringPolicy? policy = null) => Policy = (policy ?? new ScoringPolicy()).Snapshot();

    public void ValidateContext(EndpointScoringContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.AssetCriticality is null || !Policy.AssetMultipliers.ContainsKey(context.AssetCriticality))
            throw new ArgumentException("Unknown asset criticality; expected low, standard, high or critical.", nameof(context));
        if (context.Exposure is null || !Policy.ExposureMultipliers.ContainsKey(context.Exposure))
            throw new ArgumentException("Unknown exposure; expected isolated, internal, internet or unknown.", nameof(context));
        if (!ValidSource(context.AssetCriticalitySource) || !ValidSource(context.ExposureSource))
            throw new ArgumentException("Context sources must be policyDefault or userDeclared.", nameof(context));
    }

    public EndpointRiskScore ScoreEndpoint(Guid endpointId, IEnumerable<ScoringAlert> alerts,
        EndpointScoringContext context, DateTimeOffset now)
    {
        if (endpointId == Guid.Empty)
            throw new ArgumentException("Endpoint ID must not be empty.", nameof(endpointId));
        ArgumentNullException.ThrowIfNull(alerts);
        ValidateContext(context);
        var snapshot = alerts.ToArray();
        if (snapshot.Any(alert => alert is null || alert.AlertId == Guid.Empty || string.IsNullOrWhiteSpace(alert.RuleId)))
            throw new ArgumentException("Every scoring alert requires a nonempty ID and rule ID.", nameof(alerts));
        if (snapshot.Select(alert => alert.AlertId).Distinct().Count() != snapshot.Length ||
            snapshot.Select(alert => alert.RuleId).Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
            throw new ArgumentException("An endpoint may have only one tracked alert per alert ID and rule ID.", nameof(alerts));

        var asset = Policy.AssetMultipliers[context.AssetCriticality];
        var exposure = Policy.ExposureMultipliers[context.Exposure];
        var contributions = snapshot.OrderBy(alert => alert.RuleId, StringComparer.Ordinal)
            .Select(alert => ScoreAlert(alert, context, asset, exposure, now)).ToArray();
        var groups = contributions.Where(alert => alert.CorrelationEligible)
            .Select(alert => alert.CorrelationGroup!).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var baseBonus = Math.Min(Math.Max(0, groups.Length - 1) * Policy.CorrelationPointsPerExtraGroup,
            Policy.MaximumCorrelationBaseBonus);
        var bonus = baseBonus * asset * exposure;
        var raw = contributions.Sum(alert => alert.Contribution) + bonus;
        var bounded = Math.Clamp(raw, 0m, Policy.MaximumScore);
        var score = (int)decimal.Round(bounded, 0, MidpointRounding.AwayFromZero);
        return new EndpointRiskScore(endpointId, score, raw, raw > Policy.MaximumScore, now, context, asset, exposure,
            Array.AsReadOnly(contributions), Array.AsReadOnly(groups), baseBonus, bonus,
            "Sum of severity × confidence policy weight × declared/default asset criticality × declared/default exposure " +
            "× observation-age weight × remaining risk, plus the bounded current-snapshot correlation bonus weighted by asset and exposure. " +
            "Rounded to the nearest integer (halves away from zero) and capped at 100. " +
            "Accepted and investigating statuses do not reduce remaining risk; resolved removes remaining risk. " +
            "A zero displayed score can reflect resolved or policy-discounted findings, small rounded contributions, or missing observations; " +
            "it does not verify endpoint safety.");
    }

    public OrganizationRiskScore ScoreOrganization(IEnumerable<EndpointRiskScore> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var snapshot = endpoints.ToArray();
        if (snapshot.Any(endpoint => endpoint is null || endpoint.EndpointId == Guid.Empty ||
                                     endpoint.Score < 0 || endpoint.Score > Policy.MaximumScore))
            throw new ArgumentException("Organization inputs must contain valid scored endpoints.", nameof(endpoints));
        if (snapshot.Select(endpoint => endpoint.EndpointId).Distinct().Count() != snapshot.Length)
            throw new ArgumentException("Organization inputs must not duplicate endpoints.", nameof(endpoints));
        var highest = snapshot.Length == 0 ? 0 : snapshot.Max(endpoint => endpoint.Score);
        var matchingIds = snapshot.Where(endpoint => endpoint.Score == highest).Select(endpoint => endpoint.EndpointId).Order().ToArray();
        var ids = matchingIds.Take(1).ToArray();
        return new OrganizationRiskScore(highest, snapshot.Length, Array.AsReadOnly(ids), matchingIds.Length,
            matchingIds.Length > ids.Length, "maximumEndpointScore",
            "The organization score is the maximum enrolled endpoint score. Lower-risk endpoints cannot dilute a high-risk endpoint. " +
            "An empty organization has score zero; this does not establish protection or telemetry coverage.");
    }

    private AlertRiskContribution ScoreAlert(ScoringAlert alert, EndpointScoringContext context,
        decimal asset, decimal exposure, DateTimeOffset now)
    {
        var severity = alert.Severity?.ToLowerInvariant();
        var status = alert.Status?.ToLowerInvariant();
        if (severity is null || !Policy.SeverityPoints.TryGetValue(severity, out var points))
            throw new ArgumentException("Unknown alert severity.", nameof(alert));
        if (status is null || !Policy.RemainingRiskByStatus.TryGetValue(status, out var remaining))
            throw new ArgumentException("Unknown alert status.", nameof(alert));
        var future = alert.LastObservedUtc > now;
        var age = Math.Max(0m, (now.UtcTicks - alert.LastObservedUtc.UtcTicks) / (decimal)TimeSpan.TicksPerDay);
        var fresh = age <= Policy.FreshForDays;
        var aging = !fresh && age <= Policy.AgingForDays;
        var ageMultiplier = fresh ? 1m : aging ? Policy.AgingMultiplier : Policy.OldMultiplier;
        var confidenceOverride = Policy.ConfidenceByRule.TryGetValue(alert.RuleId, out var confidence);
        if (!confidenceOverride)
            confidence = Policy.DefaultConfidence;
        var beforeMitigation = points * confidence * asset * exposure * ageMultiplier;
        var contribution = beforeMitigation * remaining;
        Policy.CorrelationGroupsByRule.TryGetValue(alert.RuleId, out var group);
        var latest = context.LatestInventoryUtc.HasValue && alert.LastObservedUtc == context.LatestInventoryUtc.Value;
        var eligible = contribution > 0m && remaining > 0m && fresh && latest && group is not null;
        return new AlertRiskContribution(alert.AlertId, alert.RuleId, severity, status, alert.LastObservedUtc,
            age, fresh ? "fresh" : aging ? "aging" : "old", future, points, confidence,
            confidenceOverride ? "rulePolicyOverride" : "policyDefault", asset, exposure, ageMultiplier, remaining,
            beforeMitigation, beforeMitigation - contribution, contribution, group, latest, eligible);
    }

    private static bool ValidSource(string source) => source is "policyDefault" or "userDeclared";
}
