using System.Globalization;
using SentinelAI.Rules;
using SentinelAI.Scoring;

namespace SentinelAI.Core.Reports;

/// <summary>Inclusive UTC calendar dates; report intervals are bounded to 366 days.</summary>
public sealed record ReportPeriod(DateOnly From, DateOnly To)
{
    public bool IsValid => From <= To && To < DateOnly.MaxValue && To.DayNumber - From.DayNumber < 366;
    public DateTimeOffset StartUtc => new(From.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
    public DateTimeOffset EndExclusiveUtc => new(To.AddDays(1).ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));

    public static bool TryParse(string? from, string? to, out ReportPeriod? period)
    {
        period = null;
        if (from is not { Length: 10 } || to is not { Length: 10 } ||
            !DateOnly.TryParseExact(from, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var start) ||
            !DateOnly.TryParseExact(to, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var end)) return false;
        var candidate = new ReportPeriod(start, end);
        if (!candidate.IsValid) return false;
        period = candidate;
        return true;
    }
}

public sealed class ReportCapacityException : InvalidOperationException
{
    public ReportCapacityException() : base("The local report capacity is exceeded. Reports support at most 1000 enrolled endpoints and 13000 tracked alerts.") { }
}

public sealed record ReportHealthSummary(int Healthy, int Warning, int Offline, int Unknown);
public sealed record ReportSeverityCount(string Severity, int AssociatedAlerts, int NewAlerts);
public sealed record ReportActivitySummary(int AssociatedAlertCount, int NewAlertCount, int ResolvedAlertCount,
    IReadOnlyList<ReportSeverityCount> SeverityCounts);
public sealed record ReportEndpoint(Guid EndpointId, string EndpointName, string Health,
    DateTimeOffset? LastSeenUtc, EndpointRiskDetail CurrentRisk);
public sealed record ReportIncident(Guid AlertId, Guid EndpointId, string EndpointName, string RuleId,
    string Title, string Severity, string CurrentStatus, DateTimeOffset FirstObservedUtc,
    DateTimeOffset LastObservedUtc, string Reason, IReadOnlyList<RuleEvidence> Evidence,
    string RecommendedAction, bool FirstObservedInPeriod, bool LastObservedInPeriod,
    long StatusChangesInPeriod, long ResolutionsInPeriod, DateTimeOffset? LatestResolutionInPeriodUtc,
    bool ReopenedAfterPeriodResolution, decimal CurrentRiskContribution);
public sealed record ReportPriorityAction(string Priority, string RuleId, string Action,
    int AffectedEndpointCount, string Reason, decimal CurrentRiskContribution);

/// <summary>Period activity and current evaluated state remain explicitly separate.</summary>
public sealed record SecurityReport(ReportPeriod Period, DateTimeOffset GeneratedAtUtc,
    OrganizationRiskScore OrganizationRisk, ReportHealthSummary Health, ReportActivitySummary Activity,
    IReadOnlyList<ReportEndpoint> Endpoints, IReadOnlyList<ReportIncident> PeriodIncidents,
    IReadOnlyList<ReportIncident> MajorPostureFindings, IReadOnlyList<ReportPriorityAction> PriorityActions,
    ScoringPolicySnapshot Policy, int InventoryFreshForHours)
{
    public const int DetailedItemLimit = 200;
    public const string ChronologyCaution = "Period activity uses retained first/latest observations and all stored status transitions. " +
        "SentinelAI stores only the latest inventory and heartbeat and one alert per endpoint/rule, not a complete observation history. " +
        "An alert observed only between its retained first/latest timestamps may be absent from this period. " +
        "Activity counts are distinct retained alerts, not detection-event totals or proof of historical posture. " +
        "Risk, health, status and technical evidence below are current stored state evaluated at report generation, not the selected period's historical state.";
    public const string UnavailableTrend = "Unavailable: historical risk scores are not stored. No score trend or historical security posture can be reconstructed.";
}
