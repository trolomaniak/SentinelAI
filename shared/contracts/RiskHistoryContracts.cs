namespace SentinelAI.Contracts.RiskHistory;

public static class RiskHistoryContract
{
    public const int CaptureIntervalHours = 6;
    public const int RetentionDays = 90;
    public const int MaximumEndpointPoints = 250_000;
    public const int MaximumPoints = RetentionDays * 24 / CaptureIntervalHours + 1;
    public const int MaximumResponseBytes = 1024 * 1024;
    public const int MaximumPolicyVersionLength = 100;
    public const int MaximumRuleIds = 3;
    public const int MaximumRuleIdLength = 128;
    public static IReadOnlyList<int> PeriodHours { get; } = Array.AsReadOnly(new[] { 24, 168, 720, 2160 });
    public static IReadOnlyList<string> CauseCodes { get; } = Array.AsReadOnly(new[]
    {
        "firstCapture", "policyChanged", "contextChanged", "findingSetChanged", "statusChanged", "severityChanged",
        "observationChanged", "ageChanged", "confirmationChanged", "correlationChanged", "governingEndpointChanged",
        "fleetChanged", "unclassified"
    });
}

public sealed record RiskHistoryPoint(DateTimeOffset CapturedUtc, int Score, decimal RawScore, string PolicyVersion,
    string PolicyFingerprint, DateTimeOffset? ComparedWithUtc, IReadOnlyList<string> Causes, IReadOnlyList<string> PrincipalRuleIds,
    int? EndpointCount, Guid? GoverningEndpointId);

public sealed record RiskHistoryView(Guid? EndpointId, int PeriodHours, DateTimeOffset GeneratedUtc,
    DateTimeOffset StartUtc, IReadOnlyList<RiskHistoryPoint> Points);
