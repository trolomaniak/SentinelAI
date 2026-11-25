using System.Globalization;
using SentinelAI.Contracts.RiskHistory;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record RiskHistoryPeriod(int Hours, string Label);

public sealed class RiskHistoryPresentation
{
    internal RiskHistoryPresentation(RiskHistoryView view)
    {
        StartUtc = view.StartUtc;
        GeneratedUtc = view.GeneratedUtc;
        Points = Array.AsReadOnly(view.Points.Reverse().Select(point => new RiskHistoryPointRow(point)).ToArray());
    }

    public DateTimeOffset StartUtc { get; }
    public DateTimeOffset GeneratedUtc { get; }
    public string StartText => RiskHistoryPointRow.Timestamp(StartUtc);
    public string EndText => RiskHistoryPointRow.Timestamp(GeneratedUtc);
    public IReadOnlyList<RiskHistoryPointRow> Points { get; }
}

public sealed class RiskHistoryPointRow
{
    internal RiskHistoryPointRow(RiskHistoryPoint point)
    {
        CapturedUtc = point.CapturedUtc;
        Score = point.Score;
        RawScoreText = RiskText.Number(point.RawScore);
        var details = new List<DisplayFact>
        {
            new(T("Recorded at (UTC)"), RecordedAtText),
            new(T("Recorded score"), RiskText.Number(point.Score)),
            new(T("Raw score"), RawScoreText),
            new(T("Policy version"), point.PolicyVersion),
            new(T("Policy fingerprint (SHA-256)"), point.PolicyFingerprint),
            new(T("Compared with (UTC)"), point.ComparedWithUtc is { } compared ? Timestamp(compared) : T("None")),
            new(T("Observed changes"), point.Causes.Count == 0 ? T("No recorded score change to explain.") : RiskText.Join(point.Causes.Select(CauseText))),
            new(T("Top scoring rule IDs"), RiskText.Join(point.PrincipalRuleIds))
        };
        if (point.EndpointCount is { } count) details.Add(new(T("Endpoints at capture"), RiskText.Number(count)));
        if (point.GoverningEndpointId is { } endpointId) details.Add(new(T("Endpoint with highest raw score"), endpointId.ToString("D")));
        Details = Array.AsReadOnly(details.ToArray());
    }

    public DateTimeOffset CapturedUtc { get; }
    public string RecordedAtText => Timestamp(CapturedUtc);
    public int Score { get; }
    public string RawScoreText { get; }
    public IReadOnlyList<DisplayFact> Details { get; }

    internal static string Timestamp(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.FFFFFFF 'UTC'", CultureInfo.InvariantCulture);

    private static string CauseText(string cause) => cause switch
    {
        "firstCapture" => T("First recorded measurement"),
        "policyChanged" => T("Scoring policy changed"),
        "contextChanged" => T("Endpoint context changed"),
        "findingSetChanged" => T("Recorded findings changed"),
        "statusChanged" => T("Finding status changed"),
        "severityChanged" => T("Finding severity changed"),
        "observationChanged" => T("Finding observation changed"),
        "ageChanged" => T("Observation age band changed"),
        "confirmationChanged" => T("Finding confirmation changed"),
        "correlationChanged" => T("Finding correlation changed"),
        "governingEndpointChanged" => T("Endpoint with highest raw score changed"),
        "fleetChanged" => T("Enrolled endpoint set changed"),
        _ => T("Change unexplained by recorded factors")
    };
}
