using System.Globalization;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record AlertEndpointOption(Guid? EndpointId, string Name)
{
    public string DisplayName => EndpointId is { } id ? $"{Name} ({id:D})" : T("All endpoints");
}

public sealed record AlertEvidenceRow(string Field, string TypeLabel, string Value)
{
    public string DisplayValue => Value;
    public string Kind => TypeLabel;
}

public sealed record AlertHistoryRow(string PreviousStatus, string Status, string ChangedUtcText,
    string ChangedBy, string ChangeType);

/// <summary>Immutable public alert fields; display strings are literal text, never markup.</summary>
public sealed class AlertRow
{
    internal AlertSummary Summary { get; }
    public AlertRow(AlertSummary alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        Summary = alert;
    }
    public Guid AlertId => Summary.AlertId;
    public Guid EndpointId => Summary.EndpointId;
    public string EndpointName => Summary.EndpointName;
    public string RuleId => Summary.RuleId;
    public string Title => T(Summary.Title);
    public string Severity => Summary.Severity;
    public string SeverityLabel => Label(Severity);
    public string Status => Summary.Status;
    public string StatusLabel => Label(Status);
    public DateTimeOffset FirstObservedUtc => Summary.FirstObservedUtc;
    public DateTimeOffset LastObservedUtc => Summary.LastObservedUtc;
    public DateTimeOffset UpdatedUtc => Summary.UpdatedUtc;
    public long Version => Summary.Version;
    public string FirstObservedText => Timestamp(FirstObservedUtc);
    public string LastObservedText => Timestamp(LastObservedUtc);
    public string UpdatedText => Timestamp(UpdatedUtc);

    internal static string Timestamp(DateTimeOffset value) => value.ToUniversalTime()
        .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
    internal static string Label(string? value) => value switch
    {
        "info" => T("Info"), "low" => T("Low"), "medium" => T("Medium"), "high" => T("High"), "critical" => T("Critical"),
        "open" => T("Open"), "investigating" => T("Investigating"), "accepted" => T("Accepted"), "resolved" => T("Resolved"),
        _ => T("Unknown")
    };
}

/// <summary>Typed evidence and retained history from Core; no client detection or lifecycle inference.</summary>
public sealed class AlertPresentation
{
    public AlertPresentation(AlertDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        Detail = detail;
        Row = new AlertRow(detail.Alert);
        Reason = T(detail.Reason);
        RecommendedAction = T(detail.RecommendedAction);
        Facts = Array.AsReadOnly(new[]
        {
            new DisplayFact(T("Alert ID"), Row.AlertId.ToString("D")),
            new DisplayFact(T("Endpoint ID"), Row.EndpointId.ToString("D")),
            new DisplayFact(T("Endpoint"), Row.EndpointName),
            new DisplayFact(T("Rule ID"), Row.RuleId),
            new DisplayFact(T("Title"), Row.Title),
            new DisplayFact(T("Severity"), Row.SeverityLabel),
            new DisplayFact(T("Status"), Row.StatusLabel),
            new DisplayFact(T("First observed"), Row.FirstObservedText),
            new DisplayFact(T("Last observed"), Row.LastObservedText),
            new DisplayFact(T("Updated"), Row.UpdatedText),
            new DisplayFact(T("Created"), AlertRow.Timestamp(detail.CreatedUtc)),
            new DisplayFact(T("Status changed"), AlertRow.Timestamp(detail.StatusChangedUtc)),
            new DisplayFact(T("Version"), Row.Version.ToString(CultureInfo.InvariantCulture))
        });
        Evidence = Array.AsReadOnly(detail.Evidence.Select(evidence => new AlertEvidenceRow(evidence.Field,
            evidence.Kind switch
            {
                AlertEvidenceKind.Boolean => T("Boolean"), AlertEvidenceKind.Integer => T("Integer"),
                AlertEvidenceKind.String => T("String"), _ => T("Unknown")
            }, evidence.Kind switch
            {
                AlertEvidenceKind.Boolean => evidence.BooleanValue?.ToString() ?? T("Unknown"),
                AlertEvidenceKind.Integer => evidence.IntegerValue?.ToString(CultureInfo.InvariantCulture) ?? T("Unknown"),
                AlertEvidenceKind.String => evidence.StringValue ?? T("Unknown"),
                _ => T("Unknown")
            })).ToArray());
        History = Array.AsReadOnly(detail.StatusHistory.TakeLast(100).Select(change => new AlertHistoryRow(
            change.PreviousStatus is null ? T("None") : AlertRow.Label(change.PreviousStatus), AlertRow.Label(change.Status),
            AlertRow.Timestamp(change.ChangedUtc), change.ChangedBy,
            change.PreviousStatus is null ? T("Created") :
                change.PreviousStatus == "resolved" && change.Status == "open" && change.ChangedBy == "system"
                    ? T("Reopened") : T("Status changed"))).ToArray());
        HistoryDisclosure = detail.StatusHistoryCount == 0 ? T("No status history reported.")
            : F("Showing the last {0} of {1} status changes.", History.Count, detail.StatusHistoryCount);
    }

    public AlertDetail Detail { get; }
    public AlertRow Row { get; }
    public string Name => Row.Title;
    public long Version => Row.Version;
    public string Reason { get; }
    public string RecommendedAction { get; }
    public IReadOnlyList<DisplayFact> Facts { get; }
    public IReadOnlyList<AlertEvidenceRow> Evidence { get; }
    public IReadOnlyList<AlertHistoryRow> History { get; }
    public string HistoryDisclosure { get; }
}
