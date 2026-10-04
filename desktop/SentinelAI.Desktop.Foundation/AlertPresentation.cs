using System.Globalization;

namespace SentinelAI.Desktop.Foundation;

public sealed record AlertEndpointOption(Guid? EndpointId, string Name)
{
    public string DisplayName => EndpointId is { } id ? $"{Name} ({id:D})" : "All endpoints";
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
    public string Title => Summary.Title;
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
        "info" => "Info", "low" => "Low", "medium" => "Medium", "high" => "High", "critical" => "Critical",
        "open" => "Open", "investigating" => "Investigating", "accepted" => "Accepted", "resolved" => "Resolved",
        _ => "Unknown"
    };
}

/// <summary>Typed evidence and retained history from Core; no client detection or lifecycle inference.</summary>
public sealed class AlertPresentation
{
    public AlertPresentation(AlertDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        Row = new AlertRow(detail.Alert);
        Reason = detail.Reason;
        RecommendedAction = detail.RecommendedAction;
        Facts = Array.AsReadOnly(new[]
        {
            new DisplayFact("Alert ID", Row.AlertId.ToString("D")),
            new DisplayFact("Endpoint ID", Row.EndpointId.ToString("D")),
            new DisplayFact("Endpoint", Row.EndpointName),
            new DisplayFact("Rule ID", Row.RuleId),
            new DisplayFact("Title", Row.Title),
            new DisplayFact("Severity", Row.SeverityLabel),
            new DisplayFact("Status", Row.StatusLabel),
            new DisplayFact("First observed", Row.FirstObservedText),
            new DisplayFact("Last observed", Row.LastObservedText),
            new DisplayFact("Updated", Row.UpdatedText),
            new DisplayFact("Created", AlertRow.Timestamp(detail.CreatedUtc)),
            new DisplayFact("Status changed", AlertRow.Timestamp(detail.StatusChangedUtc)),
            new DisplayFact("Version", Row.Version.ToString(CultureInfo.InvariantCulture))
        });
        Evidence = Array.AsReadOnly(detail.Evidence.Select(evidence => new AlertEvidenceRow(evidence.Field,
            evidence.Kind switch
            {
                AlertEvidenceKind.Boolean => "Boolean", AlertEvidenceKind.Integer => "Integer",
                AlertEvidenceKind.String => "String", _ => "Unknown"
            }, evidence.Kind switch
            {
                AlertEvidenceKind.Boolean => evidence.BooleanValue?.ToString() ?? "Unknown",
                AlertEvidenceKind.Integer => evidence.IntegerValue?.ToString(CultureInfo.InvariantCulture) ?? "Unknown",
                AlertEvidenceKind.String => evidence.StringValue ?? "Unknown",
                _ => "Unknown"
            })).ToArray());
        History = Array.AsReadOnly(detail.StatusHistory.TakeLast(100).Select(change => new AlertHistoryRow(
            change.PreviousStatus is null ? "None" : AlertRow.Label(change.PreviousStatus), AlertRow.Label(change.Status),
            AlertRow.Timestamp(change.ChangedUtc), change.ChangedBy,
            change.PreviousStatus is null ? "Created" :
                change.PreviousStatus == "resolved" && change.Status == "open" && change.ChangedBy == "system"
                    ? "Reopened" : "Status changed")).ToArray());
        HistoryDisclosure = detail.StatusHistoryCount == 0 ? "No status history reported."
            : $"Showing the last {History.Count.ToString(CultureInfo.InvariantCulture)} of {detail.StatusHistoryCount.ToString(CultureInfo.InvariantCulture)} status changes.";
    }

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
