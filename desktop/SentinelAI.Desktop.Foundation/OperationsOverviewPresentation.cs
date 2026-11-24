using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.Overview;
using SentinelAI.Contracts.SecurityEvents;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record OverviewRow(string Title, string Detail);

public sealed record OverviewSection(string Summary, IReadOnlyList<OverviewRow> Rows, string PreviewNote = "");

public sealed class OperationsOverviewPresentation
{
    internal OperationsOverviewPresentation(OperationsOverviewSnapshot snapshot)
    {
        GeneratedUtc = snapshot.GeneratedUtc;
        var counts = snapshot.Counts;
        Coverage = Section(F("Active computers · {0} · Monitoring issues · {1}", counts.ActiveEndpoints, counts.CoverageIssues),
            counts.CoverageIssues, snapshot.CoverageIssues.Select(CoverageRow));
        PriorityAlerts = Section(F("High and critical alerts awaiting a decision · {0}", counts.PriorityAlerts),
            counts.PriorityAlerts, snapshot.PriorityAlerts.Select(alert => new OverviewRow(T(alert.Title),
                string.Join(" · ", AlertRow.Label(alert.Severity), AlertRow.Label(alert.Status), alert.EndpointName, AlertRow.Timestamp(alert.LastObservedUtc)))));
        UnreadNotifications = Section(F("Unread notifications · {0}", counts.UnreadNotifications),
            counts.UnreadNotifications, snapshot.UnreadNotifications.Select(notification => new OverviewRow(NotificationsViewModel.Kind(notification.Kind),
                string.Join(" · ", notification.EndpointName, F("Occurrences · {0}", notification.Occurrences), AlertRow.Timestamp(notification.LastObservedUtc)))));
        RisksNeedingAttention = Section(F("Risks requiring attention · {0}", counts.RisksNeedingAttention),
            counts.RisksNeedingAttention, snapshot.RisksNeedingAttention.Select(RiskRow));
        RecentAlertChanges = new(snapshot.RecentAlertChanges.Count == 0 ? T("No alert status changes in this period.") : string.Empty,
            snapshot.RecentAlertChanges.Select(change => new OverviewRow(T(change.Title),
                string.Join(" · ", ChangeLabel(change), change.EndpointName, AlertRow.Timestamp(change.ChangedUtc)))).ToArray());
        Backup = new(snapshot.LastSuccessfulBackupUtc is { } backup
            ? F("Last successful backup: {0}", AlertRow.Timestamp(backup)) : T("No successful backup recorded."), []);
    }

    public DateTimeOffset GeneratedUtc { get; }
    public OverviewSection Coverage { get; }
    public OverviewSection PriorityAlerts { get; }
    public OverviewSection UnreadNotifications { get; }
    public OverviewSection RisksNeedingAttention { get; }
    public OverviewSection RecentAlertChanges { get; }
    public OverviewSection Backup { get; }

    private static OverviewSection Section(string summary, int count, IEnumerable<OverviewRow> preview)
    {
        var rows = preview.ToArray();
        return new(summary, rows, rows.Length < count ? F("Showing {0} of {1}.", rows.Length, count) : string.Empty);
    }

    private static OverviewRow CoverageRow(MonitoringEndpointSummary endpoint)
    {
        var health = F("Heartbeat · {0} · Inventory · {1} · Telemetry · {2}",
            MonitoringCoveragePresentation.Heartbeat(endpoint.HeartbeatState),
            MonitoringCoveragePresentation.Freshness(endpoint.InventoryFreshness),
            MonitoringCoveragePresentation.Freshness(endpoint.TelemetryFreshness));
        var sources = F("Current collection · {0}/{1} telemetry sections · {2}/{3} event channels", endpoint.CurrentTelemetrySources,
            MonitoringCoverageContract.TelemetrySourceIds.Count, endpoint.CurrentEventChannels, SecurityEventChannels.All.Count);
        if (endpoint.HasRetainedGaps) sources += " · " + T("Retained continuity notices");
        return new(endpoint.Name, health + "\n" + sources);
    }

    private static OverviewRow RiskRow(OverviewRisk risk)
    {
        var reasons = new List<string>(3);
        if (risk.ReviewOverdue) reasons.Add(T("Review overdue"));
        if (risk.AcceptanceExpired) reasons.Add(T("Acceptance expired"));
        if (risk.TargetDatePassed) reasons.Add(T("Target date passed"));
        return new(F("{0} · {1}", risk.Reference, risk.Title), string.Join(" · ", reasons));
    }

    private static string ChangeLabel(OverviewAlertChange change) => change.PreviousStatus switch
    {
        null => T("Created"),
        "resolved" when change.Status == "open" => T("Reopened"),
        _ => AlertRow.Label(change.PreviousStatus) + " → " + AlertRow.Label(change.Status)
    };
}
