using System.Text.Json;
using SentinelAI.Contracts.Overview;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IOperationsOverviewClient
{
    public Task<DeviceReadResult<OperationsOverviewSnapshot>> GetOperationsOverviewAsync(CancellationToken cancellationToken) =>
        ReadDeviceResourceAsync("api/admin/overview", OperationsOverviewContract.MaximumResponseBytes,
            ParseOperationsOverview, allowNotFound: false, cancellationToken);

    private static OperationsOverviewSnapshot ParseOperationsOverview(JsonElement root)
    {
        var fields = CoverageFields(root, "generatedUtc", "counts", "priorityAlerts", "coverageIssues", "unreadNotifications",
            "risksNeedingAttention", "recentAlertChanges", "lastSuccessfulBackupUtc");
        var totals = CoverageFields(fields["counts"], "activeEndpoints", "coverageIssues", "priorityAlerts", "unreadNotifications", "risksNeedingAttention");
        var active = CoverageNumber(totals, "activeEndpoints", 0, int.MaxValue);
        var counts = new OverviewCounts(active, CoverageNumber(totals, "coverageIssues", 0, active),
            CoverageNumber(totals, "priorityAlerts", 0, int.MaxValue), CoverageNumber(totals, "unreadNotifications", 0, int.MaxValue),
            CoverageNumber(totals, "risksNeedingAttention", 0, int.MaxValue));
        var generated = CoverageDate(fields, "generatedUtc");
        var alerts = OverviewPreview(fields["priorityAlerts"], counts.PriorityAlerts, ParseOverviewAlert, item => item.AlertId);
        var coverage = OverviewPreview(fields["coverageIssues"], counts.CoverageIssues, ParseMonitoringSummary, item => item.EndpointId);
        var notifications = OverviewPreview(fields["unreadNotifications"], counts.UnreadNotifications, ParseOverviewNotification, item => item.NotificationId);
        var risks = OverviewPreview(fields["risksNeedingAttention"], counts.RisksNeedingAttention, ParseOverviewRisk, item => item.RiskId);
        if (coverage.Any(item => !item.HasIssue) ||
            risks.Any(risk => !(risk.ReviewOverdue || risk.AcceptanceExpired || risk.TargetDatePassed)))
            throw new InvalidResponseException();

        var changes = fields["recentAlertChanges"];
        if (changes.ValueKind != JsonValueKind.Array || changes.GetArrayLength() > OperationsOverviewContract.PreviewLimit)
            throw new InvalidResponseException();
        var recent = changes.EnumerateArray().Select(ParseOverviewAlertChange).ToArray();
        if (recent.Any(change => change.ChangedUtc > generated || generated - change.ChangedUtc > TimeSpan.FromHours(OperationsOverviewContract.RecentHours)) ||
            !recent.SequenceEqual(recent.OrderByDescending(change => change.ChangedUtc)) ||
            !alerts.SequenceEqual(alerts.OrderByDescending(alert => alert.Severity == "critical").ThenByDescending(alert => alert.LastObservedUtc)))
            throw new InvalidResponseException();

        return new(generated, counts, alerts, coverage, notifications, risks, Array.AsReadOnly(recent), OptionalDeviceDate(fields, "lastSuccessfulBackupUtc"));
    }

    private static IReadOnlyList<T> OverviewPreview<T>(JsonElement element, int total, Func<JsonElement, T> parse, Func<T, Guid> identity)
    {
        var rows = CoverageArray(element, Math.Min(total, OperationsOverviewContract.PreviewLimit)).Select(parse).ToArray();
        if (rows.Select(identity).Distinct().Count() != rows.Length) throw new InvalidResponseException();
        return Array.AsReadOnly(rows);
    }

    private static OverviewAlert ParseOverviewAlert(JsonElement root)
    {
        var fields = CoverageFields(root, "alertId", "endpointName", "title", "severity", "status", "lastObservedUtc");
        return new(OverviewId(fields["alertId"]), OverviewText(fields, "endpointName"), OverviewText(fields, "title"),
            CoverageChoice(fields, "severity", "critical", "high"), CoverageChoice(fields, "status", "open", "investigating"),
            CoverageDate(fields, "lastObservedUtc"));
    }

    private static OverviewAlertChange ParseOverviewAlertChange(JsonElement root)
    {
        var fields = CoverageFields(root, "alertId", "endpointName", "title", "previousStatus", "status", "changedUtc");
        var previous = OptionalDeviceText(fields, "previousStatus", OperationsOverviewContract.MaximumTextLength);
        var status = OverviewText(fields, "status");
        if (fields["previousStatus"].ValueKind != JsonValueKind.Null && !ValidAlertStatus(previous) || !ValidAlertStatus(status))
            throw new InvalidResponseException();
        return new(OverviewId(fields["alertId"]), OverviewText(fields, "endpointName"), OverviewText(fields, "title"),
            previous, status, CoverageDate(fields, "changedUtc"));
    }

    private static OverviewNotification ParseOverviewNotification(JsonElement root)
    {
        var fields = CoverageFields(root, "notificationId", "endpointName", "kind", "occurrences", "lastObservedUtc");
        return new(OverviewId(fields["notificationId"]), OverviewText(fields, "endpointName"),
            CoverageChoice(fields, "kind", "criticalAlertNew", "criticalAlertReopened", "criticalAlertEscalated", "monitoringOffline", "monitoringRecovered"),
            CoverageNumber(fields, "occurrences", 1, int.MaxValue), CoverageDate(fields, "lastObservedUtc"));
    }

    private static OverviewRisk ParseOverviewRisk(JsonElement root)
    {
        var fields = CoverageFields(root, "riskId", "reference", "title", "reviewOverdue", "acceptanceExpired", "targetDatePassed");
        return new(OverviewId(fields["riskId"]), OverviewText(fields, "reference"), OverviewText(fields, "title"),
            CoverageBoolean(fields, "reviewOverdue"), CoverageBoolean(fields, "acceptanceExpired"), CoverageBoolean(fields, "targetDatePassed"));
    }

    private static Guid OverviewId(JsonElement value) => value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id) && id != Guid.Empty
        ? id : throw new InvalidResponseException();

    private static string OverviewText(Dictionary<string, JsonElement> fields, string name)
    {
        var value = OptionalDeviceText(fields, name, OperationsOverviewContract.MaximumTextLength);
        return SecurityEventContract.IsBoundedText(value, OperationsOverviewContract.MaximumTextLength) ? value! : throw new InvalidResponseException();
    }
}
