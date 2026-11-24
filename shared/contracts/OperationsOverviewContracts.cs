using SentinelAI.Contracts.Monitoring;

namespace SentinelAI.Contracts.Overview;

public static class OperationsOverviewContract
{
    public const int PreviewLimit = 5;
    public const int RecentHours = 24;
    public const int MaximumResponseBytes = 64 * 1024;
    public const int MaximumTextLength = 160;
}

public sealed record OverviewCounts(int ActiveEndpoints, int CoverageIssues, int PriorityAlerts,
    int UnreadNotifications, int RisksNeedingAttention);

public sealed record OverviewAlert(Guid AlertId, string EndpointName, string Title, string Severity,
    string Status, DateTimeOffset LastObservedUtc);

public sealed record OverviewAlertChange(Guid AlertId, string EndpointName, string Title, string? PreviousStatus,
    string Status, DateTimeOffset ChangedUtc);

public sealed record OverviewNotification(Guid NotificationId, string EndpointName, string Kind,
    int Occurrences, DateTimeOffset LastObservedUtc);

public sealed record OverviewRisk(Guid RiskId, string Reference, string Title, bool ReviewOverdue,
    bool AcceptanceExpired, bool TargetDatePassed);

public sealed record OperationsOverviewSnapshot(DateTimeOffset GeneratedUtc, OverviewCounts Counts,
    IReadOnlyList<OverviewAlert> PriorityAlerts, IReadOnlyList<MonitoringEndpointSummary> CoverageIssues,
    IReadOnlyList<OverviewNotification> UnreadNotifications, IReadOnlyList<OverviewRisk> RisksNeedingAttention,
    IReadOnlyList<OverviewAlertChange> RecentAlertChanges, DateTimeOffset? LastSuccessfulBackupUtc);
