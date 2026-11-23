namespace SentinelAI.Contracts.Notifications;

public static class NotificationContract
{
    public const int MaximumPageSize = 100;
    public const int MaximumResponseBytes = 256 * 1024;
    public const int MaximumPolicyBytes = 16 * 1024;
}

public sealed record NotificationPolicy(long Version, bool CriticalAlerts, bool MonitoringChanges,
    int OfflineMinutes, int GroupMinutes, bool WebhookEnabled, string? WebhookOrigin, bool HasWebhookDestination, bool HasWebhookSecret,
    bool EmailEnabled, string? SmtpHost, int SmtpPort, string? SmtpUsername, bool HasSmtpPassword,
    string? EmailFrom, string? EmailTo, string CredentialAvailability);

// Null secret means retain; Clear flags explicitly remove it. Responses never contain secret values.
public sealed record NotificationPolicyWrite(long ExpectedVersion, bool CriticalAlerts, bool MonitoringChanges,
    int OfflineMinutes, int GroupMinutes, bool WebhookEnabled, string? WebhookUrl, string? WebhookSecret,
    bool ClearWebhookSecret, bool ClearWebhookDestination, bool EmailEnabled, string? SmtpHost, int SmtpPort, string? SmtpUsername,
    string? SmtpPassword, bool ClearSmtpPassword, string? EmailFrom, string? EmailTo);

public sealed record NotificationSummary(Guid NotificationId, string Kind, Guid EndpointId, string EndpointName,
    Guid? AlertId, string? RuleId, string Severity, int Occurrences, DateTimeOffset CreatedUtc,
    DateTimeOffset LastObservedUtc, DateTimeOffset? ReadUtc);
public sealed record NotificationDelivery(Guid DeliveryId, Guid NotificationId, string Channel, string State,
    int Attempts, DateTimeOffset CreatedUtc, DateTimeOffset? LastAttemptUtc, DateTimeOffset? NextAttemptUtc,
    string? ResultCode);
public sealed record NotificationPage(int Total, int Unread, int Offset, int Limit,
    IReadOnlyList<NotificationSummary> Items);
public sealed record NotificationDeliveryPage(int Total, int Offset, int Limit,
    IReadOnlyList<NotificationDelivery> Items);

// A recipient may receive a retry after an ambiguous transport failure. Deduplicate by this stable key.
public sealed record NotificationPayload(string Format, Guid NotificationId, string Kind, Guid EndpointId,
    Guid? AlertId, string? RuleId, string Severity, int Occurrences, DateTimeOffset CreatedUtc, DateTimeOffset LastObservedUtc);
