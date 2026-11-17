using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Desktop.Foundation;

public enum NotificationRequestOutcome { Success, Unauthenticated, UntrustedConnection, Unavailable, InvalidResponse, TooLarge, NotFound, Conflict, InvalidPolicy }
public sealed record NotificationResult<T>(NotificationRequestOutcome Outcome, T? Value = default);

/// <summary>Administrator-only local center. Secret inputs are consumed during the call and never returned.</summary>
public interface INotificationsClient
{
    Task<NotificationResult<NotificationPage>> GetNotificationsAsync(int offset, int limit, bool unreadOnly, CancellationToken cancellationToken);
    Task<NotificationResult<bool>> MarkNotificationReadAsync(Guid notificationId, CancellationToken cancellationToken);
    Task<NotificationResult<NotificationDeliveryPage>> GetNotificationDeliveriesAsync(int offset, int limit, Guid? notificationId, CancellationToken cancellationToken);
    Task<NotificationResult<NotificationPolicy>> GetNotificationPolicyAsync(CancellationToken cancellationToken);
    // The three secret string members in policy must be null. Blank buffers retain protected values;
    // the explicit Clear flags remove them. Implementations must consume these buffers synchronously
    // before returning their Task; callers wipe them immediately. No immutable secret strings are needed.
    Task<NotificationResult<NotificationPolicy>> SetNotificationPolicyAsync(NotificationPolicyWrite policy,
        ReadOnlyMemory<char> webhookUrl, ReadOnlyMemory<char> webhookSecret, ReadOnlyMemory<char> smtpPassword, CancellationToken cancellationToken);
}
