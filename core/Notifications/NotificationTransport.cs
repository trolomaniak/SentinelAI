using System.Security.Cryptography;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Core.Notifications;

// Decrypted only for one bounded attempt. The worker owns and disposes this value.
internal sealed record NotificationDestination(string Channel, Uri? WebhookUri = null,
    byte[]? WebhookSecret = null, string? SmtpHost = null, int SmtpPort = 587,
    string? SmtpUsername = null, byte[]? SmtpPassword = null, string? EmailFrom = null, string? EmailTo = null) : IDisposable
{
    public void Dispose()
    {
        if (WebhookSecret is not null) CryptographicOperations.ZeroMemory(WebhookSecret);
        if (SmtpPassword is not null) CryptographicOperations.ZeroMemory(SmtpPassword);
    }
}

internal sealed record NotificationSendResult(bool Succeeded, bool Retryable, string Code);

internal interface INotificationSender
{
    Task<NotificationSendResult> SendAsync(NotificationPayload payload, NotificationDestination destination,
        CancellationToken cancellationToken);
}
