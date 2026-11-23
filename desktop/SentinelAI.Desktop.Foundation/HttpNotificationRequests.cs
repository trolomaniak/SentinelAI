using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : INotificationsClient
{
    public Task<NotificationResult<NotificationPage>> GetNotificationsAsync(int offset, int limit, bool unreadOnly, CancellationToken cancellationToken)
    {
        NotificationPaging(offset, limit);
        return NotificationRequestAsync(HttpMethod.Get, "api/admin/notifications?offset=" + offset.ToString(CultureInfo.InvariantCulture) +
            "&limit=" + limit.ToString(CultureInfo.InvariantCulture) + "&unreadOnly=" + (unreadOnly ? "true" : "false"), null,
            NotificationContract.MaximumResponseBytes, root => ParseNotificationPage(root, offset, limit, unreadOnly), cancellationToken);
    }

    public Task<NotificationResult<bool>> MarkNotificationReadAsync(Guid notificationId, CancellationToken cancellationToken)
    {
        if (notificationId == Guid.Empty) throw new ArgumentException("A notification is required.", nameof(notificationId));
        return NotificationRequestAsync(HttpMethod.Put, "api/admin/notifications/" + notificationId.ToString("D") + "/read", null, 0, _ => true, cancellationToken);
    }

    public Task<NotificationResult<NotificationDeliveryPage>> GetNotificationDeliveriesAsync(int offset, int limit, Guid? notificationId, CancellationToken cancellationToken)
    {
        NotificationPaging(offset, limit);
        if (notificationId == Guid.Empty) throw new ArgumentException("A notification is required.", nameof(notificationId));
        return NotificationRequestAsync(HttpMethod.Get, "api/admin/notifications/deliveries?offset=" + offset.ToString(CultureInfo.InvariantCulture) +
            "&limit=" + limit.ToString(CultureInfo.InvariantCulture) + (notificationId is { } id ? "&notificationId=" + id.ToString("D") : ""), null,
            NotificationContract.MaximumResponseBytes, root => ParseNotificationDeliveries(root, offset, limit, notificationId), cancellationToken);
    }

    public Task<NotificationResult<NotificationPolicy>> GetNotificationPolicyAsync(CancellationToken cancellationToken) =>
        NotificationRequestAsync(HttpMethod.Get, "api/admin/notifications/policy", null, NotificationContract.MaximumPolicyBytes, ParseNotificationPolicy, cancellationToken);

    public Task<NotificationResult<NotificationPolicy>> SetNotificationPolicyAsync(NotificationPolicyWrite policy,
        ReadOnlyMemory<char> webhookUrl, ReadOnlyMemory<char> webhookSecret, ReadOnlyMemory<char> smtpPassword, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();
        if (policy.WebhookUrl is not null || policy.WebhookSecret is not null || policy.SmtpPassword is not null ||
            webhookUrl.Length > 2048 || webhookSecret.Length > 512 || smtpPassword.Length > 512)
            throw new ArgumentException("Secret values must use bounded input buffers.");
        // Utf8JsonWriter accepts character spans: no immutable plaintext secret strings are created.
        // The existing fixed-capacity buffer never grows or returns old arrays to a pool.
        var bytes = new RequestBuffer();
        try
        {
            using (var json = new Utf8JsonWriter(bytes))
            {
                json.WriteStartObject();
                json.WriteNumber("expectedVersion", policy.ExpectedVersion);
                json.WriteBoolean("criticalAlerts", policy.CriticalAlerts);
                json.WriteBoolean("monitoringChanges", policy.MonitoringChanges);
                json.WriteNumber("offlineMinutes", policy.OfflineMinutes);
                json.WriteNumber("groupMinutes", policy.GroupMinutes);
                json.WriteBoolean("webhookEnabled", policy.WebhookEnabled);
                WriteInput(json, "webhookUrl", webhookUrl.Span);
                WriteInput(json, "webhookSecret", webhookSecret.Span);
                json.WriteBoolean("clearWebhookSecret", policy.ClearWebhookSecret);
                json.WriteBoolean("clearWebhookDestination", policy.ClearWebhookDestination);
                json.WriteBoolean("emailEnabled", policy.EmailEnabled);
                json.WriteString("smtpHost", policy.SmtpHost);
                json.WriteNumber("smtpPort", policy.SmtpPort);
                json.WriteString("smtpUsername", policy.SmtpUsername);
                WriteInput(json, "smtpPassword", smtpPassword.Span);
                json.WriteBoolean("clearSmtpPassword", policy.ClearSmtpPassword);
                json.WriteString("emailFrom", policy.EmailFrom);
                json.WriteString("emailTo", policy.EmailTo);
                json.WriteEndObject();
            }
            if (bytes.Length > NotificationContract.MaximumPolicyBytes) throw new ArgumentException("Notification policy is too large.");
            return NotificationRequestAsync(HttpMethod.Put, "api/admin/notifications/policy", bytes.Buffer.AsSpan(0, bytes.Length).ToArray(),
                NotificationContract.MaximumPolicyBytes, ParseNotificationPolicy, cancellationToken);
        }
        finally { bytes.Dispose(); }
    }

    private static void WriteInput(Utf8JsonWriter json, string name, ReadOnlySpan<char> value)
    { if (value.IsEmpty) json.WriteNull(name); else json.WriteString(name, value); }

    private static void NotificationPaging(int offset, int limit)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(offset, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, 100_000);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, NotificationContract.MaximumPageSize);
    }

    private async Task<NotificationResult<T>> NotificationRequestAsync<T>(HttpMethod method, string path, byte[]? body,
        int maximumBytes, Func<JsonElement, T> parse, CancellationToken cancellationToken)
    {
        Operation? operation = null;
        byte[]? token = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || _token is null) return new(NotificationRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(NotificationRequestOutcome.Unauthenticated); }
                operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
                token = _token.ToArray();
            }
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(15));
            NotificationResult<T> result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(NotificationRequestOutcome.UntrustedConnection);
                else
                {
                    operation.Token.ThrowIfCancellationRequested();
                    using var request = new HttpRequestMessage(method, new Uri(_origin, path));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    if (body is not null) { request.Content = new ByteArrayContent(body); request.Content.Headers.ContentType = new("application/json"); }
                    try
                    {
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                        if (body is not null) CryptographicOperations.ZeroMemory(body);
                        operation.Token.ThrowIfCancellationRequested();
                        result = response.StatusCode switch
                        {
                            HttpStatusCode.Unauthorized => new(NotificationRequestOutcome.Unauthenticated),
                            HttpStatusCode.NotFound => new(NotificationRequestOutcome.NotFound),
                            HttpStatusCode.Conflict => new(NotificationRequestOutcome.Conflict),
                            HttpStatusCode.BadRequest => new(NotificationRequestOutcome.InvalidPolicy),
                            HttpStatusCode.RequestEntityTooLarge => new(NotificationRequestOutcome.TooLarge),
                            HttpStatusCode.NoContent when maximumBytes == 0 => new(NotificationRequestOutcome.Success, parse(default)),
                            HttpStatusCode.OK when maximumBytes > 0 => new(NotificationRequestOutcome.Success,
                                await ReadNotificationResponseAsync(response, maximumBytes, parse, operation.Token).ConfigureAwait(false)),
                            _ => new(NotificationRequestOutcome.Unavailable)
                        };
                    }
                    finally { request.Headers.Authorization = null; }
                }
            }
            catch (OperationCanceledException) { cancellationToken.ThrowIfCancellationRequested(); result = new(NotificationRequestOutcome.Unavailable); }
            catch (NotificationTooLargeException) { result = new(NotificationRequestOutcome.TooLarge); }
            catch (Exception error) when (error is InvalidResponseException or JsonException or FormatException or OverflowException or InvalidOperationException)
            { result = new(NotificationRequestOutcome.InvalidResponse); }
            catch (Exception) { cancellationToken.ThrowIfCancellationRequested(); result = new(NotificationRequestOutcome.Unavailable); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(NotificationRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(NotificationRequestOutcome.Unauthenticated); }
                if (operation.Token.IsCancellationRequested) return new(NotificationRequestOutcome.Unavailable);
                if (result.Outcome is NotificationRequestOutcome.Unauthenticated or NotificationRequestOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
        finally
        {
            if (body is not null) CryptographicOperations.ZeroMemory(body);
            if (token is not null) CryptographicOperations.ZeroMemory(token);
            operation?.Dispose();
        }
    }

    private static async Task<T> ReadNotificationResponseAsync<T>(HttpResponseMessage response, int maximumBytes, Func<JsonElement, T> parse, CancellationToken token)
    {
        if (response.Content.Headers.ContentType?.MediaType != "application/json" || response.Headers.CacheControl?.NoStore != true) throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > maximumBytes) throw new NotificationTooLargeException();
        var buffer = new byte[maximumBytes + 1];
        try
        {
            using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            var length = 0;
            while (length < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(length), token).ConfigureAwait(false);
                if (read == 0) break;
                length += read;
            }
            if (length > maximumBytes) throw new NotificationTooLargeException();
            using var document = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 5 });
            return parse(document.RootElement);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    internal static NotificationPolicy ParseNotificationPolicy(JsonElement root)
    {
        var f = NotificationFields(root, ["version", "criticalAlerts", "monitoringChanges", "offlineMinutes", "groupMinutes", "webhookEnabled", "webhookOrigin",
            "hasWebhookDestination", "hasWebhookSecret", "emailEnabled", "smtpHost", "smtpPort", "smtpUsername", "hasSmtpPassword", "emailFrom", "emailTo", "credentialAvailability"]);
        var origin = NotificationText(f["webhookOrigin"], 2048, optional: true);
        if (origin is not null && (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Port != 443 ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != "/")) throw new InvalidResponseException();
        var availability = NotificationText(f["credentialAvailability"], 32);
        if (availability is not ("available" or "unavailable")) throw new InvalidResponseException();
        var value = new NotificationPolicy(NotificationNumber(f["version"], 0, long.MaxValue), NotificationBoolean(f["criticalAlerts"]), NotificationBoolean(f["monitoringChanges"]),
            (int)NotificationNumber(f["offlineMinutes"], 5, 120), (int)NotificationNumber(f["groupMinutes"], 1, 60), NotificationBoolean(f["webhookEnabled"]), origin,
            NotificationBoolean(f["hasWebhookDestination"]), NotificationBoolean(f["hasWebhookSecret"]), NotificationBoolean(f["emailEnabled"]), NotificationText(f["smtpHost"], 253, true),
            (int)NotificationNumber(f["smtpPort"], 587, 587), NotificationText(f["smtpUsername"], 254, true), NotificationBoolean(f["hasSmtpPassword"]),
            NotificationText(f["emailFrom"], 254, true), NotificationText(f["emailTo"], 254, true), availability!);
        if (value.HasWebhookDestination != (origin is not null)) throw new InvalidResponseException();
        return value;
    }

    internal static NotificationPage ParseNotificationPage(JsonElement root, int offset, int limit, bool unreadOnly)
    {
        var f = NotificationFields(root, ["total", "unread", "offset", "limit", "items"]);
        var total = (int)NotificationNumber(f["total"], 0, 100_000);
        var unread = (int)NotificationNumber(f["unread"], 0, 100_000);
        NotificationPageShape(f, total, offset, limit);
        var rows = f["items"].EnumerateArray().Select(item =>
        {
            var p = NotificationFields(item, ["notificationId", "kind", "endpointId", "endpointName", "alertId", "ruleId", "severity", "occurrences", "createdUtc", "lastObservedUtc", "readUtc"]);
            var kind = NotificationText(p["kind"], 64);
            if (kind is not ("criticalAlertNew" or "criticalAlertReopened" or "criticalAlertEscalated" or "monitoringOffline" or "monitoringRecovered")) throw new InvalidResponseException();
            var severity = NotificationText(p["severity"], 32);
            if (severity is not ("critical" or "high" or "medium" or "low" or "info")) throw new InvalidResponseException();
            var created = NotificationDate(p["createdUtc"])!.Value;
            var last = NotificationDate(p["lastObservedUtc"])!.Value;
            var read = NotificationDate(p["readUtc"], true);
            if (last < created || unreadOnly && read is not null) throw new InvalidResponseException();
            return new NotificationSummary(NotificationId(p["notificationId"]), kind!, NotificationId(p["endpointId"]), NotificationText(p["endpointName"], 255)!,
                p["alertId"].ValueKind == JsonValueKind.Null ? null : NotificationId(p["alertId"]), NotificationText(p["ruleId"], 128, true), severity!,
                (int)NotificationNumber(p["occurrences"], 1, int.MaxValue), created, last, read);
        }).ToArray();
        if (rows.Select(x => x.NotificationId).Distinct().Count() != rows.Length || !unreadOnly && unread > total) throw new InvalidResponseException();
        return new(total, unread, offset, limit, rows);
    }

    internal static NotificationDeliveryPage ParseNotificationDeliveries(JsonElement root, int offset, int limit, Guid? notificationId)
    {
        var f = NotificationFields(root, ["total", "offset", "limit", "items"]);
        var total = (int)NotificationNumber(f["total"], 0, 100_000);
        NotificationPageShape(f, total, offset, limit);
        var rows = f["items"].EnumerateArray().Select(item =>
        {
            var p = NotificationFields(item, ["deliveryId", "notificationId", "channel", "state", "attempts", "createdUtc", "lastAttemptUtc", "nextAttemptUtc", "resultCode"]);
            var channel = NotificationText(p["channel"], 32);
            var state = NotificationText(p["state"], 32);
            var code = NotificationText(p["resultCode"], 64, true);
            if (channel is not ("webhook" or "email") || state is not ("pending" or "sending" or "retry" or "succeeded" or "failed" or "cancelled") ||
                code is not null && code.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')) throw new InvalidResponseException();
            var id = NotificationId(p["notificationId"]);
            if (notificationId is { } expected && id != expected) throw new InvalidResponseException();
            return new NotificationDelivery(NotificationId(p["deliveryId"]), id, channel!, state!, (int)NotificationNumber(p["attempts"], 0, 100),
                NotificationDate(p["createdUtc"])!.Value, NotificationDate(p["lastAttemptUtc"], true), NotificationDate(p["nextAttemptUtc"], true), code);
        }).ToArray();
        if (rows.Select(x => x.DeliveryId).Distinct().Count() != rows.Length) throw new InvalidResponseException();
        return new(total, offset, limit, rows);
    }

    private static void NotificationPageShape(Dictionary<string, JsonElement> f, int total, int offset, int limit)
    {
        if (NotificationNumber(f["offset"], 0, 100_000) != offset || NotificationNumber(f["limit"], 1, NotificationContract.MaximumPageSize) != limit ||
            f["items"].ValueKind != JsonValueKind.Array || f["items"].GetArrayLength() != Math.Min(limit, Math.Max(0, total - offset))) throw new InvalidResponseException();
    }
    private static Dictionary<string, JsonElement> NotificationFields(JsonElement value, string[] names)
    { var f = ReadProperties(value, names); return f.Count == names.Length ? f : throw new InvalidResponseException(); }
    private static string? NotificationText(JsonElement value, int maximum, bool optional = false) => value.ValueKind == JsonValueKind.Null && optional ? null :
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text && text.Length <= maximum && !text.Any(char.IsControl) ? text : throw new InvalidResponseException();
    private static long NotificationNumber(JsonElement value, long minimum, long maximum) => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) && number >= minimum && number <= maximum ? number : throw new InvalidResponseException();
    private static bool NotificationBoolean(JsonElement value) => value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : throw new InvalidResponseException();
    private static Guid NotificationId(JsonElement value) => value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id) && id != Guid.Empty ? id : throw new InvalidResponseException();
    private static DateTimeOffset? NotificationDate(JsonElement value, bool optional = false) => value.ValueKind == JsonValueKind.Null && optional ? null :
        value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out var date) && date.Offset == TimeSpan.Zero ? date : throw new InvalidResponseException();
    private sealed class NotificationTooLargeException : Exception;
}
