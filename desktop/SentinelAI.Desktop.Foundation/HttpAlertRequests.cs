using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient
{
    private const int MaximumAlertPageBytes = 1024 * 1024;
    private const int MaximumAlertDetailBytes = 256 * 1024;
    private const int MaximumAlertHistory = 100;
    private const int MaximumAlertEvidence = 64;
    private static readonly string[] AlertSummaryFields = ["alertId", "endpointId", "endpointName", "ruleId", "title", "severity", "status", "firstObservedUtc", "lastObservedUtc", "updatedUtc", "version"];

    public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (query is null || query.EndpointId == Guid.Empty || query.Offset < 0 || query.Limit is < 1 or > 200 ||
            query.Severity is not null && !ValidAlertSeverity(query.Severity) || query.Status is not null && !ValidAlertStatus(query.Status))
            return InvalidAlertRequest<AlertPage>();
        var path = "api/admin/alerts?offset=" + query.Offset.ToString(CultureInfo.InvariantCulture) + "&limit=" + query.Limit.ToString(CultureInfo.InvariantCulture);
        if (query.EndpointId is { } endpointId) path += "&endpointId=" + endpointId.ToString("D");
        if (query.Severity is { } severity) path += "&severity=" + severity;
        if (query.Status is { } status) path += "&status=" + status;
        return RequestAlertAsync(path, MaximumAlertPageBytes, root => ParseAlertPage(root, query), null, cancellationToken);
    }

    public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return alertId == Guid.Empty ? InvalidAlertRequest<AlertDetail>() : RequestAlertAsync("api/admin/alerts/" + alertId.ToString("D"),
            MaximumAlertDetailBytes, root => ParseAlertDetail(root, alertId), null, cancellationToken);
    }

    public Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status, long expectedVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (alertId == Guid.Empty || !ValidAlertStatus(status) || expectedVersion < 1) return InvalidAlertRequest<AlertDetail>();
        return RequestAlertAsync("api/admin/alerts/" + alertId.ToString("D") + "/status", MaximumAlertDetailBytes,
            root =>
            {
                var detail = ParseAlertDetail(root, alertId);
                // Core treats an unchanged status as an idempotent decision. A changed
                // status advances exactly one version within its update transaction.
                if (detail.Alert.Status != status || detail.Alert.Version != expectedVersion &&
                    (expectedVersion == long.MaxValue || detail.Alert.Version != expectedVersion + 1)) throw new InvalidResponseException();
                return detail;
            }, new AlertStatusWrite(status, expectedVersion), cancellationToken);
    }

    private Task<AlertResult<T>> InvalidAlertRequest<T>()
    {
        lock (_gate)
        {
            if (_disposed || _token is null) return Task.FromResult(new AlertResult<T>(AlertOutcome.Unauthenticated));
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return Task.FromResult(new AlertResult<T>(AlertOutcome.Unauthenticated));
            }
            return Task.FromResult(new AlertResult<T>(AlertOutcome.InvalidResponse));
        }
    }

    private async Task<AlertResult<T>> RequestAlertAsync<T>(string path, int maximumBytes, Func<JsonElement, T> parse,
        AlertStatusWrite? write, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(AlertOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(AlertOutcome.Unauthenticated);
            }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(10));
            var transmissionStarted = false;
            AlertResult<T> result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(AlertOutcome.UntrustedConnection);
                else
                {
                    operation.Token.ThrowIfCancellationRequested();
                    using var request = new HttpRequestMessage(write is null ? HttpMethod.Get : HttpMethod.Put, new Uri(_origin, path));
                    using var requestBuffer = new RequestBuffer();
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    try
                    {
                        if (write is not null)
                        {
                            using var writer = new Utf8JsonWriter(requestBuffer);
                            writer.WriteStartObject();
                            writer.WriteString("status", write.Status);
                            writer.WriteNumber("expectedVersion", write.ExpectedVersion);
                            writer.WriteEndObject();
                            writer.Flush();
                            request.Content = new ByteArrayContent(requestBuffer.Buffer, 0, requestBuffer.Length);
                            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                        }
                        transmissionStarted = true;
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                        requestBuffer.Clear();
                        operation.Token.ThrowIfCancellationRequested();
                        result = await ReadAlertResponseAsync(response, maximumBytes, parse, write is not null, operation.Token).ConfigureAwait(false);
                    }
                    finally { request.Headers.Authorization = null; }
                }
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(write is not null && transmissionStarted ? AlertOutcome.Indeterminate : AlertOutcome.Unavailable);
            }
            catch (AlertResponseTooLargeException) { result = new(write is not null && transmissionStarted ? AlertOutcome.Indeterminate : AlertOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(write is not null && transmissionStarted ? AlertOutcome.Indeterminate : AlertOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(write is not null && transmissionStarted ? AlertOutcome.Indeterminate : AlertOutcome.Unavailable);
            }
            finally { CryptographicOperations.ZeroMemory(token); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(AlertOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(AlertOutcome.Unauthenticated);
                }
                if (result.Outcome is AlertOutcome.Unauthenticated or AlertOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
    }

    private static async Task<AlertResult<T>> ReadAlertResponseAsync<T>(HttpResponseMessage response, int maximumBytes,
        Func<JsonElement, T> parse, bool write, CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized) return new(AlertOutcome.Unauthenticated);
        if (response.StatusCode == HttpStatusCode.NotFound) return new(AlertOutcome.NotFound);
        if (write && response.StatusCode == HttpStatusCode.Conflict) return new(AlertOutcome.Conflict);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            if (write) return new(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden or
                HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity or HttpStatusCode.TooManyRequests
                ? AlertOutcome.Unavailable : AlertOutcome.Indeterminate);
            return new(response.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity ? AlertOutcome.TooLarge : AlertOutcome.Unavailable);
        }
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > maximumBytes) throw new AlertResponseTooLargeException();
        var buffer = new byte[maximumBytes + 1];
        try
        {
            using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var length = 0;
            while (length < buffer.Length)
            {
                var count = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                length += count;
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (length > maximumBytes) throw new AlertResponseTooLargeException();
            using var document = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 6 });
            var value = parse(document.RootElement);
            cancellationToken.ThrowIfCancellationRequested();
            return new(AlertOutcome.Success, value);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static AlertPage ParseAlertPage(JsonElement root, AlertQuery query)
    {
        var fields = ReadProperties(root, ["alerts", "total", "offset", "limit"]);
        var total = AlertInteger(fields, "total", 0);
        if (AlertInteger(fields, "offset", 0) != query.Offset || AlertInteger(fields, "limit", 1) != query.Limit ||
            !fields.TryGetValue("alerts", out var array) || array.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (array.GetArrayLength() > query.Limit) throw new AlertResponseTooLargeException();
        if (array.GetArrayLength() > total || array.GetArrayLength() > 0 && (long)query.Offset + array.GetArrayLength() > total) throw new InvalidResponseException();
        var alerts = new List<AlertSummary>(array.GetArrayLength());
        var identities = new HashSet<Guid>();
        foreach (var element in array.EnumerateArray())
        {
            var alert = ParseAlertSummary(ReadProperties(element, AlertSummaryFields));
            if (!identities.Add(alert.AlertId) || query.EndpointId is { } endpointId && alert.EndpointId != endpointId ||
                query.Severity is { } severity && alert.Severity != severity || query.Status is { } status && alert.Status != status) throw new InvalidResponseException();
            alerts.Add(alert);
        }
        return new AlertPage(alerts.AsReadOnly(), total, query.Offset, query.Limit);
    }

    private static AlertSummary ParseAlertSummary(Dictionary<string, JsonElement> fields)
    {
        var severity = AlertText(fields, "severity", 16);
        var status = AlertText(fields, "status", 16);
        if (!ValidAlertSeverity(severity) || !ValidAlertStatus(status)) throw new InvalidResponseException();
        return new AlertSummary(AlertIdentity(fields, "alertId"), AlertIdentity(fields, "endpointId"), AlertText(fields, "endpointName", 256),
            AlertText(fields, "ruleId", 128), AlertText(fields, "title", 512), severity, status,
            AlertDate(fields, "firstObservedUtc"), AlertDate(fields, "lastObservedUtc"), AlertDate(fields, "updatedUtc"), AlertInteger(fields, "version", 1));
    }

    private static AlertDetail ParseAlertDetail(JsonElement root, Guid expectedAlertId)
    {
        var fields = ReadProperties(root, [.. AlertSummaryFields, "reason", "evidence", "recommendedAction", "createdUtc", "statusChangedUtc", "statusHistory", "statusHistoryCount"]);
        var alert = ParseAlertSummary(fields);
        if (alert.AlertId != expectedAlertId) throw new InvalidResponseException();
        if (!fields.TryGetValue("evidence", out var evidenceArray) || evidenceArray.ValueKind != JsonValueKind.Array ||
            !fields.TryGetValue("statusHistory", out var historyArray) || historyArray.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (evidenceArray.GetArrayLength() > MaximumAlertEvidence || historyArray.GetArrayLength() > MaximumAlertHistory) throw new AlertResponseTooLargeException();
        var evidence = new List<AlertEvidence>(evidenceArray.GetArrayLength());
        foreach (var element in evidenceArray.EnumerateArray())
        {
            var item = ReadProperties(element, ["field", "value"]);
            var field = AlertText(item, "field", 128);
            if (!item.TryGetValue("value", out var value)) throw new InvalidResponseException();
            evidence.Add(value.ValueKind switch
            {
                JsonValueKind.Null => new AlertEvidence(field, AlertEvidenceKind.Unknown),
                JsonValueKind.True or JsonValueKind.False => new AlertEvidence(field, AlertEvidenceKind.Boolean, BooleanValue: value.GetBoolean()),
                JsonValueKind.Number when value.TryGetInt64(out var integer) => new AlertEvidence(field, AlertEvidenceKind.Integer, IntegerValue: integer),
                JsonValueKind.String => new AlertEvidence(field, AlertEvidenceKind.String, StringValue: AlertText(item, "value", 2048, allowWhitespace: true, allowEmpty: true)),
                _ => throw new InvalidResponseException()
            });
        }
        var count = AlertInteger(fields, "statusHistoryCount", 1);
        if (historyArray.GetArrayLength() != Math.Min(count, MaximumAlertHistory)) throw new InvalidResponseException();
        var history = new List<AlertStatusChange>(historyArray.GetArrayLength());
        foreach (var element in historyArray.EnumerateArray())
        {
            var item = ReadProperties(element, ["previousStatus", "status", "changedUtc", "changedBy"]);
            if (!item.TryGetValue("previousStatus", out var previousElement)) throw new InvalidResponseException();
            var previous = previousElement.ValueKind == JsonValueKind.Null ? null : AlertText(item, "previousStatus", 16);
            var status = AlertText(item, "status", 16);
            if (previous is not null && !ValidAlertStatus(previous) || !ValidAlertStatus(status)) throw new InvalidResponseException();
            history.Add(new AlertStatusChange(previous, status, AlertDate(item, "changedUtc"), AlertText(item, "changedBy", 256)));
        }
        var statusChanged = AlertDate(fields, "statusChangedUtc");
        if (history[^1].Status != alert.Status || history[^1].ChangedUtc != statusChanged) throw new InvalidResponseException();
        return new AlertDetail(alert, AlertText(fields, "reason", 4096, allowWhitespace: true), evidence.AsReadOnly(),
            AlertText(fields, "recommendedAction", 4096, allowWhitespace: true), AlertDate(fields, "createdUtc"), statusChanged, history.AsReadOnly(), count);
    }

    private static Guid AlertIdentity(Dictionary<string, JsonElement> fields, string name)
    {
        if (!fields.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.String ||
            !Guid.TryParseExact(element.GetString(), "D", out var identity) || identity == Guid.Empty) throw new InvalidResponseException();
        return identity;
    }

    private static string AlertText(Dictionary<string, JsonElement> fields, string name, int maximum, bool allowWhitespace = false, bool allowEmpty = false)
    {
        if (!fields.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.String) throw new InvalidResponseException();
        var value = element.GetString()!;
        if (value.Length > maximum) throw new AlertResponseTooLargeException();
        if (!allowEmpty && string.IsNullOrWhiteSpace(value) || value.Any(character => char.IsControl(character) && !(allowWhitespace && character is '\r' or '\n' or '\t'))) throw new InvalidResponseException();
        return value;
    }

    private static long AlertInteger(Dictionary<string, JsonElement> fields, string name, long minimum)
    {
        if (!fields.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value) || value < minimum) throw new InvalidResponseException();
        return value;
    }

    private static DateTimeOffset AlertDate(Dictionary<string, JsonElement> fields, string name)
    {
        if (!fields.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.String ||
            !(element.GetString()!.EndsWith('Z') || element.GetString()!.EndsWith("+00:00", StringComparison.Ordinal)) ||
            !element.TryGetDateTimeOffset(out var value) || value.Offset != TimeSpan.Zero) throw new InvalidResponseException();
        return value;
    }

    private static bool ValidAlertSeverity(string? value) => value is "info" or "low" or "medium" or "high" or "critical";
    private static bool ValidAlertStatus(string? value) => value is "open" or "investigating" or "accepted" or "resolved";
    private sealed record AlertStatusWrite(string Status, long ExpectedVersion);
    private sealed class AlertResponseTooLargeException : Exception;
}
