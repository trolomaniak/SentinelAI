using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : ILicenseClient
{
    private const int MaximumLicenseBytes = 16 * 1024;
    private const int MaximumLicenseFeatures = 64;
    private const int MaximumLicenseFeatureCharacters = 64;

    public Task<LicenseRequestResult> GetLicenseAsync(CancellationToken cancellationToken) =>
        RequestLicenseAsync(renew: false, cancellationToken);
    public Task<LicenseRequestResult> RenewLicenseAsync(CancellationToken cancellationToken) =>
        RequestLicenseAsync(renew: true, cancellationToken);

    private async Task<LicenseRequestResult> RequestLicenseAsync(bool renew, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(LicenseRequestOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(LicenseRequestOutcome.Unauthenticated);
            }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            // One deadline covers origin verification, headers and the complete body.
            // Core's existing issuer timeout can be configured up to 60 seconds.
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(renew ? 65 : 10));
            var transmissionStarted = false;
            LicenseRequestResult result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(LicenseRequestOutcome.UntrustedConnection);
                else
                {
                    operation.Token.ThrowIfCancellationRequested();
                    using var request = new HttpRequestMessage(renew ? HttpMethod.Post : HttpMethod.Get,
                        new Uri(_origin, renew ? "api/admin/license/renew" : "api/admin/license"));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    // No body, query, issuer, identity, feature or time overrides are sent.
                    try
                    {
                        transmissionStarted = true;
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                        operation.Token.ThrowIfCancellationRequested();
                        result = await ReadLicenseResponseAsync(response, renew, operation.Token).ConfigureAwait(false);
                    }
                    finally { request.Headers.Authorization = null; }
                }
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(renew && transmissionStarted ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable);
            }
            catch (LicenseResponseTooLargeException) { result = new(renew && transmissionStarted ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(renew && transmissionStarted ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(renew && transmissionStarted ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable);
            }
            finally { CryptographicOperations.ZeroMemory(token); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(LicenseRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(LicenseRequestOutcome.Unauthenticated);
                }
                if (result.Outcome is LicenseRequestOutcome.Unauthenticated or LicenseRequestOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
    }

    private static async Task<LicenseRequestResult> ReadLicenseResponseAsync(HttpResponseMessage response, bool renew, CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized) return new(LicenseRequestOutcome.Unauthenticated);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) return new(LicenseRequestOutcome.Throttled);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            // Core rejects these statuses before invoking renewal. Other failures
            // cannot establish whether its single renewal attempt completed.
            return new(renew && response.StatusCode is not (HttpStatusCode.BadRequest or HttpStatusCode.Forbidden or
                HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.ServiceUnavailable)
                ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable);
        }
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > MaximumLicenseBytes) throw new LicenseResponseTooLargeException();
        var buffer = new byte[MaximumLicenseBytes + 1];
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
            if (length > MaximumLicenseBytes) throw new LicenseResponseTooLargeException();
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 4 });
            var status = ParseLicenseStatus(json.RootElement);
            cancellationToken.ThrowIfCancellationRequested();
            return new(LicenseRequestOutcome.Success, status);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static LicenseStatus ParseLicenseStatus(JsonElement root)
    {
        var fields = ReadProperties(root, ["mode", "capabilities", "lastSuccessfulValidationUtc", "fullModeUntil", "effectiveUtc", "clockRollbackDetected", "enabledFeatures"]);
        var mode = LicenseRequired(fields, "mode");
        if (mode.ValueKind != JsonValueKind.String || mode.GetString() is not ("FULL" or "GRACE" or "SAFE_MODE" or "RECOVERING")) throw new InvalidResponseException();
        var capabilities = ReadProperties(LicenseRequired(fields, "capabilities"),
            ["criticalTelemetryCollection", "localDetectionRules", "criticalAlerts", "recentIncidents", "emergencyExport", "premiumFeatures"]);
        var enabled = LicenseRequired(fields, "enabledFeatures");
        if (enabled.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (enabled.GetArrayLength() > MaximumLicenseFeatures) throw new LicenseResponseTooLargeException();
        var features = new List<string>(enabled.GetArrayLength());
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var feature in enabled.EnumerateArray())
        {
            if (feature.ValueKind != JsonValueKind.String) throw new InvalidResponseException();
            var text = feature.GetString()!;
            if (text.Length is < 1 or > MaximumLicenseFeatureCharacters || !text.All(character =>
                character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-') || !unique.Add(text)) throw new InvalidResponseException();
            features.Add(text);
        }
        // Keep Core's current mode and permission decisions verbatim. Desktop does
        // not recalculate lease deadlines or infer an unavailable last-attempt field.
        return new(mode.GetString()!, new(LicenseBoolean(capabilities, "criticalTelemetryCollection"),
            LicenseBoolean(capabilities, "localDetectionRules"), LicenseBoolean(capabilities, "criticalAlerts"),
            LicenseBoolean(capabilities, "recentIncidents"), LicenseBoolean(capabilities, "emergencyExport"),
            LicenseBoolean(capabilities, "premiumFeatures")), LicenseOptionalDate(LicenseRequired(fields, "lastSuccessfulValidationUtc")),
            LicenseOptionalDate(LicenseRequired(fields, "fullModeUntil")), LicenseDate(LicenseRequired(fields, "effectiveUtc")),
            LicenseBoolean(fields, "clockRollbackDetected"), features.AsReadOnly());
    }
    private static JsonElement LicenseRequired(Dictionary<string, JsonElement> fields, string name) =>
        fields.TryGetValue(name, out var value) ? value : throw new InvalidResponseException();
    private static bool LicenseBoolean(Dictionary<string, JsonElement> fields, string name) => LicenseRequired(fields, name).ValueKind switch
    {
        JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException()
    };
    private static DateTimeOffset? LicenseOptionalDate(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : LicenseDate(value);
    private static DateTimeOffset LicenseDate(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || !(value.GetString()!.EndsWith('Z') || value.GetString()!.EndsWith("+00:00", StringComparison.Ordinal)) ||
            !value.TryGetDateTimeOffset(out var date) || date.Offset != TimeSpan.Zero) throw new InvalidResponseException();
        return date;
    }
    private sealed class LicenseResponseTooLargeException : Exception;
}
