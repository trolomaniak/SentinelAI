using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Enrollment;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IComputerEnrollmentClient
{
    private const int MaximumEnrollmentOptionsBytes = 8 * 1024;
    private const int MaximumIssuedCodesBytes = 64 * 1024;
    private const int MaximumUnusedCodesBytes = 256 * 1024;
    private const int MaximumEnrollmentAddresses = 32;
    private const int MaximumUnusedCodes = 2000;

    public Task<ComputerEnrollmentResult<ComputerEnrollmentOptions>> GetEnrollmentOptionsAsync(CancellationToken cancellationToken) =>
        SendEnrollmentAsync(HttpMethod.Get, "api/admin/enrollment-options", null, MaximumEnrollmentOptionsBytes, ParseEnrollmentOptions, cancellationToken);

    public Task<ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>> IssueCodesAsync(int count, int validityHours, string address,
        CancellationToken cancellationToken)
    {
        if (count is < 1 or > 50 || validityHours is < 1 or > 168 || !EnrollmentCode.IsAddress(address))
            return Task.FromResult(new ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>(ComputerEnrollmentOutcome.Rejected));
        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteNumber("count", count);
            writer.WriteNumber("validityHours", validityHours);
            writer.WriteString("address", address);
            writer.WriteEndObject();
        }

        return SendEnrollmentAsync(HttpMethod.Post, "api/admin/enrollment-codes", body.ToArray(), MaximumIssuedCodesBytes,
            root => ParseIssuedCodes(root, count, address), cancellationToken);
    }

    public Task<ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>> GetUnusedCodesAsync(CancellationToken cancellationToken) =>
        SendEnrollmentAsync(HttpMethod.Get, "api/admin/enrollment-codes", null, MaximumUnusedCodesBytes, ParseUnusedCodes, cancellationToken);

    public async Task<ComputerEnrollmentOutcome> RevokeCodeAsync(Guid id, CancellationToken cancellationToken) => id == Guid.Empty
        ? ComputerEnrollmentOutcome.Rejected
        : (await SendEnrollmentAsync<object>(HttpMethod.Delete, "api/admin/enrollment-codes/" + id.ToString("D"), null, 0, null, cancellationToken)
            .ConfigureAwait(false)).Outcome;

    public async Task<ComputerEnrollmentOutcome> RemoveComputerAsync(Guid endpointId, CancellationToken cancellationToken) => endpointId == Guid.Empty
        ? ComputerEnrollmentOutcome.Rejected
        : (await SendEnrollmentAsync<object>(HttpMethod.Delete, "api/admin/devices/" + endpointId.ToString("D"), null, 0, null, cancellationToken)
            .ConfigureAwait(false)).Outcome;

    // One administrator request on the trusted loopback session: no body is expected when parse is null (204).
    private async Task<ComputerEnrollmentResult<T>> SendEnrollmentAsync<T>(HttpMethod method, string path, byte[]? body, int maximumBytes,
        Func<JsonElement, T>? parse, CancellationToken cancellationToken, int maximumDepth = 4) where T : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(ComputerEnrollmentOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(ComputerEnrollmentOutcome.Unauthenticated);
            }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(15));
            ComputerEnrollmentResult<T> result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(ComputerEnrollmentOutcome.UntrustedConnection);
                else
                {
                    operation.Token.ThrowIfCancellationRequested();
                    using var request = new HttpRequestMessage(method, new Uri(_origin, path));
                    if (body is not null) request.Content = new ByteArrayContent(body) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } };
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    try
                    {
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                        operation.Token.ThrowIfCancellationRequested();
                        result = await ReadEnrollmentResponseAsync(response, maximumBytes, parse, maximumDepth, operation.Token).ConfigureAwait(false);
                    }
                    finally { request.Headers.Authorization = null; }
                }
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(ComputerEnrollmentOutcome.Unavailable);
            }
            catch (EnrollmentResponseTooLargeException) { result = new(ComputerEnrollmentOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(ComputerEnrollmentOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(ComputerEnrollmentOutcome.Unavailable);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(token);
                if (body is not null) CryptographicOperations.ZeroMemory(body);
            }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(ComputerEnrollmentOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(ComputerEnrollmentOutcome.Unauthenticated);
                }
                if (result.Outcome is ComputerEnrollmentOutcome.Unauthenticated or ComputerEnrollmentOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
    }

    private static async Task<ComputerEnrollmentResult<T>> ReadEnrollmentResponseAsync<T>(HttpResponseMessage response, int maximumBytes,
        Func<JsonElement, T>? parse, int maximumDepth, CancellationToken cancellationToken) where T : class
    {
        switch (response.StatusCode)
        {
            case HttpStatusCode.Unauthorized: return new(ComputerEnrollmentOutcome.Unauthenticated);
            case HttpStatusCode.NotFound: return new(ComputerEnrollmentOutcome.NotFound);
            case HttpStatusCode.Conflict: return new(ComputerEnrollmentOutcome.Conflict);
            case HttpStatusCode.BadRequest: return new(ComputerEnrollmentOutcome.Rejected);
            case HttpStatusCode.UnprocessableEntity: return new(ComputerEnrollmentOutcome.Rejected);
        }
        if (parse is null) return response.StatusCode == HttpStatusCode.NoContent ? new(ComputerEnrollmentOutcome.Success) : new(ComputerEnrollmentOutcome.Unavailable);
        if (response.StatusCode != HttpStatusCode.OK) return new(ComputerEnrollmentOutcome.Unavailable);
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > maximumBytes) throw new EnrollmentResponseTooLargeException();
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
            if (length > maximumBytes) throw new EnrollmentResponseTooLargeException();
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = maximumDepth });
            return new(ComputerEnrollmentOutcome.Success, parse(json.RootElement));
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static ComputerEnrollmentOptions ParseEnrollmentOptions(JsonElement root)
    {
        var fields = ReadProperties(root, ["available", "listening", "port", "recommendedAddress", "addresses"]);
        if (fields.Count != 5) throw new InvalidResponseException();
        var available = EnrollmentBoolean(fields["available"]);
        var listening = EnrollmentBoolean(fields["listening"]);
        int? port = fields["port"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.Number when fields["port"].TryGetInt32(out var value) && value is >= 1 and <= 65535 => value,
            _ => throw new InvalidResponseException()
        };
        var recommended = fields["recommendedAddress"].ValueKind == JsonValueKind.Null ? null : EnrollmentAddress(fields["recommendedAddress"]);
        var list = fields["addresses"];
        if (list.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (list.GetArrayLength() > MaximumEnrollmentAddresses) throw new EnrollmentResponseTooLargeException();
        var addresses = new List<EnrollmentAddressOption>();
        foreach (var item in list.EnumerateArray())
        {
            var entry = ReadProperties(item, ["value", "kind", "resolves"]);
            if (entry.Count != 3 || entry["kind"].ValueKind != JsonValueKind.String) throw new InvalidResponseException();
            var value = EnrollmentAddress(entry["value"]);
            var isName = entry["kind"].GetString() switch { "name" => true, "ipv4" => false, _ => throw new InvalidResponseException() };
            if (isName == System.Net.IPAddress.TryParse(value, out _) || addresses.Any(address => string.Equals(address.Value, value, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidResponseException();
            addresses.Add(new EnrollmentAddressOption(value, isName, EnrollmentBoolean(entry["resolves"])));
        }
        // Codes need the configured role; the recommended address is one of the offered addresses.
        if (available != (port is not null) || listening && !available || !available && (addresses.Count != 0 || recommended is not null) ||
            recommended is not null && !addresses.Any(address => address.Value == recommended))
            throw new InvalidResponseException();
        return new(available, listening, port, recommended, addresses.AsReadOnly());
    }

    private static IReadOnlyList<IssuedComputerCode> ParseIssuedCodes(JsonElement root, int count, string address)
    {
        var fields = ReadProperties(root, ["codes"]);
        if (fields.Count != 1 || fields["codes"].ValueKind != JsonValueKind.Array || fields["codes"].GetArrayLength() != count)
            throw new InvalidResponseException();
        var codes = new List<IssuedComputerCode>(count);
        foreach (var item in fields["codes"].EnumerateArray())
        {
            var entry = ReadProperties(item, ["id", "code", "expiresUtc"]);
            if (entry.Count != 3 || !entry["id"].TryGetGuid(out var id) || id == Guid.Empty || entry["code"].ValueKind != JsonValueKind.String ||
                !entry["expiresUtc"].TryGetDateTimeOffset(out var expires))
                throw new InvalidResponseException();
            // Only a well-formed code for the chosen address is shown to the administrator.
            var text = entry["code"].GetString()!;
            if (!EnrollmentCode.TryParse(text, out var code) || code!.Address != address || codes.Any(existing => existing.Id == id || existing.Code == text))
                throw new InvalidResponseException();
            codes.Add(new IssuedComputerCode(id, text, expires));
        }
        return codes.AsReadOnly();
    }

    private static IReadOnlyList<UnusedComputerCode> ParseUnusedCodes(JsonElement root)
    {
        var fields = ReadProperties(root, ["codes"]);
        if (fields.Count != 1 || fields["codes"].ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (fields["codes"].GetArrayLength() > MaximumUnusedCodes) throw new EnrollmentResponseTooLargeException();
        var codes = new List<UnusedComputerCode>();
        foreach (var item in fields["codes"].EnumerateArray())
        {
            var entry = ReadProperties(item, ["id", "createdUtc", "expiresUtc"]);
            if (entry.Count != 3 || !entry["id"].TryGetGuid(out var id) || id == Guid.Empty ||
                !entry["createdUtc"].TryGetDateTimeOffset(out var created) || !entry["expiresUtc"].TryGetDateTimeOffset(out var expires) ||
                expires <= created || codes.Any(existing => existing.Id == id))
                throw new InvalidResponseException();
            codes.Add(new UnusedComputerCode(id, created, expires));
        }
        return codes.AsReadOnly();
    }

    private static bool EnrollmentBoolean(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException()
    };

    private static string EnrollmentAddress(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { } text && EnrollmentCode.IsAddress(text) ? text : throw new InvalidResponseException();

    private sealed class EnrollmentResponseTooLargeException : Exception;
}
