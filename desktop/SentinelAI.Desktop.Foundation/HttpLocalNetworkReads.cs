using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : ILocalNetworkClient
{
    private const int MaximumLocalNetworkBytes = 8 * 1024;
    private const int MaximumLocalNetworkAddresses = 16;

    public async Task<LocalNetworkRequestResult> GetLocalNetworkAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(LocalNetworkRequestOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(LocalNetworkRequestOutcome.Unauthenticated);
            }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            // One deadline covers origin verification, headers and the complete body.
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(10));
            LocalNetworkRequestResult result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(LocalNetworkRequestOutcome.UntrustedConnection);
                else
                {
                    operation.Token.ThrowIfCancellationRequested();
                    using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, "api/admin/local-network"));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    try
                    {
                        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                        operation.Token.ThrowIfCancellationRequested();
                        result = await ReadLocalNetworkResponseAsync(response, operation.Token).ConfigureAwait(false);
                    }
                    finally { request.Headers.Authorization = null; }
                }
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(LocalNetworkRequestOutcome.Unavailable);
            }
            catch (LocalNetworkResponseTooLargeException) { result = new(LocalNetworkRequestOutcome.TooLarge); }
            catch (Exception exception) when (exception is InvalidResponseException or JsonException or FormatException or OverflowException)
            {
                result = new(LocalNetworkRequestOutcome.InvalidResponse);
            }
            catch (Exception)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = new(LocalNetworkRequestOutcome.Unavailable);
            }
            finally { CryptographicOperations.ZeroMemory(token); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(LocalNetworkRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt)
                {
                    ResetGenerationLocked();
                    return new(LocalNetworkRequestOutcome.Unauthenticated);
                }
                if (result.Outcome is LocalNetworkRequestOutcome.Unauthenticated or LocalNetworkRequestOutcome.UntrustedConnection) ResetGenerationLocked();
                return result;
            }
        }
    }

    private static async Task<LocalNetworkRequestResult> ReadLocalNetworkResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized) return new(LocalNetworkRequestOutcome.Unauthenticated);
        if (response.StatusCode != HttpStatusCode.OK) return new(LocalNetworkRequestOutcome.Unavailable);
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > MaximumLocalNetworkBytes) throw new LocalNetworkResponseTooLargeException();
        var buffer = new byte[MaximumLocalNetworkBytes + 1];
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
            if (length > MaximumLocalNetworkBytes) throw new LocalNetworkResponseTooLargeException();
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 3 });
            return new(LocalNetworkRequestOutcome.Success, ParseLocalNetworkStatus(json.RootElement));
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static LocalNetworkStatus ParseLocalNetworkStatus(JsonElement root)
    {
        var fields = ReadProperties(root, ["enabled", "listening", "port", "certificateSha256", "hostName", "fullyQualifiedName", "addresses"]);
        if (fields.Count != 7) throw new InvalidResponseException();
        var enabled = LocalNetworkBoolean(fields["enabled"]);
        var listening = LocalNetworkBoolean(fields["listening"]);
        int? port = fields["port"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.Number when fields["port"].TryGetInt32(out var value) && value is >= 1 and <= 65535 => value,
            _ => throw new InvalidResponseException()
        };
        var fingerprint = fields["certificateSha256"].ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String when fields["certificateSha256"].GetString() is { Length: 64 } text &&
                text.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F') => text,
            _ => throw new InvalidResponseException()
        };
        var hostName = LocalNetworkName(fields["hostName"]) ?? throw new InvalidResponseException();
        var fullyQualifiedName = fields["fullyQualifiedName"].ValueKind == JsonValueKind.Null ? null
            : LocalNetworkName(fields["fullyQualifiedName"]) ?? throw new InvalidResponseException();
        var list = fields["addresses"];
        if (list.ValueKind != JsonValueKind.Array) throw new InvalidResponseException();
        if (list.GetArrayLength() > MaximumLocalNetworkAddresses) throw new LocalNetworkResponseTooLargeException();
        var addresses = new List<string>(list.GetArrayLength());
        foreach (var item in list.EnumerateArray())
        {
            // Only canonical IPv4 unicast text is displayed.
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { Length: >= 7 and <= 15 } text ||
                !IPAddress.TryParse(text, out var address) || address.AddressFamily != AddressFamily.InterNetwork ||
                address.ToString() != text || addresses.Contains(text, StringComparer.Ordinal)) throw new InvalidResponseException();
            addresses.Add(text);
        }
        // Core reports a port and fingerprint exactly when the role is configured; listening requires both.
        if (enabled != (port is not null) || enabled != (fingerprint is not null) || listening && !enabled || !enabled && addresses.Count != 0)
            throw new InvalidResponseException();
        return new(enabled, listening, port, fingerprint, hostName, fullyQualifiedName, addresses.AsReadOnly());
    }

    private static bool LocalNetworkBoolean(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException()
    };

    // Computer names are displayed literally; control and separator characters are refused.
    private static string? LocalNetworkName(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: >= 1 and <= 253 } text &&
        !text.Any(character => char.IsControl(character) || char.IsWhiteSpace(character) || char.GetUnicodeCategory(character) is
            System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator or
            System.Globalization.UnicodeCategory.ParagraphSeparator) ? text : null;

    private sealed class LocalNetworkResponseTooLargeException : Exception;
}
