using System.Text.Json;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Core;

// Called only after transport and Agent authentication, so an unauthenticated caller
// can never make Core buffer or parse a batch. The body is never logged.
internal static class SecurityEventRequestReader
{
    public static async Task<(SecurityEventBatch? Batch, int? ErrorStatus)> ReadAsync(
        HttpRequest request, CancellationToken cancellationToken)
    {
        if (!request.HasJsonContentType())
        {
            return (null, StatusCodes.Status415UnsupportedMediaType);
        }
        if (request.ContentLength > SecurityEventContract.MaxRequestBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        var buffer = new byte[SecurityEventContract.MaxRequestBytes + 1];
        var length = 0;
        try
        {
            while (length < buffer.Length)
            {
                var read = await request.Body.ReadAsync(buffer.AsMemory(length), cancellationToken);
                if (read == 0) break;
                length += read;
            }
        }
        catch (BadHttpRequestException)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }
        if (length > SecurityEventContract.MaxRequestBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        try
        {
            // Strict shared options: duplicate keys, nulls in non-nullable members, missing
            // required members, quoted numbers and excessive depth all fail as JsonException.
            var batch = JsonSerializer.Deserialize<SecurityEventBatch>(
                buffer.AsSpan(0, length), SecurityEventContract.Json);
            return batch is null ? (null, StatusCodes.Status400BadRequest) : (batch, null);
        }
        catch (JsonException)
        {
            return (null, StatusCodes.Status400BadRequest);
        }
    }
}
