using System.Text.Json;

namespace SentinelAI.Core;

// Called only after transport and Agent authentication, so an unauthenticated caller can never make Core buffer or
// parse a body. Bodies and parser messages are never logged.
internal static class AgentJsonRequestReader
{
    public static async Task<(T? Value, int? ErrorStatus)> ReadAsync<T>(HttpRequest request, int maximumBytes,
        JsonSerializerOptions options, CancellationToken cancellationToken) where T : class
    {
        if (!request.HasJsonContentType())
        {
            return (null, StatusCodes.Status415UnsupportedMediaType);
        }

        if (request.ContentLength > maximumBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        var buffer = new byte[maximumBytes + 1];
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

        if (length > maximumBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        try
        {
            // Strict options: duplicate keys, nulls in non-nullable members, missing required members, quoted
            // numbers and excessive depth all fail as JsonException.
            var value = JsonSerializer.Deserialize<T>(buffer.AsSpan(0, length), options);
            return value is null ? (null, StatusCodes.Status400BadRequest) : (value, null);
        }
        catch (JsonException)
        {
            return (null, StatusCodes.Status400BadRequest);
        }
    }
}
