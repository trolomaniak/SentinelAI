using System.Text.Json;
using SentinelAI.Licensing;

namespace SentinelAI.Core;

internal static class LicenseVerificationRequestReader
{
    public const int MaximumRequestBytes = 20 * 1024;

    public static async Task<(string? Lease, int? ErrorStatus)> ReadAsync(
        HttpRequest request, CancellationToken cancellationToken)
    {
        if (!request.HasJsonContentType())
        {
            return (null, StatusCodes.Status415UnsupportedMediaType);
        }
        if (request.ContentLength > MaximumRequestBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        var buffer = new byte[MaximumRequestBytes + 1];
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
        if (length > MaximumRequestBytes)
        {
            return (null, StatusCodes.Status413PayloadTooLarge);
        }

        try
        {
            using var document = JsonDocument.Parse(buffer.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
                !root.TryGetProperty("lease", out var value) || value.ValueKind != JsonValueKind.String)
            {
                return (null, StatusCodes.Status400BadRequest);
            }

            var lease = value.GetString();
            return string.IsNullOrEmpty(lease) || lease.Length > LeaseTokenFormat.MaxTokenLength
                ? (null, StatusCodes.Status400BadRequest)
                : (lease, null);
        }
        catch (JsonException)
        {
            return (null, StatusCodes.Status400BadRequest);
        }
    }
}
