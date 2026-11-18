using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SentinelAI.Contracts.Backups;

namespace SentinelAI.Core.Backups;

internal static class BackupEndpoints
{
    internal static void MapBackupEndpoints(this WebApplication app, Func<HttpContext, bool> allowed)
    {
        app.MapGet("/api/admin/backups", async (HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            try { return Results.Ok(await service.GetStatusAsync(token)); }
            catch (Exception) { return Results.StatusCode(503); }
        }).RequireAuthorization();
        app.MapPut("/api/admin/backups/key", async (HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            if (!Version(context.Request.Headers.IfMatch.ToString(), out var version)) return Results.BadRequest();
            if (!ContentType(context, "application/octet-stream")) return Results.StatusCode(415);
            var key = new byte[33];
            try
            {
                if (context.Request.ContentLength is { } size && size != 32) return Results.BadRequest();
                var count = await ReadAsync(context.Request.Body, key, token);
                if (count != 32) return Results.BadRequest();
                return Mutation(await service.SetKeyAsync(version, key.AsMemory(0, 32), token), acceptedCode: 200);
            }
            catch (Exception) { return Results.StatusCode(503); }
            finally { CryptographicOperations.ZeroMemory(key); }
        }).RequireAuthorization();
        app.MapPut("/api/admin/backups/policy", async (HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            if (!ContentType(context, "application/json")) return Results.StatusCode(415);
            if (context.Request.ContentLength is > 4096) return Results.StatusCode(413);
            var bytes = new byte[4097];
            try
            {
                var count = await ReadAsync(context.Request.Body, bytes, token);
                if (count is 0 or > 4096) return Results.StatusCode(413);
                BackupPolicyRequest request;
                try
                {
                    using var json = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 2 });
                    if (json.RootElement.ValueKind != JsonValueKind.Object) return Results.BadRequest();
                    var fields = json.RootElement.EnumerateObject().ToArray();
                    if (fields.Length != 4 || fields.Select(field => field.Name).Distinct(StringComparer.Ordinal).Count() != 4 ||
                        fields.Any(field => field.Name is not ("expectedVersion" or "enabled" or "intervalHours" or "retentionCount")))
                        return Results.BadRequest();
                    request = json.RootElement.Deserialize<BackupPolicyRequest>(new JsonSerializerOptions(JsonSerializerDefaults.Web)
                    {
                        PropertyNameCaseInsensitive = false, RespectNullableAnnotations = true, RespectRequiredConstructorParameters = true
                    }) ?? throw new JsonException();
                }
                catch (JsonException) { return Results.BadRequest(); }
                if (request.ExpectedVersion < 0 || request.IntervalHours is < 1 or > BackupContract.MaximumIntervalHours ||
                    request.RetentionCount is < 1 or > BackupContract.MaximumRetentionCount) return Results.BadRequest();
                return Mutation(await service.SetPolicyAsync(request, token), acceptedCode: 200);
            }
            catch (Exception) { return Results.StatusCode(503); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }).RequireAuthorization();
        app.MapPost("/api/admin/backups", async (HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            if (HasBody(context)) return Results.BadRequest();
            try { return Mutation(await service.StartJobAsync(null, token), acceptedCode: 202); }
            catch (Exception) { return Results.StatusCode(503); }
        }).RequireAuthorization();
        app.MapPost("/api/admin/backups/{archiveId:guid}/verify", async (Guid archiveId, HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            if (archiveId == Guid.Empty || HasBody(context)) return Results.BadRequest();
            try { return Mutation(await service.StartJobAsync(archiveId, token), acceptedCode: 202); }
            catch (Exception) { return Results.StatusCode(503); }
        }).RequireAuthorization();
        app.MapGet("/api/admin/backups/{archiveId:guid}/download", async (Guid archiveId, HttpContext context, BackupService service, CancellationToken token) =>
        {
            Headers(context);
            if (!allowed(context)) return Results.StatusCode(403);
            if (archiveId == Guid.Empty) return Results.NotFound();
            try
            {
                var download = await service.OpenDownloadAsync(archiveId, token);
                if (download is null) return Results.NotFound();
                context.Response.ContentLength = download.Value.Archive.SizeBytes;
                return Results.Stream(download.Value.Stream, "application/octet-stream", archiveId.ToString("N") + ".sab", enableRangeProcessing: false);
            }
            catch (FileNotFoundException) { return Results.NotFound(); }
            catch (Exception) { return Results.StatusCode(503); }
        }).RequireAuthorization();
    }
    private static IResult Mutation(BackupMutation result, int acceptedCode) => result.Outcome switch
    {
        BackupMutationOutcome.Accepted => Results.Json(result.Status, statusCode: acceptedCode),
        BackupMutationOutcome.Conflict => Results.Json(result.Status, statusCode: 409),
        BackupMutationOutcome.NotFound => Results.NotFound(),
        _ => Results.StatusCode(503)
    };
    private static void Headers(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    }
    private static bool ContentType(HttpContext context, string expected) =>
        System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(context.Request.ContentType, out var type) && type.MediaType == expected;
    private static bool HasBody(HttpContext context) => context.Request.ContentLength is > 0 || context.Request.Headers.TransferEncoding.Count > 0;
    private static bool Version(string header, out long version)
    {
        version = 0;
        return header.Length is >= 3 and <= 22 && header[0] == '"' && header[^1] == '"' &&
            long.TryParse(header.AsSpan(1, header.Length - 2), NumberStyles.None, CultureInfo.InvariantCulture, out version) && version >= 0;
    }
    private static async Task<int> ReadAsync(Stream input, Memory<byte> buffer, CancellationToken token)
    {
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await input.ReadAsync(buffer[count..], token);
            if (read == 0) break;
            count += read;
        }
        return count;
    }
}
