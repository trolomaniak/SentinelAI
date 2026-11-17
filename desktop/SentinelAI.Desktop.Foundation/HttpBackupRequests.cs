using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IBackupClient
{
    public Task<BackupRequestResult> GetBackupStatusAsync(CancellationToken cancellationToken) =>
        BackupRequestAsync(HttpMethod.Get, "api/admin/backups", null, null, null, cancellationToken);
    public Task<BackupRequestResult> SetBackupPolicyAsync(BackupPolicyRequest policy, CancellationToken cancellationToken) =>
        BackupRequestAsync(HttpMethod.Put, "api/admin/backups/policy", JsonSerializer.SerializeToUtf8Bytes(policy, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            "application/json", null, cancellationToken);
    public Task<BackupRequestResult> SetBackupKeyAsync(long expectedVersion, ReadOnlyMemory<byte> key, CancellationToken cancellationToken)
    {
        if (key.Length != 32 || expectedVersion < 0) throw new ArgumentException("A valid recovery key and policy version are required.");
        return BackupRequestAsync(HttpMethod.Put, "api/admin/backups/key", key.ToArray(), "application/octet-stream", expectedVersion, cancellationToken);
    }
    public Task<BackupRequestResult> CreateBackupAsync(CancellationToken cancellationToken) =>
        BackupRequestAsync(HttpMethod.Post, "api/admin/backups", null, null, null, cancellationToken);
    public Task<BackupRequestResult> VerifyBackupAsync(Guid archiveId, CancellationToken cancellationToken) =>
        BackupRequestAsync(HttpMethod.Post, "api/admin/backups/" + Nonempty(archiveId).ToString("D") + "/verify", null, null, null, cancellationToken);

    private async Task<BackupRequestResult> BackupRequestAsync(HttpMethod method, string path, byte[]? body, string? mediaType,
        long? version, CancellationToken cancellationToken)
    {
        Operation? operation = null;
        byte[]? token = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || _token is null) return new(BackupRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(BackupRequestOutcome.Unauthenticated); }
                operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
                token = _token.ToArray();
            }
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(30));
            BackupRequestResult result;
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) result = new(BackupRequestOutcome.UntrustedConnection);
                else
                {
                    using var request = new HttpRequestMessage(method, new Uri(_origin, path));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    if (version is { } expected) request.Headers.IfMatch.Add(new EntityTagHeaderValue("\"" + expected.ToString(CultureInfo.InvariantCulture) + "\""));
                    if (body is not null)
                    {
                        request.Content = new ByteArrayContent(body);
                        request.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType!);
                    }
                    using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                    if (body is not null) CryptographicOperations.ZeroMemory(body);
                    request.Headers.Authorization = null;
                    result = response.StatusCode switch
                    {
                        HttpStatusCode.Unauthorized => new(BackupRequestOutcome.Unauthenticated),
                        HttpStatusCode.NotFound => new(BackupRequestOutcome.NotFound),
                        HttpStatusCode.OK or HttpStatusCode.Accepted or HttpStatusCode.Conflict =>
                            new(response.StatusCode == HttpStatusCode.Conflict ? BackupRequestOutcome.Conflict : BackupRequestOutcome.Success,
                                await ReadBackupStatusAsync(response, operation.Token).ConfigureAwait(false)),
                        _ => new(BackupRequestOutcome.Unavailable)
                    };
                }
            }
            catch (OperationCanceledException) { cancellationToken.ThrowIfCancellationRequested(); result = new(BackupRequestOutcome.Unavailable); }
            catch (BackupTooLargeException) { result = new(BackupRequestOutcome.TooLarge); }
            catch (Exception error) when (error is InvalidResponseException or JsonException or FormatException or OverflowException or InvalidOperationException) { result = new(BackupRequestOutcome.InvalidResponse); }
            catch (Exception) { cancellationToken.ThrowIfCancellationRequested(); result = new(BackupRequestOutcome.Unavailable); }
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || _token is null) return new(BackupRequestOutcome.Unauthenticated);
                if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(BackupRequestOutcome.Unauthenticated); }
                if (operation.Token.IsCancellationRequested) return new(BackupRequestOutcome.Unavailable);
                if (result.Outcome is BackupRequestOutcome.Unauthenticated or BackupRequestOutcome.UntrustedConnection) ResetGenerationLocked();
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

    public async Task<BackupDownloadResult> DownloadBackupAsync(BackupArchiveSummary archive, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite || archive.ArchiveId == Guid.Empty || archive.SizeBytes is <= 0 || archive.SizeBytes > BackupArchive.MaximumArchiveBytes || !BackupHash(archive.Sha256))
            throw new ArgumentException("A bounded archive and writable destination are required.");
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(BackupRequestOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(BackupRequestOutcome.Unauthenticated); }
            operation = new Operation(_generation, CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            operation.Cancellation.CancelAfter(TimeSpan.FromMinutes(10));
            var buffer = new byte[81920];
            try
            {
                if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false)) return new(BackupRequestOutcome.UntrustedConnection);
                using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, "api/admin/backups/" + archive.ArchiveId.ToString("D") + "/download"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, operation.Token).ConfigureAwait(false);
                request.Headers.Authorization = null;
                if (response.StatusCode == HttpStatusCode.Unauthorized) return new(BackupRequestOutcome.Unauthenticated);
                if (response.StatusCode == HttpStatusCode.NotFound) return new(BackupRequestOutcome.NotFound);
                if (response.StatusCode != HttpStatusCode.OK) return new(BackupRequestOutcome.Unavailable);
                if (response.Headers.CacheControl?.NoStore != true || response.Content.Headers.ContentType?.MediaType != "application/octet-stream" ||
                    response.Content.Headers.ContentLength != archive.SizeBytes || response.Content.Headers.ContentDisposition?.DispositionType != "attachment" ||
                    !response.Headers.TryGetValues("X-Content-Type-Options", out var noSniff) || !noSniff.SequenceEqual(["nosniff"]))
                    return new(BackupRequestOutcome.InvalidResponse);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using var input = await response.Content.ReadAsStreamAsync(operation.Token).ConfigureAwait(false);
                long count = 0;
                while (true)
                {
                    var read = await input.ReadAsync(buffer, operation.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    count += read;
                    if (count > archive.SizeBytes) return new(BackupRequestOutcome.TooLarge);
                    hash.AppendData(buffer.AsSpan(0, read));
                    await destination.WriteAsync(buffer.AsMemory(0, read), operation.Token).ConfigureAwait(false);
                }
                if (count != archive.SizeBytes || Convert.ToHexStringLower(hash.GetHashAndReset()) != archive.Sha256) return new(BackupRequestOutcome.InvalidResponse);
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    if (_disposed || operation.Generation != _generation || _token is null) return new(BackupRequestOutcome.Unauthenticated);
                    if (_time.GetUtcNow() >= _expiresAt) { ResetGenerationLocked(); return new(BackupRequestOutcome.Unauthenticated); }
                    return new(operation.Token.IsCancellationRequested ? BackupRequestOutcome.Unavailable : BackupRequestOutcome.Success);
                }
            }
            catch (OperationCanceledException) { cancellationToken.ThrowIfCancellationRequested(); return new(BackupRequestOutcome.Unavailable); }
            catch (Exception) { cancellationToken.ThrowIfCancellationRequested(); return new(BackupRequestOutcome.Unavailable); }
            finally { CryptographicOperations.ZeroMemory(buffer); CryptographicOperations.ZeroMemory(token); }
        }
    }

    private static async Task<BackupStatus> ReadBackupStatusAsync(HttpResponseMessage response, CancellationToken token)
    {
        if (response.Content.Headers.ContentType?.MediaType != "application/json" || response.Headers.CacheControl?.NoStore != true) throw new InvalidResponseException();
        if (response.Content.Headers.ContentLength > BackupContract.MaximumStatusBytes) throw new BackupTooLargeException();
        using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var bytes = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (read == 0) break;
            if (bytes.Length + read > BackupContract.MaximumStatusBytes) throw new BackupTooLargeException();
            bytes.Write(buffer, 0, read);
        }
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 6 });
        return ParseBackupStatus(document.RootElement);
    }

    internal static BackupStatus ParseBackupStatus(JsonElement root)
    {
        var fields = ReadProperties(root, ["coreInstallationId", "organizationId", "availability", "busy", "policy", "nextDueUtc", "lastSuccessfulBackupUtc", "lastAttempt", "archives"]);
        if (fields.Count != 9 || fields["availability"].GetString() is not ("available" or "unsupported" or "storageUnavailable" or "keyUnavailable")) throw new InvalidResponseException();
        var policy = ReadProperties(fields["policy"], ["version", "enabled", "intervalHours", "retentionCount", "recoveryKeyId"]);
        if (policy.Count != 5) throw new InvalidResponseException();
        var keyId = policy["recoveryKeyId"].ValueKind == JsonValueKind.Null ? null : policy["recoveryKeyId"].GetString();
        if (keyId is not null && !BackupHash(keyId)) throw new InvalidResponseException();
        var parsedPolicy = new BackupPolicy(BackupLong(policy["version"], 0, long.MaxValue), BackupBool(policy["enabled"]),
            (int)BackupLong(policy["intervalHours"], 1, 168), (int)BackupLong(policy["retentionCount"], 1, 30), keyId);
        BackupAttempt? attempt = null;
        if (fields["lastAttempt"].ValueKind != JsonValueKind.Null)
        {
            var a = ReadProperties(fields["lastAttempt"], ["operationId", "kind", "outcome", "startedUtc", "completedUtc", "archiveId"]);
            if (a.Count != 6 || a["kind"].GetString() is not ("create" or "verify") || a["outcome"].GetString() is not ("inProgress" or "succeeded" or "failed" or "interrupted")) throw new InvalidResponseException();
            attempt = new(BackupGuid(a["operationId"]), a["kind"].GetString()!, a["outcome"].GetString()!, BackupDate(a["startedUtc"])!.Value,
                BackupDate(a["completedUtc"]), a["archiveId"].ValueKind == JsonValueKind.Null ? null : BackupGuid(a["archiveId"]));
        }
        if (fields["archives"].ValueKind != JsonValueKind.Array || fields["archives"].GetArrayLength() > 30) throw new InvalidResponseException();
        var archives = fields["archives"].EnumerateArray().Select(item =>
        {
            var a = ReadProperties(item, ["archiveId", "createdUtc", "sizeBytes", "sha256", "recoveryKeyId", "verificationState", "verifiedUtc"]);
            if (a.Count != 7 || !BackupHash(a["sha256"].GetString()) || !BackupHash(a["recoveryKeyId"].GetString()) ||
                a["verificationState"].GetString() is not ("verified" or "unknown" or "failed" or "missing")) throw new InvalidResponseException();
            return new BackupArchiveSummary(BackupGuid(a["archiveId"]), BackupDate(a["createdUtc"])!.Value,
                BackupLong(a["sizeBytes"], 1, BackupArchive.MaximumArchiveBytes), a["sha256"].GetString()!, a["recoveryKeyId"].GetString()!,
                a["verificationState"].GetString()!, BackupDate(a["verifiedUtc"]));
        }).ToArray();
        if (archives.Select(a => a.ArchiveId).Distinct().Count() != archives.Length) throw new InvalidResponseException();
        return new(BackupGuid(fields["coreInstallationId"]), BackupGuid(fields["organizationId"]), fields["availability"].GetString()!,
            BackupBool(fields["busy"]), parsedPolicy, BackupDate(fields["nextDueUtc"]), BackupDate(fields["lastSuccessfulBackupUtc"]), attempt, archives);
    }
    private static bool BackupHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static Guid BackupGuid(JsonElement value) => value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id) && id != Guid.Empty ? id : throw new InvalidResponseException();
    private static Guid Nonempty(Guid value) => value != Guid.Empty ? value : throw new ArgumentException("An archive identifier is required.");
    private static long BackupLong(JsonElement value, long min, long max) => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) && number >= min && number <= max ? number : throw new InvalidResponseException();
    private static bool BackupBool(JsonElement value) => value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new InvalidResponseException() };
    private static DateTimeOffset? BackupDate(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out var date) && date.Offset == TimeSpan.Zero ? date : throw new InvalidResponseException();
    private sealed class BackupTooLargeException : Exception;
}
