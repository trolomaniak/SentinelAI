using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Backups;
using SentinelAI.Core.Persistence;

internal static class BackupApiTests
{
    public static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-backup-api-" + Guid.NewGuid().ToString("N"));
        var clock = new Clock(DateTimeOffset.UtcNow);
        var protection = new Protection();
        var key = RandomNumberGenerator.GetBytes(32);
        var unused = RandomNumberGenerator.GetBytes(32);
        Guid retained;
        var interruptedOperation = Guid.NewGuid();
        Guid interruptedArchive;
        try
        {
            await using (var app = Build(directory, clock, protection))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                var service = app.Services.GetRequiredService<BackupService>();
                var snapshots = app.Services.GetRequiredService<ControlledSnapshots>();
                using (var anonymous = await SendAsync(client, HttpMethod.Get, "api/admin/backups"))
                    Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "An anonymous client read backup state.");
                var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
                var issued = await enrollments.IssueTokenAsync();
                var enrolled = (await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), issued.Token))).Response!;
                using (var request = new HttpRequestMessage(HttpMethod.Get, "api/admin/backups"))
                {
                    request.Headers.Authorization = new("SentinelAgent", $"{enrolled.EndpointId:D}.{enrolled.AgentCredential}");
                    using var response = await client.SendAsync(request);
                    Check(response.StatusCode == HttpStatusCode.Unauthorized, "An Agent credential read administrator backup state.");
                }
                Check(!LocalNetworkRoutes.IsAllowed("GET", "/api/admin/backups") &&
                      !LocalNetworkRoutes.IsAllowed("PUT", "/api/admin/backups/key") &&
                      !LocalNetworkRoutes.IsAllowed("POST", "/api/admin/backups"), "The Agent-only listener exposes backups.");
                var initial = await StatusAsync(client, token);
                Check(initial.Policy is { Version: 0, Enabled: false, RecoveryKeyId: null } && initial.Availability == BackupContract.KeyUnavailable,
                    "A new installation silently enabled backups or invented a recovery key.");
                using (var tooShort = await KeyAsync(client, token, key[..31], 0))
                    Check(tooShort.StatusCode == HttpStatusCode.BadRequest, "A short recovery key was accepted.");
                using (var tooLong = await KeyAsync(client, token, new byte[33], 0))
                    Check(tooLong.StatusCode == HttpStatusCode.BadRequest, "An oversized recovery key was accepted.");
                using (var missingVersion = await SendAsync(client, HttpMethod.Put, "api/admin/backups/key", token,
                           new ByteArrayContent(key)))
                    Check(missingVersion.StatusCode == HttpStatusCode.BadRequest, "Key setup omitted its policy version.");
                foreach (var json in new[]
                         {
                             "{\"expectedVersion\":0,\"enabled\":true,\"intervalHours\":0,\"retentionCount\":7}",
                             "{\"expectedVersion\":0,\"enabled\":false,\"intervalHours\":24,\"retentionCount\":31}",
                             "{\"expectedVersion\":0,\"enabled\":false,\"intervalHours\":24,\"retentionCount\":7,\"path\":\"private\"}",
                             "{\"expectedVersion\":0,\"expectedVersion\":0,\"enabled\":false,\"intervalHours\":24,\"retentionCount\":7}",
                             "{\"expectedVersion\":0,\"enabled\":false,\"intervalHours\":24}"
                         })
                {
                    using var response = await SendAsync(client, HttpMethod.Put, "api/admin/backups/policy", token,
                        new StringContent(json, Encoding.UTF8, "application/json"));
                    Check(response.StatusCode == HttpStatusCode.BadRequest, "Malformed or unbounded backup policy was accepted.");
                }

                // Protection failure must not strand an immutable anchor whose original key the UI cannot retry.
                protection.FailProtect = true;
                using (var failed = await KeyAsync(client, token, unused, 0))
                    Check(failed.StatusCode == HttpStatusCode.ServiceUnavailable, "A failed protection operation claimed success.");
                Check(!File.Exists(Path.Combine(service.StorageDirectory, "backup-identity.json")) &&
                      (await StatusAsync(client, token)).Policy.RecoveryKeyId is null,
                    "Failed initial key setup stranded an anchor or changed the configured key.");
                protection.FailProtect = false;
                using (var cancelled = new CancellationTokenSource())
                {
                    protection.BeforeProtect = cancelled.Cancel;
                    try
                    {
                        await service.SetKeyAsync(0, unused, cancelled.Token);
                        throw new InvalidOperationException("Cancelled key setup unexpectedly completed.");
                    }
                    catch (OperationCanceledException) when (cancelled.IsCancellationRequested) { }
                    finally { protection.BeforeProtect = null; }
                }
                Check(!File.Exists(Path.Combine(service.StorageDirectory, "backup-identity.json")) &&
                      (await StatusAsync(client, token)).Policy.RecoveryKeyId is null,
                    "Cancelled key setup left an immutable anchor or partially configured recovery key.");
                using (var configured = await KeyAsync(client, token, key, 0))
                    Check(configured.StatusCode == HttpStatusCode.OK, "Recovery key setup did not recover after a failed protection operation.");
                var keyed = await StatusAsync(client, token);
                Check(keyed.Policy is { Version: 1, Enabled: false } && keyed.Policy.RecoveryKeyId == BackupArchive.KeyId(key) &&
                      keyed.Availability == BackupContract.Available, "Recovery key setup enabled a schedule or lost its identity.");
                using (var replacement = await KeyAsync(client, token, unused, keyed.Policy.Version))
                    Check(replacement.StatusCode == HttpStatusCode.Conflict, "An existing immutable recovery key was silently replaced.");
                using (var stale = await PolicyAsync(client, token, new(0, true, 1, 2)))
                    Check(stale.StatusCode == HttpStatusCode.Conflict, "A stale backup policy overwrote a newer version.");
                using (var policy = await PolicyAsync(client, token, new(keyed.Policy.Version, true, 1, 2)))
                    Check(policy.StatusCode == HttpStatusCode.OK, "A valid backup schedule could not be saved.");
                Check((await StatusAsync(client, token)).NextDueUtc == clock.GetUtcNow().AddHours(1), "The next scheduled run was not persisted.");

                var first = await CreateAndWaitAsync(client, token);
                Check(first.LastAttempt is { Outcome: "succeeded", Kind: "create" } && first.Archives.Count == 1 &&
                      first.Archives[0] is { VerificationState: "verified", VerifiedUtc: not null }, "A backup was published without full verification.");
                var archive = first.Archives.Single();
                using (var response = await SendAsync(client, HttpMethod.Get, $"api/admin/backups/{archive.ArchiveId:D}/download", token))
                {
                    var bytes = await response.Content.ReadAsByteArrayAsync();
                    Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true &&
                          response.Content.Headers.ContentType?.MediaType == "application/octet-stream" &&
                          response.Headers.TryGetValues("X-Content-Type-Options", out var values) && values.Single() == "nosniff" &&
                          response.Content.Headers.ContentLength == archive.SizeBytes &&
                          Convert.ToHexStringLower(SHA256.HashData(bytes)) == archive.Sha256 &&
                          !Encoding.UTF8.GetString(bytes).Contains("SQLite format 3", StringComparison.Ordinal),
                        "Encrypted backup download lost bounded headers, integrity or confidentiality.");
                    var ownerVerify = Path.Combine(directory, "owner-verification");
                    Directory.CreateDirectory(ownerVerify);
                    var decryptedPath = Path.Combine(directory, "owner-payload.tmp");
                    await using (var input = new MemoryStream(bytes))
                    await using (var output = File.Create(decryptedPath)) await BackupArchive.DecryptAsync(input, output, key, default);
                    BackupManifest manifest;
                    await using (var input = File.OpenRead(decryptedPath)) manifest = await BackupPackage.ExtractAndVerifyAsync(input, ownerVerify, default);
                    var inspected = await SentinelAI.Core.Recovery.CoreBackupDatabase.InspectAsync(Path.Combine(ownerVerify, "core.db"), default);
                    Check(manifest.CoreInstallationId == first.CoreInstallationId && manifest.OrganizationId == first.OrganizationId &&
                          inspected.CoreInstallationId == manifest.CoreInstallationId && manifest.RecoveryKeyId == BackupArchive.KeyId(key),
                        "An exported backup could not be independently decrypted and restored into an isolated database.");
                }
                using (var response = await SendAsync(client, HttpMethod.Get, "api/admin/backups", token))
                {
                    var text = await response.Content.ReadAsStringAsync();
                    using var json = JsonDocument.Parse(text);
                    Check(json.RootElement.EnumerateObject().Count() == 9 && !text.Contains(Convert.ToBase64String(key), StringComparison.Ordinal) &&
                          !text.Contains(directory, StringComparison.Ordinal) && !text.Contains("protectedKey", StringComparison.OrdinalIgnoreCase),
                        "Backup status exposed a key, protected blob, storage path or extra private fields.");
                }

                var block = snapshots.BlockNext();
                using var start = await SendAsync(client, HttpMethod.Post, "api/admin/backups", token);
                Check(start.StatusCode == HttpStatusCode.Accepted, "A manual backup was not queued.");
                await block.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
                using (var concurrent = await SendAsync(client, HttpMethod.Post, "api/admin/backups", token))
                    Check(concurrent.StatusCode == HttpStatusCode.Conflict, "Two backup jobs ran concurrently.");
                using (var changing = await PolicyAsync(client, token, new((await StatusAsync(client, token)).Policy.Version, false, 24, 1)))
                    Check(changing.StatusCode == HttpStatusCode.Conflict, "Backup configuration changed underneath an active job.");
                // A normal heartbeat can commit while a backup operation is waiting before snapshot creation.
                var device = Guid.NewGuid();
                Check(await app.Services.GetRequiredService<DeviceStore>().RecordHeartbeatAsync(device) is not null,
                    "A pending backup blocked unrelated Core writes.");
                var writes = Task.Run(async () =>
                {
                    for (var index = 0; index < 25; index++)
                        await app.Services.GetRequiredService<DeviceStore>().RecordHeartbeatAsync(Guid.NewGuid());
                });
                block.Release.TrySetResult();
                var second = await WaitIdleAsync(client, token);
                await writes;
                Check(second.LastAttempt?.Outcome == "succeeded" && second.Archives.Count == 2, "The queued snapshot did not complete.");

                // Keep the last verified copy when a newer copy is bad, retention is lowered and replacement fails.
                var latest = second.Archives[0]; var knownGood = second.Archives[1];
                var latestPath = Path.Combine(service.StorageDirectory, latest.ArchiveId.ToString("N") + ".sab");
                await using (var file = new FileStream(latestPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                { var value = file.ReadByte(); file.Position = 0; file.WriteByte((byte)(value ^ 1)); }
                using (var verify = await SendAsync(client, HttpMethod.Post, $"api/admin/backups/{latest.ArchiveId:D}/verify", token))
                    Check(verify.StatusCode == HttpStatusCode.Accepted, "Verification was not queued.");
                var failedVerification = await WaitIdleAsync(client, token);
                Check(failedVerification.LastAttempt?.Outcome == "failed" &&
                      failedVerification.Archives.Single(item => item.ArchiveId == latest.ArchiveId).VerificationState == "failed",
                    "Archive tampering was not reported as a failed verification.");
                using (var lower = await PolicyAsync(client, token, new(failedVerification.Policy.Version, false, 1, 1)))
                    Check(lower.StatusCode == HttpStatusCode.OK, "A bounded retention change was refused.");
                snapshots.FailNext = true;
                var failedCreate = await CreateAndWaitAsync(client, token);
                Check(failedCreate.LastAttempt?.Outcome == "failed" && failedCreate.Archives.Any(item => item.ArchiveId == knownGood.ArchiveId) &&
                      File.Exists(Path.Combine(service.StorageDirectory, knownGood.ArchiveId.ToString("N") + ".sab")),
                    "A failed replacement deleted the last verified backup.");
                var successfulReplacement = await CreateAndWaitAsync(client, token);
                Check(successfulReplacement.LastAttempt?.Outcome == "succeeded" && successfulReplacement.Archives.Count == 1 &&
                      successfulReplacement.Archives.Single().VerificationState == "verified", "Retention was not applied after a verified replacement.");
                retained = successfulReplacement.Archives.Single().ArchiveId;

                // Schedule one overdue run, persist its next due time and do not replay the same overdue slot.
                using (var schedule = await PolicyAsync(client, token, new(successfulReplacement.Policy.Version, true, 1, 2)))
                    Check(schedule.StatusCode == HttpStatusCode.OK, "The schedule could not be re-enabled.");
                clock.Advance(TimeSpan.FromHours(3));
                token = await LoginAsync(client, username, password);
                await service.CheckScheduleAsync(default);
                var scheduled = await WaitIdleAsync(client, token);
                Check(scheduled.LastAttempt is { Outcome: "succeeded", Kind: "create" } && scheduled.NextDueUtc == clock.GetUtcNow().AddHours(1),
                    "An overdue schedule did not run once and move its deadline forward.");
                var operation = scheduled.LastAttempt?.OperationId ?? throw new InvalidOperationException("The scheduled backup has no attempt identity.");
                await service.CheckScheduleAsync(default);
                Check((await StatusAsync(client, token)).LastAttempt?.OperationId == operation, "An overdue schedule replayed repeatedly.");
                retained = scheduled.Archives[0].ArchiveId;
                // Mismatched key/MAC must be a safe availability state, not an HTTP exception or an invented healthy state.
                var anchorPath = Path.Combine(service.StorageDirectory, "backup-identity.json");
                var anchor = await File.ReadAllBytesAsync(anchorPath);
                await File.WriteAllTextAsync(anchorPath, "{\"SchemaVersion\":1}");
                Check((await StatusAsync(client, token)).Availability == BackupContract.KeyUnavailable,
                    "A damaged recovery anchor escaped as an error or reported healthy backup availability.");
                await File.WriteAllBytesAsync(anchorPath, anchor);
                await app.StopAsync();
                // Model a process crash after publication but before its metadata commit. Only the durable job's
                // own exact archive/work IDs may be cleaned on restart; arbitrary files are never adopted/deleted.
                var orphanWork = Path.Combine(service.StorageDirectory, "work-" + interruptedOperation.ToString("N"));
                BackupStorage.CreatePrivateDirectory(orphanWork);
                await File.WriteAllTextAsync(Path.Combine(orphanWork, "payload.tmp"), "Synthetic interrupted staging only.");
                interruptedArchive = retained; // A real fully authenticated published copy whose catalog commit was lost.
                await using var stateConnection = new SqliteConnection(new SqliteConnectionStringBuilder
                    { DataSource = Path.Combine(directory, "sentinelai.db"), Pooling = false }.ToString());
                await stateConnection.OpenAsync();
                await using var stateCommand = stateConnection.CreateCommand();
                stateCommand.CommandText = "DELETE FROM BackupArchives WHERE ArchiveId=$archive; INSERT INTO BackupAttempts VALUES ($id,'create','inProgress',$now,NULL,$archive);";
                stateCommand.Parameters.AddWithValue("$id", interruptedOperation.ToString("D"));
                stateCommand.Parameters.AddWithValue("$archive", interruptedArchive.ToString("D"));
                stateCommand.Parameters.AddWithValue("$now", clock.GetUtcNow().UtcTicks);
                await stateCommand.ExecuteNonQueryAsync();
            }
            await using (var app = Build(directory, clock, protection))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                var state = await WaitIdleAsync(client, token, interruptedOperation);
                var storage = app.Services.GetRequiredService<BackupService>().StorageDirectory;
                Check(!Directory.Exists(Path.Combine(storage, "work-" + interruptedOperation.ToString("N"))) &&
                      File.Exists(Path.Combine(storage, interruptedArchive.ToString("N") + ".sab")) &&
                      state.Archives.Any(item => item.ArchiveId == interruptedArchive && item.VerificationState == "verified"),
                    "Restart lost a valid published restore point or failed to reconcile its catalog and remove plaintext staging.");
                await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                    { DataSource = Path.Combine(directory, "sentinelai.db"), Pooling = false }.ToString()))
                {
                    await connection.OpenAsync(); await using var command = connection.CreateCommand();
                    command.CommandText = "SELECT Outcome FROM BackupAttempts WHERE OperationId=$id;";
                    command.Parameters.AddWithValue("$id", interruptedOperation.ToString("D"));
                    Check((string?)await command.ExecuteScalarAsync() == "interrupted", "Restart did not preserve the interrupted attempt result.");
                }
                Check(state.Availability == BackupContract.Available && state.Archives.Any(item => item.ArchiveId == retained) &&
                      state.Policy.RecoveryKeyId == BackupArchive.KeyId(key) && state.Policy.Enabled,
                    "Backup policy, protected key or archive history did not survive a Core restart.");
                await app.StopAsync();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(unused); protection.Clear();
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("Backup API tests passed (private key setup/failure recovery, auth, bounded policies, SQLite snapshot, independent recovery, scheduling, single-job isolation, tamper detection, safe retention, restart).");
    }
    private static WebApplication Build(string directory, Clock clock, Protection protection) => CoreHost.Build(["--SentinelAI:DataDirectory=" + directory], builder =>
    {
        builder.Logging.ClearProviders(); builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddSingleton<IBackupKeyProtection>(protection);
        builder.Services.AddSingleton<ControlledSnapshots>(services => new(new SqliteBackupSnapshotSource(services.GetRequiredService<AdminStore>())));
        builder.Services.AddSingleton<IBackupSnapshotSource>(services => services.GetRequiredService<ControlledSnapshots>());
    });
    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear(); app.Urls.Add("http://127.0.0.1:0"); await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30) };
    }
    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic backup administrator login failed.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }
    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string path,
        string? token = null, HttpContent? content = null)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }
    private static async Task<HttpResponseMessage> KeyAsync(HttpClient client, string token, byte[] key, long version)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, "api/admin/backups/key") { Content = new ByteArrayContent(key) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.IfMatch.Add(new EntityTagHeaderValue("\"" + version + "\""));
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return await client.SendAsync(request);
    }
    private static Task<HttpResponseMessage> PolicyAsync(HttpClient client, string token, BackupPolicyRequest policy) =>
        SendAsync(client, HttpMethod.Put, "api/admin/backups/policy", token, JsonContent.Create(policy));
    private static async Task<BackupStatus> StatusAsync(HttpClient client, string token)
    {
        using var response = await SendAsync(client, HttpMethod.Get, "api/admin/backups", token);
        Check(response.StatusCode == HttpStatusCode.OK, "Backup status read failed.");
        return (await response.Content.ReadFromJsonAsync<BackupStatus>())!;
    }
    private static async Task<BackupStatus> CreateAndWaitAsync(HttpClient client, string token)
    {
        using var response = await SendAsync(client, HttpMethod.Post, "api/admin/backups", token);
        Check(response.StatusCode == HttpStatusCode.Accepted, "A backup job was not accepted.");
        return await WaitIdleAsync(client, token);
    }
    private static async Task<BackupStatus> WaitIdleAsync(HttpClient client, string token, Guid? differentFrom = null)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var value = await StatusAsync(client, token);
            if (!value.Busy && value.LastAttempt is { Outcome: not "inProgress" } attempt && attempt.OperationId != differentFrom) return value;
            await Task.Delay(20);
        }
        throw new InvalidOperationException("The synthetic backup worker did not complete.");
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        private long _ticks = now.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
        internal void Advance(TimeSpan period) => Interlocked.Add(ref _ticks, period.Ticks);
    }
    private sealed class Protection : IBackupKeyProtection
    {
        private readonly byte[] _machine = RandomNumberGenerator.GetBytes(32);
        internal bool FailProtect;
        internal Action? BeforeProtect;
        public bool IsSupported => true;
        public byte[] Protect(ReadOnlySpan<byte> value)
        {
            if (FailProtect) throw new CryptographicException("Synthetic protection failure.");
            BeforeProtect?.Invoke();
            var result = new byte[value.Length + 28]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
            using var aes = new AesGcm(_machine, 16); aes.Encrypt(result.AsSpan(0, 12), value, result.AsSpan(12, value.Length), result.AsSpan(12 + value.Length, 16));
            return result;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> value)
        {
            var result = new byte[value.Length - 28]; using var aes = new AesGcm(_machine, 16);
            aes.Decrypt(value[..12], value.Slice(12, result.Length), value[^16..], result); return result;
        }
        internal void Clear() => CryptographicOperations.ZeroMemory(_machine);
    }
    private sealed class ControlledSnapshots(IBackupSnapshotSource source) : IBackupSnapshotSource
    {
        internal sealed record Block(TaskCompletionSource Started, TaskCompletionSource Release);
        private Block? _next;
        internal bool FailNext;
        internal Block BlockNext() => _next = new(new(TaskCreationOptions.RunContinuationsAsynchronously), new(TaskCreationOptions.RunContinuationsAsynchronously));
        public async Task CreateAsync(string destination, CancellationToken cancellationToken)
        {
            var pending = Interlocked.Exchange(ref _next, null);
            if (pending is not null) { pending.Started.TrySetResult(); await pending.Release.Task.WaitAsync(cancellationToken); }
            if (FailNext) { FailNext = false; throw new IOException("Synthetic snapshot storage failure."); }
            await source.CreateAsync(destination, cancellationToken);
        }
    }
}
