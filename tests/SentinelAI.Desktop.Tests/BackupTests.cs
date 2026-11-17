using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Desktop.Foundation;

internal static class BackupTests
{
    private static int _checks;
    private static readonly DateTimeOffset Now = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Core = Guid.Parse("427ff46a-55a3-4c87-b410-5c561cfcf470");
    private static readonly Guid Organization = Guid.Parse("c37e163e-1efa-4349-8db4-a97ca19a905d");
    private static readonly byte[] Secret = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    public static async Task<int> RunAsync()
    {
        _checks = 0;
        await ViewModelAsync();
        await SessionIsolationAsync();
        await TransportAsync();
        await RecoveryAsync();
        Console.WriteLine($"Desktop backups: {_checks} assertions passed.");
        return _checks;
    }
    private static void Check(bool value, string message) { _checks++; if (!value) throw new InvalidOperationException(message); }
    private static BackupStatus Status(string? key = null, bool busy = false, BackupAttempt? attempt = null, IReadOnlyList<BackupArchiveSummary>? archives = null) =>
        new(Core, Organization, key is null ? "keyUnavailable" : "available", busy, new(4, false, 24, 7, key), null, null, attempt, archives ?? []);
    private static async Task ViewModelAsync()
    {
        var client = new FakeClient();
        var files = new FakeFiles();
        using var model = new BackupViewModel(client, files);
        await model.RefreshAsync();
        Check(model.CanConfigureRecovery && !model.CanCreate && model.Archives.Count == 0, "Unconfigured backups exposed create or hid key setup.");
        await model.ConfigureRecoveryAsync("short".AsMemory());
        Check(files.Keys == 0 && client.KeyWrites == 0, "A short recovery password reached file storage/Core.");
        files.KeyOutcome = BackupFileOutcome.Cancelled;
        await model.ConfigureRecoveryAsync("Synthetic-Recovery-Password!".AsMemory());
        Check(files.Keys == 1 && client.KeyWrites == 0 && model.Message.Contains("cancelled", StringComparison.Ordinal), "Cancelled key save changed Core state.");
        files.KeyOutcome = BackupFileOutcome.Saved;
        await model.ConfigureRecoveryAsync("Synthetic-Recovery-Password!".AsMemory());
        Check(client.KeyWrites == 1 && files.Keys == 2 && client.KeyWasSavedFirst && model.Status?.Policy.RecoveryKeyId is { Length: 64 }, "Recovery key was configured before its encrypted file was saved.");
        var recovered = RecoveryKeyFile.Open(files.LastEncryptedKey!, "Synthetic-Recovery-Password!");
        try { Check(BackupArchive.KeyId(recovered) == model.Status?.Policy.RecoveryKeyId && files.LastEncryptedKey!.AsSpan().IndexOf(recovered) < 0, "The saved recovery file did not recover the configured key or contained it in plaintext."); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
        Check(model.CanCreate && !model.CanConfigureRecovery, "Configured backups retained key replacement controls.");
        model.Enabled = true; model.IntervalHours = 12; model.RetentionCount = 3;
        Check(client.PolicyWrites == 0, "Changing a schedule control automatically wrote Core state.");
        await model.SavePolicyAsync();
        Check(client.PolicyWrites == 1 && client.Policy is { ExpectedVersion: 4, Enabled: true, IntervalHours: 12, RetentionCount: 3 }, "Explicit schedule save lost version or selected values.");
        client.CreateResult = new(BackupRequestOutcome.Unavailable);
        await model.CreateAsync();
        Check(model.NeedsRefresh && !model.CanCreate && model.CanRefresh, "An uncertain create could be replayed without a refresh.");
        await model.CreateAsync();
        Check(client.Creates == 1, "An uncertain backup write was automatically replayed.");
        await model.RefreshAsync();
        Check(!model.NeedsRefresh && model.CanCreate, "A successful explicit refresh did not restore controls.");
        var intact = new BackupArchiveSummary(Guid.NewGuid(), Now, 128, new string('a', 64), client.Current.Policy.RecoveryKeyId!, "verified", Now);
        client.Current = client.Current with { Archives = [intact with { ArchiveId = Guid.NewGuid(), VerificationState = "missing" }, intact] };
        await model.RefreshAsync();
        model.SelectedArchive = model.Archives[0];
        Check(!model.CanVerifySelectedArchive && !model.CanExportSelectedArchive && model.CanCreate && model.Archives[0].Summary.Contains("missing", StringComparison.Ordinal), "A missing archive blocked new backups or exposed unusable export/verify actions.");
        model.SelectedArchive = model.Archives[1];
        Check(model.CanVerifySelectedArchive && model.CanExportSelectedArchive, "A missing sibling archive disabled a verified backup.");
        // A second operator wins the key CAS. Its existing recovery key is never touched by this VM or file service.
        var conflictFiles = new FakeFiles { KeyOutcome = BackupFileOutcome.Saved };
        var conflict = new FakeClient { KeyResult = new(BackupRequestOutcome.Conflict, Status(BackupArchive.KeyId(Secret))) };
        using var conflicting = new BackupViewModel(conflict, conflictFiles);
        await conflicting.RefreshAsync();
        await conflicting.ConfigureRecoveryAsync("Synthetic-Recovery-Password!".AsMemory());
        Check(conflict.KeyWrites == 1 && conflicting.Status?.Policy.RecoveryKeyId == BackupArchive.KeyId(Secret) && !conflicting.CanConfigureRecovery,
            "A key conflict replaced authoritative recovery metadata or permitted another key write.");
    }
    private static async Task SessionIsolationAsync()
    {
        var held = new TaskCompletionSource<BackupRequestResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new FakeClient { Read = _ => held.Task };
        using var model = new BackupViewModel(client, new FakeFiles());
        var expired = 0; model.SessionExpired += (_, _) => expired++;
        var pending = model.RefreshAsync();
        model.Clear();
        held.SetResult(new(BackupRequestOutcome.Unauthenticated));
        await pending;
        Check(model.Status is null && model.State == BackupViewState.None && expired == 0, "A stale backup result restored metadata or expired a replacement session.");
        client.Read = _ => Task.FromResult(new BackupRequestResult(BackupRequestOutcome.Unauthenticated));
        await model.RefreshAsync();
        Check(expired == 1 && model.Status is null, "Current backup session expiry did not clear state.");
    }
    private static HttpResponseMessage Response(object body, HttpStatusCode code = HttpStatusCode.OK)
    {
        var response = new HttpResponseMessage(code) { Content = new StringContent(JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json") };
        response.Headers.CacheControl = new() { NoStore = true };
        return response;
    }
    private static async Task TransportAsync()
    {
        var handler = new Handler();
        using var client = new HttpAuthenticationClient(new Trust(), handler);
        Check((await client.GetBackupStatusAsync(default)).Outcome == BackupRequestOutcome.Unauthenticated && handler.BackupCalls == 0, "Backups requested before sign-in.");
        Check((await client.SignInAsync("admin", "Synthetic-Backup-Password!".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic backup transport sign-in failed.");
        handler.Next = _ => Response(Status());
        var status = await client.GetBackupStatusAsync(default);
        Check(status is { Outcome: BackupRequestOutcome.Success, Status.Policy.Version: 4 }, "Typed bounded backup status was rejected.");
        var intactMetadata = new BackupArchiveSummary(Guid.NewGuid(), Now, 128, new string('a', 64), BackupArchive.KeyId(Secret), "verified", Now);
        handler.Next = _ => Response(Status(BackupArchive.KeyId(Secret), archives: [intactMetadata, intactMetadata with { ArchiveId = Guid.NewGuid(), VerificationState = "missing" }]));
        var mixed = await client.GetBackupStatusAsync(default);
        Check(mixed is { Outcome: BackupRequestOutcome.Success, Status.Archives.Count: 2 } && mixed.Status.Archives[1].VerificationState == "missing", "One missing archive made the entire status unreadable.");
        handler.Next = _ => Response(Status());
        await client.SetBackupKeyAsync(4, Secret, default);
        Check(handler.LastMethod == HttpMethod.Put && handler.LastPath == "/api/admin/backups/key" && handler.IfMatch == "\"4\"" && handler.LastBody.SequenceEqual(Secret), "Key setup lost exact binary input, authentication path or CAS version.");
        foreach (var mutate in new Action<JsonObject>[]
        {
            root => root["extra"] = "raw path", root => root.Remove("policy"), root => root["availability"] = "healthy",
            root => root["coreInstallationId"] = Guid.Empty.ToString(), root => root["busy"] = "true",
            root => root["policy"]!["recoveryKeyId"] = "private", root => root["policy"]!["retentionCount"] = 31
        })
        {
            var root = JsonSerializer.SerializeToNode(Status(), JsonOptions)!.AsObject(); mutate(root);
            handler.Next = _ => Response(root);
            Check((await client.GetBackupStatusAsync(default)).Outcome == BackupRequestOutcome.InvalidResponse, "A malformed/private backup status was accepted.");
        }
        handler.Next = _ => { var response = Response(Status()); response.Headers.CacheControl = null; return response; };
        Check((await client.GetBackupStatusAsync(default)).Outcome == BackupRequestOutcome.InvalidResponse, "Cacheable backup status was accepted.");
        var bytes = Encoding.UTF8.GetBytes("synthetic encrypted archive bytes");
        var archive = new BackupArchiveSummary(Guid.NewGuid(), Now, bytes.Length, Convert.ToHexStringLower(SHA256.HashData(bytes)), BackupArchive.KeyId(Secret), "verified", Now);
        handler.Next = _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
            response.Content.Headers.ContentType = new("application/octet-stream"); response.Content.Headers.ContentDisposition = new("attachment");
            response.Headers.CacheControl = new() { NoStore = true }; response.Headers.Add("X-Content-Type-Options", "nosniff"); return response;
        };
        using var destination = new MemoryStream();
        Check((await client.DownloadBackupAsync(archive, destination, default)).Outcome == BackupRequestOutcome.Success && destination.ToArray().SequenceEqual(bytes), "Verified bounded encrypted download failed.");
        using var altered = new MemoryStream();
        Check((await client.DownloadBackupAsync(archive with { Sha256 = new string('0', 64) }, altered, default)).Outcome == BackupRequestOutcome.InvalidResponse, "A mismatched archive hash was accepted.");
    }
    private static BackupRecoveryPreview Preview() => new(Guid.NewGuid(), Now, Core, Organization, 1, 2, new string('a', 64), BackupRecoveryContract.SameMachine);
    private static async Task RecoveryAsync()
    {
        var preview = Preview();
        var worker = new Worker(preview);
        var host = new Host();
        var coordinator = new BackupRecoveryCoordinator(worker, host);
        var result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "wrong", default);
        Check(result.Outcome == BackupRecoveryContract.InvalidInput && host.Stops == 0 && worker.Calls.Count == 0, "Unconfirmed restore stopped Core.");
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "RESTORE", default);
        Check(result.Outcome == BackupRecoveryContract.Committed && worker.Calls.SequenceEqual(["preview", "restore", "commit"]) && host.Stops == 1 && host.Starts == 1, "Healthy restore was not committed after service health.");
        worker = new Worker(preview); host = new Host { Health = false };
        coordinator = new(worker, host);
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "RESTORE", default);
        Check(worker.Calls.SequenceEqual(["preview", "restore", "rollback"]) && host.Stops == 2 && host.Starts == 2 && result.Outcome == BackupRecoveryContract.Unavailable, "An unhealthy restored service did not roll back its database.");
        worker = new Worker(preview) { CommitUncertain = true }; host = new Host(); coordinator = new(worker, host);
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "RESTORE", default);
        Check(result.Outcome == BackupRecoveryContract.Unavailable && host.Stops == 1 && !worker.Calls.Contains("rollback"), "An uncertain but completed commit stopped/rolled back a healthy database without a journal.");
        worker = new Worker(preview) { RejectAfterApplied = true }; host = new Host(); coordinator = new(worker, host);
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "RESTORE", default);
        Check(result.Outcome == BackupRecoveryContract.RolledBack && worker.Calls.SequenceEqual(["preview", "restore", "status", "rollback"]) && host.Stops == 2,
            "A rejected worker reply after database mutation restarted partially restored state instead of checking its journal.");
        worker = new Worker(preview) { LoseCommittedReply = true }; host = new Host(); coordinator = new(worker, host);
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "password-12345".AsMemory(), "RESTORE", default);
        Check(result.Outcome == BackupRecoveryContract.Committed && host.Stops == 1 && !worker.Calls.Contains("rollback"),
            "A lost reply after committed cleanup caused a healthy completed restore to roll back.");
        worker = new Worker(preview); host = new Host(); coordinator = new(worker, host);
        result = await coordinator.RestoreAsync(preview, "archive.sab", "key.sakey", "short".AsMemory(), "RESTORE", default);
        Check(result.Outcome == BackupRecoveryContract.InvalidInput && host.Stops == 0 && worker.Calls.Count == 0, "An absent or short recovery password interrupted monitoring.");
    }
    private sealed class FakeClient : IBackupClient
    {
        internal Func<CancellationToken, Task<BackupRequestResult>>? Read;
        internal BackupStatus Current = Status();
        internal BackupRequestResult? KeyResult, CreateResult;
        internal int KeyWrites, PolicyWrites, Creates;
        internal bool KeyWasSavedFirst;
        internal BackupPolicyRequest? Policy;
        public Task<BackupRequestResult> GetBackupStatusAsync(CancellationToken token) => Read?.Invoke(token) ?? Task.FromResult(new BackupRequestResult(BackupRequestOutcome.Success, Current));
        public Task<BackupRequestResult> SetBackupKeyAsync(long version, ReadOnlyMemory<byte> key, CancellationToken token)
        { KeyWrites++; KeyWasSavedFirst = FakeFiles.LastSaved; Current = KeyResult?.Status ?? Status(BackupArchive.KeyId(key.Span)); return Task.FromResult(KeyResult ?? new(BackupRequestOutcome.Success, Current)); }
        public Task<BackupRequestResult> SetBackupPolicyAsync(BackupPolicyRequest policy, CancellationToken token) { PolicyWrites++; Policy = policy; return Task.FromResult(new BackupRequestResult(BackupRequestOutcome.Success, Current)); }
        public Task<BackupRequestResult> CreateBackupAsync(CancellationToken token) { Creates++; return Task.FromResult(CreateResult ?? new(BackupRequestOutcome.Success, Current)); }
        public Task<BackupRequestResult> VerifyBackupAsync(Guid id, CancellationToken token) => Task.FromResult(new BackupRequestResult(BackupRequestOutcome.Success, Current));
        public Task<BackupDownloadResult> DownloadBackupAsync(BackupArchiveSummary archive, Stream stream, CancellationToken token) => Task.FromResult(new BackupDownloadResult(BackupRequestOutcome.Success));
    }
    private sealed class FakeFiles : IBackupFileService
    {
        internal static bool LastSaved;
        internal int Keys;
        internal byte[]? LastEncryptedKey;
        internal BackupFileOutcome KeyOutcome = BackupFileOutcome.Saved;
        public Task<BackupFileOutcome> SaveRecoveryKeyAsync(ReadOnlyMemory<byte> key, CancellationToken token) { Keys++; LastEncryptedKey = key.ToArray(); LastSaved = KeyOutcome == BackupFileOutcome.Saved; return Task.FromResult(KeyOutcome); }
        public Task<BackupFileOutcome> SaveArchiveAsync(BackupArchiveSummary archive, Func<Stream, CancellationToken, Task<BackupDownloadResult>> download, CancellationToken token) => Task.FromResult(BackupFileOutcome.Cancelled);
    }
    private sealed class Trust : ICoreEndpointTrust { public Task<bool> IsTrustedAsync(Uri origin, CancellationToken token) => Task.FromResult(true); }
    private sealed class Handler : HttpMessageHandler
    {
        internal Func<HttpRequestMessage, HttpResponseMessage> Next = _ => Response(Status());
        internal int BackupCalls;
        internal HttpMethod? LastMethod;
        internal string? LastPath, IfMatch;
        internal byte[] LastBody = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Response(new { tokenType = "Bearer", accessToken = "synthetic-backup-token", expiresIn = 900 });
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Response(new { username = "admin", role = "administrator" });
            BackupCalls++; LastMethod = request.Method; LastPath = request.RequestUri.AbsolutePath; IfMatch = request.Headers.IfMatch.SingleOrDefault()?.ToString();
            LastBody = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
            return Next(request);
        }
    }
    private sealed class Worker(BackupRecoveryPreview preview) : IBackupRecoveryWorker
    {
        internal readonly List<string> Calls = [];
        internal bool CommitUncertain, RejectAfterApplied, LoseCommittedReply;
        private bool _pending, _committed;
        public Task<BackupRecoveryResult> ExecuteAsync(BackupRecoveryRequest request, ReadOnlyMemory<char> password, CancellationToken token)
        {
            Calls.Add(request.Operation);
            if (request.Operation == "preview") return Task.FromResult(new BackupRecoveryResult("verified", preview));
            if (request.Operation == "restore") { _pending = true; return Task.FromResult(new BackupRecoveryResult(RejectAfterApplied ? "rejected" : "restored", preview, preview.ArchiveId)); }
            if (request.Operation == "commit")
            {
                _pending = false; _committed = LoseCommittedReply;
                if (LoseCommittedReply) throw new IOException("Synthetic lost committed reply.");
                return Task.FromResult(new BackupRecoveryResult(CommitUncertain ? "unavailable" : "committed", preview));
            }
            if (request.Operation == "rollback") { _pending = false; return Task.FromResult(new BackupRecoveryResult("rolledBack", preview)); }
            return Task.FromResult(_committed ? new BackupRecoveryResult("committed", preview) : _pending ? new("pending", preview, preview.ArchiveId) : new("ready"));
        }
    }
    private sealed class Host : IBackupRecoveryHost
    {
        internal int Stops, Starts;
        internal bool Health = true;
        public Task<bool> IsRunningAsync(CancellationToken token) => Task.FromResult(true);
        public Task StopAsync(CancellationToken token) { Stops++; return Task.CompletedTask; }
        public Task<bool> StartAndCheckAsync(CancellationToken token) { Starts++; return Task.FromResult(Health); }
    }
}
