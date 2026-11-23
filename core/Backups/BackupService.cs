using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Data.Sqlite;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Core.Persistence;
using SentinelAI.Core.Recovery;

namespace SentinelAI.Core.Backups;

internal enum BackupMutationOutcome { Accepted, Conflict, Unavailable, NotFound }
internal sealed record BackupMutation(BackupMutationOutcome Outcome, BackupStatus Status);

/// <summary>One local worker owns backup jobs. HTTP requests enqueue bounded work and never choose filesystem paths.</summary>
internal sealed class BackupService : BackgroundService
{
    private sealed record Work(Guid OperationId, string Kind, Guid ArchiveId);
    private readonly AdminStore _admins;
    private readonly EnrollmentStore _enrollments;
    private readonly BackupStore _store;
    private readonly IBackupSnapshotSource _snapshots;
    private readonly IBackupKeyProtection _protection;
    private readonly TimeProvider _time;
    private readonly IConfiguration _configuration;
    private readonly ILogger<BackupService> _logger;
    private readonly BackupStorage _storage;
    private readonly SemaphoreSlim _commands = new(1, 1);
    private readonly Channel<Work> _queue = Channel.CreateBounded<Work>(1);
    private int _busy;
    public BackupService(AdminStore admins, EnrollmentStore enrollments, BackupStore store,
        IBackupKeyProtection protection, IBackupSnapshotSource snapshots, TimeProvider time, IConfiguration configuration, CoreHostingMode mode, ILogger<BackupService> logger)
    {
        _admins = admins; _enrollments = enrollments; _store = store; _protection = protection; _time = time;
        _configuration = configuration; _logger = logger; _snapshots = snapshots;
        _storage = new BackupStorage(Path.GetDirectoryName(admins.DatabasePath)!, mode.IsWindowsService);
    }
    internal string StorageDirectory => _storage.DirectoryPath;
    internal async Task<BackupStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        await _commands.WaitAsync(cancellationToken);
        try { return await ReadStatusUnderCommandLockAsync(cancellationToken); }
        finally { _commands.Release(); }
    }

    private async Task<BackupStatus> ReadStatusUnderCommandLockAsync(CancellationToken cancellationToken)
    {
        // The command lock prevents another job from starting during this read. Capture busy
        // before the catalog so a snapshot taken during pruning cannot be reported as idle.
        var busy = Volatile.Read(ref _busy) != 0;
        var state = await _store.ReadAsync(cancellationToken);
        var identity = await _enrollments.GetCoreIdentityAsync(cancellationToken);
        var archives = state.Archives.Take(30).Select(archive =>
        {
            try { BackupStorage.AssertFile(_storage.ArchivePath(archive.ArchiveId), BackupArchive.MaximumArchiveBytes); return archive; }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return archive with { VerificationState = "missing" }; }
        }).ToArray();
        return new(identity.CoreInstallationId, identity.OrganizationId, Availability(state), busy,
            state.Policy, state.NextDueUtc, state.LastSuccessfulUtc, state.LastAttempt, archives);
    }
    private string Availability(BackupStoredState state)
    {
        if (!_protection.IsSupported) return BackupContract.Unsupported;
        try
        {
            _storage.EnsureAvailable();
            if (File.Exists(Path.Combine(_storage.DirectoryPath, "restore-journal.json"))) return BackupContract.StorageUnavailable;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return BackupContract.StorageUnavailable; }
        if (state.ProtectedKey is null || state.Policy.RecoveryKeyId is null) return BackupContract.KeyUnavailable;
        byte[]? key = null;
        try
        {
            key = _protection.Unprotect(state.ProtectedKey);
            if (key.Length != 32 || BackupArchive.KeyId(key) != state.Policy.RecoveryKeyId) return BackupContract.KeyUnavailable;
            var anchor = BackupIdentityAnchor.Read(_storage.DirectoryPath, key);
            return anchor.CoreInstallationId == Guid.Empty ? BackupContract.KeyUnavailable : BackupContract.Available;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or CryptographicException or JsonException)
        { return BackupContract.KeyUnavailable; }
        finally { if (key is not null) CryptographicOperations.ZeroMemory(key); }
    }
    internal async Task<BackupMutation> SetKeyAsync(long version, ReadOnlyMemory<byte> key, CancellationToken cancellationToken)
    {
        await _commands.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _busy) != 0)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var state = await _store.ReadAsync(cancellationToken);
            if (state.Policy.Version != version || state.Policy.RecoveryKeyId is not null)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            if (!_protection.IsSupported || key.Length != 32) return new(BackupMutationOutcome.Unavailable, await ReadStatusUnderCommandLockAsync(cancellationToken));
            _storage.EnsureAvailable();
            if (File.Exists(Path.Combine(_storage.DirectoryPath, "restore-journal.json")))
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var identity = await _enrollments.GetCoreIdentityAsync(cancellationToken);
            if (File.Exists(Path.Combine(_storage.DirectoryPath, "backup-identity.json")) &&
                BackupIdentityAnchor.Read(_storage.DirectoryPath, key.Span) != identity)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var protectedKey = _protection.Protect(key.Span);
            try
            {
                var changed = await _store.ConfigureKeyAsync(version, BackupArchive.KeyId(key.Span), protectedKey, cancellationToken);
                if (changed) BackupIdentityAnchor.Ensure(_storage.DirectoryPath, identity, key.Span);
                return new(changed ? BackupMutationOutcome.Accepted : BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            }
            finally { CryptographicOperations.ZeroMemory(protectedKey); }
        }
        finally { _commands.Release(); }
    }
    internal async Task<BackupMutation> SetPolicyAsync(BackupPolicyRequest request, CancellationToken cancellationToken)
    {
        await _commands.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _busy) != 0)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var state = await _store.ReadAsync(cancellationToken);
            if (state.Policy.Version != request.ExpectedVersion)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            if (request.Enabled && Availability(state) != BackupContract.Available)
                return new(BackupMutationOutcome.Unavailable, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var next = !request.Enabled ? null : state.Policy.Enabled && state.Policy.IntervalHours == request.IntervalHours
                ? state.NextDueUtc ?? _time.GetUtcNow().AddHours(request.IntervalHours) : (DateTimeOffset?)_time.GetUtcNow().AddHours(request.IntervalHours);
            var changed = await _store.ConfigurePolicyAsync(request, next, cancellationToken);
            return new(changed ? BackupMutationOutcome.Accepted : BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
        }
        finally { _commands.Release(); }
    }
    internal async Task<BackupMutation> StartJobAsync(Guid? archiveId, CancellationToken cancellationToken, bool scheduled = false)
    {
        await _commands.WaitAsync(cancellationToken);
        try
        {
            if (Volatile.Read(ref _busy) != 0)
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var state = await _store.ReadAsync(cancellationToken);
            if (!scheduled && Availability(state) != BackupContract.Available)
                return new(BackupMutationOutcome.Unavailable, await ReadStatusUnderCommandLockAsync(cancellationToken));
            if (archiveId is { } id && !state.Archives.Any(archive => archive.ArchiveId == id))
                return new(BackupMutationOutcome.NotFound, await ReadStatusUnderCommandLockAsync(cancellationToken));
            if (scheduled && (!state.Policy.Enabled || state.NextDueUtc is not { } due || due > _time.GetUtcNow()))
                return new(BackupMutationOutcome.Conflict, await ReadStatusUnderCommandLockAsync(cancellationToken));
            var work = new Work(Guid.NewGuid(), archiveId is null ? "create" : "verify", archiveId ?? Guid.NewGuid());
            var now = _time.GetUtcNow();
            var next = state.Policy.Enabled && work.Kind == "create" ? now.AddHours(state.Policy.IntervalHours) : state.NextDueUtc;
            await _store.BeginAttemptAsync(new(work.OperationId, work.Kind, "inProgress", now, null, work.ArchiveId), next, cancellationToken);
            Volatile.Write(ref _busy, 1);
            if (!_queue.Writer.TryWrite(work))
            {
                Volatile.Write(ref _busy, 0);
                await _store.CompleteAttemptAsync(work.OperationId, "interrupted", now, null, null, false, CancellationToken.None);
                return new(BackupMutationOutcome.Unavailable, await ReadStatusUnderCommandLockAsync(cancellationToken));
            }
            return new(BackupMutationOutcome.Accepted, await ReadStatusUnderCommandLockAsync(cancellationToken));
        }
        finally { _commands.Release(); }
    }
    internal async Task CheckScheduleAsync(CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        if (state.Policy.Enabled && state.NextDueUtc is { } due && due <= _time.GetUtcNow() && Volatile.Read(ref _busy) == 0)
            _ = await StartJobAsync(null, cancellationToken, scheduled: true);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Orphan cleanup is restricted to the durable last interrupted job's exact identifiers.
        try { await RepairMissingAnchorAsync(stoppingToken); await CleanupInterruptedAsync(stoppingToken); }
        catch (Exception) { _logger.LogWarning("Backup recovery cleanup is unavailable."); }
        var scheduler = ScheduleAsync(stoppingToken);
        try
        {
            await foreach (var work in _queue.Reader.ReadAllAsync(stoppingToken)) await RunWorkAsync(work, stoppingToken);
        }
        finally
        {
            try { await scheduler; } catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        }
    }
    private async Task ScheduleAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try { await RepairMissingAnchorAsync(cancellationToken); await CheckScheduleAsync(cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception) { _logger.LogWarning("Backup scheduling is unavailable."); }
            await Task.Delay(TimeSpan.FromSeconds(30), _time, cancellationToken);
        }
    }
    private async Task RepairMissingAnchorAsync(CancellationToken cancellationToken)
    {
        if (!_protection.IsSupported) return;
        var state = await _store.ReadAsync(cancellationToken);
        if (state.ProtectedKey is null || state.Policy.RecoveryKeyId is null) return;
        _storage.EnsureAvailable();
        if (File.Exists(Path.Combine(_storage.DirectoryPath, "backup-identity.json")) ||
            File.Exists(Path.Combine(_storage.DirectoryPath, "restore-journal.json"))) return;
        var key = _protection.Unprotect(state.ProtectedKey);
        try
        {
            if (key.Length != 32 || BackupArchive.KeyId(key) != state.Policy.RecoveryKeyId) throw new CryptographicException();
            BackupIdentityAnchor.Ensure(_storage.DirectoryPath, await _enrollments.GetCoreIdentityAsync(cancellationToken), key);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private async Task CleanupInterruptedAsync(CancellationToken cancellationToken)
    {
        if (!_protection.IsSupported) return;
        var state = await _store.ReadAsync(cancellationToken);
        if (state.LastAttempt is not { Outcome: "interrupted" } attempt) return;
        _storage.EnsureAvailable();
        if (File.Exists(Path.Combine(_storage.DirectoryPath, "restore-journal.json"))) return;
        var work = Path.Combine(_storage.DirectoryPath, "work-" + attempt.OperationId.ToString("N"));
        if (Directory.Exists(work)) _storage.DeleteWork(work);
        // A complete .sab may be the legitimate restore point captured before its own catalog insert.
        // Retain it; the next create job authenticates and re-indexes unknown fixed-name archives.

    }
    private async Task RunWorkAsync(Work work, CancellationToken stoppingToken)
    {
        string? directory = null; string? published = null; var recorded = false; byte[]? key = null;
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            deadline.CancelAfter(TimeSpan.FromMinutes(10));
            var token = deadline.Token;
            var state = await _store.ReadAsync(token);
            if (Availability(state) != BackupContract.Available) throw new IOException("Backup is unavailable.");
            key = _protection.Unprotect(state.ProtectedKey!);
            var identity = await _enrollments.GetCoreIdentityAsync(token);
            if (BackupIdentityAnchor.Read(_storage.DirectoryPath, key) != identity) throw new IOException("Backup identity is unavailable.");
            directory = _storage.CreateWorkDirectory(work.OperationId);
            if (work.Kind == "create")
            {
                if (state.Archives.Count > 30) await PruneAsync(state.Policy.RetentionCount, token, preserveVerified: true);
                await ReconcileUnknownAsync(directory, key, identity, token);
                if ((await _store.ReadAsync(token)).Archives.Count > 30)
                    await PruneAsync(state.Policy.RetentionCount, token, preserveVerified: true);
                var database = Path.Combine(directory, "snapshot.db");
                await _snapshots.CreateAsync(database, token);
                var info = await CoreBackupDatabase.InspectAsync(database, token);
                if (info.CoreInstallationId != identity.CoreInstallationId || info.OrganizationId != identity.OrganizationId)
                    throw new InvalidDataException("Backup identity is unavailable.");
                var configuration = ConfigurationReference();
                var databaseHash = await HashAsync(database, token);
                var manifest = new BackupManifest(1, work.ArchiveId, _time.GetUtcNow(), identity.CoreInstallationId,
                    identity.OrganizationId, typeof(CoreHost).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0",
                    BackupArchive.KeyId(key), new FileInfo(database).Length, databaseHash, Convert.ToHexStringLower(SHA256.HashData(configuration)));
                var payload = Path.Combine(directory, "payload.tmp");
                await using (var output = BackupStorage.CreateFile(payload))
                    await BackupPackage.CreateAsync(output, database, manifest, configuration, token);
                var encrypted = Path.Combine(directory, "archive.tmp");
                await using (var input = File.OpenRead(payload))
                await using (var output = BackupStorage.CreateFile(encrypted))
                {
                    await BackupArchive.EncryptAsync(input, output, key, token);
                    await output.FlushAsync(token); output.Flush(flushToDisk: true);
                }
                _ = await VerifyFileAsync(encrypted, directory, key, work.ArchiveId, identity, token);
                var hash = await HashAsync(encrypted, token);
                published = _storage.ArchivePath(work.ArchiveId);
                File.Move(encrypted, published, overwrite: false);
                var archive = new BackupArchiveSummary(work.ArchiveId, manifest.CreatedUtc, new FileInfo(published).Length,
                    hash, manifest.RecoveryKeyId, "verified", _time.GetUtcNow());
                await _store.CompleteAttemptAsync(work.OperationId, "succeeded", _time.GetUtcNow(), archive, null, true, token);
                recorded = true;
                await PruneAsync(state.Policy.RetentionCount, token);
            }
            else
            {
                var archive = state.Archives.Single(item => item.ArchiveId == work.ArchiveId);
                var path = _storage.ArchivePath(work.ArchiveId);
                BackupStorage.AssertFile(path, BackupArchive.MaximumArchiveBytes);
                if (new FileInfo(path).Length != archive.SizeBytes || await HashAsync(path, token) != archive.Sha256)
                    throw new InvalidDataException("Backup verification failed.");
                _ = await VerifyFileAsync(path, directory, key, work.ArchiveId, identity, token);
                await _store.CompleteAttemptAsync(work.OperationId, "succeeded", _time.GetUtcNow(), null, work.ArchiveId, true, token);
                recorded = true;
            }
        }
        catch (Exception)
        {
            // Only fixed status crosses either logs or HTTP; no paths, recovery keys, archive content or SQL details.
            _logger.LogWarning("Backup operation did not complete.");
            if (!recorded)
                try { await _store.CompleteAttemptAsync(work.OperationId, stoppingToken.IsCancellationRequested ? "interrupted" : "failed",
                    _time.GetUtcNow(), null, work.Kind == "verify" ? work.ArchiveId : null, false, CancellationToken.None); }
                catch (Exception) { _logger.LogWarning("Backup result could not be recorded."); }
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (!recorded && published is not null)
                try { BackupStorage.AssertFile(published, BackupArchive.MaximumArchiveBytes); File.Delete(published); } catch (Exception) { }
            if (directory is not null)
                try { _storage.DeleteWork(directory); } catch (Exception) { _logger.LogWarning("Backup staging cleanup is unavailable."); }
            Volatile.Write(ref _busy, 0);
        }
    }
    private async Task<BackupManifest> VerifyFileAsync(string path, string workDirectory, byte[] key, Guid archiveId,
        CoreIdentity identity, CancellationToken cancellationToken)
    {
        var payload = Path.Combine(workDirectory, "verify.tmp");
        await using (var input = File.OpenRead(path))
        await using (var output = BackupStorage.CreateFile(payload))
            await BackupArchive.DecryptAsync(input, output, key, cancellationToken);
        var extracted = Path.Combine(workDirectory, "extracted");
        BackupStorage.CreatePrivateDirectory(extracted);
        BackupManifest manifest;
        await using (var input = File.OpenRead(payload)) manifest = await BackupPackage.ExtractAndVerifyAsync(input, extracted, cancellationToken);
        var info = await CoreBackupDatabase.InspectAsync(Path.Combine(extracted, "core.db"), cancellationToken);
        if (manifest.ArchiveId != archiveId || manifest.RecoveryKeyId != BackupArchive.KeyId(key) ||
            manifest.CoreInstallationId != identity.CoreInstallationId || manifest.OrganizationId != identity.OrganizationId ||
            info.CoreInstallationId != manifest.CoreInstallationId || info.OrganizationId != manifest.OrganizationId)
            throw new InvalidDataException("Backup verification failed.");
        return manifest;
    }
    private byte[] ConfigurationReference()
    {
        // Configuration is descriptive only. The elevated restore keeps local trusted paths, receipts and certificates.
        var configured = _configuration["urls"];
        var origin = Uri.TryCreate(configured, UriKind.Absolute, out var uri) && uri.IsLoopback && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0
            ? uri.GetLeftPart(UriPartial.Authority) : null;
        var pin = _configuration["SentinelAI:LocalNetworkCertificateSha256"];
        if (pin is not { Length: 64 } || pin.Any(character => !Uri.IsHexDigit(character))) pin = null;
        return JsonSerializer.SerializeToUtf8Bytes(new { format = "sentinelai-core-configuration-reference-v1", loopbackOrigin = origin,
            localNetworkPort = int.TryParse(_configuration["SentinelAI:LocalNetworkPort"], out var port) ? (int?)port : null,
            localNetworkCertificateSha256 = pin });
    }
    private async Task ReconcileUnknownAsync(string workDirectory, byte[] key, CoreIdentity identity, CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        var known = state.Archives.Select(item => item.ArchiveId).ToHashSet();
        var recovered = new List<BackupArchiveSummary>();
        foreach (var path in Directory.EnumerateFiles(_storage.DirectoryPath, "*.sab").Take(32))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            if (!Guid.TryParseExact(name, "N", out var id) || known.Contains(id)) continue;
            BackupStorage.AssertFile(path, BackupArchive.MaximumArchiveBytes);
            // Keep the Windows handle open through verification and catalog insertion, denying mutation/removal.
            await using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                var manifest = await VerifyFileAsync(path, workDirectory, key, id, identity, cancellationToken);
                recovered.Add(new(id, manifest.CreatedUtc, held.Length, await HashAsync(path, cancellationToken),
                    manifest.RecoveryKeyId, "verified", _time.GetUtcNow()));
            }
            finally
            {
                var payload = Path.Combine(workDirectory, "verify.tmp");
                if (File.Exists(payload)) File.Delete(payload);
                var extracted = Path.Combine(workDirectory, "extracted");
                if (Directory.Exists(extracted)) Directory.Delete(extracted, recursive: true);
            }
        }
        // Missing historical catalog rows cannot be downloaded; remove only those stale metadata rows after
        // all unknown files authenticated successfully. No corresponding archive file is deleted here.
        foreach (var archive in state.Archives)
            if (!File.Exists(_storage.ArchivePath(archive.ArchiveId)))
                await _store.RemoveArchiveAsync(archive.ArchiveId, cancellationToken);
        // Reconstruct chronological catalog order, while preserving the source files on any failure.
        foreach (var archive in recovered.OrderBy(item => item.CreatedUtc))
            await _store.RegisterRecoveredArchiveAsync(archive, cancellationToken);
    }
    private async Task PruneAsync(int retained, CancellationToken cancellationToken, bool preserveVerified = false)
    {
        var state = await _store.ReadAsync(cancellationToken);
        var protectedArchive = preserveVerified ? state.Archives.FirstOrDefault(item => item.VerificationState == "verified")?.ArchiveId : null;
        foreach (var archive in state.Archives.Skip(retained).Where(item => item.ArchiveId != protectedArchive))
        {
            var path = _storage.ArchivePath(archive.ArchiveId);
            if (File.Exists(path)) { BackupStorage.AssertFile(path, BackupArchive.MaximumArchiveBytes); File.Delete(path); }
            await _store.RemoveArchiveAsync(archive.ArchiveId, cancellationToken);
        }
    }
    internal async Task<(FileStream Stream, BackupArchiveSummary Archive)?> OpenDownloadAsync(Guid id, CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        var archive = state.Archives.FirstOrDefault(item => item.ArchiveId == id);
        if (archive is null) return null;
        _storage.EnsureAvailable();
        var path = _storage.ArchivePath(id);
        BackupStorage.AssertFile(path, BackupArchive.MaximumArchiveBytes);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length != archive.SizeBytes) { await stream.DisposeAsync(); throw new InvalidDataException("Backup verification failed."); }
        return (stream, archive);
    }
    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
    }
}
