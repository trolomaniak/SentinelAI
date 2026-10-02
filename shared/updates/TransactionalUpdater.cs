using System.Text.Json;

namespace SentinelAI.Updates;

/// <summary>A real service adapter must honor cancellation, finish cancelled operations promptly, and validate the running service, not just its files.</summary>
public interface IServiceUpdateLifecycle
{
    Task StopAsync(CancellationToken cancellationToken);
    Task StartAsync(string installationDirectory, CancellationToken cancellationToken);
    Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken cancellationToken);
}

public enum UpdateInstallStatus { Installed, RolledBack, RollbackFailed, NoPendingRecovery }
public sealed record UpdateInstallResult(UpdateInstallStatus Status, string? Version, string? FailureCode);

/// <summary>Explicit local, code-only update transaction. Persistent application data must live outside the target.</summary>
public sealed class TransactionalUpdater
{
    public const string ReceiptFileName = ".sentinelai-update-receipt.json";
    private const int MaximumJournalBytes = 64 * 1024;
    private readonly TimeSpan _healthTimeout;
    private readonly TimeSpan _pollInterval;
    private readonly TimeSpan _recoveryTimeout;

    public TransactionalUpdater(TimeSpan? healthTimeout = null, TimeSpan? pollInterval = null,
        TimeSpan? recoveryTimeout = null)
    {
        _healthTimeout = healthTimeout ?? TimeSpan.FromSeconds(30);
        _pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(250);
        _recoveryTimeout = recoveryTimeout ?? TimeSpan.FromMinutes(2);
        if (_healthTimeout < TimeSpan.FromMilliseconds(10) || _healthTimeout > TimeSpan.FromMinutes(5) ||
            _pollInterval < TimeSpan.FromMilliseconds(1) || _pollInterval > _healthTimeout ||
            _recoveryTimeout < _healthTimeout || _recoveryTimeout > TimeSpan.FromMinutes(10))
            throw new ArgumentException("Update health and recovery timing must be explicitly bounded.");
    }

    public async Task<UpdateInstallResult> InstallAsync(ReadOnlyMemory<byte> signedManifest, string packagePath,
        UpdateVerificationPolicy policy, string installationDirectory, IServiceUpdateLifecycle lifecycle,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lifecycle);
        if (signedManifest.Length is < 1 or > UpdateManifestFormat.MaximumDocumentBytes)
            throw new UpdateValidationException();
        var document = signedManifest.ToArray(); // Keep authenticated metadata immutable across asynchronous work.
        var verified = UpdateManifestVerifier.Verify(document, policy);
        var expectedExecutable = ExpectedExecutable(verified.Manifest.ArtifactId);
        var paths = Paths.Create(installationDirectory, mustExist: true);
        await using var installationLock = AcquireLock(paths);
        if (File.Exists(paths.Journal)) throw new IOException("A pending update must be recovered before another installation.");
        ValidateCodeDirectory(paths.Target, expectedExecutable);
        ValidateInstalledVersion(paths.Target, verified, policy);
        cancellationToken.ThrowIfCancellationRequested();
        var transaction = new Journal(Guid.NewGuid().ToString("N"), "prepared", Convert.ToBase64String(document));
        var work = paths.Work(transaction.Id);
        UpdateFileSystem.CreatePrivateDirectory(work);
        var replacement = Path.Combine(work, "replacement");
        var backup = Path.Combine(work, "previous");
        var verifiedPackage = Path.Combine(work, "package.zip");
        var journalWritten = false;
        try
        {
            UpdateFileSystem.RejectReparseAncestors(packagePath);
            await UpdateArtifactVerifier.CopyAndVerifyAsync(packagePath, verifiedPackage, verified, cancellationToken);
            await PackageExtractor.ExtractAsync(verifiedPackage, replacement, expectedExecutable, cancellationToken);
            // The publisher cannot supply an installed-state receipt; only a healthy transaction writes one.
            if (File.Exists(Path.Combine(replacement, ReceiptFileName))) throw new InvalidDataException("A package cannot contain an update receipt.");
            cancellationToken.ThrowIfCancellationRequested();
            await WriteJournalAsync(paths, transaction, cancellationToken);
            journalWritten = true;
            await InvokeLifecycleAsync(lifecycle.StopAsync, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            ValidateCodeDirectory(paths.Target, expectedExecutable);
            UpdateFileSystem.RejectReparseAncestors(backup);
            Directory.Move(paths.Target, backup);
            transaction = transaction with { Phase = "backed-up" };
            await WriteJournalAsync(paths, transaction, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            UpdateFileSystem.RejectReparseAncestors(paths.Target);
            Directory.Move(replacement, paths.Target);
            transaction = transaction with { Phase = "installed" };
            await WriteJournalAsync(paths, transaction, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            await InvokeLifecycleAsync(token => lifecycle.StartAsync(paths.Target, token), cancellationToken);
            await EnsureHealthyAsync(paths.Target, lifecycle, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            await WriteReceiptAsync(paths.Target, document, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            transaction = transaction with { Phase = "committed" };
            await WriteJournalAsync(paths, transaction, cancellationToken);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            if (!journalWritten)
            {
                UpdateFileSystem.DeleteOwnedDirectory(work);
                throw;
            }
            return await RollbackAsync(paths, transaction, lifecycle, exception is OperationCanceledException ? "cancelled" : "update_failed");
        }
        // A cleanup problem after the durable healthy commit must not revert successfully running code.
        try { Cleanup(paths, work); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        return new UpdateInstallResult(UpdateInstallStatus.Installed, verified.Manifest.Version, null);
    }

    public async Task<UpdateInstallResult> RecoverAsync(string installationDirectory, UpdateVerificationPolicy policy,
        IServiceUpdateLifecycle lifecycle, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lifecycle);
        var paths = Paths.Create(installationDirectory, mustExist: false);
        await using var installationLock = AcquireLock(paths);
        if (!File.Exists(paths.Journal)) return new UpdateInstallResult(UpdateInstallStatus.NoPendingRecovery, null, null);
        cancellationToken.ThrowIfCancellationRequested();
        var transaction = await ReadJournalAsync(paths.Journal, cancellationToken);
        var authenticated = UpdateManifestVerifier.Authenticate(Convert.FromBase64String(transaction.Manifest), policy);
        ExpectedExecutable(authenticated.Manifest.ArtifactId);
        var work = paths.Work(transaction.Id);
        UpdateFileSystem.RejectReparseAncestors(work);
        if (!Directory.Exists(work) && transaction.Phase is not ("committed" or "rolled-back"))
            throw new IOException("A pending update has lost its transaction directory.");
        if (Directory.Exists(work)) UpdateFileSystem.ValidateTree(work);
        if (transaction.Phase == "committed")
        {
            // A durable commit can be cleaned up only when the signed receipt matches that exact update.
            ValidateCodeDirectory(paths.Target, ExpectedExecutable(authenticated.Manifest.ArtifactId));
            var receipt = await ReadBoundedAsync(Path.Combine(paths.Target, ReceiptFileName), UpdateManifestFormat.MaximumDocumentBytes, cancellationToken);
            if (!receipt.AsSpan().SequenceEqual(Convert.FromBase64String(transaction.Manifest)))
                throw new IOException("The committed update receipt does not match its transaction.");
            Cleanup(paths, work);
            return new UpdateInstallResult(UpdateInstallStatus.Installed, authenticated.Manifest.Version, null);
        }
        return await RollbackAsync(paths, transaction, lifecycle, "interrupted_update");
    }

    private async Task<UpdateInstallResult> RollbackAsync(Paths paths, Journal transaction,
        IServiceUpdateLifecycle lifecycle, string failureCode)
    {
        using var recovery = new CancellationTokenSource(_recoveryTimeout);
        var work = paths.Work(transaction.Id);
        var backup = Path.Combine(work, "previous");
        var failed = Path.Combine(work, "failed");
        try
        {
            // Do not move or delete service code until the service adapter has confirmed a stop.
            await InvokeLifecycleAsync(lifecycle.StopAsync, recovery.Token);
            recovery.Token.ThrowIfCancellationRequested();
            UpdateFileSystem.RejectReparseAncestors(paths.Target);
            if (Directory.Exists(work)) UpdateFileSystem.ValidateTree(work);
            if (Directory.Exists(backup))
            {
                if (Directory.Exists(paths.Target))
                {
                    UpdateFileSystem.ValidateTree(paths.Target);
                    if (Directory.Exists(failed)) throw new IOException("Rollback paths are ambiguous.");
                    Directory.Move(paths.Target, failed);
                }
                transaction = transaction with { Phase = "restoring" };
                await WriteJournalAsync(paths, transaction, recovery.Token);
                Directory.Move(backup, paths.Target);
                transaction = transaction with { Phase = "restored" };
                await WriteJournalAsync(paths, transaction, recovery.Token);
            }
            else if (!Directory.Exists(paths.Target) || transaction.Phase is "backed-up" or "installed")
                throw new IOException("The previous installation is unavailable for rollback.");
            UpdateFileSystem.ValidateTree(paths.Target);
            await InvokeLifecycleAsync(token => lifecycle.StartAsync(paths.Target, token), recovery.Token);
            await EnsureHealthyAsync(paths.Target, lifecycle, recovery.Token);
            recovery.Token.ThrowIfCancellationRequested();
            transaction = transaction with { Phase = "rolled-back" };
            await WriteJournalAsync(paths, transaction, recovery.Token);
            Cleanup(paths, work);
            return new UpdateInstallResult(UpdateInstallStatus.RolledBack, null, failureCode);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // Retain every remaining previous/failed directory and the journal for manual retry.
            return new UpdateInstallResult(UpdateInstallStatus.RollbackFailed, null, "rollback_failed");
        }
    }

    private async Task EnsureHealthyAsync(string directory, IServiceUpdateLifecycle lifecycle, CancellationToken cancellationToken)
    {
        using var health = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        health.CancelAfter(_healthTimeout);
        try
        {
            while (true)
            {
                health.Token.ThrowIfCancellationRequested();
                if (await lifecycle.IsHealthyAsync(directory, health.Token).WaitAsync(health.Token)) return;
                await Task.Delay(_pollInterval, health.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The updated service did not become healthy within its deadline.");
        }
    }

    private async Task InvokeLifecycleAsync(Func<CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_recoveryTimeout);
        await operation(deadline.Token).WaitAsync(deadline.Token);
    }

    private static void ValidateInstalledVersion(string target, VerifiedUpdateManifest candidate, UpdateVerificationPolicy policy)
    {
        var receiptPath = Path.Combine(target, ReceiptFileName);
        if (!File.Exists(receiptPath)) return; // Legacy installations use the explicit operator version floor.
        UpdateFileSystem.RejectReparseAncestors(receiptPath);
        var bytes = ReadBoundedAsync(receiptPath, UpdateManifestFormat.MaximumDocumentBytes, CancellationToken.None).GetAwaiter().GetResult();
        var receipt = UpdateManifestVerifier.Authenticate(bytes, policy);
        if (Version.Parse(candidate.Manifest.Version) <= Version.Parse(receipt.Manifest.Version)) throw new UpdateValidationException();
    }

    private static string ExpectedExecutable(string artifactId) => artifactId switch
    {
        "sentinelai-agent-win-x64" => "SentinelAI.Agent.exe",
        "sentinelai-core-win-x64" => "SentinelAI.Core.exe",
        _ => throw new UpdateValidationException()
    };

    private static void ValidateCodeDirectory(string target, string executable)
    {
        UpdateFileSystem.ValidateTree(target);
        var executablePath = Path.Combine(target, executable);
        if (!File.Exists(executablePath)) throw new IOException("The target is not the expected SentinelAI code installation.");
        UpdateFileSystem.RejectReparseAncestors(executablePath);
    }

    private static FileStream AcquireLock(Paths paths)
    {
        UpdateFileSystem.RejectReparseAncestors(paths.Lock);
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(paths.Lock, options); // The fixed lock file remains, preventing an unlink/reopen lock race.
    }

    private static async Task WriteReceiptAsync(string target, ReadOnlyMemory<byte> document, CancellationToken cancellationToken)
    {
        await using var file = UpdateFileSystem.CreatePrivateFile(Path.Combine(target, ReceiptFileName));
        await file.WriteAsync(document, cancellationToken);
        await file.FlushAsync(cancellationToken);
        file.Flush(flushToDisk: true);
    }

    private static async Task WriteJournalAsync(Paths paths, Journal journal, CancellationToken cancellationToken)
    {
        var temporary = paths.Journal + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { format = 1, transaction = journal.Id, phase = journal.Phase, manifest = journal.Manifest });
        if (bytes.Length > MaximumJournalBytes) throw new InvalidDataException("The update journal exceeds its limit.");
        try
        {
            await using (var file = UpdateFileSystem.CreatePrivateFile(temporary))
            {
                await file.WriteAsync(bytes, cancellationToken);
                await file.FlushAsync(cancellationToken);
                file.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            UpdateFileSystem.RejectReparseAncestors(paths.Journal);
            File.Move(temporary, paths.Journal, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static async Task<Journal> ReadJournalAsync(string journalPath, CancellationToken cancellationToken)
    {
        UpdateFileSystem.RejectReparseAncestors(journalPath);
        var bytes = await ReadBoundedAsync(journalPath, MaximumJournalBytes, cancellationToken);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The update journal is malformed.");
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var field in root.EnumerateObject())
            if (!fields.TryAdd(field.Name, field.Value)) throw new InvalidDataException("The update journal has duplicate fields.");
        if (fields.Count != 4 || !fields.TryGetValue("format", out var format) || !format.TryGetInt32(out var formatVersion) || formatVersion != 1 ||
            !fields.TryGetValue("transaction", out var id) || id.ValueKind != JsonValueKind.String ||
            !fields.TryGetValue("phase", out var phase) || phase.ValueKind != JsonValueKind.String ||
            !fields.TryGetValue("manifest", out var manifest) || manifest.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("The update journal is malformed.");
        var transactionId = id.GetString()!;
        var phaseName = phase.GetString()!;
        var manifestText = manifest.GetString()!;
        if (transactionId.Length != 32 || transactionId.Any(c => !char.IsAsciiHexDigit(c)) || transactionId != transactionId.ToLowerInvariant() ||
            phaseName is not ("prepared" or "backed-up" or "installed" or "restoring" or "restored" or "rolled-back" or "committed") ||
            manifestText.Length is < 1 or > 32768)
            throw new InvalidDataException("The update journal is malformed.");
        try { if (Convert.FromBase64String(manifestText).Length > UpdateManifestFormat.MaximumDocumentBytes) throw new InvalidDataException("The update journal is malformed."); }
        catch (FormatException) { throw new InvalidDataException("The update journal is malformed."); }
        return new Journal(transactionId, phaseName, manifestText);
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken cancellationToken)
    {
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (file.Length is < 1 || file.Length > maximum) throw new InvalidDataException("The update state exceeds its bounds.");
        var bytes = new byte[checked((int)file.Length)];
        await file.ReadExactlyAsync(bytes, cancellationToken);
        if (file.ReadByte() != -1) throw new InvalidDataException("The update state changed while reading.");
        return bytes;
    }

    private static void Cleanup(Paths paths, string work)
    {
        UpdateFileSystem.DeleteOwnedDirectory(work);
        UpdateFileSystem.RejectReparseAncestors(paths.Journal);
        File.Delete(paths.Journal);
    }

    private sealed record Journal(string Id, string Phase, string Manifest);
    private sealed record Paths(string Target, string Parent, string Prefix)
    {
        public string Lock => Path.Combine(Parent, Prefix + ".lock");
        public string Journal => Path.Combine(Parent, Prefix + ".json");
        public string Work(string id) => Path.Combine(Parent, Prefix + "-" + id);
        public static Paths Create(string directory, bool mustExist)
        {
            var target = UpdateFileSystem.ValidateInstallationPath(directory, mustExist);
            var parent = Path.GetDirectoryName(target)!;
            if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("The installation parent does not exist.");
            return new Paths(target, parent, "." + Path.GetFileName(target) + ".sentinelai-update");
        }
    }
}
