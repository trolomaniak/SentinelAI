using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Core.Backups;
using SentinelAI.Core.Persistence;
using SentinelAI.Hosting;

namespace SentinelAI.Core.Recovery;

internal enum RecoveryServiceState { Unavailable, Stopped, Running }

// The injectable environment is internal and is never selectable through command arguments or configuration.
internal sealed record BackupRestoreEnvironment(string DataDirectory, Func<RecoveryServiceState> ServiceState,
    IBackupKeyProtection KeyProtection, Action<string>? Checkpoint = null, string? LocalNetworkCertificateSha256 = null);

/// <summary>Elevated, one-shot, local recovery. Never starts an HTTP host or restores archive-selected paths.</summary>
internal static class BackupRestoreCommand
{
    private const string JournalName = "restore-journal.json";
    private const string OldName = "restore-old.db";
    private const string DatabaseName = "sentinelai.db";
    private static readonly string[] Sidecars = ["", "-wal", "-shm", "-journal"];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const string CoreSid = "S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900";

    internal static bool IsRecoveryCommand(string[] arguments) =>
        arguments.Any(argument => argument.StartsWith("--restore-backup", StringComparison.Ordinal));

    internal static async Task<int> RunAsync(string[] arguments, Stream input, TextWriter output,
        bool isWindowsService, bool isInputRedirected, CancellationToken cancellationToken = default)
    {
        var result = new BackupRecoveryResult(BackupRecoveryContract.Unavailable);
        byte[]? bytes = null;
        try
        {
            if (arguments.Length != 3 || arguments[0] != BackupRecoveryContract.Command || arguments[1] != "--config" ||
                !isInputRedirected || isWindowsService)
                result = new(BackupRecoveryContract.InvalidInput);
            else if (OperatingSystem.IsWindows() &&
                     Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME") is null &&
                     Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD") is null)
            {
                var environment = CreateInstalledEnvironment(arguments[2]);
                bytes = await ReadInputAsync(input, cancellationToken);
                result = await ExecuteAsync(ReadRequest(bytes), environment, cancellationToken);
            }
        }
        catch (OperationCanceledException) { result = new(BackupRecoveryContract.Unavailable); }
        catch (Exception) { result = new(BackupRecoveryContract.Rejected); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
        await output.WriteLineAsync(JsonSerializer.Serialize(result, Json));
        return result.Outcome is BackupRecoveryContract.Verified or BackupRecoveryContract.Restored or
            BackupRecoveryContract.RolledBack or BackupRecoveryContract.Committed or BackupRecoveryContract.Ready or
            BackupRecoveryContract.Pending ? 0 : 1;
    }

    internal static async Task<BackupRecoveryResult> ExecuteAsync(BackupRecoveryRequest request,
        BackupRestoreEnvironment environment, CancellationToken cancellationToken = default)
    {
        ValidateRequest(request);
        var storage = new BackupStorage(environment.DataDirectory, managedService: true);
        storage.EnsureAvailable();
        var root = storage.DirectoryPath;
        var database = Path.Combine(Path.GetFullPath(environment.DataDirectory), DatabaseName);
        var lockPath = Path.Combine(root, "restore.lock");
        RejectLinks(lockPath);
        if (File.Exists(lockPath)) AssertSingleLink(lockPath);
        using var operationLock = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        SetPrivateUnix(lockPath);
        var journalPath = Path.Combine(root, JournalName);
        var journal = ReadJournal(journalPath);
        if (journal is { Phase: "committed" or "rolledBack" })
        {
            var outcome = journal.Phase == "committed" ? BackupRecoveryContract.Committed : BackupRecoveryContract.RolledBack;
            CleanupCommitted(root, journalPath, journal);
            return new(outcome, journal.Preview);
        }
        if (request.Operation == BackupRecoveryContract.Status)
            return journal is null ? new(Sidecars.Any(suffix => File.Exists(Path.Combine(root, OldName + suffix)))
                ? BackupRecoveryContract.Unavailable : BackupRecoveryContract.Ready) : Pending(journal);
        if (request.Operation is BackupRecoveryContract.Rollback or BackupRecoveryContract.Commit)
        {
            if (journal is null || request.ConfirmedArchiveId != journal.Preview.ArchiveId ||
                request.Confirmation != Confirmation(journal.Preview.Mode))
                return new(BackupRecoveryContract.Rejected);
            if (request.Operation == BackupRecoveryContract.Commit)
            {
                if (journal.Phase != "applied" || environment.ServiceState() != RecoveryServiceState.Running)
                    return Pending(journal);
                var current = await ReadCurrentDatabaseInfoAsync(database, cancellationToken);
                if (current.CoreInstallationId != journal.Preview.CoreInstallationId || current.OrganizationId != journal.Preview.OrganizationId)
                    return new(BackupRecoveryContract.IdentityMismatch, journal.Preview, journal.Preview.ArchiveId);
                WriteJournal(journalPath, journal with { Phase = "committed" });
                environment.Checkpoint?.Invoke("committed");
                CleanupCommitted(root, journalPath, journal);
                return new(BackupRecoveryContract.Committed, journal.Preview);
            }
            if (environment.ServiceState() != RecoveryServiceState.Stopped)
                return new(BackupRecoveryContract.ServiceRunning, journal.Preview, journal.Preview.ArchiveId);
            await RollbackAsync(environment, journalPath, journal, cancellationToken);
            return new(BackupRecoveryContract.RolledBack, journal.Preview);
        }
        if (journal is not null) return Pending(journal);

        byte[]? key = null;
        var work = storage.CreateWorkDirectory();
        try
        {
            var keyFile = await ReadSmallFileAsync(request.RecoveryKeyPath!, 4096, cancellationToken);
            try { key = RecoveryKeyFile.Open(keyFile, request.Passphrase.AsSpan()); }
            finally { CryptographicOperations.ZeroMemory(keyFile); }
            string archiveHash;
            await using (var source = OpenRead(request.ArchivePath!, BackupArchive.MaximumArchiveBytes))
            await using (var payload = BackupStorage.CreateFile(Path.Combine(work, "payload.tmp")))
            {
                archiveHash = Convert.ToHexStringLower(await SHA256.HashDataAsync(source, cancellationToken));
                source.Position = 0;
                await BackupArchive.DecryptAsync(source, payload, key, cancellationToken);
            }
            var extracted = Path.Combine(work, "extracted");
            BackupStorage.CreatePrivateDirectory(extracted);
            BackupManifest manifest;
            await using (var payload = OpenRead(Path.Combine(work, "payload.tmp"), BackupArchive.MaximumPayloadBytes))
                manifest = await BackupPackage.ExtractAndVerifyAsync(payload, extracted, cancellationToken);
            if (manifest.RecoveryKeyId != BackupArchive.KeyId(key)) throw new InvalidDataException();
            var stagedDatabase = Path.Combine(extracted, "core.db");
            var recovered = await CoreBackupDatabase.InspectAsync(stagedDatabase, cancellationToken);
            if (recovered.CoreInstallationId != manifest.CoreInstallationId || recovered.OrganizationId != manifest.OrganizationId)
                throw new InvalidDataException();

            CoreBackupDatabaseInfo? current = null;
            try { if (File.Exists(database)) current = await ReadCurrentDatabaseInfoAsync(database, cancellationToken); }
            catch (Exception exception) when (exception is IOException or InvalidDataException or SqliteException) { }
            var identity = new CoreIdentity(manifest.CoreInstallationId, manifest.OrganizationId);
            if (request.Mode == BackupRecoveryContract.SameMachine)
            {
                var archivedPin = ReadConfigurationReference(Path.Combine(extracted, "configuration.json"));
                if (!string.Equals(archivedPin, environment.LocalNetworkCertificateSha256, StringComparison.OrdinalIgnoreCase))
                    return new(BackupRecoveryContract.IdentityMismatch);
                // The authenticated anchor is still checked when the live database is healthy. This rejects
                // an unrelated archive/key instead of treating readable SQLite as authority to replace it.
                var anchored = BackupIdentityAnchor.Read(root, key);
                if (anchored != identity || current is not null &&
                    (current.CoreInstallationId != identity.CoreInstallationId || current.OrganizationId != identity.OrganizationId))
                    return new(BackupRecoveryContract.IdentityMismatch);
            }
            else
            {
                if (current is null || current.CoreInstallationId == identity.CoreInstallationId ||
                    File.Exists(Path.Combine(root, "backup-identity.json")) ||
                    !await IsFreshMigrationTargetAsync(database, cancellationToken))
                    return new(BackupRecoveryContract.IdentityMismatch);
            }
            var preview = new BackupRecoveryPreview(manifest.ArchiveId, manifest.CreatedUtc, manifest.CoreInstallationId,
                manifest.OrganizationId, recovered.AdministratorCount, recovered.EndpointCount, archiveHash, request.Mode);
            if (request.Operation == BackupRecoveryContract.Preview) return new(BackupRecoveryContract.Verified, preview);
            if (request.ConfirmedArchiveId != preview.ArchiveId || request.ExpectedArchiveSha256 != archiveHash ||
                request.Confirmation != Confirmation(request.Mode)) return new(BackupRecoveryContract.Rejected);
            if (environment.ServiceState() != RecoveryServiceState.Stopped) return new(BackupRecoveryContract.ServiceRunning);

            // No active SQLite pool may retain old file handles through replacement.
            SqliteConnection.ClearAllPools();
            var currentHealthy = current is not null;
            if (currentHealthy)
            {
                try { _ = await CoreBackupDatabase.InspectAsync(database, cancellationToken); }
                catch (Exception error) when (error is IOException or InvalidDataException or SqliteException)
                { currentHealthy = false; }
            }
            await PrepareDatabaseAsync(stagedDatabase, database, currentHealthy, request.Mode, manifest.CreatedUtc,
                key, environment.KeyProtection, cancellationToken);
            _ = await CoreBackupDatabase.InspectAsync(stagedDatabase, cancellationToken);
            var originals = await DescribeOriginalsAsync(database, root, cancellationToken);
            journal = new RecoveryJournal(1, "capturing", preview, originals,
                File.Exists(Path.Combine(root, "backup-identity.json")), null);
            WriteJournal(journalPath, journal);
            environment.Checkpoint?.Invoke("capturing");
            await CopyOriginalsAsync(database, root, originals, cancellationToken);
            environment.Checkpoint?.Invoke("captured");
            journal = journal with { Phase = "prepared" };
            WriteJournal(journalPath, journal);
            environment.Checkpoint?.Invoke("prepared");
            // Normal Core startup refuses a prepared journal, closing the stop/start race before replacement.
            if (environment.ServiceState() != RecoveryServiceState.Stopped) return Pending(journal);
            foreach (var original in originals) await AssertFileHashAsync(Path.Combine(root, OldName + original.Suffix), original.Sha256, cancellationToken);
            RejectLinks(database);
            if (File.Exists(database)) AssertSingleLink(database);
            File.Move(stagedDatabase, database, overwrite: true);
            environment.Checkpoint?.Invoke("databaseReplaced");
            SetPrivateUnix(database);
            ApplySecurity(database, originals.FirstOrDefault(file => file.Suffix == "")?.Security);
            foreach (var suffix in Sidecars.Skip(1))
            {
                var path = database + suffix;
                if (!File.Exists(path)) continue;
                var original = originals.SingleOrDefault(item => item.Suffix == suffix) ?? throw new InvalidDataException();
                await AssertFileHashAsync(path, original.Sha256, cancellationToken);
                File.Delete(path);
            }
            if (request.Mode == BackupRecoveryContract.Migration)
            {
                BackupIdentityAnchor.Ensure(root, identity, key);
                environment.Checkpoint?.Invoke("anchorWritten");
                journal = journal with { NewAnchorSha256 = await HashFileAsync(Path.Combine(root, "backup-identity.json"), 8192, cancellationToken) };
            }
            journal = journal with { Phase = "applied" };
            WriteJournal(journalPath, journal);
            environment.Checkpoint?.Invoke("applied");
            return new(BackupRecoveryContract.Restored, preview, preview.ArchiveId);
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            storage.DeleteWork(work);
        }
    }

    /// <summary>Called before normal service hosting; interrupted pre-commit replacement must be recovered first.</summary>
    internal static void AssertHostStartupAllowed(string[] arguments)
    {
        if (!arguments.Contains("--config", StringComparer.Ordinal)) return;
        var pilot = PilotHostConfiguration.Read(arguments, agent: false);
        if (pilot.Values is null || !pilot.Values.TryGetValue("SentinelAI:DataDirectory", out var directory) || directory is null) return;
        AssertHostStartupAllowedAt(directory);
    }

    internal static void AssertHostStartupAllowedAt(string directory)
    {
        var root = Path.Combine(Path.GetFullPath(directory), "backups");
        if (!Directory.Exists(root)) return;
        RejectLinks(root);
        var lockPath = Path.Combine(root, "restore.lock");
        if (File.Exists(lockPath))
        {
            RejectLinks(lockPath); AssertSingleLink(lockPath);
            using var probe = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        var journal = ReadJournal(Path.Combine(root, JournalName));
        if (journal is not null && journal.Phase is not ("applied" or "committed" or "rolledBack"))
            throw new InvalidOperationException("Local database recovery must complete before Core starts.");
    }

    private sealed record OriginalFile(string Suffix, long Size, string Sha256, string? Security);
    private sealed record RecoveryJournal(int Version, string Phase, BackupRecoveryPreview Preview,
        IReadOnlyList<OriginalFile> Originals, bool OriginalAnchorExists, string? NewAnchorSha256);

    private static BackupRecoveryResult Pending(RecoveryJournal journal) =>
        new(BackupRecoveryContract.Pending, journal.Preview, journal.Preview.ArchiveId);
    private static string Confirmation(string mode) => mode == BackupRecoveryContract.Migration
        ? BackupRecoveryContract.MigrationConfirmation : BackupRecoveryContract.RestoreConfirmation;
    private static string? ReadConfigurationReference(string path)
    {
        using var stream = OpenRead(path, BackupPackage.MaximumConfigurationBytes);
        using var document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 2 });
        var fields = document.RootElement.EnumerateObject().ToArray();
        if (fields.Length != 4 || fields.Select(field => field.Name).Distinct(StringComparer.Ordinal).Count() != 4 ||
            fields.Any(field => field.Name is not ("format" or "loopbackOrigin" or "localNetworkPort" or "localNetworkCertificateSha256")) ||
            document.RootElement.GetProperty("format").GetString() != "sentinelai-core-configuration-reference-v1")
            throw new InvalidDataException();
        var pin = document.RootElement.GetProperty("localNetworkCertificateSha256");
        if (pin.ValueKind == JsonValueKind.Null) return null;
        if (pin.ValueKind != JsonValueKind.String || pin.GetString() is not { Length: 64 } text ||
            !text.All(Uri.IsHexDigit)) throw new InvalidDataException();
        return text;
    }

    private static async Task PrepareDatabaseAsync(string staged, string current, bool currentHealthy, string mode,
        DateTimeOffset archiveCreatedUtc, byte[] key,
        IBackupKeyProtection protection, CancellationToken cancellationToken)
    {
        if (!protection.IsSupported) throw new PlatformNotSupportedException();
        var protectedKey = protection.Protect(key);
        try
        {
            await using var connection = OpenDatabase(staged, writable: true);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction(deferred: false);
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    UPDATE BackupSettings SET Enabled=0,NextDueUtcTicks=NULL,ProtectedKey=$key,
                        RecoveryKeyId=$keyId,Version=CASE WHEN Version<9223372036854775807 THEN Version+1 ELSE Version END
                        WHERE Singleton=1;
                    UPDATE EnrollmentTokens SET RevokedUtcTicks=$now WHERE ConsumedUtcTicks IS NULL;
                    UPDATE BackupAttempts SET Outcome='interrupted',CompletedUtcTicks=$now WHERE Outcome='inProgress';
                    """;
                command.Parameters.AddWithValue("$key", protectedKey);
                command.Parameters.AddWithValue("$keyId", BackupArchive.KeyId(key));
                command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.UtcTicks);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
            if (mode == BackupRecoveryContract.Migration)
            {
                var fresh = await ReadMigrationRowsAsync(current, cancellationToken);
                await using var retire = connection.CreateCommand(); retire.Transaction = transaction;
                retire.CommandText = "UPDATE EndpointEnrollments SET RemovedUtcTicks=$now WHERE RemovedUtcTicks IS NULL;";
                retire.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.UtcTicks);
                await retire.ExecuteNonQueryAsync(cancellationToken);
                foreach (var row in fresh)
                {
                    await using var merge = connection.CreateCommand(); merge.Transaction = transaction;
                    merge.CommandText = """
                        INSERT INTO EndpointEnrollments(InstallationId,EndpointId,CoreInstallationId,OrganizationId,CredentialHash,RemovedUtcTicks,EnrolledOverLocalNetwork)
                            SELECT $installation,$endpoint,CoreInstallationId,OrganizationId,$credential,NULL,0 FROM CoreIdentity WHERE Singleton=1;
                        INSERT INTO Devices(InstallationId,LastSeenUtcTicks,HealthStatus,EnrollmentStatus) VALUES($installation,$seen,$health,$enrollment);
                        """;
                    merge.Parameters.AddWithValue("$installation", row.InstallationId); merge.Parameters.AddWithValue("$endpoint", row.EndpointId);
                    merge.Parameters.AddWithValue("$credential", row.CredentialHash); merge.Parameters.AddWithValue("$seen", row.LastSeen);
                    merge.Parameters.AddWithValue("$health", row.Health); merge.Parameters.AddWithValue("$enrollment", row.Enrollment);
                    await merge.ExecuteNonQueryAsync(cancellationToken);
                    CryptographicOperations.ZeroMemory(row.CredentialHash);
                }
            }
            else if (File.Exists(current))
            {
                // A point-in-time restore must not silently re-enable credentials revoked after that point.
                // Other tables can be damaged while this security state remains readable.
                foreach (var revoked in await ReadRevocationsAsync(current, cancellationToken))
                {
                    await using var retain = connection.CreateCommand(); retain.Transaction = transaction;
                    retain.CommandText = "UPDATE EndpointEnrollments SET RemovedUtcTicks=$when WHERE InstallationId=$id;";
                    retain.Parameters.AddWithValue("$when", revoked.When); retain.Parameters.AddWithValue("$id", revoked.Id);
                    await retain.ExecuteNonQueryAsync(cancellationToken);
                }
            }
            await using (var catalog = connection.CreateCommand())
            {
                catalog.Transaction = transaction;
                if (mode == BackupRecoveryContract.Migration)
                    catalog.CommandText = "DELETE FROM BackupArchives; DELETE FROM BackupAttempts; UPDATE BackupSettings SET LastSuccessfulUtcTicks=NULL WHERE Singleton=1;";
                else if (currentHealthy)
                {
                    // Backup files belong to the current machine's recovery store, not the older business point.
                    // Preserve their current catalog so newer retained copies remain visible and are never deleted as orphans.
                    catalog.CommandText = """
                        ATTACH DATABASE $current AS recovery_current;
                        DELETE FROM main.BackupArchives;
                        INSERT INTO main.BackupArchives(ArchiveId,CreatedUtcTicks,SizeBytes,Sha256,RecoveryKeyId,VerificationState,VerifiedUtcTicks)
                            SELECT ArchiveId,CreatedUtcTicks,SizeBytes,Sha256,RecoveryKeyId,VerificationState,VerifiedUtcTicks FROM recovery_current.BackupArchives;
                        DELETE FROM main.BackupAttempts;
                        INSERT INTO main.BackupAttempts(OperationId,Kind,Outcome,StartedUtcTicks,CompletedUtcTicks,ArchiveId)
                            SELECT OperationId,Kind,CASE WHEN Outcome='inProgress' THEN 'interrupted' ELSE Outcome END,
                                StartedUtcTicks,CASE WHEN Outcome='inProgress' THEN $now ELSE CompletedUtcTicks END,ArchiveId
                            FROM recovery_current.BackupAttempts;
                        UPDATE main.BackupSettings SET
                            Version=MAX(Version,(SELECT Version FROM recovery_current.BackupSettings WHERE Singleton=1))+1,
                            IntervalHours=(SELECT IntervalHours FROM recovery_current.BackupSettings WHERE Singleton=1),
                            RetentionCount=(SELECT RetentionCount FROM recovery_current.BackupSettings WHERE Singleton=1),
                            LastSuccessfulUtcTicks=(SELECT LastSuccessfulUtcTicks FROM recovery_current.BackupSettings WHERE Singleton=1)
                            WHERE Singleton=1;
                        """;
                    catalog.Parameters.AddWithValue("$current", Path.GetFullPath(current));
                    catalog.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.UtcTicks);
                }
                if (!string.IsNullOrEmpty(catalog.CommandText)) await catalog.ExecuteNonQueryAsync(cancellationToken);
            }
            // Restoring older business state must never move a trusted clock floor backwards or erase a
            // previously detected rollback. The authenticated archive time also survives loss of the old DB.
            var clockFloor = Math.Max(DateTimeOffset.UtcNow.UtcTicks, archiveCreatedUtc.UtcTicks);
            var clockRollback = false;
            if (File.Exists(current))
            {
                try
                {
                    await using var liveClock = OpenDatabase(current, writable: false); await liveClock.OpenAsync(cancellationToken);
                    await using var readClock = liveClock.CreateCommand();
                    readClock.CommandText = "SELECT HighWaterUtcTicks,ClockRollbackDetected FROM LicenseState WHERE Singleton=1;";
                    await using var clockReader = await readClock.ExecuteReaderAsync(cancellationToken);
                    if (await clockReader.ReadAsync(cancellationToken))
                    {
                        var knownFloor = clockReader.GetInt64(0);
                        if (knownFloor >= 0 && knownFloor <= DateTimeOffset.MaxValue.UtcTicks)
                            clockFloor = Math.Max(clockFloor, knownFloor);
                        clockRollback = clockReader.GetInt64(1) != 0;
                    }
                }
                catch (SqliteException) { }
            }
            await using (var retainClock = connection.CreateCommand())
            {
                retainClock.Transaction = transaction;
                retainClock.CommandText = """
                    INSERT OR IGNORE INTO LicenseState(Singleton,HighWaterUtcTicks,LastAttemptSucceeded,ClockRollbackDetected)
                        VALUES(1,$floor,0,$rollback);
                    UPDATE LicenseState SET HighWaterUtcTicks=MAX(HighWaterUtcTicks,$floor),
                        ClockRollbackDetected=MAX(ClockRollbackDetected,$rollback) WHERE Singleton=1;
                    """;
                retainClock.Parameters.AddWithValue("$floor", clockFloor); retainClock.Parameters.AddWithValue("$rollback", clockRollback ? 1 : 0);
                await retainClock.ExecuteNonQueryAsync(cancellationToken);
            }
            transaction.Commit();
        }
        finally { CryptographicOperations.ZeroMemory(protectedKey); }
    }

    private static async Task<IReadOnlyList<(string Id, long When)>> ReadRevocationsAsync(string database,
        CancellationToken cancellationToken)
    {
        var revoked = new List<(string Id, long When)>();
        try
        {
            await using var live = OpenDatabase(database, writable: false); await live.OpenAsync(cancellationToken);
            await using var query = live.CreateCommand();
            query.CommandText = "SELECT InstallationId,RemovedUtcTicks FROM EndpointEnrollments WHERE RemovedUtcTicks IS NOT NULL LIMIT 1000000;";
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) revoked.Add((reader.GetString(0), reader.GetInt64(1)));
        }
        catch (SqliteException) { /* Preserve any revocations read before the damaged region. */ }
        return revoked;
    }

    private sealed record MigrationRow(string InstallationId, string EndpointId, byte[] CredentialHash,
        long LastSeen, string Health, string Enrollment);
    private static async Task<bool> IsFreshMigrationTargetAsync(string database, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var created = File.GetCreationTimeUtc(database);
        if (created < now.UtcDateTime.AddHours(-24) || created > now.UtcDateTime.AddMinutes(5)) return false;
        await using var connection = OpenDatabase(database, writable: false); await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM Administrators)=1
                AND (SELECT COUNT(*) FROM EndpointEnrollments)<=1
                AND NOT EXISTS(SELECT 1 FROM EndpointEnrollments WHERE RemovedUtcTicks IS NOT NULL OR COALESCE(EnrolledOverLocalNetwork,0)<>0)
                AND NOT EXISTS(SELECT 1 FROM BackupSettings WHERE ProtectedKey IS NOT NULL OR LastSuccessfulUtcTicks IS NOT NULL)
                AND NOT EXISTS(SELECT 1 FROM RiskRegister)
                AND NOT EXISTS(SELECT 1 FROM AlertStatusHistory WHERE PreviousStatus IS NOT NULL)
                AND NOT EXISTS(SELECT 1 FROM TrackedAlerts WHERE CreatedUtcTicks<$cutoff)
                AND NOT EXISTS(SELECT 1 FROM SecurityEventObservations WHERE ReceivedUtcTicks<$cutoff);
            """;
        command.Parameters.AddWithValue("$cutoff", now.AddHours(-24).UtcTicks);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) == 1;
    }
    private static async Task<IReadOnlyList<MigrationRow>> ReadMigrationRowsAsync(string database, CancellationToken cancellationToken)
    {
        if (!await IsFreshMigrationTargetAsync(database, cancellationToken)) throw new InvalidDataException();
        await using var connection = OpenDatabase(database, writable: false); await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT e.InstallationId,e.EndpointId,e.CredentialHash,COALESCE(d.LastSeenUtcTicks,0),
                COALESCE(d.HealthStatus,'reporting'),COALESCE(d.EnrollmentStatus,'enrolled')
            FROM EndpointEnrollments e LEFT JOIN Devices d ON e.InstallationId=d.InstallationId;
            """;
        var result = new List<MigrationRow>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (result.Count != 0) throw new InvalidDataException();
            result.Add(new(reader.GetString(0), reader.GetString(1), (byte[])reader.GetValue(2), reader.GetInt64(3), reader.GetString(4), reader.GetString(5)));
        }
        return result;
    }

    private static async Task<IReadOnlyList<OriginalFile>> DescribeOriginalsAsync(string database, string root, CancellationToken cancellationToken)
    {
        var originals = new List<OriginalFile>();
        foreach (var suffix in Sidecars)
        {
            var path = database + suffix; var destination = Path.Combine(root, OldName + suffix);
            if (File.Exists(destination)) throw new InvalidDataException();
            if (!File.Exists(path)) continue;
            RejectLinks(path); AssertSingleLink(path);
            await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
            if (source.Length > BackupArchive.MaximumPayloadBytes) throw new InvalidDataException();
            var security = ReadSecurity(path);
            if (OperatingSystem.IsWindows() && security is not null) ValidateSecurity(security);
            originals.Add(new(suffix, source.Length, Convert.ToHexStringLower(await SHA256.HashDataAsync(source, cancellationToken)), security));
        }
        return originals;
    }
    private static async Task CopyOriginalsAsync(string database, string root, IReadOnlyList<OriginalFile> originals,
        CancellationToken cancellationToken)
    {
        foreach (var original in originals)
        {
            var path = database + original.Suffix;
            RejectLinks(path); AssertSingleLink(path);
            await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
            if (source.Length != original.Size) throw new InvalidDataException();
            await using (var target = BackupStorage.CreateFile(Path.Combine(root, OldName + original.Suffix)))
            {
                await source.CopyToAsync(target, cancellationToken); target.Flush(flushToDisk: true);
            }
            await AssertFileHashAsync(Path.Combine(root, OldName + original.Suffix), original.Sha256, cancellationToken);
        }
    }
    private static async Task RollbackAsync(BackupRestoreEnvironment environment, string journalPath,
        RecoveryJournal journal, CancellationToken cancellationToken)
    {
        var root = Path.GetDirectoryName(journalPath)!; var database = Path.Combine(environment.DataDirectory, DatabaseName);
        if (journal.Phase == "capturing")
        {
            // Destination data has not been touched in this phase. Incomplete safety copies may be discarded
            // only after proving that every original destination byte is still present.
            foreach (var suffix in Sidecars)
            {
                var original = journal.Originals.SingleOrDefault(item => item.Suffix == suffix);
                if (original is null)
                {
                    if (File.Exists(database + suffix)) throw new InvalidDataException();
                }
                else await AssertFileHashAsync(database + suffix, original.Sha256, cancellationToken);
            }
            WriteJournal(journalPath, journal with { Phase = "rolledBack" });
            environment.Checkpoint?.Invoke("rolledBack");
            CleanupCommitted(root, journalPath, journal);
            return;
        }
        foreach (var original in journal.Originals)
            await AssertFileHashAsync(Path.Combine(root, OldName + original.Suffix), original.Sha256, cancellationToken);
        WriteJournal(journalPath, journal with { Phase = "rollbackPrepared" });
        SqliteConnection.ClearAllPools();
        foreach (var suffix in Sidecars)
        {
            var target = database + suffix;
            RejectLinks(target);
            if (File.Exists(target)) { AssertSingleLink(target); File.Delete(target); }
        }
        foreach (var original in journal.Originals)
        {
            var target = database + original.Suffix;
            // Keep the safety copies until every file has been restored, so interruption is retryable.
            await using (var source = OpenRead(Path.Combine(root, OldName + original.Suffix), BackupArchive.MaximumPayloadBytes, allowEmpty: true))
            await using (var destination = BackupStorage.CreateFile(target))
            {
                await source.CopyToAsync(destination, cancellationToken); destination.Flush(flushToDisk: true);
            }
            ApplySecurity(target, original.Security);
        }
        if (!journal.OriginalAnchorExists && journal.Preview.Mode == BackupRecoveryContract.Migration &&
            File.Exists(Path.Combine(root, "backup-identity.json")))
        {
            var anchor = Path.Combine(root, "backup-identity.json");
            RejectLinks(anchor); AssertSingleLink(anchor);
            if (journal.NewAnchorSha256 is { } anchorHash) await AssertFileHashAsync(anchor, anchorHash, cancellationToken);
            else
            {
                // The process may have ended immediately after publishing the new anchor, before recording its hash.
                // Migration was allowed only when the destination had no anchor; reject unrelated identity metadata.
                using var source = OpenRead(anchor, 8192); using var document = JsonDocument.Parse(source);
                if (document.RootElement.GetProperty("CoreInstallationId").GetGuid() != journal.Preview.CoreInstallationId ||
                    document.RootElement.GetProperty("OrganizationId").GetGuid() != journal.Preview.OrganizationId) throw new InvalidDataException();
            }
            File.Delete(anchor);
        }
        WriteJournal(journalPath, journal with { Phase = "rolledBack" });
        environment.Checkpoint?.Invoke("rolledBack");
        CleanupCommitted(root, journalPath, journal);
    }

    private static void CleanupCommitted(string root, string journalPath, RecoveryJournal journal)
    {
        foreach (var original in journal.Originals)
        {
            var path = Path.Combine(root, OldName + original.Suffix);
            if (!File.Exists(path)) continue;
            RejectLinks(path); AssertSingleLink(path); File.Delete(path);
        }
        File.Delete(journalPath);
    }
    private static RecoveryJournal? ReadJournal(string path)
    {
        if (!File.Exists(path)) return null;
        BackupStorage.AssertFile(path, 64 * 1024); AssertSingleLink(path);
        using var stream = OpenRead(path, 64 * 1024);
        var journal = JsonSerializer.Deserialize<RecoveryJournal>(stream, Json) ?? throw new InvalidDataException();
        if (journal.Version != 1 || journal.Phase is not ("capturing" or "prepared" or "applied" or "rollbackPrepared" or "committed" or "rolledBack") ||
            journal.Preview.ArchiveId == Guid.Empty || journal.Preview.CoreInstallationId == Guid.Empty || journal.Preview.OrganizationId == Guid.Empty ||
            journal.Preview.Mode is not (BackupRecoveryContract.SameMachine or BackupRecoveryContract.Migration) ||
            !HashText(journal.Preview.ArchiveSha256) || journal.Originals.Count > 4 ||
            journal.Originals.Select(item => item.Suffix).Distinct(StringComparer.Ordinal).Count() != journal.Originals.Count ||
            journal.Originals.Any(item => !Sidecars.Contains(item.Suffix, StringComparer.Ordinal) || item.Size < 0 ||
                item.Size > BackupArchive.MaximumPayloadBytes || !HashText(item.Sha256) || item.Security?.Length > 8192) ||
            journal.NewAnchorSha256 is { } anchor && !HashText(anchor)) throw new InvalidDataException();
        foreach (var original in journal.Originals)
            if (original.Security is not null && OperatingSystem.IsWindows()) ValidateSecurity(original.Security);
        return journal;
    }
    private static void WriteJournal(string path, RecoveryJournal journal)
    {
        RejectLinks(path); if (File.Exists(path)) AssertSingleLink(path);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = BackupStorage.CreateFile(temporary))
            {
                JsonSerializer.Serialize(stream, journal, Json); stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static SqliteConnection OpenDatabase(string path, bool writable) => new(new SqliteConnectionStringBuilder
    {
        DataSource = path, Mode = writable ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
        Pooling = false, DefaultTimeout = 1
    }.ToString());
    private static async Task<CoreBackupDatabaseInfo> ReadCurrentDatabaseInfoAsync(string path, CancellationToken cancellationToken)
    {
        RejectLinks(path); AssertSingleLink(path);
        await using var connection = OpenDatabase(path, writable: false); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        Guid core, organization;
        await using (var identity = connection.CreateCommand())
        {
            identity.Transaction = transaction;
            identity.CommandText = "SELECT CoreInstallationId,OrganizationId FROM CoreIdentity WHERE Singleton=1;";
            await using var reader = await identity.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken) || !Guid.TryParse(reader.GetString(0), out core) || core == Guid.Empty ||
                !Guid.TryParse(reader.GetString(1), out organization) || organization == Guid.Empty || await reader.ReadAsync(cancellationToken))
                throw new InvalidDataException();
        }
        int admins, endpoints;
        await using (var counts = connection.CreateCommand())
        {
            counts.Transaction = transaction;
            counts.CommandText = "SELECT (SELECT COUNT(*) FROM Administrators),(SELECT COUNT(*) FROM EndpointEnrollments);";
            await using var reader = await counts.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) throw new InvalidDataException();
            admins = checked((int)reader.GetInt64(0)); endpoints = checked((int)reader.GetInt64(1));
            if (admins is < 1 or > 10_000 || endpoints is < 0 or > 1_000_000) throw new InvalidDataException();
        }
        transaction.Commit();
        // Full structural/integrity verification belongs to isolated snapshot databases. A running Core may
        // hold writable SQLite handles, so the live confirmation deliberately uses SQLite's read transaction.
        return new(core, organization, admins, endpoints, string.Empty);
    }
    private static FileStream OpenRead(string path, long maximum, bool allowEmpty = false)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException();
        RejectLinks(path);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length < 0 || !allowEmpty && stream.Length == 0 || stream.Length > maximum) { stream.Dispose(); throw new InvalidDataException(); }
        return stream;
    }
    private static async Task<byte[]> ReadSmallFileAsync(string path, int maximum, CancellationToken cancellationToken)
    {
        await using var source = OpenRead(path, maximum);
        var bytes = new byte[checked((int)source.Length)]; await source.ReadExactlyAsync(bytes, cancellationToken);
        if (source.ReadByte() != -1) { CryptographicOperations.ZeroMemory(bytes); throw new InvalidDataException(); }
        return bytes;
    }
    private static async Task<string> HashFileAsync(string path, long maximum, CancellationToken cancellationToken)
    {
        await using var stream = OpenRead(path, maximum, allowEmpty: true);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
    }
    private static async Task AssertFileHashAsync(string path, string hash, CancellationToken cancellationToken)
    {
        if (await HashFileAsync(path, BackupArchive.MaximumPayloadBytes, cancellationToken) != hash) throw new InvalidDataException();
    }
    private static bool HashText(string? value) => value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static void RejectLinks(string path) => PilotHostConfiguration.RejectLinks(Path.GetFullPath(path));
    private static void SetPrivateUnix(string path)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private static string? ReadSecurity(string path) => OperatingSystem.IsWindows()
        ? new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group)
            .GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group) : null;
    private static void ApplySecurity(string path, string? descriptor)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (descriptor is null)
        {
            // A missing original DB has no ACL to preserve. Set the same narrowly scoped mutable-data ACL
            // explicitly instead of relying on inherited staging-directory permissions surviving a move.
            var created = new FileSecurity(); created.SetAccessRuleProtection(true, false);
            created.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
            foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
                created.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, AccessControlType.Allow));
            created.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(CoreSid), FileSystemRights.Modify, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(created);
            return;
        }
        ValidateSecurity(descriptor);
        var security = new FileSecurity(); security.SetSecurityDescriptorSddlForm(descriptor);
        new FileInfo(path).SetAccessControl(security);
    }
    [SupportedOSPlatform("windows")]
    private static void ValidateSecurity(string descriptor)
    {
        var raw = new RawSecurityDescriptor(descriptor);
        if (raw.DiscretionaryAcl is null || (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || raw.Owner is null)
            throw new InvalidDataException();
        var writers = new HashSet<string>(StringComparer.Ordinal)
        { "S-1-5-18", "S-1-5-32-544", CoreSid, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
        if (!writers.Contains(raw.Owner.Value)) throw new InvalidDataException();
        var security = new FileSecurity(); security.SetSecurityDescriptorSddlForm(descriptor);
        var unsafeRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                ((rule.FileSystemRights & unsafeRights) != 0 || (unchecked((uint)rule.FileSystemRights) & 0x50000000U) != 0) &&
                !writers.Contains(((SecurityIdentifier)rule.IdentityReference).Value))
                throw new InvalidDataException();
    }
    private static void AssertSingleLink(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out var info) || info.NumberOfLinks != 1) throw new InvalidDataException();
    }

    internal static async Task<byte[]> ReadInputAsync(Stream input, CancellationToken cancellationToken)
    {
        var bytes = new byte[BackupRecoveryContract.MaximumInputBytes + 1];
        var count = 0;
        try
        {
            while (count < bytes.Length)
            {
                var read = await input.ReadAsync(bytes.AsMemory(count), cancellationToken); if (read == 0) break; count += read;
            }
            if (count is 0 or > BackupRecoveryContract.MaximumInputBytes) throw new InvalidDataException();
            _ = new UTF8Encoding(false, true).GetCharCount(bytes, 0, count);
            return bytes.AsSpan(0, count).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static BackupRecoveryRequest ReadRequest(ReadOnlyMemory<byte> bytes)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
            if (property.Name is not ("operation" or "archivePath" or "recoveryKeyPath" or "passphrase" or "mode" or "confirmedArchiveId" or
                "expectedArchiveSha256" or "confirmation") || !names.Add(property.Name)) throw new InvalidDataException();
        var request = JsonSerializer.Deserialize<BackupRecoveryRequest>(bytes.Span, Json) ?? throw new InvalidDataException();
        ValidateRequest(request); return request;
    }
    private static void ValidateRequest(BackupRecoveryRequest request)
    {
        if (request.Operation is not (BackupRecoveryContract.Status or BackupRecoveryContract.Preview or BackupRecoveryContract.Restore or
                BackupRecoveryContract.Rollback or BackupRecoveryContract.Commit) ||
            request.Mode is not (BackupRecoveryContract.SameMachine or BackupRecoveryContract.Migration)) throw new InvalidDataException();
        if (request.Operation is BackupRecoveryContract.Preview or BackupRecoveryContract.Restore)
        {
            if (request.ArchivePath is not { Length: > 0 and <= 4096 } || !Path.IsPathFullyQualified(request.ArchivePath) ||
                request.RecoveryKeyPath is not { Length: > 0 and <= 4096 } || !Path.IsPathFullyQualified(request.RecoveryKeyPath) ||
                request.Passphrase is not { Length: >= 12 and <= 1024 }) throw new InvalidDataException();
        }
        else if (request.ArchivePath is not null || request.RecoveryKeyPath is not null || request.Passphrase is not null)
            throw new InvalidDataException();
        if (request.ExpectedArchiveSha256 is not null && !HashText(request.ExpectedArchiveSha256)) throw new InvalidDataException();
    }

    [SupportedOSPlatform("windows")]
    private static BackupRestoreEnvironment CreateInstalledEnvironment(string configurationPath)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new UnauthorizedAccessException();
        if (!Path.IsPathFullyQualified(configurationPath) || Path.GetFileName(configurationPath) != "pilot-config.json" ||
            Environment.ProcessPath is not { } executable || Path.GetFileName(executable) != "SentinelAI.Core.exe")
            throw new InvalidDataException();
        configurationPath = Path.GetFullPath(configurationPath);
        var data = Path.GetDirectoryName(configurationPath)!;
        var code = Path.GetDirectoryName(executable)!;
        var protectedDataRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var protectedCodeRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        // Custom managed acceptance/pilot installs are supported only inside the same protected system roots.
        // The actual registered service, receipt hashes and ACLs below must bind these exact paths.
        if (!data.StartsWith(protectedDataRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !(code.StartsWith(protectedCodeRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
              code.StartsWith(protectedDataRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) ||
            data.StartsWith(code + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            code.StartsWith(data + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
        foreach (var path in new[] { data, code })
        {
            var drive = new DriveInfo(Path.GetPathRoot(path)!);
            if (!drive.IsReady || drive.DriveType != DriveType.Fixed || drive.DriveFormat != "NTFS") throw new InvalidDataException();
        }
        ValidateProtectedPath(configurationPath, data, serviceLeaf: false);
        ValidateProtectedPath(executable, data, serviceLeaf: false);
        var receiptPath = Path.Combine(data, "core-service-installation.json");
        ValidateProtectedPath(receiptPath, data, serviceLeaf: false);
        using var receiptFile = OpenRead(receiptPath, 4096);
        using var receipt = JsonDocument.Parse(receiptFile, new JsonDocumentOptions { MaxDepth = 2 });
        var proof = receipt.RootElement;
        if (proof.GetProperty("format").GetString() != "sentinelai-core-service-v1" ||
            proof.GetProperty("serviceName").GetString() != "SentinelAICore" ||
            proof.GetProperty("serviceAccount").GetString() != "NT SERVICE\\SentinelAICore" ||
            proof.GetProperty("serviceAccountSid").GetString() != CoreSid ||
            !string.Equals(proof.GetProperty("codeDirectory").GetString(), code, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(proof.GetProperty("dataDirectory").GetString(), data, StringComparison.OrdinalIgnoreCase) ||
            proof.GetProperty("configurationSha256").GetString() != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(configurationPath))) ||
            proof.GetProperty("executableSha256").GetString() != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))))
            throw new InvalidDataException();
        var configuration = PilotHostConfiguration.Read(["--config", configurationPath], agent: false);
        if (configuration.Values is null || !configuration.Values.TryGetValue("SentinelAI:DataDirectory", out var configuredData) ||
            !string.Equals(Path.GetFullPath(configuredData!), data, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
        ValidateProtectedPath(Path.Combine(data, "backups"), data, serviceLeaf: true);
        // Querying registration also verifies that the fixed service belongs to this executable/configuration.
        _ = ReadServiceState(executable, configurationPath);
        configuration.Values.TryGetValue("SentinelAI:LocalNetworkCertificateSha256", out var pin);
        return new(data, () => ReadServiceState(executable, configurationPath), new WindowsBackupKeyProtection(),
            LocalNetworkCertificateSha256: pin);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateProtectedPath(string path, string dataDirectory, bool serviceLeaf)
    {
        RejectLinks(path);
        var writers = new HashSet<string>(StringComparer.Ordinal)
        { "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
        for (var current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            var attributes = File.GetAttributes(current); var directory = (attributes & FileAttributes.Directory) != 0;
            if (!directory) AssertSingleLink(current);
            FileSystemSecurity security = directory
                ? new DirectoryInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var ancestor = !string.Equals(current, path, StringComparison.OrdinalIgnoreCase);
            var service = (ancestor || serviceLeaf) && (string.Equals(current, dataDirectory, StringComparison.OrdinalIgnoreCase) ||
                current.StartsWith(dataDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
            var owner = (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
            if (owner is null || !writers.Contains(owner) && !(service && owner == CoreSid)) throw new InvalidDataException();
            var unsafeRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            if (ancestor && directory) unsafeRights &= ~FileSystemRights.AppendData;
            if (ancestor && string.Equals(current, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase))
                unsafeRights &= ~FileSystemRights.Write;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                    ((rule.FileSystemRights & unsafeRights) != 0 || (unchecked((uint)rule.FileSystemRights) & 0x50000000U) != 0) &&
                    !writers.Contains(((SecurityIdentifier)rule.IdentityReference).Value) &&
                    !(service && ((SecurityIdentifier)rule.IdentityReference).Value == CoreSid)) throw new InvalidDataException();
        }
    }

    [SupportedOSPlatform("windows")]
    private static RecoveryServiceState ReadServiceState(string executable, string configuration)
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new InvalidDataException();
        try
        {
            var service = OpenService(manager, "SentinelAICore", 5);
            if (service == IntPtr.Zero) throw new InvalidDataException();
            try
            {
                _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var needed);
                if (needed is < 1 or > 16384) throw new InvalidDataException();
                var bytes = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!QueryServiceConfig(service, bytes, needed, out _)) throw new InvalidDataException();
                    var config = Marshal.PtrToStructure<ServiceConfiguration>(bytes);
                    if (!string.Equals(Marshal.PtrToStringUni(config.BinaryPath), $"\"{executable}\" --config \"{configuration}\"", StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(Marshal.PtrToStringUni(config.Account), "NT SERVICE\\SentinelAICore", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException();
                }
                finally { Marshal.FreeHGlobal(bytes); }
                if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _)) throw new InvalidDataException();
                if (status.State == 4 && status.ProcessId != 0) return RecoveryServiceState.Running;
                if (status.State != 1 || status.ProcessId != 0) return RecoveryServiceState.Unavailable;
                foreach (var process in Process.GetProcessesByName("SentinelAI.Core"))
                {
                    using (process)
                        if (process.Id != Environment.ProcessId && string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase))
                            return RecoveryServiceState.Unavailable;
                }
                return RecoveryServiceState.Stopped;
            }
            finally { _ = CloseServiceHandle(service); }
        }
        finally { _ = CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct NativeTime { public uint Low, High; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    { public uint Attributes; public NativeTime Creation, Access, Write; public uint Volume, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    { public uint Type, State, Accepted, Win32Exit, ServiceExit, CheckPoint, WaitHint, ProcessId, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfiguration
    { public uint Type, StartType, ErrorControl; public IntPtr BinaryPath, LoadGroup; public uint Tag; public IntPtr Dependencies, Account, DisplayName; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(IntPtr service, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
}
