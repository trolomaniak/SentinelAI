using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Backups;
using SentinelAI.Core.Persistence;
using SentinelAI.Core.Recovery;

internal static class BackupRestoreTests
{
    private const string Password = "Synthetic-Backup-Recovery-Only!";
    private static int _checks;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    internal static async Task RunAsync()
    {
        _checks = 0;
        var root = Path.Combine(Path.GetTempPath(), "sentinelai-restore-tests-" + Guid.NewGuid().ToString("N"));
        BackupStorage.CreatePrivateDirectory(root);
        var originalUser = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", "synthetic-recovery-admin");
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", Password);
            var source = await CreateDatabaseAsync(Path.Combine(root, "source"), endpoints: 2);
            var snapshot = Path.Combine(root, "snapshot.db");
            File.Copy(source.Database, snapshot); Private(snapshot);
            var archive = await CreateArchiveAsync(root, "point", snapshot, key);
            var keyFile = Path.Combine(root, "recovery.sak");
            await File.WriteAllBytesAsync(keyFile, RecoveryKeyFile.Create(key, Password)); Private(keyFile);
            await VerifyProtocolAsync();
            await VerifyRestoreRollbackAndCommitAsync(root, snapshot, archive, keyFile, key, source);
            foreach (var phase in new[] { "capturing", "captured", "prepared", "databaseReplaced", "applied" })
                await VerifyInterruptedAsync(root, snapshot, archive, keyFile, key, phase);
            await VerifyTerminalCleanupAsync(root, snapshot, archive, keyFile, key);
            await VerifyCorruptAndMissingAsync(root, snapshot, archive, keyFile, key);
            await VerifyPartialCorruptionAsync(root, snapshot, archive, keyFile, key, source);
            VerifyGenericAclRights();
            await VerifyMigrationAsync(root, snapshot, archive, keyFile, key);
            await VerifyRejectionsAsync(root, snapshot, archive, keyFile, key);
            Console.WriteLine($"Backup restore tests passed ({_checks} assertions: verified point, rollback/commit, durable crash phases, revocations/clock floor, migration, corrupt/missing DB, secret and input guards).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUser);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task VerifyProtocolAsync()
    {
        Check(!new BackupRecoveryRequest("preview", Passphrase: Password).ToString().Contains(Password, StringComparison.Ordinal),
            "Recovery request text disclosed a passphrase.");
        foreach (var text in new[] { "{}", "{\"operation\":\"status\",\"operation\":\"status\"}",
                     "{\"operation\":\"status\",\"extra\":1}", "{\"operation\":\"restore\"}",
                     "{\"operation\":\"status\",\"passphrase\":\"secret\"}" })
            await RejectAsync(() => Task.FromResult(BackupRestoreCommand.ReadRequest(Encoding.UTF8.GetBytes(text))),
                "Recovery accepted an ambiguous or malformed local input.");
        await RejectAsync(async () => await BackupRestoreCommand.ReadInputAsync(
            new MemoryStream(new byte[BackupRecoveryContract.MaximumInputBytes + 1]), default), "Recovery accepted an oversized request.");
        using var output = new StringWriter();
        var exit = await BackupRestoreCommand.RunAsync([BackupRecoveryContract.Command, "--config", "not-an-installed-config"],
            new MemoryStream(Encoding.UTF8.GetBytes(Password)), output, isWindowsService: true, isInputRedirected: true);
        Check(exit != 0 && !output.ToString().Contains(Password, StringComparison.Ordinal), "Recovery service context exposed input or succeeded.");
    }

    private static async Task VerifyRestoreRollbackAndCommitAsync(string root, string snapshot, Archive archive,
        string keyFile, byte[] key, Fixture source)
    {
        var data = Clone(root, "same", snapshot, source.Identity, key);
        await SqlAsync(data, "INSERT INTO Administrators VALUES('after-snapshot','synthetic-test-hash');");
        var future = DateTimeOffset.UtcNow.AddDays(3).UtcTicks;
        await SqlAsync(data, "INSERT OR IGNORE INTO LicenseState(Singleton,HighWaterUtcTicks,LastAttemptSucceeded,ClockRollbackDetected) VALUES(1,1,0,0);" +
            $"UPDATE LicenseState SET HighWaterUtcTicks={future},ClockRollbackDetected=1;" +
            $"UPDATE EndpointEnrollments SET RemovedUtcTicks={DateTimeOffset.UtcNow.UtcTicks} WHERE InstallationId='{source.Endpoints[1].InstallationId:D}';");
        var newer = await CreateArchiveAsync(root, "newer-retained", data, key);
        await AddRetainedArchiveAsync(data, archive, key);
        await AddRetainedArchiveAsync(data, newer, key);
        var state = RecoveryServiceState.Running;
        var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => state, new TestProtection());
        var request = Preview(archive, keyFile);
        var result = await BackupRestoreCommand.ExecuteAsync(request, environment);
        Check(result.Outcome == "verified" && result.Preview?.AdministratorCount == 1, "Preview did not validate isolated archive data while Core was running.");
        Check(await CountAsync(data, "Administrators") == 2, "Preview changed the live administrator database.");
        var apply = Apply(request, result.Preview!);
        Check((await BackupRestoreCommand.ExecuteAsync(apply, environment)).Outcome == "serviceRunning", "Restore replaced data while Core was running.");
        state = RecoveryServiceState.Stopped;
        Check((await BackupRestoreCommand.ExecuteAsync(apply with { Confirmation = "wrong" }, environment)).Outcome == "rejected",
            "Restore skipped explicit confirmation.");
        var restored = await BackupRestoreCommand.ExecuteAsync(apply, environment);
        Check(restored.Outcome == "restored" && restored.PendingArchiveId == archive.Id, "Confirmed restore did not leave a recoverable pending transaction.");
        Check(await CountAsync(data, "Administrators") == 1 && await ScalarAsync(data, "SELECT Enabled FROM BackupSettings WHERE Singleton=1;") == 0,
            "Restore did not restore business data and disable its schedule.");
        Check(await ScalarAsync(data, "SELECT HighWaterUtcTicks FROM LicenseState WHERE Singleton=1;") >= future &&
              await ScalarAsync(data, "SELECT ClockRollbackDetected FROM LicenseState WHERE Singleton=1;") == 1,
            "Restore erased the license clock floor or an already detected rollback.");
        Check(await ScalarAsync(data, $"SELECT RemovedUtcTicks IS NOT NULL FROM EndpointEnrollments WHERE InstallationId='{source.Endpoints[1].InstallationId:D}';") == 1,
            "Restore re-enabled an Agent credential revoked after the snapshot.");
        Check(await ScalarAsync(data, "SELECT COUNT(*) FROM EnrollmentTokens WHERE ConsumedUtcTicks IS NULL AND RevokedUtcTicks IS NULL;") == 0,
            "Restore revived unused enrollment codes.");
        Check(await CountAsync(data, "BackupArchives") == 2,
            "Restoring old business data rolled back the current machine's retained backup catalog.");
        BackupRestoreCommand.AssertHostStartupAllowedAt(environment.DataDirectory);
        var pending = await BackupRestoreCommand.ExecuteAsync(new("status"), environment);
        Check(pending.Outcome == "pending" && pending.PendingArchiveId == archive.Id, "Interrupted recovery could not be discovered without a passphrase.");
        await BackupRestoreCommand.ExecuteAsync(new("rollback", ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), environment);
        Check(await CountAsync(data, "Administrators") == 2 && !File.Exists(Path.Combine(environment.DataDirectory, "backups", "restore-journal.json")),
            "Rollback lost the original database or journal cleanup.");

        var second = await BackupRestoreCommand.ExecuteAsync(apply, environment);
        Check(second.Outcome == "restored", "Restore could not run after a successful rollback.");
        // A real live Core retains writable SQLite handles. Commit must use a SQLite read transaction,
        // rather than opening the live database as an isolated file with restrictive sharing.
        await using var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + environment.DataDirectory],
            configureBuilder: builder => { builder.Logging.ClearProviders(); builder.Services.AddSingleton<IBackupKeyProtection>(new TestProtection()); });
        app.Urls.Clear(); app.Urls.Add("http://127.0.0.1:0"); await app.StartAsync(); state = RecoveryServiceState.Running;
        var committed = await BackupRestoreCommand.ExecuteAsync(new("commit", ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), environment);
        Check(committed.Outcome == "committed", "Healthy live Core identity could not commit restored data.");
        var backups = app.Services.GetRequiredService<BackupService>();
        Check((await backups.StartJobAsync(null, default)).Outcome == BackupMutationOutcome.Accepted,
            "A backup could not be queued after restoring an older point.");
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
        {
            BackupStatus status;
            do { await Task.Delay(20, deadline.Token); status = await backups.GetStatusAsync(deadline.Token); } while (status.Busy);
            Check(status.LastAttempt?.Outcome == "succeeded" && status.Archives.Count == 3 &&
                  status.Archives.Any(item => item.ArchiveId == archive.Id) && status.Archives.Any(item => item.ArchiveId == newer.Id),
                "Creating a backup after restore lost newer retained archives or failed on their catalog entries.");
        }
        await app.StopAsync(); state = RecoveryServiceState.Stopped;
        Check((await BackupRestoreCommand.ExecuteAsync(new("status"), environment)).Outcome == "ready", "Committed recovery still appeared pending.");
    }

    private static async Task VerifyTerminalCleanupAsync(string root, string snapshot, Archive archive, string keyFile, byte[] key)
    {
        foreach (var phase in new[] { "committed", "rolledBack" })
        {
            var data = Clone(root, "terminal-" + phase, snapshot, await IdentityAsync(snapshot), key);
            await SqlAsync(data, "INSERT INTO Administrators VALUES('after-snapshot','synthetic-test-hash');");
            var state = RecoveryServiceState.Stopped;
            var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => state, new TestProtection());
            var preview = await BackupRestoreCommand.ExecuteAsync(Preview(archive, keyFile), environment);
            await BackupRestoreCommand.ExecuteAsync(Apply(Preview(archive, keyFile), preview.Preview!), environment);
            var faulting = environment with { Checkpoint = point => { if (point == phase) throw new IOException("Synthetic cleanup interruption."); } };
            if (phase == "committed") state = RecoveryServiceState.Running;
            await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(new(phase == "committed" ? "commit" : "rollback",
                    ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), faulting), "Terminal cleanup fault was not exercised.");
            // Emulate a process exit after cleanup has already removed one of several safety files.
            File.Delete(Path.Combine(environment.DataDirectory, "backups", "restore-old.db"));
            var completed = await BackupRestoreCommand.ExecuteAsync(new("status"), environment);
            Check(completed.Outcome == phase && (await BackupRestoreCommand.ExecuteAsync(new("status"), environment)).Outcome == "ready",
                "A committed/rolled-back restore could not finish interrupted cleanup.");
            Check(await CountAsync(data, "Administrators") == (phase == "committed" ? 1 : 2), "Retrying terminal cleanup changed the selected database point.");
        }
    }

    private static async Task VerifyInterruptedAsync(string root, string snapshot, Archive archive, string keyFile, byte[] key, string phase)
    {
        var identity = await IdentityAsync(snapshot);
        var data = Clone(root, "crash-" + phase, snapshot, identity, key);
        await SqlAsync(data, "INSERT INTO Administrators VALUES('after-snapshot','synthetic-test-hash');");
        var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => RecoveryServiceState.Stopped,
            new TestProtection(), point => { if (point == phase) throw new IOException("Synthetic interruption."); });
        var preview = await BackupRestoreCommand.ExecuteAsync(Preview(archive, keyFile), environment);
        await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(Apply(Preview(archive, keyFile), preview.Preview!), environment),
            "The synthetic recovery interruption was ignored.");
        var recovering = environment with { Checkpoint = null };
        Check((await BackupRestoreCommand.ExecuteAsync(new("status"), recovering)).Outcome == "pending", "An interrupted phase lost its durable journal: " + phase);
        if (phase != "applied")
            await RejectAsync(() => { BackupRestoreCommand.AssertHostStartupAllowedAt(environment.DataDirectory); return Task.CompletedTask; },
                "Core could start against an incomplete restore: " + phase);
        await BackupRestoreCommand.ExecuteAsync(new("rollback", ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), recovering);
        Check(await CountAsync(data, "Administrators") == 2 && (await BackupRestoreCommand.ExecuteAsync(new("status"), recovering)).Outcome == "ready",
            "Crash rollback did not recover the original data: " + phase);
    }

    private static async Task VerifyCorruptAndMissingAsync(string root, string snapshot, Archive archive, string keyFile, byte[] key)
    {
        foreach (var missing in new[] { false, true })
        {
            var data = Clone(root, missing ? "missing" : "corrupt", snapshot, await IdentityAsync(snapshot), key);
            if (missing) File.Delete(data); else await File.WriteAllBytesAsync(data, []);
            var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => RecoveryServiceState.Stopped, new TestProtection());
            var preview = await BackupRestoreCommand.ExecuteAsync(Preview(archive, keyFile), environment);
            Check(preview.Outcome == "verified", "Authenticated local anchor could not recover a corrupt/missing DB.");
            Check((await BackupRestoreCommand.ExecuteAsync(Apply(Preview(archive, keyFile), preview.Preview!), environment)).Outcome == "restored",
                "Restore could not replace a corrupt/missing DB.");
            await BackupRestoreCommand.ExecuteAsync(new("rollback", ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), environment);
            Check(missing ? !File.Exists(data) : new FileInfo(data).Length == 0, "Rollback did not retain the exact original corrupt/missing state.");
        }
    }

    private static async Task VerifyPartialCorruptionAsync(string root, string snapshot, Archive archive,
        string keyFile, byte[] key, Fixture source)
    {
        var scenario = 0;
        foreach (var damage in new[] { "DROP TABLE BackupArchives;", "ALTER TABLE BackupArchives DROP COLUMN Sha256;" })
        {
            var data = Clone(root, "partial-corruption-" + scenario++, snapshot, source.Identity, key);
            var floor = DateTimeOffset.UtcNow.AddDays(3).UtcTicks;
            await SqlAsync(data, "INSERT INTO Administrators VALUES('after-snapshot','synthetic-test-hash');" +
                "INSERT OR IGNORE INTO LicenseState(Singleton,HighWaterUtcTicks,LastAttemptSucceeded,ClockRollbackDetected) VALUES(1,1,0,0);" +
                $"UPDATE LicenseState SET HighWaterUtcTicks={floor},ClockRollbackDetected=1;" +
                $"UPDATE EndpointEnrollments SET RemovedUtcTicks=1 WHERE InstallationId='{source.Endpoints[0].InstallationId:D}';" + damage);
            var state = RecoveryServiceState.Stopped;
            var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => state, new TestProtection());
            var request = Preview(archive, keyFile);
            var preview = await BackupRestoreCommand.ExecuteAsync(request, environment);
            Check(preview.Outcome == "verified", "Partial catalog corruption prevented authenticated recovery preview.");
            var restored = await BackupRestoreCommand.ExecuteAsync(Apply(request, preview.Preview!), environment);
            Check(restored.Outcome == "restored" && await CountAsync(data, "Administrators") == 1,
                "Partial catalog corruption prevented restoration of the intact database point.");
            Check(await ScalarAsync(data, "SELECT HighWaterUtcTicks FROM LicenseState WHERE Singleton=1;") >= floor &&
                  await ScalarAsync(data, "SELECT ClockRollbackDetected FROM LicenseState WHERE Singleton=1;") == 1 &&
                  await ScalarAsync(data, $"SELECT COUNT(*) FROM EndpointEnrollments WHERE InstallationId='{source.Endpoints[0].InstallationId:D}' AND RemovedUtcTicks IS NOT NULL;") == 1,
                "Recovery of partial corruption discarded readable revocations or license-clock protections.");
            _ = await CoreBackupDatabase.InspectAsync(data);
            state = RecoveryServiceState.Running;
            Check((await BackupRestoreCommand.ExecuteAsync(new("commit", ConfirmedArchiveId: archive.Id, Confirmation: "RESTORE"), environment)).Outcome == "committed",
                "Recovery of partial corruption could not commit verified restored data.");
        }
    }

    private static void VerifyGenericAclRights()
    {
        if (!OperatingSystem.IsWindows()) return;
        var method = typeof(BackupRestoreCommand).GetMethod("ValidateSecurity",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        foreach (var access in new[] { "GA", "GW" })
        {
            try
            {
                method.Invoke(null, ["O:BAG:BAD:P(A;;" + access + ";;;BU)(A;;FA;;;BA)(A;;FA;;;SY)"]);
                throw new InvalidOperationException("Recovery accepted generic write/all access for ordinary users.");
            }
            catch (System.Reflection.TargetInvocationException error) when (error.InnerException is InvalidDataException)
            { _checks++; }
        }
    }

    private static async Task VerifyMigrationAsync(string root, string snapshot, Archive archive, string keyFile, byte[] key)
    {
        var target = await CreateDatabaseAsync(Path.Combine(root, "migration"), endpoints: 1);
        var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(target.Database)!, () => RecoveryServiceState.Stopped, new TestProtection());
        var request = Preview(archive, keyFile) with { Mode = "migration" };
        var preview = await BackupRestoreCommand.ExecuteAsync(request, environment);
        Check(preview.Outcome == "verified", "Fresh owned local migration target was refused.");
        var applied = await BackupRestoreCommand.ExecuteAsync(Apply(request, preview.Preview!) with { Confirmation = "MIGRATE" }, environment);
        Check(applied.Outcome == "restored", "Explicit migration did not restore the archive.");
        Check((await IdentityAsync(target.Database)) == await IdentityAsync(snapshot), "Migration did not retain the recovered organization/Core identity.");
        await using (var connection = Open(target.Database))
        {
            await connection.OpenAsync(); await using var query = connection.CreateCommand();
            query.CommandText = "SELECT CredentialHash,CoreInstallationId,OrganizationId FROM EndpointEnrollments WHERE InstallationId=$id AND RemovedUtcTicks IS NULL;";
            query.Parameters.AddWithValue("$id", target.Endpoints[0].InstallationId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync();
            var identity = await IdentityAsync(snapshot);
            Check(await reader.ReadAsync() && reader.GetString(1) == identity.CoreInstallationId.ToString("D") && reader.GetString(2) == identity.OrganizationId.ToString("D") &&
                CryptographicOperations.FixedTimeEquals((byte[])reader.GetValue(0), SHA256.HashData(Convert.FromHexString(target.Endpoints[0].AgentCredential))),
                "Migration lost the new central Agent credential or left it bound to the replaced identity.");
        }
        Check(await ScalarAsync(target.Database, "SELECT COUNT(*) FROM EndpointEnrollments WHERE RemovedUtcTicks IS NULL;") == 1,
            "Migration silently retained old remote credentials as active.");
        await BackupRestoreCommand.ExecuteAsync(new("rollback", ConfirmedArchiveId: archive.Id, Confirmation: "MIGRATE"), environment);
        Check((await IdentityAsync(target.Database)) == target.Identity && !File.Exists(Path.Combine(environment.DataDirectory, "backups", "backup-identity.json")),
            "Migration rollback did not restore the fresh destination identity and remove its new anchor.");

        // A restart between anchor publication and the journal's next write must remain reversible.
        var faulting = environment with { Checkpoint = point => { if (point == "anchorWritten") throw new IOException("Synthetic interruption."); } };
        var again = await BackupRestoreCommand.ExecuteAsync(request, faulting);
        await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(Apply(request, again.Preview!) with { Confirmation = "MIGRATE" }, faulting),
            "Migration anchor crash was not exercised.");
        await BackupRestoreCommand.ExecuteAsync(new("rollback", ConfirmedArchiveId: archive.Id, Confirmation: "MIGRATE"), environment);
        Check(!File.Exists(Path.Combine(environment.DataDirectory, "backups", "backup-identity.json")), "Interrupted migration left a foreign identity anchor after rollback.");
        // A one-device business installation is not necessarily a fresh destination.
        await SqlAsync(target.Database, $"INSERT INTO TrackedAlerts(AlertId,EndpointId,EndpointName,RuleId,Title,Severity,Status,FirstObservedUtcTicks,LastObservedUtcTicks,CreatedUtcTicks,UpdatedUtcTicks,StatusChangedUtcTicks,Version,Reason,EvidenceJson,RecommendedAction) VALUES('{Guid.NewGuid():D}','{target.Endpoints[0].EndpointId:D}','synthetic','test','synthetic','low','open',1,1,1,1,1,1,'test','[]','test');");
        Check((await BackupRestoreCommand.ExecuteAsync(request, environment)).Outcome == "identityMismatch",
            "Migration treated an established one-device database as a fresh destination.");
    }

    private static async Task VerifyRejectionsAsync(string root, string snapshot, Archive archive, string keyFile, byte[] key)
    {
        var data = Clone(root, "reject", snapshot, await IdentityAsync(snapshot), key);
        var environment = new BackupRestoreEnvironment(Path.GetDirectoryName(data)!, () => RecoveryServiceState.Stopped, new TestProtection());
        var original = await File.ReadAllBytesAsync(data);
        await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(Preview(archive, keyFile) with { Passphrase = "Wrong-test-password!" }, environment), "Wrong recovery password succeeded.");
        var changed = Path.Combine(root, "tampered.sab"); var bytes = await File.ReadAllBytesAsync(archive.Path); bytes[^1] ^= 1;
        await File.WriteAllBytesAsync(changed, bytes); Private(changed);
        await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(Preview(archive with { Path = changed }, keyFile), environment), "Tampered encrypted archive succeeded.");
        var other = await CreateDatabaseAsync(Path.Combine(root, "foreign"), endpoints: 0);
        BackupIdentityAnchor.Ensure(Path.Combine(Path.GetDirectoryName(other.Database)!, "backups"), other.Identity, key);
        var foreign = new BackupRestoreEnvironment(Path.GetDirectoryName(other.Database)!, () => RecoveryServiceState.Stopped, new TestProtection());
        Check((await BackupRestoreCommand.ExecuteAsync(Preview(archive, keyFile), foreign)).Outcome == "identityMismatch", "Foreign Core identity was accepted as same-machine recovery.");
        var afterRejectedRecovery = await File.ReadAllBytesAsync(data);
        Check(original.AsSpan().SequenceEqual(afterRejectedRecovery), "Rejected recovery modified the destination DB.");
        // A key-holder-created archive still must contain a structurally valid application database.
        var broken = Path.Combine(root, "foreign-key.db"); File.Copy(snapshot, broken); Private(broken);
        await SqlAsync(broken, "PRAGMA foreign_keys=OFF; INSERT INTO AlertStatusHistory(AlertId,Status,ChangedUtcTicks,ChangedBy) VALUES('missing-alert','open',1,'synthetic');");
        var bad = await CreateArchiveAsync(root, "foreign-key", broken, key);
        await RejectAsync(() => BackupRestoreCommand.ExecuteAsync(Preview(bad, keyFile), environment), "A foreign-key-damaged backup was accepted.");
    }

    private static async Task AddRetainedArchiveAsync(string database, Archive archive, byte[] key)
    {
        var path = Path.Combine(Path.GetDirectoryName(database)!, "backups", archive.Id.ToString("N") + ".sab");
        File.Copy(archive.Path, path); Private(path);
        await using var connection = Open(database); await connection.OpenAsync(); await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO BackupArchives(ArchiveId,CreatedUtcTicks,SizeBytes,Sha256,RecoveryKeyId,VerificationState,VerifiedUtcTicks) VALUES($id,$now,$size,$sha,$key,'verified',$now);";
        command.Parameters.AddWithValue("$id", archive.Id.ToString("D")); command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.UtcTicks);
        command.Parameters.AddWithValue("$size", new FileInfo(path).Length); command.Parameters.AddWithValue("$sha", Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(path))));
        command.Parameters.AddWithValue("$key", BackupArchive.KeyId(key)); await command.ExecuteNonQueryAsync();
    }

    private sealed record Fixture(string Database, CoreIdentity Identity, IReadOnlyList<EnrollmentResponse> Endpoints);
    private sealed record Archive(Guid Id, string Path);
    private static async Task<Fixture> CreateDatabaseAsync(string data, int endpoints)
    {
        await using var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + data],
            configureBuilder: builder => { builder.Logging.ClearProviders(); builder.Services.AddSingleton<IBackupKeyProtection>(new TestProtection()); });
        app.Urls.Clear(); app.Urls.Add("http://127.0.0.1:0"); await app.StartAsync();
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>(); var found = new List<EnrollmentResponse>();
        for (var index = 0; index < endpoints; index++)
        {
            var token = await enrollments.IssueTokenAsync();
            var result = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token), overLocalNetwork: index != 0);
            var item = result.Response ?? throw new InvalidOperationException("Synthetic enrollment failed."); found.Add(item);
            await app.Services.GetRequiredService<DeviceStore>().RecordEnrolledHeartbeatAsync(item.InstallationId);
        }
        _ = await enrollments.IssueTokenAsync();
        var identity = await enrollments.GetCoreIdentityAsync(); await app.StopAsync();
        var database = app.Services.GetRequiredService<AdminStore>().DatabasePath;
        BackupStorage.CreatePrivateDirectory(Path.Combine(data, "backups"));
        Private(database);
        return new(database, identity, found);
    }
    private static string Clone(string root, string name, string snapshot, CoreIdentity identity, byte[] key)
    {
        var directory = Path.Combine(root, name); BackupStorage.CreatePrivateDirectory(directory);
        var database = Path.Combine(directory, "sentinelai.db"); File.Copy(snapshot, database); Private(database);
        var backups = Path.Combine(directory, "backups"); BackupStorage.CreatePrivateDirectory(backups); BackupIdentityAnchor.Ensure(backups, identity, key);
        return database;
    }
    private static async Task<Archive> CreateArchiveAsync(string root, string name, string database, byte[] key)
    {
        var identity = await IdentityAsync(database); var id = Guid.NewGuid();
        var configuration = Encoding.UTF8.GetBytes("{\"format\":\"sentinelai-core-configuration-reference-v1\",\"loopbackOrigin\":null,\"localNetworkPort\":null,\"localNetworkCertificateSha256\":null}");
        var manifest = new BackupManifest(1, id, DateTimeOffset.UtcNow, identity.CoreInstallationId, identity.OrganizationId, "1.0.0",
            BackupArchive.KeyId(key), new FileInfo(database).Length, Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(database))),
            Convert.ToHexStringLower(SHA256.HashData(configuration)));
        var payload = Path.Combine(root, name + ".payload");
        await using (var output = File.Create(payload)) await BackupPackage.CreateAsync(output, database, manifest, configuration);
        Private(payload);
        var archive = Path.Combine(root, name + ".sab");
        await using (var input = File.OpenRead(payload)) await using (var output = File.Create(archive))
            await BackupArchive.EncryptAsync(input, output, key);
        Private(archive); File.Delete(payload); return new(id, archive);
    }
    private static BackupRecoveryRequest Preview(Archive archive, string keyFile) => new("preview", archive.Path, keyFile, Password);
    private static BackupRecoveryRequest Apply(BackupRecoveryRequest preview, BackupRecoveryPreview verified) => preview with
    { Operation = "restore", ConfirmedArchiveId = verified.ArchiveId, ExpectedArchiveSha256 = verified.ArchiveSha256, Confirmation = "RESTORE" };
    private static async Task<CoreIdentity> IdentityAsync(string database)
    {
        await using var connection = Open(database); await connection.OpenAsync(); await using var command = connection.CreateCommand();
        command.CommandText = "SELECT CoreInstallationId,OrganizationId FROM CoreIdentity WHERE Singleton=1;";
        await using var reader = await command.ExecuteReaderAsync(); if (!await reader.ReadAsync()) throw new InvalidOperationException();
        return new(Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)));
    }
    private static async Task SqlAsync(string database, string sql)
    { await using var connection = Open(database); await connection.OpenAsync(); await using var command = connection.CreateCommand(); command.CommandText = sql; await command.ExecuteNonQueryAsync(); }
    private static async Task<long> ScalarAsync(string database, string sql)
    { await using var connection = Open(database); await connection.OpenAsync(); await using var command = connection.CreateCommand(); command.CommandText = sql; return Convert.ToInt64(await command.ExecuteScalarAsync()); }
    private static Task<long> CountAsync(string database, string table) => ScalarAsync(database, "SELECT COUNT(*) FROM " + table + ";");
    private static SqliteConnection Open(string database) => new(new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
    private static void Private(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return;
        }
        // Match installed mutable Core files. Runner-profile inheritance deliberately
        // does not satisfy production recovery's administrators/SYSTEM/service boundary.
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900"),
            FileSystemRights.Modify, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }
    private static void Check(bool condition, string message) { _checks++; if (!condition) throw new InvalidOperationException(message); }
    private static async Task RejectAsync(Func<Task> action, string message)
    {
        try { await action(); }
        catch (Exception exception) when (exception is InvalidDataException or IOException or CryptographicException or JsonException or InvalidOperationException or SqliteException or ArgumentException)
        { _checks++; return; }
        throw new InvalidOperationException(message);
    }
    private sealed class TestProtection : IBackupKeyProtection
    {
        public bool IsSupported => true;
        public byte[] Protect(ReadOnlySpan<byte> value) => value.ToArray().Select(item => (byte)(item ^ 0xA5)).ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> value) => Protect(value);
    }
}
