using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Core.Recovery;

internal static class BackupDatabaseTests
{
    internal static async Task RunAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentinelai-backup-database-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var snapshot = Path.Combine(root, "snapshot.db");
        var checks = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
            checks++;
        }
        async Task RejectedAsync(string path)
        {
            try
            {
                await CoreBackupDatabase.InspectAsync(path);
                throw new InvalidOperationException("An unsupported backup database was accepted.");
            }
            catch (InvalidDataException) { checks++; }
        }

        try
        {
            CoreIdentity identity;
            await using (var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + Path.Combine(root, "live")],
                             configureBuilder: builder => builder.Logging.ClearProviders()))
            {
                app.Urls.Clear(); app.Urls.Add("http://127.0.0.1:0");
                await app.StartAsync();
                var store = app.Services.GetRequiredService<EnrollmentStore>();
                identity = await store.GetCoreIdentityAsync();
                await using var source = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath,
                    Mode = SqliteOpenMode.ReadOnly, Pooling = false
                }.ToString());
                await source.OpenAsync();
                await using var target = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = snapshot, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false
                }.ToString());
                await target.OpenAsync();
                source.BackupDatabase(target);
                await app.StopAsync();
            }
            var original = SHA256.HashData(await File.ReadAllBytesAsync(snapshot));
            var info = await CoreBackupDatabase.InspectAsync(snapshot);
            var repeated = await CoreBackupDatabase.InspectAsync(snapshot);
            Check(info == repeated && info.CoreInstallationId == identity.CoreInstallationId &&
                  info.OrganizationId == identity.OrganizationId && info.AdministratorCount == 1 && info.EndpointCount == 0 &&
                  info.SchemaFingerprint.Length == 64, "Backup inspection changed identity, counts or deterministic schema fingerprint.");
            var afterInspection = await File.ReadAllBytesAsync(snapshot);
            Check(original.AsSpan().SequenceEqual(SHA256.HashData(afterInspection)),
                "Read-only backup inspection modified the database.");
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                try { await CoreBackupDatabase.InspectAsync(snapshot, cancelled.Token); throw new InvalidOperationException("Backup inspection ignored cancellation."); }
                catch (OperationCanceledException) { checks++; }
            }
            foreach (var sql in new[]
                     {
                         "DELETE FROM Administrators;",
                         "UPDATE CoreIdentity SET CoreInstallationId='00000000-0000-0000-0000-000000000000';",
                         "DROP TABLE EndpointSecurityTelemetry;",
                         "CREATE TRIGGER UnreviewedMutation AFTER INSERT ON Devices BEGIN DELETE FROM Administrators; END;",
                         "CREATE/**/VIRTUAL/**/TABLE UnreviewedSearch USING fts5(value);",
                         "CREATE TABLE Parent(id INTEGER PRIMARY KEY); CREATE TABLE Child(id INTEGER REFERENCES Parent(id)); INSERT INTO Child VALUES(99);"
                     })
            {
                var damaged = Path.Combine(root, "damaged.db");
                File.Copy(snapshot, damaged, overwrite: true);
                await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                                 { DataSource = damaged, Mode = SqliteOpenMode.ReadWrite, Pooling = false, ForeignKeys = false }.ToString()))
                {
                    await connection.OpenAsync();
                    await using var command = connection.CreateCommand(); command.CommandText = sql;
                    await command.ExecuteNonQueryAsync();
                }
                await RejectedAsync(damaged);
                File.Delete(damaged);
            }
            var text = Path.Combine(root, "text.db");
            await File.WriteAllTextAsync(text, new string('x', 1024));
            await RejectedAsync(text);
            await RejectedAsync(Path.Combine(root, "missing.db"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
        Console.WriteLine($"Backup database tests passed ({checks} checks: consistent snapshot, identity, readonly verification, cancellation and rejected unsafe state).");
    }
}
