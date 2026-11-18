using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Backups;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core.Backups;

internal sealed record BackupStoredState(BackupPolicy Policy, byte[]? ProtectedKey, DateTimeOffset? NextDueUtc,
    DateTimeOffset? LastSuccessfulUtc, BackupAttempt? LastAttempt, IReadOnlyList<BackupArchiveSummary> Archives);

internal sealed class BackupStore(AdminStore admins, TimeProvider time)
{
    internal async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS BackupSettings (
                Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1), Version INTEGER NOT NULL,
                Enabled INTEGER NOT NULL, IntervalHours INTEGER NOT NULL, RetentionCount INTEGER NOT NULL,
                RecoveryKeyId TEXT, ProtectedKey BLOB, NextDueUtcTicks INTEGER, LastSuccessfulUtcTicks INTEGER);
            INSERT OR IGNORE INTO BackupSettings (Singleton,Version,Enabled,IntervalHours,RetentionCount)
                VALUES (1,0,0,24,7);
            CREATE TABLE IF NOT EXISTS BackupAttempts (
                OperationId TEXT PRIMARY KEY, Kind TEXT NOT NULL, Outcome TEXT NOT NULL,
                StartedUtcTicks INTEGER NOT NULL, CompletedUtcTicks INTEGER, ArchiveId TEXT);
            CREATE TABLE IF NOT EXISTS BackupArchives (
                ArchiveId TEXT PRIMARY KEY, CreatedUtcTicks INTEGER NOT NULL, SizeBytes INTEGER NOT NULL,
                Sha256 TEXT NOT NULL, RecoveryKeyId TEXT NOT NULL, VerificationState TEXT NOT NULL, VerifiedUtcTicks INTEGER);
            UPDATE BackupSettings SET NextDueUtcTicks=$now WHERE Enabled=1 AND EXISTS(SELECT 1 FROM BackupAttempts WHERE Outcome='inProgress');
            UPDATE BackupAttempts SET Outcome='interrupted', CompletedUtcTicks=$now WHERE Outcome='inProgress';
            """;
        command.Parameters.AddWithValue("$now", time.GetUtcNow().UtcTicks);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
    internal SqliteConnection OpenConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 5, Pooling = false
    }.ToString());
    internal async Task<BackupStoredState> ReadAsync(CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        BackupPolicy policy; byte[]? protectedKey; DateTimeOffset? next; DateTimeOffset? successful;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT Version,Enabled,IntervalHours,RetentionCount,RecoveryKeyId,ProtectedKey,NextDueUtcTicks,LastSuccessfulUtcTicks FROM BackupSettings WHERE Singleton=1;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) throw new InvalidDataException("Backup state is unavailable.");
            policy = new(reader.GetInt64(0), reader.GetBoolean(1), reader.GetInt32(2), reader.GetInt32(3), reader.IsDBNull(4) ? null : reader.GetString(4));
            protectedKey = reader.IsDBNull(5) ? null : (byte[])reader.GetValue(5);
            next = Date(reader, 6); successful = Date(reader, 7);
        }
        BackupAttempt? attempt = null;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT OperationId,Kind,Outcome,StartedUtcTicks,CompletedUtcTicks,ArchiveId FROM BackupAttempts ORDER BY rowid DESC LIMIT 1;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
                attempt = new(Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), Date(reader, 3)!.Value,
                    Date(reader, 4), reader.IsDBNull(5) ? null : Guid.Parse(reader.GetString(5)));
        }
        var archives = new List<BackupArchiveSummary>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT ArchiveId,CreatedUtcTicks,SizeBytes,Sha256,RecoveryKeyId,VerificationState,VerifiedUtcTicks FROM BackupArchives ORDER BY rowid DESC LIMIT 31;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) archives.Add(new(Guid.Parse(reader.GetString(0)), Date(reader, 1)!.Value,
                reader.GetInt64(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), Date(reader, 6)));
        }
        transaction.Commit();
        return new(policy, protectedKey, next, successful, attempt, archives);
    }
    internal async Task<bool> ConfigureKeyAsync(long expectedVersion, string keyId, byte[] protectedKey, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE BackupSettings SET Version=Version+1,RecoveryKeyId=$id,ProtectedKey=$key WHERE Singleton=1 AND Version=$version AND RecoveryKeyId IS NULL;";
        command.Parameters.AddWithValue("$id", keyId); command.Parameters.AddWithValue("$key", protectedKey); command.Parameters.AddWithValue("$version", expectedVersion);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }
    internal async Task<bool> ConfigurePolicyAsync(BackupPolicyRequest request, DateTimeOffset? next, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE BackupSettings SET Version=Version+1,Enabled=$enabled,IntervalHours=$hours,RetentionCount=$retention,NextDueUtcTicks=$next WHERE Singleton=1 AND Version=$version;";
        command.Parameters.AddWithValue("$enabled", request.Enabled); command.Parameters.AddWithValue("$hours", request.IntervalHours);
        command.Parameters.AddWithValue("$retention", request.RetentionCount); command.Parameters.AddWithValue("$version", request.ExpectedVersion);
        command.Parameters.AddWithValue("$next", (object?)next?.UtcTicks ?? DBNull.Value);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }
    internal async Task BeginAttemptAsync(BackupAttempt attempt, DateTimeOffset? next, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO BackupAttempts VALUES ($id,$kind,'inProgress',$started,NULL,$archive);
            DELETE FROM BackupAttempts WHERE OperationId IN (SELECT OperationId FROM BackupAttempts ORDER BY rowid DESC LIMIT -1 OFFSET 100);
            UPDATE BackupSettings SET NextDueUtcTicks=$next WHERE Singleton=1 AND Enabled=1;
            """;
        command.Parameters.AddWithValue("$id", attempt.OperationId.ToString("D")); command.Parameters.AddWithValue("$kind", attempt.Kind);
        command.Parameters.AddWithValue("$started", attempt.StartedUtc.UtcTicks); command.Parameters.AddWithValue("$archive", (object?)attempt.ArchiveId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$next", (object?)next?.UtcTicks ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken); transaction.Commit();
    }
    internal async Task CompleteAttemptAsync(Guid operationId, string outcome, DateTimeOffset now,
        BackupArchiveSummary? created, Guid? verifiedArchive, bool verificationSucceeded, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "UPDATE BackupAttempts SET Outcome=$outcome,CompletedUtcTicks=$now WHERE OperationId=$id;";
            command.Parameters.AddWithValue("$outcome", outcome); command.Parameters.AddWithValue("$now", now.UtcTicks); command.Parameters.AddWithValue("$id", operationId.ToString("D"));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        if (created is not null)
        {
            await using var command = connection.CreateCommand(); command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO BackupArchives VALUES ($id,$created,$size,$hash,$key,'verified',$verified);
                UPDATE BackupSettings SET LastSuccessfulUtcTicks=$verified WHERE Singleton=1;
                """;
            command.Parameters.AddWithValue("$id", created.ArchiveId.ToString("D")); command.Parameters.AddWithValue("$created", created.CreatedUtc.UtcTicks);
            command.Parameters.AddWithValue("$size", created.SizeBytes); command.Parameters.AddWithValue("$hash", created.Sha256);
            command.Parameters.AddWithValue("$key", created.RecoveryKeyId); command.Parameters.AddWithValue("$verified", now.UtcTicks);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        if (verifiedArchive is { } archive)
        {
            await using var command = connection.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "UPDATE BackupArchives SET VerificationState=$state,VerifiedUtcTicks=$now WHERE ArchiveId=$id;";
            command.Parameters.AddWithValue("$state", verificationSucceeded ? "verified" : "failed"); command.Parameters.AddWithValue("$now", now.UtcTicks);
            command.Parameters.AddWithValue("$id", archive.ToString("D")); await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }
    internal async Task RegisterRecoveredArchiveAsync(BackupArchiveSummary archive, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO BackupArchives VALUES ($id,$created,$size,$hash,$key,'verified',$verified);
            UPDATE BackupSettings SET LastSuccessfulUtcTicks=MAX(COALESCE(LastSuccessfulUtcTicks,0),$created) WHERE Singleton=1;
            """;
        command.Parameters.AddWithValue("$id", archive.ArchiveId.ToString("D"));
        command.Parameters.AddWithValue("$created", archive.CreatedUtc.UtcTicks);
        command.Parameters.AddWithValue("$size", archive.SizeBytes);
        command.Parameters.AddWithValue("$hash", archive.Sha256);
        command.Parameters.AddWithValue("$key", archive.RecoveryKeyId);
        command.Parameters.AddWithValue("$verified", archive.VerifiedUtc!.Value.UtcTicks);
        await command.ExecuteNonQueryAsync(cancellationToken); transaction.Commit();
    }
    internal async Task RemoveArchiveAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var connection = OpenConnection(); await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand(); command.CommandText = "DELETE FROM BackupArchives WHERE ArchiveId=$id;";
        command.Parameters.AddWithValue("$id", id.ToString("D")); await command.ExecuteNonQueryAsync(cancellationToken);
    }
    private static DateTimeOffset? Date(SqliteDataReader reader, int column) => reader.IsDBNull(column) ? null : new(reader.GetInt64(column), TimeSpan.Zero);
}
