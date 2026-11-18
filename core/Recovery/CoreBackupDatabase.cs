using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SentinelAI.Backup;

namespace SentinelAI.Core.Recovery;

internal sealed record CoreBackupDatabaseInfo(Guid CoreInstallationId, Guid OrganizationId,
    int AdministratorCount, int EndpointCount, string SchemaFingerprint);

/// <summary>Read-only validation of an isolated backup database, never the live database.</summary>
internal static class CoreBackupDatabase
{
    private static readonly string[] RequiredTables =
    [
        "Administrators", "CoreIdentity", "EndpointEnrollments", "EnrollmentTokens", "Devices",
        "EndpointInventories", "TrackedAlerts", "AlertStatusHistory", "EndpointSecurityTelemetry",
        "SecurityEventObservations", "SecurityEventSources", "SecurityEventGaps", "LicenseState",
        "BackupSettings", "BackupArchives", "BackupAttempts"
    ];

    internal static async Task<CoreBackupDatabaseInfo> InspectAsync(string databasePath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var file = new FileInfo(Path.GetFullPath(databasePath));
        file.Refresh();
        if (!file.Exists || file.LinkTarget is not null ||
            (file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            file.Length is < 512 or > BackupArchive.MaximumPayloadBytes)
            throw Invalid();
        await using (var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var header = new byte[16];
            await stream.ReadExactlyAsync(header, cancellationToken);
            if (!header.AsSpan().SequenceEqual("SQLite format 3\0"u8)) throw Invalid();
        }

        try
        {
            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = file.FullName, Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private, Pooling = false, DefaultTimeout = 1
            }.ToString());
            await connection.OpenAsync(cancellationToken);
            await using (var restrictions = connection.CreateCommand())
            {
                restrictions.CommandText = "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;";
                await restrictions.ExecuteNonQueryAsync(cancellationToken);
            }
            await using (var tableKinds = connection.CreateCommand())
            {
                tableKinds.CommandText = "SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('virtual','shadow','view') LIMIT 1;";
                if (await tableKinds.ExecuteScalarAsync(cancellationToken) is not null) throw Invalid();
            }
            await using (var check = connection.CreateCommand())
            {
                check.CommandText = "PRAGMA integrity_check;";
                await using var reader = await check.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken) || reader.GetString(0) != "ok" ||
                    await reader.ReadAsync(cancellationToken)) throw Invalid();
            }
            var schema = new StringBuilder();
            var tables = new HashSet<string>(StringComparer.Ordinal);
            await using (var query = connection.CreateCommand())
            {
                query.CommandText = "SELECT type,name,sql,length(sql),length(name) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;";
                await using var reader = await query.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    if (schema.Length > 1024 * 1024 || reader.GetInt64(4) > 128 ||
                        (!reader.IsDBNull(3) && reader.GetInt64(3) > 64 * 1024)) throw Invalid();
                    var type = reader.GetString(0);
                    var name = reader.GetString(1);
                    if (type == "table") tables.Add(name);
                    // Current Core has no SQL views, triggers, or virtual tables. Restoring them
                    // would introduce unreviewed behavior when normal writes resume.
                    var sql = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
                    if (type is not ("table" or "index")) throw Invalid();
                    schema.Append(type).Append('\0').Append(name).Append('\0').Append(sql).Append('\n');
                    if (schema.Length > 1024 * 1024) throw Invalid();
                }
            }
            if (!RequiredTables.All(tables.Contains)) throw Invalid();
            foreach (var projection in new[]
                     {
                         "SELECT Singleton,Version,Enabled,IntervalHours,RetentionCount,RecoveryKeyId,ProtectedKey,NextDueUtcTicks,LastSuccessfulUtcTicks FROM BackupSettings LIMIT 0;",
                         "SELECT OperationId,Kind,Outcome,StartedUtcTicks,CompletedUtcTicks,ArchiveId FROM BackupAttempts LIMIT 0;",
                         "SELECT ArchiveId,CreatedUtcTicks,SizeBytes,Sha256,RecoveryKeyId,VerificationState,VerifiedUtcTicks FROM BackupArchives LIMIT 0;"
                     })
            {
                await using var query = connection.CreateCommand(); query.CommandText = projection;
                await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            }
            Guid coreId;
            Guid organizationId;
            await using (var query = connection.CreateCommand())
            {
                query.CommandText = "SELECT Singleton,CoreInstallationId,OrganizationId FROM CoreIdentity;";
                await using var reader = await query.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken) || reader.GetInt64(0) != 1 ||
                    !Guid.TryParse(reader.GetString(1), out coreId) || coreId == Guid.Empty ||
                    !Guid.TryParse(reader.GetString(2), out organizationId) || organizationId == Guid.Empty ||
                    await reader.ReadAsync(cancellationToken)) throw Invalid();
            }
            var administratorCount = await CountAsync(connection, "Administrators", cancellationToken);
            var endpointCount = await CountAsync(connection, "EndpointEnrollments", cancellationToken);
            if (administratorCount is < 1 or > 10_000 || endpointCount > 1_000_000) throw Invalid();
            await using (var check = connection.CreateCommand())
            {
                check.CommandText = "PRAGMA foreign_key_check;";
                await using var reader = await check.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken)) throw Invalid();
            }
            return new CoreBackupDatabaseInfo(coreId, organizationId, administratorCount, endpointCount,
                Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(schema.ToString()))));
        }
        catch (SqliteException) { throw Invalid(); }
    }

    private static async Task<int> CountAsync(SqliteConnection connection, string table,
        CancellationToken cancellationToken)
    {
        // Table names are private constants supplied by InspectAsync, never archive metadata.
        await using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM " + table + ";";
        var value = (long)(await count.ExecuteScalarAsync(cancellationToken))!;
        if (value is < 0 or > int.MaxValue) throw Invalid();
        return (int)value;
    }

    private static InvalidDataException Invalid() => new("The backup database is not a supported intact Core database.");
}
