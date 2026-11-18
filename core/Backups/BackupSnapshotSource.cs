using Microsoft.Data.Sqlite;
using SentinelAI.Backup;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core.Backups;

internal interface IBackupSnapshotSource
{
    Task CreateAsync(string destination, CancellationToken cancellationToken);
}

internal sealed class SqliteBackupSnapshotSource(AdminStore admins) : IBackupSnapshotSource
{
    public async Task CreateAsync(string destination, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        BackupStorage.AssertFile(admins.DatabasePath, BackupArchive.MaximumPayloadBytes);
        await using var source = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadOnly, DefaultTimeout = 5, Pooling = false
        }.ToString());
        await source.OpenAsync(cancellationToken);
        using var transaction = source.BeginTransaction(deferred: true);
        long pages; long pageSize;
        await using (var command = source.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA page_count;";
            pages = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
            command.CommandText = "PRAGMA page_size;";
            pageSize = (long)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
        var size = checked(pages * pageSize);
        if (size is <= 0 || size > BackupArchive.MaximumPayloadBytes - 128 * 1024)
            throw new IOException("The database exceeds the backup limit.");
        var root = Path.GetPathRoot(Path.GetFullPath(destination))!;
        if (new DriveInfo(root).AvailableFreeSpace < checked(size * 6 + 64L * 1024 * 1024))
            throw new IOException("Backup storage is unavailable.");
        using (BackupStorage.CreateFile(destination)) { }
        await using var target = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = destination, Mode = SqliteOpenMode.ReadWrite, Pooling = false
        }.ToString());
        await target.OpenAsync(cancellationToken);
        // The source read transaction fixes both its size and consistent state. SQLite's backup API copies pages,
        // including any committed WAL state, without copying the live database/sidecar files.
        source.BackupDatabase(target);
        transaction.Commit();
        cancellationToken.ThrowIfCancellationRequested();
    }
}
