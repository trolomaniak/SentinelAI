using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Rules;

namespace SentinelAI.Core.Persistence;

public sealed class InventoryStore(AdminStore admins, AlertStore alerts, RuleEngine rules)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS EndpointInventories (
                EndpointId TEXT NOT NULL PRIMARY KEY,
                CollectedUtcTicks INTEGER NOT NULL,
                ReportJson TEXT NOT NULL
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task RecordLatestAsync(
        InventoryReport report,
        CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var upsert = connection.CreateCommand();
        upsert.Transaction = transaction;
        upsert.CommandText = """
            INSERT INTO EndpointInventories (EndpointId, CollectedUtcTicks, ReportJson)
            SELECT $endpointId, $collectedUtcTicks, $reportJson
            WHERE EXISTS (
                SELECT 1 FROM EndpointEnrollments WHERE EndpointId = $endpointId
            )
            ON CONFLICT (EndpointId) DO UPDATE SET
                CollectedUtcTicks = excluded.CollectedUtcTicks,
                ReportJson = excluded.ReportJson
            WHERE excluded.CollectedUtcTicks > EndpointInventories.CollectedUtcTicks;
            """;
        upsert.Parameters.AddWithValue("$endpointId", report.EndpointId.ToString("D"));
        upsert.Parameters.AddWithValue("$collectedUtcTicks", report.CollectedUtc.UtcDateTime.Ticks);
        upsert.Parameters.AddWithValue("$reportJson", JsonSerializer.Serialize(report));
        if (await upsert.ExecuteNonQueryAsync(cancellationToken) == 1)
        {
            await RecordFindingsAsync(connection, transaction, report, cancellationToken);
        }

        transaction.Commit();
    }

    /// <summary>Upgrade existing snapshots once; repeated startup never resets lifecycle state.</summary>
    public async Task BackfillAlertsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT i.ReportJson FROM EndpointInventories AS i
            INNER JOIN EndpointEnrollments AS e ON e.EndpointId = i.EndpointId
            ORDER BY i.EndpointId;
            """;
        await using (var reader = await query.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var report = JsonSerializer.Deserialize<InventoryReport>(reader.GetString(0));
                if (report is not null)
                {
                    await RecordFindingsAsync(connection, transaction, report, cancellationToken);
                }
            }
        }

        transaction.Commit();
    }

    private async Task RecordFindingsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        InventoryReport report,
        CancellationToken cancellationToken)
    {
        foreach (var finding in rules.Evaluate(EndpointState.FromInventory(report)))
        {
            await alerts.RecordObservedAsync(connection, transaction, finding, report.Hostname, cancellationToken);
        }
    }

    public async Task<InventoryReport?> FindLatestAsync(
        Guid endpointId,
        CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty)
        {
            return null;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT ReportJson FROM EndpointInventories
            WHERE EndpointId = $endpointId LIMIT 1;
            """;
        query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        var json = await query.ExecuteScalarAsync(cancellationToken) as string;
        return json is null ? null : JsonSerializer.Deserialize<InventoryReport>(json);
    }

    private SqliteConnection CreateConnection()
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 30,
            ForeignKeys = true
        };
        return new SqliteConnection(connectionString.ToString());
    }
}
