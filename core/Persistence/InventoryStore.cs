using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Core.Persistence;

public sealed class InventoryStore(AdminStore admins)
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
        await using var upsert = connection.CreateCommand();
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
        await upsert.ExecuteNonQueryAsync(cancellationToken);
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
            DefaultTimeout = 30
        };
        return new SqliteConnection(connectionString.ToString());
    }
}
