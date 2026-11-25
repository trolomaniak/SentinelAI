using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.SoftwareCatalog;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Core.Persistence;

internal sealed class SoftwareCatalogReadStore(AdminStore admins, TimeProvider time)
{
    private const string CurrentProducts = """
        FROM SoftwareInventoryItems AS s
        JOIN EndpointEnrollments AS e ON e.EndpointId = s.EndpointId AND e.RemovedUtcTicks IS NULL
        WHERE $search = '' OR instr(s.NameKey, $search) > 0 OR instr(s.PublisherKey, $search) > 0
        """;

    private const string CurrentInstallations = """
        FROM SoftwareInventoryItems AS s
        JOIN EndpointEnrollments AS e ON e.EndpointId = s.EndpointId AND e.RemovedUtcTicks IS NULL
        JOIN SoftwareInventoryState AS state ON state.EndpointId = s.EndpointId
        LEFT JOIN EndpointInventories AS i ON i.EndpointId = s.EndpointId
        WHERE s.ProductId = $product
        """;

    private const string CurrentChanges = """
        FROM SoftwareInventoryChanges AS c
        LEFT JOIN EndpointInventories AS i ON i.EndpointId = c.EndpointId
        WHERE c.ReceivedUtcTicks >= $cutoff AND c.ReceivedUtcTicks <= $now
        """;

    private const string EndpointName = "CASE WHEN json_valid(i.ReportJson) THEN substr(json_extract(i.ReportJson, '$.Hostname'), 1, 256) END";
    private static readonly JsonSerializerOptions VariantJson = new(JsonSerializerDefaults.Web);

    internal async Task<SoftwareCatalogPage> ReadProductsAsync(string search, int offset, int limit, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow().ToUniversalTime();
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var coverage = await ReadCoverageAsync(connection, transaction, now, cancellationToken);
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.Parameters.AddWithValue("$search", SoftwareInventoryWriter.NormalizeKey(search));
        query.CommandText = "SELECT COUNT(DISTINCT s.ProductId) " + CurrentProducts;
        var total = await CountAsync(query, cancellationToken);
        var items = new List<SoftwareProduct>(limit);
        if (offset < total)
        {
            query.CommandText = """
                SELECT s.ProductId, MIN(s.Name), MIN(s.Publisher), COUNT(DISTINCT s.EndpointId),
                    COUNT(DISTINCT s.Version || char(0) || s.Architecture)
                """ + " " + CurrentProducts + """

                GROUP BY s.ProductId ORDER BY MIN(s.NameKey), MIN(s.PublisherKey), s.ProductId
                LIMIT $limit OFFSET $offset;
                """;
            AddPageParameters(query, offset, limit);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                items.Add(new SoftwareProduct(reader.GetString(0), reader.GetString(1), OptionalText(reader, 2),
                    reader.GetInt32(3), reader.GetInt32(4)));
        }
        transaction.Commit();
        return new SoftwareCatalogPage(now, total, offset, limit, coverage, items.AsReadOnly());
    }

    internal async Task<SoftwareInstallationsPage> ReadInstallationsAsync(string productId, int offset, int limit,
        CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow().ToUniversalTime();
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.Parameters.AddWithValue("$product", productId);
        query.CommandText = "SELECT COUNT(*) " + CurrentInstallations;
        var total = await CountAsync(query, cancellationToken);
        var items = new List<SoftwareInstallation>(limit);
        if (offset < total)
        {
            query.CommandText = $"""
                SELECT s.EndpointId, {EndpointName}, s.Version, s.Architecture, state.CollectedUtcTicks,
                    (state.IsTruncated <> 0 OR state.SkippedCount <> 0)
                {CurrentInstallations}
                ORDER BY s.EndpointId, s.Version, s.Architecture LIMIT $limit OFFSET $offset;
                """;
            AddPageParameters(query, offset, limit);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            var cutoff = StaleCutoff(now);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = Guid.ParseExact(reader.GetString(0), "D");
                var collected = UtcDate(reader, 4);
                items.Add(new SoftwareInstallation(id, ReadEndpointName(reader, id), OptionalText(reader, 2), OptionalText(reader, 3),
                    collected, reader.GetBoolean(5), collected.UtcTicks < cutoff));
            }
        }
        transaction.Commit();
        return new SoftwareInstallationsPage(productId, now, total, offset, limit, items.AsReadOnly());
    }

    internal async Task<SoftwareChangesPage> ReadChangesAsync(string? productId, int offset, int limit,
        CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow().ToUniversalTime();
        await using var connection = await OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.Parameters.AddWithValue("$cutoff", now.UtcTicks - TimeSpan.FromDays(SoftwareCatalogContract.RetentionDays).Ticks);
        query.Parameters.AddWithValue("$now", now.UtcTicks);
        var from = CurrentChanges;
        if (productId is not null)
        {
            from += " AND c.ProductId = $product";
            query.Parameters.AddWithValue("$product", productId);
        }
        query.CommandText = "SELECT COUNT(*) " + from;
        var total = await CountAsync(query, cancellationToken);
        var items = new List<SoftwareChange>(limit);
        if (offset < total)
        {
            query.CommandText = $"""
                SELECT c.EndpointId, {EndpointName}, c.ProductId, c.Name, c.Publisher, c.Kind, c.PreviousCollectedUtcTicks,
                    c.CollectedUtcTicks, c.BeforeCount, c.AfterCount, c.BeforeJson, c.AfterJson
                {from}
                ORDER BY c.ReceivedUtcTicks DESC, c.ChangeId DESC LIMIT $limit OFFSET $offset;
                """;
            AddPageParameters(query, offset, limit);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = Guid.ParseExact(reader.GetString(0), "D");
                var before = reader.GetInt32(8);
                var after = reader.GetInt32(9);
                items.Add(new SoftwareChange(id, ReadEndpointName(reader, id), reader.GetString(2), reader.GetString(3),
                    OptionalText(reader, 4), reader.GetString(5), UtcDate(reader, 6), UtcDate(reader, 7), before, after,
                    ReadVariants(reader, 10, before), ReadVariants(reader, 11, after)));
            }
        }
        transaction.Commit();
        return new SoftwareChangesPage(productId, now, total, offset, limit, items.AsReadOnly());
    }

    private static async Task<SoftwareCatalogCoverage> ReadCoverageAsync(SqliteConnection connection,
        SqliteTransaction transaction, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT COUNT(*),
                COUNT(CASE WHEN s.Availability = 'collected' AND s.IsTruncated = 0 AND s.SkippedCount = 0 THEN 1 END),
                COUNT(CASE WHEN s.Availability = 'collected' AND (s.IsTruncated <> 0 OR s.SkippedCount <> 0) THEN 1 END),
                COUNT(CASE WHEN s.Availability <> 'collected' THEN 1 END),
                COUNT(CASE WHEN s.EndpointId IS NULL THEN 1 END),
                COUNT(CASE WHEN s.Availability = 'collected' AND s.CollectedUtcTicks < $cutoff THEN 1 END)
            FROM EndpointEnrollments AS e LEFT JOIN SoftwareInventoryState AS s ON s.EndpointId = e.EndpointId
            WHERE e.RemovedUtcTicks IS NULL;
            """;
        query.Parameters.AddWithValue("$cutoff", StaleCutoff(now));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new SoftwareCatalogCoverage(reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2),
            reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5));
    }

    private static long StaleCutoff(DateTimeOffset now) => now.UtcTicks - TimeSpan.FromHours(SoftwareCatalogContract.StaleAfterHours).Ticks;

    private static async Task<int> CountAsync(SqliteCommand query, CancellationToken cancellationToken) =>
        checked((int)(long)(await query.ExecuteScalarAsync(cancellationToken))!);

    private static string? OptionalText(SqliteDataReader reader, int index) => reader.GetString(index) is { Length: > 0 } value ? value : null;

    private static DateTimeOffset UtcDate(SqliteDataReader reader, int index) => new(reader.GetInt64(index), TimeSpan.Zero);

    private static string ReadEndpointName(SqliteDataReader reader, Guid endpointId)
    {
        var label = reader.IsDBNull(1) ? null : reader.GetString(1);
        return SecurityEventContract.IsBoundedText(label, 256) ? label! : SecurityEventStore.PlaceholderEndpointName(endpointId);
    }

    private static IReadOnlyList<SoftwareVariant> ReadVariants(SqliteDataReader reader, int index, int count)
    {
        const int maximumJsonLength = 8192;
        var json = reader.GetString(index);
        if (json.Length > maximumJsonLength || count < 0 ||
            JsonSerializer.Deserialize<SoftwareVariant[]>(json, VariantJson) is not { } variants ||
            variants.Length != Math.Min(count, SoftwareCatalogContract.MaximumChangeVariants))
            throw new InvalidDataException("Stored software change has invalid variants.");
        return Array.AsReadOnly(variants);
    }

    private static void AddPageParameters(SqliteCommand query, int offset, int limit)
    {
        query.Parameters.AddWithValue("$offset", offset);
        query.Parameters.AddWithValue("$limit", limit);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadOnly, DefaultTimeout = 30
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
