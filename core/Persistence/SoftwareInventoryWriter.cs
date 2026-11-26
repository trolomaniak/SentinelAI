using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SoftwareCatalog;

namespace SentinelAI.Core.Persistence;

internal static class SoftwareInventoryWriter
{
    private const int BackfillBatchSize = 16;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    internal static async Task InitializeAsync(SqliteConnection connection, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var create = connection.CreateCommand();
        create.Transaction = transaction;
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS SoftwareInventoryState (
                EndpointId TEXT NOT NULL PRIMARY KEY,
                CollectedUtcTicks INTEGER NOT NULL,
                ReceivedUtcTicks INTEGER NOT NULL,
                Availability TEXT NOT NULL,
                TotalCount INTEGER,
                IsTruncated INTEGER NOT NULL CHECK (IsTruncated IN (0, 1)),
                SkippedCount INTEGER NOT NULL,
                ItemsFingerprint TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS SoftwareInventoryItems (
                EndpointId TEXT NOT NULL,
                ProductId TEXT NOT NULL,
                Name TEXT NOT NULL,
                Publisher TEXT NOT NULL,
                NameKey TEXT NOT NULL,
                PublisherKey TEXT NOT NULL,
                Version TEXT NOT NULL,
                Architecture TEXT NOT NULL,
                PRIMARY KEY (EndpointId, ProductId, Version, Architecture)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS IX_SoftwareInventoryItems_Product
                ON SoftwareInventoryItems (ProductId, EndpointId, Version, Architecture);
            CREATE TABLE IF NOT EXISTS SoftwareInventoryChanges (
                ChangeId INTEGER PRIMARY KEY,
                EndpointId TEXT NOT NULL,
                ProductId TEXT NOT NULL,
                Name TEXT NOT NULL,
                Publisher TEXT NOT NULL,
                Kind TEXT NOT NULL CHECK (Kind IN ('appeared', 'disappeared', 'variantsChanged')),
                PreviousCollectedUtcTicks INTEGER NOT NULL,
                CollectedUtcTicks INTEGER NOT NULL,
                ReceivedUtcTicks INTEGER NOT NULL,
                BeforeCount INTEGER NOT NULL,
                AfterCount INTEGER NOT NULL,
                BeforeJson TEXT NOT NULL,
                AfterJson TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_SoftwareInventoryChanges_Received
                ON SoftwareInventoryChanges (ReceivedUtcTicks DESC, ChangeId DESC);
            CREATE INDEX IF NOT EXISTS IX_SoftwareInventoryChanges_Product
                ON SoftwareInventoryChanges (ProductId, ReceivedUtcTicks DESC, ChangeId DESC);
            DELETE FROM SoftwareInventoryItems WHERE EndpointId IN (
                SELECT EndpointId FROM EndpointEnrollments WHERE RemovedUtcTicks IS NOT NULL);
            DELETE FROM SoftwareInventoryState WHERE EndpointId IN (
                SELECT EndpointId FROM EndpointEnrollments WHERE RemovedUtcTicks IS NOT NULL);
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
        await PruneAsync(connection, transaction, now, enforceRowLimit: true, cancellationToken);
        transaction.Commit();
    }

    internal static async Task RemoveEndpointProjectionAsync(SqliteConnection connection, SqliteTransaction transaction,
        Guid endpointId, CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        // EnrollmentStore can run on its own before the telemetry schema is initialized.
        delete.CommandText = """
            SELECT COUNT(*) FROM sqlite_schema
            WHERE type = 'table' AND name IN ('SoftwareInventoryState', 'SoftwareInventoryItems');
            """;
        if (await delete.ExecuteScalarAsync(cancellationToken) is not 2L) return;
        delete.CommandText = """
            DELETE FROM SoftwareInventoryItems WHERE EndpointId = $endpoint;
            DELETE FROM SoftwareInventoryState WHERE EndpointId = $endpoint;
            """;
        delete.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static async Task SeedLegacyBeforeAsync(SqliteConnection connection, SqliteTransaction transaction,
        EndpointTelemetryReport report, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT t.ReportJson, t.ReceivedUtcTicks
            FROM EndpointSecurityTelemetry AS t
            JOIN EndpointEnrollments AS e ON e.EndpointId = t.EndpointId AND e.RemovedUtcTicks IS NULL
            WHERE t.EndpointId = $endpoint AND t.CollectedUtcTicks < $collected AND NOT EXISTS (
                SELECT 1 FROM SoftwareInventoryState AS s WHERE s.EndpointId = t.EndpointId);
            """;
        var endpoint = report.EndpointId.ToString("D");
        query.Parameters.AddWithValue("$endpoint", endpoint);
        query.Parameters.AddWithValue("$collected", report.CollectedUtc.UtcTicks);
        string json;
        long receivedUtcTicks;
        await using (var reader = await query.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken)) return;
            json = reader.GetString(0);
            receivedUtcTicks = reader.GetInt64(1);
        }
        await SeedLegacyAsync(connection, transaction, endpoint, json, receivedUtcTicks, cancellationToken);
    }

    internal static async Task RecordAsync(SqliteConnection connection, SqliteTransaction transaction,
        EndpointTelemetryReport report, DateTimeOffset receivedUtc, CancellationToken cancellationToken)
    {
        var fingerprint = FingerprintItems(report.Software);
        var endpoint = report.EndpointId.ToString("D");
        Dictionary<string, Product>? products = null;
        var changed = false;
        if (fingerprint != await ReadItemsFingerprintAsync(connection, transaction, endpoint, cancellationToken))
        {
            products = Project(report.Software);
            var previous = Comparable(report.Software)
                ? await ReadPreviousAsync(connection, transaction, endpoint, cancellationToken) : null;
            changed = previous is not null && await RecordChangesAsync(connection, transaction, report, receivedUtc,
                previous, products, cancellationToken);
        }
        await UpdateCurrentAsync(connection, transaction, report, receivedUtc, fingerprint, products, cancellationToken);
        await PruneAsync(connection, transaction, receivedUtc, changed, cancellationToken);
    }

    internal static async Task<string?> BackfillBatchAsync(SqliteConnection connection, string afterEndpoint,
        CancellationToken cancellationToken)
    {
        using var transaction = connection.BeginTransaction(deferred: false);
        var batch = new List<(string Endpoint, string Json, long ReceivedUtcTicks)>(BackfillBatchSize);
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT t.EndpointId, t.ReportJson, t.ReceivedUtcTicks
                FROM EndpointSecurityTelemetry AS t
                JOIN EndpointEnrollments AS e ON e.EndpointId = t.EndpointId AND e.RemovedUtcTicks IS NULL
                WHERE t.EndpointId > $after AND NOT EXISTS (
                    SELECT 1 FROM SoftwareInventoryState AS s WHERE s.EndpointId = t.EndpointId)
                ORDER BY t.EndpointId LIMIT $maximum;
                """;
            query.Parameters.AddWithValue("$after", afterEndpoint);
            query.Parameters.AddWithValue("$maximum", BackfillBatchSize);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                batch.Add((reader.GetString(0), reader.GetString(1), reader.GetInt64(2)));
        }

        foreach (var row in batch)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await SeedLegacyAsync(connection, transaction, row.Endpoint, row.Json, row.ReceivedUtcTicks, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
        return batch.Count == BackfillBatchSize ? batch[^1].Endpoint : null;
    }

    private static async Task SeedLegacyAsync(SqliteConnection connection, SqliteTransaction transaction,
        string endpoint, string json, long receivedUtcTicks, CancellationToken cancellationToken)
    {
        if (receivedUtcTicks < 0 || receivedUtcTicks > DateTime.MaxValue.Ticks ||
            EndpointTelemetryStore.Parse(json, receivedUtcTicks) is not { } stored ||
            endpoint != stored.Report.EndpointId.ToString("D") ||
            !EndpointTelemetryContract.IsValidIgnoringClock(stored.Report)) return;
        await UpdateCurrentAsync(connection, transaction, stored.Report, stored.ReceivedUtc,
            FingerprintItems(stored.Report.Software), Project(stored.Report.Software), cancellationToken);
    }

    private static bool Comparable(InstalledSoftwareTelemetry software) =>
        software.Availability == TelemetryAvailability.Collected && !software.Truncated && software.SkippedCount == 0;

    private static string FingerprintItems(InstalledSoftwareTelemetry software) => Convert.ToHexStringLower(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(software.Items ?? [], EndpointTelemetryContract.Json)));

    private static async Task<string?> ReadItemsFingerprintAsync(SqliteConnection connection, SqliteTransaction transaction,
        string endpoint, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = "SELECT ItemsFingerprint FROM SoftwareInventoryState WHERE EndpointId = $endpoint;";
        query.Parameters.AddWithValue("$endpoint", endpoint);
        return (string?)await query.ExecuteScalarAsync(cancellationToken);
    }

    private static Dictionary<string, Product> Project(InstalledSoftwareTelemetry software)
    {
        var products = new Dictionary<string, Product>(StringComparer.Ordinal);
        if (software.Items is not { } items) return products;
        foreach (var group in items.GroupBy(item => (Name: NormalizeKey(item.Name), Publisher: NormalizeKey(item.Publisher ?? string.Empty))))
        {
            var (nameKey, publisherKey) = group.Key;
            var display = group.OrderBy(item => item.Name, StringComparer.Ordinal)
                .ThenBy(item => item.Publisher, StringComparer.Ordinal).First();
            var id = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(nameKey + '\0' + publisherKey)));
            var variants = OrderVariants(group.Select(item => new SoftwareVariant(item.Version, item.Architecture)).Distinct());
            products.Add(id, new Product(display.Name, display.Publisher ?? string.Empty, nameKey, publisherKey, variants));
        }
        return products;
    }

    internal static string NormalizeKey(string value) => value.Normalize(NormalizationForm.FormC).ToUpperInvariant();

    private static SoftwareVariant[] OrderVariants(IEnumerable<SoftwareVariant> variants) =>
        variants.OrderBy(variant => variant.Version, StringComparer.Ordinal)
            .ThenBy(variant => variant.Architecture, StringComparer.Ordinal).ToArray();

    private static async Task<PreviousObservation?> ReadPreviousAsync(SqliteConnection connection,
        SqliteTransaction transaction, string endpoint, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT s.CollectedUtcTicks, i.ProductId, i.Name, i.Publisher, i.Version, i.Architecture
            FROM SoftwareInventoryState AS s
            LEFT JOIN SoftwareInventoryItems AS i ON i.EndpointId = s.EndpointId
            WHERE s.EndpointId = $endpoint AND s.Availability = $collected AND s.IsTruncated = 0 AND s.SkippedCount = 0;
            """;
        query.Parameters.AddWithValue("$endpoint", endpoint);
        query.Parameters.AddWithValue("$collected", TelemetryAvailability.Collected);
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var collected = reader.GetInt64(0);
        var products = new Dictionary<string, PreviousProduct>(StringComparer.Ordinal);
        do
        {
            if (reader.IsDBNull(1)) break; // A complete empty inventory is also a comparison baseline.
            var id = reader.GetString(1);
            if (!products.TryGetValue(id, out var product))
            {
                product = new PreviousProduct(reader.GetString(2), reader.GetString(3), []);
                products.Add(id, product);
            }
            product.Variants.Add(new SoftwareVariant(NullIfEmpty(reader.GetString(4)), NullIfEmpty(reader.GetString(5))));
        } while (await reader.ReadAsync(cancellationToken));
        return new PreviousObservation(collected, products);
    }

    private static async Task<bool> RecordChangesAsync(SqliteConnection connection, SqliteTransaction transaction,
        EndpointTelemetryReport report, DateTimeOffset receivedUtc, PreviousObservation previous,
        Dictionary<string, Product> products, CancellationToken cancellationToken)
    {
        if (previous.CollectedUtcTicks >= report.CollectedUtc.UtcTicks) return false;
        await using var write = connection.CreateCommand();
        write.Transaction = transaction;
        write.CommandText = """
            INSERT INTO SoftwareInventoryChanges(EndpointId, ProductId, Name, Publisher, Kind,
                PreviousCollectedUtcTicks, CollectedUtcTicks, ReceivedUtcTicks, BeforeCount, AfterCount, BeforeJson, AfterJson)
            VALUES($endpoint, $product, $name, $publisher, $kind, $previous, $collected, $received,
                $beforeCount, $afterCount, $before, $after);
            """;
        write.Parameters.AddWithValue("$endpoint", report.EndpointId.ToString("D"));
        write.Parameters.AddWithValue("$previous", previous.CollectedUtcTicks);
        write.Parameters.AddWithValue("$collected", report.CollectedUtc.UtcTicks);
        write.Parameters.AddWithValue("$received", receivedUtc.UtcTicks);
        var productId = write.Parameters.Add("$product", SqliteType.Text);
        var name = write.Parameters.Add("$name", SqliteType.Text);
        var publisher = write.Parameters.Add("$publisher", SqliteType.Text);
        var kind = write.Parameters.Add("$kind", SqliteType.Text);
        var beforeCount = write.Parameters.Add("$beforeCount", SqliteType.Integer);
        var afterCount = write.Parameters.Add("$afterCount", SqliteType.Integer);
        var beforeJson = write.Parameters.Add("$before", SqliteType.Text);
        var afterJson = write.Parameters.Add("$after", SqliteType.Text);
        write.Prepare();

        var changed = false;
        foreach (var id in previous.Products.Keys.Union(products.Keys).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var oldProduct = previous.Products.GetValueOrDefault(id);
            var newProduct = products.GetValueOrDefault(id);
            SoftwareVariant[] before = oldProduct is null ? [] : OrderVariants(oldProduct.Variants);
            SoftwareVariant[] after = newProduct?.Variants ?? [];
            if (before.SequenceEqual(after)) continue;
            productId.Value = id;
            name.Value = newProduct?.Name ?? oldProduct!.Name;
            publisher.Value = newProduct?.Publisher ?? oldProduct!.Publisher;
            kind.Value = oldProduct is null ? "appeared" : newProduct is null ? "disappeared" : "variantsChanged";
            beforeCount.Value = before.Length;
            afterCount.Value = after.Length;
            beforeJson.Value = JsonSerializer.Serialize(before.Take(SoftwareCatalogContract.MaximumChangeVariants), Json);
            afterJson.Value = JsonSerializer.Serialize(after.Take(SoftwareCatalogContract.MaximumChangeVariants), Json);
            await write.ExecuteNonQueryAsync(cancellationToken);
            changed = true;
        }

        return changed;
    }

    private static async Task UpdateCurrentAsync(SqliteConnection connection, SqliteTransaction transaction,
        EndpointTelemetryReport report, DateTimeOffset receivedUtc, string fingerprint, Dictionary<string, Product>? products,
        CancellationToken cancellationToken)
    {
        var endpoint = report.EndpointId.ToString("D");
        await using (var replace = connection.CreateCommand())
        {
            replace.Transaction = transaction;
            replace.CommandText = """
                INSERT INTO SoftwareInventoryState (EndpointId, CollectedUtcTicks, ReceivedUtcTicks, Availability,
                    TotalCount, IsTruncated, SkippedCount, ItemsFingerprint)
                VALUES ($endpoint, $collected, $received, $availability, $total, $truncated, $skipped, $fingerprint)
                ON CONFLICT (EndpointId) DO UPDATE SET CollectedUtcTicks = excluded.CollectedUtcTicks,
                    ReceivedUtcTicks = excluded.ReceivedUtcTicks, Availability = excluded.Availability,
                    TotalCount = excluded.TotalCount, IsTruncated = excluded.IsTruncated, SkippedCount = excluded.SkippedCount,
                    ItemsFingerprint = excluded.ItemsFingerprint;
                """;
            if (products is not null)
                replace.CommandText = "DELETE FROM SoftwareInventoryItems WHERE EndpointId = $endpoint;\n" + replace.CommandText;
            replace.Parameters.AddWithValue("$endpoint", endpoint);
            replace.Parameters.AddWithValue("$collected", report.CollectedUtc.UtcTicks);
            replace.Parameters.AddWithValue("$received", receivedUtc.UtcTicks);
            replace.Parameters.AddWithValue("$availability", report.Software.Availability);
            replace.Parameters.AddWithValue("$total", (object?)report.Software.TotalCount ?? DBNull.Value);
            replace.Parameters.AddWithValue("$truncated", report.Software.Truncated);
            replace.Parameters.AddWithValue("$skipped", report.Software.SkippedCount);
            replace.Parameters.AddWithValue("$fingerprint", fingerprint);
            await replace.ExecuteNonQueryAsync(cancellationToken);
        }

        if (products is null || products.Count == 0) return;
        await using var write = connection.CreateCommand();
        write.Transaction = transaction;
        write.CommandText = """
            INSERT INTO SoftwareInventoryItems(EndpointId, ProductId, Name, Publisher, NameKey, PublisherKey, Version, Architecture)
            VALUES($endpoint, $product, $name, $publisher, $nameKey, $publisherKey, $version, $architecture);
            """;
        write.Parameters.AddWithValue("$endpoint", endpoint);
        var productId = write.Parameters.Add("$product", SqliteType.Text);
        var name = write.Parameters.Add("$name", SqliteType.Text);
        var publisher = write.Parameters.Add("$publisher", SqliteType.Text);
        var nameKey = write.Parameters.Add("$nameKey", SqliteType.Text);
        var publisherKey = write.Parameters.Add("$publisherKey", SqliteType.Text);
        var version = write.Parameters.Add("$version", SqliteType.Text);
        var architecture = write.Parameters.Add("$architecture", SqliteType.Text);
        write.Prepare();
        foreach (var (id, product) in products)
        {
            productId.Value = id;
            name.Value = product.Name;
            publisher.Value = product.Publisher;
            nameKey.Value = product.NameKey;
            publisherKey.Value = product.PublisherKey;
            foreach (var variant in product.Variants)
            {
                cancellationToken.ThrowIfCancellationRequested();
                version.Value = variant.Version ?? string.Empty;
                architecture.Value = variant.Architecture ?? string.Empty;
                await write.ExecuteNonQueryAsync(cancellationToken);
            }
        }
    }

    private static async Task PruneAsync(SqliteConnection connection, SqliteTransaction transaction,
        DateTimeOffset now, bool enforceRowLimit, CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = "DELETE FROM SoftwareInventoryChanges WHERE ReceivedUtcTicks < $cutoff;";
        delete.Parameters.AddWithValue("$cutoff", now.UtcTicks - TimeSpan.FromDays(SoftwareCatalogContract.RetentionDays).Ticks);
        if (enforceRowLimit)
        {
            delete.CommandText += """

                DELETE FROM SoftwareInventoryChanges WHERE ChangeId <= (
                    SELECT ChangeId FROM SoftwareInventoryChanges ORDER BY ChangeId DESC LIMIT 1 OFFSET $maximum);
                """;
            delete.Parameters.AddWithValue("$maximum", SoftwareCatalogContract.MaximumChanges);
        }
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string? NullIfEmpty(string text) => text.Length == 0 ? null : text;

    private sealed record Product(string Name, string Publisher, string NameKey, string PublisherKey, SoftwareVariant[] Variants);
    private sealed record PreviousProduct(string Name, string Publisher, List<SoftwareVariant> Variants);
    private sealed record PreviousObservation(long CollectedUtcTicks, Dictionary<string, PreviousProduct> Products);
}

internal sealed class SoftwareInventoryBackfillWorker(EndpointTelemetryStore telemetry,
    ILogger<SoftwareInventoryBackfillWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? afterEndpoint = string.Empty;
        while (afterEndpoint is not null && !stoppingToken.IsCancellationRequested)
        {
            try
            {
                afterEndpoint = await telemetry.BackfillSoftwareInventoryBatchAsync(afterEndpoint, stoppingToken);
                if (afterEndpoint is not null) await Task.Delay(TimeSpan.FromMilliseconds(50), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (SqliteException exception)
            {
                logger.LogWarning("Software inventory backfill deferred (SQLite {ErrorCode}).", exception.SqliteErrorCode);
                try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            }
        }
    }
}
