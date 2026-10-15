using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Rules;

namespace SentinelAI.Core.Persistence;

public sealed record StoredEndpointTelemetry(EndpointTelemetryReport Report, DateTimeOffset ReceivedUtc);

/// <summary>The latest collection time and rule-section availability of an endpoint's stored telemetry.</summary>
internal sealed record TelemetryState(DateTimeOffset CollectedUtc, IReadOnlyDictionary<string, string?> Sections)
{
    public static IReadOnlyList<string> SectionNames { get; } =
        [TelemetrySections.BitLocker, TelemetrySections.Antivirus, TelemetrySections.Services];

    /// <summary>SQL selecting the collection time and each rule section's availability, in <see cref="SectionNames"/> order.</summary>
    public const string Columns = """
        t.CollectedUtcTicks,
        json_extract(t.ReportJson, '$.bitLocker.availability'),
        json_extract(t.ReportJson, '$.antivirus.availability'),
        json_extract(t.ReportJson, '$.services.availability')
        """;

    public static TelemetryState? Read(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal)) return null;
        var sections = new Dictionary<string, string?>(StringComparer.Ordinal);
        for (var index = 0; index < SectionNames.Count; index++)
        {
            sections[SectionNames[index]] = reader.IsDBNull(ordinal + 1 + index) ? null : reader.GetString(ordinal + 1 + index);
        }

        return new TelemetryState(new DateTimeOffset(reader.GetInt64(ordinal), TimeSpan.Zero), sections);
    }
}

/// <summary>
/// Keeps the newest accepted endpoint telemetry report per enrolled endpoint (by the Agent's collection time) and
/// raises telemetry rule findings in the same transaction, through the existing tracked-alert lifecycle.
/// </summary>
public sealed class EndpointTelemetryStore(AdminStore admins, AlertStore alerts, TelemetryRuleEngine rules, TimeProvider time)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS EndpointSecurityTelemetry (
                EndpointId TEXT NOT NULL PRIMARY KEY,
                SchemaVersion INTEGER NOT NULL,
                CollectedUtcTicks INTEGER NOT NULL,
                ReceivedUtcTicks INTEGER NOT NULL,
                ReportJson TEXT NOT NULL
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// Stores <paramref name="report"/> when its endpoint is enrolled and it is newer than the stored report, and
    /// returns whether it was stored. An older or equally old report changes nothing and raises no finding.
    /// The caller has validated the report against the contract.
    /// </summary>
    public async Task<bool> RecordLatestAsync(EndpointTelemetryReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        var endpoint = report.EndpointId.ToString("D");
        await using var upsert = connection.CreateCommand();
        upsert.Transaction = transaction;
        upsert.CommandText = """
            INSERT INTO EndpointSecurityTelemetry (EndpointId, SchemaVersion, CollectedUtcTicks, ReceivedUtcTicks, ReportJson)
            SELECT $endpointId, $schemaVersion, $collectedUtcTicks, $receivedUtcTicks, $reportJson
            WHERE EXISTS (SELECT 1 FROM EndpointEnrollments WHERE EndpointId = $endpointId)
            ON CONFLICT (EndpointId) DO UPDATE SET
                SchemaVersion = excluded.SchemaVersion,
                CollectedUtcTicks = excluded.CollectedUtcTicks,
                ReceivedUtcTicks = excluded.ReceivedUtcTicks,
                ReportJson = excluded.ReportJson
            WHERE excluded.CollectedUtcTicks > EndpointSecurityTelemetry.CollectedUtcTicks;
            """;
        upsert.Parameters.AddWithValue("$endpointId", endpoint);
        upsert.Parameters.AddWithValue("$schemaVersion", report.SchemaVersion);
        upsert.Parameters.AddWithValue("$collectedUtcTicks", report.CollectedUtc.UtcDateTime.Ticks);
        upsert.Parameters.AddWithValue("$receivedUtcTicks", time.GetUtcNow().UtcDateTime.Ticks);
        upsert.Parameters.AddWithValue("$reportJson", JsonSerializer.Serialize(report, EndpointTelemetryContract.Json));
        var stored = await upsert.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (stored)
        {
            var findings = rules.Evaluate(report);
            if (findings.Count > 0)
            {
                var name = await SecurityEventStore.ReadEndpointNameAsync(connection, transaction, report.EndpointId,
                    cancellationToken);
                foreach (var finding in findings)
                {
                    await alerts.RecordObservedAsync(connection, transaction, finding, name, cancellationToken);
                }
            }
        }

        transaction.Commit();
        return stored;
    }

    public async Task<StoredEndpointTelemetry?> FindLatestAsync(Guid endpointId, CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty)
        {
            return null;
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT ReportJson, ReceivedUtcTicks FROM EndpointSecurityTelemetry WHERE EndpointId = $endpointId;
            """;
        query.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Parse(reader.GetString(0), reader.GetInt64(1)) : null;
    }

    /// <summary>A stored report that no longer parses is treated as absent rather than shown partially.</summary>
    internal static StoredEndpointTelemetry? Parse(string json, long receivedUtcTicks)
    {
        try
        {
            return JsonSerializer.Deserialize<EndpointTelemetryReport>(json, EndpointTelemetryContract.Json) is { } report
                ? new StoredEndpointTelemetry(report, new DateTimeOffset(receivedUtcTicks, TimeSpan.Zero))
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath,
        Mode = SqliteOpenMode.ReadWrite,
        DefaultTimeout = 30,
        ForeignKeys = true
    }.ToString());
}
