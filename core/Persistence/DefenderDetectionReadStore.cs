using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Core.Persistence;

/// <summary>Administrator-only projection of the existing retained Defender malware events.</summary>
public sealed class DefenderDetectionReadStore(AdminStore admins, SecurityEventRetention retention, TimeProvider time)
{
    public async Task<DefenderDetectionsView> ReadAsync(Guid endpointId, int offset, int limit,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(offset, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, DefenderDetectionContract.MaximumOffset);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, DefenderDetectionContract.MaximumLimit);
        var now = time.GetUtcNow();
        var cutoff = now.Subtract(retention.MaxAge).UtcTicks;
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadOnly, DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        // One short deferred read transaction keeps count, page and source state consistent.
        using var transaction = connection.BeginTransaction(deferred: true);
        string sourceState = DefenderDetectionContract.NotReported;
        DateTimeOffset? sourceReported = null;
        DateTimeOffset? lastRead = null;
        await using (var source = connection.CreateCommand())
        {
            source.Transaction = transaction;
            source.CommandText = """
                SELECT StatusJson, ReceivedUtcTicks FROM SecurityEventSources
                WHERE EndpointId = $endpoint AND Channel = $channel;
                """;
            source.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
            source.Parameters.AddWithValue("$channel", SecurityEventChannels.Defender);
            await using var reader = await source.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                var status = JsonSerializer.Deserialize<SecurityEventSourceStatus>(reader.GetString(0))!;
                sourceState = status.State;
                lastRead = status.LastReadUtc;
                sourceReported = new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero);
            }
        }

        // Filter in SQLite before LIMIT, so unrelated high-volume Security events cannot
        // displace Defender history. Receipt-time age also excludes rows awaiting a sweep.
        const string predicate = """
            WHERE EndpointId = $endpoint AND Channel = $channel AND ReceivedUtcTicks >= $cutoff
                AND Kind IN ($detected, $taken, $failed)
            """;
        int total;
        await using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM SecurityEventObservations " + predicate;
            Bind(count, endpointId, cutoff);
            total = checked(Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken)));
        }

        var detections = new List<DefenderDetection>();
        await using (var page = connection.CreateCommand())
        {
            page.Transaction = transaction;
            page.CommandText = "SELECT ObservationJson, ReceivedUtcTicks FROM SecurityEventObservations " + predicate +
                " ORDER BY TimeCreatedUtcTicks DESC, Id DESC LIMIT $limit OFFSET $offset;";
            Bind(page, endpointId, cutoff);
            page.Parameters.AddWithValue("$limit", limit);
            page.Parameters.AddWithValue("$offset", offset);
            await using var reader = await page.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var observation = JsonSerializer.Deserialize<SecurityEventObservation>(reader.GetString(0))!;
                var malware = observation.Malware;
                detections.Add(new DefenderDetection(observation.TimeCreatedUtc,
                    new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero), observation.EventId, observation.Kind,
                    malware?.DetectionId, malware?.ThreatId, malware?.ThreatName, malware?.SeverityId,
                    malware?.CategoryId, malware?.ActionId, malware?.ErrorCode));
            }
        }

        transaction.Commit();
        return new DefenderDetectionsView(endpointId, now, sourceState, sourceReported, lastRead,
            checked((int)Math.Ceiling(retention.MaxAge.TotalDays)), offset, limit, total, detections);
    }

    private static void Bind(SqliteCommand command, Guid endpointId, long cutoff)
    {
        command.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        command.Parameters.AddWithValue("$channel", SecurityEventChannels.Defender);
        command.Parameters.AddWithValue("$cutoff", cutoff);
        command.Parameters.AddWithValue("$detected", SecurityEventKinds.MalwareDetected);
        command.Parameters.AddWithValue("$taken", SecurityEventKinds.MalwareActionTaken);
        command.Parameters.AddWithValue("$failed", SecurityEventKinds.MalwareActionFailed);
    }
}
