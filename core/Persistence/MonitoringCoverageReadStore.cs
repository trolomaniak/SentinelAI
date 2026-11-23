using System.Globalization;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Core.Persistence;

/// <summary>Read-only coverage of the inputs already stored by Core.</summary>
internal sealed class MonitoringCoverageReadStore(AdminStore admins, RiskScoringOptions risk, SecurityEventRetention retention,
    TimeProvider time)
{
    private const int MaximumNameLength = 128;
    private const string ActiveEndpoint = "e.RemovedUtcTicks IS NULL";
    private const string EndpointMatch = " AND e.EndpointId = $endpoint";
    private const string RetainedGap = "g.EndpointId = $endpoint AND g.ReceivedUtcTicks >= $gapCutoff";
    private const string SummaryColumns = "EndpointId, Name, HeartbeatState, Heartbeat, InventoryFreshness, InventoryCollected, " +
        "TelemetryFreshness, TelemetryCollected, TelemetryReceived, CurrentTelemetrySources, CurrentEventChannels, HasRetainedGaps, HasIssue";

    // Each path corresponds to a fixed source ID in the shared contract. The two Windows Update probes have
    // independent availability fields in the same report section.
    private static readonly string[] TelemetryProjections = MonitoringCoverageContract.TelemetrySourceIds.Select(id =>
        "json_extract(TelemetryJson, '$." + (id switch
        {
            "windowsUpdatePolicy" => "windowsUpdate.policyAvailability",
            "windowsUpdateResults" => "windowsUpdate.resultsAvailability",
            _ => id + ".availability"
        }) + "')").ToArray();

    private static readonly string TelemetryCount = string.Join(" + ", TelemetryProjections.Select(projection =>
        $"CASE WHEN {projection} = $collected THEN 1 ELSE 0 END"));

    private static readonly string ChannelParameters = string.Join(", ", SecurityEventChannels.All.Select((_, index) => $"$channel{index}"));

    private static readonly string ListFacts = EndpointFacts(string.Empty);
    private static readonly string DetailFacts = EndpointFacts(EndpointMatch);

    private int RetentionDays => checked((int)Math.Ceiling(retention.MaxAge.TotalDays));

    public async Task<MonitoringEndpointPage> ListAsync(int offset, int limit, bool issuesOnly, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var total = await CountAsync(connection, transaction, "SELECT COUNT(*) FROM EndpointEnrollments AS e WHERE " + ActiveEndpoint,
            cancellationToken);
        var predicate = issuesOnly ? " WHERE HasIssue = 1" : string.Empty;
        var matching = total;
        if (issuesOnly)
        {
            await using var count = Command(connection, transaction, ListFacts + "SELECT COUNT(*) FROM coverage" + predicate);
            BindFacts(count, now);
            matching = checked(Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture));
        }

        var items = new List<MonitoringEndpointSummary>();
        if (offset < matching)
        {
            await using var page = Command(connection, transaction, ListFacts + "SELECT " + SummaryColumns + " FROM coverage" +
                predicate + " ORDER BY EndpointId LIMIT $limit OFFSET $offset;");
            BindFacts(page, now);
            BindPage(page, offset, limit);
            await using var reader = await page.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) items.Add(ReadSummary(reader));
        }

        transaction.Commit();
        return new MonitoringEndpointPage(now, total, matching, offset, limit, risk.InventoryFreshForHours, items);
    }

    public async Task<MonitoringEndpointDetail?> FindAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        MonitoringEndpointSummary endpoint;
        await using (var query = Command(connection, transaction, DetailFacts + "SELECT " + SummaryColumns + " FROM coverage;"))
        {
            BindFacts(query, now);
            query.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return null;
            endpoint = ReadSummary(reader);
        }

        var telemetry = await ReadTelemetryAsync(connection, transaction, endpoint, cancellationToken);
        var events = await ReadEventsAsync(connection, transaction, endpointId, now, cancellationToken);
        transaction.Commit();
        return new MonitoringEndpointDetail(now, endpoint, risk.InventoryFreshForHours, RetentionDays, telemetry, events);
    }

    public async Task<MonitoringGapPage?> ListGapsAsync(Guid endpointId, int offset, int limit, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var id = endpointId.ToString("D");
        var cutoff = now.UtcTicks - retention.MaxAge.Ticks;
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var active = await CountAsync(connection, transaction, "SELECT COUNT(*) FROM EndpointEnrollments AS e WHERE " + ActiveEndpoint +
            EndpointMatch, cancellationToken, ("$endpoint", id));
        if (active == 0) return null;

        var total = await CountAsync(connection, transaction, "SELECT COUNT(*) FROM SecurityEventGaps AS g WHERE " + RetainedGap,
            cancellationToken, ("$endpoint", id), ("$gapCutoff", cutoff));
        var items = new List<MonitoringCoverageGap>();
        if (offset < total)
        {
            await using var page = Command(connection, transaction, """
                SELECT g.Channel, g.Reason, g.Cause, g.FirstRecordId, g.LastRecordId, g.DetectedUtcTicks,
                       g.ReceivedUtcTicks, g.CoverageRestart FROM SecurityEventGaps AS g WHERE
                """ + " " + RetainedGap + " ORDER BY g.Id DESC LIMIT $limit OFFSET $offset;");
            page.Parameters.AddWithValue("$endpoint", id);
            page.Parameters.AddWithValue("$gapCutoff", cutoff);
            BindPage(page, offset, limit);
            await using var reader = await page.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                items.Add(new MonitoringCoverageGap(reader.GetString(0), reader.GetString(1), ReadText(reader, 2), reader.GetInt64(3),
                    ReadInteger(reader, 4), new DateTimeOffset(reader.GetInt64(5), TimeSpan.Zero),
                    new DateTimeOffset(reader.GetInt64(6), TimeSpan.Zero), reader.GetBoolean(7)));
        }

        transaction.Commit();
        return new MonitoringGapPage(now, endpointId, total, offset, limit, RetentionDays, items);
    }

    private static string EndpointFacts(string endpointMatch) => $"""
        WITH facts AS (
            SELECT e.EndpointId,
                   CASE WHEN json_valid(i.ReportJson) THEN json_extract(i.ReportJson, '$.Hostname') END AS Name,
                   d.LastSeenUtcTicks AS Heartbeat, i.CollectedUtcTicks AS InventoryCollected,
                   t.CollectedUtcTicks AS TelemetryCollected, t.ReceivedUtcTicks AS TelemetryReceived,
                   CASE WHEN json_valid(t.ReportJson) THEN t.ReportJson END AS TelemetryJson,
                   (SELECT COUNT(*) FROM SecurityEventSources AS s WHERE s.EndpointId = e.EndpointId
                       AND s.Channel IN ({ChannelParameters}) AND s.State = $collecting
                       AND s.ReceivedUtcTicks BETWEEN $eventCutoff AND $now) AS CurrentEventChannels,
                   EXISTS(SELECT 1 FROM SecurityEventGaps AS g WHERE g.EndpointId = e.EndpointId
                       AND g.ReceivedUtcTicks >= $gapCutoff
                       AND (g.Reason <> $started OR g.CoverageRestart = 1)) AS HasRetainedGaps
            FROM EndpointEnrollments AS e
            LEFT JOIN Devices AS d ON d.InstallationId = e.InstallationId
            LEFT JOIN EndpointInventories AS i ON i.EndpointId = e.EndpointId
            LEFT JOIN EndpointSecurityTelemetry AS t ON t.EndpointId = e.EndpointId
            WHERE {ActiveEndpoint}{endpointMatch}
        ), states AS (
            SELECT EndpointId, Name, Heartbeat, InventoryCollected, TelemetryCollected, TelemetryReceived,
                CurrentEventChannels, HasRetainedGaps,
                CASE WHEN Heartbeat IS NULL THEN 'unknown' WHEN Heartbeat > $now THEN 'future'
                     WHEN Heartbeat >= $heartbeatWarning THEN 'healthy' WHEN Heartbeat >= $heartbeatOffline THEN 'warning'
                     ELSE 'offline' END AS HeartbeatState,
                CASE WHEN InventoryCollected IS NULL THEN 'missing' WHEN InventoryCollected > $now THEN 'future'
                     WHEN InventoryCollected < $inventoryCutoff THEN 'stale' ELSE 'current' END AS InventoryFreshness,
                CASE WHEN TelemetryCollected IS NULL THEN 'missing' WHEN TelemetryCollected > $now THEN 'future'
                     WHEN TelemetryCollected < $telemetryCutoff THEN 'stale' ELSE 'current' END AS TelemetryFreshness,
                CASE WHEN TelemetryCollected BETWEEN $telemetryCutoff AND $now THEN {TelemetryCount}
                     ELSE 0 END AS CurrentTelemetrySources
            FROM facts
        ), coverage AS (
            SELECT *, (HeartbeatState <> 'healthy' OR InventoryFreshness <> 'current' OR TelemetryFreshness <> 'current'
                OR CurrentTelemetrySources < {TelemetryProjections.Length} OR CurrentEventChannels < {SecurityEventChannels.All.Count}
                OR HasRetainedGaps) AS HasIssue
            FROM states
        )
        """ + " ";

    private void BindFacts(SqliteCommand command, DateTimeOffset now)
    {
        command.Parameters.AddWithValue("$now", now.UtcTicks);
        command.Parameters.AddWithValue("$heartbeatWarning", now.AddMinutes(-MonitoringCoverageContract.HeartbeatWarningMinutes).UtcTicks);
        command.Parameters.AddWithValue("$heartbeatOffline", now.AddMinutes(-MonitoringCoverageContract.HeartbeatOfflineMinutes).UtcTicks);
        command.Parameters.AddWithValue("$inventoryCutoff", now.AddHours(-risk.InventoryFreshForHours).UtcTicks);
        command.Parameters.AddWithValue("$telemetryCutoff", now.AddHours(-MonitoringCoverageContract.TelemetryFreshHours).UtcTicks);
        command.Parameters.AddWithValue("$eventCutoff", now.AddHours(-MonitoringCoverageContract.EventFreshHours).UtcTicks);
        command.Parameters.AddWithValue("$gapCutoff", now.UtcTicks - retention.MaxAge.Ticks);
        command.Parameters.AddWithValue("$collected", TelemetryAvailability.Collected);
        command.Parameters.AddWithValue("$collecting", SecurityEventSourceStates.Collecting);
        command.Parameters.AddWithValue("$started", SecurityEventGapReasons.CoverageStarted);
        for (var index = 0; index < SecurityEventChannels.All.Count; index++)
            command.Parameters.AddWithValue($"$channel{index}", SecurityEventChannels.All[index]);
    }

    private static MonitoringEndpointSummary ReadSummary(SqliteDataReader reader)
    {
        var id = Guid.Parse(reader.GetString(0));
        return new MonitoringEndpointSummary(id, EndpointName(id, ReadText(reader, 1)), reader.GetString(2), ReadUtc(reader, 3),
            reader.GetString(4), ReadUtc(reader, 5), reader.GetString(6), ReadUtc(reader, 7), ReadUtc(reader, 8), reader.GetInt32(9),
            reader.GetInt32(10), reader.GetBoolean(11), reader.GetBoolean(12));
    }

    private static string EndpointName(Guid endpointId, string? name)
    {
        if (name is { Length: > 0 })
        {
            var length = Math.Min(name.Length, MaximumNameLength);
            if (char.IsHighSurrogate(name[length - 1])) length--;
            var bounded = name[..length].Trim();
            if (SecurityEventContract.IsBoundedText(bounded, MaximumNameLength)) return bounded;
        }
        return SecurityEventStore.PlaceholderEndpointName(endpointId);
    }

    private static async Task<IReadOnlyList<MonitoringTelemetrySource>> ReadTelemetryAsync(SqliteConnection connection,
        SqliteTransaction transaction, MonitoringEndpointSummary endpoint, CancellationToken cancellationToken)
    {
        await using var query = Command(connection, transaction, "SELECT " + string.Join(", ", TelemetryProjections) + """

            FROM (SELECT CASE WHEN json_valid(ReportJson) THEN ReportJson END AS TelemetryJson
                  FROM EndpointSecurityTelemetry WHERE EndpointId = $endpoint);
            """);
        query.Parameters.AddWithValue("$endpoint", endpoint.EndpointId.ToString("D"));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        var reported = await reader.ReadAsync(cancellationToken);
        return MonitoringCoverageContract.TelemetrySourceIds.Select((id, index) =>
        {
            var state = reported ? ReadText(reader, index) : null;
            return new MonitoringTelemetrySource(id, state is not null && TelemetryAvailability.All.Contains(state, StringComparer.Ordinal)
                ? state : "unknown", endpoint.TelemetryFreshness);
        }).ToArray();
    }

    private static async Task<IReadOnlyList<MonitoringEventChannel>> ReadEventsAsync(SqliteConnection connection,
        SqliteTransaction transaction, Guid endpointId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var query = Command(connection, transaction, """
            SELECT Channel, State, ReceivedUtcTicks, CoveredSinceUtcTicks, CheckpointRecordId, CountersSinceUtcTicks,
                   json_extract(Status, '$.LastReadUtc'), json_extract(Status, '$.Gaps'), json_extract(Status, '$.SkippedRecords'),
                   json_extract(Status, '$.DroppedUnparsed'), json_extract(Status, '$.DroppedOversize')
            FROM (SELECT Channel, State, ReceivedUtcTicks, CoveredSinceUtcTicks, CheckpointRecordId, CountersSinceUtcTicks,
                         CASE WHEN json_valid(StatusJson) THEN StatusJson END AS Status
                  FROM SecurityEventSources WHERE EndpointId = $endpoint);
            """);
        query.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        var channels = new Dictionary<string, MonitoringEventChannel>(StringComparer.Ordinal);
        var cutoff = now.AddHours(-MonitoringCoverageContract.EventFreshHours);
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var channel = reader.GetString(0);
            var reported = new DateTimeOffset(reader.GetInt64(2), TimeSpan.Zero);
            var freshness = reported > now ? "future" : reported < cutoff ? "stale" : "current";
            var lastRead = DateTimeOffset.TryParse(ReadText(reader, 6), CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
                ? parsed.ToUniversalTime() : (DateTimeOffset?)null;
            channels.Add(channel, new MonitoringEventChannel(channel, reader.GetString(1), freshness, reported, lastRead,
                ReadUtc(reader, 3), ReadInteger(reader, 4), ReadUtc(reader, 5), ReadInteger(reader, 7), ReadInteger(reader, 8),
                ReadInteger(reader, 9), ReadInteger(reader, 10)));
        }
        return SecurityEventChannels.All.Select(channel => channels.GetValueOrDefault(channel) ??
            new MonitoringEventChannel(channel, "unknown", "missing", null, null, null, null, null, null, null, null, null)).ToArray();
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath,
        Mode = SqliteOpenMode.ReadOnly,
        DefaultTimeout = 30
    }.ToString());

    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command;
    }

    private static async Task<int> CountAsync(SqliteConnection connection, SqliteTransaction transaction, string sql,
        CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var count = Command(connection, transaction, sql);
        foreach (var parameter in parameters) count.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return checked(Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture));
    }

    private static void BindPage(SqliteCommand command, int offset, int limit)
    {
        command.Parameters.AddWithValue("$offset", offset);
        command.Parameters.AddWithValue("$limit", limit);
    }

    private static string? ReadText(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static long? ReadInteger(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    private static DateTimeOffset? ReadUtc(SqliteDataReader reader, int ordinal) => ReadInteger(reader, ordinal) is { } ticks
        ? new DateTimeOffset(ticks, TimeSpan.Zero) : null;
}
