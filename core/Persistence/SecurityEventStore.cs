using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Rules;

namespace SentinelAI.Core.Persistence;

/// <summary>
/// Bounded observation and gap retention, measured by Core receipt time so endpoint clock
/// skew cannot defeat it. Installed Core always uses <see cref="Default"/>.
/// </summary>
public sealed record SecurityEventRetention(
    int MaxObservationsPerEndpoint,
    TimeSpan MaxAge,
    int SweepLimit,
    int MaxGapsPerEndpoint,
    int GapSweepLimit,
    int InitialSweepLimit)
{
    public static SecurityEventRetention Default { get; } = new(10_000, TimeSpan.FromDays(30), 500, 1_000, 100, 5_000);
}

public sealed record StoredSecurityEvent(SecurityEventObservation Observation, DateTimeOffset ReceivedUtc)
{
    public override string ToString() => nameof(StoredSecurityEvent);
}

public sealed record StoredSecurityEventGap(
    string Channel,
    string Reason,
    string? Cause,
    long FirstRecordId,
    long? LastRecordId,
    DateTimeOffset DetectedUtc,
    DateTimeOffset ReceivedUtc,
    bool CoverageRestart)
{
    public override string ToString() => nameof(StoredSecurityEventGap);
}

/// <summary>Latest reported channel status plus Core receipt metadata; never observation content.</summary>
public sealed record SecurityEventSourceView(
    string Channel,
    string State,
    int? LastErrorCode,
    long? OldestRecordId,
    long? NewestRecordId,
    long? CheckpointRecordId,
    long? LogMaximumBytes,
    DateTimeOffset? LastReadUtc,
    long Scanned,
    long Observed,
    long Delivered,
    long DroppedUnparsed,
    long DroppedOversize,
    long FieldsDiscarded,
    long Gaps,
    long SkippedRecords,
    long SeekFallbacks,
    DateTimeOffset ReportedUtc,
    DateTimeOffset AgentSentUtc,
    DateTimeOffset CountersSinceUtc,
    string AgentVersion,
    DateTimeOffset? CoveredSinceUtc,
    long StoredObservations)
{
    public override string ToString() => nameof(SecurityEventSourceView);
}

public sealed record SecurityEventGapView(
    string Channel,
    string Reason,
    string? Cause,
    long FirstRecordId,
    long? LastRecordId,
    DateTimeOffset DetectedUtc,
    DateTimeOffset ReceivedUtc,
    bool CoverageRestart)
{
    public override string ToString() => nameof(SecurityEventGapView);
}

public sealed record SecurityEventSourcesView(
    Guid EndpointId,
    IReadOnlyList<SecurityEventSourceView> Sources,
    IReadOnlyList<SecurityEventGapView> RecentGaps)
{
    public override string ToString() => nameof(SecurityEventSourcesView);
}

/// <summary>
/// Deduplicated security event observations, durable continuity gaps and the latest
/// per-channel status. Every write is one IMMEDIATE transaction without RETURNING and
/// without a reader held across commit. Stored JSON is Core's re-serialization of the
/// validated typed record, so raw request text and unknown members are never persisted.
/// </summary>
public sealed class SecurityEventStore(AdminStore admins, SecurityEventRetention retention, AlertStore alerts,
    EventRuleEngine rules, TimeProvider time)
{
    private const int RecentGapLimit = 50;
    // Rule history read per batch: the newest rows inside the longest rule window. Thresholds are far smaller.
    private const int RuleHistoryLimit = 4096;
    private const string Observations = "SecurityEventObservations";
    private const string Gaps = "SecurityEventGaps";

    private readonly SecurityEventRetention _retention = Validate(retention);

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using (var create = connection.CreateCommand())
        {
            create.CommandText = """
                CREATE TABLE IF NOT EXISTS SecurityEventObservations (
                    Id INTEGER PRIMARY KEY,
                    EndpointId TEXT NOT NULL REFERENCES EndpointEnrollments(EndpointId),
                    Channel TEXT NOT NULL CHECK (length(Channel) BETWEEN 1 AND 128),
                    Provider TEXT NOT NULL CHECK (length(Provider) BETWEEN 1 AND 128),
                    EventId INTEGER NOT NULL CHECK (EventId BETWEEN 0 AND 65535),
                    EventVersion INTEGER NOT NULL CHECK (EventVersion BETWEEN 0 AND 255),
                    RecordId INTEGER NOT NULL CHECK (RecordId > 0),
                    TimeCreatedUtcTicks INTEGER NOT NULL,
                    Kind TEXT NOT NULL CHECK (length(Kind) BETWEEN 1 AND 64),
                    Format TEXT NOT NULL,
                    ReceivedUtcTicks INTEGER NOT NULL,
                    ObservationJson TEXT NOT NULL CHECK (length(ObservationJson) <= 8192),
                    UNIQUE (EndpointId, Channel, RecordId, TimeCreatedUtcTicks)
                );
                CREATE INDEX IF NOT EXISTS IX_SecurityEventObservations_Endpoint ON SecurityEventObservations (EndpointId);
                CREATE INDEX IF NOT EXISTS IX_SecurityEventObservations_Received ON SecurityEventObservations (ReceivedUtcTicks);
                CREATE INDEX IF NOT EXISTS IX_SecurityEventObservations_Kind ON SecurityEventObservations (EndpointId, Kind, TimeCreatedUtcTicks);

                CREATE TABLE IF NOT EXISTS SecurityEventGaps (
                    Id INTEGER PRIMARY KEY,
                    EndpointId TEXT NOT NULL REFERENCES EndpointEnrollments(EndpointId),
                    Channel TEXT NOT NULL CHECK (length(Channel) BETWEEN 1 AND 128),
                    Reason TEXT NOT NULL CHECK (Reason IN ('overwritten','logReset','coverageStarted','dropped','rejected')),
                    Cause TEXT NULL CHECK (Cause IS NULL OR Cause IN ('noCheckpoint','checkpointInvalid','endpointChanged')),
                    FirstRecordId INTEGER NOT NULL CHECK (FirstRecordId > 0),
                    LastRecordId INTEGER NULL CHECK (LastRecordId IS NULL OR LastRecordId >= FirstRecordId),
                    CoverageRestart INTEGER NOT NULL CHECK (CoverageRestart IN (0,1)),
                    DetectedUtcTicks INTEGER NOT NULL,
                    ReceivedUtcTicks INTEGER NOT NULL,
                    UNIQUE (EndpointId, Channel, Reason, FirstRecordId)
                );
                CREATE INDEX IF NOT EXISTS IX_SecurityEventGaps_Endpoint ON SecurityEventGaps (EndpointId);
                CREATE INDEX IF NOT EXISTS IX_SecurityEventGaps_Received ON SecurityEventGaps (ReceivedUtcTicks);

                CREATE TABLE IF NOT EXISTS SecurityEventSources (
                    EndpointId TEXT NOT NULL REFERENCES EndpointEnrollments(EndpointId),
                    Channel TEXT NOT NULL CHECK (length(Channel) BETWEEN 1 AND 128),
                    State TEXT NOT NULL CHECK (State IN ('collecting','disabled','accessDenied','notFound','error')),
                    CheckpointRecordId INTEGER NULL,
                    CoveredSinceUtcTicks INTEGER NULL,
                    AgentVersion TEXT NOT NULL,
                    AgentSentUtcTicks INTEGER NOT NULL,
                    CountersSinceUtcTicks INTEGER NOT NULL,
                    ReceivedUtcTicks INTEGER NOT NULL,
                    StatusJson TEXT NOT NULL CHECK (length(StatusJson) <= 4096),
                    PRIMARY KEY (EndpointId, Channel)
                );
                """;
            await create.ExecuteNonQueryAsync(cancellationToken);
        }

        // One bounded global sweep at startup also ages out endpoints that stopped reporting.
        var cutoff = time.GetUtcNow().UtcTicks - _retention.MaxAge.Ticks;
        using var transaction = connection.BeginTransaction(deferred: false);
        await SweepAsync(connection, transaction, Observations, cutoff, _retention.InitialSweepLimit, cancellationToken);
        await SweepAsync(connection, transaction, Gaps, cutoff, _retention.InitialSweepLimit, cancellationToken);
        transaction.Commit();
    }

    /// <summary>
    /// Stores one authenticated batch atomically. Unknown items are ignored, invalid items are
    /// rejected individually (an invalid observation also becomes a durable "rejected" gap row),
    /// and Accepted/Duplicates count newly stored versus already present observations.
    /// </summary>
    public async Task<SecurityEventBatchResult> RecordAsync(
        Guid endpointId,
        SecurityEventBatch batch,
        CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty || !SecurityEventContract.IsValidEnvelope(batch) || batch.EndpointId != endpointId)
        {
            throw new ArgumentException("The security event batch envelope is invalid for this endpoint.", nameof(batch));
        }

        var endpoint = endpointId.ToString("D");
        var received = time.GetUtcNow().UtcTicks;
        int accepted = 0, duplicates = 0, ignored = 0, rejected = 0, gapsWritten = 0;
        var added = new List<SecurityEventObservation>();

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var gap = Prepare(connection, transaction, """
            INSERT INTO SecurityEventGaps (EndpointId, Channel, Reason, Cause, FirstRecordId, LastRecordId,
                CoverageRestart, DetectedUtcTicks, ReceivedUtcTicks)
            SELECT $e, $channel, $reason, $cause, $first, $last,
                CASE WHEN $reason = 'coverageStarted' AND EXISTS (SELECT 1 FROM SecurityEventSources
                    WHERE EndpointId = $e AND Channel = $channel AND CoveredSinceUtcTicks IS NOT NULL) THEN 1 ELSE 0 END,
                $detected, $received
            WHERE EXISTS (SELECT 1 FROM EndpointEnrollments WHERE EndpointId = $e)
            ON CONFLICT (EndpointId, Channel, Reason, FirstRecordId) DO UPDATE SET
                LastRecordId = CASE WHEN SecurityEventGaps.LastRecordId IS NULL OR excluded.LastRecordId IS NULL
                    THEN coalesce(SecurityEventGaps.LastRecordId, excluded.LastRecordId)
                    ELSE max(SecurityEventGaps.LastRecordId, excluded.LastRecordId) END;
            """, endpoint, received, "$channel", "$reason", "$cause", "$first", "$last", "$detected");
        await using var observation = Prepare(connection, transaction, """
            INSERT INTO SecurityEventObservations (EndpointId, Channel, Provider, EventId, EventVersion, RecordId,
                TimeCreatedUtcTicks, Kind, Format, ReceivedUtcTicks, ObservationJson)
            SELECT $e, $channel, $provider, $eventId, $eventVersion, $recordId, $timeTicks, $kind, $format, $received, $json
            WHERE EXISTS (SELECT 1 FROM EndpointEnrollments WHERE EndpointId = $e)
            ON CONFLICT (EndpointId, Channel, RecordId, TimeCreatedUtcTicks) DO NOTHING;
            """, endpoint, received, "$channel", "$provider", "$eventId", "$eventVersion", "$recordId", "$timeTicks",
            "$kind", "$format", "$json");
        await using var source = Prepare(connection, transaction, """
            INSERT INTO SecurityEventSources (EndpointId, Channel, State, CheckpointRecordId, CoveredSinceUtcTicks,
                AgentVersion, AgentSentUtcTicks, CountersSinceUtcTicks, ReceivedUtcTicks, StatusJson)
            SELECT $e, $channel, $state, $checkpoint, CASE WHEN $checkpoint IS NOT NULL THEN $received END,
                $agentVersion, $sent, $since, $received, $json
            WHERE EXISTS (SELECT 1 FROM EndpointEnrollments WHERE EndpointId = $e)
            ON CONFLICT (EndpointId, Channel) DO UPDATE SET
                State = excluded.State, CheckpointRecordId = excluded.CheckpointRecordId,
                CoveredSinceUtcTicks = coalesce(SecurityEventSources.CoveredSinceUtcTicks, excluded.CoveredSinceUtcTicks),
                AgentVersion = excluded.AgentVersion, AgentSentUtcTicks = excluded.AgentSentUtcTicks,
                CountersSinceUtcTicks = excluded.CountersSinceUtcTicks, ReceivedUtcTicks = excluded.ReceivedUtcTicks,
                StatusJson = excluded.StatusJson
            WHERE excluded.CountersSinceUtcTicks <> SecurityEventSources.CountersSinceUtcTicks
               OR excluded.AgentSentUtcTicks >= SecurityEventSources.AgentSentUtcTicks;
            """, endpoint, received, "$channel", "$state", "$checkpoint", "$agentVersion", "$sent", "$since", "$json");

        async Task WriteGapAsync(string channel, string reason, string? cause, long first, long? last, long detectedTicks)
        {
            Bind(gap, "$channel", channel);
            Bind(gap, "$reason", reason);
            Bind(gap, "$cause", cause);
            Bind(gap, "$first", first);
            Bind(gap, "$last", last);
            Bind(gap, "$detected", detectedTicks);
            gapsWritten += await gap.ExecuteNonQueryAsync(cancellationToken);
        }

        // 1. Gaps first, so CoverageRestart sees coverage as it was before this batch's statuses.
        foreach (var item in batch.Gaps)
        {
            switch (SecurityEventContract.Classify(item))
            {
                case SecurityEventItemValidity.Unknown: ignored++; break;
                case SecurityEventItemValidity.Invalid: rejected++; break;
                default:
                    await WriteGapAsync(item.Channel, item.Reason, item.Cause, item.FirstRecordId, item.LastRecordId,
                        item.DetectedUtc.UtcTicks);
                    break;
            }
        }

        // 2. Observations, deduplicated by (endpoint, channel, record, event time).
        foreach (var item in batch.Events)
        {
            var validity = SecurityEventContract.Classify(item);
            if (validity == SecurityEventItemValidity.Unknown)
            {
                ignored++;
                continue;
            }
            if (validity == SecurityEventItemValidity.Invalid)
            {
                rejected++;
                if (SecurityEventChannels.All.Contains(item.Channel, StringComparer.Ordinal) && item.RecordId > 0)
                {
                    await WriteGapAsync(item.Channel, SecurityEventGapReasons.Rejected, null, item.RecordId, item.RecordId, received);
                }
                continue;
            }

            Bind(observation, "$channel", item.Channel);
            Bind(observation, "$provider", item.Provider);
            Bind(observation, "$eventId", item.EventId);
            Bind(observation, "$eventVersion", item.EventVersion);
            Bind(observation, "$recordId", item.RecordId);
            Bind(observation, "$timeTicks", item.TimeCreatedUtc.UtcTicks);
            Bind(observation, "$kind", item.Kind);
            Bind(observation, "$format", batch.Format);
            Bind(observation, "$json", JsonSerializer.Serialize(item));
            if (await observation.ExecuteNonQueryAsync(cancellationToken) == 1)
            {
                accepted++;
                added.Add(item);
            }
            else duplicates++;
        }

        // 2b. Runtime rules over the newly stored observations, in this transaction: an observation and the
        // alert it raises commit together, and a replayed duplicate never fires again.
        if (added.Any(item => rules.IsTrigger(item.Kind)))
        {
            await EvaluateRulesAsync(connection, transaction, endpointId, added, received, cancellationToken);
        }

        // 3. Latest status per channel; an older attempt of the same Agent process never wins.
        foreach (var item in batch.Sources)
        {
            switch (SecurityEventContract.Classify(item))
            {
                case SecurityEventItemValidity.Unknown: ignored++; break;
                case SecurityEventItemValidity.Invalid: rejected++; break;
                default:
                    Bind(source, "$channel", item.Channel);
                    Bind(source, "$state", item.State);
                    Bind(source, "$checkpoint", item.CheckpointRecordId);
                    Bind(source, "$agentVersion", batch.AgentVersion);
                    Bind(source, "$sent", batch.SentUtc.UtcTicks);
                    Bind(source, "$since", batch.CountersSinceUtc.UtcTicks);
                    Bind(source, "$json", JsonSerializer.Serialize(item));
                    await source.ExecuteNonQueryAsync(cancellationToken);
                    break;
            }
        }

        // 4. Bounded retention: per-endpoint caps for what this batch added, then the global age sweep.
        if (accepted > 0)
        {
            await CapAsync(connection, transaction, Observations, endpoint, _retention.MaxObservationsPerEndpoint, cancellationToken);
        }
        if (gapsWritten > 0)
        {
            await CapAsync(connection, transaction, Gaps, endpoint, _retention.MaxGapsPerEndpoint, cancellationToken);
        }
        var cutoff = received - _retention.MaxAge.Ticks;
        await SweepAsync(connection, transaction, Observations, cutoff, _retention.SweepLimit, cancellationToken);
        await SweepAsync(connection, transaction, Gaps, cutoff, _retention.GapSweepLimit, cancellationToken);

        transaction.Commit();
        return new SecurityEventBatchResult(accepted, duplicates, ignored, rejected);
    }

    public async Task<long> CountAsync(Guid endpointId, CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT COUNT(*) FROM SecurityEventObservations WHERE EndpointId = $e;";
        query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        return (long)(await query.ExecuteScalarAsync(cancellationToken))!;
    }

    /// <summary>Newest stored observations first (internal consumers and tests; no admin route returns content).</summary>
    public async Task<IReadOnlyList<StoredSecurityEvent>> ListRecentAsync(
        Guid endpointId, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 1000);
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT ObservationJson, ReceivedUtcTicks FROM SecurityEventObservations
            WHERE EndpointId = $e ORDER BY Id DESC LIMIT $limit;
            """;
        query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        query.Parameters.AddWithValue("$limit", limit);
        var events = new List<StoredSecurityEvent>();
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(new StoredSecurityEvent(
                JsonSerializer.Deserialize<SecurityEventObservation>(reader.GetString(0))!,
                new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero)));
        }

        return events;
    }

    public async Task<IReadOnlyList<StoredSecurityEventGap>> ListGapsAsync(
        Guid endpointId, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 500);
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT Channel, Reason, Cause, FirstRecordId, LastRecordId, DetectedUtcTicks, ReceivedUtcTicks, CoverageRestart
            FROM SecurityEventGaps WHERE EndpointId = $e ORDER BY Id DESC LIMIT $limit;
            """;
        query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        query.Parameters.AddWithValue("$limit", limit);
        var gaps = new List<StoredSecurityEventGap>();
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            gaps.Add(new StoredSecurityEventGap(
                reader.GetString(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.GetInt64(3),
                reader.IsDBNull(4) ? null : reader.GetInt64(4),
                new DateTimeOffset(reader.GetInt64(5), TimeSpan.Zero),
                new DateTimeOffset(reader.GetInt64(6), TimeSpan.Zero),
                reader.GetInt64(7) == 1));
        }

        return gaps;
    }

    public async Task<IReadOnlyList<SecurityEventSourceView>> ListSourcesAsync(
        Guid endpointId, CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT s.StatusJson, s.ReceivedUtcTicks, s.AgentSentUtcTicks, s.CountersSinceUtcTicks, s.AgentVersion,
                s.CoveredSinceUtcTicks,
                (SELECT COUNT(*) FROM SecurityEventObservations AS o
                 WHERE o.EndpointId = s.EndpointId AND o.Channel = s.Channel)
            FROM SecurityEventSources AS s WHERE s.EndpointId = $e ORDER BY s.Channel;
            """;
        query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        var sources = new List<SecurityEventSourceView>();
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var s = JsonSerializer.Deserialize<SecurityEventSourceStatus>(reader.GetString(0))!;
            sources.Add(new SecurityEventSourceView(
                s.Channel, s.State, s.LastErrorCode, s.OldestRecordId, s.NewestRecordId, s.CheckpointRecordId,
                s.LogMaximumBytes, s.LastReadUtc, s.Scanned, s.Observed, s.Delivered, s.DroppedUnparsed,
                s.DroppedOversize, s.FieldsDiscarded, s.Gaps, s.SkippedRecords, s.SeekFallbacks,
                new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero),
                new DateTimeOffset(reader.GetInt64(2), TimeSpan.Zero),
                new DateTimeOffset(reader.GetInt64(3), TimeSpan.Zero),
                reader.GetString(4),
                reader.IsDBNull(5) ? null : new DateTimeOffset(reader.GetInt64(5), TimeSpan.Zero),
                reader.GetInt64(6)));
        }

        return sources;
    }

    /// <summary>Status-only view for the administrator route: states, counters, record numbers and gap metadata.</summary>
    public async Task<SecurityEventSourcesView> GetSourcesViewAsync(
        Guid endpointId, CancellationToken cancellationToken = default)
    {
        var sources = await ListSourcesAsync(endpointId, cancellationToken);
        var gaps = await ListGapsAsync(endpointId, RecentGapLimit, cancellationToken);
        return new SecurityEventSourcesView(endpointId, sources, gaps.Select(gap => new SecurityEventGapView(
            gap.Channel, gap.Reason, gap.Cause, gap.FirstRecordId, gap.LastRecordId, gap.DetectedUtc, gap.ReceivedUtc,
            gap.CoverageRestart)).ToArray());
    }

    private static SqliteCommand Prepare(SqliteConnection connection, SqliteTransaction transaction, string sql,
        string endpoint, long received, params string[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$e", endpoint);
        command.Parameters.AddWithValue("$received", received);
        foreach (var name in parameters)
        {
            command.Parameters.AddWithValue(name, DBNull.Value);
        }
        command.Prepare();
        return command;
    }

    private static void Bind(SqliteCommand command, string name, object? value) =>
        command.Parameters[name].Value = value ?? DBNull.Value;

    // Table names are compile-time constants; every value is a bound parameter.
    private async Task EvaluateRulesAsync(SqliteConnection connection, SqliteTransaction transaction, Guid endpointId,
        IReadOnlyList<SecurityEventObservation> added, long receivedTicks, CancellationToken cancellationToken)
    {
        // Events are ordered by their time clamped to receipt, so a future-dated event cannot fire early; the engine
        // also checks window membership against the Agent's own event times.
        var receivedUtc = new DateTimeOffset(receivedTicks, TimeSpan.Zero);
        var triggers = added.Select(item => EventRuleObservation.Clamped(item, receivedUtc)).ToArray();
        var history = new List<EventRuleObservation>();
        if (rules.HistoryKinds.Count > 0)
        {
            var from = (triggers.Min(item => item.EffectiveUtc) - rules.MaximumHistoryWindow).UtcTicks;
            var kinds = rules.HistoryKinds.Select((_, index) => "$kind" + index.ToString(CultureInfo.InvariantCulture)).ToArray();
            await using var query = connection.CreateCommand();
            query.Transaction = transaction;
            // min(event time, receipt) > from exactly when both are.
            query.CommandText =
                "SELECT ObservationJson, ReceivedUtcTicks FROM SecurityEventObservations " +
                "WHERE EndpointId = $e AND Kind IN (" + string.Join(", ", kinds) + ") " +
                "AND TimeCreatedUtcTicks > $from AND ReceivedUtcTicks > $from " +
                "ORDER BY TimeCreatedUtcTicks DESC, Id DESC LIMIT $limit;";
            query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
            query.Parameters.AddWithValue("$from", from);
            query.Parameters.AddWithValue("$limit", RuleHistoryLimit);
            for (var index = 0; index < kinds.Length; index++) query.Parameters.AddWithValue(kinds[index], rules.HistoryKinds[index]);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                history.Add(EventRuleObservation.Clamped(
                    JsonSerializer.Deserialize<SecurityEventObservation>(reader.GetString(0))!,
                    new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero)));
            }
        }

        var findings = rules.Evaluate(endpointId, triggers, history);
        if (findings.Count == 0) return;
        var endpointName = await ReadEndpointNameAsync(connection, transaction, endpointId, cancellationToken);
        foreach (var finding in findings.OrderBy(item => item.Timestamp))
        {
            await alerts.RecordObservedAsync(connection, transaction, finding, endpointName, cancellationToken);
        }
    }

    private static async Task<string> ReadEndpointNameAsync(SqliteConnection connection, SqliteTransaction transaction,
        Guid endpointId, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = "SELECT ReportJson FROM EndpointInventories WHERE EndpointId = $e;";
        query.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        if (await query.ExecuteScalarAsync(cancellationToken) is string json &&
            JsonSerializer.Deserialize<InventoryReport>(json)?.Hostname is { Length: > 0 } hostname)
        {
            return hostname;
        }

        return PlaceholderEndpointName(endpointId);
    }

    /// <summary>The fallback name the device views use before the first inventory; the inventory replaces it on alerts.</summary>
    internal static string PlaceholderEndpointName(Guid endpointId) => $"Endpoint {endpointId.ToString("N")[..8]}";

    private static async Task CapAsync(SqliteConnection connection, SqliteTransaction transaction, string table,
        string endpoint, int maximum, CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = $"""
            DELETE FROM {table} WHERE EndpointId = $e AND Id <= (
                SELECT Id FROM {table} WHERE EndpointId = $e ORDER BY Id DESC LIMIT 1 OFFSET $maximum);
            """;
        delete.Parameters.AddWithValue("$e", endpoint);
        delete.Parameters.AddWithValue("$maximum", maximum);
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task SweepAsync(SqliteConnection connection, SqliteTransaction transaction, string table,
        long cutoffTicks, int limit, CancellationToken cancellationToken)
    {
        await using var delete = connection.CreateCommand();
        delete.Transaction = transaction;
        delete.CommandText = $"""
            DELETE FROM {table} WHERE Id IN (
                SELECT Id FROM {table} WHERE ReceivedUtcTicks < $cutoff ORDER BY ReceivedUtcTicks LIMIT $limit);
            """;
        delete.Parameters.AddWithValue("$cutoff", cutoffTicks);
        delete.Parameters.AddWithValue("$limit", limit);
        await delete.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SecurityEventRetention Validate(SecurityEventRetention retention)
    {
        if (retention.MaxObservationsPerEndpoint < 1 || retention.MaxAge <= TimeSpan.Zero || retention.SweepLimit < 1 ||
            retention.MaxGapsPerEndpoint < 1 || retention.GapSweepLimit < 1 || retention.InitialSweepLimit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(retention), "Security event retention bounds must be positive.");
        }

        return retention;
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
