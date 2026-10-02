using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Rules;

namespace SentinelAI.Core.Persistence;

public enum AlertStatusUpdateOutcome { Updated, NotFound, Conflict }

public sealed record AlertStatusUpdateResult(AlertStatusUpdateOutcome Outcome, AlertDetail? Alert);

/// <summary>A durable lifecycle for each endpoint/rule, separate from current rule findings.</summary>
public sealed class AlertStore(AdminStore admins)
{
    private const string SelectColumns = """
        AlertId, EndpointId, EndpointName, RuleId, Title, Severity, Status,
        FirstObservedUtcTicks, LastObservedUtcTicks, UpdatedUtcTicks, Version,
        Reason, EvidenceJson, RecommendedAction, CreatedUtcTicks, StatusChangedUtcTicks
        """;

    public static bool IsValidSeverity(string? value) => value is "info" or "low" or "medium" or "high" or "critical";

    public static bool IsValidStatus(string? value) => value is "open" or "investigating" or "resolved" or "accepted";

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS TrackedAlerts (
                AlertId TEXT NOT NULL PRIMARY KEY,
                EndpointId TEXT NOT NULL REFERENCES EndpointEnrollments(EndpointId),
                EndpointName TEXT NOT NULL,
                RuleId TEXT NOT NULL,
                Title TEXT NOT NULL,
                Severity TEXT NOT NULL,
                Status TEXT NOT NULL CHECK (Status IN ('open', 'investigating', 'resolved', 'accepted')),
                FirstObservedUtcTicks INTEGER NOT NULL,
                LastObservedUtcTicks INTEGER NOT NULL,
                CreatedUtcTicks INTEGER NOT NULL,
                UpdatedUtcTicks INTEGER NOT NULL,
                StatusChangedUtcTicks INTEGER NOT NULL,
                Version INTEGER NOT NULL,
                Reason TEXT NOT NULL,
                EvidenceJson TEXT NOT NULL,
                RecommendedAction TEXT NOT NULL,
                UNIQUE (EndpointId, RuleId)
            );
            CREATE TABLE IF NOT EXISTS AlertStatusHistory (
                SequenceId INTEGER PRIMARY KEY AUTOINCREMENT,
                AlertId TEXT NOT NULL REFERENCES TrackedAlerts(AlertId),
                PreviousStatus TEXT,
                Status TEXT NOT NULL,
                ChangedUtcTicks INTEGER NOT NULL,
                ChangedBy TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_TrackedAlerts_Filters ON TrackedAlerts (Status, Severity);
            CREATE INDEX IF NOT EXISTS IX_AlertStatusHistory_AlertId ON AlertStatusHistory (AlertId, SequenceId);
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    // The caller owns the transaction: an accepted inventory and its findings commit together.
    internal async Task RecordObservedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SecurityAlert finding,
        string endpointName,
        CancellationToken cancellationToken)
    {
        var observedTicks = finding.Timestamp.UtcDateTime.Ticks;
        var now = DateTimeOffset.UtcNow;
        string? alertId = null;
        string? status = null;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT AlertId, Status, LastObservedUtcTicks FROM TrackedAlerts
                WHERE EndpointId = $endpointId AND RuleId = $ruleId;
                """;
            query.Parameters.AddWithValue("$endpointId", finding.EndpointId.ToString("D"));
            query.Parameters.AddWithValue("$ruleId", finding.RuleId);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                if (observedTicks <= reader.GetInt64(2))
                {
                    return;
                }

                alertId = reader.GetString(0);
                status = reader.GetString(1);
            }
        }

        var isNew = alertId is null;
        alertId ??= Guid.NewGuid().ToString("D");
        var reopen = status == "resolved";
        await using (var write = connection.CreateCommand())
        {
            write.Transaction = transaction;
            write.CommandText = isNew ? """
                INSERT INTO TrackedAlerts (
                    AlertId, EndpointId, EndpointName, RuleId, Title, Severity, Status,
                    FirstObservedUtcTicks, LastObservedUtcTicks, CreatedUtcTicks,
                    UpdatedUtcTicks, StatusChangedUtcTicks, Version, Reason, EvidenceJson, RecommendedAction)
                VALUES ($alertId, $endpointId, $endpointName, $ruleId, $title, $severity, 'open',
                    $observedTicks, $observedTicks, $nowTicks, $nowTicks, $nowTicks,
                    1, $reason, $evidenceJson, $recommendedAction);
                """ : """
                UPDATE TrackedAlerts SET EndpointName = $endpointName, Title = $title,
                    Severity = $severity, Reason = $reason, EvidenceJson = $evidenceJson,
                    RecommendedAction = $recommendedAction, LastObservedUtcTicks = $observedTicks,
                    UpdatedUtcTicks = $nowTicks, Version = Version + 1,
                    Status = CASE WHEN Status = 'resolved' THEN 'open' ELSE Status END,
                    StatusChangedUtcTicks = CASE WHEN Status = 'resolved' THEN $nowTicks ELSE StatusChangedUtcTicks END
                WHERE AlertId = $alertId;
                """;
            write.Parameters.AddWithValue("$alertId", alertId);
            write.Parameters.AddWithValue("$endpointId", finding.EndpointId.ToString("D"));
            write.Parameters.AddWithValue("$endpointName", endpointName);
            write.Parameters.AddWithValue("$ruleId", finding.RuleId);
            write.Parameters.AddWithValue("$title", finding.Title);
            write.Parameters.AddWithValue("$severity", finding.Severity);
            write.Parameters.AddWithValue("$reason", finding.Reason);
            write.Parameters.AddWithValue("$evidenceJson", JsonSerializer.Serialize(finding.Evidence));
            write.Parameters.AddWithValue("$recommendedAction", finding.RecommendedAction);
            write.Parameters.AddWithValue("$observedTicks", observedTicks);
            write.Parameters.AddWithValue("$nowTicks", now.UtcDateTime.Ticks);
            await write.ExecuteNonQueryAsync(cancellationToken);
        }

        if (isNew || reopen)
        {
            await RecordHistoryAsync(connection, transaction, alertId, status, "open", now, "system", cancellationToken);
        }
    }

    public async Task<AlertPage> ListAsync(
        string? severity,
        string? status,
        int offset,
        int limit,
        CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        const string filter = "WHERE ($severity IS NULL OR Severity = $severity) AND ($status IS NULL OR Status = $status)";
        long total;
        await using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM TrackedAlerts " + filter + ";";
            count.Parameters.AddWithValue("$severity", (object?)severity ?? DBNull.Value);
            count.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
            total = (long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L);
        }

        var alerts = new List<AlertListItem>();
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT " + SelectColumns + " FROM TrackedAlerts " + filter + """
                 ORDER BY LastObservedUtcTicks DESC, AlertId LIMIT $limit OFFSET $offset;
                """;
            query.Parameters.AddWithValue("$severity", (object?)severity ?? DBNull.Value);
            query.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
            query.Parameters.AddWithValue("$limit", limit);
            query.Parameters.AddWithValue("$offset", offset);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                alerts.Add(ReadListItem(reader));
            }
        }

        transaction.Commit();
        return new AlertPage(alerts, total, offset, limit);
    }

    public async Task<IncidentExport> ExportAsync(int offset, int limit, DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        if (offset < 0 || limit is < 1 or > 200) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        long total;
        await using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM TrackedAlerts;";
            total = (long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L);
        }
        var ids = new List<Guid>();
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT AlertId FROM TrackedAlerts ORDER BY LastObservedUtcTicks DESC, AlertId
                LIMIT $limit OFFSET $offset;
                """;
            query.Parameters.AddWithValue("$limit", limit);
            query.Parameters.AddWithValue("$offset", offset);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) ids.Add(Guid.Parse(reader.GetString(0)));
        }
        var incidents = new List<AlertDetail>();
        foreach (var id in ids)
        {
            if (await FindAsync(connection, transaction, id, cancellationToken) is { } detail)
                incidents.Add(detail);
        }
        transaction.Commit();
        return new("sentinelai-emergency-incidents-v1", now, incidents, total, offset, limit);
    }

    public async Task<AlertDetail?> FindAsync(Guid alertId, CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var detail = await FindAsync(connection, transaction, alertId, cancellationToken);
        transaction.Commit();
        return detail;
    }

    public async Task<AlertStatusUpdateResult> UpdateStatusAsync(
        Guid alertId,
        string status,
        long expectedVersion,
        string actor,
        CancellationToken cancellationToken = default)
    {
        if (!IsValidStatus(status) || expectedVersion < 1 || string.IsNullOrWhiteSpace(actor))
        {
            throw new ArgumentException("A valid status, version, and administrator identity are required.");
        }

        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        var current = await FindAsync(connection, transaction, alertId, cancellationToken);
        if (current is null)
        {
            return new AlertStatusUpdateResult(AlertStatusUpdateOutcome.NotFound, null);
        }

        if (current.Version != expectedVersion)
        {
            return new AlertStatusUpdateResult(AlertStatusUpdateOutcome.Conflict, null);
        }

        if (current.Status == status)
        {
            transaction.Commit();
            return new AlertStatusUpdateResult(AlertStatusUpdateOutcome.Updated, current);
        }

        var now = DateTimeOffset.UtcNow;
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE TrackedAlerts SET Status = $status, UpdatedUtcTicks = $nowTicks,
                    StatusChangedUtcTicks = $nowTicks, Version = Version + 1
                WHERE AlertId = $alertId;
                """;
            update.Parameters.AddWithValue("$alertId", alertId.ToString("D"));
            update.Parameters.AddWithValue("$status", status);
            update.Parameters.AddWithValue("$nowTicks", now.UtcDateTime.Ticks);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await RecordHistoryAsync(connection, transaction, alertId.ToString("D"), current.Status, status,
            now, actor, cancellationToken);
        var detail = await FindAsync(connection, transaction, alertId, cancellationToken);
        transaction.Commit();
        return new AlertStatusUpdateResult(AlertStatusUpdateOutcome.Updated, detail);
    }

    private static async Task<AlertDetail?> FindAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid alertId,
        CancellationToken cancellationToken)
    {
        AlertDetail detail;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT " + SelectColumns + " FROM TrackedAlerts WHERE AlertId = $alertId;";
            query.Parameters.AddWithValue("$alertId", alertId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            var item = ReadListItem(reader);
            detail = new AlertDetail(item.AlertId, item.EndpointId, item.EndpointName, item.RuleId, item.Title,
                item.Severity, item.Status, item.FirstObservedUtc, item.LastObservedUtc, item.UpdatedUtc,
                item.Version, reader.GetString(11),
                JsonSerializer.Deserialize<RuleEvidence[]>(reader.GetString(12)) ?? [], reader.GetString(13),
                ReadTime(reader, 14), ReadTime(reader, 15), [], 0);
        }

        long historyCount;
        await using (var count = connection.CreateCommand())
        {
            count.Transaction = transaction;
            count.CommandText = "SELECT COUNT(*) FROM AlertStatusHistory WHERE AlertId = $alertId;";
            count.Parameters.AddWithValue("$alertId", alertId.ToString("D"));
            historyCount = (long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L);
        }

        var history = new List<AlertStatusChange>();
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT PreviousStatus, Status, ChangedUtcTicks, ChangedBy FROM (
                    SELECT SequenceId, PreviousStatus, Status, ChangedUtcTicks, ChangedBy
                    FROM AlertStatusHistory WHERE AlertId = $alertId ORDER BY SequenceId DESC LIMIT 100
                ) ORDER BY SequenceId;
                """;
            query.Parameters.AddWithValue("$alertId", alertId.ToString("D"));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                history.Add(new AlertStatusChange(reader.IsDBNull(0) ? null : reader.GetString(0),
                    reader.GetString(1), ReadTime(reader, 2), reader.GetString(3)));
            }
        }

        return detail with { StatusHistory = history, StatusHistoryCount = historyCount };
    }

    private static AlertListItem ReadListItem(SqliteDataReader reader) => new(
        Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)), reader.GetString(2),
        reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6),
        ReadTime(reader, 7), ReadTime(reader, 8), ReadTime(reader, 9), reader.GetInt64(10));

    private static DateTimeOffset ReadTime(SqliteDataReader reader, int ordinal) =>
        new(reader.GetInt64(ordinal), TimeSpan.Zero);

    private static async Task RecordHistoryAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string alertId,
        string? previousStatus,
        string status,
        DateTimeOffset now,
        string actor,
        CancellationToken cancellationToken)
    {
        await using var history = connection.CreateCommand();
        history.Transaction = transaction;
        history.CommandText = """
            INSERT INTO AlertStatusHistory (AlertId, PreviousStatus, Status, ChangedUtcTicks, ChangedBy)
            VALUES ($alertId, $previousStatus, $status, $nowTicks, $actor);
            """;
        history.Parameters.AddWithValue("$alertId", alertId);
        history.Parameters.AddWithValue("$previousStatus", (object?)previousStatus ?? DBNull.Value);
        history.Parameters.AddWithValue("$status", status);
        history.Parameters.AddWithValue("$nowTicks", now.UtcDateTime.Ticks);
        history.Parameters.AddWithValue("$actor", actor);
        await history.ExecuteNonQueryAsync(cancellationToken);
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath,
        Mode = SqliteOpenMode.ReadWrite,
        DefaultTimeout = 30,
        ForeignKeys = true
    }.ToString());
}
