using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Overview;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Core.Persistence;

internal sealed class OperationsOverviewReadStore(AdminStore admins, MonitoringCoverageReadStore coverage, TimeProvider time)
{
    public async Task<OperationsOverviewSnapshot> ReadAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        const int limit = OperationsOverviewContract.PreviewLimit;
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);

        var issues = await coverage.ListAsync(connection, transaction, now, 0, limit, issuesOnly: true, cancellationToken);
        var (alertCount, alerts) = await ReadPriorityAlertsAsync(connection, transaction, cancellationToken);
        var (unreadCount, notifications) = await ReadUnreadNotificationsAsync(connection, transaction, cancellationToken);
        var riskPage = await RiskRegisterStore.ListAsync(connection, transaction, DateOnly.FromDateTime(now.UtcDateTime),
            new RiskRegisterQuery(null, null, null, true, null, null, 0, limit), cancellationToken);
        var risks = riskPage.Records.Select(risk => new OverviewRisk(risk.RiskId, Bound(risk.Reference), Bound(risk.Title),
            risk.Flags.ReviewOverdue, risk.Flags.AcceptanceExpired, risk.Flags.TargetDatePassed)).ToArray();
        var changes = await ReadRecentChangesAsync(connection, transaction, now, cancellationToken);
        await using var backup = Command(connection, transaction, "SELECT LastSuccessfulUtcTicks FROM BackupSettings WHERE Singleton = 1;");
        var lastBackup = await backup.ExecuteScalarAsync(cancellationToken) is long ticks ? Utc(ticks) : (DateTimeOffset?)null;

        transaction.Commit();
        return new OperationsOverviewSnapshot(now, new OverviewCounts(issues.Total, issues.Matching, alertCount, unreadCount,
            riskPage.Counts.NeedsAttention), alerts, issues.Items, notifications, risks, changes, lastBackup);
    }

    private static Task<(int Total, IReadOnlyList<OverviewAlert> Items)> ReadPriorityAlertsAsync(SqliteConnection connection,
        SqliteTransaction transaction, CancellationToken cancellationToken) => ReadCountedPreviewAsync(connection, transaction, """
        SELECT COUNT(*) OVER(), a.AlertId, a.EndpointName, a.Title, a.Severity, a.Status, a.LastObservedUtcTicks
        FROM TrackedAlerts AS a
        INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId AND e.RemovedUtcTicks IS NULL
        WHERE a.Status IN ('open', 'investigating') AND a.Severity IN ('critical', 'high')
        ORDER BY CASE a.Severity WHEN 'critical' THEN 0 ELSE 1 END, a.LastObservedUtcTicks DESC, a.AlertId
        LIMIT $limit;
        """, reader => new OverviewAlert(Guid.Parse(reader.GetString(1)), Bound(reader.GetString(2)), Bound(reader.GetString(3)),
            reader.GetString(4), reader.GetString(5), Utc(reader.GetInt64(6))), cancellationToken);

    private static Task<(int Total, IReadOnlyList<OverviewNotification> Items)> ReadUnreadNotificationsAsync(SqliteConnection connection,
        SqliteTransaction transaction, CancellationToken cancellationToken) => ReadCountedPreviewAsync(connection, transaction, """
        SELECT COUNT(*) OVER(), NotificationId, EndpointName, Kind, Occurrences, LastObservedUtcTicks
        FROM Notifications WHERE ReadUtcTicks IS NULL
        ORDER BY CreatedUtcTicks DESC, NotificationId
        LIMIT $limit;
        """, reader => new OverviewNotification(Guid.Parse(reader.GetString(1)), Bound(reader.GetString(2)), Bound(reader.GetString(3)),
            reader.GetInt32(4), Utc(reader.GetInt64(5))), cancellationToken);

    private static async Task<IReadOnlyList<OverviewAlertChange>> ReadRecentChangesAsync(SqliteConnection connection,
        SqliteTransaction transaction, DateTimeOffset now, CancellationToken cancellationToken)
    {
        // Status history remains relevant for a removed endpoint, even though it has no current queue entry.
        await using var command = Command(connection, transaction, """
            SELECT a.AlertId, a.EndpointName, a.Title, h.PreviousStatus, h.Status, h.ChangedUtcTicks
            FROM AlertStatusHistory AS h
            INNER JOIN TrackedAlerts AS a ON a.AlertId = h.AlertId
            WHERE h.ChangedUtcTicks BETWEEN $cutoff AND $now
            ORDER BY h.ChangedUtcTicks DESC, h.SequenceId DESC
            LIMIT $limit;
            """);
        command.Parameters.AddWithValue("$now", now.UtcTicks);
        command.Parameters.AddWithValue("$cutoff", now.UtcTicks - TimeSpan.FromHours(OperationsOverviewContract.RecentHours).Ticks);
        command.Parameters.AddWithValue("$limit", OperationsOverviewContract.PreviewLimit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var changes = new List<OverviewAlertChange>();
        while (await reader.ReadAsync(cancellationToken))
            changes.Add(new OverviewAlertChange(Guid.Parse(reader.GetString(0)), Bound(reader.GetString(1)), Bound(reader.GetString(2)),
                reader.IsDBNull(3) ? null : Bound(reader.GetString(3)), Bound(reader.GetString(4)), Utc(reader.GetInt64(5))));
        return changes;
    }

    private static async Task<(int Total, IReadOnlyList<T> Items)> ReadCountedPreviewAsync<T>(SqliteConnection connection,
        SqliteTransaction transaction, string sql, Func<SqliteDataReader, T> project, CancellationToken cancellationToken)
    {
        await using var command = Command(connection, transaction, sql);
        command.Parameters.AddWithValue("$limit", OperationsOverviewContract.PreviewLimit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var total = 0;
        var items = new List<T>();
        while (await reader.ReadAsync(cancellationToken))
        {
            total = reader.GetInt32(0);
            items.Add(project(reader));
        }
        return (total, items);
    }

    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command;
    }

    private static DateTimeOffset Utc(long ticks) => new(ticks, TimeSpan.Zero);

    private static string Bound(string value)
    {
        const int maximum = OperationsOverviewContract.MaximumTextLength;
        var length = Math.Min(value.Length, maximum);
        if (length > 0 && char.IsHighSurrogate(value[length - 1])) length--;
        var text = value[..length].Trim();
        return SecurityEventContract.IsBoundedText(text, maximum) ? text : "?";
    }
}
