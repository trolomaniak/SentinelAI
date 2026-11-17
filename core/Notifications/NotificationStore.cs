using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core.Notifications;

public sealed partial class NotificationStore(AdminStore admins, TimeProvider time, INotificationCredentialProtection protection)
{
    internal const int MaximumNotifications = 10_000;
    internal const int MaximumOffset = 100_000;
    private volatile bool _ready;
    internal event Action? PolicyChanged;
    private const string SummaryColumns = "NotificationId,Kind,EndpointId,EndpointName,AlertId,RuleId,Severity,Occurrences,CreatedUtcTicks,LastObservedUtcTicks,ReadUtcTicks";

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await ExecuteAsync(connection, transaction, """
            CREATE TABLE IF NOT EXISTS NotificationPolicy (
                Singleton INTEGER PRIMARY KEY CHECK(Singleton=1), Version INTEGER NOT NULL,
                CriticalAlerts INTEGER NOT NULL, MonitoringChanges INTEGER NOT NULL,
                OfflineMinutes INTEGER NOT NULL, GroupMinutes INTEGER NOT NULL,
                WebhookEnabled INTEGER NOT NULL, WebhookOrigin TEXT, ProtectedWebhookUrl BLOB, ProtectedWebhookSecret BLOB,
                EmailEnabled INTEGER NOT NULL, SmtpHost TEXT, SmtpPort INTEGER NOT NULL, SmtpUsername TEXT,
                ProtectedSmtpPassword BLOB, EmailFrom TEXT, EmailTo TEXT);
            INSERT OR IGNORE INTO NotificationPolicy VALUES(1,1,1,1,15,5,0,NULL,NULL,NULL,0,NULL,587,NULL,NULL,NULL,NULL);
            CREATE TABLE IF NOT EXISTS Notifications (
                NotificationId TEXT PRIMARY KEY NOT NULL, Kind TEXT NOT NULL, EndpointId TEXT NOT NULL,
                EndpointName TEXT NOT NULL, AlertId TEXT, RuleId TEXT, Severity TEXT NOT NULL,
                Occurrences INTEGER NOT NULL, CreatedUtcTicks INTEGER NOT NULL, LastObservedUtcTicks INTEGER NOT NULL,
                ReadUtcTicks INTEGER, GroupKey TEXT NOT NULL, GroupUntilUtcTicks INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS IX_Notifications_Created ON Notifications(CreatedUtcTicks DESC,NotificationId);
            CREATE INDEX IF NOT EXISTS IX_Notifications_Group ON Notifications(GroupKey,CreatedUtcTicks DESC);
            CREATE TABLE IF NOT EXISTS NotificationDeliveries (
                DeliveryId TEXT PRIMARY KEY NOT NULL, NotificationId TEXT NOT NULL REFERENCES Notifications(NotificationId) ON DELETE CASCADE,
                Channel TEXT NOT NULL, State TEXT NOT NULL, Attempts INTEGER NOT NULL, PolicyVersion INTEGER NOT NULL,
                CreatedUtcTicks INTEGER NOT NULL, LastAttemptUtcTicks INTEGER, NextAttemptUtcTicks INTEGER,
                ResultCode TEXT, PayloadJson TEXT, UNIQUE(NotificationId,Channel));
            CREATE INDEX IF NOT EXISTS IX_NotificationDeliveries_Due ON NotificationDeliveries(State,NextAttemptUtcTicks);
            CREATE TABLE IF NOT EXISTS NotificationMonitoringState (
                EndpointId TEXT PRIMARY KEY NOT NULL, Offline INTEGER NOT NULL, LastSeenUtcTicks INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS NotificationRuntime (Singleton INTEGER PRIMARY KEY CHECK(Singleton=1), MonitoringCursor TEXT NOT NULL, BaselinePending INTEGER NOT NULL);
            INSERT OR IGNORE INTO NotificationRuntime VALUES(1,'',1);
            """, cancellationToken);
        // Seed current monitoring state once, without turning old endpoints into upgrade notifications.
        var initialPolicy = await ReadPolicyAsync(connection, transaction, cancellationToken);
        await using (var seed = Command(connection, transaction, """
            INSERT OR IGNORE INTO NotificationMonitoringState(EndpointId,Offline,LastSeenUtcTicks)
                SELECT e.EndpointId,CASE WHEN d.LastSeenUtcTicks <= $cutoff THEN 1 ELSE 0 END,d.LastSeenUtcTicks
                FROM EndpointEnrollments e JOIN Devices d ON d.InstallationId=e.InstallationId
                WHERE e.RemovedUtcTicks IS NULL AND (SELECT BaselinePending FROM NotificationRuntime WHERE Singleton=1)=1;
            UPDATE NotificationRuntime SET BaselinePending=0 WHERE Singleton=1;
            UPDATE NotificationDeliveries SET State=CASE WHEN Attempts>=5 THEN 'failed' ELSE 'retry' END,
                ResultCode='interrupted',NextAttemptUtcTicks=CASE WHEN Attempts>=5 THEN NULL ELSE $now END WHERE State='sending';
            """, ("$cutoff", time.GetUtcNow().AddMinutes(-initialPolicy.OfflineMinutes).UtcTicks), ("$now", time.GetUtcNow().UtcTicks)))
            await seed.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit(); _ready = true;
    }

    internal async Task RecordCriticalAsync(SqliteConnection connection, SqliteTransaction transaction,
        Guid alertId, Guid endpointId, string endpointName, string ruleId, string kind, CancellationToken cancellationToken)
    {
        if (!_ready) return; // Startup alert backfill precedes initialization: no historical flood.
        var policy = await ReadPolicyAsync(connection, transaction, cancellationToken);
        if (policy.CriticalAlerts)
            await RecordAsync(connection, transaction, policy, kind, endpointId, endpointName, alertId, ruleId, "critical", cancellationToken);
    }

    private async Task RecordAsync(SqliteConnection connection, SqliteTransaction transaction, StoredPolicy policy,
        string kind, Guid endpointId, string endpointName, Guid? alertId, string? ruleId, string severity, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var groupKey = kind + ":" + endpointId.ToString("D") + ":" + alertId?.ToString("D");
        string? id;
        await using (var find = Command(connection, transaction, """
            SELECT NotificationId FROM Notifications WHERE GroupKey=$key AND CreatedUtcTicks<=$now AND GroupUntilUtcTicks>$now
            ORDER BY CreatedUtcTicks DESC LIMIT 1;
            """, ("$key", groupKey), ("$now", now.UtcTicks)))
            id = await find.ExecuteScalarAsync(cancellationToken) as string;
        if (id is not null)
        {
            await using var update = Command(connection, transaction, """
                UPDATE Notifications SET Occurrences=MIN(Occurrences+1,2147483647),LastObservedUtcTicks=$now,ReadUtcTicks=NULL WHERE NotificationId=$id;
                """, ("$now", now.UtcTicks), ("$id", id));
            await update.ExecuteNonQueryAsync(cancellationToken); return;
        }
        id = Guid.NewGuid().ToString("D");
        var due = now.AddMinutes(policy.GroupMinutes).UtcTicks;
        await using (var insert = Command(connection, transaction, """
            INSERT INTO Notifications VALUES($id,$kind,$endpoint,$name,$alert,$rule,$severity,1,$now,$now,NULL,$key,$due);
            """, ("$id", id), ("$kind", kind), ("$endpoint", endpointId.ToString("D")),
            ("$name", Bound(endpointName,128)), ("$alert", alertId?.ToString("D")), ("$rule", Bound(ruleId,128)),
            ("$severity", severity), ("$now", now.UtcTicks), ("$key", groupKey), ("$due", due)))
            await insert.ExecuteNonQueryAsync(cancellationToken);
        foreach (var channel in new[] { policy.WebhookEnabled ? "webhook" : null, policy.EmailEnabled ? "email" : null })
        {
            if (channel is null) continue;
            await using var delivery = Command(connection, transaction, """
                INSERT INTO NotificationDeliveries VALUES($delivery,$id,$channel,'pending',0,$version,$now,NULL,$due,NULL,NULL);
                """, ("$delivery", Guid.NewGuid().ToString("D")), ("$id", id), ("$channel", channel),
                ("$version", policy.Version), ("$now", now.UtcTicks), ("$due", due));
            await delivery.ExecuteNonQueryAsync(cancellationToken);
        }
        // Keep storage bounded even when alert traffic outruns the periodic retention sweep.
        await ExecuteAsync(connection, transaction, """
            DELETE FROM Notifications WHERE NotificationId IN (
                SELECT NotificationId FROM Notifications ORDER BY CreatedUtcTicks DESC,NotificationId LIMIT 1 OFFSET 10000);
            """, cancellationToken);
    }

    public async Task<NotificationPage> ListAsync(int offset, int limit, bool unreadOnly = false, CancellationToken cancellationToken = default)
    {
        ValidatePage(offset, limit);
        await using var connection = CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        int total, unread;
        await using (var count = Command(connection, transaction,
            "SELECT COUNT(*),COALESCE(SUM(CASE WHEN ReadUtcTicks IS NULL THEN 1 ELSE 0 END),0) FROM Notifications;"))
        {
            await using var reader = await count.ExecuteReaderAsync(cancellationToken); await reader.ReadAsync(cancellationToken);
            total = reader.GetInt32(0); unread = reader.GetInt32(1);
        }
        var items = new List<NotificationSummary>();
        await using (var query = Command(connection, transaction, "SELECT " + SummaryColumns + """
             FROM Notifications WHERE ($unread=0 OR ReadUtcTicks IS NULL) ORDER BY CreatedUtcTicks DESC,NotificationId LIMIT $limit OFFSET $offset;
            """, ("$unread", unreadOnly ? 1 : 0), ("$limit", limit), ("$offset", offset)))
        {
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) items.Add(ReadSummary(reader));
        }
        transaction.Commit(); return new(unreadOnly ? unread : total, unread, offset, limit, items);
    }

    public async Task<bool> MarkReadAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection(); await connection.OpenAsync(cancellationToken);
        await using var command = Command(connection, null,
            "UPDATE Notifications SET ReadUtcTicks=COALESCE(ReadUtcTicks,$now) WHERE NotificationId=$id;",
            ("$now", time.GetUtcNow().UtcTicks), ("$id", id.ToString("D")));
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<NotificationDeliveryPage> DeliveriesAsync(int offset, int limit, Guid? notificationId = null, CancellationToken cancellationToken = default)
    {
        ValidatePage(offset, limit);
        await using var connection = CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        const string filter = " WHERE ($id IS NULL OR NotificationId=$id) ";
        int total;
        await using (var count = Command(connection, transaction, "SELECT COUNT(*) FROM NotificationDeliveries" + filter, ("$id", notificationId?.ToString("D"))))
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken));
        var items = new List<NotificationDelivery>();
        await using (var query = Command(connection, transaction,
            "SELECT DeliveryId,NotificationId,Channel,State,Attempts,CreatedUtcTicks,LastAttemptUtcTicks,NextAttemptUtcTicks,ResultCode FROM NotificationDeliveries" +
            filter + "ORDER BY CreatedUtcTicks DESC,DeliveryId LIMIT $limit OFFSET $offset;",
            ("$id", notificationId?.ToString("D")), ("$limit", limit), ("$offset", offset)))
        {
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) items.Add(new(Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)),
                reader.GetString(2), reader.GetString(3), reader.GetInt32(4), ReadTime(reader,5), NullableTime(reader,6), NullableTime(reader,7), NullableString(reader,8)));
        }
        transaction.Commit(); return new(total,offset,limit,items);
    }

    internal async Task PruneAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: false);
        await using var prune = Command(connection, transaction, """
            DELETE FROM Notifications WHERE NotificationId IN (
                SELECT NotificationId FROM Notifications WHERE CreatedUtcTicks<$cutoff ORDER BY CreatedUtcTicks LIMIT 500);
            DELETE FROM Notifications WHERE NotificationId IN (
                SELECT NotificationId FROM Notifications ORDER BY CreatedUtcTicks DESC,NotificationId LIMIT 500 OFFSET 10000);
            DELETE FROM NotificationMonitoringState WHERE EndpointId IN (
                SELECT s.EndpointId FROM NotificationMonitoringState s LEFT JOIN EndpointEnrollments e ON e.EndpointId=s.EndpointId
                WHERE e.EndpointId IS NULL OR e.RemovedUtcTicks IS NOT NULL LIMIT 500);
            """, ("$cutoff", time.GetUtcNow().AddDays(-30).UtcTicks));
        await prune.ExecuteNonQueryAsync(cancellationToken); transaction.Commit();
    }

    internal static void ValidatePage(int offset, int limit)
    {
        if (offset is < 0 or > MaximumOffset || limit is < 1 or > NotificationContract.MaximumPageSize) throw new ArgumentOutOfRangeException(nameof(limit));
    }
    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    { DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 1, ForeignKeys = true }.ToString());
    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Key,object? Value)[] parameters)
    {
        var command = connection.CreateCommand(); command.Transaction=transaction; command.CommandText=sql;
        foreach (var (key,value) in parameters) command.Parameters.AddWithValue(key,value ?? DBNull.Value);
        return command;
    }
    private static async Task ExecuteAsync(SqliteConnection connection, SqliteTransaction transaction, string sql, CancellationToken cancellationToken)
    { await using var command=Command(connection,transaction,sql); await command.ExecuteNonQueryAsync(cancellationToken); }
    private static string? Bound(string? value,int maximum) => value is null ? null : value.Length <= maximum ? value : value[..maximum];
    private static DateTimeOffset ReadTime(SqliteDataReader reader,int ordinal) => new(reader.GetInt64(ordinal),TimeSpan.Zero);
    private static DateTimeOffset? NullableTime(SqliteDataReader reader,int ordinal) => reader.IsDBNull(ordinal) ? null : ReadTime(reader,ordinal);
    private static string? NullableString(SqliteDataReader reader,int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static NotificationSummary ReadSummary(SqliteDataReader reader) => new(Guid.Parse(reader.GetString(0)),reader.GetString(1),
        Guid.Parse(reader.GetString(2)),reader.GetString(3),reader.IsDBNull(4)?null:Guid.Parse(reader.GetString(4)),NullableString(reader,5),
        reader.GetString(6),reader.GetInt32(7),ReadTime(reader,8),ReadTime(reader,9),NullableTime(reader,10));
}
