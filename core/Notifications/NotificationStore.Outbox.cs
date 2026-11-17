using System.Text.Json;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Core.Notifications;

internal sealed record NotificationAttempt(Guid DeliveryId,long PolicyVersion,string Channel,int Attempts,NotificationPayload Payload);

public sealed partial class NotificationStore
{
    internal async Task ObserveMonitoringAsync(CancellationToken cancellationToken = default)
    {
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction=connection.BeginTransaction(deferred:false);
        var policy=await ReadPolicyAsync(connection,transaction,cancellationToken);
        string cursor;
        await using (var query=Command(connection,transaction,"SELECT MonitoringCursor FROM NotificationRuntime WHERE Singleton=1;"))
            cursor=(string)(await query.ExecuteScalarAsync(cancellationToken))!;
        var endpoints=new List<(Guid Id,long Seen,bool? Offline,string Name)>();
        await using (var query=Command(connection,transaction,"""
            SELECT e.EndpointId,d.LastSeenUtcTicks,s.Offline,
                COALESCE(json_extract(i.ReportJson,'$.Hostname'),json_extract(i.ReportJson,'$.hostname'),e.EndpointId) FROM EndpointEnrollments e
                JOIN Devices d ON d.InstallationId=e.InstallationId
                LEFT JOIN NotificationMonitoringState s ON s.EndpointId=e.EndpointId
                LEFT JOIN EndpointInventories i ON i.EndpointId=e.EndpointId
                WHERE e.RemovedUtcTicks IS NULL AND e.EndpointId>$cursor ORDER BY e.EndpointId LIMIT 500;
            """,("$cursor",cursor)))
        {
            await using var reader=await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) endpoints.Add((Guid.Parse(reader.GetString(0)),reader.GetInt64(1),reader.IsDBNull(2)?null:reader.GetInt32(2)!=0,reader.GetString(3)));
        }
        var cutoff=time.GetUtcNow().AddMinutes(-policy.OfflineMinutes).UtcTicks;
        foreach (var endpoint in endpoints)
        {
            var offline=endpoint.Seen<=cutoff;
            if ((endpoint.Offline is not null && endpoint.Offline!=offline || endpoint.Offline is null && offline) && policy.MonitoringChanges)
                await RecordAsync(connection,transaction,policy,offline?"monitoringOffline":"monitoringRecovered",endpoint.Id,
                    endpoint.Name,null,null,offline?"high":"info",cancellationToken);
            await using var update=Command(connection,transaction,"""
                INSERT INTO NotificationMonitoringState VALUES($id,$offline,$seen)
                ON CONFLICT(EndpointId) DO UPDATE SET Offline=excluded.Offline,LastSeenUtcTicks=excluded.LastSeenUtcTicks;
                """,("$id",endpoint.Id.ToString("D")),("$offline",offline?1:0),("$seen",endpoint.Seen));
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var update=Command(connection,transaction,"UPDATE NotificationRuntime SET MonitoringCursor=$cursor WHERE Singleton=1;",
            ("$cursor",endpoints.Count==500?endpoints[^1].Id.ToString("D"):string.Empty)))
            await update.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
    }

    internal async Task<NotificationAttempt?> ClaimAsync(CancellationToken cancellationToken = default)
    {
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction=connection.BeginTransaction(deferred:false);
        var policy=await ReadPolicyAsync(connection,transaction,cancellationToken);
        await using (var cancel=Command(connection,transaction,"""
            UPDATE NotificationDeliveries SET State='cancelled',NextAttemptUtcTicks=NULL,ResultCode='policy_changed'
                WHERE State IN ('pending','retry','sending') AND PolicyVersion<>$version;
            UPDATE NotificationDeliveries SET State=CASE WHEN Attempts>=5 THEN 'failed' ELSE 'retry' END,
                ResultCode='interrupted',NextAttemptUtcTicks=CASE WHEN Attempts>=5 THEN NULL ELSE $now END
                WHERE State='sending' AND LastAttemptUtcTicks<=$lease;
            """,("$version",policy.Version),("$now",time.GetUtcNow().UtcTicks),("$lease",time.GetUtcNow().AddMinutes(-1).UtcTicks)))
            await cancel.ExecuteNonQueryAsync(cancellationToken);
        Guid id; string notificationId,channel; int attempts; string? json;
        await using (var query=Command(connection,transaction,"""
            SELECT DeliveryId,NotificationId,Channel,Attempts,PayloadJson FROM NotificationDeliveries
                WHERE State IN ('pending','retry') AND Attempts<5 AND NextAttemptUtcTicks<=$now
                ORDER BY NextAttemptUtcTicks,DeliveryId LIMIT 1;
            """,("$now",time.GetUtcNow().UtcTicks)))
        {
            await using var reader=await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) { transaction.Commit(); return null; }
            id=Guid.Parse(reader.GetString(0)); notificationId=reader.GetString(1); channel=reader.GetString(2);
            attempts=reader.GetInt32(3)+1; json=NullableString(reader,4);
        }
        NotificationPayload payload;
        if (json is null)
        {
            await using var query=Command(connection,transaction,"SELECT "+SummaryColumns+" FROM Notifications WHERE NotificationId=$id;",("$id",notificationId));
            await using var reader=await query.ExecuteReaderAsync(cancellationToken); await reader.ReadAsync(cancellationToken);
            var item=ReadSummary(reader);
            payload=new("sentinelai-notification-v1",item.NotificationId,item.Kind,item.EndpointId,item.AlertId,item.RuleId,item.Severity,
                item.Occurrences,item.CreatedUtc,item.LastObservedUtc);
            json=JsonSerializer.Serialize(payload);
        }
        else payload=JsonSerializer.Deserialize<NotificationPayload>(json) ?? throw new InvalidDataException("Notification payload unavailable.");
        await using (var update=Command(connection,transaction,"""
            UPDATE NotificationDeliveries SET State='sending',Attempts=Attempts+1,LastAttemptUtcTicks=$now,NextAttemptUtcTicks=NULL,PayloadJson=$json
                WHERE DeliveryId=$id;
            """,("$now",time.GetUtcNow().UtcTicks),("$json",json),("$id",id.ToString("D"))))
            await update.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit(); return new(id,policy.Version,channel,attempts,payload);
    }

    internal async Task CompleteAsync(NotificationAttempt attempt,NotificationSendResult result,CancellationToken cancellationToken = default)
    {
        var retry=!result.Succeeded && result.Retryable && attempt.Attempts<5;
        var seconds=attempt.Attempts switch { 1=>15,2=>60,_=>300 };
        // Transport codes are an allowlisted machine identifier, never protocol/exception text.
        var code=result.Code.Length is >0 and <=64 && result.Code.All(c=>char.IsAsciiLetterOrDigit(c)||c=='_')?result.Code:"transport_error";
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        await using var update=Command(connection,null,"""
            UPDATE NotificationDeliveries SET State=$state,ResultCode=$code,NextAttemptUtcTicks=$next
                WHERE DeliveryId=$id AND State='sending' AND PolicyVersion=$version AND Attempts=$attempts
                AND PolicyVersion=(SELECT Version FROM NotificationPolicy WHERE Singleton=1);
            """,("$state",result.Succeeded?"succeeded":retry?"retry":"failed"),("$code",code),
            ("$next",retry?time.GetUtcNow().AddSeconds(seconds).UtcTicks:null),("$id",attempt.DeliveryId.ToString("D")),
            ("$version",attempt.PolicyVersion),("$attempts",attempt.Attempts));
        await update.ExecuteNonQueryAsync(cancellationToken);
    }
}
