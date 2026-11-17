using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Core.Notifications;

public sealed partial class NotificationStore
{
    private sealed record StoredPolicy(long Version,bool CriticalAlerts,bool MonitoringChanges,int OfflineMinutes,int GroupMinutes,
        bool WebhookEnabled,string? WebhookOrigin,byte[]? ProtectedWebhookUrl,byte[]? ProtectedWebhookSecret,
        bool EmailEnabled,string? SmtpHost,int SmtpPort,string? SmtpUsername,byte[]? ProtectedSmtpPassword,string? EmailFrom,string? EmailTo);

    public async Task<NotificationPolicy> GetPolicyAsync(CancellationToken cancellationToken = default)
    {
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        return PublicPolicy(await ReadPolicyAsync(connection,null,cancellationToken));
    }

    // Returns null only for optimistic concurrency failure. Invalid input has a fixed safe error code.
    public async Task<NotificationPolicy?> UpdatePolicyAsync(NotificationPolicyWrite request,CancellationToken cancellationToken = default)
    {
        ValidatePolicy(request);
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        using var transaction=connection.BeginTransaction(deferred:false);
        var current=await ReadPolicyAsync(connection,transaction,cancellationToken);
        if (request.ExpectedVersion!=current.Version || current.Version==long.MaxValue) return null;
        var url=current.ProtectedWebhookUrl;
        var secret=current.ProtectedWebhookSecret;
        var password=current.ProtectedSmtpPassword;
        var origin=current.WebhookOrigin;
        if (request.ClearWebhookDestination) { url=null; origin=null; }
        else if (request.WebhookUrl is not null)
        {
            url=Protect(request.WebhookUrl);
            origin=new Uri(request.WebhookUrl).GetLeftPart(UriPartial.Authority);
        }
        if (request.ClearWebhookSecret) secret=null;
        else if (request.WebhookSecret is not null) secret=Protect(request.WebhookSecret);
        if (request.ClearSmtpPassword) password=null;
        else if (request.SmtpPassword is not null) password=Protect(request.SmtpPassword);
        if (request.WebhookEnabled && (url is null || !protection.IsSupported) ||
            request.EmailEnabled && (password is null || !protection.IsSupported))
            throw new ArgumentException("credentials_unavailable");
        await using (var update=Command(connection,transaction,"""
            UPDATE NotificationPolicy SET Version=Version+1,CriticalAlerts=$critical,MonitoringChanges=$monitoring,
                OfflineMinutes=$offline,GroupMinutes=$group,WebhookEnabled=$webhook,WebhookOrigin=$origin,
                ProtectedWebhookUrl=$url,ProtectedWebhookSecret=$secret,EmailEnabled=$email,SmtpHost=$host,SmtpPort=587,
                SmtpUsername=$username,ProtectedSmtpPassword=$password,EmailFrom=$from,EmailTo=$to WHERE Singleton=1;
            UPDATE NotificationDeliveries SET State='cancelled',NextAttemptUtcTicks=NULL,ResultCode='policy_changed'
                WHERE State IN ('pending','retry','sending');
            """,("$critical",request.CriticalAlerts?1:0),("$monitoring",request.MonitoringChanges?1:0),
            ("$offline",request.OfflineMinutes),("$group",request.GroupMinutes),("$webhook",request.WebhookEnabled?1:0),
            ("$origin",origin),("$url",url),("$secret",secret),("$email",request.EmailEnabled?1:0),
            ("$host",request.SmtpHost),("$username",request.SmtpUsername),("$password",password),
            ("$from",request.EmailFrom),("$to",request.EmailTo)))
            await update.ExecuteNonQueryAsync(cancellationToken);
        var saved=PublicPolicy(await ReadPolicyAsync(connection,transaction,cancellationToken));
        transaction.Commit(); PolicyChanged?.Invoke(); return saved;
    }

    private byte[] Protect(string text)
    {
        if (!protection.IsSupported) throw new ArgumentException("credentials_unavailable");
        var bytes=Encoding.UTF8.GetBytes(text);
        try { return protection.Protect(bytes); }
        catch (CryptographicException) { throw new ArgumentException("credentials_unavailable"); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidatePolicy(NotificationPolicyWrite request)
    {
        if (request.ExpectedVersion<1 || request.OfflineMinutes is <5 or >120 || request.GroupMinutes is <1 or >60 ||
            request.SmtpPort!=587 || request.ClearWebhookDestination && request.WebhookUrl is not null ||
            request.ClearWebhookSecret && request.WebhookSecret is not null || request.ClearSmtpPassword && request.SmtpPassword is not null)
            throw new ArgumentException("invalid_policy");
        if (request.WebhookUrl is not null && (request.WebhookUrl.Length>2048 ||
            !Uri.TryCreate(request.WebhookUrl,UriKind.Absolute,out var uri) || !NotificationNetwork.IsValidWebhookUri(uri)))
            throw new ArgumentException("invalid_webhook");
        if (request.SmtpPassword is not null && !ValidSecret(request.SmtpPassword,8,512) ||
            request.WebhookSecret is not null && !ValidSecret(request.WebhookSecret,16,512))
            throw new ArgumentException("invalid_secret");
        if (request.SmtpHost is not null && !NotificationNetwork.IsValidHost(request.SmtpHost) ||
            request.SmtpUsername is not null && !ValidText(request.SmtpUsername,254) ||
            request.EmailFrom is not null && !NotificationNetwork.IsValidMailbox(request.EmailFrom) ||
            request.EmailTo is not null && !NotificationNetwork.IsValidMailbox(request.EmailTo))
            throw new ArgumentException("invalid_email");
        if (request.EmailEnabled && (request.SmtpHost is null || request.SmtpUsername is null || request.EmailFrom is null || request.EmailTo is null))
            throw new ArgumentException("invalid_email");
    }
    private static bool ValidSecret(string value,int minimum,int maximum)
    {
        try { var length=new UTF8Encoding(false,true).GetByteCount(value); return length>=minimum && length<=maximum && !value.Any(char.IsControl); }
        catch (EncoderFallbackException) { return false; }
    }
    private static bool ValidText(string value,int maximum) => value.Length>0 && value.Length<=maximum && !value.Any(char.IsControl);
    private NotificationPolicy PublicPolicy(StoredPolicy policy) => new(policy.Version,policy.CriticalAlerts,policy.MonitoringChanges,
        policy.OfflineMinutes,policy.GroupMinutes,policy.WebhookEnabled,policy.WebhookOrigin,policy.ProtectedWebhookUrl is not null,
        policy.ProtectedWebhookSecret is not null,policy.EmailEnabled,policy.SmtpHost,policy.SmtpPort,policy.SmtpUsername,
        policy.ProtectedSmtpPassword is not null,policy.EmailFrom,policy.EmailTo,protection.IsSupported?"available":"unavailable");

    private static async Task<StoredPolicy> ReadPolicyAsync(SqliteConnection connection,SqliteTransaction? transaction,CancellationToken cancellationToken)
    {
        await using var query=Command(connection,transaction,"""
            SELECT Version,CriticalAlerts,MonitoringChanges,OfflineMinutes,GroupMinutes,WebhookEnabled,WebhookOrigin,
                ProtectedWebhookUrl,ProtectedWebhookSecret,EmailEnabled,SmtpHost,SmtpPort,SmtpUsername,ProtectedSmtpPassword,EmailFrom,EmailTo
                FROM NotificationPolicy WHERE Singleton=1;
            """);
        await using var reader=await query.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) throw new InvalidDataException("Notification policy unavailable.");
        return new(reader.GetInt64(0),reader.GetInt32(1)!=0,reader.GetInt32(2)!=0,reader.GetInt32(3),reader.GetInt32(4),reader.GetInt32(5)!=0,
            NullableString(reader,6),reader.IsDBNull(7)?null:(byte[])reader[7],reader.IsDBNull(8)?null:(byte[])reader[8],reader.GetInt32(9)!=0,
            NullableString(reader,10),reader.GetInt32(11),NullableString(reader,12),reader.IsDBNull(13)?null:(byte[])reader[13],NullableString(reader,14),NullableString(reader,15));
    }

    internal async Task<NotificationDestination?> GetDestinationAsync(long version,string channel,CancellationToken cancellationToken)
    {
        await using var connection=CreateConnection(); await connection.OpenAsync(cancellationToken);
        var policy=await ReadPolicyAsync(connection,null,cancellationToken);
        if (policy.Version!=version || !protection.IsSupported) return null;
        if (channel=="webhook" && policy.WebhookEnabled && policy.ProtectedWebhookUrl is not null)
        {
            var bytes=protection.Unprotect(policy.ProtectedWebhookUrl);
            try
            {
                if (bytes.Length>8192 || !Uri.TryCreate(new UTF8Encoding(false,true).GetString(bytes),UriKind.Absolute,out var uri) ||
                    !NotificationNetwork.IsValidWebhookUri(uri)) return null;
                return new("webhook",uri,policy.ProtectedWebhookSecret is null?null:protection.Unprotect(policy.ProtectedWebhookSecret));
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        if (channel=="email" && policy.EmailEnabled && policy.ProtectedSmtpPassword is not null)
            return new("email",SmtpHost:policy.SmtpHost,SmtpUsername:policy.SmtpUsername,
                SmtpPassword:protection.Unprotect(policy.ProtectedSmtpPassword),EmailFrom:policy.EmailFrom,EmailTo:policy.EmailTo);
        return null;
    }

    // Tables are optional for pre-notification backups. Called inside recovery's caller-owned transaction.
    internal static async Task SuppressAfterRecoveryAsync(SqliteConnection connection,SqliteTransaction transaction,CancellationToken cancellationToken)
    {
        foreach (var (table,sql) in new[]
        {
            ("NotificationPolicy","""
                UPDATE NotificationPolicy SET WebhookEnabled=0,EmailEnabled=0,ProtectedWebhookUrl=NULL,WebhookOrigin=NULL,
                    ProtectedWebhookSecret=NULL,ProtectedSmtpPassword=NULL,Version=CASE WHEN Version<9223372036854775807 THEN Version+1 ELSE Version END;
                """),
            ("NotificationDeliveries","UPDATE NotificationDeliveries SET State='cancelled',NextAttemptUtcTicks=NULL,ResultCode='recovery' WHERE State IN ('pending','retry','sending');"),
            ("NotificationMonitoringState","DELETE FROM NotificationMonitoringState;"),
            ("NotificationRuntime","UPDATE NotificationRuntime SET MonitoringCursor='',BaselinePending=1 WHERE Singleton=1;")
        })
        {
            await using var exists=Command(connection,transaction,"SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$name;",("$name",table));
            if (await exists.ExecuteScalarAsync(cancellationToken) is not null)
                await ExecuteAsync(connection,transaction,sql,cancellationToken);
        }
    }
}
