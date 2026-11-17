using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Core.Notifications;

internal static class NotificationEndpoints
{
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web) { MaxDepth=2 };
    private static readonly HashSet<string> PolicyProperties=new(StringComparer.Ordinal)
    {
        "expectedVersion","criticalAlerts","monitoringChanges","offlineMinutes","groupMinutes","webhookEnabled",
        "webhookUrl","webhookSecret","clearWebhookSecret","clearWebhookDestination","emailEnabled","smtpHost","smtpPort",
        "smtpUsername","smtpPassword","clearSmtpPassword","emailFrom","emailTo"
    };

    internal static bool IsLocal(HttpContext context)
    {
        var address=context.Connection.RemoteIpAddress;
        return !LocalNetworkRoutes.IsLocalNetworkRequest(context) && address is not null &&
            (IPAddress.IsLoopback(address)||address.IsIPv4MappedToIPv6&&IPAddress.IsLoopback(address.MapToIPv4()));
    }

    internal static void MapNotificationEndpoints(this WebApplication app)
    {
        var group=app.MapGroup("/api/admin/notifications").RequireAuthorization();
        group.MapGet("",async (HttpContext context,NotificationStore store,CancellationToken cancellationToken)=>
        {
            if (!TryPage(context,out var offset,out var limit)) return Results.BadRequest();
            var unread=false;
            if (context.Request.Query.TryGetValue("unreadOnly",out var value) && (value.Count!=1||!bool.TryParse(value[0],out unread))) return Results.BadRequest();
            return Results.Ok(await store.ListAsync(offset,limit,unread,cancellationToken));
        });
        group.MapPut("/{id:guid}/read",async (Guid id,NotificationStore store,CancellationToken cancellationToken)=>
            await store.MarkReadAsync(id,cancellationToken)?Results.NoContent():Results.NotFound());
        group.MapGet("/deliveries",async (HttpContext context,NotificationStore store,CancellationToken cancellationToken)=>
        {
            if (!TryPage(context,out var offset,out var limit)) return Results.BadRequest();
            Guid? id=null;
            if (context.Request.Query.TryGetValue("notificationId",out var value))
            {
                if (value.Count!=1||!Guid.TryParse(value[0],out var parsed)||parsed==Guid.Empty) return Results.BadRequest();
                id=parsed;
            }
            return Results.Ok(await store.DeliveriesAsync(offset,limit,id,cancellationToken));
        });
        group.MapGet("/policy",async (NotificationStore store,CancellationToken cancellationToken)=>Results.Ok(await store.GetPolicyAsync(cancellationToken)));
        group.MapPut("/policy",async (HttpContext context,NotificationStore store,CancellationToken cancellationToken)=>
        {
            var bytes=new byte[NotificationContract.MaximumPolicyBytes+1];
            try
            {
                var count=0;
                while (count<bytes.Length)
                {
                    var read=await context.Request.Body.ReadAsync(bytes.AsMemory(count),cancellationToken);
                    if (read==0) break;
                    count+=read;
                }
                if (count==0) return Results.BadRequest();
                if (count>NotificationContract.MaximumPolicyBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                using var document=JsonDocument.Parse(bytes.AsMemory(0,count),new JsonDocumentOptions { MaxDepth=2 });
                if (document.RootElement.ValueKind!=JsonValueKind.Object) return Results.BadRequest();
                var seen=new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in document.RootElement.EnumerateObject())
                    if (!PolicyProperties.Contains(property.Name)||!seen.Add(property.Name)) return Results.BadRequest();
                // Every nonnullable contract field must be explicit; an omitted boolean must not
                // silently disable a channel or a local security notification category.
                foreach (var required in new[] { "expectedVersion","criticalAlerts","monitoringChanges","offlineMinutes","groupMinutes",
                    "webhookEnabled","clearWebhookSecret","clearWebhookDestination","emailEnabled","smtpPort","clearSmtpPassword" })
                    if (!seen.Contains(required)) return Results.BadRequest();
                var request=JsonSerializer.Deserialize<NotificationPolicyWrite>(bytes.AsSpan(0,count),Json);
                if (request is null) return Results.BadRequest();
                var saved=await store.UpdatePolicyAsync(request,cancellationToken);
                return saved is null?Results.Conflict():Results.Ok(saved);
            }
            catch (JsonException) { return Results.BadRequest(); }
            catch (ArgumentException error) { return Results.BadRequest(new { code=error.Message is "invalid_policy" or "invalid_webhook" or "invalid_email" or "invalid_secret" or "credentials_unavailable"?error.Message:"invalid_policy" }); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }).WithMetadata(new RequestSizeLimitAttribute(NotificationContract.MaximumPolicyBytes));
    }

    private static bool TryPage(HttpContext context,out int offset,out int limit)
    {
        offset=0; limit=50;
        if (context.Request.Query.TryGetValue("offset",out var offsetText) && (offsetText.Count!=1||!int.TryParse(offsetText[0],out offset))) return false;
        if (context.Request.Query.TryGetValue("limit",out var limitText) && (limitText.Count!=1||!int.TryParse(limitText[0],out limit))) return false;
        return offset is >=0 and <=NotificationStore.MaximumOffset && limit is >=1 and <=NotificationContract.MaximumPageSize;
    }
}
