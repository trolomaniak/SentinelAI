using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Core;
using SentinelAI.Core.Notifications;
using SentinelAI.Core.Persistence;
using SentinelAI.Hosting;

internal static class NotificationApiTests
{
    private static int _checks;
    private static void Check(bool condition, string code)
    { _checks++; if (!condition) throw new InvalidOperationException("Notification API: " + code); }

    internal static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-notification-api-" + Guid.NewGuid().ToString("N"));
        try
        {
            await using var app = CoreHost.Build(["--SentinelAI:DataDirectory=" + directory], false, builder =>
            {
                builder.Logging.ClearProviders();
                builder.Services.AddSingleton<INotificationCredentialProtection>(new SyntheticProtection());
                builder.Services.AddSingleton<INotificationSender>(new ForbiddenSender());
            }, configureBeforeAuthentication: application => application.Use((context, next) =>
            {
                // Only this test fixture installs the synthetic remote-address adapter.
                context.Connection.RemoteIpAddress = context.Request.Headers.ContainsKey("Synthetic-Remote") ? IPAddress.Parse("192.0.2.13") : IPAddress.Loopback;
                return next(context);
            }));
            app.Urls.Clear(); app.Urls.Add("http://127.0.0.1:0"); await app.StartAsync();
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false }) { BaseAddress = new Uri(app.Urls.Single()) };
            using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
            login.EnsureSuccessStatusCode();
            using var loginJson = JsonDocument.Parse(await login.Content.ReadAsByteArrayAsync());
            var bearer = loginJson.RootElement.GetProperty("accessToken").GetString()!;
            foreach (var path in new[] { "", "/policy", "/deliveries" })
            {
                using var response = await SendAsync(client, HttpMethod.Get, path);
                Check(response.StatusCode == HttpStatusCode.Unauthorized && response.Headers.CacheControl?.NoStore == true, "anonymous-refused-no-store");
            }
            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
            var enrollmentToken = await enrollments.IssueTokenAsync();
            var enrolled = (await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), enrollmentToken.Token))).Response!;
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/notifications/policy"))
            {
                request.Headers.Authorization = new("SentinelAgent", enrolled.EndpointId.ToString("D") + "." + enrolled.AgentCredential);
                using var response = await client.SendAsync(request);
                Check(response.StatusCode == HttpStatusCode.Unauthorized, "agent-cannot-read-notification-settings");
            }
            foreach (var route in new[] { "/api/admin/notifications", "/api/admin/notifications/policy", "/api/admin/notifications/deliveries" })
                Check(!LocalNetworkRoutes.IsAllowed("GET", route) && !LocalNetworkRoutes.IsAllowed("PUT", route), "lan-listener-denied");
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/notifications/policy"))
            {
                request.Headers.Authorization = new("Bearer", bearer); request.Headers.Add("Synthetic-Remote", "1");
                using var response = await client.SendAsync(request);
                Check(response.StatusCode == HttpStatusCode.Forbidden && response.Headers.CacheControl?.NoStore == true, "remote-administration-refused");
            }
            NotificationPolicy initial;
            using (var response = await SendAsync(client, HttpMethod.Get, "/policy", bearer))
            {
                Check(response.IsSuccessStatusCode && response.Headers.CacheControl?.NoStore == true, "policy-no-store");
                initial = (await response.Content.ReadFromJsonAsync<NotificationPolicy>())!;
                Check(initial is { WebhookEnabled: false, EmailEnabled: false, HasWebhookDestination: false, HasWebhookSecret: false, HasSmtpPassword: false }, "external-disabled-by-default");
            }
            using (var response = await SendAsync(client, HttpMethod.Get, "?offset=0&limit=100&unreadOnly=true", bearer))
            {
                var page = (await response.Content.ReadFromJsonAsync<NotificationPage>())!;
                Check(page.Total == 0 && page.Unread == 0 && page.Items.Count == 0 && page.Limit == 100, "empty-center-bounded-page");
            }
            foreach (var query in new[] { "?limit=101", "?limit=0", "?offset=-1", "?offset=100001", "?offset=1&offset=2", "?unreadOnly=maybe" })
            {
                using var response = await SendAsync(client, HttpMethod.Get, query, bearer);
                Check(response.StatusCode == HttpStatusCode.BadRequest, "invalid-page-refused");
            }
            using (var response = await SendAsync(client, HttpMethod.Get, "/deliveries?notificationId=00000000-0000-0000-0000-000000000000", bearer))
                Check(response.StatusCode == HttpStatusCode.BadRequest, "empty-notification-filter-refused");
            using (var response = await SendAsync(client, HttpMethod.Put, "/" + Guid.NewGuid().ToString("D") + "/read", bearer))
                Check(response.StatusCode == HttpStatusCode.NotFound, "unknown-read-not-found");

            const string url = "https://example.com/synthetic-private-token?access=synthetic-url-secret";
            const string webhookSecret = "synthetic-signature-secret-not-production";
            const string smtpPassword = "synthetic-smtp-password-not-production";
            var write = new NotificationPolicyWrite(initial.Version, true, true, 5, 1, false, url, webhookSecret, false, false,
                false, "smtp.example.com", 587, "synthetic-user", smtpPassword, false, "core@example.com", "owner@example.com");
            using (var response = await SendAsync(client, HttpMethod.Put, "/policy", bearer, JsonContent.Create(write)))
            {
                Check(response.IsSuccessStatusCode && response.Headers.CacheControl?.NoStore == true, "save-disabled-channel-settings");
                var text = await response.Content.ReadAsStringAsync();
                Check(!text.Contains("synthetic-private-token", StringComparison.Ordinal) && !text.Contains(webhookSecret, StringComparison.Ordinal) &&
                    !text.Contains(smtpPassword, StringComparison.Ordinal) && !text.Contains("synthetic-url-secret", StringComparison.Ordinal), "write-only-values-never-returned");
                var saved = JsonSerializer.Deserialize<NotificationPolicy>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
                Check(saved.Version == initial.Version + 1 && saved.HasWebhookDestination && saved.HasWebhookSecret && saved.HasSmtpPassword &&
                    saved.WebhookOrigin == "https://example.com", "sanitized-origin-and-secret-presence-only");
            }
            using (var response = await SendAsync(client, HttpMethod.Put, "/policy", bearer, JsonContent.Create(write)))
                Check(response.StatusCode == HttpStatusCode.Conflict, "stale-version-conflict");
            foreach (var malformed in new[] { "{}", "{\"expectedVersion\":1,\"expectedVersion\":1}", "{\"url\":\"https://example.com/\"}", "[]" })
            {
                using var response = await SendAsync(client, HttpMethod.Put, "/policy", bearer, new StringContent(malformed, Encoding.UTF8, "application/json"));
                Check(response.StatusCode == HttpStatusCode.BadRequest, "malformed-policy-refused");
            }
            foreach (var invalid in new[] { write with { ExpectedVersion = initial.Version + 1, WebhookUrl = "http://example.com/" },
                write with { ExpectedVersion = initial.Version + 1, OfflineMinutes = 4 }, write with { ExpectedVersion = initial.Version + 1, GroupMinutes = 0 },
                write with { ExpectedVersion = initial.Version + 1, EmailEnabled = true, EmailFrom = "one@example.com\r\nBcc: two@example.com" } })
            {
                using var response = await SendAsync(client, HttpMethod.Put, "/policy", bearer, JsonContent.Create(invalid));
                Check(response.StatusCode == HttpStatusCode.BadRequest, "unsafe-policy-refused");
            }
            using (var response = await SendAsync(client, HttpMethod.Put, "/policy", bearer,
                new StringContent(new string('x', NotificationContract.MaximumPolicyBytes + 1), Encoding.UTF8, "application/json")))
                Check(response.StatusCode == HttpStatusCode.RequestEntityTooLarge, "oversized-policy-refused");
            await using (var database = new FileStream(app.Services.GetRequiredService<AdminStore>().DatabasePath,
                FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using var bytes = new MemoryStream(); await database.CopyToAsync(bytes);
                Check(!Encoding.UTF8.GetString(bytes.ToArray()).Contains(smtpPassword, StringComparison.Ordinal), "database-no-plaintext-password");
            }
            await app.StopAsync();
        }
        finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
        Console.WriteLine($"Notification API tests passed: {_checks} checks (auth, bounds, privacy, policy concurrency; no external sending).");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string suffix, string? bearer = null, HttpContent? content = null)
    {
        using var request = new HttpRequestMessage(method, "/api/admin/notifications" + suffix) { Content = content };
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await client.SendAsync(request);
    }
    private sealed class SyntheticProtection : INotificationCredentialProtection
    {
        public bool IsSupported => true;
        public byte[] Protect(ReadOnlySpan<byte> value) => value.ToArray().Select(b => (byte)(b ^ 0x5a)).ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> value) => Protect(value);
    }
    private sealed class ForbiddenSender : INotificationSender
    {
        public Task<NotificationSendResult> SendAsync(NotificationPayload payload, NotificationDestination destination, CancellationToken cancellationToken)
            => throw new InvalidOperationException("External transport must remain disabled in API fixtures.");
    }
}
