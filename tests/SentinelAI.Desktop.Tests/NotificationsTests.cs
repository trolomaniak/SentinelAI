using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Localization;

internal static class NotificationsTests
{
    private static int _checks;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly DateTimeOffset Now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Endpoint = Guid.Parse("fa8fd9a7-59e3-4932-a649-1129294a1241");
    internal static NotificationPolicy Policy() => new(4, true, true, 15, 5, false, null, false, false, false, null, 587, null, false, null, null, "available");
    private static NotificationSummary Item(int index) => new(Guid.Parse("11111111-1111-1111-1111-" + index.ToString("D12")), "criticalAlertReopened", Endpoint,
        "{Binding hostile}<script>literal endpoint</script>", Guid.NewGuid(), "rule.synthetic", "critical", 7, Now, Now.AddMinutes(1), null);
    public static async Task<int> RunAsync()
    {
        _checks = 0;
        await ViewModelAsync();
        await SessionAsync();
        await TransportAsync();
        await TransportIsolationAsync();
        Console.WriteLine($"Desktop notifications: {_checks} assertions passed.");
        return _checks;
    }
    private static void Check(bool condition, string reason) { _checks++; if (!condition) throw new InvalidOperationException(reason); }
    private static async Task ViewModelAsync()
    {
        var client = new FakeClient();
        using var model = new NotificationsViewModel(client);
        Check(!model.CanSavePolicy && model.Rows.Count == 0, "Notification settings were editable before reading Core's version.");
        await model.RefreshAsync();
        Check(model.Rows.Count == NotificationsViewModel.PageSize && model.CanNextPage && !model.CanPreviousPage, "Notification paging did not expose the first bounded page.");
        Check(model.Rows[0].Endpoint == "{Binding hostile}<script>literal endpoint</script>" && model.Rows[0].Occurrences.Contains('7'), "The local center lost literal endpoint text or grouped occurrence count.");
        Check(!model.WebhookEnabled && !model.EmailEnabled && client.Writes == 0, "Reading notifications enabled or contacted an external channel.");
        await model.NextPageAsync();
        Check(model.Rows.Count == 5 && model.CanPreviousPage && !model.CanNextPage && client.LastOffset == 25, "Notification second-page bounds were wrong.");
        await model.PreviousPageAsync();
        model.SelectedNotification = model.Rows[0];
        await model.ShowSelectedDeliveriesAsync();
        Check(client.LastDeliveryId == model.SelectedNotification?.NotificationId, "Selected delivery history used a different notification ID.");
        await model.ShowAllDeliveriesAsync();
        Check(client.LastDeliveryId is null && model.CanNextDeliveryPage, "All-delivery history retained the selected notification filter.");
        await model.NextDeliveryPageAsync();
        Check(model.DeliveryRows.Count == 5 && model.CanPreviousDeliveryPage && !model.CanNextDeliveryPage, "Delivery paging was not bounded independently.");
        model.UnreadOnly = true;
        await model.ApplyFilterAsync();
        model.SelectedNotification = model.Rows[0];
        await model.MarkSelectedReadAsync();
        Check(client.Reads == 1 && model.Rows.All(r => r.NotificationId != client.LastReadId) && model.PageText.Contains("29", StringComparison.Ordinal), "Mark-read did not refresh unread state and counts.");
        model.CriticalAlerts = false; model.OfflineMinutes = 30; model.GroupMinutes = 10;
        Check(client.Writes == 0, "Editing notification controls wrote policy without an explicit save.");
        await model.SavePolicyAsync(default, default, default);
        Check(client.LastWrite is { ExpectedVersion: 4, CriticalAlerts: false, OfflineMinutes: 30, GroupMinutes: 10, SmtpPort: 587, WebhookUrl: null, WebhookSecret: null, SmtpPassword: null },
            "Explicit policy save lost CAS, bounded settings or write-only metadata semantics.");
        Check(client.LastSecretLengths.SequenceEqual([0, 0, 0]) && !client.LastWrite!.ClearSmtpPassword, "Blank secret inputs cleared protected values.");
        var url = "https://public.example/hook?token=synthetic".ToCharArray();
        var secret = "Synthetic-Webhook-Secret".ToCharArray();
        var password = "Synthetic-SMTP-Password".ToCharArray();
        model.WebhookEnabled = true;
        await model.SavePolicyAsync(url, secret, password);
        Check(client.LastSecretLengths.SequenceEqual([url.Length, secret.Length, password.Length]) && client.LastWrite!.WebhookUrl is null,
            "Secret input buffers were not passed separately from policy metadata.");
        Check(!typeof(NotificationsViewModel).GetProperties().Any(p => p.Name is "WebhookUrl" or "WebhookSecret" or "SmtpPassword"), "A plaintext secret became a view-model property.");
        model.ClearWebhookSecret = true; model.ClearSmtpPassword = true;
        var previous = client.Writes;
        await model.SavePolicyAsync(default, secret, default);
        Check(client.Writes == previous && model.Message.Contains("invalid", StringComparison.Ordinal), "Conflicting replace/clear choices reached Core.");
        await model.SavePolicyAsync(default, default, default);
        Check(client.LastWrite is { ClearWebhookSecret: true, ClearSmtpPassword: true }, "Explicit protected-value clear flags were lost.");
        client.WriteOutcome = NotificationRequestOutcome.Conflict;
        await model.SavePolicyAsync(default, default, default);
        previous = client.Writes;
        await model.SavePolicyAsync(default, default, default);
        Check(model.NeedsRefresh && !model.CanSavePolicy && client.Writes == previous && model.Message.Contains("changed elsewhere", StringComparison.Ordinal), "A policy conflict allowed a blind repeat write.");
        client.WriteOutcome = NotificationRequestOutcome.Success;
        await model.RefreshAsync();
        Check(model.CanSavePolicy && !model.NeedsRefresh, "An explicit refresh did not restore authoritative policy editing.");
        model.OfflineMinutes = 4;
        await model.SavePolicyAsync(default, default, default);
        Check(client.Writes == previous, "An offline threshold below five minutes reached Core.");
        model.OfflineMinutes = 120; model.GroupMinutes = 61;
        await model.SavePolicyAsync(default, default, default);
        Check(client.Writes == previous, "A grouping window above sixty minutes reached Core.");
        client.PolicyOutcome = NotificationRequestOutcome.Unavailable;
        await model.RefreshAsync();
        model.SelectedNotification = model.Rows[0];
        Check(model.Rows.Count > 0 && model.CanMarkRead && !model.CanSavePolicy, "An unavailable policy disabled the independent local center.");
        model.Clear();
        Check(model.Policy is null && model.Rows.Count == 0 && model.DeliveryRows.Count == 0 && model.SmtpHost.Length == 0 && !model.EmailEnabled && !model.CanSavePolicy,
            "Session reset retained notification data or editable channel state.");
        Localizer.Use(UiLanguage.Polish);
        try
        {
            using var polish = new NotificationsViewModel(new FakeClient());
            await polish.RefreshAsync();
            Check(polish.Rows[0].Title == "Ponownie otwarty alert krytyczny" && polish.Rows[0].ReadState == "Nieprzeczytane", "Notification rows were not localized into Polish.");
        }
        finally { Localizer.Use(UiLanguage.English); }
    }

    private static async Task SessionAsync()
    {
        var client = new FakeClient();
        var held = new TaskCompletionSource<NotificationResult<NotificationPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Held = held;
        using var model = new NotificationsViewModel(client);
        var expired = 0; model.SessionExpired += (_, _) => expired++;
        var pending = model.RefreshAsync();
        var cancellation = client.LastToken;
        model.Clear();
        client.Held = null;
        await model.RefreshAsync();
        held.SetResult(new(NotificationRequestOutcome.Unauthenticated));
        await pending;
        Check(cancellation.IsCancellationRequested && model.Rows.Count == 25 && expired == 0, "An old cancelled page request affected a replacement session.");
        client.ListOutcome = NotificationRequestOutcome.Unauthenticated;
        await model.RefreshAsync();
        Check(expired == 1 && model.Rows.Count == 0 && model.Policy is null, "Current session expiry did not erase notification state.");
        client.ListOutcome = NotificationRequestOutcome.Success;
        client.Held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        pending = model.RefreshAsync(); cancellation = client.LastToken;
        model.Dispose();
        client.Held.SetResult(new(NotificationRequestOutcome.Success, new(0, 0, 0, 25, [])));
        await pending;
        Check(cancellation.IsCancellationRequested && !model.CanRefresh && model.Rows.Count == 0, "Closing the notification center published an in-flight response.");
    }

    private static NotificationPage EmptyPage(int offset = 0, int limit = 25) => new(0, 0, offset, limit, []);
    private static HttpResponseMessage Response(object body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(JsonSerializer.Serialize(body, Json), Encoding.UTF8, "application/json") };
        response.Headers.CacheControl = new() { NoStore = true };
        return response;
    }
    private static async Task TransportAsync()
    {
        var handler = new Handler(); var trust = new Trust();
        using var client = new HttpAuthenticationClient(trust, handler);
        Check((await client.GetNotificationsAsync(0, 25, false, default)).Outcome == NotificationRequestOutcome.Unauthenticated && handler.NotificationCalls == 0, "Notification reads bypassed sign-in.");
        await client.SignInAsync("admin", "Synthetic-Notification-Password!".AsMemory(), default);
        handler.Next = (_, _) => Task.FromResult(Response(EmptyPage()));
        Check((await client.GetNotificationsAsync(0, 25, false, default)).Outcome == NotificationRequestOutcome.Success && handler.LastUri!.PathAndQuery == "/api/admin/notifications?offset=0&limit=25&unreadOnly=false" && handler.Authenticated,
            "The local center used the wrong bounded authenticated route.");
        var row = Item(1);
        handler.Next = (_, _) => Task.FromResult(Response(new NotificationPage(1, 1, 0, 25, [row])));
        Check((await client.GetNotificationsAsync(0, 25, true, default)).Value?.Items[0].Occurrences == 7, "The typed grouped notification response was rejected.");
        foreach (var mutate in new Action<JsonObject>[]
        {
            r => r["extra"] = "private", r => r["offset"] = 1, r => r["items"]![0]!["endpointId"] = Guid.Empty.ToString(),
            r => r["items"]![0]!["occurrences"] = 0, r => r["items"]![0]!["readUtc"] = Now.ToString("O"),
            r => r["items"]![0]!["endpointName"] = "bad\nname", r => r["items"]![0]!["kind"] = "executeLink"
        })
        {
            var body = JsonSerializer.SerializeToNode(new NotificationPage(1, 1, 0, 25, [row]), Json)!.AsObject(); mutate(body);
            handler.Next = (_, _) => Task.FromResult(Response(body));
            Check((await client.GetNotificationsAsync(0, 25, true, default)).Outcome == NotificationRequestOutcome.InvalidResponse, "A malformed, inconsistent or secret-bearing notification response was accepted.");
        }
        handler.Next = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        Check((await client.MarkNotificationReadAsync(row.NotificationId, default)).Outcome == NotificationRequestOutcome.Success && handler.LastMethod == HttpMethod.Put && handler.LastBody.Length == 0,
            "Mark-read did not use the body-free PUT route.");
        handler.Next = (_, _) => Task.FromResult(Response(new NotificationDeliveryPage(0, 0, 25, [])));
        Check((await client.GetNotificationDeliveriesAsync(0, 25, row.NotificationId, default)).Outcome == NotificationRequestOutcome.Success && handler.LastUri!.Query.EndsWith(row.NotificationId.ToString("D"), StringComparison.Ordinal), "Delivery history lost its selected notification scope.");
        foreach (var mutate in new Action<JsonObject>[]
        {
            r => r["webhookUrl"] = "https://public.example/token", r => r["smtpPassword"] = "secret", r => r["offlineMinutes"] = 4,
            r => r["groupMinutes"] = 61, r => r["smtpPort"] = 25, r => { r["webhookOrigin"] = "https://public.example/hook?token=private"; r["hasWebhookDestination"] = true; }
        })
        {
            var body = JsonSerializer.SerializeToNode(Policy(), Json)!.AsObject(); mutate(body);
            handler.Next = (_, _) => Task.FromResult(Response(body));
            Check((await client.GetNotificationPolicyAsync(default)).Outcome == NotificationRequestOutcome.InvalidResponse, "The policy reader accepted returned secrets, full destinations or invalid settings.");
        }
        handler.Next = (_, _) => Task.FromResult(Response(Policy()));
        var write = new NotificationPolicyWrite(4, true, false, 30, 10, false, null, null, false, false, false, null, 587, null, null, false, null, null);
        var url = "https://public.example/hook?token=synthetic".ToCharArray();
        var secret = "Synthetic-Webhook-Token".ToCharArray(); var password = "Synthetic-Smtp-Password".ToCharArray();
        var put = client.SetNotificationPolicyAsync(write, url, secret, password, default);
        Array.Clear(url); Array.Clear(secret); Array.Clear(password);
        Check((await put).Outcome == NotificationRequestOutcome.Success, "A valid policy response was rejected.");
        using (var body = JsonDocument.Parse(handler.LastBody))
            Check(body.RootElement.GetProperty("webhookUrl").GetString() == "https://public.example/hook?token=synthetic" && body.RootElement.GetProperty("smtpPassword").GetString() == "Synthetic-Smtp-Password" && body.RootElement.GetProperty("expectedVersion").GetInt64() == 4,
                "Policy input buffers were consumed after their lifetime or lost CAS.");
        await client.SetNotificationPolicyAsync(write with { ClearSmtpPassword = true }, default, default, default, default);
        using (var body = JsonDocument.Parse(handler.LastBody))
            Check(body.RootElement.GetProperty("webhookUrl").ValueKind == JsonValueKind.Null && body.RootElement.GetProperty("smtpPassword").ValueKind == JsonValueKind.Null && body.RootElement.GetProperty("clearSmtpPassword").GetBoolean(), "Blank protected values did not retain by null with explicit removal flags.");
        handler.Next = (_, _) => Task.FromResult(Response(new { error = "synthetic private server diagnostics" }, HttpStatusCode.Conflict));
        Check((await client.SetNotificationPolicyAsync(write, default, default, default, default)).Outcome == NotificationRequestOutcome.Conflict, "Policy conflicts were not safe and typed.");
        handler.Next = (_, _) => { var r = Response(Policy()); r.Headers.CacheControl = null; return Task.FromResult(r); };
        Check((await client.GetNotificationPolicyAsync(default)).Outcome == NotificationRequestOutcome.InvalidResponse, "Cacheable protected-policy metadata was accepted.");
        handler.Next = (_, _) => Task.FromResult(Response(new string('x', NotificationContract.MaximumPolicyBytes)));
        Check((await client.GetNotificationPolicyAsync(default)).Outcome == NotificationRequestOutcome.TooLarge, "A declared oversized policy response was not bounded.");
        var stream = new CountingStream(Encoding.UTF8.GetBytes(new string(' ', NotificationContract.MaximumResponseBytes + 100)));
        handler.Next = (_, _) => { var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }; r.Content.Headers.ContentType = new("application/json"); r.Headers.CacheControl = new() { NoStore = true }; return Task.FromResult(r); };
        Check((await client.GetNotificationsAsync(0, 25, false, default)).Outcome == NotificationRequestOutcome.TooLarge && stream.BytesRead == NotificationContract.MaximumResponseBytes + 1, "An unknown-length response exceeded its bounded read.");
        trust.Allowed = false; var calls = handler.NotificationCalls;
        Check((await client.GetNotificationPolicyAsync(default)).Outcome == NotificationRequestOutcome.UntrustedConnection && handler.NotificationCalls == calls,
            "A failed Core trust check sent notification credentials.");
    }

    private static async Task TransportIsolationAsync()
    {
        var handler = new Handler();
        using var client = new HttpAuthenticationClient(new Trust(), handler);
        await client.SignInAsync("admin", "Synthetic-Notification-Password!".AsMemory(), default);
        var held = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken observed = default;
        handler.Next = (_, token) => { observed = token; return held.Task; };
        var pending = client.GetNotificationPolicyAsync(default);
        client.SignOut();
        await client.SignInAsync("admin", "Synthetic-Notification-Password!".AsMemory(), default);
        held.SetResult(Response(Policy(), HttpStatusCode.Unauthorized));
        Check((await pending).Outcome == NotificationRequestOutcome.Unauthenticated && observed.IsCancellationRequested, "Sign-out did not cancel/suppress an old notification request.");
        handler.Next = (_, _) => Task.FromResult(Response(Policy()));
        Check((await client.GetNotificationPolicyAsync(default)).Outcome == NotificationRequestOutcome.Success, "A stale unauthorized notification response invalidated a replacement session.");
        using var cancellation = new CancellationTokenSource();
        handler.Next = async (_, token) => { await Task.Delay(Timeout.Infinite, token); return Response(Policy()); };
        pending = client.GetNotificationPolicyAsync(cancellation.Token); cancellation.Cancel();
        try { await pending; Check(false, "Caller notification cancellation was swallowed."); }
        catch (OperationCanceledException error) { Check(error.CancellationToken == cancellation.Token, "Notification cancellation lost its caller token."); }
    }

    private sealed class FakeClient : INotificationsClient
    {
        private readonly List<NotificationSummary> _items = Enumerable.Range(1, 30).Select(Item).ToList();
        internal NotificationPolicy Current = Policy();
        internal NotificationRequestOutcome PolicyOutcome = NotificationRequestOutcome.Success, ListOutcome = NotificationRequestOutcome.Success, WriteOutcome = NotificationRequestOutcome.Success;
        internal TaskCompletionSource<NotificationResult<NotificationPage>>? Held;
        internal CancellationToken LastToken;
        internal int LastOffset, Reads, Writes;
        internal Guid? LastDeliveryId, LastReadId;
        internal NotificationPolicyWrite? LastWrite;
        internal int[] LastSecretLengths = [];
        public Task<NotificationResult<NotificationPage>> GetNotificationsAsync(int offset, int limit, bool unreadOnly, CancellationToken token)
        {
            LastToken = token; LastOffset = offset;
            var rows = _items.Where(x => !unreadOnly || x.ReadUtc is null).ToArray();
            return Held?.Task ?? Task.FromResult(new NotificationResult<NotificationPage>(ListOutcome, new(rows.Length, _items.Count(x => x.ReadUtc is null), offset, limit, rows.Skip(offset).Take(limit).ToArray())));
        }
        public Task<NotificationResult<bool>> MarkNotificationReadAsync(Guid id, CancellationToken token)
        { Reads++; LastReadId = id; var index = _items.FindIndex(x => x.NotificationId == id); _items[index] = _items[index] with { ReadUtc = Now }; return Task.FromResult(new NotificationResult<bool>(NotificationRequestOutcome.Success, true)); }
        public Task<NotificationResult<NotificationDeliveryPage>> GetNotificationDeliveriesAsync(int offset, int limit, Guid? id, CancellationToken token)
        {
            LastDeliveryId = id;
            var all = Enumerable.Range(1, 30).Select(_ => new NotificationDelivery(Guid.NewGuid(), id ?? _items[0].NotificationId, "webhook", "retry", 1, Now, Now, Now.AddMinutes(1), "timeout")).ToArray();
            return Task.FromResult(new NotificationResult<NotificationDeliveryPage>(NotificationRequestOutcome.Success, new(all.Length, offset, limit, all.Skip(offset).Take(limit).ToArray())));
        }
        public Task<NotificationResult<NotificationPolicy>> GetNotificationPolicyAsync(CancellationToken token) => Task.FromResult(new NotificationResult<NotificationPolicy>(PolicyOutcome, Current));
        public Task<NotificationResult<NotificationPolicy>> SetNotificationPolicyAsync(NotificationPolicyWrite policy, ReadOnlyMemory<char> url, ReadOnlyMemory<char> secret, ReadOnlyMemory<char> password, CancellationToken token)
        {
            Writes++; LastWrite = policy; LastSecretLengths = [url.Length, secret.Length, password.Length];
            return Task.FromResult(new NotificationResult<NotificationPolicy>(WriteOutcome, Current));
        }
    }
    private sealed class Trust : ICoreEndpointTrust
    { internal bool Allowed = true; public Task<bool> IsTrustedAsync(Uri origin, CancellationToken token) => Task.FromResult(Allowed); }
    private sealed class Handler : HttpMessageHandler
    {
        internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Next = (_, _) => Task.FromResult(Response(Policy()));
        internal int NotificationCalls;
        internal HttpMethod? LastMethod;
        internal Uri? LastUri;
        internal bool Authenticated;
        internal byte[] LastBody = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Response(new { tokenType = "Bearer", accessToken = "synthetic-notification-token", expiresIn = 900 });
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Response(new { username = "admin", role = "administrator" });
            NotificationCalls++; LastMethod = request.Method; LastUri = request.RequestUri;
            Authenticated = request.Headers.Authorization?.Scheme == "Bearer";
            LastBody = request.Content is null ? [] : (await request.Content.ReadAsByteArrayAsync(token)).ToArray();
            return await Next(request, token);
        }
    }
    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        { var read = await base.ReadAsync(buffer, token); BytesRead += read; return read; }
    }
}
