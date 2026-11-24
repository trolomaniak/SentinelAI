using System.Net;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.Overview;
using SentinelAI.Desktop.Foundation;

internal static class OperationsOverviewTests
{
    private const string Bearer = "synthetic-overview-token";
    private const string AlertTitle = "{Binding synthetic}<alert>";
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid First = Guid.Parse("e24ca7c3-ddcb-447d-9798-d21ce5dc6394");
    private static readonly Guid Second = Guid.Parse("bd05e0fb-507e-4ad5-887a-a2bc0dbd8dff");
    private static readonly OperationsOverviewSnapshot Empty = new(Now, new(0, 0, 0, 0, 0), [], [], [], [], [], null);
    private static readonly OperationsOverviewSnapshot Populated = new(Now, new(8, 1, 2, 1, 1),
        [new(First, "Synthetic endpoint", AlertTitle, "critical", "open", Now.AddHours(-2)),
         new(Second, "Other endpoint", "High alert", "high", "investigating", Now.AddHours(-1))],
        [new MonitoringEndpointSummary(First, "Synthetic endpoint", "offline", Now.AddHours(-2), "stale", Now.AddDays(-3),
            "missing", null, null, 0, 0, true, true)],
        [new(First, "Synthetic endpoint", "monitoringOffline", 2, Now.AddHours(-1))],
        [new(First, "RISK-01", "Review test", true, true, false)],
        [new(First, "Synthetic endpoint", AlertTitle, "resolved", "open", Now),
         new(First, "Synthetic endpoint", AlertTitle, null, "open", Now.AddHours(-24))],
        Now.AddDays(-1));
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await ViewModelAsync();
        Console.WriteLine($"Operations Overview: {_assertions} assertions passed.");
        return _assertions;
    }

    private static async Task TransportAsync()
    {
        var trust = new Trust();
        var handler = new Handler();
        using var client = new HttpAuthenticationClient(trust, handler);
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.Unauthenticated && handler.Reads == 0,
            "Overview called Core before sign-in.");
        await SignInAsync(client);

        handler.Response = () => Json(Populated);
        var result = await client.GetOperationsOverviewAsync(default);
        Check(result.Outcome == DeviceReadOutcome.Success && result.Value is { } overview && overview.Counts == Populated.Counts &&
            overview.PriorityAlerts.SequenceEqual(Populated.PriorityAlerts) && overview.CoverageIssues.SequenceEqual(Populated.CoverageIssues) &&
            overview.UnreadNotifications.SequenceEqual(Populated.UnreadNotifications) && overview.RisksNeedingAttention.SequenceEqual(Populated.RisksNeedingAttention) &&
            overview.RecentAlertChanges.SequenceEqual(Populated.RecentAlertChanges) && overview.LastSuccessfulBackupUtc == Populated.LastSuccessfulBackupUtc,
            "Overview lost the counts, preview rows, inclusive time boundaries, or backup timestamp.");
        Check(handler.LastUri == new Uri("http://127.0.0.1:5000/api/admin/overview") && handler.LastMethod == HttpMethod.Get &&
            handler.LastAuthorization == "Bearer " + Bearer, "Overview did not use the authenticated local read-only route.");

        handler.Response = () => Json(Empty);
        result = await client.GetOperationsOverviewAsync(default);
        Check(result.Outcome == DeviceReadOutcome.Success && result.Value is { Counts.ActiveEndpoints: 0, LastSuccessfulBackupUtc: null },
            "An empty Overview did not load successfully.");
        handler.Response = () => new(HttpStatusCode.ServiceUnavailable);
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.Unavailable, "A failed read was reported as an empty Overview.");

        var alert = Populated.PriorityAlerts[0];
        var endpoint = Populated.CoverageIssues[0];
        var risk = Populated.RisksNeedingAttention[0];
        var change = Populated.RecentAlertChanges[0];
        foreach (var invalid in new[]
        {
            Populated with { Counts = Populated.Counts with { ActiveEndpoints = 0 } },
            Populated with { Counts = Populated.Counts with { PriorityAlerts = 7 } },
            Populated with { PriorityAlerts = [alert, alert] },
            Populated with { PriorityAlerts = Populated.PriorityAlerts.Reverse().ToArray() },
            Populated with { PriorityAlerts = [alert with { Status = "accepted" }, Populated.PriorityAlerts[1]] },
            Populated with { PriorityAlerts = [alert with { Title = new string('a', OperationsOverviewContract.MaximumTextLength + 1) }, Populated.PriorityAlerts[1]] },
            Populated with { PriorityAlerts = [alert with { Title = "invisible\u202econtent" }, Populated.PriorityAlerts[1]] },
            Populated with { CoverageIssues = [endpoint with { HasIssue = false }] },
            Populated with { RisksNeedingAttention = [risk with { ReviewOverdue = false, AcceptanceExpired = false }] },
            Populated with { UnreadNotifications = [Populated.UnreadNotifications[0] with { Occurrences = 0 }] },
            Populated with { RecentAlertChanges = [change with { ChangedUtc = Now.AddTicks(1) }] },
            Populated with { RecentAlertChanges = [change with { ChangedUtc = Now.AddHours(-24).AddTicks(-1) }] },
            Populated with { RecentAlertChanges = Enumerable.Repeat(change, OperationsOverviewContract.PreviewLimit + 1).ToArray() }
        })
        {
            handler.Response = () => Json(invalid);
            Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.InvalidResponse, "Overview accepted an invalid count or preview.");
        }

        var emptyJson = JsonSerializer.Serialize(Empty, JsonOptions);
        handler.Response = () => Json(emptyJson.Insert(1, "\"evidence\":[],"));
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.InvalidResponse, "Overview accepted an unrecognized field.");
        handler.Response = () => Json(emptyJson.Insert(1, "\"lastSuccessfulBackupUtc\":null,"));
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.InvalidResponse, "Overview accepted duplicate response fields.");
        handler.Response = () => Json(emptyJson.Replace(",\"lastSuccessfulBackupUtc\":null", "", StringComparison.Ordinal));
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.InvalidResponse, "Overview accepted a missing nullable field.");

        using var tooLarge = new ReadFailureStream();
        handler.Response = () =>
        {
            var response = StreamJson(tooLarge);
            response.Content.Headers.ContentLength = OperationsOverviewContract.MaximumResponseBytes + 1;
            return response;
        };
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.TooLarge && tooLarge.ReadCalls == 0,
            "Overview read a response declared over 64 KiB.");
        foreach (var length in new[] { OperationsOverviewContract.MaximumResponseBytes, OperationsOverviewContract.MaximumResponseBytes + 1 })
        {
            using var stream = new NonSeekableStream(Encoding.UTF8.GetBytes(emptyJson.PadRight(length)));
            handler.Response = () => StreamJson(stream);
            var streamed = await client.GetOperationsOverviewAsync(default);
            Check(streamed.Outcome == (length == OperationsOverviewContract.MaximumResponseBytes ? DeviceReadOutcome.Success : DeviceReadOutcome.TooLarge) &&
                stream.BytesRead == length, "Overview did not enforce the 64 KiB response boundary on a streamed body.");
        }

        var held = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Held = held.Task;
        using (var cancellation = new CancellationTokenSource())
        {
            var pending = client.GetOperationsOverviewAsync(cancellation.Token);
            cancellation.Cancel();
            held.SetResult(Json(Populated));
            try { await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException error)
            {
                Check(error.CancellationToken == cancellation.Token, "Overview failed to retain the caller cancellation token.");
                pending = null;
            }
            Check(pending is null, "Overview accepted a result after the caller canceled.");
        }

        held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Held = held.Task;
        var stale = client.GetOperationsOverviewAsync(default);
        client.SignOut();
        await SignInAsync(client);
        handler.Held = null;
        held.SetResult(new(HttpStatusCode.Unauthorized));
        Check((await stale.WaitAsync(TimeSpan.FromSeconds(5))).Outcome == DeviceReadOutcome.Unauthenticated,
            "A request from the old session produced a view result.");
        handler.Response = () => Json(Empty);
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.Success, "A late 401 invalidated a new Overview session.");

        trust.Allowed = false;
        var calls = handler.Reads;
        Check((await client.GetOperationsOverviewAsync(default)).Outcome == DeviceReadOutcome.UntrustedConnection && handler.Reads == calls,
            "Overview sent a request after connection trust failed.");
    }

    private static async Task ViewModelAsync()
    {
        var client = new ControlledClient();
        using var model = new OperationsOverviewViewModel(client);
        await model.RefreshAsync();
        Check(model.Summary is { } empty && empty.Coverage.Summary.EndsWith(" · 0", StringComparison.Ordinal) &&
            empty.PriorityAlerts.Rows.Count == 0 && empty.RecentAlertChanges.Rows.Count == 0 &&
            empty.Backup.Summary == "No successful backup recorded." && model.StatusText.StartsWith("Snapshot at ", StringComparison.Ordinal),
            "The Overview did not distinguish an empty snapshot and absent backup from read failure.");

        client.Response = new(DeviceReadOutcome.Success, Populated);
        await model.RefreshAsync();
        Check(model.Summary is { } populated && populated.PriorityAlerts.Rows[0].Title == AlertTitle &&
            populated.PriorityAlerts.Rows[0].Detail.StartsWith("Critical · Open", StringComparison.Ordinal) &&
            populated.Coverage.Rows[0].Detail.Contains("Offline", StringComparison.Ordinal) &&
            populated.UnreadNotifications.Rows[0].Title == "Endpoint monitoring lost" &&
            populated.RisksNeedingAttention.Rows[0].Detail == "Review overdue · Acceptance expired" &&
            populated.RecentAlertChanges.Rows[0].Detail.StartsWith("Reopened", StringComparison.Ordinal) &&
            populated.RecentAlertChanges.Rows[1].Detail.StartsWith("Created", StringComparison.Ordinal) &&
            populated.Backup.Summary.EndsWith("2026-11-23 10:00:00 UTC", StringComparison.Ordinal),
            "The Overview did not render literal labels, action states, and backup history.");
        client.Response = new(DeviceReadOutcome.InvalidResponse);
        await model.RefreshAsync();
        Check(model.Summary is null && model.StatusText.Contains("unavailable", StringComparison.Ordinal) && model.CanRefresh,
            "A failed refresh showed stale details or did not offer retry.");

        var expiries = 0;
        model.SessionExpired += (_, _) => expiries++;
        var held = new TaskCompletionSource<DeviceReadResult<OperationsOverviewSnapshot>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Held = held.Task;
        var pending = model.RefreshAsync();
        var oldToken = client.LastToken;
        var reads = client.Reads;
        await model.RefreshAsync();
        Check(!model.CanRefresh && client.Reads == reads && model.StatusText == "Reading operations overview…",
            "The Overview did not show loading or started another read while busy.");
        model.Clear();
        Check(oldToken.IsCancellationRequested && model.Summary is null && model.StatusText.Length == 0, "Leaving the Overview did not clear and cancel.");
        client.Held = null;
        client.Response = new(DeviceReadOutcome.Success, Empty);
        await model.RefreshAsync();
        held.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await pending.WaitAsync(TimeSpan.FromSeconds(5));
        Check(expiries == 0 && model.Summary?.PriorityAlerts.Rows.Count == 0, "A canceled Overview request signed out a newer session.");

        held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Held = held.Task;
        pending = model.RefreshAsync();
        oldToken = client.LastToken;
        model.Clear();
        held.SetResult(new(DeviceReadOutcome.Success, Populated));
        await pending.WaitAsync(TimeSpan.FromSeconds(5));
        Check(oldToken.IsCancellationRequested && model.Summary is null && model.StatusText.Length == 0,
            "A stale successful read restored private Overview details after clear.");

        client.Held = null;
        client.Response = new(DeviceReadOutcome.Unauthenticated);
        await model.RefreshAsync();
        Check(expiries == 1 && model.Summary is null, "The active Overview session did not expire on a 401.");

        held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Held = held.Task;
        pending = model.RefreshAsync();
        oldToken = client.LastToken;
        model.Dispose();
        held.SetResult(new(DeviceReadOutcome.Success, Populated));
        await pending.WaitAsync(TimeSpan.FromSeconds(5));
        Check(oldToken.IsCancellationRequested && model.Summary is null && !model.CanRefresh,
            "Closing the Overview accepted a late result or retained data.");
    }

    private static async Task SignInAsync(HttpAuthenticationClient client) => Check(
        (await client.SignInAsync("admin", "Synthetic-Overview-Password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
        "Synthetic Overview login failed.");

    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value is string text ? text : JsonSerializer.Serialize(value, JsonOptions), Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage StreamJson(Stream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new("application/json");
        return response;
    }

    private static void Check(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class ControlledClient : IOperationsOverviewClient
    {
        public DeviceReadResult<OperationsOverviewSnapshot> Response = new(DeviceReadOutcome.Success, Empty);
        public Task<DeviceReadResult<OperationsOverviewSnapshot>>? Held;
        public CancellationToken LastToken;
        public int Reads;

        public Task<DeviceReadResult<OperationsOverviewSnapshot>> GetOperationsOverviewAsync(CancellationToken cancellationToken)
        {
            LastToken = cancellationToken;
            Reads++;
            return Held ?? Task.FromResult(Response);
        }
    }

    private sealed class Trust : ICoreEndpointTrust
    {
        public bool Allowed = true;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) => Task.FromResult(Allowed);
    }

    private sealed class Handler : HttpMessageHandler
    {
        public Func<HttpResponseMessage> Response = () => Json(Empty);
        public Task<HttpResponseMessage>? Held;
        public Uri? LastUri;
        public HttpMethod? LastMethod;
        public string? LastAuthorization;
        public int Reads;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login")
                return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Bearer + "\",\"expiresIn\":900}"));
            if (request.RequestUri.AbsolutePath == "/api/admin/me")
                return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
            Reads++;
            LastUri = request.RequestUri;
            LastMethod = request.Method;
            LastAuthorization = request.Headers.Authorization?.ToString();
            return Held ?? Task.FromResult(Response());
        }
    }
}
