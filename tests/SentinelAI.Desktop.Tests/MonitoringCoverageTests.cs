using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Desktop.Foundation;

internal static class MonitoringCoverageTests
{
    private const string Path = "/api/admin/monitoring-coverage";
    private const string Token = "synthetic-coverage-bearer";
    private static readonly DateTimeOffset Now = new(2099, 1, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid First = Guid.Parse("b143ee5f-fbc8-4cfa-83da-bcf1d400839e");
    private static readonly Guid Second = Guid.Parse("60d29698-37fb-4a55-b369-34a73caa3f65");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await PagingAsync();
        await SessionAndSelectionAsync();
        Console.WriteLine($"Desktop monitoring coverage: {_assertions} assertions passed.");
        return _assertions;
    }

    private static async Task TransportAsync()
    {
        var trust = new Trust();
        var handler = new Handler();
        using var client = new HttpAuthenticationClient(trust, handler);
        Check((await client.GetMonitoringEndpointsAsync(0, 1, true, default)).Outcome == DeviceReadOutcome.Unauthenticated && handler.LastPath is null,
            "Coverage exposed a network read before sign-in.");
        await SignInAsync(client);
        var summary = Summary(First);
        handler.Response = () => Json(new MonitoringEndpointPage(Now, 4, 2, 0, 1, 12, [summary]));
        var page = await client.GetMonitoringEndpointsAsync(0, 1, true, default);
        Check(page.Value is { Total: 4, Matching: 2, Items.Count: 1 } && page.Value.Items[0] == summary &&
            handler.LastPath == Path + "?offset=0&limit=1&issuesOnly=true" && handler.Bearer == "Bearer " + Token,
            "Coverage lost the authenticated filter, total or literal summary.");
        var detail = Detail(First);
        handler.Response = () => Json(detail);
        var sources = await client.GetMonitoringEndpointAsync(First, default);
        Check(sources.Value is { Telemetry.Count: 9, EventChannels.Count: 4 } && sources.Value.EventChannels[0].CheckpointRecordId == 42 &&
            handler.LastPath == $"{Path}/{First:D}", "Coverage did not preserve all sources or address the requested computer.");
        var gaps = GapPage(First, 1, 1, 2);
        handler.Response = () => Json(gaps);
        var history = await client.GetMonitoringGapsAsync(First, 1, 1, default);
        Check(history.Value is { Items.Count: 1 } && history.Value.Items[0].CoverageRestart && handler.LastPath == $"{Path}/{First:D}/gaps?offset=1&limit=1",
            "Coverage did not read the specified page of continuity notices.");

        foreach (var bad in new object[]
                 {
                     detail with { Endpoint = Summary(Second) }, detail with { Telemetry = [.. detail.Telemetry.Skip(1), detail.Telemetry[1]] },
                     detail with { EventChannels = [.. detail.EventChannels.Skip(1)] }, detail with { Endpoint = summary with { Name = "hidden\u200bname" } },
                     detail with { Endpoint = summary with { HeartbeatState = "safe" } }, detail with { Endpoint = summary with { CurrentEventChannels = 5 } },
                     detail with { Endpoint = summary with { InventoryCollectedUtc = Now.ToOffset(TimeSpan.FromHours(1)) } }
                 })
        {
            handler.Response = () => Json(bad);
            Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.InvalidResponse,
                "An invalid coverage detail was accepted.");
        }
        var extra = JsonSerializer.SerializeToNode(detail, JsonOptions)!.AsObject();
        extra["rawEvents"] = new JsonArray();
        handler.Response = () => Json(extra);
        Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.InvalidResponse, "An unknown detail field was accepted.");
        handler.Response = () => Json(gaps with { Offset = 0 });
        Check((await client.GetMonitoringGapsAsync(First, 1, 1, default)).Outcome == DeviceReadOutcome.InvalidResponse, "A wrong continuity page was accepted.");
        handler.Response = () => Json(new MonitoringEndpointPage(Now, 4, 2, 0, 1, 12, [summary with { HasIssue = false }]));
        Check((await client.GetMonitoringEndpointsAsync(0, 1, true, default)).Outcome == DeviceReadOutcome.InvalidResponse,
            "An issue-only result contained a computer without an issue.");
        handler.Response = () => new(HttpStatusCode.OK) { Content = new StringContent(new string(' ', MonitoringCoverageContract.MaximumResponseBytes + 1), Encoding.UTF8, "application/json") };
        Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.TooLarge, "An oversized coverage response was accepted.");
        handler.Response = () => new(HttpStatusCode.NotFound);
        Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.NotFound, "A removed computer did not return NotFound.");

        var held = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Held = held.Task;
        var old = client.GetMonitoringEndpointAsync(First, default);
        client.SignOut();
        await SignInAsync(client);
        handler.Held = null;
        held.SetResult(new(HttpStatusCode.Unauthorized));
        Check((await old.WaitAsync(TimeSpan.FromSeconds(5))).Outcome == DeviceReadOutcome.Unauthenticated, "A result from a signed-out session was accepted.");
        handler.Response = () => Json(detail);
        Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.Success, "An old coverage request ended the new session.");
        trust.Allowed = false;
        var previousCalls = handler.Calls;
        Check((await client.GetMonitoringEndpointAsync(First, default)).Outcome == DeviceReadOutcome.UntrustedConnection && handler.Calls == previousCalls,
            "Coverage sent credentials after failing connection trust.");
    }

    private static async Task PagingAsync()
    {
        var client = new FakeClient();
        using var model = new MonitoringCoverageViewModel(client);
        await model.RefreshAsync();
        Check(model.Rows.Count == 25 && model.CanNextPage && !model.CanPreviousPage && model.PageText.Contains("31 active", StringComparison.Ordinal),
            "The first device page lost its rows, total or navigation state.");
        await model.NextPageAsync();
        Check(client.LastPage == (25, false) && model.Rows.Count == 6 && model.CanPreviousPage && !model.CanNextPage, "The second device page used the wrong offset.");
        await model.SetIssuesOnlyAsync(true);
        Check(client.LastPage == (0, true) && model.Rows.Count == 2 && model.PageText.Contains("2 matching", StringComparison.Ordinal), "The issue filter did not reset paging.");
        var row = model.Rows[0];
        Check(row.Heartbeat.Contains("Future timestamp", StringComparison.Ordinal) && row.Inventory.Contains("Missing", StringComparison.Ordinal) &&
            row.Telemetry.Contains("3 h 1 min ago", StringComparison.Ordinal), "Heartbeat, inventory or telemetry age lost its own state.");
        await model.SelectEndpointAsync(row);
        var detail = model.SourceDetail;
        Check(detail is { Telemetry.Count: 9, EventChannels.Count: 4 } && detail.Telemetry[2].Name == "Microsoft Defender Antivirus status" &&
            detail.EventChannels[3].Name == "Microsoft Defender Operational event log", "Coverage conflated Defender Antivirus with the event log or lost a source.");
        Check(detail!.Telemetry[0].Availability.Contains("Unsupported · freshness · Stale", StringComparison.Ordinal) &&
            detail.EventChannels[0].Availability.Contains("Collecting · freshness · Stale", StringComparison.Ordinal) &&
            detail.EventChannels[1].Availability.Contains("Unknown · freshness · Missing", StringComparison.Ordinal), "Past state and freshness were conflated.");
        Check(model.GapRows[0].Title.Contains("First coverage baseline", StringComparison.Ordinal) && model.GapRows[1].Title.Contains("Coverage restarted", StringComparison.Ordinal),
            "Continuity history conflated baseline and restart.");
        await model.NextGapPageAsync();
        Check(client.LastGapOffset == 15 && model.GapRows.Count == 1 && model.CanPreviousGapPage && !model.CanNextGapPage &&
            ReferenceEquals(detail, model.SourceDetail) && client.LastPage == (0, true), "Continuity paging changed the device list or source detail.");
        await model.PreviousGapPageAsync();
        Check(client.LastGapOffset == 0 && model.GapRows.Count == 15, "Continuity paging could not return to its first page.");
    }

    private static async Task SessionAndSelectionAsync()
    {
        var client = new FakeClient();
        using var model = new MonitoringCoverageViewModel(client);
        var expiry = 0;
        model.SessionExpired += (_, _) => expiry++;
        await model.SetIssuesOnlyAsync(true);
        var detail = new TaskCompletionSource<DeviceReadResult<MonitoringEndpointDetail>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gaps = new TaskCompletionSource<DeviceReadResult<MonitoringGapPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.PendingDetail = detail.Task;
        client.PendingGaps = gaps.Task;
        var selected = model.SelectEndpointAsync(model.Rows[0]);
        var oldToken = client.DetailToken;
        var oldGapToken = client.GapToken;
        client.PendingDetail = null;
        client.PendingGaps = null;
        await model.SelectEndpointAsync(model.Rows[1]);
        detail.SetResult(new(DeviceReadOutcome.Unauthenticated));
        gaps.SetResult(new(DeviceReadOutcome.Success, GapPage(First, 0, 15, 1)));
        await selected.WaitAsync(TimeSpan.FromSeconds(5));
        Check(oldToken.IsCancellationRequested && oldGapToken.IsCancellationRequested && expiry == 0 && model.SourceDetail?.Endpoint.EndpointId == Second &&
            model.GapRows.Count == 15, "A previous selection published rows or expired the current session.");

        var read = new TaskCompletionSource<DeviceReadResult<MonitoringEndpointPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.PendingList = read.Task;
        var refresh = model.RefreshAsync();
        model.Clear();
        client.PendingList = null;
        await model.RefreshAsync();
        read.SetResult(new(DeviceReadOutcome.Success, new(Now, 1, 1, 0, 25, 12, [Summary(Second)])));
        await refresh.WaitAsync(TimeSpan.FromSeconds(5));
        Check(!model.IssuesOnly && model.Rows.Count == 25 && model.SelectedEndpoint is null && model.SourceDetail is null && model.GapRows.Count == 0,
            "A late list response restored data after navigation or a new session.");
        client.PendingDetail = Task.FromResult(new DeviceReadResult<MonitoringEndpointDetail>(DeviceReadOutcome.Unauthenticated));
        await model.SelectEndpointAsync(model.Rows[0]);
        Check(expiry == 1 && model.Rows.Count == 0 && !model.HasSelection && model.SourceDetail is null && model.GapRows.Count == 0,
            "Current authentication failure did not expire and clear monitoring coverage.");
    }

    private static MonitoringEndpointSummary Summary(Guid id) => new(id, "{Binding literal}<synthetic>", "future", Now.AddMinutes(1), "missing", null,
        "stale", Now.AddMinutes(-181), Now.AddHours(-1), 0, 0, true, true);

    private static MonitoringEndpointDetail Detail(Guid id) => new(Now, Summary(id), 12, 30,
        MonitoringCoverageContract.TelemetrySourceIds.Select(name => new MonitoringTelemetrySource(name, "unsupported", "stale")).ToArray(),
        SecurityEventChannels.All.Select((channel, index) => index == 0
            ? new MonitoringEventChannel(channel, "collecting", "stale", Now.AddHours(-3), Now.AddHours(-3), Now.AddDays(-1), 42, Now.AddDays(-1), 7, 8, 9, 10)
            : new MonitoringEventChannel(channel, "unknown", "missing", null, null, null, null, null, null, null, null, null)).ToArray());

    private static MonitoringGapPage GapPage(Guid id, int offset, int limit, int total) => new(Now, id, total, offset, limit, 30,
        Enumerable.Range(offset, Math.Min(limit, Math.Max(0, total - offset))).Select(index => new MonitoringCoverageGap(SecurityEventChannels.Security,
            "coverageStarted", index == 0 ? "noCheckpoint" : "checkpointInvalid", 5, null, Now.AddHours(-5), Now.AddHours(-4), index != 0)).ToArray());

    private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        { Content = new StringContent(body is string text ? text : JsonSerializer.Serialize(body, JsonOptions), Encoding.UTF8, "application/json") };

    private static async Task SignInAsync(HttpAuthenticationClient client) => Check(
        (await client.SignInAsync("admin", "synthetic-coverage-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic coverage login failed.");

    private static void Check(bool condition, string message) { _assertions++; if (!condition) throw new InvalidOperationException(message); }

    private sealed class Trust : ICoreEndpointTrust
    {
        public bool Allowed = true;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) => Task.FromResult(Allowed);
    }

    private sealed class Handler : HttpMessageHandler
    {
        public Func<HttpResponseMessage> Response = () => new(HttpStatusCode.ServiceUnavailable);
        public Task<HttpResponseMessage>? Held;
        public string? LastPath, Bearer;
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}"));
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
            Calls++;
            LastPath = request.RequestUri.PathAndQuery;
            Bearer = request.Headers.Authorization?.ToString();
            return Held ?? Task.FromResult(Response());
        }
    }

    private sealed class FakeClient : IMonitoringCoverageClient
    {
        public (int Offset, bool IssuesOnly) LastPage;
        public int LastGapOffset;
        public CancellationToken DetailToken, GapToken;
        public Task<DeviceReadResult<MonitoringEndpointPage>>? PendingList;
        public Task<DeviceReadResult<MonitoringEndpointDetail>>? PendingDetail;
        public Task<DeviceReadResult<MonitoringGapPage>>? PendingGaps;

        public Task<DeviceReadResult<MonitoringEndpointPage>> GetMonitoringEndpointsAsync(int offset, int limit, bool issuesOnly, CancellationToken token)
        {
            LastPage = (offset, issuesOnly);
            var matching = issuesOnly ? 2 : 31;
            var items = Enumerable.Range(offset, Math.Min(limit, matching - offset))
                .Select(index => Summary(index == 0 ? First : index == 1 ? Second : Guid.NewGuid())).ToArray();
            return PendingList ?? Task.FromResult(new DeviceReadResult<MonitoringEndpointPage>(DeviceReadOutcome.Success, new(Now, 31, matching, offset, limit, 12, items)));
        }

        public Task<DeviceReadResult<MonitoringEndpointDetail>> GetMonitoringEndpointAsync(Guid endpointId, CancellationToken token)
        {
            DetailToken = token;
            return PendingDetail ?? Task.FromResult(new DeviceReadResult<MonitoringEndpointDetail>(DeviceReadOutcome.Success, Detail(endpointId)));
        }

        public Task<DeviceReadResult<MonitoringGapPage>> GetMonitoringGapsAsync(Guid endpointId, int offset, int limit, CancellationToken token)
        {
            LastGapOffset = offset;
            GapToken = token;
            return PendingGaps ?? Task.FromResult(new DeviceReadResult<MonitoringGapPage>(DeviceReadOutcome.Success, GapPage(endpointId, offset, limit, 16)));
        }
    }
}
