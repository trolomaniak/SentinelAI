using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Localization;

internal static class DefenderDetectionTests
{
    private const string Token = "synthetic-defender-bearer";
    private static int _assertions;
    private static readonly Guid Endpoint = Guid.Parse("3e1eb7b6-e350-4418-9d46-790dff2cdd71");
    private static readonly DateTimeOffset Now = new(2099, 1, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await PresentationAsync();
        await CancellationAsync();
        Console.WriteLine($"Desktop Defender history: {_assertions} assertions passed.");
        return _assertions;
    }

    private static DefenderDetection Detection(int eventId = 1116) => new(Now.AddMinutes(-2), Now.AddMinutes(-1), eventId,
        eventId == 1116 ? SecurityEventKinds.MalwareDetected : eventId == 1117 ? SecurityEventKinds.MalwareActionTaken : SecurityEventKinds.MalwareActionFailed,
        Guid.Parse("0da595b8-f02e-43e2-94a6-63bd2a545ce0"), 12345, "Synthetic:<script>&{Binding}", 5, 8, eventId == 1116 ? null : 2, eventId == 1118 ? 5 : null);
    private static DefenderDetectionsView History(Guid? endpoint = null, int offset = 0, int total = 1, string state = "collecting", bool stale = false) =>
        new(endpoint ?? Endpoint, Now, state, state == "notReported" ? null : Now.AddHours(stale ? -3 : -1),
            state == "notReported" ? null : Now.AddHours(-1), 30, offset, 50, total,
            Enumerable.Range(0, Math.Min(50, Math.Max(0, total - offset))).Select(_ => Detection()).ToArray());
    private static JsonObject Body() => JsonSerializer.SerializeToNode(History(), JsonOptions)!.AsObject();
    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static void Ensure(bool value, string message) { _assertions++; if (!value) throw new InvalidOperationException(message); }

    private static async Task TransportAsync()
    {
        using var context = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        Ensure((await context.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default)).Outcome == DeviceReadOutcome.Unauthenticated && context.Handler.LastPath is null,
            "Defender history was requested before sign-in.");
        await context.SignInAsync();
        var result = await context.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default);
        Ensure(result is { Outcome: DeviceReadOutcome.Success, Value.Detections.Count: 1 } && result.Value.Detections[0].ThreatName == Detection().ThreatName,
            "The bounded typed Defender history was not read literally.");
        Ensure(context.Handler.LastPath == $"/api/admin/devices/{Endpoint:D}/defender-detections?offset=0&limit=50" &&
               context.Handler.Bearer == "Bearer " + Token && context.Trust.Calls >= 3,
            "Defender history did not use the authenticated trusted Core endpoint and explicit page.");
        foreach (var change in new Action<JsonObject>[]
                 {
                     body => body["extra"] = "raw data", body => body.Remove("sourceState"),
                     body => body["endpointId"] = Guid.NewGuid().ToString(), body => body["sourceState"] = "healthy",
                     body => body["sourceReportedUtc"] = null, body => body["totalCount"] = 0,
                     body => body["offset"] = 50, body => body["limit"] = 100, body => body["retentionDays"] = 0,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["filePath"] = "private",
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["kind"] = "clean",
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["eventId"] = 1117,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["threatName"] = new string('x',257),
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["threatName"] = "bad\nname",
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["threatName"] = " spaced ",
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["threatName"] = "invisible\u200bname",
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["actionId"] = 2,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["errorCode"] = 5,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["threatId"] = -1,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["severityId"] = 256,
                     body => ((JsonObject)((JsonArray)body["detections"]!)[0]!)["receivedUtc"] = "2099-01-12T12:00:00+01:00"
                 })
        {
            var body = Body(); change(body);
            using var invalid = new Context((_, _) => Task.FromResult(Json(body.ToJsonString())));
            await invalid.SignInAsync();
            Ensure((await invalid.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default)).Outcome == DeviceReadOutcome.InvalidResponse,
                "An inconsistent or non-allowlisted Defender history response was accepted.");
        }
        using var oversized = new Context((_, _) => Task.FromResult(Json(new string(' ', 256 * 1024 + 1))));
        await oversized.SignInAsync();
        Ensure((await oversized.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default)).Outcome == DeviceReadOutcome.TooLarge, "Oversized Defender history was accepted.");
        using var absent = new Context((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
        await absent.SignInAsync();
        Ensure((await absent.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default)).Outcome == DeviceReadOutcome.NotFound, "A removed Defender endpoint was not reported.");
        context.Trust.Allowed = false;
        Ensure((await context.Client.GetDefenderDetectionsAsync(Endpoint, 0, 50, default)).Outcome == DeviceReadOutcome.UntrustedConnection, "Defender history ignored connection trust failure.");
    }

    private static async Task PresentationAsync()
    {
        var client = new FakeClient();
        using var model = new DefenderDetectionsViewModel(client);
        client.Next = (_, offset, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success, History(offset: offset, total: 51)));
        await model.LoadAsync(Endpoint);
        Ensure(model.State == DefenderHistoryState.Ready && model.Detections.Count == 50 && model.Detections[0].ThreatName == Detection().ThreatName &&
               model.Detections[0].EventText == "Threat detected" && !model.CanPreviousPage && model.CanNextPage,
            "Defender detections lost literal names or bounded first-page state.");
        Ensure(!model.SourceText.Contains("stale", StringComparison.Ordinal) && model.RetentionText.Contains("currently active or removed", StringComparison.Ordinal),
            "Normal hourly collection was stale or history implied a current infection verdict.");
        await model.NextPageAsync();
        Ensure(client.LastOffset == 50 && model.Detections.Count == 1 && model.CanPreviousPage && !model.CanNextPage && model.PageText == "Events 51–51 of 51",
            "Defender pagination did not load the next bounded page.");
        await model.PreviousPageAsync();
        Ensure(client.LastOffset == 0 && model.Detections.Count == 50, "Defender previous page did not return to the start.");
        client.Next = (_, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success, History(total: 0, state: "notReported")));
        await model.RefreshAsync();
        Ensure(model.SourceText.Contains("Unknown", StringComparison.Ordinal) && model.StatusText.Contains("does not establish", StringComparison.Ordinal) && model.Detections.Count == 0,
            "Missing Defender source or empty history was presented as safe.");
        client.Next = (_, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success, History(stale: true)));
        await model.RefreshAsync();
        Ensure(model.SourceText.Contains("stale", StringComparison.Ordinal), "Stale Defender collecting status looked current.");
        foreach (var (eventId, expected) in new[] { (1117, "Defender reported an action"), (1118, "Defender action failed") })
        {
            client.Next = (_, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success, History() with { Detections = [Detection(eventId)] }));
            await model.RefreshAsync();
            Ensure(model.Detections[0].EventText == expected && !model.Detections[0].EventText.Contains("removed", StringComparison.Ordinal),
                "A Defender event was relabeled as successful remediation.");
        }
        Localizer.Use(UiLanguage.Polish);
        try
        {
            Ensure(model.Detections[0].EventText == "Działanie Defendera nie powiodło się" && model.RetentionText.Contains("dni", StringComparison.Ordinal),
                "Defender history was not translated into Polish.");
        }
        finally { Localizer.Use(UiLanguage.English); }
        client.Next = (_, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Unavailable));
        await model.RefreshAsync();
        Ensure(model.State == DefenderHistoryState.Unavailable && model.Detections.Count == 0 && model.CanRefresh, "A failed Defender read retained old detections or blocked retry.");
    }

    private static async Task CancellationAsync()
    {
        var client = new FakeClient();
        using var model = new DefenderDetectionsViewModel(client);
        var pending = new TaskCompletionSource<DeviceReadResult<DefenderDetectionsView>>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken firstToken = default;
        client.Next = (_, _, token) => { firstToken = token; return pending.Task; };
        var first = model.LoadAsync(Endpoint);
        var secondId = Guid.NewGuid();
        client.Next = (id, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success, History(endpoint:id, total:0)));
        await model.LoadAsync(secondId);
        pending.SetResult(new(DeviceReadOutcome.Unauthenticated));
        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        await first;
        Ensure(firstToken.IsCancellationRequested && model.EndpointId == secondId && model.State == DefenderHistoryState.Ready && expired == 0,
            "A stale Defender response replaced or expired the newly selected endpoint/session.");
        var held = new TaskCompletionSource<DeviceReadResult<DefenderDetectionsView>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Next = (_, _, _) => held.Task;
        var loading = model.RefreshAsync();
        model.Clear();
        held.SetResult(new(DeviceReadOutcome.Success, History(endpoint:secondId)));
        await loading;
        Ensure(model.State == DefenderHistoryState.None && model.EndpointId is null && model.Detections.Count == 0, "Navigation/sign-out clearing was undone by a late Defender response.");
        client.Next = (_, _, _) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Unauthenticated));
        await model.LoadAsync(Endpoint);
        Ensure(expired == 1 && model.EndpointId is null && model.State == DefenderHistoryState.None, "Current Defender authentication failure did not clear and expire the session.");
    }

    private sealed class FakeClient : IDefenderDetectionsClient
    {
        internal Func<Guid,int,CancellationToken,Task<DeviceReadResult<DefenderDetectionsView>>> Next = (_,_,_) => Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Unavailable));
        internal int LastOffset;
        public Task<DeviceReadResult<DefenderDetectionsView>> GetDefenderDetectionsAsync(Guid endpointId, int offset, int limit, CancellationToken cancellationToken)
        { LastOffset = offset; return Next(endpointId, offset, cancellationToken); }
    }
    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> answer) { Handler = new(answer); Client = new(Trust, Handler); }
        internal Trust Trust { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-defender-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic Defender login failed.");
        public void Dispose() => Client.Dispose();
    }
    private sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> answer) : HttpMessageHandler
    {
        internal string? LastPath;
        internal string? Bearer;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\""+Token+"\",\"expiresIn\":900}"));
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
            LastPath = request.RequestUri.PathAndQuery; Bearer = request.Headers.Authorization?.ToString(); return answer(request,cancellationToken);
        }
    }
    private sealed class Trust : ICoreEndpointTrust
    {
        internal bool Allowed = true;
        internal int Calls;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
}
