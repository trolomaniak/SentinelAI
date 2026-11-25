using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Contracts.RiskHistory;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Scoring;

internal static class RiskHistoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 16, 30, 0, TimeSpan.Zero);
    private static readonly Guid Endpoint = Guid.Parse("dd333944-a067-4b70-b487-e7103784d7ae");
    private static readonly string Fingerprint = new('a', 64);
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await HttpAsync();
        await WorkspaceAsync();
        return _assertions;
    }

    private static async Task HttpAsync()
    {
        using var handler = new HistoryHandler();
        using var client = new HttpAuthenticationClient(new Trusted(), handler);
        Check((await client.GetRiskHistoryAsync(null, 168, default)).Outcome == RiskReadOutcome.Unauthenticated && handler.Reads.Count == 0,
            "Unauthenticated history reached HTTP.");
        await SignInAsync(client);
        var organization = View(null, 168);
        var json = JsonSerializer.Serialize(organization, Web);
        handler.Answer = () => Task.FromResult(Json(json));
        var result = await client.GetRiskHistoryAsync(null, 168, default);
        Check(result.Outcome == RiskReadOutcome.Success && JsonSerializer.Serialize(result.Value, Web) == json &&
            result.Value!.Points[1].RawScore == decimal.MaxValue && result.Value.Points[1].ComparedWithUtc == result.Value.Points[0].CapturedUtc,
            "Desktop changed captured values, retained comparisons, or decimal precision.");
        Check(handler.Reads is [{ Path: "/api/admin/risk-history", Query: "?hours=168", Authorization: "Bearer synthetic-history-token" }] &&
            handler.Reads[0].Request.Method == HttpMethod.Get && handler.Reads[0].Request.Content is null &&
            handler.Reads[0].Request.Headers.Authorization is null, "Organization history used the wrong route, method, or session.");

        var earliest = organization.Points[0];
        var prunedAt = earliest.CapturedUtc.AddHours(-6);
        var pruned = organization with { Points = [earliest with { ComparedWithUtc = prunedAt, Causes = ["statusChanged"] }, organization.Points[1]] };
        handler.Answer = () => Task.FromResult(Json(JsonSerializer.Serialize(pruned, Web)));
        result = await client.GetRiskHistoryAsync(null, 168, default);
        Check(result is { Outcome: RiskReadOutcome.Success } && result.Value!.Points[0].ComparedWithUtc == prunedAt && prunedAt >= organization.StartUtc,
            "A comparison timestamp within the period was lost after its whole capture was pruned.");

        foreach (var hours in RiskHistoryContract.PeriodHours)
        {
            handler.Answer = () => Task.FromResult(Json(JsonSerializer.Serialize(View(Endpoint, hours) with { Points = [] }, Web)));
            var endpoint = await client.GetRiskHistoryAsync(Endpoint, hours, default);
            Check(endpoint is { Outcome: RiskReadOutcome.Success, Value.Points.Count: 0 } && endpoint.Value.EndpointId == Endpoint &&
                handler.Reads[^1].Path == "/api/admin/risk-history/" + Endpoint && handler.Reads[^1].Query == $"?hours={hours}",
                "Empty endpoint history lost its scope or requested period.");
        }
        var readCount = handler.Reads.Count;
        Check((await client.GetRiskHistoryAsync(Guid.Empty, 24, default)).Outcome == RiskReadOutcome.InvalidResponse &&
            (await client.GetRiskHistoryAsync(null, 48, default)).Outcome == RiskReadOutcome.InvalidResponse && handler.Reads.Count == readCount,
            "An invalid history period or endpoint reached Core.");

        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[]
        {
            root => root["endpointId"] = Endpoint.ToString("D"),
            root => root["periodHours"] = 24,
            root => root["startUtc"] = Now.AddHours(-169).ToString("O"),
            root => root["generatedUtc"] = "2026-11-25T17:30:00+01:00",
            root => root["unexpected"] = true,
            root => Point(root, 0)["capturedUtc"] = Now.AddDays(-8).ToString("O"),
            root => Point(root, 1)["capturedUtc"] = Now.AddSeconds(1).ToString("O"),
            root => Point(root, 1)["capturedUtc"] = organization.Points[0].CapturedUtc.AddMinutes(1).ToString("O"),
            root => Point(root, 1)["comparedWithUtc"] = organization.Points[0].CapturedUtc.AddDays(-1).ToString("O"),
            root => Point(root, 1)["score"] = 101,
            root => Point(root, 1)["score"] = 99,
            root => Point(root, 0)["rawScore"] = -1,
            root => Point(root, 0)["policyFingerprint"] = Fingerprint.ToUpperInvariant(),
            root => Point(root, 1)["causes"] = new JsonArray("policyChanged", "policyChanged"),
            root => Point(root, 1)["causes"] = new JsonArray("provedRemediation"),
            root => Point(root, 1)["principalRuleIds"] = new JsonArray("<rule>"),
            root => Point(root, 0)["governingEndpointId"] = null,
            root => Point(root, 0)["endpointCount"] = RiskHistoryContract.MaximumEndpointPoints + 1
        })
        {
            var root = JsonNode.Parse(json)!.AsObject();
            corrupt(root);
            handler.Answer = () => Task.FromResult(Json(root.ToJsonString()));
            Check((await client.GetRiskHistoryAsync(null, 168, default)).Outcome == RiskReadOutcome.InvalidResponse,
                "Desktop accepted malformed risk history.");
        }
        var tooMany = View(null, 2160) with { Points = Enumerable.Repeat(organization.Points[0], RiskHistoryContract.MaximumPoints + 1).ToArray() };
        handler.Answer = () => Task.FromResult(Json(JsonSerializer.Serialize(tooMany, Web)));
        Check((await client.GetRiskHistoryAsync(null, 2160, default)).Outcome == RiskReadOutcome.TooLarge,
            "Desktop accepted more than the bounded number of measurements.");
        handler.Answer = () => Task.FromResult(Json(new string('x', RiskHistoryContract.MaximumResponseBytes + 1)));
        Check((await client.GetRiskHistoryAsync(null, 168, default)).Outcome == RiskReadOutcome.TooLarge,
            "Desktop accepted a history body exceeding its byte limit.");

        var delayed = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Answer = () => { started.SetResult(); return delayed.Task; };
        var old = client.GetRiskHistoryAsync(null, 168, default);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        client.SignOut();
        await SignInAsync(client);
        handler.Answer = () => Task.FromResult(Json(json));
        delayed.SetResult(Json("{}", HttpStatusCode.Unauthorized));
        Check((await old).Outcome == RiskReadOutcome.Unauthenticated &&
            (await client.GetRiskHistoryAsync(null, 168, default)).Outcome == RiskReadOutcome.Success,
            "A previous session's history response was published or invalidated the replacement session.");
    }

    private static async Task WorkspaceAsync()
    {
        var client = new WorkspaceClient();
        using var model = new RiskViewModel(client, client);
        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        Check(!model.CanShowHistory && model.HistoryPeriodHours == 168 && model.HistoryPeriods.Select(period => period.Hours).SequenceEqual(RiskHistoryContract.PeriodHours),
            "History loaded before entering Risk or omitted supported periods.");

        await model.RefreshAsync();
        var original = client.Requests.Single();
        Check(original.Endpoint is null && original.Hours == 168 && model.ListState == RiskListState.Ready && model.History is null,
            "Loading history blocked or changed the current Risk list.");
        model.HistoryPeriodHours = 24;
        var changedPeriod = client.Requests[^1];
        Check(original.Token.IsCancellationRequested && changedPeriod.Hours == 24 && changedPeriod.Endpoint is null,
            "A new period did not replace the previous history request.");
        changedPeriod.Complete();
        original.Complete(RiskReadOutcome.Unauthenticated);
        var recent = model.SelectedHistoryPoint;
        Check(expired == 0 && recent is { Score: 100 } && recent.RawScoreText == decimal.MaxValue.ToString() &&
            recent.Details.Any(fact => fact.Value == Fingerprint) && recent.Details.Any(fact => fact.Value == "Scoring policy changed") &&
            recent.Details.Any(fact => fact.Value == "SA-FW-001") && model.History!.Points.Count == 2,
            "The selected measurement omitted recorded evidence or a stale error expired the session.");

        await model.OpenEndpointAsync(Endpoint);
        var endpoint = client.Requests[^1];
        Check(endpoint.Endpoint == Endpoint && endpoint.Hours == 24 && model.DetailState == RiskDetailState.NotFound && model.History is null,
            "Opening an endpoint did not clear organization history and request the endpoint's retained points.");
        model.SelectedHistoryPoint = recent;
        Check(model.SelectedHistoryPoint is null, "A selection from the previous scope was retained.");
        endpoint.Complete();
        Check(model.History?.Points.Count == 2 && model.SelectedHistoryPoint!.Details.All(fact => fact.Label != "Endpoints at capture"),
            "A missing endpoint's measurements did not appear or were mischaracterized as organization measurements.");

        model.CloseDetail();
        var returning = client.Requests[^1];
        Check(returning.Endpoint is null, "Returning to Risk did not restore organization scope.");
        model.LeaveHistory();
        returning.Complete();
        Check(returning.Token.IsCancellationRequested && !model.CanShowHistory && model.History is null,
            "Navigating away did not cancel and clear risk history.");

        await model.RefreshAsync();
        var signingOut = client.Requests[^1];
        model.Clear();
        signingOut.Complete();
        Check(signingOut.Token.IsCancellationRequested && !model.CanShowHistory && model.History is null && model.HistoryPeriodHours == 168,
            "Signing out leaked history, selection, or its period into the next session.");
        await model.RefreshAsync();
        client.Requests[^1].Complete(RiskReadOutcome.Unauthenticated);
        Check(expired == 1 && !model.CanShowHistory && model.ListState == RiskListState.NotLoaded,
            "A current history authorization failure did not clear the Risk workspace.");
    }

    private static JsonObject Point(JsonObject view, int index) => view["points"]!.AsArray()[index]!.AsObject();

    private static RiskHistoryView View(Guid? endpoint, int hours)
    {
        int? count = endpoint is null ? 1 : null;
        Guid? governing = endpoint is null ? Endpoint : null;
        var earlier = Now.AddHours(-20).AddTicks(123);
        return new(endpoint, hours, Now, Now.AddHours(-hours),
        [
            new(earlier, 49, 48.5m, "policy-a", Fingerprint, null, ["firstCapture"], [], count, governing),
            new(Now.AddHours(-1), 100, decimal.MaxValue, "policy-b", Fingerprint, earlier, ["policyChanged"], ["SA-FW-001"], count, governing)
        ]);
    }

    private static HttpResponseMessage Json(string json, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static async Task SignInAsync(HttpAuthenticationClient client) =>
        Check((await client.SignInAsync("admin", "synthetic-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated,
            "Synthetic sign-in failed.");

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        _assertions++;
    }

    private sealed class Trusted : ICoreEndpointTrust
    {
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed record Read(HttpRequestMessage Request, string Path, string Query, string? Authorization);

    private sealed class HistoryHandler : HttpMessageHandler
    {
        public List<Read> Reads { get; } = [];
        public Func<Task<HttpResponseMessage>> Answer { get; set; } = () => throw new InvalidOperationException("Unexpected history request.");

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            switch (uri.AbsolutePath)
            {
                case "/api/auth/login": return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"synthetic-history-token\",\"expiresIn\":900}"));
                case "/api/admin/me": return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
                default:
                    Reads.Add(new(request, uri.AbsolutePath, uri.Query, request.Headers.Authorization?.ToString()));
                    return Answer();
            }
        }
    }

    private sealed class PendingRead(Guid? endpoint, int hours, CancellationToken token)
    {
        private readonly TaskCompletionSource<RiskReadResult<RiskHistoryView>> _result = new();
        public Guid? Endpoint { get; } = endpoint;
        public int Hours { get; } = hours;
        public CancellationToken Token { get; } = token;
        public Task<RiskReadResult<RiskHistoryView>> Task => _result.Task;
        public void Complete(RiskReadOutcome outcome = RiskReadOutcome.Success) =>
            _result.SetResult(new(outcome, outcome == RiskReadOutcome.Success ? View(Endpoint, Hours) : null));
    }

    private sealed class WorkspaceClient : IRiskClient, IRiskHistoryClient
    {
        public List<PendingRead> Requests { get; } = [];

        public Task<RiskReadResult<RiskHistoryView>> GetRiskHistoryAsync(Guid? endpointId, int periodHours, CancellationToken cancellationToken)
        {
            var read = new PendingRead(endpointId, periodHours, cancellationToken);
            Requests.Add(read);
            return read.Task;
        }

        public Task<RiskReadResult<RiskPage>> GetRiskPageAsync(int offset, int limit, CancellationToken cancellationToken)
        {
            var organization = new OrganizationRiskView(50, 1, [Endpoint], 1, false, "maximumEndpointScore", "Synthetic", Now, 1, 0, 0, 0, 0, new(1, 0, 0, 0));
            var endpoint = new EndpointRiskSummary(Endpoint, "Synthetic endpoint", Now, 50, 50m, new("fresh", "known", 13, 13, "Synthetic"), 1, "Synthetic", Now);
            return Task.FromResult(new RiskReadResult<RiskPage>(RiskReadOutcome.Success, new(organization, [endpoint], 1, offset, limit, new RiskScorer().Policy, 12)));
        }

        public Task<RiskReadResult<EndpointRiskDetail>> GetEndpointRiskDetailAsync(Guid endpointId, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskReadResult<EndpointRiskDetail>(RiskReadOutcome.NotFound));
    }
}
