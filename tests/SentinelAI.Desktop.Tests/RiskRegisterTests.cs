using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

// TASK-032: the Risk Register page shows Core's records, saves with the version that was read and words Core's field
// errors. Synthetic records, computers and alerts only.
internal static class RiskRegisterTests
{
    private const string Token = "synthetic-risk-register-bearer";
    private static readonly Guid RiskId = Guid.Parse("4b1d3c5e-8f20-4a6b-9c7d-1e2f3a4b5c6d");
    private static readonly Guid EndpointId = Guid.Parse("2a6f3c9e-7d41-4b58-9e0a-5c1d8f2b7e63");
    private static readonly Guid AlertId = Guid.Parse("7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f");
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await ClosedSchemaAsync();
        await ViewModelAsync();
        Console.WriteLine($"Desktop Risk Register: {_assertions} assertions passed.");
        return _assertions;
    }

    private static JsonObject Rating(int likelihood, int impact, string level) =>
        new() { ["likelihood"] = likelihood, ["impact"] = impact, ["score"] = likelihood * impact, ["level"] = level };

    private static JsonObject Flags(bool review = false, bool acceptance = false, bool target = false) => new()
    {
        ["reviewOverdue"] = review, ["acceptanceExpired"] = acceptance, ["targetDatePassed"] = target, ["needsAttention"] = review || acceptance || target
    };

    private static JsonObject Summary() => new()
    {
        ["riskId"] = RiskId.ToString("D"), ["reference"] = "R-0001", ["title"] = "Legacy application", ["status"] = "open", ["treatment"] = "accept",
        ["owner"] = "Finance lead", ["inherent"] = Rating(3, 4, "high"), ["residual"] = Rating(2, 3, "medium"), ["reviewDate"] = "2099-01-01",
        ["targetDate"] = null, ["acceptanceExpiresOn"] = "2099-02-01", ["flags"] = Flags(review: true), ["endpointCount"] = 1, ["alertCount"] = 1,
        ["version"] = 2, ["updatedUtc"] = "2099-01-02T10:00:00+00:00"
    };

    private static JsonObject Page() => new()
    {
        ["records"] = new JsonArray(Summary()), ["total"] = 1, ["offset"] = 0, ["limit"] = 50,
        ["counts"] = new JsonObject { ["open"] = 1, ["monitoring"] = 0, ["closed"] = 0, ["needsAttention"] = 1 }, ["today"] = "2099-01-05"
    };

    private static JsonObject Detail(int version = 2) => new()
    {
        ["riskId"] = RiskId.ToString("D"), ["reference"] = "R-0001", ["title"] = "Legacy application", ["description"] = "Line one.\nLine two.",
        ["owner"] = "Finance lead", ["inherent"] = Rating(3, 4, "high"), ["controls"] = "Isolated network segment.", ["residual"] = Rating(2, 3, "medium"),
        ["treatment"] = "accept", ["acceptanceRationale"] = "Replacement is budgeted.", ["acceptanceExpiresOn"] = "2099-02-01", ["targetDate"] = null,
        ["reviewDate"] = "2099-01-01", ["status"] = "open", ["flags"] = Flags(review: true),
        ["endpoints"] = new JsonArray(new JsonObject { ["endpointId"] = EndpointId.ToString("D"), ["name"] = "FINANCE-PC", ["enrolled"] = true }),
        ["alerts"] = new JsonArray(new JsonObject
        {
            ["alertId"] = AlertId.ToString("D"), ["exists"] = true, ["endpointId"] = EndpointId.ToString("D"), ["endpointName"] = "FINANCE-PC",
            ["ruleId"] = "SA-TEST-001", ["title"] = "Synthetic finding", ["severity"] = "high", ["status"] = "open"
        }),
        ["tickets"] = new JsonArray("INC-1"), ["createdUtc"] = "2099-01-01T09:00:00+00:00", ["createdBy"] = "admin",
        ["updatedUtc"] = "2099-01-02T10:00:00+00:00", ["updatedBy"] = "admin", ["lastReviewedUtc"] = null, ["lastReviewedBy"] = null,
        ["version"] = version,
        ["history"] = new JsonArray(Enumerable.Range(1, version).Reverse().Select(entry => (JsonNode)new JsonObject
        {
            ["version"] = entry, ["changedUtc"] = "2099-01-0" + entry + "T10:00:00+00:00", ["changedBy"] = "admin",
            ["action"] = entry == 1 ? "created" : "updated",
            ["changes"] = new JsonArray(new JsonObject { ["field"] = "title", ["from"] = entry == 1 ? null : "Old title", ["to"] = "Legacy application" }),
            ["note"] = entry == 1 ? "First recorded." : null
        }).ToArray()),
        ["today"] = "2099-01-05"
    };

    private static RiskRegisterDraft Draft() => new("Legacy application", null, "Finance lead", 3, 4, null, 2, 3, "accept", "Replacement is budgeted.",
        "2099-02-01", null, "2099-03-01", "open", [EndpointId], [AlertId], ["INC-1"], "A note.");

    private static async Task TransportAsync()
    {
        using var context = new Context((request, _) => Task.FromResult(request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == "/api/admin/risk-register"
            ? Json(Page().ToJsonString())
            : request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/api/admin/risk-register"
                ? Json(Detail(1).ToJsonString(), HttpStatusCode.Created)
                : Json(Detail().ToJsonString())));
        await context.SignInAsync();
        var page = await context.Client.GetRiskRegisterAsync(new RiskRegisterQuery("active", "accept", "medium", true, EndpointId, Offset: 50, Limit: 50), default);
        Ensure(context.Handler.Requests.Last().RequestUri!.PathAndQuery ==
               $"/api/admin/risk-register?status=active&treatment=accept&level=medium&attention=true&endpointId={EndpointId:D}&offset=50&limit=50" &&
               context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted, "The register query was not sent as filtered, trusted and authenticated.");
        Ensure(page is { Outcome: RiskRegisterOutcome.Success, Value: { Total: 1, Today: "2099-01-05", Counts.NeedsAttention: 1 } value } &&
               value.Records[0] is { Reference: "R-0001", Treatment: "accept", Residual: { Score: 6, Level: "medium" }, Flags: { ReviewOverdue: true, NeedsAttention: true } },
            "Desktop changed Core's register page.");

        var detail = await context.Client.GetRiskRecordAsync(RiskId, default);
        Ensure(detail is { Outcome: RiskRegisterOutcome.Success, Value: { Version: 2, Description: "Line one.\nLine two.", History.Count: 2 } record } &&
               record.Endpoints[0] is { Name: "FINANCE-PC", Enrolled: true } && record.Alerts[0] is { Exists: true, RuleId: "SA-TEST-001" } &&
               record.History[1] is { Action: "created", Note: "First recorded." }, "Desktop changed Core's record.");

        var created = await context.Client.CreateRiskRecordAsync(Draft(), default);
        using (var body = JsonDocument.Parse(context.Handler.LastBody!))
            Ensure(created is { Outcome: RiskRegisterOutcome.Success, Value.Version: 1 } && !body.RootElement.TryGetProperty("expectedVersion", out _) &&
                   body.RootElement.GetProperty("title").GetString() == "Legacy application" && body.RootElement.GetProperty("likelihood").GetInt32() == 3 &&
                   body.RootElement.GetProperty("endpointIds")[0].GetString() == EndpointId.ToString("D") &&
                   body.RootElement.GetProperty("description").ValueKind == JsonValueKind.Null, "A created record was not sent and read as Core expects.");

        await context.Client.UpdateRiskRecordAsync(RiskId, 2, Draft(), default);
        using (var body = JsonDocument.Parse(context.Handler.LastBody!))
            Ensure(context.Handler.Requests.Last().Method == HttpMethod.Put && body.RootElement.GetProperty("expectedVersion").GetInt64() == 2 &&
                   body.RootElement.GetProperty("record").GetProperty("acceptanceExpiresOn").GetString() == "2099-02-01", "An update did not carry the version that was read.");

        await context.Client.ReviewRiskRecordAsync(RiskId, 2, "2099-04-01", null, default);
        using (var body = JsonDocument.Parse(context.Handler.LastBody!))
            Ensure(context.Handler.Requests.Last().RequestUri!.AbsolutePath == $"/api/admin/risk-register/{RiskId:D}/review" &&
                   body.RootElement.GetProperty("nextReviewDate").GetString() == "2099-04-01", "A review was not sent as Core expects.");

        using var refusing = new Context((request, _) => Task.FromResult(request.Method == HttpMethod.Put
            ? new HttpResponseMessage(HttpStatusCode.Conflict)
            : Json("{\"errors\":[{\"field\":\"owner\",\"code\":\"requiredForAcceptance\"},{\"field\":\"residual\",\"code\":\"exceedsInherent\"}]}", HttpStatusCode.UnprocessableEntity)));
        await refusing.SignInAsync();
        var rejected = await refusing.Client.CreateRiskRecordAsync(Draft(), default);
        Ensure(rejected is { Outcome: RiskRegisterOutcome.Rejected, Value: null, Errors.Count: 2 } && rejected.Errors[0] == new RiskRegisterError("owner", "requiredForAcceptance"),
            "Core's field errors were not read.");
        Ensure((await refusing.Client.UpdateRiskRecordAsync(RiskId, 1, Draft(), default)).Outcome == RiskRegisterOutcome.Conflict, "A version conflict was not reported.");
    }

    private static async Task ClosedSchemaAsync()
    {
        async Task Refused(string body, string message)
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            var page = await context.Client.GetRiskRegisterAsync(new RiskRegisterQuery(), default);
            var detail = await context.Client.GetRiskRecordAsync(RiskId, default);
            Ensure(page.Outcome == RiskRegisterOutcome.InvalidResponse && detail.Outcome == RiskRegisterOutcome.InvalidResponse, message);
        }

        JsonObject Changed(Func<JsonObject, JsonObject> change, bool detail) => change(detail ? Detail() : Page());
        foreach (var (body, message) in new (JsonObject, string)[]
                 {
                     (Changed(page => { page["extra"] = 1; return page; }, false), "an unknown page property"),
                     (Changed(page => { ((JsonObject)page["records"]![0]!)["residual"] = Rating(2, 3, "high"); return page; }, false), "a level that does not match its score"),
                     (Changed(page => { ((JsonObject)page["records"]![0]!)["flags"] = new JsonObject { ["reviewOverdue"] = true, ["acceptanceExpired"] = false, ["targetDatePassed"] = false, ["needsAttention"] = false }; return page; }, false), "inconsistent attention flags"),
                     (Changed(detail => { detail["version"] = 3; return detail; }, true), "a history that does not match the version"),
                     (Changed(detail => { detail["treatment"] = "mitigate"; return detail; }, true), "an acceptance date without acceptance"),
                     (Changed(detail => { detail["title"] = "Bell\u0007"; return detail; }, true), "control characters in a title")
                 })
            await Refused(body.ToJsonString(), "Desktop accepted " + message + ".");
    }

    private static async Task ViewModelAsync()
    {
        var client = new FakeClient();
        var devices = new FakeDevices();
        var alerts = new FakeAlerts();
        using var vm = new RiskRegisterViewModel(client, devices, alerts);
        var expired = 0;
        vm.SessionExpired += (_, _) => expired++;
        Ensure(vm.DistinctionText.Contains("never change alerts, detection or the technical risk score", StringComparison.Ordinal),
            "The page did not keep business risk apart from the technical score.");

        await vm.RefreshAsync();
        Ensure(vm.ListState == RiskRegisterListState.Ready && vm.Rows.Single() is { Reference: "R-0001", Residual: "6 · Medium", Attention: "Review overdue", Treatment: "Accept" } &&
               vm.CountsText.Contains("Needing attention: 1", StringComparison.Ordinal) && client.Queries.Last() is { Status: "active", Treatment: null, Offset: 0 },
            "The register page did not show Core's records.");
        vm.StatusFilter = "all";
        vm.TreatmentFilter = "none";
        vm.AttentionOnly = true;
        await vm.ApplyFiltersAsync();
        Ensure(client.Queries.Last() is { Status: null, Treatment: "none", Level: null, AttentionOnly: true }, "Filters were not applied as chosen.");

        // A new risk: computers from Core, accepted with owner and expiry, tickets one per line.
        await vm.NewRiskAsync();
        Ensure(vm.EditorMode == RiskRegisterEditorMode.Create && vm.EndpointChoices.Select(choice => choice.Text).SequenceEqual(["FINANCE-PC", "RECEPTION-PC"]) &&
               vm.ReviewDate == new DateTime(2099, 4, 5),
            "A new risk did not start with Core's computers and a review in three months.");
        vm.Title = "  Legacy application ";
        vm.Treatment = "accept";
        vm.Owner = "Finance lead";
        vm.AcceptanceRationale = "Replacement is budgeted.";
        vm.AcceptanceExpiresOn = new DateTime(2099, 2, 1);
        vm.TicketsText = "INC-1\r\nINC-2, INC-3";
        vm.EndpointChoices[0].IsSelected = true;
        await vm.LoadAlertChoicesAsync();
        Ensure(vm.AlertChoices.Single() is { Id: var alertId } && alertId == AlertId && alerts.Queries.Single().EndpointId == EndpointId,
            "Alerts of the ticked computer were not offered.");
        vm.AlertChoices[0].IsSelected = true;
        client.CreateResult = new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Rejected,
            Errors: [new RiskRegisterError("owner", "requiredForAcceptance"), new RiskRegisterError("acceptanceExpiresOn", "tooFar")]);
        await vm.SaveAsync();
        Ensure(vm.ValidationText.Contains("An accepted risk needs a named owner.", StringComparison.Ordinal) &&
               vm.ValidationText.Contains("Acceptance expires on can be at most one year ahead.", StringComparison.Ordinal) &&
               vm.EditorMode == RiskRegisterEditorMode.Create, "Core's refusal was not worded for the administrator.");
        Ensure(client.Drafts.Last() is { Title: "Legacy application", Treatment: "accept", AcceptanceExpiresOn: "2099-02-01", Tickets.Count: 3 } draft &&
               draft.EndpointIds.Single() == EndpointId && draft.AlertIds.Single() == AlertId, "The draft did not carry the form.");
        vm.Treatment = "mitigate";
        client.CreateResult = new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, DetailRecord(1));
        await vm.SaveAsync();
        Ensure(client.Drafts.Last() is { AcceptanceRationale: null, AcceptanceExpiresOn: null } && vm.EditorMode == RiskRegisterEditorMode.Edit &&
               vm.MessageText == "Risk recorded." && vm.HistoryRows.Count == 1, "Only an accepted risk carries acceptance, and a save shows the record.");

        // Saves name the version that was read; conflicts and lost answers are never retried.
        client.UpdateResult = new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Conflict);
        var writes = client.Updates.Count;
        await vm.SaveAsync();
        Ensure(client.Updates.Count == writes + 1 && client.Updates.Last() == (RiskId, 1L) && vm.MessageText.Contains("Another administrator changed this record", StringComparison.Ordinal),
            "A conflict was not reported.");
        client.UpdateResult = new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Unavailable);
        await vm.SaveAsync();
        Ensure(client.Updates.Count == writes + 2 && vm.MessageText.Contains("did not confirm", StringComparison.Ordinal), "A lost answer was retried or hidden.");

        // Reviews need a date.
        await vm.OpenAsync(RiskId);
        Ensure(vm.EndpointChoices.Count == 2 && vm.EndpointChoices[0] is { Text: "FINANCE-PC", IsSelected: true } && !vm.EndpointChoices[1].IsSelected && devices.Reads >= 2,
            "Opening a record did not offer Core's computers with the linked one ticked.");
        Ensure(vm.FlagsText.Contains("Review overdue", StringComparison.Ordinal) && vm.RecordText.Contains("Not reviewed yet", StringComparison.Ordinal) &&
               vm.HistoryRows.Count == 2 && vm.HistoryRows[1].Contains("Note: First recorded.", StringComparison.Ordinal), "The record did not show its flags and history.");
        await vm.RecordReviewAsync();
        Ensure(vm.ValidationText == "Choose the date of the next review." && client.Reviews.Count == 0, "A review without a date was sent.");
        vm.NextReviewDate = new DateTime(2099, 4, 1);
        vm.ReviewNote = "Controls verified.";
        await vm.RecordReviewAsync();
        Ensure(client.Reviews.Single() == (RiskId, 2L, "2099-04-01", "Controls verified."), "The review was not sent with its date and note.");

        // An expired session clears the page.
        client.PageOutcome = RiskRegisterOutcome.Unauthenticated;
        await vm.RefreshAsync();
        Ensure(expired == 1 && vm.Rows.Count == 0 && vm.EditorMode == RiskRegisterEditorMode.None, "An expired session left register data visible.");
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        Interlocked.Increment(ref _assertions);
    }

    private static RiskRegisterDetail DetailRecord(int version) => new(RiskId, "R-0001", "Legacy application", null, "Finance lead", new(3, 4, 12, "high"), null,
        new(2, 3, 6, "medium"), "mitigate", null, null, null, "2099-03-01", "open", new(false, false, false, false),
        [new RiskRegisterLinkedEndpoint(EndpointId, "FINANCE-PC", true)], [], ["INC-1"], new DateTimeOffset(2099, 1, 1, 9, 0, 0, TimeSpan.Zero), "admin",
        new DateTimeOffset(2099, 1, 1, 9, 0, 0, TimeSpan.Zero), "admin", null, null, version,
        Enumerable.Range(1, version).Reverse().Select(entry => new RiskRegisterHistoryEntry(entry, new DateTimeOffset(2099, 1, entry, 9, 0, 0, TimeSpan.Zero),
            "admin", entry == 1 ? "created" : "updated", [new RiskRegisterFieldChange("title", null, "Legacy application")], entry == 1 ? "First recorded." : null)).ToArray(),
        "2099-01-05");

    private sealed class FakeClient : IRiskRegisterClient
    {
        internal List<RiskRegisterQuery> Queries { get; } = [];
        internal List<RiskRegisterDraft> Drafts { get; } = [];
        internal List<(Guid, long)> Updates { get; } = [];
        internal List<(Guid, long, string, string?)> Reviews { get; } = [];
        internal RiskRegisterOutcome PageOutcome = RiskRegisterOutcome.Success;
        internal RiskRegisterResult<RiskRegisterDetail> CreateResult = new(RiskRegisterOutcome.Unavailable);
        internal RiskRegisterResult<RiskRegisterDetail> UpdateResult = new(RiskRegisterOutcome.Unavailable);

        public Task<RiskRegisterResult<RiskRegisterPage>> GetRiskRegisterAsync(RiskRegisterQuery query, CancellationToken cancellationToken)
        {
            Queries.Add(query);
            var page = new RiskRegisterPage([new RiskRegisterSummary(RiskId, "R-0001", "Legacy application", "open", "accept", "Finance lead",
                new(3, 4, 12, "high"), new(2, 3, 6, "medium"), "2099-01-01", null, "2099-02-01", new(true, false, false, true), 1, 1, 2,
                new DateTimeOffset(2099, 1, 2, 10, 0, 0, TimeSpan.Zero))], 1, 0, 50, new(1, 0, 0, 1), "2099-01-05");
            return Task.FromResult(new RiskRegisterResult<RiskRegisterPage>(PageOutcome, PageOutcome == RiskRegisterOutcome.Success ? page : null));
        }

        public Task<RiskRegisterResult<RiskRegisterDetail>> GetRiskRecordAsync(Guid riskId, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, DetailRecord(2) with
            {
                Flags = new(true, false, false, true), ReviewDate = "2099-01-01"
            }));

        public Task<RiskRegisterResult<RiskRegisterDetail>> CreateRiskRecordAsync(RiskRegisterDraft draft, CancellationToken cancellationToken)
        {
            Drafts.Add(draft);
            return Task.FromResult(CreateResult);
        }

        public Task<RiskRegisterResult<RiskRegisterDetail>> UpdateRiskRecordAsync(Guid riskId, long expectedVersion, RiskRegisterDraft draft, CancellationToken cancellationToken)
        {
            Updates.Add((riskId, expectedVersion));
            Drafts.Add(draft);
            return Task.FromResult(UpdateResult);
        }

        public Task<RiskRegisterResult<RiskRegisterDetail>> ReviewRiskRecordAsync(Guid riskId, long expectedVersion, string nextReviewDate, string? note,
            CancellationToken cancellationToken)
        {
            Reviews.Add((riskId, expectedVersion, nextReviewDate, note));
            return Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, DetailRecord(3)));
        }
    }

    private sealed class FakeDevices : IDevicesClient
    {
        internal int Reads;

        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken)
        {
            Reads++;
            return Task.FromResult(new DeviceReadResult<IReadOnlyList<DeviceSummary>>(DeviceReadOutcome.Success,
                [new DeviceSummary(EndpointId, "FINANCE-PC", "Windows 11", "healthy", null, "1.0.0", "No findings"),
                 new DeviceSummary(Guid.Parse("3b7f4d0a-8e52-4c69-a01b-6d2e9f3c8a74"), "RECEPTION-PC", "Windows 10", "healthy", null, "1.0.0", "No findings")]));
        }

        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken) =>
            Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.NotFound));
    }

    private sealed class FakeAlerts : IAlertsClient
    {
        internal List<AlertQuery> Queries { get; } = [];

        public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken cancellationToken)
        {
            Queries.Add(query);
            var now = new DateTimeOffset(2099, 1, 2, 10, 0, 0, TimeSpan.Zero);
            return Task.FromResult(new AlertResult<AlertPage>(AlertOutcome.Success, new AlertPage(
                [new AlertSummary(AlertId, EndpointId, "FINANCE-PC", "SA-TEST-001", "Synthetic finding", "high", "open", now, now, now, 1)], 1, 0, 50)));
        }

        public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken cancellationToken) =>
            Task.FromResult(new AlertResult<AlertDetail>(AlertOutcome.NotFound));

        public Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status, long expectedVersion, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The Risk Register never changes an alert.");
    }

    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler); }
        internal Trust Trust { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-risk-register-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login failed.");
        public void Dispose() => Client.Dispose();
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer, Trust trust) : HttpMessageHandler
    {
        internal List<HttpRequestMessage> Requests { get; } = [];
        internal string? Bearer;
        internal string? LastBody;
        internal bool WasTrusted;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}");
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Json("{\"username\":\"admin\",\"role\":\"administrator\"}");
            Bearer = request.Headers.Authorization?.ToString();
            WasTrusted = trust.Allowed && trust.Calls >= 3;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return await answer(request, cancellationToken);
        }
    }

    private sealed class Trust : ICoreEndpointTrust
    {
        internal bool Allowed = true;
        internal int Calls;

        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(Allowed);
        }
    }
}
