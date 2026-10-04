using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

internal static class HttpAlertRequestsTests
{
    private static readonly Guid AlertId = Guid.Parse("6091a546-a074-4d53-a725-a0c380c0b9b3");
    private static readonly Guid EndpointId = Guid.Parse("40bf828f-e868-40d7-a925-fc82d441e504");
    private const string Token = "synthetic-alert-bearer-for-tests";
    private const string When = "2026-10-04T12:00:00+00:00";
    private const string Literal = "<script>alert('literal')</script> ${operator} & <b>text</b>";
    private const string PrivateError = "synthetic-private-error-must-not-be-disclosed";
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await ListsAndDetailsAsync();
        await InvalidInputsAsync();
        await ClosedSchemasAsync();
        await VersionedWritesAsync();
        await HttpFailuresAndTrustAsync();
        await BoundsAndErasureAsync();
        await SessionIsolationAsync();
        await CancellationAndDeadlineAsync();
        return _assertions;
    }

    private static async Task ListsAndDetailsAsync()
    {
        using var context = new TestContext((request, _) => Task.FromResult(Json(request.RequestUri!.AbsolutePath == "/api/admin/alerts"
            ? Page([Summary(status: "investigating")], total: 21, offset: 20, limit: 2) : Detail(evidence: Evidence()))));
        Ensure((await context.Client.GetAlertsAsync(new(), default)).Outcome == AlertOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
            "An unauthenticated alert request reached Core.");
        await context.SignInAsync();
        var page = await context.Client.GetAlertsAsync(new(EndpointId, "high", "investigating", 20, 2), default);
        Ensure(page is { Outcome: AlertOutcome.Success, Value.Alerts.Count: 1, Value.Total: 21, Value.Offset: 20, Value.Limit: 2 }, "A filtered page lost count or paging metadata.");
        var summary = page.Value!.Alerts[0];
        Ensure(summary.AlertId == AlertId && summary.EndpointId == EndpointId && summary.EndpointName == Literal && summary.Title == Literal && summary.Version == 1,
            "Public alert summary fields or literal text changed.");
        var detail = (await context.Client.GetAlertDetailAsync(AlertId, default)).Value!;
        Ensure(detail.Alert.RuleId == "windows.test-rule" && detail.Reason == Literal && detail.RecommendedAction == Literal &&
            detail.CreatedUtc.Offset == TimeSpan.Zero && detail.StatusHistoryCount == 1 && detail.StatusHistory[0].PreviousStatus is null && detail.StatusHistory[0].ChangedBy == "system",
            "Alert detail, observation/history or literal reason/action was lost.");
        Ensure(detail.Evidence.Count == 5 && detail.Evidence[0] is { Kind: AlertEvidenceKind.Boolean, BooleanValue: false, IntegerValue: null, StringValue: null } &&
            detail.Evidence[1] is { Kind: AlertEvidenceKind.Integer, IntegerValue: long.MinValue, BooleanValue: null } &&
            detail.Evidence[2] is { Kind: AlertEvidenceKind.Unknown, BooleanValue: null, IntegerValue: null, StringValue: null } &&
            detail.Evidence[3] is { Kind: AlertEvidenceKind.String, StringValue: Literal } && detail.Evidence[4].StringValue == string.Empty,
            "Typed evidence was coerced, inferred or rendered as content.");
        var reads = context.Handler.Requests.Where(request => request.Path.StartsWith("/api/admin/alerts", StringComparison.Ordinal)).ToArray();
        Ensure(reads.Length == 2 && reads.All(request => request.Method == HttpMethod.Get && request.Body is null && request.Authorization == "Bearer " + Token && request.Origin == "http://127.0.0.1:5000"),
            "Alert reads changed authentication, used bodies or reached another destination.");
        Ensure(reads.All(request => request.Request.Headers.Authorization is null), "Completed read headers retained bearer material.");
        Ensure(reads[0].Query == "?offset=20&limit=2&endpointId=" + EndpointId + "&severity=high&status=investigating" && reads[1].Path == "/api/admin/alerts/" + AlertId,
            "Filters or fixed alert routes were not encoded canonically.");
        Ensure(context.Trust.Calls >= context.Handler.Requests.Count, "An alert request skipped the trusted Core adapter.");
        using var empty = new TestContext((_, _) => Task.FromResult(Json(Page([], total: 0, offset: 100))));
        await empty.SignInAsync();
        Ensure((await empty.Client.GetAlertsAsync(new(Offset: 100), default)) is { Outcome: AlertOutcome.Success, Value.Alerts.Count: 0, Value.Total: 0 },
            "An empty page beyond the final offset became unavailable.");
        var history = Enumerable.Range(0, 100).Select(_ => History("open", "open")).ToArray();
        using var retained = new TestContext((_, _) => Task.FromResult(Json(Detail(history: history, historyCount: 150))));
        await retained.SignInAsync();
        Ensure((await retained.Client.GetAlertDetailAsync(AlertId, default)) is { Outcome: AlertOutcome.Success, Value.StatusHistory.Count: 100, Value.StatusHistoryCount: 150 },
            "Retained history lost the disclosed full history count.");
    }

    private static async Task InvalidInputsAsync()
    {
        using var context = new TestContext((_, _) => throw new InvalidOperationException("Invalid input must not reach HTTP."));
        await context.SignInAsync();
        var initial = context.Handler.Requests.Count;
        foreach (var query in new[] { new AlertQuery(EndpointId: Guid.Empty), new AlertQuery(Severity: "HIGH"), new AlertQuery(Severity: "high&external=secret"),
                     new AlertQuery(Status: "closed"), new AlertQuery(Offset: -1), new AlertQuery(Limit: 0), new AlertQuery(Limit: 201) })
            Ensure((await context.Client.GetAlertsAsync(query, default)).Outcome == AlertOutcome.InvalidResponse, "An invalid alert filter/page was accepted.");
        Ensure((await context.Client.GetAlertsAsync(null!, default)).Outcome == AlertOutcome.InvalidResponse &&
            (await context.Client.GetAlertDetailAsync(Guid.Empty, default)).Outcome == AlertOutcome.InvalidResponse, "An invalid query or alert ID was accepted.");
        foreach (var (id, status, version) in new[] { (Guid.Empty, "open", 1L), (AlertId, "Open", 1L), (AlertId, "open", 0L), (AlertId, "resolved", -1L), (AlertId, "resolved\"}", 1L) })
            Ensure((await context.Client.UpdateAlertStatusAsync(id, status, version, default)).Outcome == AlertOutcome.InvalidResponse, "An invalid status write was transmitted.");
        Ensure(context.Handler.Requests.Count == initial, "Invalid local inputs reached Core.");
    }

    private static async Task ClosedSchemasAsync()
    {
        var page = Page([Summary()]);
        foreach (var body in new[]
                 {
                     "[]", "null", "{}", Mutate(page, node => node["privateKey"] = PrivateError), page.Replace("\"total\":1", "\"total\":1,\"total\":1", StringComparison.Ordinal),
                     Mutate(page, node => node["offset"] = 1), Mutate(page, node => node["limit"] = 2), Mutate(page, node => node["total"] = -1),
                     Mutate(page, node => node["total"] = 0), Mutate(page, node => node["alerts"] = new JsonArray(JsonNode.Parse(Summary()), JsonNode.Parse(Summary()))),
                     Page([Summary().Replace("\"version\":1", "\"version\":0", StringComparison.Ordinal)]),
                     Page([Summary().Replace("\"high\"", "\"urgent\"", StringComparison.Ordinal)]),
                     Page([Summary().Replace("\"open\"", "\"closed\"", StringComparison.Ordinal)]),
                     Page([Mutate(Summary(), node => node["endpointId"] = Guid.Empty.ToString())]),
                     Page([Mutate(Summary(), node => node["alertId"] = "not-an-id")]),
                     Page([Mutate(Summary(), node => node.Remove("title"))]),
                     Page([Mutate(Summary(), node => node["title"] = false)]),
                     Page([Mutate(Summary(), node => node["updatedUtc"] = "2026-10-04T12:00:00+01:00")]),
                     Page([Mutate(Summary(), node => node["updatedUtc"] = "2026-10-04T12:00:00")]),
                     Page([Mutate(Summary(), node => node["endpointName"] = "unsafe\0name")]),
                     Page([Mutate(Summary(), node => node["passwordHash"] = PrivateError)]),
                     page.Replace("\"alerts\":[", "\"alerts\":[/*comment*/", StringComparison.Ordinal), page.Replace("}],", "},],", StringComparison.Ordinal)
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            var result = await context.Client.GetAlertsAsync(new(), default);
            Ensure(result.Outcome == AlertOutcome.InvalidResponse && result.Value is null && !result.ToString().Contains(PrivateError, StringComparison.Ordinal),
                "Malformed, duplicate, unknown/private list fields were admitted.");
        }
        foreach (var body in new[]
                 {
                     "{}", "[]", Mutate(Detail(), node => node["alertId"] = Guid.NewGuid().ToString()), Mutate(Detail(), node => node.Remove("reason")),
                     Mutate(Detail(), node => node["config"] = PrivateError), Mutate(Detail(), node => node["evidence"] = new JsonArray(new JsonObject { ["field"] = "x", ["value"] = new JsonObject { ["secret"] = PrivateError } })),
                     Mutate(Detail(), node => node["evidence"] = new JsonArray(new JsonObject { ["field"] = "x", ["value"] = new JsonArray(1) })),
                     Mutate(Detail(), node => node["evidence"] = new JsonArray(new JsonObject { ["field"] = "x", ["value"] = 1.5 })),
                     Detail(evidence: "[{\"field\":\"x\",\"value\":9223372036854775808}]"), Detail(evidence: "[{\"field\":\"x\",\"value\":true,\"value\":false}]"),
                     Detail(evidence: "[{\"field\":\"x\",\"value\":true,\"rawSqlite\":\"secret\"}]"), Detail(evidence: "[{\"field\":\"x\"}]"),
                     Mutate(Detail(), node => node["statusHistoryCount"] = 0), Detail(historyCount: 2),
                     Detail(history: [History("resolved", "open")]),
                     Detail(history: [History("open", "invalid")]),
                     Mutate(Detail(), node => node["statusHistory"]![0]!.AsObject().Remove("previousStatus")),
                     Mutate(Detail(), node => node["statusHistory"]![0]!["changedUtc"] = "2026-10-04T11:00:00+00:00"),
                     Mutate(Detail(), node => node["statusHistory"]![0]!["token"] = PrivateError),
                     Mutate(Detail(), node => node["statusHistory"]![0]!["changedBy"] = false)
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetAlertDetailAsync(AlertId, default)) is { Outcome: AlertOutcome.InvalidResponse, Value: null }, "An unsafe/mismatched detail or untyped evidence was admitted.");
        }
        using var filtered = new TestContext((_, _) => Task.FromResult(Json(page)));
        await filtered.SignInAsync();
        Ensure((await filtered.Client.GetAlertsAsync(new(Status: "resolved"), default)).Outcome == AlertOutcome.InvalidResponse &&
            (await filtered.Client.GetAlertsAsync(new(Severity: "info"), default)).Outcome == AlertOutcome.InvalidResponse &&
            (await filtered.Client.GetAlertsAsync(new(EndpointId: Guid.NewGuid()), default)).Outcome == AlertOutcome.InvalidResponse, "A response silently ignored a requested filter.");
    }

    private static async Task VersionedWritesAsync()
    {
        foreach (var status in new[] { "open", "investigating", "accepted", "resolved" })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(Detail(status: status, version: 8))));
            await context.SignInAsync();
            Ensure((await context.Client.UpdateAlertStatusAsync(AlertId, status, 7, default)) is { Outcome: AlertOutcome.Success, Value.Alert.Version: 8 }, "An allowed versioned transition failed.");
            var write = context.Handler.Requests.Single(request => request.Method == HttpMethod.Put);
            Ensure(write.Path == "/api/admin/alerts/" + AlertId + "/status" && write.Query == "" && write.Authorization == "Bearer " + Token,
                "A status write used another destination/route or omitted authentication.");
            using var body = JsonDocument.Parse(write.Body!);
            Ensure(body.RootElement.EnumerateObject().Count() == 2 && body.RootElement.GetProperty("status").GetString() == status && body.RootElement.GetProperty("expectedVersion").GetInt64() == 7,
                "Status writes included extra data or discarded the expected version.");
            Ensure(write.Request.Headers.Authorization is null, "Write bearer header was retained.");
            Ensure(write.BodyBuffer is not null && write.BodyBuffer.All(value => value == 0), "Owned write payload buffer was retained (observed buffer length: " + write.BodyBuffer?.Length + ").");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json(Detail(status: "resolved", version: 7)))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 7, default)).Outcome == AlertOutcome.Success, "A same-status idempotent decision required another version increment.");
        }
        foreach (var body in new[] { "{}", Detail(version: 7), Detail(status: "resolved", version: 9), Detail(status: "resolved", version: 6),
                     Mutate(Detail(status: "resolved", version: 8), node => node["alertId"] = Guid.NewGuid().ToString()) })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 7, default)) is { Outcome: AlertOutcome.Indeterminate, Value: null },
                "A malformed or mismatched write success was treated as a definite outcome.");
            Ensure(context.Handler.Requests.Count(request => request.Method == HttpMethod.Put) == 1, "An uncertain write was automatically retried.");
            Ensure(context.Handler.Requests.Last().BodyBuffer!.All(value => value == 0), "An uncertain success retained write payload bytes.");
        }
        using var failure = new TestContext((_, _) => throw new HttpRequestException(PrivateError));
        await failure.SignInAsync();
        var uncertain = await failure.Client.UpdateAlertStatusAsync(AlertId, "resolved", 7, default);
        Ensure(uncertain is { Outcome: AlertOutcome.Indeterminate, Value: null } && !uncertain.ToString().Contains(PrivateError, StringComparison.Ordinal) &&
            failure.Handler.Requests.Count(request => request.Method == HttpMethod.Put) == 1, "A failed write leaked errors or retried a possible persisted change.");
        Ensure(failure.Handler.Requests.Last().BodyBuffer!.All(value => value == 0), "A network failure retained write payload bytes.");
    }

    private static async Task HttpFailuresAndTrustAsync()
    {
        foreach (var (status, read, write) in new[]
                 {
                     (HttpStatusCode.Unauthorized, AlertOutcome.Unauthenticated, AlertOutcome.Unauthenticated),
                     (HttpStatusCode.NotFound, AlertOutcome.NotFound, AlertOutcome.NotFound),
                     (HttpStatusCode.Conflict, AlertOutcome.Unavailable, AlertOutcome.Conflict),
                     (HttpStatusCode.Forbidden, AlertOutcome.Unavailable, AlertOutcome.Unavailable),
                     (HttpStatusCode.BadRequest, AlertOutcome.Unavailable, AlertOutcome.Unavailable),
                     (HttpStatusCode.TooManyRequests, AlertOutcome.Unavailable, AlertOutcome.Unavailable),
                     (HttpStatusCode.ServiceUnavailable, AlertOutcome.Unavailable, AlertOutcome.Indeterminate),
                     (HttpStatusCode.Redirect, AlertOutcome.Unavailable, AlertOutcome.Indeterminate),
                     (HttpStatusCode.RequestTimeout, AlertOutcome.Unavailable, AlertOutcome.Indeterminate),
                     (HttpStatusCode.RequestEntityTooLarge, AlertOutcome.TooLarge, AlertOutcome.Unavailable),
                     (HttpStatusCode.UnprocessableEntity, AlertOutcome.TooLarge, AlertOutcome.Unavailable)
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json("{\"private\":\"" + PrivateError + "\"}", status)));
            await context.SignInAsync();
            var result = await context.Client.GetAlertDetailAsync(AlertId, default);
            Ensure(result.Outcome == read && result.Value is null && !result.ToString().Contains(PrivateError, StringComparison.Ordinal), "Read error mapping leaked private data.");
            await context.SignInAsync();
            var mutation = await context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 7, default);
            Ensure(mutation.Outcome == write && mutation.Value is null && !mutation.ToString().Contains(PrivateError, StringComparison.Ordinal), "Write error mapping falsely confirmed a persisted state or disclosed errors.");
            if (status == HttpStatusCode.Unauthorized) Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "A matching 401 retained session credentials.");
        }
        using var untrusted = new TestContext((_, _) => Task.FromResult(Json(Detail())));
        await untrusted.SignInAsync();
        var requests = untrusted.Handler.Requests.Count;
        untrusted.Trust.Allowed = false;
        Ensure((await untrusted.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default)).Outcome == AlertOutcome.UntrustedConnection && untrusted.Handler.Requests.Count == requests,
            "An untrusted endpoint received a bearer or mutation.");
        Ensure((await untrusted.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "Trust failure retained a session.");
        using var nonJson = new TestContext((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Detail(), Encoding.UTF8, "text/html") }));
        await nonJson.SignInAsync();
        Ensure((await nonJson.Client.GetAlertDetailAsync(AlertId, default)).Outcome == AlertOutcome.InvalidResponse &&
            (await nonJson.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default)).Outcome == AlertOutcome.Indeterminate, "Non-JSON success bodies were accepted.");
        using var errorBody = new CapturedStream(Encoding.UTF8.GetBytes(PrivateError));
        using var unread = new TestContext((_, _) => { var error = StreamResponse(errorBody); error.StatusCode = HttpStatusCode.Conflict; return Task.FromResult(error); });
        await unread.SignInAsync();
        Ensure((await unread.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default)).Outcome == AlertOutcome.Conflict && errorBody.BytesRead == 0 &&
            unread.Handler.Requests.Count(request => request.Method == HttpMethod.Put) == 1, "A conflict read private error bytes or retried the write.");
    }

    private static async Task BoundsAndErasureAsync()
    {
        foreach (var (list, maximum) in new[] { (true, 1024 * 1024), (false, 256 * 1024) })
        {
            using (var context = new TestContext((_, _) =>
                   {
                       var response = Json("{}"); response.Content.Headers.ContentLength = maximum + 1; return Task.FromResult(response);
                   }))
            {
                await context.SignInAsync();
                Ensure((list ? (await context.Client.GetAlertsAsync(new(), default)).Outcome : (await context.Client.GetAlertDetailAsync(AlertId, default)).Outcome) == AlertOutcome.TooLarge,
                    "An oversized declared alert body was not explicit.");
                if (!list) Ensure((await context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default)).Outcome == AlertOutcome.Indeterminate, "An oversized write success hid uncertainty.");
            }
            using var stream = new CapturedStream(new byte[maximum + 1024]);
            using var streamed = new TestContext((_, _) => Task.FromResult(StreamResponse(stream)));
            await streamed.SignInAsync();
            Ensure((list ? (await streamed.Client.GetAlertsAsync(new(), default)).Outcome : (await streamed.Client.GetAlertDetailAsync(AlertId, default)).Outcome) == AlertOutcome.TooLarge && stream.BytesRead == maximum + 1,
                "An unknown-length alert response escaped its bound or was silently truncated.");
            Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "An oversized response buffer was retained.");
        }
        foreach (var body in new[] { Detail(), "{}", Detail(status: "resolved", version: 2) })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(body));
            using var context = new TestContext((_, _) => Task.FromResult(StreamResponse(stream)));
            await context.SignInAsync();
            await context.Client.GetAlertDetailAsync(AlertId, default);
            Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "A success/invalid detail body buffer was not erased.");
        }
        foreach (var body in new[]
                 {
                     Page(Enumerable.Repeat(Summary(), 51).ToArray(), total: 51),
                     Detail(history: Enumerable.Repeat(History(), 101).ToArray(), historyCount: 101),
                     Detail(evidence: "[" + string.Join(',', Enumerable.Repeat("{\"field\":\"x\",\"value\":true}", 65)) + "]"),
                     Mutate(Detail(), node => node["endpointName"] = new string('x', 257)), Mutate(Detail(), node => node["ruleId"] = new string('x', 129)),
                     Mutate(Detail(), node => node["title"] = new string('x', 513)), Mutate(Detail(), node => node["reason"] = new string('x', 4097)),
                     Detail(evidence: JsonSerializer.Serialize(new[] { new { field = "x", value = new string('x', 2049) } }))
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((body.StartsWith("{\"alerts\"", StringComparison.Ordinal) ? (await context.Client.GetAlertsAsync(new(), default)).Outcome :
                (await context.Client.GetAlertDetailAsync(AlertId, default)).Outcome) == AlertOutcome.TooLarge, "Alert collection/text bounds were not enforced explicitly.");
        }
    }

    private static async Task SessionIsolationAsync()
    {
        foreach (var response in new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized })
        foreach (var write in new[] { false, true })
        {
            var answer = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var context = new TestContext((_, _) => { entered.TrySetResult(); return answer.Task; });
            await context.SignInAsync();
            var oldToken = StoredToken(context.Client);
            var pending = write ? context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default) : context.Client.GetAlertDetailAsync(AlertId, default);
            await entered.Task;
            await context.SignInAsync();
            Ensure(oldToken.All(value => value == 0), "Reauthentication retained old bearer bytes.");
            answer.SetResult(Json(Detail(status: "resolved", version: 2), response));
            Ensure((await pending).Outcome == AlertOutcome.Unauthenticated, "An old request published details into a newer session.");
            Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated, "A stale result/401 cleared a newly authenticated session.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json(Detail()))))
        {
            await context.SignInAsync();
            var stored = StoredToken(context.Client); var count = context.Handler.Requests.Count;
            context.Clock.Advance(TimeSpan.FromMinutes(15));
            Ensure((await context.Client.GetAlertsAsync(new(), default)).Outcome == AlertOutcome.Unauthenticated && context.Handler.Requests.Count == count && stored.All(value => value == 0),
                "An expired session sent a bearer, retained credentials or published results.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json(Detail()))))
        {
            await context.SignInAsync(); context.Client.SignOut();
            Ensure((await context.Client.GetAlertDetailAsync(AlertId, default)).Outcome == AlertOutcome.Unauthenticated, "A signed-out client returned details.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json(Detail()))))
        {
            await context.SignInAsync();
            context.Handler.Answer = (_, _) => { context.Clock.Advance(TimeSpan.FromMinutes(15)); return Task.FromResult(Json(Detail())); };
            Ensure((await context.Client.GetAlertDetailAsync(AlertId, default)).Outcome == AlertOutcome.Unauthenticated, "A response completed after local session expiry was published.");
        }
    }

    private static async Task CancellationAndDeadlineAsync()
    {
        foreach (var write in new[] { false, true })
        {
            using var cancellation = new CancellationTokenSource();
            using var context = new TestContext(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json("{}"); });
            await context.SignInAsync();
            var pending = write ? context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, cancellation.Token) : context.Client.GetAlertDetailAsync(AlertId, cancellation.Token);
            cancellation.Cancel();
            var cancelled = false;
            try { await pending.WaitAsync(TimeSpan.FromSeconds(2)); } catch (OperationCanceledException) { cancelled = true; }
            Ensure(cancelled, "Caller cancellation did not stop an alert read/write.");
            var captured = context.Handler.Requests.Last();
            Ensure(captured.Request.Headers.Authorization is null && (captured.BodyBuffer is null || captured.BodyBuffer.All(value => value == 0)), "Cancellation retained a bearer header or write payload.");
        }
        var reads = DeadlineAsync(write: false); var writes = DeadlineAsync(write: true);
        await Task.WhenAll(reads, writes);
    }

    private static async Task DeadlineAsync(bool write)
    {
        using var stream = new StalledStream();
        using var context = new TestContext((_, _) => Task.FromResult(StreamResponse(stream)));
        await context.SignInAsync();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var outcome = write ? (await context.Client.UpdateAlertStatusAsync(AlertId, "resolved", 1, default).WaitAsync(TimeSpan.FromSeconds(13))).Outcome :
            (await context.Client.GetAlertDetailAsync(AlertId, default).WaitAsync(TimeSpan.FromSeconds(13))).Outcome;
        Ensure(outcome == (write ? AlertOutcome.Indeterminate : AlertOutcome.Unavailable) && watch.Elapsed < TimeSpan.FromSeconds(12), "A stalled full response escaped its deadline or write uncertainty.");
        Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "Timed-out response bytes were retained.");
    }

    private static string Summary(string status = "open", long version = 1) => JsonSerializer.Serialize(new
    {
        alertId = AlertId, endpointId = EndpointId, endpointName = Literal, ruleId = "windows.test-rule", title = Literal,
        severity = "high", status, firstObservedUtc = When, lastObservedUtc = When, updatedUtc = When, version
    });
    private static string Page(string[] alerts, long? total = null, int offset = 0, int limit = 50) => "{\"alerts\":[" + string.Join(',', alerts) +
        "],\"total\":" + (total ?? alerts.Length) + ",\"offset\":" + offset + ",\"limit\":" + limit + "}";
    private static string Detail(string status = "open", long version = 1, string? evidence = null, string[]? history = null, long? historyCount = null) =>
        Summary(status, version)[..^1] + ",\"reason\":" + JsonSerializer.Serialize(Literal) + ",\"evidence\":" + (evidence ?? "[]") +
        ",\"recommendedAction\":" + JsonSerializer.Serialize(Literal) + ",\"createdUtc\":\"" + When + "\",\"statusChangedUtc\":\"" + When +
        "\",\"statusHistory\":[" + string.Join(',', history ?? [History(status)]) + "],\"statusHistoryCount\":" + (historyCount ?? history?.Length ?? 1) + "}";
    private static string History(string status = "open", string? previous = null) => JsonSerializer.Serialize(new { previousStatus = previous, status, changedUtc = When, changedBy = "system" });
    private static string Evidence() => JsonSerializer.Serialize(new object[] { new { field = "firewall.enabled", value = (object)false }, new { field = "integer", value = (object)long.MinValue },
        new { field = "unknown", value = (object?)null }, new { field = "literal", value = (object)Literal }, new { field = "empty", value = (object)string.Empty } });
    private static string Mutate(string json, Action<JsonObject> mutate) { var node = JsonNode.Parse(json)!.AsObject(); mutate(node); return node.ToJsonString(); }
    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static HttpResponseMessage StreamResponse(Stream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); return response;
    }
    private static byte[] StoredToken(HttpAuthenticationClient client) => (byte[])typeof(HttpAuthenticationClient).GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class TestContext : IDisposable
    {
        internal TestContext(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer)
        {
            Handler = new TestHandler(answer); Client = new(Trust, Handler, timeProvider: Clock);
        }
        internal TestHandler Handler { get; }
        internal TestTrust Trust { get; } = new();
        internal TestClock Clock { get; } = new();
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login fixture failed.");
        public void Dispose() => Client.Dispose();
    }
    private sealed class TestHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) : HttpMessageHandler
    {
        internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Answer { get; set; } = answer;
        internal List<CapturedRequest> Requests { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[]? buffer = null;
            // ByteArrayContent deliberately hides its backing array from its public
            // stream. Observe the borrowed array directly to verify actual erasure.
            if (request.Content is ByteArrayContent bytes)
                buffer = (byte[])typeof(ByteArrayContent).GetField("_content", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(bytes)!;
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new(request, request.Method, request.RequestUri!.AbsolutePath, request.RequestUri.Query,
                request.RequestUri.GetLeftPart(UriPartial.Authority), request.Headers.Authorization?.ToString(), body, buffer));
            return request.RequestUri.AbsolutePath switch
            {
                "/api/auth/login" => Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}"),
                "/api/admin/me" => Json("{\"username\":\"admin\",\"role\":\"administrator\"}"),
                _ => await Answer(request, cancellationToken)
            };
        }
    }
    private sealed record CapturedRequest(HttpRequestMessage Request, HttpMethod Method, string Path, string Query, string Origin, string? Authorization, string? Body, byte[]? BodyBuffer);
    private sealed class TestTrust : ICoreEndpointTrust
    {
        internal bool Allowed { get; set; } = true;
        internal int Calls { get; private set; }
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.Parse(When, global::System.Globalization.CultureInfo.InvariantCulture);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private class CapturedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead { get; private set; }
        internal byte[]? DestinationBuffer { get; private set; }
        protected void Capture(Memory<byte> buffer) { if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) DestinationBuffer = segment.Array; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer); var read = await base.ReadAsync(buffer, cancellationToken); BytesRead += read; return read;
        }
    }
    private sealed class StalledStream() : CapturedStream([])
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0;
        }
    }
}
