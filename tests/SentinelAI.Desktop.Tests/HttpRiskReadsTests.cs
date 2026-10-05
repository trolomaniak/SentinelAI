using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Scoring;

internal static class HttpRiskReadsTests
{
    private static readonly Guid EndpointId = Guid.Parse("66e900ea-763b-4f4c-823f-514a574933f3");
    private static readonly Guid AlertId = Guid.Parse("60d457b1-70db-4a38-95d2-3ab2c0aa70f7");
    private static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const string Token = "synthetic-risk-bearer-for-tests";
    private const string Literal = "<script>alert('literal')</script> ${operator} & <b>text</b>";
    private const string PrivateError = "synthetic-private-data-not-for-display";
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await PublicShapeAsync();
        await InputsAndHttpAsync();
        await ClosedSchemaAsync();
        await PolicyValidationAsync();
        await BoundsAndErasureAsync();
        await SessionIsolationAsync();
        await CancellationAndDeadlineAsync();
        return _assertions;
    }

    private static async Task PublicShapeAsync()
    {
        var expected = Detail();
        using var context = new TestContext((request, _) => Task.FromResult(Json(request.RequestUri!.AbsolutePath == "/api/admin/risk"
            ? Serialize(Page([expected], offset: 20, total: 21)) : Serialize(expected))));
        Ensure((await context.Client.GetRiskPageAsync(0, 50, default)).Outcome == RiskReadOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
            "An unauthenticated risk read sent a request.");
        await context.SignInAsync();
        var page = await context.Client.GetRiskPageAsync(20, 50, default);
        Ensure(page is { Outcome: RiskReadOutcome.Success, Value.Offset: 20, Value.Limit: 50, Value.Total: 21, Value.Endpoints.Count: 1 } &&
            page.Value.Organization.Score == expected.Risk.Score && page.Value.Endpoints[0].RawScore == expected.Risk.RawScore, "Organization/page values were invented or lost.");
        var result = await context.Client.GetEndpointRiskDetailAsync(EndpointId, default);
        Ensure(result is { Outcome: RiskReadOutcome.Success, Value.Alerts.Count: 2, Value.Risk.Contributions.Count: 2 }, "The public risk detail shape failed.");
        var actual = result.Value!;
        Ensure(Serialize(actual) == Serialize(expected), "Core's deterministic output was changed, recalculated or lost while projecting immutable scoring records.");
        var factor = actual.Risk.Contributions.Single(value => value.AlertId == AlertId);
        Ensure(factor.SeverityPoints == 25m && factor.DetectionConfidence == 0.1234567890123456789012345678m && factor.ConfidenceSource == "rulePolicyOverride" &&
            factor.AssetCriticalityMultiplier == 2m && factor.ExposureMultiplier == 1.5m && factor.AgeMultiplier == 0.75m && factor.AgeBand == "aging" &&
            factor.RemainingRiskMultiplier == 1m && factor.MitigationReduction == 0m && factor.PointsBeforeMitigation == factor.Contribution,
            "Decimal severity/confidence/asset/exposure/age/status factors lost precision or policy sources.");
        Ensure(actual.Risk.Context is { AssetCriticality: "critical", Exposure: "internet", AssetCriticalitySource: "userDeclared", ExposureSource: "userDeclared" } &&
            actual.Coverage is { InventoryState: "stale", SignalCoverage: "partial", KnownRuleSignals: 4, TotalRuleSignals: 13 } && actual.EndpointName == Literal && actual.Alerts[0].Reason == Literal,
            "Declared context, coverage or literal text was inferred or interpreted.");
        var resolved = actual.Risk.Contributions.Single(value => value.Status == "resolved");
        Ensure(resolved.RemainingRiskMultiplier == 0 && resolved.Contribution == 0 && resolved.MitigationReduction == resolved.PointsBeforeMitigation,
            "Core's resolved/remediation effect was lost.");
        var reads = context.Handler.Requests.Where(request => request.Path.Contains("risk", StringComparison.Ordinal)).ToArray();
        Ensure(reads.Length == 2 && reads.All(request => request.Method == HttpMethod.Get && !request.HasBody && request.Authorization == "Bearer " + Token &&
            request.Origin == "http://127.0.0.1:5000" && request.Request.Headers.Authorization is null), "Risk reads wrote data, changed origin or retained bearer headers.");
        Ensure(reads[0].Query == "?offset=20&limit=50" && reads[1].Path == "/api/admin/devices/" + EndpointId + "/risk" && context.Trust.Calls >= context.Handler.Requests.Count,
            "Risk routes/query or connected-peer trust composition changed.");

        var missing = Detail(missing: true);
        using var unknown = new TestContext((_, _) => Task.FromResult(Json(Serialize(missing))));
        await unknown.SignInAsync();
        Ensure((await unknown.Client.GetEndpointRiskDetailAsync(EndpointId, default)) is { Outcome: RiskReadOutcome.Success, Value.InventoryCollectedUtc: null,
            Value.Risk.Context.LatestInventoryUtc: null, Value.Coverage.InventoryState: "missing", Value.Coverage.SignalCoverage: "unknown", Value.Coverage.KnownRuleSignals: 0 },
            "Missing inventory was converted into a fabricated observation.");
        using var empty = new TestContext((_, _) => Task.FromResult(Json(Serialize(Page([], offset: 100)))));
        await empty.SignInAsync();
        Ensure((await empty.Client.GetRiskPageAsync(100, 50, default)) is { Outcome: RiskReadOutcome.Success, Value.Endpoints.Count: 0, Value.Organization.Score: 0, Value.Organization.EndpointCount: 0 },
            "An empty organization was not represented by the existing API output.");
        var fresh = Detail(fresh: true);
        using var correlation = new TestContext((_, _) => Task.FromResult(Json(Serialize(fresh))));
        await correlation.SignInAsync();
        var correlated = (await correlation.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Value!;
        Ensure(correlated.Risk is { Score: 100, Saturated: true, CorrelationBaseBonus: 5m, CorrelationBonus: 15m } &&
            correlated.Risk.CorrelatedGroups.SequenceEqual(["FW", "UAC"]) && correlated.Risk.Contributions.All(value => value.LatestSnapshotConfirmed && value.CorrelationEligible),
            "Raw/saturation/correlation/current-snapshot factors changed.");
        var tied = Page([fresh, Detail(fresh: true, endpointId: Guid.NewGuid())]);
        using var ties = new TestContext((_, _) => Task.FromResult(Json(Serialize(tied))));
        await ties.SignInAsync();
        Ensure((await ties.Client.GetRiskPageAsync(0, 50, default)) is { Outcome: RiskReadOutcome.Success, Value.Organization.HighestRiskEndpointIds.Count: 1,
            Value.Organization.HighestRiskEndpointCount: 2, Value.Organization.HighestRiskEndpointIdsTruncated: true }, "Highest-risk ties lost the disclosed count/representative limit.");
        var defaultScorer = new RiskScorer();
        var assumptions = fresh with { Risk = defaultScorer.ScoreEndpoint(EndpointId, fresh.Alerts.Select(value => new ScoringAlert(value.AlertId, value.RuleId, value.Severity, value.Status, value.LastObservedUtc)),
            new EndpointScoringContext(LatestInventoryUtc: fresh.InventoryCollectedUtc), Now), Policy = defaultScorer.Policy };
        using var defaults = new TestContext((_, _) => Task.FromResult(Json(Serialize(assumptions)))); await defaults.SignInAsync();
        Ensure((await defaults.Client.GetEndpointRiskDetailAsync(EndpointId, default)) is { Outcome: RiskReadOutcome.Success,
            Value.Risk.Context.AssetCriticality: "standard", Value.Risk.Context.Exposure: "unknown", Value.Risk.Context.AssetCriticalitySource: "policyDefault", Value.Risk.Context.ExposureSource: "policyDefault" },
            "Policy assumptions were presented as observed or declared context.");
        var future = Detail(fresh: true, future: true);
        using var skew = new TestContext((_, _) => Task.FromResult(Json(Serialize(future)))); await skew.SignInAsync();
        var futureResult = (await skew.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Value!;
        Ensure(futureResult.Coverage.InventoryState == "future" && futureResult.Risk.Contributions.All(value => value.FutureTimestampClamped && value.AgeDays == 0),
            "Core's future-inventory and clamped observation-age indicators were changed.");
    }

    private static async Task InputsAndHttpAsync()
    {
        using var inputs = new TestContext((_, _) => throw new InvalidOperationException("Invalid input reached HTTP."));
        await inputs.SignInAsync(); var initial = inputs.Handler.Requests.Count;
        foreach (var (offset, limit) in new[] { (-1, 50), (0, 0), (0, 201) })
            Ensure((await inputs.Client.GetRiskPageAsync(offset, limit, default)).Outcome == RiskReadOutcome.InvalidResponse, "Invalid risk paging was accepted.");
        Ensure((await inputs.Client.GetEndpointRiskDetailAsync(Guid.Empty, default)).Outcome == RiskReadOutcome.InvalidResponse && inputs.Handler.Requests.Count == initial, "An invalid endpoint ID reached Core.");
        foreach (var (status, expected) in new[] { (HttpStatusCode.Unauthorized, RiskReadOutcome.Unauthenticated), (HttpStatusCode.Forbidden, RiskReadOutcome.Unavailable),
                     (HttpStatusCode.ServiceUnavailable, RiskReadOutcome.Unavailable), (HttpStatusCode.Redirect, RiskReadOutcome.Unavailable),
                     (HttpStatusCode.NotFound, RiskReadOutcome.NotFound), (HttpStatusCode.RequestEntityTooLarge, RiskReadOutcome.TooLarge), (HttpStatusCode.UnprocessableEntity, RiskReadOutcome.TooLarge) })
        {
            using var body = new CapturedStream(Encoding.UTF8.GetBytes(PrivateError));
            using var context = new TestContext((_, _) => { var response = StreamResponse(body); response.StatusCode = status; return Task.FromResult(response); });
            await context.SignInAsync();
            var result = await context.Client.GetEndpointRiskDetailAsync(EndpointId, default);
            Ensure(result.Outcome == expected && result.Value is null && body.BytesRead == 0 && !result.ToString().Contains(PrivateError, StringComparison.Ordinal), "An error response exposed private body bytes or had the wrong outcome.");
            if (status == HttpStatusCode.Unauthorized) Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "A matching 401 retained bearer material.");
        }
        using var missingList = new TestContext((_, _) => Task.FromResult(Json("{}", HttpStatusCode.NotFound)));
        await missingList.SignInAsync();
        Ensure((await missingList.Client.GetRiskPageAsync(0, 50, default)).Outcome == RiskReadOutcome.Unavailable, "A missing Risk API route became an empty fleet.");
        using var trust = new TestContext((_, _) => Task.FromResult(Json(Serialize(Detail()))));
        await trust.SignInAsync(); initial = trust.Handler.Requests.Count; trust.Trust.Allowed = false;
        Ensure((await trust.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.UntrustedConnection && trust.Handler.Requests.Count == initial &&
            (await trust.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "An untrusted endpoint received or retained bearer material.");
        using var nonJson = new TestContext((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Serialize(Detail()), Encoding.UTF8, "text/html") }));
        await nonJson.SignInAsync();
        Ensure((await nonJson.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.InvalidResponse, "A non-JSON risk body was admitted.");
    }

    private static async Task ClosedSchemaAsync()
    {
        var detail = Serialize(Detail()); var page = Serialize(Page([Detail()]));
        foreach (var body in new[] { "{}", "[]", "null", Mutate(page, node => node["total"] = -1), Mutate(page, node => node["offset"] = 1),
                     Mutate(page, node => node["limit"] = 1), Mutate(page, node => node["total"] = 0), Mutate(page, node => node["passwordHash"] = PrivateError),
                     Mutate(page, node => node["organization"]!["endpointCount"] = 2), Mutate(page, node => node["organization"]!["score"] = 101),
                     Mutate(page, node => node["organization"]!["method"] = "inventedAverage"), Mutate(page, node => node["organization"]!["missingInventoryCount"] = 1),
                     Mutate(page, node => node["organization"]!["alertStatusCounts"]!["credentials"] = PrivateError),
                     Mutate(page, node => node["organization"]!["highestRiskEndpointIds"] = new JsonArray(Guid.Empty.ToString())),
                     Mutate(page, node => node["organization"]!["highestRiskEndpointIdsTruncated"] = true),
                     Mutate(page, node => node["endpoints"]!.AsArray().Add(JsonNode.Parse(Serialize(Page([Detail()])))!["endpoints"]![0]!.DeepClone())),
                     Mutate(page, node => node["endpoints"]![0]!["endpointName"] = null), Mutate(page, node => node["endpoints"]![0]!["coverage"]!["caution"] = null),
                     page.Replace("\"total\":1", "\"total\":1,\"total\":1", StringComparison.Ordinal), page.Replace("\"rawScore\":", "\"rawScore\":1e999,\"ignored\":", StringComparison.Ordinal) })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body))); await context.SignInAsync();
            Ensure((await context.Client.GetRiskPageAsync(0, 50, default)) is { Outcome: RiskReadOutcome.InvalidResponse, Value: null }, "Malformed/duplicate/private risk page fields were admitted.");
        }
        foreach (var mutate in new Action<JsonObject>[]
                 {
                     node => node["endpointId"] = Guid.NewGuid().ToString(), node => node.Remove("inventoryCollectedUtc"), node => node["privateConfig"] = PrivateError,
                     node => node["risk"]!["endpointId"] = Guid.NewGuid().ToString(), node => node["risk"]!["score"] = -1, node => node["risk"]!["rawScore"] = "NaN",
                     node => node["risk"]!["rawScore"] = -1, node => node["risk"]!["saturated"] = 1, node => node["risk"]!["context"] = null,
                     node => node["risk"]!["context"]!["exposure"] = "detectedInternet", node => node["risk"]!["context"]!["assetCriticality"] = "important",
                     node => node["risk"]!["context"]!["assetCriticalitySource"] = "inferred", node => node["risk"]!["context"]!["latestInventoryUtc"] = null,
                     node => node["risk"]!["context"]!["sqlitePath"] = PrivateError, node => node["risk"]!["contributions"]![0]!["confidenceSource"] = "AI",
                     node => node["risk"]!["contributions"]![0]!["detectionConfidence"] = 1.1, node => node["risk"]!["contributions"]![0]!["ageMultiplier"] = 0,
                     node => node["risk"]!["contributions"]![0]!["ageBand"] = "foreverSafe", node => node["risk"]!["contributions"]![0]!["futureTimestampClamped"] = "true",
                     node => node["risk"]!["contributions"]![0]!["correlationGroup"] = new JsonObject { ["secret"] = PrivateError },
                     node => node["risk"]!["contributions"]![0]!.AsObject().Remove("correlationGroup"), node => node["risk"]!["contributions"]![0]!["apiToken"] = PrivateError,
                     node => node["risk"]!["contributions"]!.AsArray().Add(node["risk"]!["contributions"]![0]!.DeepClone()),
                     node => node["risk"]!["correlatedGroups"] = new JsonArray("FW", "FW"), node => node["alerts"]![0]!["alertId"] = Guid.NewGuid().ToString(),
                     node => node["alerts"]![0]!["severity"] = "unsafe", node => node["alerts"]![0]!["status"] = "normalAutoResolved", node => node["alerts"]![0]!["ruleId"] = "mismatched",
                     node => node["alerts"]![0]!["reason"] = "control\0text", node => node["alerts"]!.AsArray().RemoveAt(0),
                     node => node["coverage"]!["inventoryState"] = "fresh", node => node["coverage"]!["signalCoverage"] = "safe", node => node["coverage"]!["knownRuleSignals"] = 14,
                     node => node["coverage"]!["totalRuleSignals"] = 14, node => node["coverage"]!["signalCoverage"] = "complete", node => node["inventoryFreshForHours"] = 8761,
                     node => node["risk"]!["calculatedUtc"] = "2026-10-04T12:00:00", node => node["risk"]!["calculatedUtc"] = "2026-10-04T12:00:00+01:00"
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(Mutate(detail, mutate)))); await context.SignInAsync();
            var result = await context.Client.GetEndpointRiskDetailAsync(EndpointId, default);
            Ensure(result is { Outcome: RiskReadOutcome.InvalidResponse, Value: null } && !result.ToString().Contains(PrivateError, StringComparison.Ordinal), "Unsafe detail/context/factor/coverage fields were admitted.");
        }
        foreach (var body in new[] { detail.Replace("\"ageDays\":10", "\"ageDays\":1e999", StringComparison.Ordinal),
                     detail.Replace("\"detectionConfidence\":", "\"detectionConfidence\":NaN,\"unused\":", StringComparison.Ordinal),
                     detail.Replace("\"rawScore\":", "\"rawScore\":1e999,\"unused\":", StringComparison.Ordinal),
                     detail.Replace("\"severityPoints\":25", "\"severityPoints\":25,\"severityPoints\":25", StringComparison.Ordinal) })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body))); await context.SignInAsync();
            Ensure((await context.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.InvalidResponse, "A nonfinite/duplicate numeric factor was admitted.");
        }
    }

    private static async Task PolicyValidationAsync()
    {
        var body = Serialize(Detail());
        foreach (var mutate in new Action<JsonObject>[]
                 {
                     node => node["policy"]!["defaultConfidence"] = 0, node => node["policy"]!["defaultConfidence"] = 2, node => node["policy"]!["maximumScore"] = 101,
                     node => node["policy"]!["severityPoints"]!["critical"] = -1, node => node["policy"]!["severityPoints"]!["high"] = 51,
                     node => node["policy"]!["severityPoints"]!["private"] = 1, node => node["policy"]!["assetMultipliers"]!.AsObject().Remove("standard"),
                     node => node["policy"]!["assetMultipliers"]!["high"] = 11, node => node["policy"]!["exposureMultipliers"]!["isolated"] = 2,
                     node => node["policy"]!["remainingRiskByStatus"]!["accepted"] = 0, node => node["policy"]!["remainingRiskByStatus"]!["resolved"] = 1,
                     node => node["policy"]!["freshForDays"] = 30, node => node["policy"]!["agingForDays"] = 3651, node => node["policy"]!["oldMultiplier"] = 0,
                     node => node["policy"]!["oldMultiplier"] = 0.9, node => node["policy"]!["confidenceByRule"]!["SA-FW-001"] = "0.5",
                     node => node["policy"]!["confidenceByRule"]!["SA-FW-001"] = new JsonObject { ["password"] = PrivateError },
                     node => node["policy"]!["correlationGroupsByRule"]!["SA-FW-001"] = null, node => node["policy"]!["correlationGroupsByRule"]!["bad\0label"] = "FW",
                     node => node["policy"]!["correlationPointsPerExtraGroup"] = 101, node => node["policy"]!["maximumCorrelationBaseBonus"] = -1,
                     node => node["policy"]!["version"] = " ", node => node["policy"]!["licenseSecret"] = PrivateError
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(Mutate(body, mutate)))); await context.SignInAsync();
            Ensure((await context.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.InvalidResponse, "An unknown, malformed or unsafe scoring policy was admitted.");
        }
        foreach (var duplicate in new[] { body.Replace("\"SA-FW-001\":0.1234567890123456789012345678", "\"SA-FW-001\":0.1234567890123456789012345678,\"SA-FW-001\":0.5", StringComparison.Ordinal),
                     body.Replace("\"SA-FW-001\":\"FW\"", "\"SA-FW-001\":\"FW\",\"SA-FW-001\":\"FW\"", StringComparison.Ordinal) })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(duplicate))); await context.SignInAsync();
            Ensure((await context.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.InvalidResponse, "A duplicate policy rule key was admitted.");
        }
    }

    private static async Task BoundsAndErasureAsync()
    {
        foreach (var (page, maximum) in new[] { (true, 2 * 1024 * 1024), (false, 1024 * 1024) })
        {
            using var declared = new TestContext((_, _) => { var response = Json("{}"); response.Content.Headers.ContentLength = maximum + 1; return Task.FromResult(response); });
            await declared.SignInAsync();
            Ensure((page ? (await declared.Client.GetRiskPageAsync(0, 50, default)).Outcome : (await declared.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome) == RiskReadOutcome.TooLarge,
                "Declared risk-body limits were not explicit.");
            using var stream = new CapturedStream(new byte[maximum + 4096]);
            using var context = new TestContext((_, _) => Task.FromResult(StreamResponse(stream))); await context.SignInAsync();
            Ensure((page ? (await context.Client.GetRiskPageAsync(0, 50, default)).Outcome : (await context.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome) == RiskReadOutcome.TooLarge && stream.BytesRead == maximum + 1,
                "An unbounded risk body exceeded its cap or was silently truncated.");
            Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "Oversized risk bytes were not erased.");
        }
        var detail = Serialize(Detail());
        foreach (var body in new[] { detail, "{}" })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(body));
            using var context = new TestContext((_, _) => Task.FromResult(StreamResponse(stream))); await context.SignInAsync();
            await context.Client.GetEndpointRiskDetailAsync(EndpointId, default);
            Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "Success/malformed risk response buffers were retained.");
        }
        foreach (var mutate in new Action<JsonObject>[]
                 {
                     node => node["endpointName"] = new string('x', 257), node => node["risk"]!["explanation"] = new string('x', 4097),
                     node => node["alerts"] = new JsonArray(Enumerable.Range(0, 65).Select(_ => node["alerts"]![0]!.DeepClone()).ToArray()),
                     node => node["risk"]!["contributions"] = new JsonArray(Enumerable.Range(0, 65).Select(_ => node["risk"]!["contributions"]![0]!.DeepClone()).ToArray()),
                     node => node["policy"]!["version"] = new string('x', 101), node => node["policy"]!["confidenceByRule"] = ManyPolicyRules(strings: false),
                     node => node["policy"]!["correlationGroupsByRule"] = ManyPolicyRules(strings: true)
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(Mutate(detail, mutate)))); await context.SignInAsync();
            Ensure((await context.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.TooLarge, "Risk string/array/policy work limits were not explicit.");
        }
        var pageBody = Mutate(Serialize(Page([Detail()])), node => { node["limit"] = 200; node["endpoints"] = new JsonArray(Enumerable.Range(0, 201).Select(_ => node["endpoints"]![0]!.DeepClone()).ToArray()); });
        using var rows = new TestContext((_, _) => Task.FromResult(Json(pageBody))); await rows.SignInAsync();
        Ensure((await rows.Client.GetRiskPageAsync(0, 200, default)).Outcome == RiskReadOutcome.TooLarge, "Risk pages admitted more than 200 endpoint rows.");
    }

    private static async Task SessionIsolationAsync()
    {
        foreach (var code in new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized })
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var answer = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var context = new TestContext((_, _) => { entered.TrySetResult(); return answer.Task; }); await context.SignInAsync();
            var oldToken = StoredToken(context.Client); var pending = context.Client.GetEndpointRiskDetailAsync(EndpointId, default); await entered.Task;
            await context.SignInAsync(); Ensure(oldToken.All(value => value == 0), "Reauthentication retained previous bearer bytes.");
            answer.SetResult(Json(Serialize(Detail()), code));
            Ensure((await pending).Outcome == RiskReadOutcome.Unauthenticated && (await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated,
                "A stale result/401 restored old data or cleared a newer session.");
        }
        using var expired = new TestContext((_, _) => Task.FromResult(Json(Serialize(Detail())))); await expired.SignInAsync();
        var token = StoredToken(expired.Client); var requests = expired.Handler.Requests.Count; expired.Clock.Advance(TimeSpan.FromMinutes(15));
        Ensure((await expired.Client.GetRiskPageAsync(0, 50, default)).Outcome == RiskReadOutcome.Unauthenticated && expired.Handler.Requests.Count == requests && token.All(value => value == 0),
            "An exactly expired session reached Core or retained bearer bytes.");
        using var during = new TestContext((_, _) => Task.FromResult(Json(Serialize(Detail())))); await during.SignInAsync();
        during.Handler.Answer = (_, _) => { during.Clock.Advance(TimeSpan.FromMinutes(15)); return Task.FromResult(Json(Serialize(Detail()))); };
        Ensure((await during.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.Unauthenticated, "A result completed after expiry was published.");
        using var signedOut = new TestContext((_, _) => Task.FromResult(Json(Serialize(Detail())))); await signedOut.SignInAsync(); signedOut.Client.SignOut();
        Ensure((await signedOut.Client.GetEndpointRiskDetailAsync(EndpointId, default)).Outcome == RiskReadOutcome.Unauthenticated, "A signed-out client published risk data.");
    }

    private static async Task CancellationAndDeadlineAsync()
    {
        using var cancellation = new CancellationTokenSource();
        using var context = new TestContext(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json("{}"); }); await context.SignInAsync();
        var pending = context.Client.GetEndpointRiskDetailAsync(EndpointId, cancellation.Token); cancellation.Cancel();
        var cancelled = false; try { await pending.WaitAsync(TimeSpan.FromSeconds(2)); } catch (OperationCanceledException) { cancelled = true; }
        Ensure(cancelled && context.Handler.Requests.Last().Request.Headers.Authorization is null, "Caller cancellation did not stop the read or clear its header.");
        await Task.WhenAll(DeadlineAsync(headers: true), DeadlineAsync(headers: false));
    }

    private static async Task DeadlineAsync(bool headers)
    {
        using var stream = new StalledStream();
        using var context = new TestContext(async (_, token) => { if (headers) await Task.Delay(Timeout.InfiniteTimeSpan, token); return StreamResponse(stream); });
        await context.SignInAsync(); var watch = System.Diagnostics.Stopwatch.StartNew();
        Ensure((await context.Client.GetEndpointRiskDetailAsync(EndpointId, default).WaitAsync(TimeSpan.FromSeconds(13))).Outcome == RiskReadOutcome.Unavailable && watch.Elapsed < TimeSpan.FromSeconds(12),
            "A stalled header/body exceeded the full risk-request deadline.");
        if (!headers) Ensure(stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "Timed-out risk buffer bytes were retained.");
    }

    private static EndpointRiskDetail Detail(bool missing = false, bool fresh = false, Guid? endpointId = null, bool future = false)
    {
        var id = endpointId ?? EndpointId; var observed = future ? Now.AddHours(1) : fresh ? Now : Now.AddDays(-10);
        var policy = new ScoringPolicy(); if (!fresh) policy.ConfidenceByRule["SA-FW-001"] = 0.1234567890123456789012345678m;
        var scorer = new RiskScorer(policy);
        var alerts = new RiskAlertView[] { new(AlertId, "SA-FW-001", Literal, fresh ? "critical" : "high", "open", observed, Literal),
            new(Guid.Parse("40357c6e-54cd-4b58-8f9a-753c908939cc"), "SA-UAC-001", "UAC finding", "critical", fresh ? "accepted" : "resolved", observed, "Operator decision") };
        var inventory = missing ? (DateTimeOffset?)null : observed;
        var context = new EndpointScoringContext("critical", "internet", inventory, "userDeclared", "userDeclared");
        var risk = scorer.ScoreEndpoint(id, alerts.Select(value => new ScoringAlert(value.AlertId, value.RuleId, value.Severity, value.Status, value.LastObservedUtc)), context, Now);
        return new(id, Literal, inventory, risk, new(missing ? "missing" : future ? "future" : fresh ? "current" : "stale", missing ? "unknown" : "partial", missing ? 0 : 4, 13, Literal),
            Array.AsReadOnly(alerts), scorer.Policy, 12);
    }
    private static RiskPage Page(EndpointRiskDetail[] details, int offset = 0, long? total = null)
    {
        var count = (int)(total ?? details.Length); var score = details.Length == 0 ? 0 : details.Max(value => value.Risk.Score);
        var highest = details.Where(value => value.Risk.Score == score).Select(value => value.EndpointId).Order().ToArray();
        var alerts = details.SelectMany(value => value.Alerts).ToArray();
        var missing = details.Count(value => value.InventoryCollectedUtc is null);
        var organization = new OrganizationRiskView(score, count, Array.AsReadOnly(highest.Take(1).ToArray()), highest.Length, highest.Length > 1, "maximumEndpointScore", Literal,
            Now, count - missing, missing, missing, details.Count(value => value.Coverage.SignalCoverage == "partial"), details.Count(value => value.Coverage.InventoryState == "stale"),
            new(alerts.Count(value => value.Status == "open"), alerts.Count(value => value.Status == "investigating"), alerts.Count(value => value.Status == "accepted"), alerts.Count(value => value.Status == "resolved")));
        return new(organization, Array.AsReadOnly(details.Select(value => new EndpointRiskSummary(value.EndpointId, value.EndpointName, value.InventoryCollectedUtc, value.Risk.Score, value.Risk.RawScore,
            value.Coverage, value.Alerts.Count(alert => alert.Status != "resolved"), Literal, Now)).ToArray()), total ?? details.Length, offset, 50, details.FirstOrDefault()?.Policy ?? new RiskScorer().Policy, 12);
    }
    private static JsonObject ManyPolicyRules(bool strings)
    {
        var result = new JsonObject(); for (var i = 0; i < 1025; i++) result["rule-" + i] = strings ? JsonValue.Create("group") : JsonValue.Create(0.5m); return result;
    }
    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, JsonOptions);
    private static string Mutate(string json, Action<JsonObject> mutate) { var node = JsonNode.Parse(json)!.AsObject(); mutate(node); return node.ToJsonString(); }
    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static HttpResponseMessage StreamResponse(Stream stream) { var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }; response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); return response; }
    private static byte[] StoredToken(HttpAuthenticationClient client) => (byte[])typeof(HttpAuthenticationClient).GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }
    private sealed class TestContext : IDisposable
    {
        internal TestContext(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer); Client = new(Trust, Handler, timeProvider: Clock); }
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
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request, request.Method, request.RequestUri!.AbsolutePath, request.RequestUri.Query, request.RequestUri.GetLeftPart(UriPartial.Authority), request.Content is not null, request.Headers.Authorization?.ToString()));
            return request.RequestUri.AbsolutePath switch
            {
                "/api/auth/login" => Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}")),
                "/api/admin/me" => Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}")), _ => Answer(request, cancellationToken)
            };
        }
    }
    private sealed record CapturedRequest(HttpRequestMessage Request, HttpMethod Method, string Path, string Query, string Origin, bool HasBody, string? Authorization);
    private sealed class TestTrust : ICoreEndpointTrust
    {
        internal bool Allowed { get; set; } = true;
        internal int Calls { get; private set; }
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = Now; public override DateTimeOffset GetUtcNow() => _now; internal void Advance(TimeSpan duration) => _now += duration;
    }
    private class CapturedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead { get; private set; }
        internal byte[]? DestinationBuffer { get; private set; }
        protected void Capture(Memory<byte> buffer) { if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) DestinationBuffer = segment.Array; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) { Capture(buffer); var read = await base.ReadAsync(buffer, cancellationToken); BytesRead += read; return read; }
    }
    private sealed class StalledStream() : CapturedStream([])
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) { Capture(buffer); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
    }
}
