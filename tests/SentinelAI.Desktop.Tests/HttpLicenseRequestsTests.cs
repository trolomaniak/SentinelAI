using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

internal static class HttpLicenseRequestsTests
{
    private const string Token = "synthetic-license-bearer";
    private const string PrivateError = "synthetic-activation-lease-provider-secret";
    private const string PublicJson = """
        {"mode":"SAFE_MODE","capabilities":{"criticalTelemetryCollection":true,"localDetectionRules":true,"criticalAlerts":true,"recentIncidents":true,"emergencyExport":true,"premiumFeatures":false},"lastSuccessfulValidationUtc":null,"fullModeUntil":null,"effectiveUtc":"2035-10-08T12:34:56Z","clockRollbackDetected":false,"enabledFeatures":[]}
        """;
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        // Run both actual whole-operation deadlines together with the fast cases.
        var deadlines = Task.WhenAll(DeadlineAsync(false), DeadlineAsync(true));
        await PublicModesAndRequestsAsync();
        await ClosedSchemaAsync();
        await BoundsAndHeadersAsync();
        await ErrorAndTrustAsync();
        await SessionIsolationAsync();
        await CancellationAsync();
        await deadlines;
        Console.WriteLine($"Desktop license transport: {_assertions} assertions passed.");
        return _assertions;
    }

    private static async Task PublicModesAndRequestsAsync()
    {
        foreach (var renew in new[] { false, true })
        foreach (var mode in new[] { "FULL", "GRACE", "SAFE_MODE", "RECOVERING" })
        foreach (var premium in new[] { false, true })
        {
            var root = Body();
            root["mode"] = mode;
            root["capabilities"]!["premiumFeatures"] = premium;
            // Expired/null lease dates must not let Desktop override Core's mode.
            root["lastSuccessfulValidationUtc"] = "2001-01-01T12:00:00+00:00";
            root["fullModeUntil"] = "2001-01-08T12:00:00Z";
            root["clockRollbackDetected"] = true;
            root["enabledFeatures"] = new JsonArray("cloud_ai", "CLOUD_AI", "Feature_2-x");
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(root.ToJsonString()), 1);
            using var context = new Context((_, _) => Task.FromResult(Json(stream)));
            await context.SignInAsync();
            var result = await Request(context, renew);
            Ensure(result.Outcome == LicenseRequestOutcome.Success && result.Status?.Mode == mode &&
                   result.Status.Capabilities.PremiumFeatures == premium && result.Status.ClockRollbackDetected,
                "Desktop recalculated Core's mode, underlying permissions or rollback state.");
            Ensure(result.Status!.LastSuccessfulValidationUtc == new DateTimeOffset(2001, 1, 1, 12, 0, 0, TimeSpan.Zero) &&
                   result.Status.FullModeUntil == new DateTimeOffset(2001, 1, 8, 12, 0, 0, TimeSpan.Zero) &&
                   result.Status.EffectiveUtc == new DateTimeOffset(2035, 10, 8, 12, 34, 56, TimeSpan.Zero) &&
                   result.Status.EnabledFeatures.SequenceEqual(new[] { "cloud_ai", "CLOUD_AI", "Feature_2-x" }),
                "Public signed times or ordinal feature identities changed in transit.");
            var request = context.Handler.Requests.Last();
            Ensure(request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/license" + (renew ? "/renew" : "") &&
                   request.Method == (renew ? HttpMethod.Post : HttpMethod.Get) && request.Content is null && request.Headers.Accept.Single().MediaType == "application/json",
                "Licensing sent body/query/destination overrides or changed the existing Core contract.");
            Ensure(context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted && request.Headers.Authorization is null,
                "Licensing did not borrow and clear the private trusted Core bearer.");
            AssertErased(stream);
            Ensure(((ICollection<string>)result.Status.EnabledFeatures).IsReadOnly,
                "The accepted license features exposed a mutable collection.");
        }
        // Every Core capability is authoritative, including an unexpected false baseline flag.
        var flags = Body();
        foreach (var property in flags["capabilities"]!.AsObject().ToList()) flags["capabilities"]![property.Key] = false;
        using var allFalse = new Context((_, _) => Task.FromResult(Json(flags.ToJsonString())));
        await allFalse.SignInAsync();
        var capabilities = (await Request(allFalse, false)).Status!.Capabilities;
        Ensure(!capabilities.CriticalTelemetryCollection && !capabilities.LocalDetectionRules && !capabilities.CriticalAlerts &&
               !capabilities.RecentIncidents && !capabilities.EmergencyExport && !capabilities.PremiumFeatures,
            "Desktop invented local or optional permissions instead of exposing Core's flags.");
    }

    private static async Task ClosedSchemaAsync()
    {
        var invalid = new List<string> { "", "null", "[]", "{}", "{", PublicJson + "{}",
            PublicJson.Replace("\"mode\":\"SAFE_MODE\"", "\"mode\":\"SAFE_MODE\",\"mode\":\"SAFE_MODE\"", StringComparison.Ordinal),
            PublicJson.Replace("\"criticalAlerts\":true", "\"criticalAlerts\":true,\"criticalAlerts\":true", StringComparison.Ordinal) };
        foreach (var property in Body().AsObject().ToList())
        {
            var missing = Body(); missing.AsObject().Remove(property.Key); invalid.Add(missing.ToJsonString());
            var wrongCase = Body(); wrongCase[property.Key.ToUpperInvariant()] = wrongCase[property.Key]?.DeepClone();
            wrongCase.AsObject().Remove(property.Key); invalid.Add(wrongCase.ToJsonString());
        }
        foreach (var key in Body()["capabilities"]!.AsObject().Select(property => property.Key).ToList())
        {
            var missing = Body(); missing["capabilities"]!.AsObject().Remove(key); invalid.Add(missing.ToJsonString());
            var wrong = Body(); wrong["capabilities"]![key] = "true"; invalid.Add(wrong.ToJsonString());
        }
        foreach (var mode in new JsonNode?[] { null, JsonValue.Create("full"), JsonValue.Create("REVOKED"), JsonValue.Create(0), new JsonObject() })
        {
            var body = Body(); body["mode"] = mode; invalid.Add(body.ToJsonString());
        }
        foreach (var key in new[] { "signedLease", "activationCredential", "issuerUrl", "providerKey" })
        {
            var rootSecret = Body(); rootSecret[key] = PrivateError; invalid.Add(rootSecret.ToJsonString());
            var nestedSecret = Body(); nestedSecret["capabilities"]![key] = PrivateError; invalid.Add(nestedSecret.ToJsonString());
        }
        foreach (var timestamp in new[] { "2026-10-08", "2026-10-08T12:00:00", "2026-10-08T12:00:00+01:00", "invalid", "2026-02-30T00:00:00Z" })
        foreach (var key in new[] { "effectiveUtc", "lastSuccessfulValidationUtc", "fullModeUntil" })
        {
            var body = Body(); body[key] = timestamp; invalid.Add(body.ToJsonString());
        }
        foreach (var (key, value) in new (string, JsonNode?)[] { ("effectiveUtc", null), ("clockRollbackDetected", null),
                     ("clockRollbackDetected", JsonValue.Create(1)), ("capabilities", null), ("enabledFeatures", null),
                     ("enabledFeatures", new JsonObject()), ("enabledFeatures", new JsonArray("duplicate", "duplicate")),
                     ("enabledFeatures", new JsonArray("")), ("enabledFeatures", new JsonArray(new string('a', 65))),
                     ("enabledFeatures", new JsonArray("cloud ai")), ("enabledFeatures", new JsonArray("日本語")),
                     ("enabledFeatures", new JsonArray("https://issuer.invalid")), ("enabledFeatures", new JsonArray((JsonNode?)null)),
                     ("enabledFeatures", new JsonArray(JsonValue.Create(1))), ("enabledFeatures", new JsonArray("line\nbreak")) })
        {
            var body = Body(); body[key] = value; invalid.Add(body.ToJsonString());
        }
        foreach (var renew in new[] { false, true })
        foreach (var text in invalid)
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(text));
            using var context = new Context((_, _) => Task.FromResult(Json(stream)));
            await context.SignInAsync();
            var result = await Request(context, renew);
            Ensure(result.Outcome == (renew ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.InvalidResponse) && result.Status is null &&
                   !result.ToString().Contains(PrivateError, StringComparison.Ordinal),
                "An incomplete, duplicate, private or incompatible license projection escaped its safe category.");
            AssertErased(stream);
        }
    }

    private static async Task BoundsAndHeadersAsync()
    {
        foreach (var count in new[] { 0, 64, 65 })
        {
            var body = Body(); body["enabledFeatures"] = new JsonArray(Enumerable.Range(0, count).Select(index => (JsonNode?)JsonValue.Create(index.ToString("D2") + new string('x', 62))).ToArray());
            using var context = new Context((_, _) => Task.FromResult(Json(body.ToJsonString())));
            await context.SignInAsync();
            var result = await Request(context, false);
            Ensure(result.Outcome == (count <= 64 ? LicenseRequestOutcome.Success : LicenseRequestOutcome.TooLarge) &&
                   (count > 64 || result.Status!.EnabledFeatures.Count == count), "The 64-feature/64-character inclusive bound changed.");
        }
        foreach (var renew in new[] { false, true })
        foreach (var length in new[] { 16 * 1024, 16 * 1024 + 1, 128 * 1024 })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(PublicJson.PadRight(length)));
            using var context = new Context((_, _) => Task.FromResult(Json(stream)));
            await context.SignInAsync();
            var result = await Request(context, renew);
            Ensure(result.Outcome == (length <= 16 * 1024 ? LicenseRequestOutcome.Success : renew ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.TooLarge) &&
                   stream.BytesRead <= 16 * 1024 + 1, "An unknown-length licensing response exceeded its bounded read.");
            AssertErased(stream);
        }
        foreach (var contentType in new[] { null, "text/html", "text/plain" })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(PublicJson));
            using var context = new Context((_, _) => { var response = Json(stream); response.Content.Headers.ContentType = contentType is null ? null : new(contentType); return Task.FromResult(response); });
            await context.SignInAsync();
            Ensure((await Request(context, false)).Outcome == LicenseRequestOutcome.InvalidResponse && stream.BytesRead == 0 && stream.Disposed,
                "Licensing read or accepted a non-JSON response.");
        }
        using var oversized = new CapturedStream(Encoding.UTF8.GetBytes(PublicJson));
        using var declared = new Context((_, _) => { var response = Json(oversized); response.Content.Headers.ContentLength = 16 * 1024 + 1; return Task.FromResult(response); });
        await declared.SignInAsync();
        Ensure((await Request(declared, false)).Outcome == LicenseRequestOutcome.TooLarge && oversized.BytesRead == 0 && oversized.Disposed,
            "A declared oversized response was read before rejection.");
    }

    private static async Task ErrorAndTrustAsync()
    {
        foreach (var renew in new[] { false, true })
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests, HttpStatusCode.BadRequest,
                     HttpStatusCode.Forbidden, HttpStatusCode.RequestEntityTooLarge, HttpStatusCode.ServiceUnavailable,
                     HttpStatusCode.NotFound, HttpStatusCode.Found, HttpStatusCode.NoContent, HttpStatusCode.InternalServerError })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(PrivateError));
            using var context = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StreamContent(stream) }));
            await context.SignInAsync();
            var token = StoredToken(context.Client);
            var result = await Request(context, renew);
            var expected = status == HttpStatusCode.Unauthorized ? LicenseRequestOutcome.Unauthenticated :
                status == HttpStatusCode.TooManyRequests ? LicenseRequestOutcome.Throttled :
                renew && status is not (HttpStatusCode.BadRequest or HttpStatusCode.Forbidden or HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.ServiceUnavailable)
                    ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable;
            Ensure(result.Outcome == expected && result.Status is null && stream.BytesRead == 0 && stream.Disposed &&
                   !result.ToString().Contains(PrivateError, StringComparison.Ordinal), "A licensing failure read private error material or claimed an unproven renewal result.");
            Ensure(context.Handler.Requests.Last().Headers.Authorization is null &&
                   (status == HttpStatusCode.Unauthorized ? token.All(value => value == 0) : token.Any(value => value != 0)),
                "A licensing failure retained a borrowed bearer or invalidated the wrong session.");
        }
        foreach (var renew in new[] { false, true })
        {
            using var failed = new Context((_, _) => throw new HttpRequestException(PrivateError));
            await failed.SignInAsync();
            Ensure((await Request(failed, renew)).Outcome == (renew ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable) && failed.Handler.Requests.Last().Headers.Authorization is null,
                "A lost renewal response was retried, exposed exception details or treated as definite failure.");
            using var context = new Context((_, _) => Task.FromResult(Json(PublicJson)));
            await context.SignInAsync();
            var calls = context.Handler.Requests.Count;
            var token = StoredToken(context.Client);
            context.Trust.Allowed = false;
            Ensure((await Request(context, renew)).Outcome == LicenseRequestOutcome.UntrustedConnection && context.Handler.Requests.Count == calls && token.All(value => value == 0),
                "An untrusted licensing origin received credentials or retained its session.");
        }
        using var handler = new HttpClientHandler { AllowAutoRedirect = true, UseProxy = true, UseCookies = true, UseDefaultCredentials = true };
        using var client = new HttpAuthenticationClient(new Trust(), handler);
        Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies && !handler.UseDefaultCredentials && handler.Credentials is null,
            "Licensing composition allows redirects or ambient authentication.");
    }

    private static async Task SessionIsolationAsync()
    {
        foreach (var renew in new[] { false, true })
        {
            var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var context = new Context((_, _) => response.Task);
            Ensure((await Request(context, renew)).Outcome == LicenseRequestOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
                "A signed-out licensing request reached the network.");
            await context.SignInAsync();
            var oldToken = StoredToken(context.Client);
            var old = Request(context, renew);
            context.Client.SignOut();
            await context.SignInAsync();
            var newToken = StoredToken(context.Client);
            response.SetResult(new(HttpStatusCode.Unauthorized));
            Ensure((await old).Outcome == LicenseRequestOutcome.Unauthenticated && oldToken.All(value => value == 0) && newToken.Any(value => value != 0) &&
                   (await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated,
                "A stale licensing401 erased the replacement session.");
            context.Clock.Advance(TimeSpan.FromMinutes(15));
            var calls = context.Handler.Requests.Count;
            Ensure((await Request(context, renew)).Outcome == LicenseRequestOutcome.Unauthenticated && context.Handler.Requests.Count == calls && newToken.All(value => value == 0),
                "An expired licensing session sent or retained its bearer.");
        }
    }

    private static async Task CancellationAsync()
    {
        foreach (var renew in new[] { false, true })
        {
            using var context = new Context((_, _) => Task.FromResult(Json(PublicJson)));
            await context.SignInAsync();
            using var early = new CancellationTokenSource(); early.Cancel();
            var calls = context.Handler.Requests.Count;
            await Cancelled(Request(context, renew, early.Token), early.Token);
            Ensure(context.Handler.Requests.Count == calls, "An already-cancelled licensing request reached the network.");
            using var cancellation = new CancellationTokenSource();
            using var pendingContext = new Context(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json(PublicJson); });
            await pendingContext.SignInAsync();
            var pending = Request(pendingContext, renew, cancellation.Token);
            cancellation.Cancel();
            await Cancelled(pending, cancellation.Token);
            Ensure(pendingContext.Handler.Requests.Last().Headers.Authorization is null, "Caller cancellation retained a licensing bearer.");
            using var bodyCancellation = new CancellationTokenSource();
            using var stream = new StalledStream();
            using var body = new Context((_, _) => Task.FromResult(Json(stream)));
            await body.SignInAsync();
            var read = Request(body, renew, bodyCancellation.Token);
            await stream.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            bodyCancellation.Cancel();
            await Cancelled(read, bodyCancellation.Token);
            AssertErased(stream);
        }
    }

    private static async Task DeadlineAsync(bool renew)
    {
        using var stream = new StalledStream();
        using var context = new Context(async (_, token) => { await Task.Delay(TimeSpan.FromSeconds(renew ? 5 : 3), token); return Json(stream); });
        await context.SignInAsync();
        var watch = Stopwatch.StartNew();
        var result = await Request(context, renew).WaitAsync(TimeSpan.FromSeconds(renew ? 72 : 15));
        Ensure(result.Outcome == (renew ? LicenseRequestOutcome.Indeterminate : LicenseRequestOutcome.Unavailable) &&
               watch.Elapsed >= TimeSpan.FromSeconds(renew ? 63 : 8) && watch.Elapsed < TimeSpan.FromSeconds(renew ? 69 : 12),
            "Licensing headers and complete body did not share the10-second read/65-second renewal deadline.");
        AssertErased(stream);
        Ensure(context.Handler.Requests.Last().Headers.Authorization is null, "A licensing deadline retained a bearer.");
    }

    private static Task<LicenseRequestResult> Request(Context context, bool renew, CancellationToken cancellation = default) =>
        renew ? context.Client.RenewLicenseAsync(cancellation) : context.Client.GetLicenseAsync(cancellation);
    private static JsonNode Body() => JsonNode.Parse(PublicJson)!;
    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static HttpResponseMessage Json(Stream stream) { var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }; response.Content.Headers.ContentType = new("application/json"); return response; }
    private static byte[] StoredToken(HttpAuthenticationClient client) => (byte[])typeof(HttpAuthenticationClient).GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;
    private static void AssertErased(CapturedStream stream) => Ensure(stream.Disposed && stream.Destination is not null && stream.Destination.All(value => value == 0), "Owned license response bytes were retained after completion.");
    private static async Task Cancelled(Task<LicenseRequestResult> task, CancellationToken token)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (OperationCanceledException exception) { Ensure(exception.CancellationToken == token, "Licensing cancellation lost its caller token."); return; }
        throw new InvalidOperationException("Licensing ignored caller cancellation.");
    }
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }
    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler, timeProvider: Clock); }
        internal Trust Trust { get; } = new();
        internal Clock Clock { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-license-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic licensing login failed.");
        public void Dispose() => Client.Dispose();
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer, Trust trust) : HttpMessageHandler
    {
        internal List<HttpRequestMessage> Requests { get; } = [];
        internal string? Bearer;
        internal bool WasTrusted;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}"));
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
            Bearer = request.Headers.Authorization?.ToString(); WasTrusted = trust.Allowed && trust.Calls >= 3;
            return answer(request, cancellationToken);
        }
    }
    private sealed class Trust : ICoreEndpointTrust
    {
        internal bool Allowed = true;
        internal int Calls;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private class CapturedStream(byte[] bytes, int chunkSize = int.MaxValue) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead;
        internal bool Disposed;
        internal byte[]? Destination;
        protected void Capture(Memory<byte> buffer) { if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) Destination = segment.Array; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer); var count = await base.ReadAsync(buffer[..Math.Min(buffer.Length, chunkSize)], cancellationToken); BytesRead += count; return count;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class StalledStream() : CapturedStream([])
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer); buffer.Span[0] = (byte)'x'; Entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0;
        }
    }
}
