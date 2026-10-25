using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

// MVP-3: Settings → License shows the pilot; the shell shows the warning and ended notices with an uninstall action.
internal static class PilotLicenseTests
{
    private const string Token = "synthetic-pilot-bearer";
    private const string Key = "eyJhbGciOiJFUzI1NiJ9.eyJwbGFuIjoicGlsb3QifQ.c3ludGhldGlj";
    private static readonly DateTimeOffset Now = new(2026, 1, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly PilotContactDetails Contact = new("Example Company", "pilot@example.invalid", "+00 000 000 000", "https://example.invalid");
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await ClosedSchemaAsync();
        await OutcomesAsync();
        await ViewModelAsync();
        await NoticesAsync();
        Console.WriteLine($"Desktop pilot license: {_assertions} assertions passed.");
        return _assertions;
    }

    private static JsonObject Body(string state = "ending", int? daysLeft = 5, bool contact = true) => new()
    {
        ["state"] = state,
        ["customer"] = state is "scheduled" or "active" or "ending" or "ended" ? "Zażółć Example" : null,
        ["startsUtc"] = state is "scheduled" or "active" or "ending" or "ended" ? "2026-01-01T00:00:00Z" : null,
        ["expiresUtc"] = state is "scheduled" or "active" or "ending" or "ended" ? "2026-01-15T00:00:00Z" : null,
        ["daysLeft"] = daysLeft,
        ["effectiveUtc"] = "2026-01-10T12:00:00Z",
        ["contact"] = contact ? new JsonObject { ["company"] = Contact.Company, ["email"] = Contact.Email, ["phone"] = Contact.Phone, ["website"] = Contact.Website } : null
    };

    private static async Task TransportAsync()
    {
        using var context = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        await context.SignInAsync();
        var result = await context.Client.GetPilotLicenseAsync(default);
        Ensure(result.Outcome == PilotLicenseOutcome.Success && result.Info is { State: "ending", Customer: "Zażółć Example", DaysLeft: 5 } info &&
               info.ExpiresUtc == new DateTimeOffset(2026, 1, 15, 0, 0, 0, TimeSpan.Zero) && info.Contact == Contact,
            "Desktop changed Core's pilot license projection.");
        var request = context.Handler.Requests.Last();
        Ensure(request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/license/pilot" && request.Method == HttpMethod.Get &&
               request.Content is null && context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted && request.Headers.Authorization is null,
            "The pilot license was not read from the trusted loopback Core with the private bearer.");

        var posted = await context.Client.SetPilotLicenseKeyAsync("  " + Key + "\r\n", default);
        Ensure(posted.Outcome == PilotLicenseOutcome.Success && context.Handler.LastBody == "{\"key\":\"" + Key + "\"}" &&
               context.Handler.Requests.Last().Method == HttpMethod.Post, "Desktop did not send exactly the trimmed pilot key.");

        foreach (var invalid in new[] { "", "   ", "not a key", "a.b", "a.b.c.d", "a.b.c<", new string('a', 1021) + ".b.c", "ä.b.c" })
        {
            var count = context.Handler.Requests.Count;
            Ensure((await context.Client.SetPilotLicenseKeyAsync(invalid, default)).Outcome == PilotLicenseOutcome.Rejected &&
                   context.Handler.Requests.Count == count, "Desktop sent text that cannot be a pilot key.");
        }
        foreach (var state in new[] { "unavailable", "none", "invalid" })
        {
            using var other = new Context((_, _) => Task.FromResult(Json(Body(state, null, contact: state != "unavailable").ToJsonString())));
            await other.SignInAsync();
            Ensure((await other.Client.GetPilotLicenseAsync(default)).Info is { Customer: null, ExpiresUtc: null, DaysLeft: null } parsed && parsed.State == state,
                "Desktop rejected a pilot state without a key.");
        }
        using var scheduled = new Context((_, _) => Task.FromResult(Json(Body("scheduled", null).ToJsonString())));
        await scheduled.SignInAsync();
        Ensure((await scheduled.Client.GetPilotLicenseAsync(default)).Info is { State: "scheduled", DaysLeft: null }, "Desktop rejected a scheduled pilot.");
    }

    private static async Task ClosedSchemaAsync()
    {
        var invalid = new List<string> { "", "null", "[]", "{}", "{", Body().ToJsonString() + "{}" };
        foreach (var property in Body().ToList())
        {
            var missing = Body(); missing.Remove(property.Key); invalid.Add(missing.ToJsonString());
            var renamed = Body(); renamed[property.Key.ToUpperInvariant()] = renamed[property.Key]?.DeepClone(); renamed.Remove(property.Key); invalid.Add(renamed.ToJsonString());
        }
        foreach (var (key, value) in new (string, JsonNode?)[]
                 {
                     ("state", "unknown"), ("state", "Active"), ("state", null), ("customer", ""), ("customer", " padded"), ("customer", "a\nb"),
                     ("customer", new string('x', 65)), ("customer", 1), ("expiresUtc", "2026-01-15T00:00:00+01:00"), ("expiresUtc", "2026-01-15"),
                     ("startsUtc", "2026-02-01T00:00:00Z"), ("daysLeft", -1), ("daysLeft", 367), ("daysLeft", 8), ("daysLeft", 0), ("daysLeft", "5"),
                     ("daysLeft", 5.5), ("effectiveUtc", null), ("contact", "Example"), ("contact", new JsonObject { ["company"] = "Example" }),
                     ("key", Key), ("privateKey", "synthetic-private-key")
                 })
        {
            var body = Body(); body[key] = value?.DeepClone(); invalid.Add(body.ToJsonString());
        }
        foreach (var (field, value) in new (string, JsonNode?)[] { ("company", ""), ("email", null), ("phone", "a\u0007"), ("website", new string('w', 129)), ("extra", "x") })
        {
            var body = Body(); body["contact"]![field] = value?.DeepClone(); invalid.Add(body.ToJsonString());
        }
        // Details exactly for a trusted key, days left exactly once it has started, zero exactly when ended.
        invalid.Add(Body("none", null).Also(body => body["customer"] = "Example").ToJsonString());
        invalid.Add(Body("active", null).ToJsonString());
        invalid.Add(Body("scheduled", 3).ToJsonString());
        invalid.Add(Body("ended", 2).ToJsonString());
        invalid.Add(Body("invalid", 0).ToJsonString());
        foreach (var body in invalid)
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetPilotLicenseAsync(default)).Outcome == PilotLicenseOutcome.InvalidResponse,
                "Desktop accepted an ambiguous, inconsistent or extended pilot projection: " + body);
        }
        using var large = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString().PadRight(4 * 1024 + 1))));
        await large.SignInAsync();
        Ensure((await large.Client.GetPilotLicenseAsync(default)).Outcome == PilotLicenseOutcome.TooLarge, "Desktop accepted an unbounded pilot projection.");
        using var html = new Context((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body().ToJsonString(), Encoding.UTF8, "text/html") }));
        await html.SignInAsync();
        Ensure((await html.Client.GetPilotLicenseAsync(default)).Outcome == PilotLicenseOutcome.InvalidResponse, "A non-JSON pilot projection was accepted.");
    }

    private static async Task OutcomesAsync()
    {
        foreach (var (status, read, write) in new[]
                 {
                     (HttpStatusCode.BadRequest, PilotLicenseOutcome.Unavailable, PilotLicenseOutcome.Rejected),
                     (HttpStatusCode.NotFound, PilotLicenseOutcome.Unavailable, PilotLicenseOutcome.NotConfigured),
                     (HttpStatusCode.Conflict, PilotLicenseOutcome.Unavailable, PilotLicenseOutcome.Expired),
                     (HttpStatusCode.TooManyRequests, PilotLicenseOutcome.Unavailable, PilotLicenseOutcome.Unavailable),
                     (HttpStatusCode.InternalServerError, PilotLicenseOutcome.Unavailable, PilotLicenseOutcome.Unavailable),
                     (HttpStatusCode.Unauthorized, PilotLicenseOutcome.Unauthenticated, PilotLicenseOutcome.Unauthenticated)
                 })
        {
            using var getContext = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("synthetic-private-error") }));
            await getContext.SignInAsync();
            Ensure((await getContext.Client.GetPilotLicenseAsync(default)) is { Info: null } got && got.Outcome == read, "A failed pilot read was misclassified: " + status);
            using var postContext = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("synthetic-private-error") }));
            await postContext.SignInAsync();
            Ensure((await postContext.Client.SetPilotLicenseKeyAsync(Key, default)) is { Info: null } set && set.Outcome == write, "A refused pilot key was misclassified: " + status);
        }
        using var untrusted = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        await untrusted.SignInAsync();
        untrusted.Trust.Allowed = false;
        Ensure((await untrusted.Client.SetPilotLicenseKeyAsync(Key, default)).Outcome == PilotLicenseOutcome.UntrustedConnection &&
               untrusted.Handler.Requests.All(request => request.RequestUri!.AbsolutePath != "/api/admin/license/pilot"),
            "Desktop sent a pilot key to an untrusted local Core endpoint.");
        using var signedOut = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        Ensure((await signedOut.Client.GetPilotLicenseAsync(default)).Outcome == PilotLicenseOutcome.Unauthenticated && signedOut.Handler.Requests.Count == 0,
            "Desktop read the pilot license without a session.");
    }

    private static async Task ViewModelAsync()
    {
        var client = new FakeClient(new(PilotLicenseOutcome.Success, Info("active", 30)));
        var launcher = new FakeLauncher();
        using var model = new PilotLicenseViewModel(client, launcher);
        Ensure(model.State == PilotLicenseState.NotLoaded && model.StatusText == "Not loaded" && !model.IsNoticeVisible && !model.CanSubmit,
            "Settings showed a pilot before reading Core.");
        await model.RefreshAsync();
        Ensure(model.State == PilotLicenseState.Ready && model.CustomerText == "Zażółć Example" && model.ExpiresText == "2026-01-15 00:00 UTC" &&
               model.DaysLeftText == "30" && model.StatusText == "The pilot for Zażółć Example is active." && !model.IsNoticeVisible && !model.CanUninstall,
            "Settings did not show customer, expiry and days left for an active pilot.");

        model.KeyText = "  ";
        Ensure(!model.CanSubmit, "A blank key could be submitted.");
        model.KeyText = Key;
        client.Next = new(PilotLicenseOutcome.Rejected);
        await model.SubmitAsync();
        Ensure(client.Keys.Last() == Key && model.Info?.State == "active" && model.KeyText == Key && model.SubmitStatusText.Contains("not a valid", StringComparison.Ordinal),
            "A refused key changed the shown pilot or lost what was typed.");
        client.Next = new(PilotLicenseOutcome.Expired);
        await model.SubmitAsync();
        Ensure(model.SubmitStatusText.Contains("already expired", StringComparison.Ordinal) && model.Info?.State == "active", "An expired key was not explained.");
        client.Next = new(PilotLicenseOutcome.NotConfigured);
        await model.SubmitAsync();
        Ensure(model.SubmitStatusText.Contains("does not accept", StringComparison.Ordinal), "A build without pilot keys was not explained.");
        client.Next = new(PilotLicenseOutcome.Success, Info("active", 90));
        await model.SubmitAsync();
        Ensure(model.KeyText.Length == 0 && model.DaysLeftText == "90" && model.SubmitStatusText.StartsWith("Pilot license key accepted.", StringComparison.Ordinal),
            "An extension key did not replace the shown pilot.");
        model.KeyText = Key;
        client.Next = new(PilotLicenseOutcome.Unavailable);
        await model.SubmitAsync();
        Ensure(model.State == PilotLicenseState.Unavailable && model.Info is null && model.SubmitStatusText.Contains("unknown", StringComparison.Ordinal) &&
               model.ErrorText.Contains("unavailable", StringComparison.Ordinal), "An unknown submission result kept a stale pilot.");
        foreach (var (outcome, text) in new[]
                 {
                     (PilotLicenseOutcome.InvalidResponse, "invalid pilot license response"), (PilotLicenseOutcome.TooLarge, "invalid pilot license response"),
                     (PilotLicenseOutcome.UntrustedConnection, "could not be trusted"), (PilotLicenseOutcome.Unavailable, "Local Core is unavailable")
                 })
        {
            client.Next = new(outcome);
            await model.RefreshAsync();
            Ensure(model.State == PilotLicenseState.Unavailable && model.Info is null && model.ErrorText.Contains(text, StringComparison.Ordinal) &&
                   model.CustomerText == "Not applicable", "A failed pilot read left stale values or an unclear error.");
        }
        foreach (var (state, text) in new[]
                 {
                     ("unavailable", "does not use pilot license keys"), ("none", "No pilot license key"), ("invalid", "not valid"),
                     ("scheduled", "starts on 2026-01-01 00:00 UTC")
                 })
        {
            client.Next = new(PilotLicenseOutcome.Success, Info(state, null));
            await model.RefreshAsync();
            Ensure(model.StatusText.Contains(text, StringComparison.Ordinal) && !model.IsNoticeVisible && (state != "unavailable" || !model.CanSubmit),
                "Pilot state " + state + " was shown incorrectly.");
        }

        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        client.Next = new(PilotLicenseOutcome.Unauthenticated);
        await model.RefreshAsync();
        Ensure(expired == 1 && model.State == PilotLicenseState.NotLoaded, "An expired session did not end the Desktop session.");

        var pending = new FakeClient(null);
        using var slow = new PilotLicenseViewModel(pending, launcher);
        var refresh = slow.RefreshAsync();
        Ensure(!slow.CanRefresh && ReferenceEquals(refresh, slow.RefreshAsync()) && pending.Calls == 1, "Concurrent refreshes created duplicate reads.");
        slow.Clear();
        pending.Complete(new(PilotLicenseOutcome.Success, Info("ended", 0)));
        await refresh.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(slow.Info is null && !slow.IsNoticeVisible && slow.CanRefresh, "A response from before sign-out restored the pilot notice.");
    }

    private static async Task NoticesAsync()
    {
        var client = new FakeClient(new(PilotLicenseOutcome.Success, Info("ending", 5)));
        var launcher = new FakeLauncher();
        using var model = new PilotLicenseViewModel(client, launcher);
        await model.RefreshAsync();
        Ensure(model.IsNoticeVisible && model.NoticeTitle == "Pilot ends in 5 days — contact us" && model.StatusText == model.NoticeTitle &&
               !model.IsEnded && !model.CanUninstall && model.NoticeText.Contains("Monitoring continues", StringComparison.Ordinal),
            "The warning did not say how many days are left.");
        Ensure(model.ContactText == string.Join(Environment.NewLine, "Example Company", "E-mail: pilot@example.invalid", "Phone: +00 000 000 000", "Website: https://example.invalid"),
            "The warning did not show the build-time contact details.");
        client.Next = new(PilotLicenseOutcome.Success, Info("ending", 1));
        await model.RefreshAsync();
        Ensure(model.NoticeTitle == "Pilot ends in 1 day — contact us", "The last day was not worded in the singular.");
        model.HideNotice();
        Ensure(!model.IsNoticeVisible, "The warning could not be hidden.");
        await model.RefreshAsync();
        Ensure(!model.IsNoticeVisible, "A hidden warning came back on the next read in the same session.");

        client.Next = new(PilotLicenseOutcome.Success, Info("ended", 0));
        await model.RefreshAsync();
        Ensure(model.IsNoticeVisible && model.IsEnded && model.CanUninstall && model.NoticeTitle == "Your SentinelAI pilot has ended" &&
               model.NoticeText.Contains("All monitoring continues", StringComparison.Ordinal) && model.NoticeText.Contains("Uninstall SentinelAI", StringComparison.Ordinal),
            "The ended notice did not replace a hidden warning, or lacked the uninstall action.");
        Ensure(launcher.Calls == 0, "The uninstall flow started without the administrator asking.");
        model.StartUninstall();
        Ensure(launcher.Calls == 1 && model.UninstallStatusText.Contains("kept unless you type DELETE", StringComparison.Ordinal),
            "Uninstall SentinelAI did not open the existing Setup uninstall flow.");
        launcher.Next = UninstallLaunchOutcome.Cancelled;
        model.StartUninstall();
        Ensure(model.UninstallStatusText == "Uninstall was not started.", "A cancelled elevation prompt was misreported.");
        launcher.Throw = true;
        model.StartUninstall();
        Ensure(model.UninstallStatusText.Contains("Windows Settings", StringComparison.Ordinal), "A missing Setup did not point to Windows Settings.");
        model.HideNotice();
        await model.RefreshAsync();
        Ensure(!model.IsNoticeVisible && model.StatusText.Contains("has ended", StringComparison.Ordinal),
            "Hiding the ended notice for the session did not hold, or hid the state in Settings.");
        model.Clear();
        client.Next = new(PilotLicenseOutcome.Success, Info("ended", 0, contact: false));
        await model.RefreshAsync();
        Ensure(model.IsNoticeVisible && model.ContactText == "Contact your SentinelAI provider.", "A hidden notice outlived sign-out, or missing contact details were invented.");

        using var noLauncher = new PilotLicenseViewModel(client, null);
        await noLauncher.RefreshAsync();
        noLauncher.StartUninstall();
        Ensure(noLauncher.IsNoticeVisible && !noLauncher.CanUninstall && noLauncher.UninstallStatusText.Length == 0, "Uninstall was offered without a launcher.");
    }

    private static PilotLicenseInfo Info(string state, int? daysLeft, bool contact = true)
    {
        var trusted = state is "scheduled" or "active" or "ending" or "ended";
        return new(state, trusted ? "Zażółć Example" : null, trusted ? new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero) : null,
            trusted ? new DateTimeOffset(2026, 1, 15, 0, 0, 0, TimeSpan.Zero) : null, daysLeft, Now, contact ? Contact : null);
    }

    private static JsonObject Also(this JsonObject value, Action<JsonObject> change) { change(value); return value; }
    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class FakeClient(PilotLicenseResult? result) : IPilotLicenseClient
    {
        private TaskCompletionSource<PilotLicenseResult>? _pending;
        internal PilotLicenseResult? Next = result;
        internal int Calls;
        internal List<string> Keys { get; } = [];
        public Task<PilotLicenseResult> GetPilotLicenseAsync(CancellationToken cancellationToken) => Answer();
        public Task<PilotLicenseResult> SetPilotLicenseKeyAsync(string key, CancellationToken cancellationToken) { Keys.Add(key); return Answer(); }
        private Task<PilotLicenseResult> Answer()
        {
            Calls++;
            if (Next is not null) return Task.FromResult(Next);
            _pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
            return _pending.Task;
        }
        internal void Complete(PilotLicenseResult value) => _pending!.TrySetResult(value);
    }

    private sealed class FakeLauncher : ISetupUninstallLauncher
    {
        internal int Calls;
        internal UninstallLaunchOutcome Next = UninstallLaunchOutcome.Started;
        internal bool Throw;
        public UninstallLaunchOutcome Start()
        {
            Calls++;
            return Throw ? throw new InvalidOperationException("synthetic") : Next;
        }
    }

    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler); }
        internal Trust Trust { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-pilot-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login failed.");
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
            Bearer = request.Headers.Authorization?.ToString(); WasTrusted = trust.Allowed && trust.Calls >= 3;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return await answer(request, cancellationToken);
        }
    }

    private sealed class Trust : ICoreEndpointTrust
    {
        internal bool Allowed = true;
        internal int Calls;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
}
