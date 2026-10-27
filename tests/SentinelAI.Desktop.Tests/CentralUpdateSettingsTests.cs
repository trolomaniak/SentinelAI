using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

// MVP-7: Settings → Updates shows Core's update settings and state; Install now opens the verified Setup and closes Desktop.
internal static class CentralUpdateSettingsTests
{
    private const string Token = "synthetic-update-bearer";
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await ClosedSchemaAsync();
        await ViewModelAsync();
        Console.WriteLine($"Desktop central update: {_assertions} assertions passed.");
        return _assertions;
    }

    private static JsonObject Body(bool configured = true, bool checkEnabled = true, string? ready = "1.1.0", int attempts = 0) => new()
    {
        ["configured"] = configured,
        ["server"] = configured ? "updates.example.invalid" : null,
        ["checkEnabled"] = checkEnabled,
        ["autoInstall"] = true,
        ["installedVersion"] = "1.0.0",
        ["lastCheck"] = ready is null ? "current" : "ready",
        ["lastCheckUtc"] = "2026-10-27T01:00:00+00:00",
        ["readyVersion"] = ready,
        ["installAttempts"] = attempts,
        ["lastAttemptUtc"] = attempts == 0 ? null : "2026-10-27T02:30:00Z"
    };

    private static async Task TransportAsync()
    {
        using var context = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        await context.SignInAsync();
        var result = await context.Client.GetCentralUpdateAsync(default);
        Ensure(result.Outcome == CentralUpdateRequestOutcome.Success && result.Info is
               { Configured: true, Server: "updates.example.invalid", CheckEnabled: true, AutoInstall: true, InstalledVersion: "1.0.0", LastCheck: "ready", ReadyVersion: "1.1.0" } info &&
               info.LastCheckUtc == new DateTimeOffset(2026, 10, 27, 1, 0, 0, TimeSpan.Zero), "Desktop changed Core's update projection.");
        var request = context.Handler.Requests.Last();
        Ensure(request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/updates" && request.Method == HttpMethod.Get &&
               context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted && request.Headers.Authorization is null,
            "The update status was not read from the trusted loopback Core with the private bearer.");

        await context.Client.SetCentralUpdateSettingsAsync(true, false, default);
        Ensure(context.Handler.Requests.Last().RequestUri!.AbsolutePath == "/api/admin/updates/settings" &&
               context.Handler.LastBody == "{\"checkEnabled\":true,\"autoInstall\":false}", "Desktop did not send exactly the two update settings.");
        await context.Client.CheckCentralUpdateAsync(default);
        Ensure(context.Handler.Requests.Last().RequestUri!.AbsolutePath == "/api/admin/updates/check" && context.Handler.LastBody is null,
            "Desktop did not request a check without a body.");

        foreach (var (status, expected) in new[]
                 {
                     (HttpStatusCode.NotFound, CentralUpdateRequestOutcome.NotConfigured),
                     (HttpStatusCode.Conflict, CentralUpdateRequestOutcome.NotEnabled),
                     (HttpStatusCode.InternalServerError, CentralUpdateRequestOutcome.Unavailable)
                 })
        {
            using var refused = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status)));
            await refused.SignInAsync();
            Ensure((await refused.Client.CheckCentralUpdateAsync(default)).Outcome == expected, $"Desktop misread Core's {(int)status} answer.");
        }
        using var untrusted = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        await untrusted.SignInAsync();
        untrusted.Trust.Allowed = false;
        Ensure((await untrusted.Client.SetCentralUpdateSettingsAsync(true, true, default)).Outcome == CentralUpdateRequestOutcome.UntrustedConnection &&
               untrusted.Handler.Requests.All(sent => !sent.RequestUri!.AbsolutePath.StartsWith("/api/admin/updates", StringComparison.Ordinal)),
            "Desktop sent update settings to an untrusted local Core endpoint.");
    }

    private static async Task ClosedSchemaAsync()
    {
        var invalid = new List<string> { "", "null", "[]", "{}" };
        foreach (var property in Body().ToList())
        {
            var missing = Body(); missing.Remove(property.Key); invalid.Add(missing.ToJsonString());
        }
        var extra = Body(); extra["url"] = "https://elsewhere.example.invalid"; invalid.Add(extra.ToJsonString());
        foreach (var (name, value) in new (string, JsonNode?)[]
                 {
                     ("lastCheck", "unknown"), ("installedVersion", "1.0"), ("installedVersion", "01.0.0"), ("readyVersion", "latest"),
                     ("installAttempts", -1), ("server", "Updates.Example"), ("server", "evil.example/path"), ("lastCheckUtc", "2026-10-27T01:00:00+02:00"),
                     ("checkEnabled", "true")
                 })
        {
            var changed = Body(); changed[name] = value; invalid.Add(changed.ToJsonString());
        }
        var unconfigured = Body(configured: false); invalid.Add(unconfigured.ToJsonString());
        foreach (var body in invalid)
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetCentralUpdateAsync(default)).Outcome == CentralUpdateRequestOutcome.InvalidResponse,
                "Desktop accepted an ambiguous or extended update projection: " + body);
        }
        using var plain = new Context((_, _) => Task.FromResult(Json(Body(configured: false, checkEnabled: false, ready: null).ToJsonString())));
        await plain.SignInAsync();
        Ensure((await plain.Client.GetCentralUpdateAsync(default)).Info is { Configured: false, Server: null }, "Desktop rejected a build without an update server.");
    }

    private static async Task ViewModelAsync()
    {
        var client = new FakeClient { Next = Info(checkEnabled: false, ready: null) };
        var installer = new FakeInstaller();
        using var model = new CentralUpdateViewModel(client, installer);
        Ensure(model.StatusText == "Not loaded" && !model.CanChangeSettings && !model.CanInstall, "Settings showed updates before reading Core.");
        await model.RefreshAsync();
        Ensure(!model.CheckEnabled && model.CanChangeSettings && !model.CanChangeAutoInstall && !model.CanCheckNow &&
               model.StatusText.StartsWith("Off. SentinelAI connects to no update server.", StringComparison.Ordinal),
            "Checking was not shown as off with no internet connection.");

        client.Next = Info(checkEnabled: true, ready: null);
        model.CheckEnabled = true;
        Ensure(client.Saved == (true, true) && model.CheckEnabled && model.CanCheckNow, "Turning on checking did not keep night-time installation on.");
        client.Next = Info(checkEnabled: true, ready: null, autoInstall: false);
        model.AutoInstall = false;
        Ensure(client.Saved == (true, false) && !model.AutoInstall, "Night-time installation could not be turned off.");

        client.Next = Info(checkEnabled: true, ready: "1.1.0", autoInstall: true);
        await model.CheckNowAsync();
        Ensure(client.Checks == 1 && model.CanInstall && model.StatusText.Contains("installs tonight between 02:00 and 04:00", StringComparison.Ordinal),
            "A downloaded update was not shown with its night-time installation.");
        client.Next = Info(checkEnabled: true, ready: "1.1.0", autoInstall: true, attempts: 3);
        await model.RefreshAsync();
        Ensure(model.StatusText.Contains("did not install after 3 nights", StringComparison.Ordinal), "Repeated failed installations were not shown.");

        var exits = 0;
        model.ExitRequested += (_, _) => exits++;
        installer.Next = CentralUpdateInstallOutcome.Rejected;
        await model.InstallAsync();
        Ensure(exits == 0 && model.InstallStatusText.Contains("did not pass verification", StringComparison.Ordinal), "A rejected update closed Desktop.");
        installer.Next = CentralUpdateInstallOutcome.Started;
        await model.InstallAsync();
        Ensure(exits == 1 && installer.Calls == 2 && model.InstallStatusText.StartsWith("SentinelAI Setup opened", StringComparison.Ordinal),
            "Install now did not close Desktop once the verified Setup started.");

        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        client.Result = new(CentralUpdateRequestOutcome.Unauthenticated);
        await model.RefreshAsync();
        Ensure(expired == 1 && model.Info is null && !model.CanInstall, "An expired session kept update controls.");
    }

    private static CentralUpdateInfo Info(bool checkEnabled, string? ready, bool autoInstall = true, int attempts = 0) =>
        new(true, "updates.example.invalid", checkEnabled, autoInstall, "1.0.0", ready is null ? "current" : "ready", null, ready, attempts, null);

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class FakeClient : ICentralUpdateClient
    {
        internal CentralUpdateInfo? Next;
        internal CentralUpdateRequestResult? Result;
        internal (bool, bool)? Saved;
        internal int Checks;

        // Completed answers: each settings change finishes before its setter returns.
        private Task<CentralUpdateRequestResult> Answer() =>
            Task.FromResult(Result ?? new CentralUpdateRequestResult(CentralUpdateRequestOutcome.Success, Next));

        public Task<CentralUpdateRequestResult> GetCentralUpdateAsync(CancellationToken cancellationToken) => Answer();
        public Task<CentralUpdateRequestResult> SetCentralUpdateSettingsAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken)
        {
            Saved = (checkEnabled, autoInstall);
            return Answer();
        }
        public Task<CentralUpdateRequestResult> CheckCentralUpdateAsync(CancellationToken cancellationToken)
        {
            Checks++;
            return Answer();
        }
    }

    private sealed class FakeInstaller : ICentralUpdateInstaller
    {
        internal CentralUpdateInstallOutcome Next = CentralUpdateInstallOutcome.Started;
        internal int Calls;
        public Task<CentralUpdateInstallOutcome> StartAsync(CancellationToken cancellationToken) { Calls++; return Task.FromResult(Next); }
    }

    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler); }
        internal Trust Trust { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-update-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login failed.");
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
