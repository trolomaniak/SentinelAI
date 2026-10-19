using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SentinelAI.Desktop.Foundation;

// MVP-1: Settings shows Core's local-network addresses, port and certificate fingerprint.
internal static class LocalNetworkSettingsTests
{
    private const string Token = "synthetic-local-network-bearer";
    private static readonly string Pin = new('A', 64);
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        await TransportAsync();
        await ClosedSchemaAsync();
        await FailuresAsync();
        await ViewModelAsync();
        Console.WriteLine($"Desktop local-network settings: {_assertions} assertions passed.");
        return _assertions;
    }

    private static JsonObject Body(bool enabled = true, bool listening = true) => new()
    {
        ["enabled"] = enabled, ["listening"] = listening, ["port"] = enabled ? 5443 : null,
        ["certificateSha256"] = enabled ? Pin : null, ["hostName"] = "SYNTHETIC-CORE",
        ["fullyQualifiedName"] = "SYNTHETIC-CORE.corp.example",
        ["addresses"] = enabled ? new JsonArray("10.0.0.5", "192.168.1.20") : new JsonArray()
    };

    private static async Task TransportAsync()
    {
        using var context = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString())));
        await context.SignInAsync();
        var result = await context.Client.GetLocalNetworkAsync(default);
        Ensure(result.Outcome == LocalNetworkRequestOutcome.Success && result.Status is { Enabled: true, Listening: true, Port: 5443 } status &&
               status.CertificateSha256 == Pin && status.HostName == "SYNTHETIC-CORE" && status.FullyQualifiedName == "SYNTHETIC-CORE.corp.example" &&
               status.Addresses.SequenceEqual(["10.0.0.5", "192.168.1.20"]) && ((ICollection<string>)status.Addresses).IsReadOnly,
            "Desktop changed Core's local-network addresses, port or fingerprint.");
        var request = context.Handler.Requests.Last();
        Ensure(request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/local-network" && request.Method == HttpMethod.Get &&
               request.Content is null && request.Headers.Accept.Single().MediaType == "application/json" &&
               context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted && request.Headers.Authorization is null,
            "Settings did not read the local-network projection from the trusted loopback Core with the private bearer.");

        foreach (var body in new[] { Body(enabled: false, listening: false), Body(listening: false) })
        {
            using var other = new Context((_, _) => Task.FromResult(Json(body.ToJsonString())));
            await other.SignInAsync();
            var parsed = await other.Client.GetLocalNetworkAsync(default);
            Ensure(parsed.Outcome == LocalNetworkRequestOutcome.Success && parsed.Status!.Enabled == body["enabled"]!.GetValue<bool>() &&
                   parsed.Status.Listening == body["listening"]!.GetValue<bool>(), "Desktop rejected a local-only or unavailable listener projection.");
        }
        var noDomain = Body(); noDomain["fullyQualifiedName"] = null; noDomain["addresses"] = new JsonArray();
        using var plain = new Context((_, _) => Task.FromResult(Json(noDomain.ToJsonString())));
        await plain.SignInAsync();
        Ensure((await plain.Client.GetLocalNetworkAsync(default)).Status is { FullyQualifiedName: null, Addresses.Count: 0 },
            "Desktop invented a domain or address.");
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
                     ("enabled", "true"), ("listening", null), ("port", 0), ("port", 65536), ("port", "5443"), ("port", 5443.5),
                     ("certificateSha256", Pin.ToLowerInvariant()), ("certificateSha256", new string('A', 63)), ("certificateSha256", new string('G', 64)),
                     ("hostName", ""), ("hostName", null), ("hostName", "bad name"), ("hostName", "bad\nname"), ("hostName", new string('a', 254)),
                     ("fullyQualifiedName", ""), ("fullyQualifiedName", 1), ("addresses", null), ("addresses", "10.0.0.5"),
                     ("addresses", new JsonArray("10.0.0.5", "10.0.0.5")), ("addresses", new JsonArray("::1")), ("addresses", new JsonArray("fe80::1")),
                     ("addresses", new JsonArray("10.0.0.005")), ("addresses", new JsonArray("10.0.0")), ("addresses", new JsonArray(1)),
                     ("privateKey", "synthetic-private-key"), ("password", "synthetic-password")
                 })
        {
            var body = Body(); body[key] = value?.DeepClone(); invalid.Add(body.ToJsonString());
        }
        // Core reports a port and fingerprint exactly when the role is configured.
        var inconsistent = new List<JsonObject>();
        var a = Body(enabled: false, listening: false); a["port"] = 5443; inconsistent.Add(a);
        var b = Body(enabled: false, listening: false); b["certificateSha256"] = Pin; inconsistent.Add(b);
        var c = Body(enabled: false, listening: true); inconsistent.Add(c);
        var d = Body(enabled: false, listening: false); d["addresses"] = new JsonArray("10.0.0.5"); inconsistent.Add(d);
        var e = Body(); e["port"] = null; inconsistent.Add(e);
        var f = Body(); f["certificateSha256"] = null; inconsistent.Add(f);
        invalid.AddRange(inconsistent.Select(item => item.ToJsonString()));
        foreach (var body in invalid)
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.InvalidResponse,
                "Desktop accepted an ambiguous, inconsistent or extended local-network projection.");
        }
        var many = Body(); many["addresses"] = new JsonArray(Enumerable.Range(1, 17).Select(index => (JsonNode)JsonValue.Create("10.0.0." + index)!).ToArray());
        foreach (var body in new[] { many.ToJsonString(), Body().ToJsonString().PadRight(8 * 1024 + 1) })
        {
            using var context = new Context((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            Ensure((await context.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.TooLarge,
                "Desktop accepted an unbounded local-network projection.");
        }
    }

    private static async Task FailuresAsync()
    {
        foreach (var (status, expected) in new[]
                 {
                     (HttpStatusCode.Unauthorized, LocalNetworkRequestOutcome.Unauthenticated), (HttpStatusCode.Forbidden, LocalNetworkRequestOutcome.Unavailable),
                     (HttpStatusCode.NotFound, LocalNetworkRequestOutcome.Unavailable), (HttpStatusCode.InternalServerError, LocalNetworkRequestOutcome.Unavailable)
                 })
        {
            using var context = new Context((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("synthetic-private-error") }));
            await context.SignInAsync();
            var result = await context.Client.GetLocalNetworkAsync(default);
            Ensure(result.Outcome == expected && result.Status is null, "A failed local-network read was misclassified.");
            if (expected == LocalNetworkRequestOutcome.Unauthenticated)
                Ensure((await context.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.Unauthenticated &&
                       context.Handler.Requests.Count(request => request.RequestUri!.AbsolutePath == "/api/admin/local-network") == 1,
                    "An expired Core session kept its bearer for another request.");
        }
        using (var untrusted = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString()))))
        {
            await untrusted.SignInAsync();
            untrusted.Trust.Allowed = false;
            Ensure((await untrusted.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.UntrustedConnection &&
                   untrusted.Handler.Requests.All(request => request.RequestUri!.AbsolutePath != "/api/admin/local-network"),
                "Desktop sent its bearer to an untrusted local Core endpoint.");
        }
        using (var html = new Context((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body().ToJsonString(), Encoding.UTF8, "text/html") })))
        {
            await html.SignInAsync();
            Ensure((await html.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.InvalidResponse, "A non-JSON projection was accepted.");
        }
        using (var signedOut = new Context((_, _) => Task.FromResult(Json(Body().ToJsonString()))))
            Ensure((await signedOut.Client.GetLocalNetworkAsync(default)).Outcome == LocalNetworkRequestOutcome.Unauthenticated &&
                   signedOut.Handler.Requests.Count == 0, "Desktop read local-network settings without a session.");
    }

    private static async Task ViewModelAsync()
    {
        var client = new FakeClient(new(LocalNetworkRequestOutcome.Success, new LocalNetworkStatus(true, true, 5443, Pin, "SYNTHETIC-CORE",
            "SYNTHETIC-CORE.corp.example", ["10.0.0.5", "192.168.1.20"])));
        using var model = new LocalNetworkViewModel(client);
        Ensure(model.State == LocalNetworkState.NotLoaded && model.PortText == "Not loaded" && model.FingerprintText == "Not loaded",
            "Settings showed local-network values before reading Core.");
        await model.RefreshAsync();
        Ensure(model.State == LocalNetworkState.Ready && model.PortText == "5443" && model.FingerprintText == Pin &&
               model.AddressesText == "10.0.0.5" + Environment.NewLine + "192.168.1.20" &&
               model.ComputerNameText == "SYNTHETIC-CORE (SYNTHETIC-CORE.corp.example)" && model.AccessText.StartsWith("On.", StringComparison.Ordinal),
            "Settings did not show Core's addresses, port and exact fingerprint.");
        client.Next = new(LocalNetworkRequestOutcome.Success, new LocalNetworkStatus(true, false, 5443, Pin, "SYNTHETIC-CORE", null, ["10.0.0.5"]));
        await model.RefreshAsync();
        Ensure(model.AccessText.Contains("not listening", StringComparison.Ordinal) && model.FingerprintText == Pin && model.ComputerNameText == "SYNTHETIC-CORE",
            "Settings hid that Core's local-network listener is unavailable.");
        client.Next = new(LocalNetworkRequestOutcome.Success, new LocalNetworkStatus(false, false, null, null, "SYNTHETIC-CORE", null, []));
        await model.RefreshAsync();
        Ensure(model.AccessText.StartsWith("Off.", StringComparison.Ordinal) && model.PortText == "Not applicable" &&
               model.FingerprintText == "Not applicable" && model.AddressesText == "Not applicable", "Settings showed a port or fingerprint for a local-only installation.");
        foreach (var (outcome, text) in new[]
                 {
                     (LocalNetworkRequestOutcome.Unavailable, "Local Core is unavailable"), (LocalNetworkRequestOutcome.InvalidResponse, "invalid local-network settings"),
                     (LocalNetworkRequestOutcome.UntrustedConnection, "could not be trusted"), (LocalNetworkRequestOutcome.TooLarge, "supported size")
                 })
        {
            client.Next = new(outcome);
            await model.RefreshAsync();
            Ensure(model.State == LocalNetworkState.Unavailable && model.Status is null && model.ErrorText.Contains(text, StringComparison.Ordinal) &&
                   model.FingerprintText == "Not loaded", "A failed read left stale local-network values or an unclear error.");
        }
        var expired = 0;
        model.SessionExpired += (_, _) => expired++;
        client.Next = new(LocalNetworkRequestOutcome.Unauthenticated);
        await model.RefreshAsync();
        Ensure(expired == 1 && model.State == LocalNetworkState.NotLoaded, "An expired session did not end the Desktop session.");
        client.Next = new(LocalNetworkRequestOutcome.Success, new LocalNetworkStatus(true, true, 5443, Pin, "SYNTHETIC-CORE", null, []));
        await model.RefreshAsync();
        model.Clear();
        Ensure(model.Status is null && model.FingerprintText == "Not loaded", "Sign-out kept Core's local-network values.");

        var pending = new FakeClient(null);
        using var slow = new LocalNetworkViewModel(pending);
        var refresh = slow.RefreshAsync();
        Ensure(!slow.CanRefresh && ReferenceEquals(refresh, slow.RefreshAsync()) && pending.Calls == 1, "Concurrent refreshes created duplicate reads.");
        slow.Clear();
        pending.Complete(new(LocalNetworkRequestOutcome.Success, new LocalNetworkStatus(true, true, 5443, Pin, "SYNTHETIC-CORE", null, [])));
        await refresh.WaitAsync(TimeSpan.FromSeconds(2));
        Ensure(slow.Status is null && slow.CanRefresh, "A response from before sign-out restored local-network values.");
    }

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class FakeClient(LocalNetworkRequestResult? result) : ILocalNetworkClient
    {
        private TaskCompletionSource<LocalNetworkRequestResult>? _pending;
        internal LocalNetworkRequestResult? Next = result;
        internal int Calls;
        public Task<LocalNetworkRequestResult> GetLocalNetworkAsync(CancellationToken cancellationToken)
        {
            Calls++;
            if (Next is not null) return Task.FromResult(Next);
            _pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
            return _pending.Task;
        }
        internal void Complete(LocalNetworkRequestResult value) => _pending!.TrySetResult(value);
    }

    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler); }
        internal Trust Trust { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-network-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic login failed.");
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
}
