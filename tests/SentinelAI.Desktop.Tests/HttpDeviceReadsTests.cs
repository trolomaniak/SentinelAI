using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SentinelAI.Desktop.Foundation;

internal static class HttpDeviceReadsTests
{
    private static int _assertions;
    private static readonly Guid EndpointId = Guid.Parse("8f732922-0cff-4b41-aa69-e720bb6b43d2");
    private const string Token = "synthetic.devices-token_123";
    private const string PrivateError = "synthetic-private-server-detail";

    public static async Task<int> RunAsync()
    {
        _assertions = 0;
        await ReadsAndUnknownValuesAsync();
        await StatusAndTrustAsync();
        await ResponseValidationAsync();
        await WorkBoundsAsync();
        await ResponseMemoryAsync();
        await SessionIsolationAsync();
        await CancellationAndDeadlineAsync();
        return _assertions;
    }

    private static void Ensure(bool condition, string message)
    {
        _assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private static string Summary(Guid? id = null, string health = "healthy") => JsonSerializer.Serialize(new
    {
        endpointId = id ?? EndpointId,
        name = "synthetic-endpoint",
        operatingSystem = "Windows 11 26H2 10.0.26200.0",
        healthState = health,
        lastSeenUtc = "2026-10-03T12:00:00Z",
        agentVersion = "1.0.0",
        securityPostureSummary = "Firewall enabled on all profiles",
        inventoryCollectedUtc = "2026-10-03T11:00:00Z"
    });

    private static string Detail(string? additions = null, Guid? id = null) =>
        "{\"device\":" + Summary(id) + (additions is null ? "" : "," + additions) + "}";

    private sealed class TestContext(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> deviceAnswer) : IDisposable
    {
        internal TestTrust Trust { get; } = new();
        internal TestClock Clock { get; } = new();
        internal ReadHandler Handler { get; } = new(deviceAnswer);
        private HttpAuthenticationClient? _client;
        internal HttpAuthenticationClient Client => _client ??= new(Trust, Handler, timeProvider: Clock);
        internal async Task SignInAsync()
        {
            var result = await Client.SignInAsync("admin", "synthetic-test-password".AsMemory(), default);
            Ensure(result.Outcome == AuthenticationOutcome.Authenticated, "Test session did not authenticate.");
        }
        public void Dispose() { _client?.Dispose(); Handler.Dispose(); }
    }

    private static async Task ReadsAndUnknownValuesAsync()
    {
        using var context = new TestContext((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/admin/devices"
            ? Json("[" + string.Join(',', new[] { "healthy", "warning", "offline", "unknown", "unexpected-health" }
                .Select((health, index) => Summary(new Guid(index + 1, 0, 0, new byte[8]), health))) + "]")
            : Json(Detail("\"inventoryCollectedUtc\":\"2026-10-03T11:00:00Z\",\"osName\":\"Windows 11\",\"osVersion\":\"26H2 10.0.26200.0\",\"architecture\":\"X64\",\"cpu\":{\"model\":\"Synthetic CPU\",\"logicalProcessorCount\":8},\"installedRamBytes\":17179869184,\"disks\":[{\"name\":\"C:\",\"totalBytes\":1000,\"availableBytes\":250}],\"securityPosture\":{\"domainFirewallEnabled\":true,\"privateFirewallEnabled\":false,\"configuration\":{\"uacEnabled\":true,\"rdpEnabled\":null,\"rdpSecurityLayer\":2}}"))));
        Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
            "Signed-out device reads reached Core.");
        Ensure((await context.Client.GetDeviceDetailAsync(Guid.Empty, default)).Outcome == DeviceReadOutcome.Unauthenticated,
            "An empty detail selection bypassed signed-out state.");
        await context.SignInAsync();
        var beforeInvalidSelection = context.Handler.Requests.Count;
        Ensure((await context.Client.GetDeviceDetailAsync(Guid.Empty, default)).Outcome == DeviceReadOutcome.NotFound && context.Handler.Requests.Count == beforeInvalidSelection,
            "An empty authenticated detail selection sent a request.");
        var list = await context.Client.GetDevicesAsync(default);
        Ensure(list.Outcome == DeviceReadOutcome.Success && list.Value!.Count == 5, "Enrolled endpoint list was not read.");
        Ensure(list.Value!.Select(device => device.HealthState).SequenceEqual(["healthy", "warning", "offline", "unknown", "unknown"]),
            "Core's health states changed or an unknown state became healthy.");
        Ensure(list.Value![0].OperatingSystem == "Windows 11 26H2 10.0.26200.0" && list.Value[0].AgentVersion == "1.0.0" &&
            list.Value[0].InventoryCollectedUtc == DateTimeOffset.Parse("2026-10-03T11:00:00Z"), "Public inventory and OS release/build fields were lost.");
        var detail = await context.Client.GetDeviceDetailAsync(EndpointId, default);
        Ensure(detail.Outcome == DeviceReadOutcome.Success && detail.Value!.Device.EndpointId == EndpointId && detail.Value.Cpu!.LogicalProcessorCount == 8,
            "Selected endpoint hardware detail was not read.");
        Ensure(detail.Value!.InstalledRamBytes == 17179869184 && detail.Value.Disks.Count == 1 && detail.Value.Disks[0].AvailableBytes == 250,
            "Endpoint capacities changed.");
        Ensure(detail.Value.SecurityPosture!.DomainFirewallEnabled == true && detail.Value.SecurityPosture.PrivateFirewallEnabled == false &&
            detail.Value.SecurityPosture.PublicFirewallEnabled is null && detail.Value.SecurityPosture.Configuration!.RdpEnabled is null &&
            detail.Value.SecurityPosture.Configuration.RdpSecurityLayer == 2, "Missing firewall/configuration observations became false or disappeared.");
        var reads = context.Handler.Requests.Where(request => request.Path.StartsWith("/api/admin/devices", StringComparison.Ordinal)).ToArray();
        Ensure(reads.Length == 2 && reads.All(request => request.Method == HttpMethod.Get && !request.HasBody && request.Authorization == "Bearer " + Token),
            "Device reads changed authentication or used writes/request bodies.");
        Ensure(reads[1].Path == "/api/admin/devices/" + EndpointId.ToString("D") && reads.All(request => request.Origin == "http://127.0.0.1:5000"),
            "Endpoint reads allowed another route or destination.");
        Ensure(context.Trust.Calls >= context.Handler.Requests.Count, "A device read skipped Core trust verification.");

        using var missing = new TestContext((request, _) => Task.FromResult(Json(request.RequestUri!.AbsolutePath == "/api/admin/devices"
            ? "[{\"endpointId\":\"" + EndpointId + "\"}]" : Detail("\"securityPosture\":{\"configuration\":{}}"))));
        await missing.SignInAsync();
        var unknown = (await missing.Client.GetDevicesAsync(default)).Value![0];
        Ensure(unknown.Name == "Unknown" && unknown.HealthState == "unknown" && unknown.OperatingSystem is null && unknown.AgentVersion is null &&
            unknown.InventoryCollectedUtc is null && unknown.LastSeenUtc is null && unknown.SecurityPostureSummary == "Firewall status unknown",
            "Missing public summary fields were inferred instead of remaining Unknown.");
        var missingDetail = (await missing.Client.GetDeviceDetailAsync(EndpointId, default)).Value!;
        Ensure(missingDetail.Cpu is null && missingDetail.InstalledRamBytes is null && missingDetail.Disks.Count == 0 && missingDetail.OsVersion is null &&
            missingDetail.SecurityPosture!.DomainFirewallEnabled is null && missingDetail.SecurityPosture.Configuration!.UacEnabled is null,
            "Missing hardware or security inventory was inferred.");

        using var empty = new TestContext((_, _) => Task.FromResult(Json("[]")));
        await empty.SignInAsync();
        Ensure((await empty.Client.GetDevicesAsync(default)) is { Outcome: DeviceReadOutcome.Success, Value.Count: 0 }, "An empty enrolled fleet was treated as unavailable.");
    }

    private static async Task StatusAndTrustAsync()
    {
        foreach (var (status, expected) in new[]
                 {
                     (HttpStatusCode.Unauthorized, DeviceReadOutcome.Unauthenticated),
                     (HttpStatusCode.Forbidden, DeviceReadOutcome.Unavailable),
                     (HttpStatusCode.ServiceUnavailable, DeviceReadOutcome.Unavailable),
                     (HttpStatusCode.TooManyRequests, DeviceReadOutcome.Unavailable),
                     (HttpStatusCode.Redirect, DeviceReadOutcome.Unavailable),
                     (HttpStatusCode.RequestEntityTooLarge, DeviceReadOutcome.TooLarge),
                     (HttpStatusCode.UnprocessableEntity, DeviceReadOutcome.TooLarge)
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json("{\"private\":\"" + PrivateError + "\"}", status)));
            await context.SignInAsync();
            var result = await context.Client.GetDevicesAsync(default);
            Ensure(result.Outcome == expected && result.Value is null, "HTTP failure was mapped incorrectly or exposed device data.");
            Ensure(!result.ToString().Contains(PrivateError, StringComparison.Ordinal), "A server error body entered a public result.");
            if (status == HttpStatusCode.Unauthorized)
                Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "A matching 401 retained the local session.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json("{}", HttpStatusCode.NotFound))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetDeviceDetailAsync(EndpointId, default)).Outcome == DeviceReadOutcome.NotFound, "Missing endpoint detail was not explicit.");
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.Unavailable, "Missing list route became an empty fleet.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[]"))))
        {
            await context.SignInAsync();
            var requests = context.Handler.Requests.Count;
            context.Trust.Allowed = false;
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.UntrustedConnection && context.Handler.Requests.Count == requests,
                "An untrusted Core received bearer material.");
            Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "Rejected endpoint trust retained a session.");
        }
    }

    private static async Task ResponseValidationAsync()
    {
        foreach (var body in new[]
                 {
                     "{}", "null", "[{}]", "[{\"endpointId\":\"invalid\"}]", "[{\"endpointId\":\"00000000-0000-0000-0000-000000000000\"}]",
                     "[" + Summary() + "," + Summary() + "]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"name\":\"one\",\"name\":\"two\"}]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"passwordHash\":\"" + PrivateError + "\"}]",
                     "[" + Summary().Replace("healthy", "bad\\ncontrol", StringComparison.Ordinal) + "]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"lastSeenUtc\":\"not-a-date\"}]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"lastSeenUtc\":\"2026-10-03T12:00:00+01:00\"}]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"name\":false}]",
                     "[{\"endpointId\":\"" + EndpointId + "\",\"name\":\"" + new string('x', 256) + "\"}]",
                     "[/*comment*/" + Summary() + "]", "[" + Summary() + ",]"
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            var result = await context.Client.GetDevicesAsync(default);
            Ensure(result.Outcome == DeviceReadOutcome.InvalidResponse && result.Value is null && !result.ToString().Contains(PrivateError, StringComparison.Ordinal),
                "Malformed, duplicate, unsafe or private summary fields were admitted.");
        }
        foreach (var body in new[]
                 {
                     Detail(id: Guid.Parse("d3d0f6a5-3730-46fa-b7ad-7d41b562bd8c")), "{}", "[]",
                     Detail("\"cpu\":{\"model\":\"missing-count\"}"), Detail("\"cpu\":{\"logicalProcessorCount\":0}"),
                     Detail("\"cpu\":{\"logicalProcessorCount\":1025}"), Detail("\"installedRamBytes\":0"),
                     Detail("\"installedRamBytes\":9223372036854775808"), Detail("\"disks\":[{\"name\":\"C:\",\"totalBytes\":100,\"availableBytes\":101}]"),
                     Detail("\"disks\":[{\"name\":\"C:\",\"totalBytes\":100}]"), Detail("\"securityPosture\":{\"domainFirewallEnabled\":\"true\"}"),
                     Detail("\"securityPosture\":{\"configuration\":{\"rdpSecurityLayer\":3}}"),
                     Detail("\"securityPosture\":{\"configuration\":{\"adminConsentPromptBehavior\":6}}"),
                     Detail("\"securityPosture\":{\"configuration\":{\"rdpMinimumEncryptionLevel\":0}}"),
                     Detail("\"enrollmentCredential\":\"" + PrivateError + "\""), Detail("\"cpu\":[]")
                 })
        {
            using var context = new TestContext((_, _) => Task.FromResult(Json(body)));
            await context.SignInAsync();
            var result = await context.Client.GetDeviceDetailAsync(EndpointId, default);
            Ensure(result.Outcome == DeviceReadOutcome.InvalidResponse && result.Value is null, "Malformed, mismatched, or private endpoint detail was admitted.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]", Encoding.UTF8, "text/html") })))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.InvalidResponse, "A non-JSON device response was accepted.");
        }
    }

    private static async Task WorkBoundsAsync()
    {
        foreach (var (detail, maximum) in new[] { (false, 8 * 1024 * 1024), (true, 256 * 1024) })
        {
            using (var context = new TestContext((_, _) =>
                   {
                       var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };
                       response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                       response.Content.Headers.ContentLength = maximum + 1;
                       return Task.FromResult(response);
                   }))
            {
                await context.SignInAsync();
                var outcome = detail ? (await context.Client.GetDeviceDetailAsync(EndpointId, default)).Outcome : (await context.Client.GetDevicesAsync(default)).Outcome;
                Ensure(outcome == DeviceReadOutcome.TooLarge, "An oversized declared device response was not explicit.");
            }
            using var body = new CountedStream(new byte[maximum + 4096]);
            using (var context = new TestContext((_, _) =>
                   {
                       var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
                       response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                       return Task.FromResult(response);
                   }))
            {
                await context.SignInAsync();
                var outcome = detail ? (await context.Client.GetDeviceDetailAsync(EndpointId, default)).Outcome : (await context.Client.GetDevicesAsync(default)).Outcome;
                Ensure(outcome == DeviceReadOutcome.TooLarge && body.BytesRead == maximum + 1, "An unknown-length device stream exceeded its bound or was silently truncated.");
                Ensure(body.DestinationBuffer is not null && body.DestinationBuffer.All(value => value == 0), "An oversized device body buffer was not erased.");
            }
        }
        var identities = Enumerable.Range(1, 10_001).Select(index => "{\"endpointId\":\"" + new Guid(index, 0, 0, new byte[8]) + "\"}").ToArray();
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[" + string.Join(',', identities.Take(10_000)) + "]"))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetDevicesAsync(default)) is { Outcome: DeviceReadOutcome.Success, Value.Count: 10_000 }, "The documented maximum fleet was silently truncated.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[" + string.Join(',', identities) + "]"))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.TooLarge, "An oversized fleet was silently truncated.");
        }
        var disks = string.Join(',', Enumerable.Repeat("{\"name\":\"synthetic-disk\",\"totalBytes\":100,\"availableBytes\":50}", 65));
        using (var context = new TestContext((_, _) => Task.FromResult(Json(Detail("\"disks\":[" + disks + "]")))))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GetDeviceDetailAsync(EndpointId, default)).Outcome == DeviceReadOutcome.TooLarge, "An oversized disk collection was silently truncated.");
        }
    }

    private static async Task ResponseMemoryAsync()
    {
        foreach (var payload in new[] { "[" + Summary() + "]", "[{\"privateCredential\":\"synthetic-private-buffer-data\"}]" })
        {
            using var body = new CountedStream(Encoding.UTF8.GetBytes(payload));
            using var context = new TestContext((_, _) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                return Task.FromResult(response);
            });
            await context.SignInAsync();
            var result = await context.Client.GetDevicesAsync(default);
            Ensure(result.Outcome is DeviceReadOutcome.Success or DeviceReadOutcome.InvalidResponse, "Buffer cleanup fixture did not exercise parsing.");
            Ensure(body.DestinationBuffer is not null && body.DestinationBuffer.All(value => value == 0), "A completed or rejected device body buffer was not erased.");
        }
    }

    private static async Task SessionIsolationAsync()
    {
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[]"))))
        {
            await context.SignInAsync();
            context.Clock.Advance(TimeSpan.FromMinutes(15));
            var calls = context.Handler.Requests.Count;
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.Unauthenticated && context.Handler.Requests.Count == calls,
                "Local session expiry sent bearer material or admitted data.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[]"))))
        {
            await context.SignInAsync();
            context.Client.SignOut();
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.Unauthenticated, "Sign-out retained device access.");
        }
        foreach (var status in new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized })
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var completed = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var context = new TestContext((_, _) => { entered.TrySetResult(); return completed.Task; });
            await context.SignInAsync();
            var pending = context.Client.GetDevicesAsync(default);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await context.SignInAsync();
            completed.SetResult(Json("[]", status));
            var obsolete = await pending.WaitAsync(TimeSpan.FromSeconds(2));
            Ensure(obsolete.Outcome == DeviceReadOutcome.Unauthenticated && obsolete.Value is null, "An obsolete session published device data.");
            Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated, "An obsolete response cleared a new authenticated session.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Json("[]"))))
        {
            await context.SignInAsync();
            context.Clock.Advance(TimeSpan.FromMinutes(14));
            context.Handler.DeviceAnswer = (_, _) => { context.Clock.Advance(TimeSpan.FromMinutes(2)); return Task.FromResult(Json("[]")); };
            Ensure((await context.Client.GetDevicesAsync(default)).Outcome == DeviceReadOutcome.Unauthenticated, "Expiry during a successful device reply admitted stale data.");
            Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut, "Expiry during device reading retained bearer material.");
        }
    }

    private static async Task CancellationAndDeadlineAsync()
    {
        using (var cancellation = new CancellationTokenSource())
        using (var context = new TestContext(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json("[]"); }))
        {
            await context.SignInAsync();
            var pending = context.Client.GetDevicesAsync(cancellation.Token);
            cancellation.Cancel();
            var cancelled = false;
            try { await pending.WaitAsync(TimeSpan.FromSeconds(2)); } catch (OperationCanceledException) { cancelled = true; }
            Ensure(cancelled, "Caller cancellation did not stop a pending device request.");
        }
        using (var stream = new StalledStream())
        using (var context = new TestContext((_, _) =>
               {
                   var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
                   response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                   return Task.FromResult(response);
               }))
        {
            await context.SignInAsync();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var result = await context.Client.GetDevicesAsync(default).WaitAsync(TimeSpan.FromSeconds(13));
            Ensure(result.Outcome == DeviceReadOutcome.Unavailable && watch.Elapsed < TimeSpan.FromSeconds(12), "A stalled device body exceeded its total deadline.");
        }
    }

    private sealed class ReadHandler : HttpMessageHandler
    {
        internal ReadHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) => DeviceAnswer = answer;
        internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> DeviceAnswer { get; set; }
        internal List<CapturedRead> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request.Method, request.RequestUri!.AbsolutePath, request.RequestUri.GetLeftPart(UriPartial.Authority), request.Content is not null,
                request.Headers.Authorization?.ToString()));
            return request.RequestUri.AbsolutePath switch
            {
                "/api/auth/login" => Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}")),
                "/api/admin/me" => Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}")),
                _ => DeviceAnswer(request, cancellationToken)
            };
        }
    }
    private sealed record CapturedRead(HttpMethod Method, string Path, string Origin, bool HasBody, string? Authorization);
    private sealed class TestTrust : ICoreEndpointTrust
    {
        internal bool Allowed { get; set; } = true;
        internal int Calls { get; private set; }
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 3, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private sealed class CountedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead { get; private set; }
        internal byte[]? DestinationBuffer { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) DestinationBuffer = segment.Array;
            var read = await base.ReadAsync(buffer, cancellationToken); BytesRead += read; return read;
        }
    }
    private sealed class StalledStream : MemoryStream
    {
        public override bool CanSeek => false;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0;
        }
    }
}
