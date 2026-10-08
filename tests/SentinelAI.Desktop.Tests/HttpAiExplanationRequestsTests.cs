using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using SentinelAI.Contracts.Ai;
using SentinelAI.Desktop.Foundation;

internal static class HttpAiExplanationRequestsTests
{
    private const string Token = "synthetic-ai-bearer";
    private static readonly Guid AlertId = new("aaaaaaaa-bbbb-cccc-dddd-000000000001");
    private const string Body = """
        {"label":"AI assistive analysis","analysis":{"explanation":"Literal <script>alert(1)</script> π 日本語","whyItMatters":"Administrator review is needed.","recommendedInvestigation":["Inspect the current local configuration."],"suggestedRemediation":["Consider an approved change."],"confidence":"medium","uncertainty":"Configuration evidence does not prove exploitation."}}
        """;
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        var deadline = WholeDeadlineAsync();
        await ContractAndSessionsAsync();
        await StatusAndTrustAsync();
        await HeadersAndSchemaAsync();
        await BoundsAndErasureAsync();
        await StaleSessionsAsync();
        await CancellationAsync();
        await deadline;
        Console.WriteLine($"Desktop AI transport: {_assertions} assertions passed.");
        return _assertions;
    }

    private static async Task ContractAndSessionsAsync()
    {
        using var stream = new CapturedStream(Encoding.UTF8.GetBytes(Body), 1);
        using var context = new Context((_, _) => Task.FromResult(Response(stream)));
        Check((await context.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
            "Signed-out AI issued a request.");
        await context.LoginAsync();
        var before = context.Handler.Requests.Count;
        Check((await context.Client.ExplainAlertAsync(Guid.Empty, default)).Outcome == AiExplanationOutcome.Unsupported && context.Handler.Requests.Count == before,
            "An empty AI alert identifier reached Core.");
        var result = await context.Client.ExplainAlertAsync(AlertId, default);
        Check(result.Outcome == AiExplanationOutcome.Success && result.Analysis?.Explanation == "Literal <script>alert(1)</script> π 日本語" &&
            result.Analysis.Confidence == "medium" && result.Analysis.Uncertainty.Length > 0,
            "Validated AI text was rewritten, lost or not returned literally.");
        var request = context.Handler.Requests.Last();
        Check(request.Method == HttpMethod.Post && request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/alerts/" + AlertId.ToString("D") + "/explanation" &&
            request.Content is null && request.RequestUri.Query.Length == 0 && request.Headers.Accept.Single().MediaType == "application/json",
            "AI did not use the existing bodyless selected-alert contract.");
        Check(context.Handler.Bearer == "Bearer " + Token && context.Handler.WasTrusted && !request.Headers.Contains("Cookie") && request.Headers.Authorization is null,
            "AI sent ambient credentials, bypassed trust or retained its bearer header.");
        Cleared(stream);
        context.Clock.Advance(TimeSpan.FromMinutes(15));
        before = context.Handler.Requests.Count;
        Check((await context.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.Unauthenticated && context.Handler.Requests.Count == before,
            "An expired session issued an AI request.");
        context.Client.Dispose();
        Check((await context.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.Unauthenticated,
            "Disposed AI accepted a request.");
    }

    private static async Task StatusAndTrustAsync()
    {
        foreach (var (status, outcome, expires) in new[]
        {
            (HttpStatusCode.Unauthorized, AiExplanationOutcome.Unauthenticated, true),
            (HttpStatusCode.Forbidden, AiExplanationOutcome.Disabled, false),
            (HttpStatusCode.NotFound, AiExplanationOutcome.NotFound, false),
            (HttpStatusCode.UnprocessableEntity, AiExplanationOutcome.Unsupported, false),
            (HttpStatusCode.TooManyRequests, AiExplanationOutcome.Throttled, false),
            (HttpStatusCode.ServiceUnavailable, AiExplanationOutcome.Unavailable, false),
            (HttpStatusCode.InternalServerError, AiExplanationOutcome.Unavailable, false),
            (HttpStatusCode.Redirect, AiExplanationOutcome.Unavailable, false),
            (HttpStatusCode.TemporaryRedirect, AiExplanationOutcome.Unavailable, false),
            (HttpStatusCode.NoContent, AiExplanationOutcome.Unavailable, false)
        })
        {
            using var stream = new FailureStream();
            using var context = new Context((_, _) =>
            {
                var response = Response(stream); response.StatusCode = status;
                response.Headers.Location = new Uri("https://untrusted.example/explain");
                return Task.FromResult(response);
            });
            await context.LoginAsync();
            var ownedToken = StoredToken(context.Client);
            var result = await context.Client.ExplainAlertAsync(AlertId, default);
            Check(result.Outcome == outcome && result.Analysis is null && stream.ReadCalls == 0 && stream.Disposed,
                "AI mapped a status incorrectly or read a private error body.");
            Check(context.Handler.Requests.Count == 3 && context.Handler.Requests.Last().Headers.Authorization is null,
                "An AI failure retried, followed a redirect or retained authorization.");
            Check((await context.Client.ValidateSessionAsync(default)).Status == (expires ? SessionStatus.SignedOut : SessionStatus.Authenticated),
                "An optional AI failure changed the local session incorrectly.");
            if (expires) Check(ownedToken.All(value => value == 0), "AI 401 retained the old session token.");
        }
        using var denied = new Context((_, _) => Task.FromResult(Json(Body)));
        await denied.LoginAsync();
        var token = StoredToken(denied.Client);
        denied.Trust.Allowed = false;
        Check((await denied.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.UntrustedConnection && denied.Handler.Requests.Count == 2,
            "Untrusted AI reached the HTTP handler.");
        Check(token.All(value => value == 0) && (await denied.Client.ValidateSessionAsync(default)).Status == SessionStatus.SignedOut,
            "Trust failure retained the authenticated token.");

        using var failed = new Context((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("synthetic-provider-key-private-error")));
        await failed.LoginAsync();
        var failure = await failed.Client.ExplainAlertAsync(AlertId, default);
        Check(failure == new AiExplanationResult(AiExplanationOutcome.Unavailable) && failed.Handler.Requests.Count == 3,
            "A network failure escaped, exposed private error text or retried AI.");
    }

    private static async Task HeadersAndSchemaAsync()
    {
        foreach (Action<HttpResponseMessage> modify in new Action<HttpResponseMessage>[]
        {
            response => response.Content.Headers.ContentType = null,
            response => response.Content.Headers.ContentType = new("text/html"),
            response => response.Content.Headers.ContentType!.CharSet = "utf-16",
            response => response.Headers.CacheControl = null,
            response => response.Headers.CacheControl = new() { NoStore = false },
            response => response.Content.Headers.ContentLength = AiContract.MaximumResponseBytes + 1
        })
        {
            using var stream = new FailureStream();
            using var context = new Context((_, _) => { var response = Response(stream); modify(response); return Task.FromResult(response); });
            await context.LoginAsync();
            Check((await context.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.InvalidResponse && stream.ReadCalls == 0 && stream.Disposed,
                "AI read or accepted an unsafe header/declaration.");
        }
        foreach (var invalid in new[]
        {
            "", "null", "[]", "{}", Body[..^1],
            Body.Replace("\"label\":", "\"label\":\"AI assistive analysis\",\"label\":", StringComparison.Ordinal),
            Body.Replace("\"analysis\":", "\"providerKey\":\"synthetic-private-key\",\"analysis\":", StringComparison.Ordinal),
            Body.Replace("AI assistive analysis", "Authoritative remediation", StringComparison.Ordinal),
            Body.Replace("\"whyItMatters\":", "\"explanation\":\"duplicate\",\"whyItMatters\":", StringComparison.Ordinal),
            Body.Replace("\"confidence\":\"medium\"", "\"confidence\":\"certain\"", StringComparison.Ordinal),
            Body.Replace("\"confidence\":\"medium\"", "\"confidence\":0.9", StringComparison.Ordinal),
            Body.Replace("[\"Consider an approved change.\"]", "[]", StringComparison.Ordinal),
            Body.Replace("Administrator review is needed.", new string('x', 1025), StringComparison.Ordinal),
            Body.Replace("Inspect the current local configuration.", "bad\\u0000text", StringComparison.Ordinal),
            Body.Replace("\"uncertainty\":", "\"action\":\"run-command\",\"uncertainty\":", StringComparison.Ordinal)
        })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(invalid));
            using var context = new Context((_, _) => Task.FromResult(Response(stream)));
            await context.LoginAsync();
            var result = await context.Client.ExplainAlertAsync(AlertId, default);
            Check(result.Outcome == AiExplanationOutcome.InvalidResponse && result.Analysis is null,
                "Malformed, ambiguous or private-field AI output was accepted.");
            Cleared(stream);
        }
        using var malformed = new CapturedStream([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d]);
        using var utf8 = new Context((_, _) => Task.FromResult(Response(malformed)));
        await utf8.LoginAsync();
        Check((await utf8.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.InvalidResponse,
            "Malformed UTF8 AI output was accepted.");
        Cleared(malformed);
    }

    private static async Task BoundsAndErasureAsync()
    {
        foreach (var size in new[] { AiContract.MaximumResponseBytes, AiContract.MaximumResponseBytes + 1, AiContract.MaximumResponseBytes * 2 })
        {
            var bytes = Encoding.UTF8.GetBytes(Body);
            var padded = new byte[size]; Array.Fill(padded, (byte)' '); bytes.CopyTo(padded, 0);
            using var stream = new CapturedStream(padded, 1024);
            using var context = new Context((_, _) => Task.FromResult(Response(stream)));
            await context.LoginAsync();
            Check((await context.Client.ExplainAlertAsync(AlertId, default)).Outcome ==
                (size == AiContract.MaximumResponseBytes ? AiExplanationOutcome.Success : AiExplanationOutcome.InvalidResponse),
                "The streamed AI byte boundary was truncated or exceeded.");
            Check(stream.BytesRead == Math.Min(size, AiContract.MaximumResponseBytes + 1), "AI read excess response bytes without a bound.");
            Cleared(stream);
        }
        using var streamFailure = new FailureStream();
        using var contextFailure = new Context((_, _) => Task.FromResult(Response(streamFailure)));
        await contextFailure.LoginAsync();
        Check((await contextFailure.Client.ExplainAlertAsync(AlertId, default)).Outcome == AiExplanationOutcome.Unavailable && streamFailure.ReadCalls == 1,
            "A private stream failure escaped the AI boundary.");
    }

    private static async Task StaleSessionsAsync()
    {
        foreach (var status in new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized })
        {
            var answer = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var context = new Context((_, _) => answer.Task);
            await context.LoginAsync();
            var oldToken = StoredToken(context.Client);
            var pending = context.Client.ExplainAlertAsync(AlertId, default);
            await context.LoginAsync();
            var response = Json(Body); response.StatusCode = status; answer.SetResult(response);
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(3));
            Check(result.Outcome == AiExplanationOutcome.Unauthenticated && result.Analysis is null && oldToken.All(value => value == 0),
                "An obsolete AI success/401 published into the new session or retained the old bearer.");
            Check((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated,
                "An obsolete AI 401 expired a newer authenticated session.");
        }
        using var stream = new CapturedStream(Encoding.UTF8.GetBytes(Body));
        using var expired = new Context((_, _) => Task.FromResult(Response(stream)));
        await expired.LoginAsync();
        stream.OnEnd = () => expired.Clock.Advance(TimeSpan.FromMinutes(15));
        var late = await expired.Client.ExplainAlertAsync(AlertId, default);
        Check(late.Outcome == AiExplanationOutcome.Unauthenticated && late.Analysis is null,
            "AI published analysis that completed after session expiry.");
        Cleared(stream);
    }

    private static async Task CancellationAsync()
    {
        using (var cancellation = new CancellationTokenSource())
        using (var context = new Context(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json(Body); }))
        {
            await context.LoginAsync();
            cancellation.Cancel();
            await Cancelled(context.Client.ExplainAlertAsync(AlertId, cancellation.Token), cancellation.Token);
            Check(context.Handler.Requests.Count == 2, "Pre-cancelled AI reached HTTP.");
        }
        using (var cancellation = new CancellationTokenSource())
        using (var context = new Context(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json(Body); }))
        {
            await context.LoginAsync();
            var pending = context.Client.ExplainAlertAsync(AlertId, cancellation.Token); cancellation.Cancel();
            await Cancelled(pending, cancellation.Token);
            Check(context.Handler.Requests.Last().Headers.Authorization is null, "Cancelled AI headers retained the bearer.");
        }
        using var bodyCancellation = new CancellationTokenSource();
        using var stream = new StalledStream();
        using var body = new Context((_, _) => Task.FromResult(Response(stream)));
        await body.LoginAsync();
        var reading = body.Client.ExplainAlertAsync(AlertId, bodyCancellation.Token);
        await stream.Entered.Task; bodyCancellation.Cancel();
        await Cancelled(reading, bodyCancellation.Token);
        Cleared(stream);
        Check(body.Handler.Requests.Last().Headers.Authorization is null, "Cancelled AI body retained the bearer.");
    }

    private static async Task WholeDeadlineAsync()
    {
        using var bodyStream = new StalledStream();
        using var body = new Context(async (_, token) => { await Task.Delay(TimeSpan.FromSeconds(3), token); return Response(bodyStream); });
        using var headers = new Context(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Json(Body); });
        using var trust = new Context((_, _) => Task.FromResult(Json(Body)));
        await Task.WhenAll(body.LoginAsync(), headers.LoginAsync(), trust.LoginAsync());
        trust.Trust.Answer = async token => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return true; };
        var watch = Stopwatch.StartNew();
        var results = await Task.WhenAll(body.Client.ExplainAlertAsync(AlertId, default), headers.Client.ExplainAlertAsync(AlertId, default), trust.Client.ExplainAlertAsync(AlertId, default))
            .WaitAsync(TimeSpan.FromSeconds(72));
        Check(results.All(result => result.Outcome == AiExplanationOutcome.Unavailable && result.Analysis is null) &&
            watch.Elapsed >= TimeSpan.FromSeconds(63) && watch.Elapsed < TimeSpan.FromSeconds(70),
            "AI trust, headers and body did not share the complete 65-second deadline.");
        Check(trust.Handler.Requests.Count == 2 && body.Handler.Requests.Count == 3 && headers.Handler.Requests.Count == 3,
            "A timed-out AI attempt retried or bypassed stalled trust.");
        Cleared(bodyStream);
        Check(body.Handler.Requests.Last().Headers.Authorization is null && headers.Handler.Requests.Last().Headers.Authorization is null,
            "Timed-out AI retained authorization.");
    }

    private static async Task Cancelled(Task<AiExplanationResult> task, CancellationToken token)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(3)); }
        catch (OperationCanceledException exception) { Check(exception.CancellationToken == token, "AI caller cancellation lost its token."); return; }
        throw new InvalidOperationException("AI caller cancellation was swallowed.");
    }
    private static HttpResponseMessage Json(string body) => Response(new CapturedStream(Encoding.UTF8.GetBytes(body)));
    private static HttpResponseMessage Response(Stream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new("application/json") { CharSet = "utf-8" };
        response.Headers.CacheControl = new() { NoStore = true };
        return response;
    }
    private static byte[] StoredToken(HttpAuthenticationClient client) => (byte[])typeof(HttpAuthenticationClient).GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;
    private static void Cleared(CapturedStream stream) => Check(stream.Disposed && stream.Destination is not null && stream.Destination.All(value => value == 0), "AI response bytes were retained after completion.");
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class Context : IDisposable
    {
        internal Context(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer) { Handler = new(answer, Trust); Client = new(Trust, Handler, timeProvider: Clock); }
        internal Trust Trust { get; } = new();
        internal Clock Clock { get; } = new();
        internal Handler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task LoginAsync() => Check((await Client.SignInAsync("admin", "synthetic-ai-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic AI test login failed.");
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
        internal Func<CancellationToken, Task<bool>>? Answer;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Answer?.Invoke(cancellationToken) ?? Task.FromResult(Allowed); }
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan amount) => _now += amount;
    }
    private class CapturedStream(byte[] bytes, int chunkSize = int.MaxValue) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead;
        internal bool Disposed;
        internal byte[]? Destination;
        internal Action? OnEnd;
        protected void Capture(Memory<byte> buffer) { if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) Destination = segment.Array; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer);
            var count = await base.ReadAsync(buffer[..Math.Min(buffer.Length, chunkSize)], cancellationToken); BytesRead += count;
            if (count == 0) { OnEnd?.Invoke(); OnEnd = null; }
            return count;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class StalledStream() : CapturedStream([])
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer); buffer.Span[0] = (byte)'x'; Entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0;
        }
    }
    private sealed class FailureStream() : CapturedStream([])
    {
        internal int ReadCalls;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { ReadCalls++; throw new IOException("synthetic-gateway-credential-private-error"); }
    }
}
