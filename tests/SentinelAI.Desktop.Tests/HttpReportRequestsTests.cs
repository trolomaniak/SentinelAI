using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using SentinelAI.Desktop.Foundation;

internal static class HttpReportRequestsTests
{
    private const string Token = "synthetic-report-bearer";
    private const string PrivateError = "synthetic-password-hash-and-agent-credential";
    private const string Policy = "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
    private static readonly ReportDateRange Period = new(new DateOnly(2026, 9, 1), new DateOnly(2026, 9, 30));
    private static readonly byte[] Html = Encoding.UTF8.GetBytes("<!doctype html><html><body>Core report: π &amp; 日本語</body></html>");
    private static int _assertions;

    internal static async Task<int> RunAsync()
    {
        _assertions = 0;
        var deadline = DeadlineAsync();
        await RoundTripAsync();
        await InvalidDatesAndSessionsAsync();
        await StatusAndTrustAsync();
        await HeadersAndUtf8Async();
        await ByteBoundsAsync();
        await SessionIsolationAsync();
        await CancellationAsync();
        await deadline;
        return _assertions;
    }

    private static async Task RoundTripAsync()
    {
        using var stream = new CapturedStream([0xef, 0xbb, 0xbf, .. Html], chunkSize: 1);
        using var context = new TestContext((_, _) =>
        {
            var response = Report(stream);
            response.Content.Headers.ContentDisposition!.FileName = "../../server-selected-name.html";
            response.Content.Headers.ContentDisposition.FileNameStar = "C:/untrusted/server-selected-name.html";
            return Task.FromResult(response);
        });
        await context.SignInAsync();
        var previousCulture = CultureInfo.CurrentCulture;
        SecurityReportResult result;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            result = await context.Client.GenerateSecurityReportAsync(Period, default);
        }
        finally { CultureInfo.CurrentCulture = previousCulture; }
        using var document = result.Document;
        Ensure(result.Outcome == ReportOutcome.Success && document is not null, "A valid Core report was not accepted.");
        var copy = document!.CopyContent();
        Ensure(copy.SequenceEqual(new byte[] { 0xef, 0xbb, 0xbf }.Concat(Html)), "Report bytes were decoded, rewritten or lost across UTF8 chunks.");
        Array.Clear(copy);
        copy = document.CopyContent();
        try { Ensure(copy.SequenceEqual(new byte[] { 0xef, 0xbb, 0xbf }.Concat(Html)), "A report did not own an independent copy."); }
        finally { Array.Clear(copy); }
        Ensure(document.Period == Period && document.SuggestedFileName == "SentinelAI-security-report-2026-09-01-2026-09-30.html",
            "A server filename or culture changed the locally derived report name.");
        var request = context.Handler.Requests.Last();
        Ensure(request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri == "http://127.0.0.1:5000/api/admin/reports/security?from=2026-09-01&to=2026-09-30",
            "Report generation changed the existing Core request contract.");
        Ensure(request.Content is null && request.Headers.Accept.Single().MediaType == "text/html" && request.Headers.Authorization is null,
            "Report transport retained a bearer header, posted data or requested a different format.");
        Ensure(context.Handler.ReportBearer == "Bearer " + Token && context.Handler.ReportWasTrusted, "Report generation did not use the private trusted authentication session.");
        AssertCleared(stream);
        var owned = (byte[])typeof(SecurityReportDocument).GetField("_content", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(document)!;
        document.Dispose();
        Ensure(owned.All(value => value == 0) && document.ByteCount == 0, "Disposing an accepted report retained its owned content.");
    }

    private static async Task InvalidDatesAndSessionsAsync()
    {
        using var context = new TestContext((_, _) => Task.FromResult(Report(new CapturedStream(Html))));
        Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.Unauthenticated && context.Handler.Requests.Count == 0,
            "A signed-out report sent a request.");
        await context.SignInAsync();
        var requests = context.Handler.Requests.Count;
        var trustCalls = context.Trust.Calls;
        foreach (var invalid in new ReportDateRange?[]
        {
            null, new(Period.To, Period.From), new(new DateOnly(2024, 1, 1), new DateOnly(2025, 1, 1)), new(DateOnly.MaxValue, DateOnly.MaxValue)
        })
        {
            Ensure((await context.Client.GenerateSecurityReportAsync(invalid!, default)).Outcome == ReportOutcome.InvalidPeriod,
                "An invalid report period was accepted.");
        }
        Ensure(context.Handler.Requests.Count == requests && context.Trust.Calls == trustCalls, "Invalid periods reached the network or trust adapter.");
        foreach (var valid in new[] { new ReportDateRange(Period.From, Period.From), new(new DateOnly(2024, 1, 1), new DateOnly(2024, 12, 31)), new(DateOnly.MinValue, DateOnly.MinValue) })
        {
            using var document = (await context.Client.GenerateSecurityReportAsync(valid, default)).Document;
            Ensure(document?.Period == valid, "An inclusive valid report period was rejected.");
        }
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        requests = context.Handler.Requests.Count;
        await ExpectCancelledAsync(context.Client.GenerateSecurityReportAsync(Period, cancellation.Token));
        Ensure(context.Handler.Requests.Count == requests, "Already-cancelled report generation sent a request.");
        var token = StoredToken(context.Client);
        context.Clock.Advance(TimeSpan.FromMinutes(15));
        Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.Unauthenticated && context.Handler.Requests.Count == requests && token.All(value => value == 0),
            "An expired session sent or retained its bearer for a report.");
    }

    private static async Task StatusAndTrustAsync()
    {
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.UnprocessableEntity, HttpStatusCode.RequestEntityTooLarge,
            HttpStatusCode.Found, HttpStatusCode.BadRequest, HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.TooManyRequests,
            HttpStatusCode.InternalServerError, HttpStatusCode.ServiceUnavailable })
        {
            using var stream = new CapturedStream(Encoding.UTF8.GetBytes(PrivateError));
            using var context = new TestContext((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StreamContent(stream) }));
            await context.SignInAsync();
            var token = StoredToken(context.Client);
            var result = await context.Client.GenerateSecurityReportAsync(Period, default);
            Ensure(result.Outcome == (status == HttpStatusCode.Unauthorized ? ReportOutcome.Unauthenticated : status == HttpStatusCode.UnprocessableEntity ? ReportOutcome.CapacityExceeded : ReportOutcome.Unavailable) && result.Document is null,
                "A report error status escaped its safe category.");
            Ensure(stream.BytesRead == 0 && stream.Disposed && !result.ToString().Contains(PrivateError, StringComparison.Ordinal), "An error report body was read or disclosed.");
            Ensure(context.Handler.Requests.Last().Headers.Authorization is null, "A report error retained a bearer header.");
            Ensure(status == HttpStatusCode.Unauthorized ? token.All(value => value == 0) : token.Any(value => value != 0), "A report error changed the wrong session state.");
        }
        using (var context = new TestContext((_, _) => throw new HttpRequestException(PrivateError)))
        {
            await context.SignInAsync();
            Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.Unavailable && context.Handler.Requests.Last().Headers.Authorization is null,
                "A report network failure exposed details or retained a bearer.");
        }
        using (var context = new TestContext((_, _) => Task.FromResult(Report(new CapturedStream(Html)))))
        {
            await context.SignInAsync();
            var requests = context.Handler.Requests.Count;
            var token = StoredToken(context.Client);
            context.Trust.Allowed = false;
            Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.UntrustedConnection && context.Handler.Requests.Count == requests && token.All(value => value == 0),
                "An untrusted report origin received credentials or left its session active.");
        }
        using var handler = new HttpClientHandler { AllowAutoRedirect = true, UseProxy = true, UseCookies = true, UseDefaultCredentials = true };
        using var client = new HttpAuthenticationClient(new TestTrust(), handler);
        Ensure(!handler.AllowAutoRedirect && !handler.UseProxy && !handler.UseCookies && !handler.UseDefaultCredentials && handler.Credentials is null,
            "Report composition permits credential redirects, proxies or ambient credentials.");
    }

    private static async Task HeadersAndUtf8Async()
    {
        Action<HttpResponseMessage>[] invalidHeaders =
        [
            response => response.Content.Headers.ContentType = null,
            response => response.Content.Headers.ContentType = new("application/json") { CharSet = "utf-8" },
            response => response.Content.Headers.ContentType!.CharSet = null,
            response => response.Content.Headers.ContentType!.CharSet = "utf-16",
            response => response.Content.Headers.ContentDisposition = null,
            response => response.Content.Headers.ContentDisposition!.DispositionType = "inline",
            response => response.Headers.CacheControl = null,
            response => response.Headers.CacheControl = new() { NoStore = false },
            response => response.Headers.Remove("X-Content-Type-Options"),
            response => response.Headers.Add("X-Content-Type-Options", "unsafe"),
            response => response.Headers.Remove("Content-Security-Policy"),
            response => { response.Headers.Remove("Content-Security-Policy"); response.Headers.Add("Content-Security-Policy", "script-src 'unsafe-inline'"); },
            response => response.Headers.Add("Content-Security-Policy", Policy)
        ];
        foreach (var change in invalidHeaders)
        {
            using var stream = new CapturedStream(Html);
            using var context = new TestContext((_, _) => { var response = Report(stream); change(response); return Task.FromResult(response); });
            await context.SignInAsync();
            Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.InvalidResponse && stream.BytesRead == 0 && stream.Disposed,
                "Unsafe report headers were accepted or their body was read.");
        }
        foreach (var bytes in new byte[][] { [], [0xc3, 0x28], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xef, 0xbb] })
        {
            using var stream = new CapturedStream(bytes, chunkSize: 1);
            using var context = new TestContext((_, _) => Task.FromResult(Report(stream)));
            await context.SignInAsync();
            Ensure((await context.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.InvalidResponse, "An empty or malformed UTF8 report was accepted.");
            AssertCleared(stream);
        }
    }

    private static async Task ByteBoundsAsync()
    {
        foreach (var count in new[] { SecurityReportDocument.MaximumBytes, SecurityReportDocument.MaximumBytes + 4096 })
        {
            using var stream = new CapturedStream(Enumerable.Repeat((byte)'x', count).ToArray(), chunkSize: 4096);
            using var context = new TestContext((_, _) => Task.FromResult(Report(stream)));
            await context.SignInAsync();
            var result = await context.Client.GenerateSecurityReportAsync(Period, default);
            using var document = result.Document;
            Ensure(result.Outcome == (count == SecurityReportDocument.MaximumBytes ? ReportOutcome.Success : ReportOutcome.TooLarge), "The real chunked report byte boundary was not enforced.");
            Ensure(stream.BytesRead == Math.Min(count, SecurityReportDocument.MaximumBytes + 1), "Report generation read unbounded excess bytes or truncated an accepted report.");
            Ensure(document is null || document.ByteCount == count, "An accepted report was silently truncated.");
            AssertCleared(stream);
        }
        using var declared = new CapturedStream(Html);
        using var oversized = new TestContext((_, _) => { var response = Report(declared); response.Content.Headers.ContentLength = SecurityReportDocument.MaximumBytes + 1; return Task.FromResult(response); });
        await oversized.SignInAsync();
        Ensure((await oversized.Client.GenerateSecurityReportAsync(Period, default)).Outcome == ReportOutcome.TooLarge && declared.BytesRead == 0 && declared.Disposed,
            "Declared oversized reports were read before rejection.");
    }

    private static async Task SessionIsolationAsync()
    {
        foreach (var status in new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized })
        {
            var answer = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var stream = new CapturedStream(Html);
            using var context = new TestContext((_, _) => { entered.TrySetResult(); return answer.Task; });
            await context.SignInAsync();
            var token = StoredToken(context.Client);
            var pending = context.Client.GenerateSecurityReportAsync(Period, default);
            await entered.Task;
            await context.SignInAsync();
            var response = Report(stream); response.StatusCode = status;
            answer.SetResult(response);
            Ensure((await pending).Outcome == ReportOutcome.Unauthenticated && token.All(value => value == 0), "An obsolete report published into a fresh session or retained the old bearer.");
            Ensure((await context.Client.ValidateSessionAsync(default)).Status == SessionStatus.Authenticated, "An old report result or 401 invalidated the new login.");
            Ensure(stream.Disposed && context.Handler.Requests.Single(request => request.RequestUri!.AbsolutePath.Contains("/reports/", StringComparison.Ordinal)).Headers.Authorization is null,
                "An abandoned response or bearer header was retained.");
        }
        using var expiredBody = new CapturedStream(Html);
        using var expired = new TestContext((_, _) => Task.FromResult(Report(expiredBody)));
        await expired.SignInAsync();
        expiredBody.OnEnd = () => expired.Clock.Advance(TimeSpan.FromMinutes(15));
        var result = await expired.Client.GenerateSecurityReportAsync(Period, default);
        Ensure(result.Outcome == ReportOutcome.Unauthenticated && result.Document is null, "A parsed report completed after session expiry was published.");
        AssertCleared(expiredBody);
    }

    private static async Task CancellationAsync()
    {
        using (var cancellation = new CancellationTokenSource())
        using (var context = new TestContext(async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Report(new CapturedStream(Html)); }))
        {
            await context.SignInAsync();
            var pending = context.Client.GenerateSecurityReportAsync(Period, cancellation.Token);
            cancellation.Cancel();
            await ExpectCancelledAsync(pending);
            Ensure(context.Handler.Requests.Last().Headers.Authorization is null, "Cancellation before headers retained a bearer header.");
        }
        using var bodyCancellation = new CancellationTokenSource();
        using var stream = new StalledStream();
        using var body = new TestContext((_, _) => Task.FromResult(Report(stream)));
        await body.SignInAsync();
        var request = body.Client.GenerateSecurityReportAsync(Period, bodyCancellation.Token);
        await stream.Entered.Task;
        bodyCancellation.Cancel();
        await ExpectCancelledAsync(request);
        AssertCleared(stream);
        Ensure(body.Handler.Requests.Last().Headers.Authorization is null, "Cancelled report body retained a bearer header.");
    }

    private static async Task DeadlineAsync()
    {
        using var stream = new StalledStream();
        using var context = new TestContext(async (_, token) => { await Task.Delay(TimeSpan.FromSeconds(3), token); return Report(stream); });
        await context.SignInAsync();
        var watch = Stopwatch.StartNew();
        var result = await context.Client.GenerateSecurityReportAsync(Period, default).WaitAsync(TimeSpan.FromSeconds(35));
        Ensure(result.Outcome == ReportOutcome.Unavailable && watch.Elapsed >= TimeSpan.FromSeconds(28) && watch.Elapsed < TimeSpan.FromSeconds(33),
            "The report deadline did not bound headers and full body together to 30 seconds.");
        AssertCleared(stream);
        Ensure(context.Handler.Requests.Last().Headers.Authorization is null, "A timed-out report retained a bearer header.");
    }

    private static async Task ExpectCancelledAsync(Task<SecurityReportResult> task)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (OperationCanceledException) { Ensure(true, "Caller cancellation completed."); return; }
        throw new InvalidOperationException("Report generation ignored caller cancellation.");
    }

    private static HttpResponseMessage Report(Stream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) };
        response.Content.Headers.ContentType = new("text/html") { CharSet = "utf-8" };
        response.Content.Headers.ContentDisposition = new("attachment") { FileName = "server-name.html" };
        response.Headers.CacheControl = new() { NoStore = true };
        response.Headers.Add("X-Content-Type-Options", "nosniff");
        response.Headers.Add("Content-Security-Policy", Policy);
        return response;
    }
    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static byte[] StoredToken(HttpAuthenticationClient client) => (byte[])typeof(HttpAuthenticationClient).GetField("_token", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;
    private static void AssertCleared(CapturedStream stream) => Ensure(stream.Disposed && stream.DestinationBuffer is not null && stream.DestinationBuffer.All(value => value == 0), "Owned report response bytes were retained after completion.");
    private static void Ensure(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); Interlocked.Increment(ref _assertions); }

    private sealed class TestContext : IDisposable
    {
        internal TestContext(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer)
        {
            Handler = new(answer, Trust); Client = new(Trust, Handler, timeProvider: Clock);
        }
        internal TestTrust Trust { get; } = new();
        internal TestClock Clock { get; } = new();
        internal TestHandler Handler { get; }
        internal HttpAuthenticationClient Client { get; }
        internal async Task SignInAsync() => Ensure((await Client.SignInAsync("admin", "synthetic-report-password".AsMemory(), default)).Outcome == AuthenticationOutcome.Authenticated, "Synthetic report login failed.");
        public void Dispose() => Client.Dispose();
    }
    private sealed class TestHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> answer, TestTrust trust) : HttpMessageHandler
    {
        internal List<HttpRequestMessage> Requests { get; } = [];
        internal string? ReportBearer;
        internal bool ReportWasTrusted;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.RequestUri!.AbsolutePath == "/api/auth/login") return Task.FromResult(Json("{\"tokenType\":\"Bearer\",\"accessToken\":\"" + Token + "\",\"expiresIn\":900}"));
            if (request.RequestUri.AbsolutePath == "/api/admin/me") return Task.FromResult(Json("{\"username\":\"admin\",\"role\":\"administrator\"}"));
            ReportBearer = request.Headers.Authorization?.ToString();
            ReportWasTrusted = trust.Allowed && trust.Calls >= 3;
            return answer(request, cancellationToken);
        }
    }
    private sealed class TestTrust : ICoreEndpointTrust
    {
        internal bool Allowed = true;
        internal int Calls;
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken) { Calls++; return Task.FromResult(Allowed); }
    }
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 4, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private class CapturedStream(byte[] bytes, int chunkSize = int.MaxValue) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        internal int BytesRead;
        internal bool Disposed;
        internal byte[]? DestinationBuffer;
        internal Action? OnEnd;
        protected void Capture(Memory<byte> buffer) { if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) DestinationBuffer = segment.Array; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Capture(buffer);
            var count = await base.ReadAsync(buffer[..Math.Min(buffer.Length, chunkSize)], cancellationToken);
            BytesRead += count;
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
}
