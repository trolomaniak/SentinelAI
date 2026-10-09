using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Setup.Foundation;

internal static class EnrollmentProtocolTests
{
    private const string Password = "Synthetic-only-\"密碼\n-password";
    private static readonly string Enrollment = new('A', 64);
    private const string Login = "{\"tokenType\":\"Bearer\",\"accessToken\":\"synthetic.jwt-token\",\"expiresIn\":900,\"refreshToken\":\"ignored-synthetic-refresh\"}";
    private static string TokenDocument() => JsonSerializer.Serialize(new
    {
        token = Enrollment, expiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
        coreInstallationId = "11111111-1111-4111-8111-111111111111", organizationId = "22222222-2222-4222-8222-222222222222"
    });

    public static async Task<int> RunAsync()
    {
        var checks = 0;
        void Ensure(bool value, string context) { checks++; if (!value) throw new InvalidOperationException("Setup enrollment protocol: " + context); }
        async Task Reject(ProtocolHandler handler, Trust? trust = null, CancellationToken token = default)
        {
            using var issuer = new HttpSetupEnrollmentIssuer(trust ?? new Trust(), handler);
            var rejected = false;
            try { _ = await issuer.IssueAsync(" setup-test ", Password.AsMemory(), token); }
            catch (InvalidDataException error) { rejected = error.Message == "Local Agent enrollment unavailable."; }
            catch (OperationCanceledException) { rejected = token.IsCancellationRequested; }
            Ensure(rejected, "invalid exchange fails with fixed text and no result");
            Ensure(handler.PasswordBuffer is null || handler.PasswordBuffer.All(value => value == 0), "failed exchange wipes borrowed password bytes");
            foreach (var stream in handler.ResponseStreams) Ensure(stream.ReadBuffer is null || stream.ReadBuffer.All(value => value == 0), "failed exchange wipes response bytes");
        }

        var healthy = new ProtocolHandler(); var trusted = new Trust();
        using (var issuer = new HttpSetupEnrollmentIssuer(trusted, healthy))
        {
            Ensure(await issuer.IssueAsync(" setup-test ", Password.AsMemory(), CancellationToken.None) == Enrollment, "returns the exact one-use token");
            Ensure(healthy.Paths.SequenceEqual(new[] { "/api/auth/login", "/api/admin/enrollment-tokens" }), "one login then one token request without retry");
            Ensure(trusted.Calls == 2, "rechecks trust before each request");
            using var login = JsonDocument.Parse(healthy.LoginBody!);
            Ensure(login.RootElement.GetProperty("username").GetString() == "setup-test" && login.RootElement.GetProperty("password").GetString() == Password, "literal bounded Unicode credentials and trimmed username");
            Ensure(healthy.Authorizations.SequenceEqual(new string?[] { null, "Bearer synthetic.jwt-token" }), "bearer remains private and is used only for token issuance");
            Ensure(healthy.PasswordBuffer is not null && healthy.PasswordBuffer.All(value => value == 0), "successful request wipes password backing buffer");
            foreach (var stream in healthy.ResponseStreams) Ensure(stream.ReadBuffer is not null && stream.ReadBuffer.All(value => value == 0), "successful exchange wipes login/token response buffers");
        }
        Ensure(healthy.Disposed, "issuer owns and disposes its handler");

        var noTrust = new ProtocolHandler(); await Reject(noTrust, new Trust(false));
        Ensure(noTrust.Paths.Count == 0, "untrusted Core receives no credentials");
        var changedTrust = new ProtocolHandler(); await Reject(changedTrust, new Trust(true, false));
        Ensure(changedTrust.Paths.Count == 1, "lost trust receives no bearer or enrollment request");
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests, HttpStatusCode.Redirect, HttpStatusCode.InternalServerError })
        {
            var failed = new ProtocolHandler { LoginStatus = status }; await Reject(failed);
            Ensure(failed.Paths.Count == 1, "failed login is not retried or followed by token issuance");
        }
        await Reject(new ProtocolHandler { LoginMediaType = "text/html" });
        foreach (var invalid in new[]
        {
            "[]", "{}", Login.Replace("Bearer", "Basic", StringComparison.Ordinal),
            Login.Replace("synthetic.jwt-token", "bad token", StringComparison.Ordinal),
            Login.Replace("synthetic.jwt-token", new string('x', 8193), StringComparison.Ordinal),
            Login.Replace("synthetic.jwt-token", "", StringComparison.Ordinal),
            Login.Replace("900", "0", StringComparison.Ordinal), Login.Replace("900", "\"900\"", StringComparison.Ordinal),
            Login.Replace("\"ignored-synthetic-refresh\"", "null", StringComparison.Ordinal),
            Login.Replace("\"accessToken\":", "\"accessToken\":\"first\",\"accessToken\":", StringComparison.Ordinal),
            Login[..^1] + ",\"unknown\":true}", new string('x', 65537)
        }) await Reject(new ProtocolHandler { LoginDocument = invalid });
        await Reject(new ProtocolHandler { LoginBytes = [0x7b, 0xff, 0x7d] });
        await Reject(new ProtocolHandler { LoginDocument = new string('x', 65537), UnknownLength = true });

        foreach (var invalid in new[]
        {
            "[]", "{}", TokenDocument().Replace(Enrollment, "bad", StringComparison.Ordinal),
            TokenDocument().Replace(Enrollment, new string('G', 64), StringComparison.Ordinal),
            TokenDocument().Replace("11111111-1111-4111-8111-111111111111", Guid.Empty.ToString("D"), StringComparison.Ordinal),
            TokenDocument().Replace("22222222-2222-4222-8222-222222222222", "other", StringComparison.Ordinal),
            TokenDocument().Replace("\"token\":", "\"token\":\"first\",\"token\":", StringComparison.Ordinal),
            TokenDocument()[..^1] + ",\"other\":true}",
            TokenDocument().Replace(DateTimeOffset.UtcNow.Year.ToString(), "2000", StringComparison.Ordinal),
            TokenDocument().Replace(DateTimeOffset.UtcNow.Year.ToString(), "2099", StringComparison.Ordinal), new string('x', 4097)
        }) await Reject(new ProtocolHandler { EnrollmentDocument = invalid });
        await Reject(new ProtocolHandler { EnrollmentStatus = HttpStatusCode.Forbidden });
        await Reject(new ProtocolHandler { EnrollmentDocument = new string('x', 4097), UnknownLength = true });
        var thrown = new ProtocolHandler { ThrowAfterPassword = true }; await Reject(thrown);
        Ensure(thrown.Paths.Count == 1, "transport failure cannot retry a password");
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel(); var before = new ProtocolHandler(); await Reject(before, token: canceled.Token);
            Ensure(before.Paths.Count == 0, "initial cancellation sends no request");
        }
        using (var canceled = new CancellationTokenSource(TimeSpan.FromMilliseconds(40)))
            await Reject(new ProtocolHandler { StallBody = true }, token: canceled.Token);
        using (var issuer = new HttpSetupEnrollmentIssuer(new Trust(), new ProtocolHandler()))
        {
            var rejected = false;
            try { await issuer.IssueAsync("user\n", Password.AsMemory(), CancellationToken.None); }
            catch (InvalidDataException) { rejected = true; }
            Ensure(rejected, "invalid credentials never enter protocol");
        }
        return checks;
    }

    private sealed class Trust(params bool[] states) : ICoreEndpointTrust
    {
        public int Calls { get; private set; }
        public Task<bool> IsTrustedAsync(Uri origin, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (origin.AbsoluteUri != "http://127.0.0.1:5000/") throw new InvalidOperationException("Origin changed.");
            var index = Calls++;
            return Task.FromResult(states.Length == 0 || states[Math.Min(index, states.Length - 1)]);
        }
    }
    private sealed class ProtocolHandler : HttpMessageHandler
    {
        public HttpStatusCode LoginStatus { get; init; } = HttpStatusCode.OK;
        public HttpStatusCode EnrollmentStatus { get; init; } = HttpStatusCode.OK;
        public string LoginDocument { get; init; } = Login;
        public byte[]? LoginBytes { get; init; }
        public string EnrollmentDocument { get; init; } = TokenDocument();
        public string LoginMediaType { get; init; } = "application/json";
        public bool UnknownLength { get; init; }
        public bool StallBody { get; init; }
        public bool ThrowAfterPassword { get; init; }
        public bool Disposed { get; private set; }
        public string? LoginBody { get; private set; }
        public byte[]? PasswordBuffer { get; private set; }
        public List<string> Paths { get; } = [];
        public List<string?> Authorizations { get; } = [];
        public List<ResponseStream> ResponseStreams { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Method != HttpMethod.Post || request.RequestUri?.GetLeftPart(UriPartial.Authority) != "http://127.0.0.1:5000" ||
                request.Headers.Accept.Single().MediaType != "application/json") throw new InvalidOperationException("Request contract changed.");
            var path = request.RequestUri.AbsolutePath; Paths.Add(path); Authorizations.Add(request.Headers.Authorization?.ToString());
            var login = path == "/api/auth/login";
            if (login)
            {
                using var sink = new CaptureStream(); await request.Content!.CopyToAsync(sink, token);
                PasswordBuffer = sink.Backing; LoginBody = Encoding.UTF8.GetString(sink.ToArray());
                if (ThrowAfterPassword) throw new IOException("Synthetic transport failure.");
            }
            else if (request.Content is not null || path != "/api/admin/enrollment-tokens") throw new InvalidOperationException("Token request gained a body or endpoint override.");
            var bytes = login ? LoginBytes ?? Encoding.UTF8.GetBytes(LoginDocument) : Encoding.UTF8.GetBytes(EnrollmentDocument);
            var stream = new ResponseStream(bytes, UnknownLength, StallBody); ResponseStreams.Add(stream);
            var content = new StreamContent(stream);
            content.Headers.ContentType = new MediaTypeHeaderValue(login ? LoginMediaType : "application/json");
            return new HttpResponseMessage(login ? LoginStatus : EnrollmentStatus) { Content = content };
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class CaptureStream : MemoryStream
    {
        public byte[]? Backing { get; private set; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (MemoryMarshal.TryGetArray(buffer, out var segment)) Backing = segment.Array;
            return base.WriteAsync(buffer, token);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            Backing = buffer; return base.WriteAsync(buffer, offset, count, token);
        }
    }
    private sealed class ResponseStream(byte[] bytes, bool unknownLength, bool stall) : MemoryStream(bytes, writable: false)
    {
        public byte[]? ReadBuffer { get; private set; }
        public override bool CanSeek => !unknownLength;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) ReadBuffer = segment.Array;
            if (stall) await Task.Delay(Timeout.Infinite, token);
            return await base.ReadAsync(buffer, token);
        }
    }
}
