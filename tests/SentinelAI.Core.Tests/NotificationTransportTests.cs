using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Core.Notifications;

internal static class NotificationTransportTests
{
    private static int _checks;
    private static void Check(bool condition, string code)
    { _checks++; if (!condition) throw new InvalidOperationException("Notification transport: " + code); }

    internal static async Task RunAsync()
    {
        foreach (var value in new[] { "0.1.2.3", "10.2.3.4", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
            "192.168.0.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.1.1", "198.51.100.2", "203.0.113.2",
            "224.0.0.1", "255.255.255.255", "100.64.0.1", "100.127.255.254", "::", "::1", "fe80::1", "fc00::1", "ff02::1",
            "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001::1", "2001:2::1", "2001:db8::1", "2002:a00:1::1", "3fff::1" })
            Check(!NotificationNetwork.IsPublicAddress(IPAddress.Parse(value)), "nonpublic-address-refused");
        foreach (var value in new[] { "8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8" })
            Check(NotificationNetwork.IsPublicAddress(IPAddress.Parse(value)), "public-address-allowed");
        foreach (var host in new[] { "localhost", "printer.local", "a.internal", "a.home.arpa", "a.invalid", "a.test", "example.com.", " example.com", "127.1", "2130706433", "0x7f000001", "fe80::1%2" })
            Check(!NotificationNetwork.IsValidHost(host), "unsafe-host-refused");
        foreach (var uri in new[] { "http://example.com/a", "https://user:pass@example.com/a", "https://example.com:444/a", "https://example.com/a#secret", "https://127.0.0.1/a" })
            Check(!NotificationNetwork.IsValidWebhookUri(new Uri(uri)), "unsafe-uri-refused");
        Check(NotificationNetwork.IsValidWebhookUri(new Uri("https://example.com/private-token?access=synthetic")), "protected-token-url-supported");
        foreach (var mailbox in new[] { "Name <one@example.com>", "one@example.com\r\nBcc: other@example.com", "one@example.com,other@example.com", " one@example.com", "" })
            Check(!NotificationNetwork.IsValidMailbox(mailbox), "header-injection-refused");
        Check(NotificationNetwork.IsValidMailbox("one@example.com"), "mailbox-allowed");

        var connections = 0;
        Task<Stream> Connect(IPAddress address, int port, CancellationToken token)
        { connections++; Check(address.Equals(IPAddress.Parse("8.8.8.8")) && port == 443, "socket-pins-checked-ip"); return Task.FromResult<Stream>(new MemoryStream()); }
        foreach (var addresses in new[] { Array.Empty<IPAddress>(), new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Loopback }, Enumerable.Repeat(IPAddress.Parse("8.8.8.8"), 17).ToArray() })
        {
            try { using var stream = await NotificationNetwork.ConnectResolvedAsync(addresses, 443, Connect, default); Check(false, "mixed-answer-accepted"); }
            catch (NotificationDestinationRejectedException) { Check(connections == 0, "dns-validation-before-connect"); }
        }
        using (await NotificationNetwork.ConnectResolvedAsync([IPAddress.Parse("8.8.8.8")], 443, Connect, default)) { }
        Check(connections == 1, "one-pinned-connect");

        var payload = new NotificationPayload("sentinelai-notification-v1", Guid.NewGuid(), "criticalAlert", Guid.NewGuid(),
            Guid.NewGuid(), "SA-TEST", "critical", 2, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        var secret = Encoding.UTF8.GetBytes("synthetic-webhook-secret-not-production");
        foreach (var status in new[] { 200, 202, 204, 301, 400, 401, 408, 429, 500 })
        {
            var handler = new WebhookFixture(status, payload, secret);
            var sender = new NotificationSender((_, _, _) => throw new InvalidOperationException(), (_, _, _) => throw new InvalidOperationException(), () => handler);
            using var destination = new NotificationDestination("webhook", new Uri("https://example.com/token"), secret.ToArray());
            var result = await sender.SendAsync(payload, destination, default);
            Check(result.Succeeded == (status is >= 200 and < 300), "http-status-success");
            Check(result.Retryable == (status is 408 or 429 or >= 500), "http-status-retry");
            Check(handler.Calls == 1, "one-webhook-attempt-no-redirect");
        }
        using (var destination = new NotificationDestination("webhook", new Uri("https://127.0.0.1/a")))
        {
            var sender = new NotificationSender((_, _, _) => throw new InvalidOperationException(), (_, _, _) => throw new InvalidOperationException(),
                () => throw new InvalidOperationException());
            var result = await sender.SendAsync(payload, destination, default);
            Check(result is { Succeeded: false, Retryable: false, Code: "destinationRejected" }, "destination-before-http");
        }
        {
            var sender = new NotificationSender((_, _, _) => throw new InvalidOperationException(), (_, _, _) => throw new InvalidOperationException(), () => new RejectedDns());
            using var destination = new NotificationDestination("webhook", new Uri("https://example.com/a"));
            var result = await sender.SendAsync(payload, destination, default);
            Check(result is { Retryable: false, Code: "destinationRejected" }, "wrapped-dns-rejection-permanent");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            try { await sender.SendAsync(payload, destination, cancelled.Token); Check(false, "caller-cancellation-swallowed"); }
            catch (OperationCanceledException) { Check(true, "caller-cancellation-propagated"); }
        }
        await SmtpAsync(payload, "220 fixture\r\n250-fixture\r\n250 STARTTLS\r\n220 begin\r\n250-fixture\r\n250 AUTH PLAIN\r\n235 accepted\r\n250 sender\r\n250 recipient\r\n354 data\r\n250 queued\r\n", true, "delivered");
        await SmtpAsync(payload, "220 fixture\r\n250 STARTTLS\r\n220 begin\r\n250 AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n235 accepted\r\n250 sender\r\n251 recipient\r\n354 data\r\n250 queued\r\n", true, "delivered");
        await SmtpAsync(payload, "220 fixture\r\n250 no-upgrade\r\n", false, "tlsRequired");
        await SmtpAsync(payload, "220 fixture\r\n250 STARTTLS\r\n220 begin\r\n", false, "tlsRejected", tlsFailure: true);
        await SmtpAsync(payload, "220 fixture\r\n250 STARTTLS\r\n220 begin\r\n250 AUTH PLAIN\r\n535 rejected\r\n", false, "smtpRejected");
        await SmtpAsync(payload, "421 temporary\r\n", false, "smtpRejected", retryable: true);
        await SmtpAsync(payload, "220-hello\r\n250 different-code\r\n", false, "protocolRejected");
        await SmtpAsync(payload, "220 " + new string('x', 513) + "\r\n", false, "protocolRejected");
        await SmtpAsync(payload, string.Concat(Enumerable.Repeat("220-more\r\n", 33)), false, "protocolRejected");
        await SmtpAsync(payload, "220 bare-newline\n", false, "protocolRejected");
        var ownedSecret = secret.ToArray(); var ownedPassword = secret.ToArray();
        new NotificationDestination("email", WebhookSecret: ownedSecret, SmtpPassword: ownedPassword).Dispose();
        Check(ownedSecret.All(b => b == 0) && ownedPassword.All(b => b == 0), "attempt-secrets-cleared");
        CryptographicOperations.ZeroMemory(secret);
        Console.WriteLine($"Notification transport tests passed: {_checks} checks (synthetic memory transports only).");
    }

    private static async Task SmtpAsync(NotificationPayload payload, string replies, bool succeeded, string code,
        bool tlsFailure = false, bool retryable = false)
    {
        using var stream = new SmtpFixture(replies);
        var tlsEstablished = false;
        var sender = new NotificationSender((host, port, token) =>
        { Check(host == "smtp.example.com" && port == 587, "fixed-starttls-port"); return Task.FromResult<Stream>(stream); },
            (inner, host, token) =>
            {
                Check(ReferenceEquals(inner, stream) && host == "smtp.example.com", "tls-validates-original-host");
                if (tlsFailure) throw new AuthenticationException();
                tlsEstablished = true; return Task.FromResult<Stream>(stream);
            }, null);
        using var destination = new NotificationDestination("email", SmtpHost: "smtp.example.com", SmtpUsername: "synthetic-user",
            SmtpPassword: Encoding.UTF8.GetBytes("synthetic-password-not-production"), EmailFrom: "core@example.com", EmailTo: "owner@example.com");
        var result = await sender.SendAsync(payload, destination, default);
        Check(result.Succeeded == succeeded && result.Code == code && result.Retryable == retryable, "smtp-classified-result");
        var commands = Encoding.ASCII.GetString(stream.Written.ToArray());
        Check(!commands.Contains("AUTH ", StringComparison.Ordinal) || tlsEstablished, "credentials-require-verified-tls");
        if (succeeded)
        {
            Check(commands.Contains("MAIL FROM:<core@example.com>\r\nRCPT TO:<owner@example.com>\r\nDATA\r\n", StringComparison.Ordinal), "bounded-envelope");
            Check(commands.Contains("Message-ID: <" + payload.NotificationId.ToString("N"), StringComparison.Ordinal), "stable-message-id");
            Check(!commands.Contains("synthetic-password", StringComparison.Ordinal), "no-cleartext-password-command");
            var encoded = commands.Split("\r\n\r\n", 2)[1].Split("\r\n.\r\n", 2)[0];
            using var decoded = JsonDocument.Parse(Convert.FromBase64String(encoded));
            Check(decoded.RootElement.GetProperty("notificationId").GetGuid() == payload.NotificationId, "minimal-json-email");
        }
    }

    private sealed class WebhookFixture(int status, NotificationPayload payload, byte[] secret) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Check(request.Method == HttpMethod.Post && request.RequestUri?.Scheme == "https", "https-post");
            Check(request.Headers.GetValues("Idempotency-Key").Single() == payload.NotificationId.ToString("D"), "stable-webhook-id");
            var body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            Check(request.Headers.GetValues("X-SentinelAI-Signature").Single() == "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(secret, body)), "signature-authenticates-exact-body");
            using var json = JsonDocument.Parse(body);
            Check(!json.RootElement.TryGetProperty("endpointName", out _) && !json.RootElement.TryGetProperty("evidence", out _), "payload-minimizes-customer-context");
            return new((HttpStatusCode)status) { Content = new StreamContent(new UnreadResponse()), Headers = { Location = new Uri("https://127.0.0.1/") } };
        }
    }

    private sealed class UnreadResponse : MemoryStream
    {
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("Response body must not be read.");
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Response body must not be read.");
    }

    private sealed class RejectedDns : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new HttpRequestException("Synthetic connection failure.", new NotificationDestinationRejectedException());
        }
    }

    private sealed class SmtpFixture(string replies) : Stream
    {
        private readonly MemoryStream _input = new(Encoding.ASCII.GetBytes(replies));
        public MemoryStream Written { get; } = new();
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _input.ReadAsync(buffer, cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => Written.WriteAsync(buffer, cancellationToken);
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
