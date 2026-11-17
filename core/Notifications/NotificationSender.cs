using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Notifications;

namespace SentinelAI.Core.Notifications;

/// <summary>Deliberately narrow HTTPS and authenticated STARTTLS transports. No templates or raw finding text.</summary>
internal sealed class NotificationSender : INotificationSender
{
    private readonly Func<string, int, CancellationToken, Task<Stream>> _connect;
    private readonly Func<Stream, string, CancellationToken, Task<Stream>> _tls;
    private readonly Func<HttpMessageHandler>? _httpHandler;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public NotificationSender() : this(NotificationNetwork.ConnectAsync, AuthenticateTlsAsync, null) { }

    // In-memory protocol fixtures only; production DI uses the parameterless constructor above.
    internal NotificationSender(Func<string, int, CancellationToken, Task<Stream>> connect,
        Func<Stream, string, CancellationToken, Task<Stream>> tls, Func<HttpMessageHandler>? httpHandler)
    { _connect = connect; _tls = tls; _httpHandler = httpHandler; }

    public async Task<NotificationSendResult> SendAsync(NotificationPayload payload, NotificationDestination destination,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(25));
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, Json);
            try
            {
                if (bytes.Length > 16 * 1024) return new(false, false, "payloadRejected");
                return destination.Channel switch
                {
                    "webhook" => await SendWebhookAsync(payload.NotificationId, bytes, destination, deadline.Token),
                    "email" => await SendEmailAsync(payload.NotificationId, bytes, destination, deadline.Token),
                    _ => new(false, false, "channelRejected")
                };
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return new(false, true, "timeout"); }
        catch (OperationCanceledException) { throw; }
        catch (NotificationDestinationRejectedException) { return new(false, false, "destinationRejected"); }
        catch (AuthenticationException) { return new(false, false, "tlsRejected"); }
        catch (SmtpProtocolException exception) { return new(false, exception.Retryable, exception.Code); }
        catch (HttpRequestException exception) when (HasDestinationRejection(exception))
        { return new(false, false, "destinationRejected"); }
        catch (HttpRequestException exception) when (exception.HttpRequestError == HttpRequestError.SecureConnectionError)
        { return new(false, false, "tlsRejected"); }
        catch (Exception exception) when (exception is IOException or HttpRequestException or System.Net.Sockets.SocketException)
        { return new(false, true, "connectionFailed"); }
        catch (Exception) { return new(false, false, "transportRejected"); }
    }

    private async Task<NotificationSendResult> SendWebhookAsync(Guid id, byte[] body, NotificationDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.WebhookUri is not { } uri || !NotificationNetwork.IsValidWebhookUri(uri))
            return new(false, false, "destinationRejected");
        using var handler = _httpHandler?.Invoke() ?? new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 16, MaxResponseDrainSize = 0, ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (context, token) => await _connect(context.DnsEndPoint.Host, context.DnsEndPoint.Port, token),
            SslOptions = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 }
        };
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        { Content = new ByteArrayContent(body), Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        request.Headers.Add("Idempotency-Key", id.ToString("D"));
        if (destination.WebhookSecret is { Length: > 0 } secret)
        {
            var mac = HMACSHA256.HashData(secret, body);
            try { request.Headers.Add("X-SentinelAI-Signature", "sha256=" + Convert.ToHexStringLower(mac)); }
            finally { CryptographicOperations.ZeroMemory(mac); }
        }
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // The response body is never needed, read, logged or buffered. Redirects are never followed.
        var code = (int)response.StatusCode;
        return code is >= 200 and <= 299 ? new(true, false, "delivered") :
            new(false, code is 408 or 429 || code >= 500, "httpRejected");
    }

    private async Task<NotificationSendResult> SendEmailAsync(Guid id, byte[] body, NotificationDestination destination,
        CancellationToken cancellationToken)
    {
        if (!NotificationNetwork.IsValidHost(destination.SmtpHost) || destination.SmtpPort != 587 ||
            !NotificationNetwork.IsValidMailbox(destination.EmailFrom) || !NotificationNetwork.IsValidMailbox(destination.EmailTo) ||
            destination.SmtpUsername is not { Length: > 0 and <= 254 } username || username.Any(char.IsControl) ||
            destination.SmtpPassword is not { Length: >= 8 and <= 2048 } password)
            return new(false, false, "destinationRejected");
        await using var connection = await _connect(destination.SmtpHost!, 587, cancellationToken);
        Require(await ReadReplyAsync(connection, cancellationToken), 220);
        await WriteLineAsync(connection, "EHLO sentinelai.local", cancellationToken);
        var hello = await ReadReplyAsync(connection, cancellationToken); Require(hello, 250);
        if (!hello.Lines.Any(line => line.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase)))
            throw new SmtpProtocolException(false, "tlsRequired");
        await WriteLineAsync(connection, "STARTTLS", cancellationToken);
        Require(await ReadReplyAsync(connection, cancellationToken), 220);
        await using var tls = await _tls(connection, destination.SmtpHost!, cancellationToken);
        await WriteLineAsync(tls, "EHLO sentinelai.local", cancellationToken);
        hello = await ReadReplyAsync(tls, cancellationToken); Require(hello, 250);
        var authentication = hello.Lines.Where(line => line.StartsWith("AUTH ", StringComparison.OrdinalIgnoreCase))
            .SelectMany(line => line[5..].Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray();
        if (authentication.Contains("PLAIN", StringComparer.OrdinalIgnoreCase))
        {
            var user = Encoding.UTF8.GetBytes(username);
            var credentials = new byte[user.Length + password.Length + 2];
            try
            {
                user.CopyTo(credentials, 1); password.CopyTo(credentials, user.Length + 2);
                await WriteSecretAsync(tls, "AUTH PLAIN ", credentials, cancellationToken);
            }
            finally { CryptographicOperations.ZeroMemory(user); CryptographicOperations.ZeroMemory(credentials); }
            Require(await ReadReplyAsync(tls, cancellationToken), 235);
        }
        else if (authentication.Contains("LOGIN", StringComparer.OrdinalIgnoreCase))
        {
            await WriteLineAsync(tls, "AUTH LOGIN", cancellationToken); Require(await ReadReplyAsync(tls, cancellationToken), 334);
            var user = Encoding.UTF8.GetBytes(username);
            try { await WriteSecretAsync(tls, "", user, cancellationToken); }
            finally { CryptographicOperations.ZeroMemory(user); }
            Require(await ReadReplyAsync(tls, cancellationToken), 334);
            await WriteSecretAsync(tls, "", password, cancellationToken); Require(await ReadReplyAsync(tls, cancellationToken), 235);
        }
        else throw new SmtpProtocolException(false, "authenticationUnsupported");
        await WriteLineAsync(tls, "MAIL FROM:<" + destination.EmailFrom + ">", cancellationToken);
        Require(await ReadReplyAsync(tls, cancellationToken), 250);
        await WriteLineAsync(tls, "RCPT TO:<" + destination.EmailTo + ">", cancellationToken);
        Require(await ReadReplyAsync(tls, cancellationToken), 250, 251);
        await WriteLineAsync(tls, "DATA", cancellationToken); Require(await ReadReplyAsync(tls, cancellationToken), 354);
        var message = Encoding.ASCII.GetBytes("From: " + destination.EmailFrom + "\r\nTo: " + destination.EmailTo +
            "\r\nDate: " + DateTimeOffset.UtcNow.ToString("r", System.Globalization.CultureInfo.InvariantCulture) +
            "\r\nSubject: SentinelAI security notification\r\nMessage-ID: <" + id.ToString("N") +
            "@sentinelai.local>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
            Convert.ToBase64String(body, Base64FormattingOptions.InsertLineBreaks) + "\r\n.\r\n");
        try { await tls.WriteAsync(message, cancellationToken); await tls.FlushAsync(cancellationToken); }
        finally { CryptographicOperations.ZeroMemory(message); }
        Require(await ReadReplyAsync(tls, cancellationToken), 250);
        // A successful DATA response is the delivery acknowledgement; QUIT cannot undo it.
        return new(true, false, "delivered");
    }

    private static async Task<Stream> AuthenticateTlsAsync(Stream stream, string host, CancellationToken cancellationToken)
    {
        var tls = new SslStream(stream, leaveInnerStreamOpen: true);
        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            { TargetHost = host, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 }, cancellationToken);
            return tls;
        }
        catch { await tls.DisposeAsync(); throw; }
    }

    private static bool HasDestinationRejection(Exception exception)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            if (exception is NotificationDestinationRejectedException) return true;
            if (exception.InnerException is not { } inner) return false;
            exception = inner;
        }
        return false;
    }

    private sealed record SmtpReply(int Code, IReadOnlyList<string> Lines);
    private sealed class SmtpProtocolException(bool retryable, string code) : Exception
    { public bool Retryable { get; } = retryable; public string Code { get; } = code; }

    private static void Require(SmtpReply reply, params int[] expected)
    {
        if (!expected.Contains(reply.Code)) throw new SmtpProtocolException(reply.Code is >= 400 and <= 499, "smtpRejected");
    }

    private static async Task<SmtpReply> ReadReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lines = new List<string>(); var code = 0; var one = new byte[1];
        for (var count = 0; count < 32; count++)
        {
            var buffer = new byte[512]; var length = 0;
            while (true)
            {
                if (length == buffer.Length || await stream.ReadAsync(one, cancellationToken) != 1)
                    throw new SmtpProtocolException(false, "protocolRejected");
                var value = one[0];
                if (value == 13)
                {
                    if (await stream.ReadAsync(one, cancellationToken) != 1 || one[0] != 10)
                        throw new SmtpProtocolException(false, "protocolRejected");
                    break;
                }
                if (value is < 32 or > 126) throw new SmtpProtocolException(false, "protocolRejected");
                buffer[length++] = value;
            }
            if (length < 4 || buffer[0] is < 50 or > 53 || buffer[1] is < 48 or > 57 || buffer[2] is < 48 or > 57 || buffer[3] is not (32 or 45))
                throw new SmtpProtocolException(false, "protocolRejected");
            var current = (buffer[0] - 48) * 100 + (buffer[1] - 48) * 10 + buffer[2] - 48;
            if (count > 0 && current != code) throw new SmtpProtocolException(false, "protocolRejected");
            code = current; lines.Add(Encoding.ASCII.GetString(buffer, 4, length - 4));
            if (buffer[3] == 32) return new(code, lines);
        }
        throw new SmtpProtocolException(false, "protocolRejected");
    }

    private static async Task WriteLineAsync(Stream stream, string value, CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(value + "\r\n");
        try { await stream.WriteAsync(bytes, cancellationToken); await stream.FlushAsync(cancellationToken); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static async Task WriteSecretAsync(Stream stream, string prefix, byte[] value, CancellationToken cancellationToken)
    {
        var prefixBytes = Encoding.ASCII.GetBytes(prefix);
        var encoded = new byte[prefixBytes.Length + 4 * ((value.Length + 2) / 3) + 2];
        try
        {
            prefixBytes.CopyTo(encoded, 0);
            var status = System.Buffers.Text.Base64.EncodeToUtf8(value, encoded.AsSpan(prefixBytes.Length), out _, out var written);
            if (status != System.Buffers.OperationStatus.Done) throw new SmtpProtocolException(false, "protocolRejected");
            encoded[prefixBytes.Length + written] = 13; encoded[prefixBytes.Length + written + 1] = 10;
            await stream.WriteAsync(encoded, cancellationToken); await stream.FlushAsync(cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }
}
