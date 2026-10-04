using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

/// <summary>
/// Authenticates only with a composition-selected, trusted Core origin. Passwords are
/// borrowed for one request; bearer material stays private, in memory, for at most 15 minutes.
/// </summary>
public sealed partial class HttpAuthenticationClient : IAuthenticationClient, IDevicesClient, IAlertsClient
{
    private const int MaximumUsernameCharacters = 256;
    private const int MaximumPasswordCharacters = 1024;
    private const int MaximumResponseBytes = 64 * 1024;
    private const int MaximumTokenCharacters = 8192;
    private static readonly Uri DefaultOrigin = new("http://127.0.0.1:5000/");
    private readonly object _gate = new();
    private readonly HttpClient _http;
    private readonly ICoreEndpointTrust _trust;
    private readonly Uri _origin;
    private readonly TimeProvider _time;
    private CancellationTokenSource _generationCancellation = new();
    private long _generation;
    private byte[]? _token;
    private string? _username;
    private DateTimeOffset _expiresAt;
    private bool _disposed;

    public HttpAuthenticationClient(ICoreEndpointTrust trust)
        : this(trust, new HttpClientHandler())
    {
    }

    /// <summary>Injection is for trusted composition and tests; no destination comes from user input.</summary>
    public HttpAuthenticationClient(ICoreEndpointTrust trust, HttpMessageHandler handler,
        Uri? trustedOrigin = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(handler);
        _origin = trustedOrigin ?? DefaultOrigin;
        ValidateOrigin(_origin);
        _trust = trust;
        _time = timeProvider ?? TimeProvider.System;
        if (handler is HttpClientHandler httpHandler)
        {
            httpHandler.AllowAutoRedirect = false;
            httpHandler.UseProxy = false;
            httpHandler.UseCookies = false;
            httpHandler.UseDefaultCredentials = false;
            httpHandler.Credentials = null;
        }
        else if (handler is SocketsHttpHandler socketsHandler)
        {
            socketsHandler.AllowAutoRedirect = false;
            socketsHandler.UseProxy = false;
            socketsHandler.UseCookies = false;
            socketsHandler.Credentials = null;
        }
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task<AuthenticationResult> SignInAsync(string username, ReadOnlyMemory<char> password,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = BeginOperation(invalidateSession: true, cancellationToken);
        if (operation is null)
            return new(AuthenticationOutcome.Unavailable);
        username = username?.Trim() ?? string.Empty;
        if (!ValidUsername(username) || password.Length is < 1 or > MaximumPasswordCharacters)
            return new(AuthenticationOutcome.InvalidCredentials);
        operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(15));
        var startedAt = _time.GetUtcNow();
        byte[]? candidateToken = null;
        using var requestBuffer = new RequestBuffer();
        try
        {
            if (!await _trust.IsTrustedAsync(_origin, operation.Token).ConfigureAwait(false))
                return new(AuthenticationOutcome.UntrustedConnection);
            operation.Token.ThrowIfCancellationRequested();

            using (var writer = new Utf8JsonWriter(requestBuffer))
            {
                writer.WriteStartObject();
                writer.WriteString("username", username);
                writer.WriteString("password", password.Span);
                writer.WriteEndObject();
                writer.Flush();
            }
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_origin, "api/auth/login"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = new ByteArrayContent(requestBuffer.Buffer, 0, requestBuffer.Length);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                operation.Token).ConfigureAwait(false);
            // Request content has completed transmission; erase the owned password bytes
            // before reading or validating any response or making a bearer request.
            requestBuffer.Clear();
            operation.Token.ThrowIfCancellationRequested();
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                return new(AuthenticationOutcome.InvalidCredentials);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return new(AuthenticationOutcome.Throttled);
            if (response.StatusCode != HttpStatusCode.OK)
                return new(AuthenticationOutcome.Unavailable);

            DateTimeOffset expiresAt;
            using (var json = await ReadJsonAsync(response, operation.Token).ConfigureAwait(false))
            {
                var properties = ReadProperties(json.Document.RootElement,
                    ["tokenType", "accessToken", "expiresIn", "refreshToken"]);
                if (!properties.TryGetValue("tokenType", out var tokenType) || tokenType.ValueKind != JsonValueKind.String ||
                    !string.Equals(tokenType.GetString(), "Bearer", StringComparison.OrdinalIgnoreCase) ||
                    !properties.TryGetValue("accessToken", out var token) || token.ValueKind != JsonValueKind.String ||
                    !properties.TryGetValue("expiresIn", out var expiry) || expiry.ValueKind != JsonValueKind.Number ||
                    !expiry.TryGetInt64(out var seconds) || seconds <= 0 ||
                    properties.TryGetValue("refreshToken", out var refresh) && refresh.ValueKind != JsonValueKind.String)
                    return new(AuthenticationOutcome.InvalidResponse);
                var tokenText = token.GetString()!;
                if (tokenText.Length is < 1 or > MaximumTokenCharacters ||
                    tokenText.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_' and not '.'))
                    return new(AuthenticationOutcome.InvalidResponse);
                candidateToken = Encoding.ASCII.GetBytes(tokenText);
                expiresAt = startedAt.AddSeconds(Math.Min(seconds, 900));
                // The refresh token is deliberately never extracted or retained.
            }

            var session = await ReadSessionAsync(candidateToken, operation.Token).ConfigureAwait(false);
            if (session.Status != SessionStatus.Authenticated)
                return new(session.Status == SessionStatus.UntrustedConnection
                    ? AuthenticationOutcome.UntrustedConnection : AuthenticationOutcome.Unavailable);
            lock (_gate)
            {
                if (_disposed || operation.Generation != _generation || operation.Token.IsCancellationRequested ||
                    _time.GetUtcNow() >= expiresAt)
                    return new(AuthenticationOutcome.Unavailable);
                _token = candidateToken;
                candidateToken = null;
                _username = session.Username;
                _expiresAt = expiresAt;
                return new(AuthenticationOutcome.Authenticated, _username);
            }
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(AuthenticationOutcome.Unavailable);
        }
        catch (InvalidResponseException)
        {
            return new(AuthenticationOutcome.InvalidResponse);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(AuthenticationOutcome.Unavailable);
        }
        finally
        {
            if (candidateToken is not null)
                CryptographicOperations.ZeroMemory(candidateToken);
            requestBuffer.Clear();
        }
    }

    public async Task<SessionResult> ValidateSessionAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = BeginOperation(invalidateSession: false, cancellationToken);
        if (operation is null)
            return new(SessionStatus.SignedOut);
        byte[] token;
        lock (_gate)
        {
            if (_token is null)
                return new(SessionStatus.SignedOut);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(SessionStatus.Expired);
            }
            token = _token.ToArray();
        }
        operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(3));
        SessionResult result;
        try
        {
            result = await ReadSessionAsync(token, operation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            result = new(SessionStatus.Unavailable);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            result = new(SessionStatus.Unavailable);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(token);
        }
        lock (_gate)
        {
            if (_disposed || operation.Generation != _generation)
                return new(SessionStatus.SignedOut);
            if (result.Status != SessionStatus.Authenticated)
            {
                ResetGenerationLocked();
                return result;
            }
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(SessionStatus.Expired);
            }
            // The bearer cannot change its administrator identity during a session.
            if (!string.Equals(result.Username, _username, StringComparison.Ordinal))
            {
                ResetGenerationLocked();
                return new(SessionStatus.Unavailable);
            }
            return new(SessionStatus.Authenticated, _username);
        }
    }

    private async Task<SessionResult> ReadSessionAsync(byte[] token, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        if (!await _trust.IsTrustedAsync(_origin, deadline.Token).ConfigureAwait(false))
            return new(SessionStatus.UntrustedConnection);
        deadline.Token.ThrowIfCancellationRequested();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, "api/admin/me"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
            .ConfigureAwait(false);
        deadline.Token.ThrowIfCancellationRequested();
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            return new(SessionStatus.Expired);
        if (response.StatusCode != HttpStatusCode.OK)
            return new(SessionStatus.Unavailable);
        using var json = await ReadJsonAsync(response, deadline.Token).ConfigureAwait(false);
        var properties = ReadProperties(json.Document.RootElement, ["username", "role"]);
        if (!properties.TryGetValue("username", out var username) || username.ValueKind != JsonValueKind.String ||
            !properties.TryGetValue("role", out var role) || role.ValueKind != JsonValueKind.String ||
            role.GetString() != "administrator" || !ValidUsername(username.GetString()))
            throw new InvalidResponseException();
        return new(SessionStatus.Authenticated, username.GetString());
    }

    private static Dictionary<string, JsonElement> ReadProperties(JsonElement root, string[] allowed)
    {
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidResponseException();
        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!allowed.Contains(property.Name, StringComparer.Ordinal) || !properties.TryAdd(property.Name, property.Value))
                throw new InvalidResponseException();
        return properties;
    }

    private static async Task<BufferedJson> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentLength > MaximumResponseBytes)
            throw new InvalidResponseException();
        var buffer = new byte[MaximumResponseBytes + 1];
        try
        {
            using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var length = 0;
            while (length < buffer.Length)
            {
                var count = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                length += count;
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (length > MaximumResponseBytes)
                throw new InvalidResponseException();
            return new BufferedJson(buffer, JsonDocument.Parse(buffer.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 4 }));
        }
        catch (JsonException)
        {
            CryptographicOperations.ZeroMemory(buffer);
            throw new InvalidResponseException();
        }
        catch
        {
            CryptographicOperations.ZeroMemory(buffer);
            throw;
        }
    }

    private Operation? BeginOperation(bool invalidateSession, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_disposed) return null;
            if (invalidateSession) ResetGenerationLocked();
            return new Operation(_generation,
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
        }
    }

    private void ResetGenerationLocked()
    {
        _generation++;
        if (_token is not null) CryptographicOperations.ZeroMemory(_token);
        _token = null;
        _username = null;
        _expiresAt = default;
        _generationCancellation.Cancel();
        _generationCancellation.Dispose();
        _generationCancellation = new CancellationTokenSource();
    }

    public void SignOut()
    {
        lock (_gate)
            if (!_disposed) ResetGenerationLocked();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ResetGenerationLocked();
            _generationCancellation.Dispose();
        }
        _http.Dispose();
    }

    private static bool ValidUsername(string? username) =>
        !string.IsNullOrWhiteSpace(username) && username.Length <= MaximumUsernameCharacters && !username.Any(char.IsControl);

    private static void ValidateOrigin(Uri origin)
    {
        if (!origin.IsAbsoluteUri || origin.Scheme is not "http" and not "https" || origin.AbsolutePath != "/" ||
            origin.Port < 1 || origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0 ||
            origin.Scheme == "http" && (!IPAddress.TryParse(origin.Host, out var address) || !IPAddress.IsLoopback(address)))
            throw new ArgumentException("Authentication requires a trusted HTTPS origin or a literal loopback HTTP origin.", nameof(origin));
    }

    private sealed class Operation(long generation, CancellationTokenSource cancellation) : IDisposable
    {
        internal long Generation { get; } = generation;
        internal CancellationTokenSource Cancellation { get; } = cancellation;
        internal CancellationToken Token => Cancellation.Token;
        public void Dispose() => Cancellation.Dispose();
    }

    private sealed class BufferedJson(byte[] buffer, JsonDocument document) : IDisposable
    {
        internal JsonDocument Document { get; } = document;
        public void Dispose()
        {
            Document.Dispose();
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    // The writer writes directly into this owned array. Its entire capacity is erased,
    // including any uncommitted bytes if serialization or transmission is interrupted.
    private sealed class RequestBuffer : IBufferWriter<byte>, IDisposable
    {
        internal byte[] Buffer { get; } = new byte[16 * 1024];
        internal int Length { get; private set; }
        public void Advance(int count)
        {
            if (count < 0 || count > Buffer.Length - Length) throw new InvalidOperationException();
            Length += count;
        }
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            if (sizeHint < 0 || sizeHint > Buffer.Length - Length) throw new InvalidOperationException();
            return Buffer.AsMemory(Length);
        }
        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;
        internal void Clear() => CryptographicOperations.ZeroMemory(Buffer);
        public void Dispose() => Clear();
    }

    private sealed class InvalidResponseException : Exception;
}
