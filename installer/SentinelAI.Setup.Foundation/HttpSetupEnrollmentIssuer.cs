using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Setup.Foundation;

/// <summary>One bounded local login/token exchange; native composition authenticates the connected Core peer.</summary>
public sealed class HttpSetupEnrollmentIssuer : ISetupEnrollmentIssuer, IDisposable
{
    private static readonly Uri Origin = new("http://127.0.0.1:5000/");
    private readonly ICoreEndpointTrust _trust;
    private readonly HttpClient _http;

    public HttpSetupEnrollmentIssuer(ICoreEndpointTrust trust, HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(trust); ArgumentNullException.ThrowIfNull(handler);
        _trust = trust;
        if (handler is HttpClientHandler basic)
        {
            basic.AllowAutoRedirect = false; basic.UseProxy = false; basic.UseCookies = false;
            basic.UseDefaultCredentials = false; basic.Credentials = null;
        }
        else if (handler is SocketsHttpHandler sockets)
        {
            sockets.AllowAutoRedirect = false; sockets.UseProxy = false; sockets.UseCookies = false; sockets.Credentials = null;
        }
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task<string> IssueAsync(string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!SetupWorkflow.ValidCredentials(username, password.Span, password.Span)) throw new InvalidDataException("Invalid setup credentials.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        byte[]? bearer = null;
        try
        {
            if (!await _trust.IsTrustedAsync(Origin, deadline.Token).ConfigureAwait(false)) throw new InvalidDataException();
            deadline.Token.ThrowIfCancellationRequested();
            bearer = await LoginAsync(username.Trim(), password, deadline.Token).ConfigureAwait(false);
            if (!await _trust.IsTrustedAsync(Origin, deadline.Token).ConfigureAwait(false)) throw new InvalidDataException();
            deadline.Token.ThrowIfCancellationRequested();
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(Origin, "api/admin/enrollment-tokens"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(bearer));
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(bearer);
            var buffer = await ReadJsonBytesAsync(response, 4096, deadline.Token).ConfigureAwait(false);
            try
            {
                using var document = JsonDocument.Parse(buffer.Bytes.AsMemory(0, buffer.Length), new JsonDocumentOptions { MaxDepth = 2 });
                var fields = Properties(document.RootElement, ["token", "expiresUtc", "coreInstallationId", "organizationId"]);
                var enrollment = Text(fields, "token");
                if (fields.Count != 4 || !SetupWorkflow.ValidEnrollmentToken(enrollment) ||
                    !DateTimeOffset.TryParse(Text(fields, "expiresUtc"), CultureInfo.InvariantCulture, DateTimeStyles.None, out var expiry) ||
                    expiry <= DateTimeOffset.UtcNow || expiry > DateTimeOffset.UtcNow.AddMinutes(15) ||
                    !ValidGuid(Text(fields, "coreInstallationId")) || !ValidGuid(Text(fields, "organizationId"))) throw new InvalidDataException();
                return enrollment;
            }
            finally { CryptographicOperations.ZeroMemory(buffer.Bytes); }
        }
        catch
        {
            token.ThrowIfCancellationRequested();
            throw new InvalidDataException("Local Agent enrollment unavailable.");
        }
        finally { if (bearer is not null) CryptographicOperations.ZeroMemory(bearer); }
    }

    private async Task<byte[]> LoginAsync(string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        var input = new byte[16 * 1024];
        try
        {
            using var memory = new MemoryStream(input, 0, input.Length, writable: true, publiclyVisible: true);
            memory.SetLength(0);
            using (var writer = new Utf8JsonWriter(memory))
            {
                writer.WriteStartObject(); writer.WriteString("username", username); writer.WriteString("password", password.Span);
                writer.WriteEndObject(); writer.Flush();
            }
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(Origin, "api/auth/login"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = new ByteArrayContent(input, 0, checked((int)memory.Length));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(input);
            var buffer = await ReadJsonBytesAsync(response, 64 * 1024, token).ConfigureAwait(false);
            try
            {
                using var document = JsonDocument.Parse(buffer.Bytes.AsMemory(0, buffer.Length), new JsonDocumentOptions { MaxDepth = 2 });
                var fields = Properties(document.RootElement, ["tokenType", "accessToken", "expiresIn", "refreshToken"]);
                var bearer = Text(fields, "accessToken");
                if (fields.Count is < 3 or > 4 || Text(fields, "tokenType") != "Bearer" || bearer.Length is < 1 or > 8192 ||
                    bearer.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not '-' and not '_' and not '.') ||
                    !fields.TryGetValue("expiresIn", out var seconds) || !seconds.TryGetInt64(out var duration) || duration <= 0 ||
                    fields.TryGetValue("refreshToken", out var refresh) && (refresh.ValueKind != JsonValueKind.String || refresh.GetString()!.Length > 8192))
                    throw new InvalidDataException();
                return Encoding.ASCII.GetBytes(bearer);
            }
            finally { CryptographicOperations.ZeroMemory(buffer.Bytes); }
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static async Task<(byte[] Bytes, int Length)> ReadJsonBytesAsync(HttpResponseMessage response, int maximum, CancellationToken token)
    {
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentType?.MediaType != "application/json" ||
            response.Content.Headers.ContentLength > maximum) throw new InvalidDataException();
        var bytes = new byte[maximum + 1]; var length = 0;
        try
        {
            using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            while (true)
            {
                var count = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false);
                if (count == 0) return (bytes, length);
                length = checked(length + count);
                if (length > maximum) throw new InvalidDataException();
            }
        }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }

    private static Dictionary<string, JsonElement> Properties(JsonElement value, string[] allowed)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var field in value.EnumerateObject())
            if (!allowed.Contains(field.Name, StringComparer.Ordinal) || !fields.TryAdd(field.Name, field.Value)) throw new InvalidDataException();
        return fields;
    }
    private static string Text(Dictionary<string, JsonElement> fields, string name) =>
        fields.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new InvalidDataException();
    private static bool ValidGuid(string value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty;
    public void Dispose() => _http.Dispose();
}
