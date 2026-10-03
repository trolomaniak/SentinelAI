using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SentinelAI.Desktop.Foundation;

/// <summary>Checks the existing public health route at one fixed local Core destination.</summary>
public sealed class HttpCoreClient : ICoreClient
{
    private static readonly Uri HealthUri = new("http://127.0.0.1:5000/api/health");
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(3);
    private const int MaximumResponseBytes = 4 * 1024;
    private readonly HttpClient _client;
    private int _disposed;

    public HttpCoreClient() : this(new HttpClientHandler())
    {
    }

    /// <summary>Allows a trusted host or tests to supply transport; the destination remains fixed.</summary>
    public HttpCoreClient(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
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

        _client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public async Task<CoreHealth> CheckHealthAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(RequestTimeout);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, HealthUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (response.StatusCode != HttpStatusCode.OK ||
                !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentLength > MaximumResponseBytes)
                return CoreHealth.Unavailable;

            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            var buffer = new byte[MaximumResponseBytes + 1];
            var bytesRead = 0;
            while (bytesRead < buffer.Length)
            {
                var count = await stream.ReadAsync(buffer.AsMemory(bytesRead), deadline.Token).ConfigureAwait(false);
                if (count == 0)
                    break;
                bytesRead += count;
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (bytesRead > MaximumResponseBytes)
                return CoreHealth.Unavailable;

            using var json = JsonDocument.Parse(buffer.AsMemory(0, bytesRead), new JsonDocumentOptions { MaxDepth = 4 });
            cancellationToken.ThrowIfCancellationRequested();
            if (json.RootElement.ValueKind != JsonValueKind.Object)
                return CoreHealth.Unavailable;
            var properties = json.RootElement.EnumerateObject();
            if (!properties.MoveNext())
                return CoreHealth.Unavailable;
            var status = properties.Current;
            return status.NameEquals("status") && status.Value.ValueKind == JsonValueKind.String &&
                   status.Value.GetString() == "healthy" && !properties.MoveNext()
                ? CoreHealth.Available
                : CoreHealth.Unavailable;
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CoreHealth.Unavailable;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException or InvalidOperationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CoreHealth.Unavailable;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _client.Dispose();
    }
}
