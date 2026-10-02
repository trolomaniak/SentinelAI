using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SentinelAI.Contracts.Ai;

namespace SentinelAI.Core;

public interface IAiGatewayClient
{
    bool Configured { get; }
    Task<AiExplanationResponse?> ExplainAsync(AiAlertContext context, CancellationToken cancellationToken = default);
}

/// <summary>Bounded calls to the fixed Gateway with no redirects and normal TLS verification.</summary>
public sealed class AiGatewayClient : IAiGatewayClient, IDisposable
{
    private readonly AiOptions options;
    private readonly HttpClient client;
    private readonly bool ownsClient;
    private readonly SemaphoreSlim concurrency = new(2, 2);

    public AiGatewayClient(AiOptions options)
        : this(options, new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { Timeout = System.Threading.Timeout.InfiniteTimeSpan }, ownsClient: true) { }

    // An injected transport permits deterministic transport tests without production credentials.
    public AiGatewayClient(AiOptions options, HttpClient client) : this(options, client, ownsClient: false) { }

    private AiGatewayClient(AiOptions options, HttpClient client, bool ownsClient)
    {
        this.options = options;
        this.client = client;
        this.ownsClient = ownsClient;
    }

    public bool Configured => options.Configured;

    public async Task<AiExplanationResponse?> ExplainAsync(AiAlertContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Configured || !AiContract.IsValidContext(context) || !await concurrency.WaitAsync(0, cancellationToken))
            return null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.Timeout);
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(options.GatewayUrl!, "/api/ai/alerts/explain"))
            { Content = JsonContent.Create(context) };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.GatewayCredential);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK ||
                !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentLength > AiContract.MaximumResponseBytes) return null;
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            var buffer = new byte[AiContract.MaximumResponseBytes + 1];
            var length = 0;
            while (length < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token);
                if (read == 0) break;
                length += read;
            }
            if (length > AiContract.MaximumResponseBytes) return null;
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            cancellationToken.ThrowIfCancellationRequested();
            return AiContract.TryReadResponse(json.RootElement, out var result) ? result : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
        finally { concurrency.Release(); }
    }

    public void Dispose()
    {
        if (ownsClient) client.Dispose();
        concurrency.Dispose();
    }
}
