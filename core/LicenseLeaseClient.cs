using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SentinelAI.Core.Persistence;
using SentinelAI.Licensing;

namespace SentinelAI.Core;

public interface ILicenseLeaseClient
{
    bool Configured { get; }
    Task<string?> FetchAsync(CoreIdentity identity, CancellationToken cancellationToken = default);
}

/// <summary>Fetches an untrusted token only from the configured issuer; Core verifies it locally.</summary>
public sealed class LicenseLeaseClient : ILicenseLeaseClient, IDisposable
{
    private const int MaximumResponseBytes = 20 * 1024;
    private readonly LicenseRenewalOptions options;
    private readonly HttpClient client;

    public LicenseLeaseClient(LicenseRenewalOptions options)
    {
        this.options = options;
        client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        {
            // The linked cancellation token bounds both headers and the streamed response body.
            Timeout = System.Threading.Timeout.InfiniteTimeSpan
        };
    }

    public bool Configured => options.Configured;

    public async Task<string?> FetchAsync(CoreIdentity identity,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Configured) return null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.Timeout);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(options.Url!, "/api/licenses/lease"))
        {
            Content = JsonContent.Create(new
            {
                organizationId = identity.OrganizationId,
                installationId = identity.CoreInstallationId
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ActivationCredential);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK ||
                !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
                response.Content.Headers.ContentLength > MaximumResponseBytes)
            {
                return null;
            }
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            var buffer = new byte[MaximumResponseBytes + 1];
            var length = 0;
            while (length < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token);
                if (read == 0) break;
                length += read;
            }
            if (length > MaximumResponseBytes) return null;
            using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 4 });
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
                !root.TryGetProperty("lease", out var value) || value.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            var lease = value.GetString();
            cancellationToken.ThrowIfCancellationRequested();
            return lease is { Length: > 0 and <= LeaseTokenFormat.MaxTokenLength } ? lease : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    public void Dispose() => client.Dispose();
}
