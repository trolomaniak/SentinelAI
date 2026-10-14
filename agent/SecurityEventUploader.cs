using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Agent;

public enum UploadResult { Accepted, Incompatible, Failed }

public readonly record struct UploadOutcome(UploadResult Result, int? StatusCode, SecurityEventBatchResult? Counts);

public interface ISecurityEventUploader
{
    Task<UploadOutcome> SendAsync(SecurityEventBatch batch, EnrollmentState enrollment, CancellationToken cancellationToken);
}

/// <summary>
/// Posts one batch to Core. A success status means Core committed every item; incompatibility
/// statuses hold the batch for a long retry and anything else is transient. Nothing is logged here.
/// </summary>
/// <remarks>
/// HttpClient.Timeout ends when the headers arrive; the small result body has its own bound
/// (<paramref name="resultReadTimeout"/>, 10 seconds by default) so a peer that stalls after a 2xx can never
/// hold the loop.
/// </remarks>
public sealed class HttpSecurityEventUploader(HttpClient httpClient, AgentOptions options,
    TimeSpan? resultReadTimeout = null) : ISecurityEventUploader
{
    private readonly TimeSpan _resultReadTimeout = resultReadTimeout ?? TimeSpan.FromSeconds(10);

    public async Task<UploadOutcome> SendAsync(SecurityEventBatch batch, EnrollmentState enrollment,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, options.SecurityEventsUrl)
        {
            Content = JsonContent.Create(batch, options: SecurityEventContract.Json)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "SentinelAgent", $"{enrollment.EndpointId:D}.{enrollment.AgentCredential}");
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            var status = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                // Core already committed; the counts are informational and never cause a resend.
                return new(UploadResult.Accepted, status,
                    await ReadCountsAsync(response, _resultReadTimeout, cancellationToken));
            }

            return new(status is 400 or 404 or 405 or 413 or 415 ? UploadResult.Incompatible : UploadResult.Failed,
                status, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException)
        {
            return new(UploadResult.Failed, null, null);
        }
    }

    private static async Task<SecurityEventBatchResult?> ReadCountsAsync(HttpResponseMessage response,
        TimeSpan readTimeout, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(readTimeout);
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            var buffer = new byte[SecurityEventContract.MaxResultBytes + 1];
            var length = 0;
            int read;
            while (length < buffer.Length &&
                   (read = await stream.ReadAsync(buffer.AsMemory(length), timeout.Token)) > 0)
            {
                length += read;
            }

            return length is 0 or > SecurityEventContract.MaxResultBytes
                ? null
                : JsonSerializer.Deserialize<SecurityEventBatchResult>(buffer.AsSpan(0, length), SecurityEventContract.Json);
        }
        catch (Exception exception) when (exception is JsonException or HttpRequestException or IOException or
                                              OperationCanceledException)
        {
            return null;
        }
    }
}
