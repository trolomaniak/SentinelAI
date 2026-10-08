using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.Ai;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IAiExplanationClient
{
    public async Task<AiExplanationResult> ExplainAlertAsync(Guid alertId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (alertId == Guid.Empty) return new(AiExplanationOutcome.Unsupported);
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(AiExplanationOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(AiExplanationOutcome.Unauthenticated);
            }
            operation = new Operation(_generation,
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            // Core permits a gateway timeout up to sixty seconds. This complete
            // deadline includes trust, headers and the bounded response body.
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(65));
            try
            {
                AiExplanationResult result;
                try { result = await RequestAiExplanationAsync(alertId, token, operation.Token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result = new(AiExplanationOutcome.Unavailable);
                }
                catch (Exception exception) when (exception is InvalidResponseException or JsonException)
                {
                    result = new(AiExplanationOutcome.InvalidResponse);
                }
                catch (Exception)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result = new(AiExplanationOutcome.Unavailable);
                }
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    // An obsolete response cannot publish analysis or expire a new login.
                    if (_disposed || operation.Generation != _generation || _token is null)
                        return new(AiExplanationOutcome.Unauthenticated);
                    if (_time.GetUtcNow() >= _expiresAt)
                    {
                        ResetGenerationLocked();
                        return new(AiExplanationOutcome.Unauthenticated);
                    }
                    if (operation.Token.IsCancellationRequested) return new(AiExplanationOutcome.Unavailable);
                    if (result.Outcome is AiExplanationOutcome.Unauthenticated or AiExplanationOutcome.UntrustedConnection)
                        ResetGenerationLocked();
                    return result;
                }
            }
            finally { CryptographicOperations.ZeroMemory(token); }
        }
    }

    private async Task<AiExplanationResult> RequestAiExplanationAsync(Guid alertId, byte[] token,
        CancellationToken cancellationToken)
    {
        if (!await _trust.IsTrustedAsync(_origin, cancellationToken).ConfigureAwait(false))
            return new(AiExplanationOutcome.UntrustedConnection);
        cancellationToken.ThrowIfCancellationRequested();
        using var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(_origin, "api/admin/alerts/" + alertId.ToString("D") + "/explanation"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
        try
        {
            // Deliberately no content, query, retry, context or gateway settings.
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var failure = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => AiExplanationOutcome.Unauthenticated,
                HttpStatusCode.Forbidden => AiExplanationOutcome.Disabled,
                HttpStatusCode.NotFound => AiExplanationOutcome.NotFound,
                HttpStatusCode.UnprocessableEntity => AiExplanationOutcome.Unsupported,
                HttpStatusCode.TooManyRequests => AiExplanationOutcome.Throttled,
                _ => AiExplanationOutcome.Unavailable
            };
            if (response.StatusCode != HttpStatusCode.OK) return new(failure);
            var type = response.Content.Headers.ContentType;
            if (!string.Equals(type?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
                type?.CharSet is { Length: > 0 } charset && !string.Equals(charset.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase) ||
                response.Headers.CacheControl?.NoStore != true ||
                response.Content.Headers.ContentLength > AiContract.MaximumResponseBytes)
                throw new InvalidResponseException();
            var buffer = new byte[AiContract.MaximumResponseBytes + 1];
            try
            {
                using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                var length = 0;
                while (length < buffer.Length)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
                    if (read == 0) break;
                    length += read;
                }
                cancellationToken.ThrowIfCancellationRequested();
                if (length > AiContract.MaximumResponseBytes) throw new InvalidResponseException();
                using var json = JsonDocument.Parse(buffer.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
                if (!AiContract.TryReadResponse(json.RootElement, out var parsed) || parsed is null)
                    throw new InvalidResponseException();
                cancellationToken.ThrowIfCancellationRequested();
                return new(AiExplanationOutcome.Success, parsed.Analysis);
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        finally { request.Headers.Authorization = null; }
    }
}
