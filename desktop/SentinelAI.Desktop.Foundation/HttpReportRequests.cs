using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Desktop.Foundation;

public sealed partial class HttpAuthenticationClient : IReportsClient
{
    private const string ReportContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; " +
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
    private static readonly UTF8Encoding ReportUtf8 = new(false, true);

    public async Task<SecurityReportResult> GenerateSecurityReportAsync(ReportDateRange period, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (period is null || !period.IsValid) return new(ReportOutcome.InvalidPeriod);
        Operation operation;
        byte[] token;
        lock (_gate)
        {
            if (_disposed || _token is null) return new(ReportOutcome.Unauthenticated);
            if (_time.GetUtcNow() >= _expiresAt)
            {
                ResetGenerationLocked();
                return new(ReportOutcome.Unauthenticated);
            }
            operation = new Operation(_generation,
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _generationCancellation.Token));
            token = _token.ToArray();
        }
        using (operation)
        {
            // One deadline covers trust, response headers and the entire body.
            operation.Cancellation.CancelAfter(TimeSpan.FromSeconds(30));
            SecurityReportDocument? document = null;
            var published = false;
            try
            {
                SecurityReportResult result;
                try
                {
                    result = await RequestSecurityReportAsync(period, token, operation.Token).ConfigureAwait(false);
                    document = result.Document;
                }
                catch (OperationCanceledException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result = new(ReportOutcome.Unavailable);
                }
                catch (ReportResponseTooLargeException) { result = new(ReportOutcome.TooLarge); }
                catch (Exception exception) when (exception is InvalidResponseException or DecoderFallbackException or FormatException)
                {
                    result = new(ReportOutcome.InvalidResponse);
                }
                catch (Exception)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result = new(ReportOutcome.Unavailable);
                }
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    // Obsolete downloads cannot publish bytes or expire a newer login.
                    if (_disposed || operation.Generation != _generation || _token is null)
                        return new(ReportOutcome.Unauthenticated);
                    if (_time.GetUtcNow() >= _expiresAt)
                    {
                        ResetGenerationLocked();
                        return new(ReportOutcome.Unauthenticated);
                    }
                    if (operation.Token.IsCancellationRequested) return new(ReportOutcome.Unavailable);
                    if (result.Outcome is ReportOutcome.Unauthenticated or ReportOutcome.UntrustedConnection)
                        ResetGenerationLocked();
                    published = result.Outcome == ReportOutcome.Success;
                    return result;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(token);
                if (!published) document?.Dispose();
            }
        }
    }

    private async Task<SecurityReportResult> RequestSecurityReportAsync(ReportDateRange period, byte[] token,
        CancellationToken cancellationToken)
    {
        if (!await _trust.IsTrustedAsync(_origin, cancellationToken).ConfigureAwait(false))
            return new(ReportOutcome.UntrustedConnection);
        cancellationToken.ThrowIfCancellationRequested();
        var path = "api/admin/reports/security?from=" + period.From.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) +
            "&to=" + period.To.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_origin, path));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Encoding.ASCII.GetString(token));
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (response.StatusCode == HttpStatusCode.Unauthorized) return new(ReportOutcome.Unauthenticated);
            if (response.StatusCode == HttpStatusCode.UnprocessableEntity) return new(ReportOutcome.CapacityExceeded);
            if (response.StatusCode != HttpStatusCode.OK) return new(ReportOutcome.Unavailable);
            var type = response.Content.Headers.ContentType;
            if (!string.Equals(type?.MediaType, "text/html", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(type?.CharSet?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(response.Content.Headers.ContentDisposition?.DispositionType, "attachment", StringComparison.OrdinalIgnoreCase) ||
                response.Headers.CacheControl?.NoStore != true ||
                !SingleReportHeader(response.Headers, "X-Content-Type-Options", "nosniff", StringComparison.OrdinalIgnoreCase) ||
                !SingleReportHeader(response.Headers, "Content-Security-Policy", ReportContentSecurityPolicy, StringComparison.Ordinal))
                throw new InvalidResponseException();
            if (response.Content.Headers.ContentLength > SecurityReportDocument.MaximumBytes) throw new ReportResponseTooLargeException();
            var buffer = new byte[SecurityReportDocument.MaximumBytes + 1];
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
                if (length > SecurityReportDocument.MaximumBytes) throw new ReportResponseTooLargeException();
                if (length == 0 || ReportUtf8.GetCharCount(buffer.AsSpan(0, length)) == 0) throw new InvalidResponseException();
                cancellationToken.ThrowIfCancellationRequested();
                // Retain Core's exact bytes. No HTML interpretation or server filename use.
                var document = new SecurityReportDocument(period, buffer.AsSpan(0, length));
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return new(ReportOutcome.Success, document);
                }
                catch { document.Dispose(); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(buffer); }
        }
        finally { request.Headers.Authorization = null; }
    }

    private static bool SingleReportHeader(HttpResponseHeaders headers, string name, string expected, StringComparison comparison)
    {
        if (!headers.TryGetValues(name, out var values)) return false;
        using var enumerator = values.GetEnumerator();
        return enumerator.MoveNext() && string.Equals(enumerator.Current, expected, comparison) && !enumerator.MoveNext();
    }

    private sealed class ReportResponseTooLargeException : Exception;
}
