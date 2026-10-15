using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.EndpointTelemetry;

namespace SentinelAI.Agent;

/// <summary>
/// Fixed telemetry cadence: a full report every hour, five minutes after a failed delivery and six hours after
/// Core rejected the report as incompatible.
/// </summary>
public sealed record EndpointTelemetryTimings(TimeSpan Interval, TimeSpan RetryDelay, TimeSpan IncompatibleRetryDelay)
{
    public static EndpointTelemetryTimings Default { get; } =
        new(TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), TimeSpan.FromHours(6));
}

public readonly record struct TelemetryUploadOutcome(UploadResult Result, int? StatusCode);

public interface IEndpointTelemetryUploader
{
    Task<TelemetryUploadOutcome> SendAsync(EndpointTelemetryReport report, EnrollmentState enrollment,
        CancellationToken cancellationToken);
}

/// <summary>Posts one report. Core answers 204 whether it stored the report or already holds a newer one.</summary>
public sealed class HttpEndpointTelemetryUploader(HttpClient httpClient, AgentOptions options) : IEndpointTelemetryUploader
{
    public async Task<TelemetryUploadOutcome> SendAsync(EndpointTelemetryReport report, EnrollmentState enrollment,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, options.SecurityTelemetryUrl)
        {
            Content = JsonContent.Create(report, options: EndpointTelemetryContract.Json)
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
                return new(UploadResult.Accepted, status);
            }

            return new(status is 400 or 404 or 405 or 413 or 415 ? UploadResult.Incompatible : UploadResult.Failed, status);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException)
        {
            return new(UploadResult.Failed, null);
        }
    }
}

/// <summary>
/// Collects and delivers endpoint telemetry on its own schedule, separately from heartbeats so that a slow platform
/// source can never delay them. It is dormant until <see cref="AgentLink"/> reports an enrolled, acknowledged Agent,
/// keeps nothing on disk and sends only the latest report: there is no queue to replay.
/// </summary>
public sealed class EndpointTelemetryWorker(
    AgentLink link,
    EndpointTelemetryCollector collector,
    IEndpointTelemetryUploader uploader,
    TimeProvider time,
    ILogger<EndpointTelemetryWorker> logger,
    EndpointTelemetryTimings? timings = null) : BackgroundService
{
    private readonly EndpointTelemetryTimings _timings = timings ?? EndpointTelemetryTimings.Default;
    private string? _lastSources;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Guid? endpointId = null;
        var nextUtc = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            // Capture the signal before reading the link so that a concurrent change still wakes the wait.
            var changed = link.Changed;
            var linked = link.Current;
            try
            {
                if (linked is null)
                {
                    await changed.WaitAsync(stoppingToken);
                    continue;
                }

                if (linked.EndpointId != endpointId)
                {
                    endpointId = linked.EndpointId;
                    nextUtc = DateTimeOffset.MinValue;
                }

                var now = time.GetUtcNow();
                if (now >= nextUtc)
                {
                    nextUtc = time.GetUtcNow() + await DeliverAsync(linked, stoppingToken);
                    continue;
                }

                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                await Task.WhenAny(Task.Delay(nextUtc - now, time, wait.Token), changed.WaitAsync(wait.Token));
                await wait.CancelAsync();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>Collects and sends one report and returns the delay before the next.</summary>
    private async Task<TimeSpan> DeliverAsync(EnrollmentState enrollment, CancellationToken cancellationToken)
    {
        EndpointTelemetryReport report;
        try
        {
            report = await collector.CollectAsync(enrollment.EndpointId, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(exception, "Endpoint telemetry collection failed");
            return _timings.RetryDelay;
        }

        var sources = Describe(report);
        if (!string.Equals(sources, _lastSources, StringComparison.Ordinal))
        {
            // Availability only, once per change; values are never logged.
            logger.LogInformation("Endpoint telemetry sources: {Sources}", sources);
            _lastSources = sources;
        }

        var outcome = await uploader.SendAsync(report, enrollment, cancellationToken);
        switch (outcome.Result)
        {
            case UploadResult.Accepted:
                logger.LogDebug("Endpoint telemetry acknowledged for endpoint {EndpointId}", enrollment.EndpointId);
                return _timings.Interval;
            case UploadResult.Incompatible:
                logger.LogWarning("Endpoint telemetry was rejected with HTTP {StatusCode}", outcome.StatusCode);
                return _timings.IncompatibleRetryDelay;
            default:
                logger.LogWarning("Endpoint telemetry upload failed with HTTP {StatusCode}", outcome.StatusCode);
                return _timings.RetryDelay;
        }
    }

    /// <summary>Each section's availability; never a value.</summary>
    public static string Describe(EndpointTelemetryReport report) =>
        $"bitLocker={report.BitLocker.Availability}, antivirus={report.Antivirus.Availability}, " +
        $"defender={report.Defender.Availability}, localAdministrators={report.LocalAdministrators.Availability}, " +
        $"updatePolicy={report.WindowsUpdate.PolicyAvailability}, updateResults={report.WindowsUpdate.ResultsAvailability}, " +
        $"pendingReboot={report.PendingReboot.Availability}, services={report.Services.Availability}, " +
        $"software={report.Software.Availability}";
}
