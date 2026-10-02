using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Heartbeat;

namespace SentinelAI.Agent;

public sealed class HeartbeatWorker(
    AgentOptions options,
    InstallationIdentityStore identityStore,
    EnrollmentStateStore enrollmentStateStore,
    AgentEnrollmentClient enrollmentClient,
    InventoryCollector inventoryCollector,
    HttpClient httpClient,
    ILogger<HeartbeatWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var installationId = await identityStore.LoadOrCreateAsync(stoppingToken);
        var enrollment = await enrollmentStateStore.LoadAsync(installationId, stoppingToken);
        if (enrollment is not null)
        {
            await enrollmentStateStore.WriteEndpointReceiptAsync(enrollment, stoppingToken);
            EnrollmentTokenHandoff.DeleteIfPresent(options);
        }
        logger.LogInformation("Agent installation {InstallationId} started", installationId);
        if (enrollment is null && !options.HasEnrollmentToken && !options.CoreUrl.IsLoopback)
        {
            logger.LogWarning("An enrollment token is required before connecting to a remote Core");
        }

        var nextRetryDelay = options.RetryDelay;
        var nextInventoryUtc = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            bool acknowledged;
            try
            {
                if (enrollment is null && options.HasEnrollmentToken)
                {
                    var attempt = await enrollmentClient.EnrollAsync(installationId, stoppingToken);
                    if (attempt.Response is null)
                    {
                        logger.LogWarning("Agent enrollment failed with HTTP {StatusCode}", attempt.StatusCode);
                        acknowledged = false;
                    }
                    else
                    {
                        enrollment = await enrollmentStateStore.SaveAsync(attempt.Response, stoppingToken);
                        await enrollmentStateStore.WriteEndpointReceiptAsync(enrollment, stoppingToken);
                        EnrollmentTokenHandoff.DeleteIfPresent(options);
                        logger.LogInformation("Agent endpoint {EndpointId} enrolled", enrollment.EndpointId);
                        acknowledged = await SendHeartbeatAsync(installationId, enrollment, stoppingToken);
                    }
                }
                else if (enrollment is null && !options.CoreUrl.IsLoopback)
                {
                    acknowledged = false;
                }
                else
                {
                    acknowledged = await SendHeartbeatAsync(installationId, enrollment, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (HttpRequestException exception)
            {
                logger.LogWarning(exception, "Heartbeat transport failed");
                acknowledged = false;
            }
            catch (OperationCanceledException exception)
            {
                logger.LogWarning(exception, "Heartbeat request timed out");
                acknowledged = false;
            }
            catch (IOException exception)
            {
                logger.LogWarning(exception, "Heartbeat response could not be read");
                acknowledged = false;
            }
            catch (JsonException exception)
            {
                logger.LogWarning(exception, "Heartbeat response was invalid JSON");
                acknowledged = false;
            }

            if (acknowledged && enrollment is not null && DateTimeOffset.UtcNow >= nextInventoryUtc)
            {
                bool inventorySent;
                try
                {
                    inventorySent = await SendInventoryAsync(enrollment, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Inventory collection or delivery failed");
                    inventorySent = false;
                }

                nextInventoryUtc = DateTimeOffset.UtcNow +
                    (inventorySent ? TimeSpan.FromHours(6) : TimeSpan.FromMinutes(5));
            }

            var delay = acknowledged ? options.HeartbeatInterval : nextRetryDelay;
            nextRetryDelay = acknowledged ? options.RetryDelay : DoubleDelay(nextRetryDelay, options.MaxRetryDelay);
            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task<bool> SendHeartbeatAsync(
        Guid installationId,
        EnrollmentState? enrollment,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, options.HeartbeatUrl)
        {
            Content = JsonContent.Create(new HeartbeatRequest(installationId))
        };
        if (enrollment is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "SentinelAgent", $"{enrollment.EndpointId:D}.{enrollment.AgentCredential}");
        }

        using var response = await httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("Heartbeat failed with HTTP {StatusCode}", (int)response.StatusCode);
            return false;
        }

        var acknowledgement = await response.Content.ReadFromJsonAsync<HeartbeatResponse>(cancellationToken);
        if (acknowledgement is null || acknowledgement.InstallationId != installationId ||
            acknowledgement.HealthStatus != DeviceHealthStatus.Reporting)
        {
            logger.LogWarning("Heartbeat acknowledgement was invalid");
            return false;
        }

        logger.LogDebug("Heartbeat acknowledged for installation {InstallationId}", installationId);
        return true;
    }

    private static TimeSpan DoubleDelay(TimeSpan delay, TimeSpan maximum) =>
        delay.Ticks >= maximum.Ticks / 2
            ? maximum
            : TimeSpan.FromTicks(delay.Ticks * 2);

    private async Task<bool> SendInventoryAsync(
        EnrollmentState enrollment,
        CancellationToken cancellationToken)
    {
        var report = inventoryCollector.Collect(enrollment.EndpointId);
        using var request = new HttpRequestMessage(HttpMethod.Post, options.InventoryUrl)
        {
            Content = JsonContent.Create(report)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "SentinelAgent", $"{enrollment.EndpointId:D}.{enrollment.AgentCredential}");

        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("Inventory upload failed with HTTP {StatusCode}", (int)response.StatusCode);
            return false;
        }

        logger.LogDebug("Inventory acknowledged for endpoint {EndpointId}", enrollment.EndpointId);
        return true;
    }
}
