using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Heartbeat;

namespace SentinelAI.Agent;

public sealed class HeartbeatWorker(
    AgentOptions options,
    InstallationIdentityStore identityStore,
    HttpClient httpClient,
    ILogger<HeartbeatWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var installationId = await identityStore.LoadOrCreateAsync(stoppingToken);
        logger.LogInformation("Agent installation {InstallationId} started", installationId);

        var nextRetryDelay = options.RetryDelay;
        while (!stoppingToken.IsCancellationRequested)
        {
            bool acknowledged;
            try
            {
                acknowledged = await SendHeartbeatAsync(installationId, stoppingToken);
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

    private async Task<bool> SendHeartbeatAsync(Guid installationId, CancellationToken cancellationToken)
    {
        using var response = await httpClient.PostAsJsonAsync(
            options.HeartbeatUrl,
            new HeartbeatRequest(installationId),
            cancellationToken);

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
}
