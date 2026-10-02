namespace SentinelAI.Core;

internal sealed class LicenseRenewalWorker(
    LicenseStateService licensing,
    LicenseRenewalOptions options,
    ILogger<LicenseRenewalWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Configured || !options.Automatic) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await licensing.RenewAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception)
            {
                // A licensing failure must never stop the Core monitoring host or expose credentials.
                logger.LogWarning("License renewal could not complete; local monitoring remains available.");
            }
            try { await Task.Delay(options.Interval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
