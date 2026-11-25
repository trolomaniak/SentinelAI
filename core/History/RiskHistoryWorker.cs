namespace SentinelAI.Core.History;

internal sealed class RiskHistoryWorker(RiskHistoryStore history, TimeProvider time, ILogger<RiskHistoryWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1), time);
            do
            {
                try
                {
                    await history.CaptureAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception error)
                {
                    logger.LogWarning("Risk history capture deferred ({ErrorType}).", error.GetType().Name);
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}
