using System.Security.Cryptography;

namespace SentinelAI.Core.Notifications;

internal sealed class NotificationWorker(NotificationStore store,INotificationSender sender,TimeProvider time,
    ILogger<NotificationWorker> logger) : BackgroundService
{
    private readonly object _gate=new();
    private CancellationTokenSource? _attemptCancellation;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        store.PolicyChanged+=CancelAttempt;
        try
        {
            // Local monitoring must keep progressing while an external recipient is slow or unavailable.
            await Task.WhenAll(RunPeriodicAsync(MaintainAsync,stoppingToken),
                RunPeriodicAsync(DeliverAsync,stoppingToken));
        }
        finally { store.PolicyChanged-=CancelAttempt; }
    }

    private async Task RunPeriodicAsync(Func<CancellationToken,Task> process,CancellationToken stoppingToken)
    {
        try
        {
            using var timer=new PeriodicTimer(TimeSpan.FromSeconds(15),time);
            do
            {
                try { await process(stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception) { logger.LogWarning("Notification processing deferred."); }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    internal async Task ProcessOnceAsync(CancellationToken cancellationToken=default)
    {
        await MaintainAsync(cancellationToken);
        await DeliverAsync(cancellationToken);
    }

    private async Task MaintainAsync(CancellationToken cancellationToken)
    {
        await store.ObserveMonitoringAsync(cancellationToken);
        await store.PruneAsync(cancellationToken);
    }

    private async Task DeliverAsync(CancellationToken cancellationToken)
    {
        for (var count=0;count<20;count++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var attempt=await store.ClaimAsync(cancellationToken);
            if (attempt is null) break;
            using var bounded=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromSeconds(30));
            lock (_gate) _attemptCancellation=bounded;
            NotificationSendResult result;
            try
            {
                using var destination=await store.GetDestinationAsync(attempt.PolicyVersion,attempt.Channel,bounded.Token);
                result=destination is null ? new(false,false,"credentials_unavailable") : await sender.SendAsync(attempt.Payload,destination,bounded.Token);
            }
            catch (OperationCanceledException) { result=new(false,true,"cancelled"); }
            catch (CryptographicException) { result=new(false,false,"credentials_unavailable"); }
            catch (Exception) { result=new(false,true,"transport_error"); }
            finally { lock (_gate) _attemptCancellation=null; }
            // A cancelled shutdown still leaves an honest durable retry; a policy change has already
            // marked the row cancelled, so Complete's compare-and-set cannot resurrect it.
            await store.CompleteAsync(attempt,result,CancellationToken.None);
        }
    }
    private void CancelAttempt() { lock (_gate) _attemptCancellation?.Cancel(); }
}
