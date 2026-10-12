using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Agent;

/// <summary>
/// Detects changes to the bounded security posture allowlist between inventory
/// reconciliations. Change notifications, coalesced into one slot, only request a re-read
/// after a settle period; periodic verification covers missed or unavailable notifications.
/// A difference from the posture Core last acknowledged becomes one pending delivery, never a
/// queue of observations; <see cref="HeartbeatWorker"/> then sends a fresh full inventory.
/// </summary>
public sealed class PostureMonitor(
    AgentOptions options,
    ISecurityPostureReader postureReader,
    IPostureChangeSource changeSource,
    ILogger<PostureMonitor> logger) : BackgroundService
{
    // Uploads keep the existing five-minute inventory retry after a failure.
    public static readonly TimeSpan DeliveryRetryDelay = TimeSpan.FromMinutes(5);
    // A continuous notification storm still yields a read after this many settle delays.
    private const int MaximumSettleDelays = 5;

    private readonly Channel<bool> _notifications = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly object _gate = new();
    private SecurityPostureInventory? _acknowledged;
    private SecurityPostureInventory? _observed;
    private DateTimeOffset _observedUtc = DateTimeOffset.MinValue;
    private bool _pending;
    private DateTimeOffset _nextDeliveryUtc = DateTimeOffset.MinValue;
    private TaskCompletionSource _changed = NewSignal();
    private bool? _watching;
    private long _verifications;

    /// <summary>Number of completed allowlist verifications, exposed for bounded-work checks.</summary>
    public long Verifications => Interlocked.Read(ref _verifications);

    /// <summary>Completes when a newly observed posture differs from Core's acknowledged posture.</summary>
    public Task ChangeDetected
    {
        get
        {
            lock (_gate)
            {
                return _changed.Task;
            }
        }
    }

    /// <summary>When a pending change may next be delivered, or null when nothing is pending.</summary>
    public DateTimeOffset? PendingDeliveryUtc
    {
        get
        {
            lock (_gate)
            {
                return _pending ? _nextDeliveryUtc : null;
            }
        }
    }

    public bool IsDeliveryDue(DateTimeOffset now)
    {
        lock (_gate)
        {
            return _pending && now >= _nextDeliveryUtc;
        }
    }

    /// <summary>Records an inventory Core accepted; spaces the next change-triggered delivery.</summary>
    public void RecordDelivered(InventoryReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        lock (_gate)
        {
            _acknowledged = report.SecurityPosture;
            if (_observed is null || report.CollectedUtc >= _observedUtc)
            {
                _observed = report.SecurityPosture;
                _observedUtc = report.CollectedUtc;
            }

            // A read made after this report was collected may already differ from it.
            _pending = _observed != _acknowledged;
            _nextDeliveryUtc = DateTimeOffset.UtcNow + options.PostureDeliveryInterval;
        }
    }

    public void RecordDeliveryFailed()
    {
        lock (_gate)
        {
            _nextDeliveryUtc = DateTimeOffset.UtcNow + DeliveryRetryDelay;
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        logger.LogInformation(
            "Posture monitor started; settle delay {SettleDelay}, verification interval {VerificationInterval}",
            options.PostureSettleDelay, options.PostureCheckInterval);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    Verify();
                    if (await WaitForNotificationAsync(options.PostureCheckInterval, stoppingToken))
                    {
                        await SettleAsync(stoppingToken);
                    }
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    // Monitoring failures must not stop the Agent; reconciliation still runs.
                    logger.LogWarning(exception, "Posture monitoring failed; retrying after the verification interval");
                    await Task.Delay(options.PostureCheckInterval, stoppingToken);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private void Verify()
    {
        // Arm before reading: a change after this point raises a new notification, and a
        // change before it is included in the read below.
        bool watching;
        try
        {
            watching = changeSource.Arm(() => _notifications.Writer.TryWrite(true));
        }
        catch (Exception exception) when (exception is not ObjectDisposedException)
        {
            logger.LogWarning(exception, "Posture change notifications could not be registered");
            watching = false;
        }

        if (_watching != watching)
        {
            _watching = watching;
            if (watching)
            {
                logger.LogInformation("Watching all monitored posture locations for changes");
            }
            else
            {
                logger.LogInformation(
                    "Posture change notifications are unavailable for some locations; verifying every {VerificationInterval}",
                    options.PostureCheckInterval);
            }
        }

        while (_notifications.Reader.TryRead(out _))
        {
        }

        var observedUtc = DateTimeOffset.UtcNow;
        var posture = postureReader.Read();
        TaskCompletionSource? changed = null;
        lock (_gate)
        {
            if (observedUtc >= _observedUtc)
            {
                _observed = posture;
                _observedUtc = observedUtc;
            }

            var differs = _observed != _acknowledged;
            if (differs && !_pending)
            {
                changed = _changed;
                _changed = NewSignal();
            }

            _pending = differs;
        }

        Interlocked.Increment(ref _verifications);
        if (changed is not null)
        {
            logger.LogInformation("Security posture change detected; inventory delivery requested");
            changed.TrySetResult();
        }
    }

    private async Task SettleAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + options.PostureSettleDelay * MaximumSettleDelays;
        while (true)
        {
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero ||
                !await WaitForNotificationAsync(
                    remaining < options.PostureSettleDelay ? remaining : options.PostureSettleDelay,
                    cancellationToken))
            {
                return;
            }
        }
    }

    private async Task<bool> WaitForNotificationAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await _notifications.Reader.ReadAsync(timeoutSource.Token);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}
