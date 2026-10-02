namespace SentinelAI.Core;

public sealed record LicenseClockReading(DateTimeOffset UtcNow, bool RollbackDetected);

/// <summary>Advances trusted time even if the wall clock moves backwards.</summary>
public sealed class LicenseClock(TimeProvider timeProvider)
{
    private static readonly TimeSpan RollbackTolerance = TimeSpan.FromMinutes(1);
    private readonly object _gate = new();
    private DateTimeOffset? _lastEffectiveUtc;
    private DateTimeOffset? _lastWallUtc;
    private long _lastTimestamp;

    public LicenseClockReading Observe(DateTimeOffset persistedHighWaterUtc)
    {
        lock (_gate)
        {
            var wall = timeProvider.GetUtcNow().ToUniversalTime();
            var timestamp = timeProvider.GetTimestamp();
            var persisted = persistedHighWaterUtc.ToUniversalTime();
            var rollback = persisted - wall > RollbackTolerance ||
                (_lastWallUtc is { } previousWall && previousWall - wall > RollbackTolerance);
            var effective = wall >= persisted ? wall : persisted;

            if (_lastEffectiveUtc is { } previous)
            {
                var elapsed = timeProvider.GetElapsedTime(_lastTimestamp, timestamp);
                if (elapsed < TimeSpan.Zero) elapsed = TimeSpan.Zero;
                var remaining = DateTimeOffset.MaxValue - previous;
                var advanced = elapsed >= remaining ? DateTimeOffset.MaxValue : previous.Add(elapsed);
                if (advanced > effective) effective = advanced;
            }

            _lastWallUtc = wall;
            _lastEffectiveUtc = effective;
            _lastTimestamp = timestamp;
            return new(effective, rollback);
        }
    }
}
