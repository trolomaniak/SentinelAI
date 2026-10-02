using SentinelAI.Core;

internal static class LicenseStateMachineTests
{
    private static int _assertions;

    public static void Run()
    {
        var issued = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
        var deadline = issued.AddDays(7);
        Check(LicenseStateMachine.Evaluate(issued, issued, deadline, true, true, false) == LicenseMode.Full,
            "Successful validation must enable full mode.");
        Check(LicenseStateMachine.Evaluate(issued.AddDays(1), issued, deadline, true, false, false) == LicenseMode.Grace,
            "A connectivity failure inside seven days must enable grace.");
        Check(LicenseStateMachine.Evaluate(deadline.AddTicks(-1), issued, deadline, true, false, false) == LicenseMode.Grace,
            "Grace must remain available immediately before its boundary.");
        Check(LicenseStateMachine.Evaluate(deadline, issued, deadline, true, false, false) == LicenseMode.SafeMode,
            "The exact seven-day boundary must enter Safe Mode.");
        Check(LicenseStateMachine.Evaluate(issued.AddDays(8), issued, deadline, true, false, false) == LicenseMode.SafeMode,
            "An automated eight-day outage must enter Safe Mode.");
        Check(LicenseStateMachine.Evaluate(deadline, issued, deadline, true, true, false) == LicenseMode.SafeMode,
            "A previous successful attempt cannot keep an expired lease in full mode.");
        Check(LicenseStateMachine.Evaluate(issued.AddHours(2), issued, issued.AddHours(1), true, false, false) == LicenseMode.SafeMode,
            "A shorter signed expiration must end grace before seven days.");
        Check(LicenseStateMachine.Evaluate(issued.AddDays(7), issued, issued.AddDays(14), true, false, false) == LicenseMode.SafeMode,
            "No lease may extend grace beyond seven days since validation.");
        Check(LicenseStateMachine.Evaluate(issued, null, null, false, false, false) == LicenseMode.SafeMode,
            "A fresh installation without a trusted lease must use Safe Mode.");
        Check(LicenseStateMachine.Evaluate(issued, issued, deadline, false, true, false) == LicenseMode.SafeMode,
            "An untrusted token cannot grant full mode.");
        Check(LicenseStateMachine.Evaluate(issued.AddTicks(-1), issued, deadline, true, true, false) == LicenseMode.SafeMode,
            "A future validation baseline cannot grant full mode.");
        Check(LicenseStateMachine.Evaluate(issued, issued, issued, true, true, false) == LicenseMode.SafeMode,
            "A nonpositive validity window cannot grant full mode.");
        Check(LicenseStateMachine.Evaluate(issued.AddDays(8), issued, deadline, true, false, true) == LicenseMode.Recovering,
            "A renewal attempt after an outage must expose Recovering.");
        var restored = issued.AddDays(8);
        Check(LicenseStateMachine.Evaluate(restored, restored, restored.AddDays(7), true, true, false) == LicenseMode.Full,
            "A successful fresh validation after connectivity returns must restore full mode.");

        foreach (var state in new[]
        {
            (Now: issued, Last: (DateTimeOffset?)issued, Until: (DateTimeOffset?)deadline, Trusted: true, Success: true, Recovering: false),
            (Now: issued.AddDays(1), Last: (DateTimeOffset?)issued, Until: (DateTimeOffset?)deadline, Trusted: true, Success: false, Recovering: false),
            (Now: issued.AddDays(8), Last: (DateTimeOffset?)issued, Until: (DateTimeOffset?)deadline, Trusted: true, Success: false, Recovering: false),
            (Now: issued.AddDays(8), Last: (DateTimeOffset?)issued, Until: (DateTimeOffset?)deadline, Trusted: true, Success: false, Recovering: true),
            (Now: issued, Last: (DateTimeOffset?)null, Until: (DateTimeOffset?)null, Trusted: false, Success: false, Recovering: false)
        })
        {
            var capabilities = LicenseStateMachine.Capabilities(state.Now, state.Last, state.Until,
                state.Trusted, state.Success, state.Recovering);
            Check(capabilities.CriticalTelemetryCollection && capabilities.LocalDetectionRules &&
                capabilities.CriticalAlerts && capabilities.RecentIncidents && capabilities.EmergencyExport,
                "Every mode must preserve telemetry, detection, alerts, incidents, and emergency export.");
        }
        Check(LicenseStateMachine.Capabilities(issued, issued, deadline, true, true, false).PremiumFeatures,
            "Full mode must permit optional premium features.");
        Check(LicenseStateMachine.Capabilities(issued.AddDays(1), issued, deadline, true, false, true).PremiumFeatures,
            "Recovering from grace must retain grace permissions.");
        Check(!LicenseStateMachine.Capabilities(deadline, issued, deadline, true, false, true).PremiumFeatures,
            "Recovering must not extend optional feature authorization past expiration.");
        Check(!LicenseStateMachine.Capabilities(issued, null, null, false, false, true).PremiumFeatures,
            "Recovering without a valid lease must not grant optional features.");

        TestClock(issued);
        Console.WriteLine($"License state/clock checks passed ({_assertions} assertions).");
    }

    private static void TestClock(DateTimeOffset start)
    {
        var provider = new IndependentTimeProvider(start);
        var clock = new LicenseClock(provider);
        var first = clock.Observe(DateTimeOffset.MinValue);
        Check(first.UtcNow == start && !first.RollbackDetected, "Initial clock observation must use UTC wall time.");
        provider.Advance(TimeSpan.FromHours(1));
        var advanced = clock.Observe(first.UtcNow);
        Check(advanced.UtcNow == start.AddHours(1) && !advanced.RollbackDetected,
            "Normal wall and monotonic progress must advance effective UTC.");
        provider.WallUtc = start.AddHours(-1);
        provider.AdvanceMonotonic(TimeSpan.FromMinutes(5));
        var rolledBack = clock.Observe(advanced.UtcNow);
        Check(rolledBack.RollbackDetected && rolledBack.UtcNow == advanced.UtcNow.AddMinutes(5),
            "A backwards wall clock must be detected while monotonic time continues.");
        provider.AdvanceMonotonic(TimeSpan.FromDays(8));
        var expired = clock.Observe(rolledBack.UtcNow);
        Check(expired.UtcNow > start.AddDays(7), "A frozen rolled-back wall clock cannot freeze the grace deadline.");
        Check(LicenseStateMachine.Evaluate(expired.UtcNow, start, start.AddDays(7), true, false, false) == LicenseMode.SafeMode,
            "Monotonic passage during rollback must eventually force Safe Mode.");

        var restarted = new LicenseClock(new IndependentTimeProvider(start));
        var restored = restarted.Observe(expired.UtcNow);
        Check(restored.RollbackDetected && restored.UtcNow == expired.UtcNow,
            "Restart must preserve the persisted high-water time and detect rollback.");

        var slightProvider = new IndependentTimeProvider(start);
        var slightClock = new LicenseClock(slightProvider);
        slightClock.Observe(start);
        slightProvider.WallUtc = start.AddSeconds(-30);
        var slight = slightClock.Observe(start);
        Check(!slight.RollbackDetected && slight.UtcNow == start,
            "A small wall adjustment must not reduce effective time or flag an obvious rollback.");

        var extremeProvider = new IndependentTimeProvider(DateTimeOffset.MaxValue.AddSeconds(-1));
        var extremeClock = new LicenseClock(extremeProvider);
        extremeClock.Observe(DateTimeOffset.MinValue);
        extremeProvider.AdvanceMonotonic(TimeSpan.FromDays(1));
        Check(extremeClock.Observe(DateTimeOffset.MinValue).UtcNow == DateTimeOffset.MaxValue,
            "Clock arithmetic near the timestamp limit must saturate rather than throw.");
        Check(LicenseStateMachine.Evaluate(DateTimeOffset.MaxValue, DateTimeOffset.MaxValue.AddDays(-1),
                DateTimeOffset.MaxValue, true, false, false) == LicenseMode.SafeMode,
            "Deadline calculations near the timestamp limit must not overflow.");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        _assertions++;
    }

    private sealed class IndependentTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private long _timestamp;
        public DateTimeOffset WallUtc { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => WallUtc;
        public override long GetTimestamp() => _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public void AdvanceMonotonic(TimeSpan elapsed) => _timestamp += elapsed.Ticks;
        public void Advance(TimeSpan elapsed)
        {
            WallUtc = WallUtc.Add(elapsed);
            AdvanceMonotonic(elapsed);
        }
    }
}
