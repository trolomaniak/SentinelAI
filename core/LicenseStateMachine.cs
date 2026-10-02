namespace SentinelAI.Core;

public enum LicenseMode { Full, Grace, SafeMode, Recovering }

public sealed record LicenseCapabilities(
    bool CriticalTelemetryCollection,
    bool LocalDetectionRules,
    bool CriticalAlerts,
    bool RecentIncidents,
    bool EmergencyExport,
    bool PremiumFeatures);

/// <summary>Licensing affects optional features, never the local security baseline.</summary>
public static class LicenseStateMachine
{
    public static readonly TimeSpan GracePeriod = TimeSpan.FromDays(7);

    public static LicenseMode Evaluate(
        DateTimeOffset now,
        DateTimeOffset? lastSuccessfulValidationUtc,
        DateTimeOffset? fullModeUntil,
        bool trustedLease,
        bool lastAttemptSucceeded,
        bool recovering)
    {
        // Recovery describes an in-flight attempt, not an authorization grant.
        if (recovering) return LicenseMode.Recovering;

        if (!trustedLease || lastSuccessfulValidationUtc is not { } validated ||
            fullModeUntil is not { } expires || now < validated || expires <= validated)
        {
            return LicenseMode.SafeMode;
        }

        // Subtraction avoids overflowing when a persisted timestamp is near MaxValue.
        if (now >= expires || now - validated >= GracePeriod) return LicenseMode.SafeMode;
        return lastAttemptSucceeded ? LicenseMode.Full : LicenseMode.Grace;
    }

    public static LicenseCapabilities Capabilities(
        DateTimeOffset now,
        DateTimeOffset? lastSuccessfulValidationUtc,
        DateTimeOffset? fullModeUntil,
        bool trustedLease,
        bool lastAttemptSucceeded,
        bool recovering)
    {
        var underlying = Evaluate(now, lastSuccessfulValidationUtc, fullModeUntil,
            trustedLease, lastAttemptSucceeded, recovering: false);
        return new(true, true, true, true, true,
            underlying is LicenseMode.Full or LicenseMode.Grace);
    }
}
