namespace SentinelAI.Desktop.Foundation;

// Public administrator projections only. Core retains activation credentials,
// signed leases, issuer configuration and all licensing decisions.
public sealed record LicenseCapabilities(bool CriticalTelemetryCollection, bool LocalDetectionRules,
    bool CriticalAlerts, bool RecentIncidents, bool EmergencyExport, bool PremiumFeatures);
public sealed record LicenseStatus(string Mode, LicenseCapabilities Capabilities,
    DateTimeOffset? LastSuccessfulValidationUtc, DateTimeOffset? FullModeUntil,
    DateTimeOffset EffectiveUtc, bool ClockRollbackDetected, IReadOnlyList<string> EnabledFeatures);

public enum LicenseRequestOutcome
{
    Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge, Throttled, Indeterminate
}
public sealed record LicenseRequestResult(LicenseRequestOutcome Outcome, LicenseStatus? Status = null);
public interface ILicenseClient
{
    Task<LicenseRequestResult> GetLicenseAsync(CancellationToken cancellationToken);
    Task<LicenseRequestResult> RenewLicenseAsync(CancellationToken cancellationToken);
}
