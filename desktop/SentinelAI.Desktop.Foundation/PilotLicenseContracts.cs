namespace SentinelAI.Desktop.Foundation;

// MVP-3 pilot license as Core reports it. Core verifies the key offline and decides the state; Desktop only shows it.
// The pilot never changes local monitoring, and grants no cloud permission.
public sealed record PilotContactDetails(string Company, string Email, string Phone, string Website);
public sealed record PilotLicenseInfo(string State, string? Customer, DateTimeOffset? StartsUtc, DateTimeOffset? ExpiresUtc,
    int? DaysLeft, DateTimeOffset EffectiveUtc, PilotContactDetails? Contact);

public enum PilotLicenseOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge, NotConfigured, Rejected, Expired }
public sealed record PilotLicenseResult(PilotLicenseOutcome Outcome, PilotLicenseInfo? Info = null);

public interface IPilotLicenseClient
{
    Task<PilotLicenseResult> GetPilotLicenseAsync(CancellationToken cancellationToken);
    Task<PilotLicenseResult> SetPilotLicenseKeyAsync(string key, CancellationToken cancellationToken);
}

public enum UninstallLaunchOutcome { Started, Cancelled, Unavailable }

/// <summary>Starts the installed SentinelAI Setup in its uninstall view: data is retained unless DELETE is typed there.</summary>
public interface ISetupUninstallLauncher
{
    UninstallLaunchOutcome Start();
}
