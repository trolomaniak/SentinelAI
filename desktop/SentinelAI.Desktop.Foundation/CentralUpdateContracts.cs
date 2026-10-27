namespace SentinelAI.Desktop.Foundation;

// MVP-7: the optional update of this central installation from the provider's server, as Core reports it. Core
// downloads; the SYSTEM update task verifies the signature before anything runs.
public sealed record CentralUpdateInfo(bool Configured, string? Server, bool CheckEnabled, bool AutoInstall, string InstalledVersion,
    string LastCheck, DateTimeOffset? LastCheckUtc, string? ReadyVersion, int InstallAttempts, DateTimeOffset? LastAttemptUtc);

public enum CentralUpdateRequestOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge, NotConfigured, NotEnabled }
public sealed record CentralUpdateRequestResult(CentralUpdateRequestOutcome Outcome, CentralUpdateInfo? Info = null);

public interface ICentralUpdateClient
{
    Task<CentralUpdateRequestResult> GetCentralUpdateAsync(CancellationToken cancellationToken);
    Task<CentralUpdateRequestResult> SetCentralUpdateSettingsAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken);
    Task<CentralUpdateRequestResult> CheckCentralUpdateAsync(CancellationToken cancellationToken);
}

public enum CentralUpdateInstallOutcome { Started, Cancelled, NothingToInstall, Rejected, Unavailable }

/// <summary>Runs the installed Updater elevated to verify and open the downloaded Setup; Desktop then closes.</summary>
public interface ICentralUpdateInstaller
{
    Task<CentralUpdateInstallOutcome> StartAsync(CancellationToken cancellationToken);
}
