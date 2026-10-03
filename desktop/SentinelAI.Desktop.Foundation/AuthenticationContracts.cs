namespace SentinelAI.Desktop.Foundation;

public enum AuthenticationOutcome
{
    Authenticated,
    InvalidCredentials,
    Throttled,
    Unavailable,
    UntrustedConnection,
    InvalidResponse
}

public enum SessionStatus
{
    SignedOut,
    Authenticated,
    Expired,
    Unavailable,
    UntrustedConnection
}

public sealed record AuthenticationResult(AuthenticationOutcome Outcome, string? Username = null);
public sealed record SessionResult(SessionStatus Status, string? Username = null);

/// <summary>Core verifies credentials; implementations retain no passwords and expose no bearer tokens.</summary>
public interface IAuthenticationClient : IDisposable
{
    Task<AuthenticationResult> SignInAsync(string username, ReadOnlyMemory<char> password, CancellationToken cancellationToken);
    Task<SessionResult> ValidateSessionAsync(CancellationToken cancellationToken);
    void SignOut();
}

public enum AdministratorSetupState
{
    Required,
    Initialized,
    Unavailable,
    PermissionRequired,
    UntrustedInstallation
}

public enum AdministratorSetupResult
{
    Created,
    AlreadyInitialized,
    InvalidInput,
    Unavailable,
    PermissionRequired,
    UntrustedInstallation
}

/// <summary>Only a trusted local Core process may inspect or initialize the protected administrator store.</summary>
public interface IAdministratorSetupClient : IDisposable
{
    Task<AdministratorSetupState> GetStateAsync(CancellationToken cancellationToken);
    Task<AdministratorSetupResult> InitializeAsync(string username, ReadOnlyMemory<char> password, CancellationToken cancellationToken);
}

/// <summary>A trusted composition root verifies Core before sending credentials or session material.</summary>
public interface ICoreEndpointTrust
{
    Task<bool> IsTrustedAsync(Uri origin, CancellationToken cancellationToken);
}
