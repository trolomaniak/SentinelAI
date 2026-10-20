namespace SentinelAI.Desktop.Foundation;

// Core's local-network role as an administrator compares it with an Agent: addresses, the HTTPS port
// and the SHA-256 fingerprint Agents pin. Public values only; Core keeps the certificate key.
public sealed record LocalNetworkStatus(bool Enabled, bool Listening, int? Port, string? CertificateSha256,
    string HostName, string? FullyQualifiedName, IReadOnlyList<string> Addresses);

public enum LocalNetworkRequestOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, TooLarge }
public sealed record LocalNetworkRequestResult(LocalNetworkRequestOutcome Outcome, LocalNetworkStatus? Status = null);
public interface ILocalNetworkClient
{
    Task<LocalNetworkRequestResult> GetLocalNetworkAsync(CancellationToken cancellationToken);
}
