using SentinelAI.Contracts.Licensing;

namespace SentinelAI.Licensing;

public enum LeaseVerificationStatus
{
    Valid,
    Expired,
    Invalid,
    NotYetValid,
    IdentityMismatch
}

public sealed record LeaseVerificationResult(
    LeaseVerificationStatus Status,
    LeaseClaims? Claims = null,
    string? KeyId = null);

/// <summary>Authenticated claims only; callers must still enforce time and licensing policy.</summary>
public sealed record AuthenticatedLease(LeaseClaims Claims, string KeyId);
