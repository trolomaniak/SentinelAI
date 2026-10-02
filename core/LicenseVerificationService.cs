using SentinelAI.Licensing;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

/// <summary>Signature and identity verification without contacting the license server.</summary>
public sealed class LicenseVerificationService(
    LicenseVerificationOptions options,
    EnrollmentStore enrollments,
    TimeProvider clock)
{
    public bool Configured => options.Configured;

    public async Task<LeaseVerificationResult> VerifyAsync(
        string? lease, CancellationToken cancellationToken = default)
    {
        var identity = await enrollments.GetCoreIdentityAsync(cancellationToken);
        return options.Verifier.Verify(lease, identity.OrganizationId,
            identity.CoreInstallationId, clock.GetUtcNow());
    }
}
