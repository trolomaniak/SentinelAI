namespace SentinelAI.Contracts.Enrollment;

public sealed record EnrollmentTokenResponse(
    string Token,
    DateTimeOffset ExpiresUtc,
    Guid CoreInstallationId,
    Guid OrganizationId)
{
    public override string ToString() => nameof(EnrollmentTokenResponse);
}

public sealed record EnrollmentRequest(Guid InstallationId, string EnrollmentToken)
{
    public override string ToString() => nameof(EnrollmentRequest);
}

public sealed record EnrollmentResponse(
    Guid InstallationId,
    Guid EndpointId,
    Guid CoreInstallationId,
    Guid OrganizationId,
    string AgentCredential)
{
    public override string ToString() => nameof(EnrollmentResponse);
}
