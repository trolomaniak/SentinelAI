namespace SentinelAI.Contracts.Licensing;

public sealed record LeaseClaims(
    Guid OrganizationId,
    Guid InstallationId,
    string Plan,
    int EndpointLimit,
    IReadOnlyList<string> EnabledFeatures,
    DateTimeOffset IssuedAt,
    DateTimeOffset FullModeUntil);

public sealed record SignedLease(string Lease)
{
    public override string ToString() => nameof(SignedLease);
}

public sealed record VerifyLeaseRequest(string Lease)
{
    public override string ToString() => nameof(VerifyLeaseRequest);
}
