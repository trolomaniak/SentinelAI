namespace SentinelAI.Contracts.Heartbeat;

public sealed record HeartbeatRequest(Guid InstallationId);

public sealed record HeartbeatResponse(
    Guid InstallationId,
    DateTimeOffset LastSeenUtc,
    string HealthStatus);

public static class DeviceHealthStatus
{
    public const string Reporting = "reporting";
}
