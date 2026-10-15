using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Desktop.Foundation;

/// <summary>Public administrator device fields; never enrollment or persistence records.</summary>
public sealed record DeviceSummary(
    Guid EndpointId,
    string Name,
    string? OperatingSystem,
    string HealthState,
    DateTimeOffset? LastSeenUtc,
    string? AgentVersion,
    string SecurityPostureSummary,
    DateTimeOffset? InventoryCollectedUtc = null);

public sealed record EndpointDetail(
    DeviceSummary Device,
    DateTimeOffset? InventoryCollectedUtc,
    string? OsVersion,
    string? Architecture,
    CpuInventory? Cpu,
    long? InstalledRamBytes,
    IReadOnlyList<DiskInventory> Disks,
    SecurityPostureInventory? SecurityPosture,
    string? OsName = null,
    EndpointTelemetryDetail? SecurityTelemetry = null);

/// <summary>Core's newest accepted endpoint telemetry (schema 1); installed applications are a summary only.</summary>
public sealed record EndpointTelemetryDetail(
    DateTimeOffset CollectedUtc,
    DateTimeOffset ReceivedUtc,
    BitLockerTelemetry BitLocker,
    AntivirusTelemetry Antivirus,
    DefenderTelemetry Defender,
    LocalAdministratorsTelemetry LocalAdministrators,
    WindowsUpdateTelemetry WindowsUpdate,
    PendingRebootTelemetry PendingReboot,
    SecurityServicesTelemetry Services,
    InstalledSoftwareSummary Software);

public sealed record InstalledSoftwareSummary(string Availability, int? TotalCount, int? ReportedCount, bool Truncated, int SkippedCount);

public enum DeviceReadOutcome
{
    Success,
    Unauthenticated,
    Unavailable,
    UntrustedConnection,
    InvalidResponse,
    NotFound,
    TooLarge
}

public sealed record DeviceReadResult<T>(DeviceReadOutcome Outcome, T? Value = default);

/// <summary>Read-only access owned by the active authentication client.</summary>
public interface IDevicesClient
{
    Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken);
    Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken);
}
