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
    string? OsName = null);

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
