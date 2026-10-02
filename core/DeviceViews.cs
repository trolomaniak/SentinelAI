using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Core;

public sealed record DeviceListItem(
    Guid EndpointId,
    string Name,
    string? OperatingSystem,
    string HealthState,
    DateTimeOffset? LastSeenUtc,
    string? AgentVersion,
    string SecurityPostureSummary);

public sealed record DeviceDetail(
    DeviceListItem Device,
    DateTimeOffset? InventoryCollectedUtc,
    string? OsVersion,
    string? Architecture,
    CpuInventory? Cpu,
    long? InstalledRamBytes,
    IReadOnlyList<DiskInventory> Disks,
    SecurityPostureInventory? SecurityPosture,
    string? OsName = null);
