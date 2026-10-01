namespace SentinelAI.Contracts.Inventory;

public sealed record InventoryReport(
    Guid EndpointId,
    DateTimeOffset CollectedUtc,
    string AgentVersion,
    string Hostname,
    string OsName,
    string OsVersion,
    string Architecture,
    CpuInventory Cpu,
    long? InstalledRamBytes,
    IReadOnlyList<DiskInventory> Disks,
    SecurityPostureInventory SecurityPosture);

public sealed record CpuInventory(string? Model, int LogicalProcessorCount);

public sealed record DiskInventory(string Name, long TotalBytes, long AvailableBytes);

public sealed record SecurityPostureInventory(
    bool? DomainFirewallEnabled,
    bool? PrivateFirewallEnabled,
    bool? PublicFirewallEnabled);
