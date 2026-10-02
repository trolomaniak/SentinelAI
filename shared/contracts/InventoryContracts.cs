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
    SecurityPostureInventory SecurityPosture,
    string? OsDisplayVersion = null,
    string? OsInstallationType = null);

public sealed record CpuInventory(string? Model, int LogicalProcessorCount);

public sealed record DiskInventory(string Name, long TotalBytes, long AvailableBytes);

public sealed record SecurityPostureInventory(
    bool? DomainFirewallEnabled,
    bool? PrivateFirewallEnabled,
    bool? PublicFirewallEnabled,
    WindowsSecurityConfiguration? Configuration = null);

// Null means unavailable, absent, or unrecognized. These are observed configuration
// values, not assertions about effective protection or Internet reachability.
public sealed record WindowsSecurityConfiguration(
    bool? UacEnabled = null,
    int? AdminConsentPromptBehavior = null,
    bool? RdpEnabled = null,
    bool? RdpNetworkLevelAuthenticationRequired = null,
    int? RdpSecurityLayer = null,
    int? RdpMinimumEncryptionLevel = null,
    bool? Smb1ServerEnabled = null,
    bool? SmbInsecureGuestLogonsAllowed = null,
    bool? AutomaticAdminLogonEnabled = null,
    bool? LsaProtectionEnabled = null,
    bool? AutomaticUpdatesDisabled = null);
