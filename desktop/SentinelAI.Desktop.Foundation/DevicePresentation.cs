using System.Globalization;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Desktop.Foundation;

public enum DeviceHealth { Healthy, Warning, Offline, Unknown }
public sealed record DisplayFact(string Label, string Value);

/// <summary>Immutable, nonsecret display fields. Connectivity is taken from Core, never inferred from posture.</summary>
public sealed class DeviceRow
{
    public DeviceRow(DeviceSummary device)
    {
        ArgumentNullException.ThrowIfNull(device);
        EndpointId = device.EndpointId;
        Name = Known(device.Name);
        OperatingSystemText = Known(device.OperatingSystem);
        AgentVersionText = Known(device.AgentVersion);
        Health = device.HealthState switch
        {
            "healthy" => DeviceHealth.Healthy,
            "warning" => DeviceHealth.Warning,
            "offline" => DeviceHealth.Offline,
            _ => DeviceHealth.Unknown
        };
        LastSeenUtc = device.LastSeenUtc;
        InventoryCollectedUtc = device.InventoryCollectedUtc;
        FirewallSummary = device.SecurityPostureSummary switch
        {
            "Firewall enabled on all profiles" => "Enabled on all profiles",
            "Firewall disabled on one or more profiles" => "Disabled on one or more profiles",
            _ => "Unknown"
        };
    }

    public Guid EndpointId { get; }
    public string Name { get; }
    public string OperatingSystemText { get; }
    public string AgentVersionText { get; }
    public DeviceHealth Health { get; }
    public string HealthLabel => Health.ToString();
    public DateTimeOffset? LastSeenUtc { get; }
    public string LastSeenText => Timestamp(LastSeenUtc);
    public DateTimeOffset? InventoryCollectedUtc { get; }
    public string InventoryCollectedText => InventoryCollectedUtc is null ? "Unknown / not reported" : Timestamp(InventoryCollectedUtc);
    public bool HasInventory => InventoryCollectedUtc is not null;
    public string FirewallSummary { get; }

    internal static string Known(string? value) => string.IsNullOrWhiteSpace(value) ? "Unknown" : value;
    internal static string Timestamp(DateTimeOffset? value) => value?.ToUniversalTime()
        .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? "Unknown";
}

/// <summary>Public endpoint inventory facts only; Boolean observations retain their explicit unknown state.</summary>
public sealed class EndpointPresentation
{
    public EndpointPresentation(EndpointDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        Device = new DeviceRow(detail.Device);
        InventoryStatusText = detail.InventoryCollectedUtc is null ? "No inventory reported" : "Inventory reported";
        var facts = new List<DisplayFact>
        {
            new("Hostname", Name),
            new("Endpoint ID", EndpointId.ToString("D")),
            new("Heartbeat connectivity", Device.HealthLabel),
            new("Last heartbeat", Device.LastSeenText),
            new("Inventory", InventoryStatusText),
            new("Last inventory", detail.InventoryCollectedUtc is null ? "No inventory" : DeviceRow.Timestamp(detail.InventoryCollectedUtc)),
            new("Operating system", Device.OperatingSystemText),
            new("Operating system name", DeviceRow.Known(detail.OsName)),
            new("Release / build", DeviceRow.Known(detail.OsVersion)),
            new("Architecture", DeviceRow.Known(detail.Architecture)),
            new("Agent version", Device.AgentVersionText),
            new("CPU model", DeviceRow.Known(detail.Cpu?.Model)),
            new("Logical processors", detail.Cpu is null ? "Unknown" : detail.Cpu.LogicalProcessorCount.ToString(CultureInfo.InvariantCulture)),
            new("Installed RAM", Bytes(detail.InstalledRamBytes))
        };
        if (detail.InventoryCollectedUtc is null || detail.Disks.Count == 0)
            facts.Add(new("Disks", "Unknown"));
        else
            foreach (var disk in detail.Disks)
                facts.Add(new("Disk", $"{DeviceRow.Known(disk.Name)} · {Bytes(disk.TotalBytes)} total · {Bytes(disk.AvailableBytes)} available"));
        Facts = Array.AsReadOnly(facts.ToArray());

        var posture = detail.SecurityPosture;
        var configuration = posture?.Configuration;
        PostureFacts = Array.AsReadOnly(new[]
        {
            new DisplayFact("Configured firewall summary", Device.FirewallSummary),
            new DisplayFact("Configured Domain firewall", Boolean(posture?.DomainFirewallEnabled)),
            new DisplayFact("Configured Private firewall", Boolean(posture?.PrivateFirewallEnabled)),
            new DisplayFact("Configured Public firewall", Boolean(posture?.PublicFirewallEnabled)),
            new DisplayFact("User Account Control", Boolean(configuration?.UacEnabled)),
            new DisplayFact("Administrator consent prompt behavior", Number(configuration?.AdminConsentPromptBehavior)),
            new DisplayFact("Remote Desktop", Boolean(configuration?.RdpEnabled)),
            new DisplayFact("Remote Desktop network level authentication", Boolean(configuration?.RdpNetworkLevelAuthenticationRequired)),
            new DisplayFact("Remote Desktop security layer", Number(configuration?.RdpSecurityLayer)),
            new DisplayFact("Remote Desktop minimum encryption level", Number(configuration?.RdpMinimumEncryptionLevel)),
            new DisplayFact("SMB1 server", Boolean(configuration?.Smb1ServerEnabled)),
            new DisplayFact("SMB insecure guest logons", Boolean(configuration?.SmbInsecureGuestLogonsAllowed)),
            new DisplayFact("Automatic administrator logon", Boolean(configuration?.AutomaticAdminLogonEnabled)),
            new DisplayFact("Local Security Authority protection", Boolean(configuration?.LsaProtectionEnabled)),
            new DisplayFact("Automatic updates", Boolean(configuration?.AutomaticUpdatesDisabled is { } disabled ? !disabled : null))
        });
    }

    public Guid EndpointId => Device.EndpointId;
    public string Name => Device.Name;
    public DeviceRow Device { get; }
    public string InventoryStatusText { get; }
    public IReadOnlyList<DisplayFact> Facts { get; }
    public IReadOnlyList<DisplayFact> PostureFacts { get; }

    private static string Boolean(bool? value) => value switch { true => "Enabled", false => "Disabled", null => "Unknown" };
    private static string Number(int? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "Unknown";
    private static string Bytes(long? bytes) => bytes is null ? "Unknown" : bytes.Value.ToString("N0", CultureInfo.InvariantCulture) + " bytes";
}
