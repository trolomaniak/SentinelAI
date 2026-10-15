using System.Globalization;
using SentinelAI.Contracts.EndpointTelemetry;
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

        var telemetry = detail.SecurityTelemetry;
        SecurityTelemetryReported = telemetry is not null;
        TelemetryStatusText = telemetry is null
            ? "No endpoint telemetry reported. Every telemetry value is Unknown, which is not evidence of protection."
            : "Observed values from the Agent. Unknown means the value was not observed, and is not evidence of protection.";
        TelemetryFacts = Array.AsReadOnly(TelemetryPresentation.Facts(telemetry).ToArray());
    }

    public Guid EndpointId => Device.EndpointId;
    public string Name => Device.Name;
    public DeviceRow Device { get; }
    public string InventoryStatusText { get; }
    public IReadOnlyList<DisplayFact> Facts { get; }
    public IReadOnlyList<DisplayFact> PostureFacts { get; }
    public bool SecurityTelemetryReported { get; }
    public string TelemetryStatusText { get; }
    public IReadOnlyList<DisplayFact> TelemetryFacts { get; }

    private static string Boolean(bool? value) => value switch { true => "Enabled", false => "Disabled", null => "Unknown" };
    private static string Number(int? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "Unknown";
    private static string Bytes(long? bytes) => bytes is null ? "Unknown" : bytes.Value.ToString("N0", CultureInfo.InvariantCulture) + " bytes";
}

/// <summary>
/// Literal text for endpoint telemetry. Every value that was not observed says Unknown and why: not reported, not
/// supported on the endpoint, not readable by the Agent's account, or unavailable.
/// </summary>
public static class TelemetryPresentation
{
    private static readonly IReadOnlyDictionary<string, string> ServiceNames = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["WinDefend"] = "Microsoft Defender Antivirus (WinDefend)",
        ["WdNisSvc"] = "Defender network inspection (WdNisSvc)",
        ["Sense"] = "Defender for Endpoint (Sense)",
        ["MpsSvc"] = "Windows Defender Firewall (MpsSvc)",
        ["BFE"] = "Base Filtering Engine (BFE)",
        ["EventLog"] = "Windows Event Log (EventLog)",
        ["wscsvc"] = "Security Center (wscsvc)",
        ["SecurityHealthService"] = "Windows Security service (SecurityHealthService)",
        ["wuauserv"] = "Windows Update (wuauserv)"
    };

    public static IEnumerable<DisplayFact> Facts(EndpointTelemetryDetail? telemetry)
    {
        yield return new("Telemetry collected", telemetry is null ? "Not reported" : DeviceRow.Timestamp(telemetry.CollectedUtc));
        yield return new("Telemetry received by Core", telemetry is null ? "Not reported" : DeviceRow.Timestamp(telemetry.ReceivedUtc));

        var bitLocker = telemetry?.BitLocker;
        yield return new("BitLocker protection (system volume)", Value(telemetry, bitLocker?.Availability, bitLocker?.ProtectionStatus switch
        {
            "on" => "On",
            "off" => "Off",
            _ => null
        }));
        yield return new("BitLocker encryption (system volume)", Value(telemetry, bitLocker?.Availability, bitLocker?.ConversionStatus switch
        {
            "fullyDecrypted" => "Fully decrypted",
            "fullyEncrypted" => "Fully encrypted",
            "encryptionInProgress" => "Encryption in progress",
            "decryptionInProgress" => "Decryption in progress",
            "encryptionPaused" => "Encryption paused",
            "decryptionPaused" => "Decryption paused",
            _ => null
        }));

        var antivirus = telemetry?.Antivirus;
        yield return new("Antivirus health (Windows Security Center)", Value(telemetry, antivirus?.Availability, antivirus?.SecurityCenterHealth switch
        {
            "good" => "Good",
            "notMonitored" => "Not monitored",
            "poor" => "Poor",
            "snooze" => "Snoozed",
            _ => null
        }));

        var defender = telemetry?.Defender;
        yield return new("Microsoft Defender mode", Value(telemetry, defender?.Availability, defender?.RunningMode switch
        {
            "normal" => "Active",
            "passive" => "Passive",
            "edrBlock" => "EDR block mode",
            "sxsPassive" => "Side-by-side passive",
            _ => null
        }));
        yield return new("Microsoft Defender antivirus", Value(telemetry, defender?.Availability, Enabled(defender?.AntivirusEnabled)));
        yield return new("Microsoft Defender real-time protection", Value(telemetry, defender?.Availability, Enabled(defender?.RealTimeProtectionEnabled)));
        yield return new("Microsoft Defender tamper protection", Value(telemetry, defender?.Availability, Enabled(defender?.TamperProtectionEnabled)));
        yield return new("Microsoft Defender signature age", Value(telemetry, defender?.Availability,
            defender?.SignatureAgeDays is { } days ? days.ToString(CultureInfo.InvariantCulture) + (days == 1 ? " day" : " days") : null));

        var administrators = telemetry?.LocalAdministrators;
        yield return new("Local Administrators members", Value(telemetry, administrators?.Availability,
            administrators?.MemberCount?.ToString(CultureInfo.InvariantCulture)));
        if (administrators is { Availability: TelemetryAvailability.Collected, Members: { } members })
        {
            yield return new("Local Administrators composition", Composition(members));
            foreach (var member in members)
                yield return new("Administrators member", $"{member.Sid} · {Scope(member.Scope)} · {AccountType(member.AccountType)}");
            if (administrators.MemberCount > members.Count)
                yield return new("Administrators members not listed", (administrators.MemberCount.Value - members.Count).ToString(CultureInfo.InvariantCulture));
        }

        var update = telemetry?.WindowsUpdate;
        yield return new("Automatic updates policy", Value(telemetry, update?.PolicyAvailability, update?.AutomaticUpdatesPolicy switch
        {
            "notConfigured" => "Not configured by policy",
            "disabled" => "Disabled by policy",
            "notifyDownload" => "Notify before download",
            "autoDownloadNotifyInstall" => "Download automatically, notify to install",
            "autoDownloadScheduledInstall" => "Download and install on a schedule",
            "localAdminChooses" => "Local administrator chooses",
            "autoDownloadNotifyInstallNotifyRestart" => "Download automatically, notify to install and restart",
            _ => null
        }));
        yield return new("Managed update server policy (WSUS)", Value(telemetry, update?.PolicyAvailability, update?.ManagedUpdateServer switch
        {
            true => "Configured",
            false => "Not configured",
            null => null
        }));
        yield return new("Last successful update search", Value(telemetry, update?.ResultsAvailability,
            update?.LastSuccessfulSearchUtc is { } search ? DeviceRow.Timestamp(search) : null));
        yield return new("Last successful update installation", Value(telemetry, update?.ResultsAvailability,
            update?.LastSuccessfulInstallationUtc is { } installation ? DeviceRow.Timestamp(installation) : null));

        var reboot = telemetry?.PendingReboot;
        yield return new("Restart pending (component servicing)", Value(telemetry, reboot?.Availability, Pending(reboot?.ComponentBasedServicing)));
        yield return new("Restart pending (Windows Update)", Value(telemetry, reboot?.Availability, Pending(reboot?.WindowsUpdate)));
        yield return new("Restart pending (file rename operations)", Value(telemetry, reboot?.Availability, Pending(reboot?.PendingFileRenameOperations)));

        var services = telemetry?.Services;
        foreach (var name in EndpointTelemetryContract.MonitoredServices)
        {
            var service = services?.Items?.FirstOrDefault(item => item.Name == name);
            yield return new("Service: " + ServiceNames[name], Value(telemetry, services?.Availability, ServiceText(service)));
        }

        var software = telemetry?.Software;
        yield return new("Installed applications (machine-wide)", Value(telemetry, software?.Availability, software switch
        {
            { TotalCount: { } total, ReportedCount: { } reported, Truncated: true } =>
                $"{total.ToString("N0", CultureInfo.InvariantCulture)} ({reported.ToString("N0", CultureInfo.InvariantCulture)} reported; list truncated)",
            { TotalCount: { } total } => total.ToString("N0", CultureInfo.InvariantCulture),
            _ => null
        }));
        if (software is { Availability: TelemetryAvailability.Collected, SkippedCount: > 0 })
            yield return new("Application entries not readable", software.SkippedCount.ToString("N0", CultureInfo.InvariantCulture));
    }

    /// <summary>The observed value, or Unknown with the reason the value was not observed.</summary>
    public static string Value(EndpointTelemetryDetail? telemetry, string? availability, string? observed) =>
        telemetry is null ? "Unknown (no telemetry reported)" : availability switch
        {
            TelemetryAvailability.Collected => observed ?? "Unknown",
            TelemetryAvailability.Unsupported => "Unknown (not supported on this endpoint)",
            TelemetryAvailability.AccessDenied => "Unknown (not readable by the Agent's service account)",
            _ => "Unknown (source unavailable)"
        };

    private static string? Enabled(bool? value) => value switch { true => "Enabled", false => "Disabled", null => null };
    private static string? Pending(bool? value) => value switch { true => "Pending", false => "Not pending", null => null };

    private static string? ServiceText(SecurityServiceObservation? service)
    {
        if (service is null) return null;
        if (service.State == ServiceRunStates.NotInstalled) return "Not installed";
        var state = service.State switch
        {
            "running" => "Running",
            "stopped" => "Stopped",
            "startPending" => "Starting",
            "stopPending" => "Stopping",
            "paused" => "Paused",
            "pausePending" => "Pausing",
            "continuePending" => "Resuming",
            _ => "State unknown"
        };
        var start = service.StartType switch
        {
            "auto" => "automatic start",
            "demand" => "manual start",
            "disabled" => "start disabled",
            "boot" => "boot start",
            "system" => "system start",
            _ => "start type unknown"
        };
        return $"{state} · {start}";
    }

    private static string Composition(IReadOnlyList<LocalAdministratorMember> members)
    {
        var parts = new (string Scope, string Label)[]
        {
            (AdministratorScopes.Local, "local"), (AdministratorScopes.Domain, "domain"), (AdministratorScopes.Entra, "Microsoft Entra"),
            (AdministratorScopes.WellKnown, "built-in or well-known")
        }.Select(part => (part.Label, Count: members.Count(member => member.Scope == part.Scope)))
            .Where(part => part.Count > 0).Select(part => $"{part.Count.ToString(CultureInfo.InvariantCulture)} {part.Label}").ToList();
        var unknown = members.Count(member => member.Scope is null);
        if (unknown > 0) parts.Add($"{unknown.ToString(CultureInfo.InvariantCulture)} unknown scope");
        return parts.Count == 0 ? "No members" : string.Join(", ", parts);
    }

    private static string Scope(string? scope) => scope switch
    {
        AdministratorScopes.Local => "local",
        AdministratorScopes.Domain => "domain",
        AdministratorScopes.Entra => "Microsoft Entra",
        AdministratorScopes.WellKnown => "built-in or well-known",
        _ => "unknown scope"
    };

    private static string AccountType(string? type) => type switch
    {
        "user" => "user",
        "group" => "group",
        "alias" => "local group",
        "wellKnownGroup" => "well-known group",
        "deletedAccount" => "deleted account",
        "computer" => "computer",
        _ => "unknown type"
    };
}
