using System.Globalization;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;
using static SentinelAI.Localization.Localizer;

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
            "Firewall enabled on all profiles" => T("Enabled on all profiles"),
            "Firewall disabled on one or more profiles" => T("Disabled on one or more profiles"),
            _ => T("Unknown")
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
    public string InventoryCollectedText => InventoryCollectedUtc is null ? T("Unknown / not reported") : Timestamp(InventoryCollectedUtc);
    public bool HasInventory => InventoryCollectedUtc is not null;
    public string FirewallSummary { get; }

    internal static string Known(string? value) => string.IsNullOrWhiteSpace(value) ? T("Unknown") : value;
    internal static string Timestamp(DateTimeOffset? value) => value?.ToUniversalTime()
        .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? T("Unknown");
}

/// <summary>Public endpoint inventory facts only; Boolean observations retain their explicit unknown state.</summary>
public sealed class EndpointPresentation
{
    public EndpointPresentation(EndpointDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);
        Device = new DeviceRow(detail.Device);
        InventoryStatusText = detail.InventoryCollectedUtc is null ? T("No inventory reported") : T("Inventory reported");
        var facts = new List<DisplayFact>
        {
            new(T("Hostname"), Name),
            new(T("Endpoint ID"), EndpointId.ToString("D")),
            new(T("Heartbeat connectivity"), Device.HealthLabel),
            new(T("Last heartbeat"), Device.LastSeenText),
            new(T("Inventory"), InventoryStatusText),
            new(T("Last inventory"), detail.InventoryCollectedUtc is null ? T("No inventory") : DeviceRow.Timestamp(detail.InventoryCollectedUtc)),
            new(T("Operating system"), Device.OperatingSystemText),
            new(T("Operating system name"), DeviceRow.Known(detail.OsName)),
            new(T("Release / build"), DeviceRow.Known(detail.OsVersion)),
            new(T("Architecture"), DeviceRow.Known(detail.Architecture)),
            new(T("Agent version"), Device.AgentVersionText),
            new(T("CPU model"), DeviceRow.Known(detail.Cpu?.Model)),
            new(T("Logical processors"), detail.Cpu is null ? T("Unknown") : detail.Cpu.LogicalProcessorCount.ToString(CultureInfo.InvariantCulture)),
            new(T("Installed RAM"), Bytes(detail.InstalledRamBytes))
        };
        if (detail.InventoryCollectedUtc is null || detail.Disks.Count == 0)
            facts.Add(new(T("Disks"), "Unknown"));
        else
            foreach (var disk in detail.Disks)
                facts.Add(new(T("Disk"), F("{0} · {1} total · {2} available", DeviceRow.Known(disk.Name), Bytes(disk.TotalBytes), Bytes(disk.AvailableBytes))));
        Facts = Array.AsReadOnly(facts.ToArray());

        var posture = detail.SecurityPosture;
        var configuration = posture?.Configuration;
        PostureFacts = Array.AsReadOnly(new[]
        {
            new DisplayFact(T("Configured firewall summary"), Device.FirewallSummary),
            new DisplayFact(T("Configured Domain firewall"), Boolean(posture?.DomainFirewallEnabled)),
            new DisplayFact(T("Configured Private firewall"), Boolean(posture?.PrivateFirewallEnabled)),
            new DisplayFact(T("Configured Public firewall"), Boolean(posture?.PublicFirewallEnabled)),
            new DisplayFact(T("User Account Control"), Boolean(configuration?.UacEnabled)),
            new DisplayFact(T("Administrator consent prompt behavior"), Number(configuration?.AdminConsentPromptBehavior)),
            new DisplayFact(T("Remote Desktop"), Boolean(configuration?.RdpEnabled)),
            new DisplayFact(T("Remote Desktop network level authentication"), Boolean(configuration?.RdpNetworkLevelAuthenticationRequired)),
            new DisplayFact(T("Remote Desktop security layer"), Number(configuration?.RdpSecurityLayer)),
            new DisplayFact(T("Remote Desktop minimum encryption level"), Number(configuration?.RdpMinimumEncryptionLevel)),
            new DisplayFact(T("SMB1 server"), Boolean(configuration?.Smb1ServerEnabled)),
            new DisplayFact(T("SMB insecure guest logons"), Boolean(configuration?.SmbInsecureGuestLogonsAllowed)),
            new DisplayFact(T("Automatic administrator logon"), Boolean(configuration?.AutomaticAdminLogonEnabled)),
            new DisplayFact(T("Local Security Authority protection"), Boolean(configuration?.LsaProtectionEnabled)),
            new DisplayFact(T("Automatic updates"), Boolean(configuration?.AutomaticUpdatesDisabled is { } disabled ? !disabled : null))
        });

        var telemetry = detail.SecurityTelemetry;
        SecurityTelemetryReported = telemetry is not null;
        TelemetryStatusText = telemetry is null
            ? T("No endpoint telemetry reported. Every telemetry value is Unknown, which is not evidence of protection.")
            : T("Observed values from the Agent. Unknown means the value was not observed, and is not evidence of protection.");
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

    private static string Boolean(bool? value) => value switch { true => T("Enabled"), false => T("Disabled"), null => T("Unknown") };
    private static string Number(int? value) => value?.ToString(CultureInfo.InvariantCulture) ?? T("Unknown");
    private static string Bytes(long? bytes) => bytes is null ? T("Unknown") : bytes.Value.ToString("N0", CultureInfo.InvariantCulture) + " bytes";
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
        yield return new(T("Telemetry collected"), telemetry is null ? T("Not reported") : DeviceRow.Timestamp(telemetry.CollectedUtc));
        yield return new(T("Telemetry received by Core"), telemetry is null ? T("Not reported") : DeviceRow.Timestamp(telemetry.ReceivedUtc));

        var bitLocker = telemetry?.BitLocker;
        yield return new(T("BitLocker protection (system volume)"), Value(telemetry, bitLocker?.Availability, bitLocker?.ProtectionStatus switch
        {
            "on" => T("On"),
            "off" => T("Off"),
            _ => null
        }));
        yield return new(T("BitLocker encryption (system volume)"), Value(telemetry, bitLocker?.Availability, bitLocker?.ConversionStatus switch
        {
            "fullyDecrypted" => T("Fully decrypted"),
            "fullyEncrypted" => T("Fully encrypted"),
            "encryptionInProgress" => T("Encryption in progress"),
            "decryptionInProgress" => T("Decryption in progress"),
            "encryptionPaused" => T("Encryption paused"),
            "decryptionPaused" => T("Decryption paused"),
            _ => null
        }));

        var antivirus = telemetry?.Antivirus;
        yield return new(T("Antivirus health (Windows Security Center)"), Value(telemetry, antivirus?.Availability, antivirus?.SecurityCenterHealth switch
        {
            "good" => T("Good"),
            "notMonitored" => T("Not monitored"),
            "poor" => T("Poor"),
            "snooze" => T("Snoozed"),
            _ => null
        }));

        var defender = telemetry?.Defender;
        yield return new(T("Microsoft Defender mode"), Value(telemetry, defender?.Availability, defender?.RunningMode switch
        {
            "normal" => T("Active"),
            "passive" => T("Passive"),
            "edrBlock" => T("EDR block mode"),
            "sxsPassive" => T("Side-by-side passive"),
            _ => null
        }));
        yield return new(T("Microsoft Defender antivirus"), Value(telemetry, defender?.Availability, Enabled(defender?.AntivirusEnabled)));
        yield return new(T("Microsoft Defender real-time protection"), Value(telemetry, defender?.Availability, Enabled(defender?.RealTimeProtectionEnabled)));
        yield return new(T("Microsoft Defender tamper protection"), Value(telemetry, defender?.Availability, Enabled(defender?.TamperProtectionEnabled)));
        yield return new(T("Microsoft Defender signature age"), Value(telemetry, defender?.Availability,
            defender?.SignatureAgeDays is { } days ? days.ToString(CultureInfo.InvariantCulture) + (days == 1 ? " day" : " days") : null));

        var administrators = telemetry?.LocalAdministrators;
        yield return new(T("Local Administrators members"), Value(telemetry, administrators?.Availability,
            administrators?.MemberCount?.ToString(CultureInfo.InvariantCulture)));
        if (administrators is { Availability: TelemetryAvailability.Collected, Members: { } members })
        {
            yield return new(T("Local Administrators composition"), Composition(members));
            foreach (var member in members)
                yield return new(T("Administrators member"), $"{member.Sid} · {Scope(member.Scope)} · {AccountType(member.AccountType)}");
            if (administrators.MemberCount > members.Count)
                yield return new(T("Administrators members not listed"), (administrators.MemberCount.Value - members.Count).ToString(CultureInfo.InvariantCulture));
        }

        var update = telemetry?.WindowsUpdate;
        yield return new(T("Automatic updates policy"), Value(telemetry, update?.PolicyAvailability, update?.AutomaticUpdatesPolicy switch
        {
            "notConfigured" => T("Not configured by policy"),
            "disabled" => T("Disabled by policy"),
            "notifyDownload" => T("Notify before download"),
            "autoDownloadNotifyInstall" => T("Download automatically, notify to install"),
            "autoDownloadScheduledInstall" => T("Download and install on a schedule"),
            "localAdminChooses" => T("Local administrator chooses"),
            "autoDownloadNotifyInstallNotifyRestart" => T("Download automatically, notify to install and restart"),
            _ => null
        }));
        yield return new(T("Managed update server policy (WSUS)"), Value(telemetry, update?.PolicyAvailability, update?.ManagedUpdateServer switch
        {
            true => T("Configured"),
            false => T("Not configured"),
            null => null
        }));
        yield return new(T("Last successful update search"), Value(telemetry, update?.ResultsAvailability,
            update?.LastSuccessfulSearchUtc is { } search ? DeviceRow.Timestamp(search) : null));
        yield return new(T("Last successful update installation"), Value(telemetry, update?.ResultsAvailability,
            update?.LastSuccessfulInstallationUtc is { } installation ? DeviceRow.Timestamp(installation) : null));

        var reboot = telemetry?.PendingReboot;
        yield return new(T("Restart pending (component servicing)"), Value(telemetry, reboot?.Availability, Pending(reboot?.ComponentBasedServicing)));
        yield return new(T("Restart pending (Windows Update)"), Value(telemetry, reboot?.Availability, Pending(reboot?.WindowsUpdate)));
        yield return new(T("Restart pending (file rename operations)"), Value(telemetry, reboot?.Availability, Pending(reboot?.PendingFileRenameOperations)));

        var services = telemetry?.Services;
        foreach (var name in EndpointTelemetryContract.MonitoredServices)
        {
            var service = services?.Items?.FirstOrDefault(item => item.Name == name);
            yield return new(T("Service: ") + ServiceNames[name], Value(telemetry, services?.Availability, ServiceText(service)));
        }

        var software = telemetry?.Software;
        yield return new(T("Installed applications (machine-wide)"), Value(telemetry, software?.Availability, software switch
        {
            { TotalCount: { } total, ReportedCount: { } reported, Truncated: true } =>
                F("{0} ({1} reported; list truncated)", total.ToString("N0", CultureInfo.InvariantCulture), reported.ToString("N0", CultureInfo.InvariantCulture)),
            { TotalCount: { } total } => total.ToString("N0", CultureInfo.InvariantCulture),
            _ => null
        }));
        if (software is { Availability: TelemetryAvailability.Collected, SkippedCount: > 0 })
            yield return new(T("Application entries not readable"), software.SkippedCount.ToString("N0", CultureInfo.InvariantCulture));
    }

    /// <summary>The observed value, or Unknown with the reason the value was not observed.</summary>
    public static string Value(EndpointTelemetryDetail? telemetry, string? availability, string? observed) =>
        telemetry is null ? T("Unknown (no telemetry reported)") : availability switch
        {
            TelemetryAvailability.Collected => observed ?? T("Unknown"),
            TelemetryAvailability.Unsupported => T("Unknown (not supported on this endpoint)"),
            TelemetryAvailability.AccessDenied => T("Unknown (not readable by the Agent's service account)"),
            _ => T("Unknown (source unavailable)")
        };

    private static string? Enabled(bool? value) => value switch { true => T("Enabled"), false => T("Disabled"), null => null };
    private static string? Pending(bool? value) => value switch { true => T("Pending"), false => T("Not pending"), null => null };

    private static string? ServiceText(SecurityServiceObservation? service)
    {
        if (service is null) return null;
        if (service.State == ServiceRunStates.NotInstalled) return T("Not installed");
        var state = service.State switch
        {
            "running" => T("Running"),
            "stopped" => T("Stopped"),
            "startPending" => T("Starting"),
            "stopPending" => T("Stopping"),
            "paused" => T("Paused"),
            "pausePending" => T("Pausing"),
            "continuePending" => T("Resuming"),
            _ => T("State unknown")
        };
        var start = service.StartType switch
        {
            "auto" => T("automatic start"),
            "demand" => T("manual start"),
            "disabled" => T("start disabled"),
            "boot" => T("boot start"),
            "system" => T("system start"),
            _ => T("start type unknown")
        };
        return $"{state} · {start}";
    }

    private static string Composition(IReadOnlyList<LocalAdministratorMember> members)
    {
        var parts = new (string Scope, string Label)[]
        {
            (AdministratorScopes.Local, "local"), (AdministratorScopes.Domain, "domain"), (AdministratorScopes.Entra, T("Microsoft Entra")),
            (AdministratorScopes.WellKnown, T("built-in or well-known"))
        }.Select(part => (part.Label, Count: members.Count(member => member.Scope == part.Scope)))
            .Where(part => part.Count > 0).Select(part => $"{part.Count.ToString(CultureInfo.InvariantCulture)} {part.Label}").ToList();
        var unknown = members.Count(member => member.Scope is null);
        if (unknown > 0) parts.Add(F("{0} unknown scope", unknown));
        return parts.Count == 0 ? T("No members") : string.Join(", ", parts);
    }

    private static string Scope(string? scope) => scope switch
    {
        AdministratorScopes.Local => "local",
        AdministratorScopes.Domain => "domain",
        AdministratorScopes.Entra => T("Microsoft Entra"),
        AdministratorScopes.WellKnown => T("built-in or well-known"),
        _ => T("unknown scope")
    };

    private static string AccountType(string? type) => type switch
    {
        "user" => "user",
        "group" => "group",
        "alias" => T("local group"),
        "wellKnownGroup" => T("well-known group"),
        "deletedAccount" => T("deleted account"),
        "computer" => "computer",
        _ => T("unknown type")
    };
}
