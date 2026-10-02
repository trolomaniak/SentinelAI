using System.Runtime.Versioning;
using Microsoft.Win32;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Agent;

/// <summary>Reads a bounded allowlist of explicit Windows configuration values.</summary>
public static class WindowsSecurityConfigurationCollector
{
    private const string SystemPolicy = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string TerminalServicesPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string TerminalServer = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcp = TerminalServer + @"\WinStations\RDP-Tcp";

    [SupportedOSPlatform("windows")]
    public static SecurityPostureInventory CollectPosture() => CollectPosture(ReadLocalMachineValue);

    // The reader returns null for an absent value and throws for unavailable access.
    // Keeping this overload platform-independent allows deterministic probe tests
    // without changing the machine's registry or requiring administrator privileges.
    public static SecurityPostureInventory CollectPosture(Func<string, string, object?> readValue)
    {
        ArgumentNullException.ThrowIfNull(readValue);

        return new SecurityPostureInventory(
            ReadFirewallEnabled(readValue, "DomainProfile"),
            ReadFirewallEnabled(readValue, "StandardProfile"),
            ReadFirewallEnabled(readValue, "PublicProfile"),
            new WindowsSecurityConfiguration(
                UacEnabled: Read(readValue, "EnableLUA", BooleanDword, SystemPolicy),
                AdminConsentPromptBehavior: Read(readValue, "ConsentPromptBehaviorAdmin",
                    value => BoundedDword(value, 0, 5), SystemPolicy),
                RdpEnabled: Read(readValue, "fDenyTSConnections", InvertedBooleanDword,
                    TerminalServicesPolicy, TerminalServer),
                RdpNetworkLevelAuthenticationRequired: Read(readValue, "UserAuthentication", BooleanDword,
                    TerminalServicesPolicy, RdpTcp),
                RdpSecurityLayer: Read(readValue, "SecurityLayer",
                    value => BoundedDword(value, 0, 2), TerminalServicesPolicy, RdpTcp),
                RdpMinimumEncryptionLevel: Read(readValue, "MinEncryptionLevel",
                    value => BoundedDword(value, 1, 4), TerminalServicesPolicy, RdpTcp),
                Smb1ServerEnabled: Read(readValue, "SMB1", BooleanDword,
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"),
                SmbInsecureGuestLogonsAllowed: Read(readValue, "AllowInsecureGuestAuth", BooleanDword,
                    @"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
                    @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"),
                AutomaticAdminLogonEnabled: Read(readValue, "AutoAdminLogon", BooleanString,
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
                // ConfigureLsaProtectedProcess policy writes RunAsPPL here directly.
                LsaProtectionEnabled: Read(readValue, "RunAsPPL", LsaProtection,
                    @"SYSTEM\CurrentControlSet\Control\Lsa"),
                AutomaticUpdatesDisabled: Read(readValue, "NoAutoUpdate", BooleanDword,
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")));
    }

    private static bool? ReadFirewallEnabled(Func<string, string, object?> readValue, string profile) =>
        Read(readValue, "EnableFirewall", BooleanDword,
            @"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + profile,
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profile);

    private static T? Read<T>(Func<string, string, object?> readValue, string valueName,
        Func<object, T?> parse, params string[] keyPaths) where T : struct
    {
        try
        {
            foreach (var keyPath in keyPaths)
            {
                var value = readValue(keyPath, valueName);
                if (value is not null)
                {
                    // A present policy has precedence even if malformed. Do not
                    // silently substitute a contradictory local configuration.
                    return parse(value);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           System.Security.SecurityException or PlatformNotSupportedException)
        {
            // Unreadable policy is unknown; a local fallback cannot establish it.
        }

        return null;
    }

    private static bool? BooleanDword(object value) => value switch
    {
        0 => false,
        1 => true,
        _ => null
    };

    private static bool? InvertedBooleanDword(object value) => BooleanDword(value) is { } enabled
        ? !enabled
        : null;

    private static int? BoundedDword(object value, int minimum, int maximum) =>
        value is int number && number >= minimum && number <= maximum ? number : null;

    private static bool? BooleanString(object value) => value switch
    {
        "0" => false,
        "1" => true,
        _ => null
    };

    private static bool? LsaProtection(object value) => value switch
    {
        0 => false,
        1 or 2 => true,
        _ => null
    };

    [SupportedOSPlatform("windows")]
    private static object? ReadLocalMachineValue(string keyPath, string valueName)
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(keyPath);
        return key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }
}
