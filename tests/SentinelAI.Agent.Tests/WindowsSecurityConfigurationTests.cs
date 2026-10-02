using System.Text.Json;
using SentinelAI.Agent;
using SentinelAI.Contracts.Inventory;

internal static class WindowsSecurityConfigurationTests
{
    private const string SystemPolicy = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string TerminalPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string TerminalServer = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcp = TerminalServer + @"\WinStations\RDP-Tcp";
    private const string GuestPolicy = @"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
    private const string GuestLocal = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private const string LsaLocal = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string SmbServer = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const string Winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string UpdatePolicy = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";

    public static void Run()
    {
        VerifyAbsentAndBoundedReads();
        VerifyExplicitValues();
        VerifyPolicyPrecedence();
        VerifyInvalidValues();
        VerifyUnavailableValues();
        VerifyLegacyPayload();
    }

    private static void VerifyAbsentAndBoundedReads()
    {
        var calls = new HashSet<(string Key, string Name)>();
        var posture = WindowsSecurityConfigurationCollector.CollectPosture((key, name) =>
        {
            Ensure(calls.Add((key, name)), "Configuration collector repeated a registry probe.");
            return null;
        });
        Ensure(posture == new SecurityPostureInventory(null, null, null, new WindowsSecurityConfiguration()),
            "Missing explicit configuration was replaced with an assumed safe or risky default.");

        var allowed = new HashSet<(string Key, string Name)>
        {
            (SystemPolicy, "EnableLUA"), (SystemPolicy, "ConsentPromptBehaviorAdmin"),
            (TerminalPolicy, "fDenyTSConnections"), (TerminalServer, "fDenyTSConnections"),
            (TerminalPolicy, "UserAuthentication"), (RdpTcp, "UserAuthentication"),
            (TerminalPolicy, "SecurityLayer"), (RdpTcp, "SecurityLayer"),
            (TerminalPolicy, "MinEncryptionLevel"), (RdpTcp, "MinEncryptionLevel"),
            (GuestPolicy, "AllowInsecureGuestAuth"), (GuestLocal, "AllowInsecureGuestAuth"),
            (LsaLocal, "RunAsPPL"),
            (SmbServer, "SMB1"), (Winlogon, "AutoAdminLogon"), (UpdatePolicy, "NoAutoUpdate")
        };
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            allowed.Add((FirewallPolicy(profile), "EnableFirewall"));
            allowed.Add((FirewallLocal(profile), "EnableFirewall"));
        }

        Ensure(calls.Count == 22 && calls.SetEquals(allowed),
            "Configuration collection read outside its bounded allowlist, including possible account secrets.");
    }

    private static void VerifyExplicitValues()
    {
        var risky = new Dictionary<(string, string), object>
        {
            [(SystemPolicy, "EnableLUA")] = 0,
            [(SystemPolicy, "ConsentPromptBehaviorAdmin")] = 0,
            [(TerminalServer, "fDenyTSConnections")] = 0,
            [(RdpTcp, "UserAuthentication")] = 0,
            [(RdpTcp, "SecurityLayer")] = 0,
            [(RdpTcp, "MinEncryptionLevel")] = 1,
            [(SmbServer, "SMB1")] = 1,
            [(GuestLocal, "AllowInsecureGuestAuth")] = 1,
            [(Winlogon, "AutoAdminLogon")] = "1",
            [(LsaLocal, "RunAsPPL")] = 0,
            [(UpdatePolicy, "NoAutoUpdate")] = 1
        };
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            risky[(FirewallLocal(profile), "EnableFirewall")] = 0;
        }

        var posture = Collect(risky);
        Ensure(posture == new SecurityPostureInventory(false, false, false,
                new WindowsSecurityConfiguration(false, 0, true, false, 0, 1, true, true, true, false, true)),
            "Explicit risky settings were parsed incorrectly, including inverse RDP deny semantics.");

        risky[(SystemPolicy, "EnableLUA")] = 1;
        risky[(SystemPolicy, "ConsentPromptBehaviorAdmin")] = 5;
        risky[(TerminalServer, "fDenyTSConnections")] = 1;
        risky[(RdpTcp, "UserAuthentication")] = 1;
        risky[(RdpTcp, "SecurityLayer")] = 2;
        risky[(RdpTcp, "MinEncryptionLevel")] = 4;
        risky[(SmbServer, "SMB1")] = 0;
        risky[(GuestLocal, "AllowInsecureGuestAuth")] = 0;
        risky[(Winlogon, "AutoAdminLogon")] = "0";
        risky[(LsaLocal, "RunAsPPL")] = 2;
        risky[(UpdatePolicy, "NoAutoUpdate")] = 0;
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            risky[(FirewallLocal(profile), "EnableFirewall")] = 1;
        }

        Ensure(Collect(risky) == new SecurityPostureInventory(true, true, true,
                new WindowsSecurityConfiguration(true, 5, false, true, 2, 4, false, false, false, true, false)),
            "Explicit normal settings were parsed incorrectly.");
        risky[(LsaLocal, "RunAsPPL")] = 1;
        Ensure(Collect(risky).Configuration?.LsaProtectionEnabled == true,
            "LSA protection with a UEFI lock was not recognized.");
    }

    private static void VerifyPolicyPrecedence()
    {
        var settings = new Dictionary<(string, string), object>
        {
            [(TerminalPolicy, "fDenyTSConnections")] = 1,
            [(TerminalServer, "fDenyTSConnections")] = 0,
            [(TerminalPolicy, "UserAuthentication")] = 1,
            [(RdpTcp, "UserAuthentication")] = 0,
            [(TerminalPolicy, "SecurityLayer")] = 2,
            [(RdpTcp, "SecurityLayer")] = 0,
            [(TerminalPolicy, "MinEncryptionLevel")] = 4,
            [(RdpTcp, "MinEncryptionLevel")] = 1,
            [(GuestPolicy, "AllowInsecureGuestAuth")] = 0,
            [(GuestLocal, "AllowInsecureGuestAuth")] = 1
        };
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            settings[(FirewallPolicy(profile), "EnableFirewall")] = 1;
            settings[(FirewallLocal(profile), "EnableFirewall")] = 0;
        }

        var posture = Collect(settings);
        Ensure(posture.DomainFirewallEnabled == true && posture.PrivateFirewallEnabled == true &&
               posture.PublicFirewallEnabled == true && posture.Configuration is
               { RdpEnabled: false, RdpNetworkLevelAuthenticationRequired: true, RdpSecurityLayer: 2,
                 RdpMinimumEncryptionLevel: 4, SmbInsecureGuestLogonsAllowed: false, LsaProtectionEnabled: null },
            "Local settings incorrectly overrode policy configuration.");

        // Present but malformed policy must remain unknown rather than silently
        // falling back to the contradictory and otherwise valid local setting.
        foreach (var setting in settings.Keys.Where(pair => pair.Item1.StartsWith(@"SOFTWARE\Policies\"))
                     .ToArray())
        {
            settings[setting] = "malformed";
        }
        var localReads = 0;
        posture = WindowsSecurityConfigurationCollector.CollectPosture((key, name) =>
        {
            if (key.StartsWith(@"SYSTEM\"))
            {
                localReads++;
            }
            return settings.GetValueOrDefault((key, name));
        });
        Ensure(posture == new SecurityPostureInventory(null, null, null, new WindowsSecurityConfiguration()),
            "Malformed policy fell back to a local setting or an assumed default.");
        // SMB1 and LSA are local-only probes. Present policy settings stop lookup.
        Ensure(localReads == 2, "Malformed policies caused local configuration fallback.");
    }

    private static void VerifyInvalidValues()
    {
        var specifications = new (string Key, string Name, object[] Invalid,
            Func<WindowsSecurityConfiguration, object?> Select)[]
        {
            (SystemPolicy, "EnableLUA", ["0", -1, 2, 0L, false], config => config.UacEnabled),
            (SystemPolicy, "ConsentPromptBehaviorAdmin", ["0", -1, 6, 5L], config => config.AdminConsentPromptBehavior),
            (TerminalPolicy, "fDenyTSConnections", ["0", -1, 2, 0L], config => config.RdpEnabled),
            (TerminalPolicy, "UserAuthentication", ["0", -1, 2, 0L], config => config.RdpNetworkLevelAuthenticationRequired),
            (TerminalPolicy, "SecurityLayer", ["0", -1, 3, 2L], config => config.RdpSecurityLayer),
            (TerminalPolicy, "MinEncryptionLevel", ["1", 0, 5, 4L], config => config.RdpMinimumEncryptionLevel),
            (SmbServer, "SMB1", ["0", -1, 2, 0L], config => config.Smb1ServerEnabled),
            (GuestPolicy, "AllowInsecureGuestAuth", ["0", -1, 2, 0L], config => config.SmbInsecureGuestLogonsAllowed),
            (Winlogon, "AutoAdminLogon", [0, 1, "true", " 1", "2"], config => config.AutomaticAdminLogonEnabled),
            (LsaLocal, "RunAsPPL", ["0", -1, 3, 2L], config => config.LsaProtectionEnabled),
            (UpdatePolicy, "NoAutoUpdate", ["0", -1, 2, 0L], config => config.AutomaticUpdatesDisabled)
        };
        foreach (var specification in specifications)
        {
            foreach (var invalid in specification.Invalid)
            {
                var settings = new Dictionary<(string, string), object>
                {
                    [(specification.Key, specification.Name)] = invalid
                };
                Ensure(specification.Select(Collect(settings).Configuration!) is null,
                    $"Unrecognized {specification.Name} was treated as a valid configuration value.");
            }
        }

        foreach (var invalid in new object[] { "0", -1, 2, 0L, false })
        {
            var settings = new Dictionary<(string, string), object>
            {
                [(FirewallPolicy("DomainProfile"), "EnableFirewall")] = invalid,
                [(FirewallLocal("DomainProfile"), "EnableFirewall")] = 0
            };
            Ensure(Collect(settings).DomainFirewallEnabled is null,
                "Malformed firewall policy became a detection through local fallback.");
        }
    }

    private static void VerifyUnavailableValues()
    {
        foreach (var exception in new Exception[]
                 { new UnauthorizedAccessException(), new System.Security.SecurityException(), new IOException() })
        {
            var posture = WindowsSecurityConfigurationCollector.CollectPosture((key, name) =>
            {
                if (key == TerminalPolicy || key == FirewallPolicy("DomainProfile"))
                {
                    throw exception;
                }
                return name switch
                {
                    "EnableLUA" => 0,
                    "fDenyTSConnections" or "UserAuthentication" or "SecurityLayer" => 0,
                    "MinEncryptionLevel" => 1,
                    "EnableFirewall" => 0,
                    _ => null
                };
            });
            Ensure(posture.DomainFirewallEnabled is null && posture.PrivateFirewallEnabled == false &&
                   posture.Configuration is { UacEnabled: false, RdpEnabled: null,
                       RdpNetworkLevelAuthenticationRequired: null, RdpSecurityLayer: null,
                       RdpMinimumEncryptionLevel: null },
                "Unavailable policy used local fallback or prevented independent configuration probes.");
        }
    }

    private static void VerifyLegacyPayload()
    {
        const string json = """
            {"endpointId":"9418c3b7-399e-4dcd-aa7a-09c25e032cb5","collectedUtc":"2026-10-02T00:00:00Z",
             "agentVersion":"1.0","hostname":"test-only","osName":"Windows","osVersion":"10.0",
             "architecture":"X64","cpu":{"model":null,"logicalProcessorCount":2},
             "installedRamBytes":null,"disks":[],
             "securityPosture":{"domainFirewallEnabled":true,"privateFirewallEnabled":null,"publicFirewallEnabled":false}}
            """;
        var report = JsonSerializer.Deserialize<InventoryReport>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Ensure(report?.SecurityPosture is { DomainFirewallEnabled: true, PrivateFirewallEnabled: null,
            PublicFirewallEnabled: false, Configuration: null },
            "A previously published inventory payload stopped working after optional configuration fields were added.");
    }

    private static SecurityPostureInventory Collect(Dictionary<(string, string), object> settings) =>
        WindowsSecurityConfigurationCollector.CollectPosture((key, name) => settings.GetValueOrDefault((key, name)));

    private static string FirewallPolicy(string profile) => @"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + profile;
    private static string FirewallLocal(string profile) =>
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profile;

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }
}
