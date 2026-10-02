using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Rules;

public sealed class DomainFirewallDisabledRule() : EndpointRule(
    "SA-FW-001", "Domain firewall profile configured disabled", "high",
    "The reported Domain firewall profile setting is explicitly disabled.",
    "Review domain policy and enable the Domain firewall profile with appropriate application rules.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.domainFirewallEnabled", posture.DomainFirewallEnabled, false);
}

public sealed class PrivateFirewallDisabledRule() : EndpointRule(
    "SA-FW-002", "Private firewall profile configured disabled", "high",
    "The reported Private firewall profile setting is explicitly disabled.",
    "Enable the Private firewall profile and allow only required application traffic.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.privateFirewallEnabled", posture.PrivateFirewallEnabled, false);
}

public sealed class PublicFirewallDisabledRule() : EndpointRule(
    "SA-FW-003", "Public firewall profile configured disabled", "high",
    "The reported Public firewall profile setting is explicitly disabled.",
    "Enable the Public firewall profile and review inbound traffic exceptions.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.publicFirewallEnabled", posture.PublicFirewallEnabled, false);
}

public sealed class UacDisabledRule() : EndpointRule(
    "SA-UAC-001", "User Account Control configured disabled", "high",
    "The reported User Account Control setting is explicitly disabled.",
    "Enable User Account Control through approved Windows policy and review compatibility requirements.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.uacEnabled", posture.Configuration?.UacEnabled, false);
}

public sealed class UacAdministratorPromptDisabledRule() : EndpointRule(
    "SA-UAC-002", "Administrator elevation configured without a prompt", "high",
    "User Account Control is configured enabled, but administrator elevation is configured to occur without prompting.",
    "Configure administrator elevation to require consent or credentials under the organization's policy.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        posture.Configuration is { UacEnabled: true, AdminConsentPromptBehavior: 0 }
            ? [RuleEvidence.Boolean("securityPosture.configuration.uacEnabled", true),
               RuleEvidence.Integer("securityPosture.configuration.adminConsentPromptBehavior", 0)]
            : null;
}

public sealed class RdpNlaDisabledRule() : EndpointRule(
    "SA-RDP-001", "Remote Desktop configured without Network Level Authentication", "high",
    "Remote Desktop is configured enabled and its Network Level Authentication requirement is explicitly disabled.",
    "Require Network Level Authentication, or disable Remote Desktop if remote access is unnecessary.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        posture.Configuration is { RdpEnabled: true, RdpNetworkLevelAuthenticationRequired: false }
            ? [RuleEvidence.Boolean("securityPosture.configuration.rdpEnabled", true),
               RuleEvidence.Boolean("securityPosture.configuration.rdpNetworkLevelAuthenticationRequired", false)]
            : null;
}

public sealed class RdpNativeSecurityRule() : EndpointRule(
    "SA-RDP-002", "Remote Desktop configured to use native RDP security", "high",
    "Remote Desktop is configured enabled with the native RDP security layer rather than TLS server authentication.",
    "Review client compatibility and configure the Remote Desktop security layer to require TLS.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        posture.Configuration is { RdpEnabled: true, RdpSecurityLayer: 0 }
            ? [RuleEvidence.Boolean("securityPosture.configuration.rdpEnabled", true),
               RuleEvidence.Integer("securityPosture.configuration.rdpSecurityLayer", 0)]
            : null;
}

public sealed class RdpLowEncryptionRule() : EndpointRule(
    "SA-RDP-003", "Remote Desktop configured with low encryption", "medium",
    "Remote Desktop is configured enabled with native RDP security permitted and its minimum encryption level set to Low (1).",
    "Configure High or FIPS compliant encryption as appropriate and require TLS for Remote Desktop.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        posture.Configuration is { RdpEnabled: true, RdpSecurityLayer: 0 or 1, RdpMinimumEncryptionLevel: 1 }
            ? [RuleEvidence.Boolean("securityPosture.configuration.rdpEnabled", true),
               RuleEvidence.Integer("securityPosture.configuration.rdpSecurityLayer", posture.Configuration.RdpSecurityLayer.Value),
               RuleEvidence.Integer("securityPosture.configuration.rdpMinimumEncryptionLevel", 1)]
            : null;
}

public sealed class Smb1ServerEnabledRule() : EndpointRule(
    "SA-SMB-001", "SMB1 server configured enabled", "high",
    "The SMB1 server setting is explicitly enabled; the legacy protocol lacks modern security protections.",
    "Review legacy dependencies and disable the SMB1 server setting through approved Windows policy.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.smb1ServerEnabled", posture.Configuration?.Smb1ServerEnabled, true);
}

public sealed class SmbInsecureGuestLogonsRule() : EndpointRule(
    "SA-SMB-002", "Insecure SMB guest logons configured allowed", "high",
    "The SMB client policy explicitly allows insecure guest logons without authenticated user identity.",
    "Disable insecure SMB guest logons and configure authenticated access to required file shares.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.smbInsecureGuestLogonsAllowed",
            posture.Configuration?.SmbInsecureGuestLogonsAllowed, true);
}

public sealed class AutomaticWindowsLogonRule() : EndpointRule(
    "SA-LOGON-001", "Automatic Windows logon configured enabled", "high",
    "Automatic Windows logon is explicitly enabled, creating potential unattended access and stored credential risk.",
    "Disable automatic Windows logon unless an approved access-controlled deployment requires it.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.automaticAdminLogonEnabled",
            posture.Configuration?.AutomaticAdminLogonEnabled, true);
}

public sealed class LsaProtectionDisabledRule() : EndpointRule(
    "SA-LSA-001", "LSA protection configured disabled", "medium",
    "The Local Security Authority protection setting is explicitly disabled; this does not establish its effective runtime state.",
    "Review operating system support and authentication plug-in compatibility, then enable LSA protection through approved policy.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.lsaProtectionEnabled", posture.Configuration?.LsaProtectionEnabled, false);
}

public sealed class AutomaticUpdatesDisabledRule() : EndpointRule(
    "SA-UPDATE-001", "Automatic Windows updates configured disabled", "high",
    "The automatic Windows update policy is explicitly disabled; this does not establish installed or missing update status.",
    "Enable automatic updates or verify that an approved managed update process provides timely security updates.")
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture) =>
        BooleanMatch("securityPosture.configuration.automaticUpdatesDisabled", posture.Configuration?.AutomaticUpdatesDisabled, true);
}
