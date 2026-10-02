using SentinelAI.Contracts.Licensing;
using SentinelAI.Licensing;

namespace SentinelAI.LicenseApi;

public sealed class LicenseEntitlement
{
    private readonly byte[] activationCredentialSha256;
    public Guid OrganizationId { get; }
    public Guid InstallationId { get; }
    public string Plan { get; }
    public int EndpointLimit { get; }
    public IReadOnlyList<string> EnabledFeatures { get; }
    internal ReadOnlySpan<byte> CredentialDigest => activationCredentialSha256;

    internal LicenseEntitlement(Guid organizationId, Guid installationId, string plan, int endpointLimit,
        IReadOnlyList<string> enabledFeatures, byte[] digest)
    {
        OrganizationId = organizationId;
        InstallationId = installationId;
        Plan = plan;
        EndpointLimit = endpointLimit;
        EnabledFeatures = Array.AsReadOnly(enabledFeatures.ToArray());
        activationCredentialSha256 = digest.ToArray();
    }
}

public sealed class LicenseApiOptions
{
    public string KeyId { get; }
    public string SigningPrivateKeyPath { get; }
    public IReadOnlyList<LicenseEntitlement> Entitlements { get; }

    private LicenseApiOptions(string keyId, string privateKeyPath, List<LicenseEntitlement> entitlements)
    {
        KeyId = keyId;
        SigningPrivateKeyPath = privateKeyPath;
        Entitlements = entitlements.AsReadOnly();
    }

    public static LicenseApiOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:LicenseApi");
        RequireKnownKeys(section, "KeyId", "SigningPrivateKeyPath", "Entitlements");
        RequireScalar(section, "KeyId", "SigningPrivateKeyPath");
        var keyId = section["KeyId"];
        var privateKeyPath = section["SigningPrivateKeyPath"];
        if (!IsLabel(keyId) || string.IsNullOrWhiteSpace(privateKeyPath) || !Path.IsPathFullyQualified(privateKeyPath))
        {
            throw InvalidConfiguration();
        }

        var entitlements = new List<LicenseEntitlement>();
        var identities = new HashSet<(Guid, Guid)>();
        if (section.GetSection("Entitlements").Value is not null) throw InvalidConfiguration();
        foreach (var grant in section.GetSection("Entitlements").GetChildren())
        {
            RequireKnownKeys(grant, "OrganizationId", "InstallationId", "Plan", "EndpointLimit",
                "EnabledFeatures", "ActivationCredentialSha256");
            RequireScalar(grant, "OrganizationId", "InstallationId", "Plan", "EndpointLimit", "ActivationCredentialSha256");
            if (grant.GetSection("EnabledFeatures").Value is not null) throw InvalidConfiguration();
            if (!Guid.TryParse(grant["OrganizationId"], out var organizationId)
                || !Guid.TryParse(grant["InstallationId"], out var installationId)
                || !int.TryParse(grant["EndpointLimit"], out var endpointLimit)
                || !identities.Add((organizationId, installationId)))
            {
                throw InvalidConfiguration();
            }

            var features = grant.GetSection("EnabledFeatures").GetChildren()
                .Select(feature => feature.Value ?? string.Empty).ToArray();
            var claims = new LeaseClaims(organizationId, installationId, grant["Plan"] ?? string.Empty,
                endpointLimit, Array.AsReadOnly(features), DateTimeOffset.UnixEpoch.AddDays(1),
                DateTimeOffset.UnixEpoch.AddDays(8));
            var digest = grant["ActivationCredentialSha256"];
            if (!LeaseTokenFormat.ValidateClaims(claims) || digest?.Length != 64
                || !digest.All(Uri.IsHexDigit))
            {
                throw InvalidConfiguration();
            }
            entitlements.Add(new LicenseEntitlement(organizationId, installationId, claims.Plan,
                endpointLimit, claims.EnabledFeatures, Convert.FromHexString(digest)));
        }

        // Static grants are sufficient for development; the issue endpoint never accepts entitlement fields.
        if (entitlements.Count is < 1 or > 1000)
        {
            throw InvalidConfiguration();
        }
        return new LicenseApiOptions(keyId!, privateKeyPath!, entitlements);
    }

    internal static bool IsLabel(string? value) => value is { Length: >= 1 and <= 64 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-');

    private static void RequireKnownKeys(IConfigurationSection section, params string[] allowed)
    {
        if (section.GetChildren().Any(child => !allowed.Contains(child.Key, StringComparer.OrdinalIgnoreCase)))
        {
            throw InvalidConfiguration();
        }
    }

    private static void RequireScalar(IConfigurationSection section, params string[] keys)
    {
        if (keys.Any(key => section.GetSection(key).GetChildren().Any())) throw InvalidConfiguration();
    }

    private static InvalidOperationException InvalidConfiguration() =>
        new("License API configuration is missing or invalid. Configure server-side key material and entitlements.");
}
