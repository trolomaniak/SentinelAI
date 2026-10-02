using SentinelAI.Licensing;

namespace SentinelAI.Core;

/// <summary>Locally provisioned public trust anchors; never a cloud signing key.</summary>
public sealed class LicenseVerificationOptions
{
    private LicenseVerificationOptions(LeaseTokenVerifier verifier, bool configured, LicenseRenewalOptions renewal)
    {
        Verifier = verifier;
        Configured = configured;
        Renewal = renewal;
    }

    public LeaseTokenVerifier Verifier { get; }
    public bool Configured { get; }
    public LicenseRenewalOptions Renewal { get; }

    public static LicenseVerificationOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:Licensing");
        if (section.GetChildren().Any(child =>
                !string.Equals(child.Key, "TrustedPublicKeys", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(child.Key, "Renewal", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Unknown SentinelAI:Licensing setting.");
        }

        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        var entries = section.GetSection("TrustedPublicKeys").GetChildren().ToArray();
        if (entries.Length > 32)
        {
            throw new InvalidOperationException("At most 32 license public verification keys may be configured.");
        }

        foreach (var entry in entries)
        {
            if (entry.GetChildren().Any() || string.IsNullOrWhiteSpace(entry.Value) ||
                !Path.IsPathFullyQualified(entry.Value))
            {
                throw new InvalidOperationException("License public keys require an absolute public PEM file path.");
            }

            var file = new FileInfo(entry.Value);
            if (!file.Exists || file.Length is <= 0 or > 4096)
            {
                throw new InvalidOperationException("License public key files must exist and be at most 4096 bytes.");
            }

            keys.Add(entry.Key, File.ReadAllText(file.FullName));
        }

        var renewal = LicenseRenewalOptions.Load(configuration);
        if (renewal.Configured && keys.Count == 0)
        {
            throw new InvalidOperationException("License renewal requires configured public verification trust anchors.");
        }

        try
        {
            return new LicenseVerificationOptions(new LeaseTokenVerifier(keys), keys.Count != 0, renewal);
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException("License trust anchors must be named P-256 SPKI public PEM keys.");
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            throw new InvalidOperationException("License trust anchors must be named P-256 SPKI public PEM keys.");
        }
    }
}
