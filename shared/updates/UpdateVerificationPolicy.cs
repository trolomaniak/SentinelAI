using System.Security.Cryptography;

namespace SentinelAI.Updates;

/// <summary>Explicit operator trust for exactly one environment, release channel and artifact.</summary>
public sealed class UpdateVerificationPolicy
{
    private readonly Dictionary<string, byte[]> _publicKeys = new(StringComparer.Ordinal);
    internal Version ParsedInstalledVersion { get; }

    public UpdateVerificationPolicy(string requiredEnvironment, string channel, string artifactId, string installedVersion,
        IReadOnlyDictionary<string, string> trustedPublicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKeyPems);
        if (!UpdateManifestFormat.IsEnvironment(requiredEnvironment) || !UpdateManifestFormat.IsChannel(channel) ||
            !UpdateManifestFormat.IsIdentifier(artifactId) || !UpdateManifestFormat.TryVersion(installedVersion, out var parsedVersion) ||
            trustedPublicKeyPems.Count is < 1 or > 32)
            throw new ArgumentException("An explicit bounded update trust policy is required.");
        foreach (var (keyId, pem) in trustedPublicKeyPems)
        {
            if (!UpdateManifestFormat.IsIdentifier(keyId) || string.IsNullOrWhiteSpace(pem) || pem.Length > 4_096 ||
                !PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "PUBLIC KEY")
                throw new ArgumentException("Update trust accepts only bounded public SPKI PEM keys.", nameof(trustedPublicKeyPems));
            var (start, length) = fields.Location.GetOffsetAndLength(pem.Length);
            if (!string.IsNullOrWhiteSpace(pem[..start]) || !string.IsNullOrWhiteSpace(pem[(start + length)..]))
                throw new ArgumentException("Each update key must contain exactly one public SPKI PEM block.", nameof(trustedPublicKeyPems));
            try
            {
                var encoded = Convert.FromBase64String(pem[fields.Base64Data]);
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(encoded, out var consumed);
                var parameters = key.ExportParameters(false);
                if (consumed != encoded.Length || key.KeySize != 256 ||
                    parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                    parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32 || parameters.D is not null)
                    throw new CryptographicException();
                _publicKeys.Add(keyId, key.ExportSubjectPublicKeyInfo());
            }
            catch (Exception exception) when (exception is CryptographicException or FormatException)
            {
                throw new ArgumentException("Update trust requires a valid public P-256 SPKI PEM.", nameof(trustedPublicKeyPems));
            }
        }
        RequiredEnvironment = requiredEnvironment;
        Channel = channel;
        ArtifactId = artifactId;
        InstalledVersion = installedVersion;
        ParsedInstalledVersion = parsedVersion;
    }

    public string RequiredEnvironment { get; }
    public string Channel { get; }
    public string ArtifactId { get; }
    public string InstalledVersion { get; }

    internal bool TryGetPublicKey(string keyId, out byte[] key) => _publicKeys.TryGetValue(keyId, out key!);
}
