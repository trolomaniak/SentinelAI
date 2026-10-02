using System.Security.Cryptography;

namespace SentinelAI.Updates;

public static class UpdateManifestVerifier
{
    public static VerifiedUpdateManifest Verify(ReadOnlySpan<byte> document, UpdateVerificationPolicy policy)
    {
        var verified = Authenticate(document, policy);
        if (!UpdateManifestFormat.TryVersion(verified.Manifest.Version, out var version) ||
            version <= policy.ParsedInstalledVersion) throw new UpdateValidationException();
        return verified;
    }

    // Installer receipts/journals authenticate installed metadata without authorizing a replay as an update.
    internal static VerifiedUpdateManifest Authenticate(ReadOnlySpan<byte> document, UpdateVerificationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (!UpdateManifestFormat.TryRead(document, out var manifest, out var keyId, out var signature) ||
            manifest is null || keyId is null || !policy.TryGetPublicKey(keyId, out var publicKey))
            throw new UpdateValidationException();
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            if (!key.VerifyData(UpdateManifestFormat.CreateSigningData(manifest, keyId), signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new UpdateValidationException();
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException) { throw new UpdateValidationException(); }
        if (manifest.Environment != policy.RequiredEnvironment || manifest.Channel != policy.Channel ||
            manifest.ArtifactId != policy.ArtifactId) throw new UpdateValidationException();
        return new VerifiedUpdateManifest(manifest, keyId);
    }
}
