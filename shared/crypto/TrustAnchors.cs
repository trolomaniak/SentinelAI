using System.Security.Cryptography;

namespace SentinelAI.Licensing;

/// <summary>An immutable snapshot of named P-256 public SPKI keys; private keys are rejected.</summary>
internal static class TrustAnchors
{
    public static Dictionary<string, byte[]> Load(IReadOnlyDictionary<string, string> publicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(publicKeyPems);
        if (publicKeyPems.Count > 32) throw new ArgumentException("At most 32 overlapping verification keys are supported.", nameof(publicKeyPems));
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (keyId, pem) in publicKeyPems)
        {
            if (!LeaseTokenFormat.IsIdentifier(keyId) || string.IsNullOrWhiteSpace(pem) || pem.Length > 4_096 ||
                !PemEncoding.TryFind(pem, out var fields) || pem[fields.Label] != "PUBLIC KEY")
                throw new ArgumentException("Each verification key must be a bounded identifier and a public SPKI PEM.", nameof(publicKeyPems));
            var (start, length) = fields.Location.GetOffsetAndLength(pem.Length);
            if (!string.IsNullOrWhiteSpace(pem[..start]) || !string.IsNullOrWhiteSpace(pem[(start + length)..]))
                throw new ArgumentException("Only one public SPKI PEM block is accepted per verification key.", nameof(publicKeyPems));
            try
            {
                var encoded = Convert.FromBase64String(pem[fields.Base64Data]);
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(encoded, out var consumed);
                var parameters = key.ExportParameters(false);
                if (consumed != encoded.Length || key.KeySize != 256 ||
                    parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                    parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32 || parameters.D is not null)
                    throw new CryptographicException("A P-256 verification key is required.");
                keys.Add(keyId, key.ExportSubjectPublicKeyInfo());
            }
            catch (Exception exception) when (exception is CryptographicException or FormatException)
            {
                throw new ArgumentException("Verification key must be a valid P-256 public SPKI PEM.", nameof(publicKeyPems));
            }
        }
        return keys;
    }

    public static bool VerifySignature(byte[] publicKey, string signingInput, byte[] signature)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(System.Text.Encoding.ASCII.GetBytes(signingInput), signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
    }
}
