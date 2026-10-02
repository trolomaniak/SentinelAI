using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Licensing;

/// <summary>Local verification using an immutable snapshot of public SPKI P-256 keys.</summary>
public sealed class LeaseTokenVerifier
{
    private readonly Dictionary<string, byte[]> _publicKeys = new(StringComparer.Ordinal);

    public LeaseTokenVerifier(IReadOnlyDictionary<string, string> publicKeyPems)
    {
        ArgumentNullException.ThrowIfNull(publicKeyPems);
        if (publicKeyPems.Count > 32) throw new ArgumentException("At most 32 overlapping verification keys are supported.", nameof(publicKeyPems));
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
                _publicKeys.Add(keyId, key.ExportSubjectPublicKeyInfo());
            }
            catch (Exception exception) when (exception is CryptographicException or FormatException)
            {
                throw new ArgumentException("Verification key must be a valid P-256 public SPKI PEM.", nameof(publicKeyPems));
            }
        }
    }

    public LeaseVerificationResult Verify(string? token, Guid expectedOrganizationId, Guid expectedInstallationId, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(token) || token.Length > LeaseTokenFormat.MaxTokenLength ||
            expectedOrganizationId == Guid.Empty || expectedInstallationId == Guid.Empty) return Invalid();
        var signatureSeparator = token.LastIndexOf('.');
        if (signatureSeparator < 1 || !LeaseTokenFormat.TryReadSigningInput(token[..signatureSeparator], out var keyId, out var payload) ||
            keyId is null || !_publicKeys.TryGetValue(keyId, out var publicKey) ||
            !LeaseTokenFormat.TryDecode(token.AsSpan(signatureSeparator + 1), out var signature) ||
            signature.Length != LeaseTokenFormat.SignatureLength) return Invalid();
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            if (!key.VerifyData(Encoding.ASCII.GetBytes(token[..signatureSeparator]), signature,
                    HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return Invalid();
        }
        catch (CryptographicException) { return Invalid(); }
        if (!LeaseTokenFormat.TryReadClaims(payload, out var claims) || claims is null) return Invalid();
        if (claims.OrganizationId != expectedOrganizationId || claims.InstallationId != expectedInstallationId)
            return new(LeaseVerificationStatus.IdentityMismatch, KeyId: keyId);
        if (now < claims.IssuedAt) return new(LeaseVerificationStatus.NotYetValid, KeyId: keyId);
        return new(now >= claims.FullModeUntil ? LeaseVerificationStatus.Expired : LeaseVerificationStatus.Valid, claims, keyId);
    }

    private static LeaseVerificationResult Invalid() => new(LeaseVerificationStatus.Invalid);
}
