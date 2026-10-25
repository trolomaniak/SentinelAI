using System.Security.Cryptography;
using System.Text;

namespace SentinelAI.Licensing;

/// <summary>Local verification using an immutable snapshot of public SPKI P-256 keys.</summary>
public sealed class LeaseTokenVerifier
{
    private readonly Dictionary<string, byte[]> _publicKeys;

    public LeaseTokenVerifier(IReadOnlyDictionary<string, string> publicKeyPems) => _publicKeys = TrustAnchors.Load(publicKeyPems);

    public LeaseVerificationResult Verify(string? token, Guid expectedOrganizationId, Guid expectedInstallationId, DateTimeOffset now)
    {
        var result = VerifyBinding(token, expectedOrganizationId, expectedInstallationId);
        if (result.Status != LeaseVerificationStatus.Valid || result.Claims is not { } claims) return result;
        if (now < claims.IssuedAt) return new(LeaseVerificationStatus.NotYetValid, KeyId: result.KeyId);
        return new(now >= claims.FullModeUntil ? LeaseVerificationStatus.Expired : LeaseVerificationStatus.Valid, claims, result.KeyId);
    }

    /// <summary>
    /// Authenticates the signature, strict format and identity before a renewal client trusts
    /// signed server time. This does not authorize FULL mode or ignore expiry in Verify.
    /// </summary>
    public AuthenticatedLease? Authenticate(string? token, Guid expectedOrganizationId, Guid expectedInstallationId)
    {
        var result = VerifyBinding(token, expectedOrganizationId, expectedInstallationId);
        return result.Status == LeaseVerificationStatus.Valid && result.Claims is { } claims && result.KeyId is { } keyId
            ? new AuthenticatedLease(claims, keyId) : null;
    }

    private LeaseVerificationResult VerifyBinding(string? token, Guid expectedOrganizationId, Guid expectedInstallationId)
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
        return new(LeaseVerificationStatus.Valid, claims, keyId);
    }

    private static LeaseVerificationResult Invalid() => new(LeaseVerificationStatus.Invalid);
}
