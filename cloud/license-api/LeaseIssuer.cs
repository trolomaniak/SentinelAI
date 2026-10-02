using System.Security.Cryptography;
using System.Text;
using SentinelAI.Contracts.Licensing;
using SentinelAI.Licensing;

namespace SentinelAI.LicenseApi;

// This class belongs only to the cloud issuer. Core and the verifier library never load private keys.
public sealed class LeaseIssuer : IDisposable
{
    private readonly ECDsa signingKey;
    private readonly object signingLock = new();
    private readonly string keyId;

    public LeaseIssuer(LicenseApiOptions options)
    {
        keyId = options.KeyId;
        signingKey = ECDsa.Create();
        try
        {
            var info = new FileInfo(options.SigningPrivateKeyPath);
            if (!info.Exists || info.Length is < 1 or > 16384)
            {
                throw new CryptographicException();
            }
            var pem = File.ReadAllText(options.SigningPrivateKeyPath);
            if (!pem.StartsWith("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal))
            {
                throw new CryptographicException();
            }
            signingKey.ImportFromPem(pem);
            var parameters = signingKey.ExportParameters(true);
            try
            {
                if (parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7" || parameters.D?.Length != 32)
                {
                    throw new CryptographicException();
                }
            }
            finally
            {
                if (parameters.D is not null)
                {
                    CryptographicOperations.ZeroMemory(parameters.D);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or ArgumentException or CryptographicException)
        {
            signingKey.Dispose();
            throw new InvalidOperationException("License API requires a readable server-side PKCS#8 P-256 private key.");
        }
    }

    public SignedLease Issue(LicenseEntitlement grant, DateTimeOffset issuedAt)
    {
        var claims = new LeaseClaims(grant.OrganizationId, grant.InstallationId, grant.Plan,
            grant.EndpointLimit, grant.EnabledFeatures, issuedAt.ToUniversalTime(), issuedAt.ToUniversalTime().AddDays(7));
        var signingInput = LeaseTokenFormat.CreateSigningInput(claims, keyId);
        byte[] signature;
        lock (signingLock)
        {
            signature = signingKey.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        return new SignedLease(LeaseTokenFormat.Assemble(signingInput, signature));
    }

    public void Dispose()
    {
        lock (signingLock)
        {
            signingKey.Dispose();
        }
    }
}
