using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SentinelAI.Hosting;

// Linked into Core and Setup: Core's local-network certificate is found by its exact SHA-256,
// the same value Agents pin. Only public certificate data is read here.
internal static class LocalNetworkCertificate
{
    public const int DefaultPort = 5443;
    public const string FriendlyName = "SentinelAI Core local network";
    // NT SERVICE\SentinelAICore; Windows derives it from the service name.
    public const string CoreServiceSid = "S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900";

    public static string Sha256(X509Certificate certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData()));

    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    // Returns the LocalMachine\My certificate with this exact SHA-256 and an associated private key,
    // or null. The caller owns the returned certificate.
    [SupportedOSPlatform("windows")]
    public static X509Certificate2? FindInMachineStore(string sha256)
    {
        if (!IsSha256(sha256)) throw new ArgumentException("A SHA-256 certificate fingerprint is required.", nameof(sha256));
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        X509Certificate2? match = null;
        foreach (var certificate in store.Certificates)
        {
            if (match is null && certificate.HasPrivateKey && Sha256(certificate) == sha256) match = certificate;
            else certificate.Dispose();
        }

        return match;
    }
}
