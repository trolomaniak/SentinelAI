using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SentinelAI.Hosting;

// Linked into Setup (and the Core tests): creates Core's own local-network TLS certificate at
// install time and removes it after confirmed data removal. Agents trust it only by its exact
// SHA-256; nothing is added to any trusted root store.
internal static class LocalNetworkCertificateProvisioning
{
    private const string KeyNamePrefix = "SentinelAI-Core-LocalNetwork-";
    private const string SecurityDescriptorProperty = "Security Descr";
    private const CngPropertyOptions DaclSecurityInformation = (CngPropertyOptions)4;
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

    // Protected DACL: SYSTEM and Administrators full control, Core's service account read
    // (enough for Windows to use the key for TLS). No inherited or other entries.
    public static string KeySecurityDescriptorSddl =>
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + LocalNetworkCertificate.CoreServiceSid + ")";

    private const string SystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const uint FullControl = 0x1F01FF; // FILE_ALL_ACCESS
    private const uint ReadAccess = 0x120089; // FILE_GENERIC_READ
    private const uint GenericRead = 0x80000000;

    // Checks a key DACL as Windows reports it. Microsoft Software KSP stores each granted right
    // together with its generic equivalent (0xD01F01FF for full control, 0x80120089 for read), so
    // access is judged by what each identity may do: a protected DACL that allows exactly SYSTEM
    // and Administrators full control and Core's service account read access, and nothing else.
    public static bool HasExpectedKeyAccess(bool protectedDacl, IReadOnlyCollection<(bool Allowed, string Sid, uint Mask)> entries) =>
        protectedDacl && entries.Count == 3 && entries.All(entry => entry.Allowed) &&
        entries.Select(entry => entry.Sid).Distinct(StringComparer.Ordinal).Count() == 3 &&
        entries.All(entry => entry.Sid switch
        {
            SystemSid or AdministratorsSid => (entry.Mask & FullControl) == FullControl,
            LocalNetworkCertificate.CoreServiceSid => (entry.Mask & ReadAccess) == ReadAccess && (entry.Mask & ~(ReadAccess | GenericRead)) == 0,
            _ => false
        });

    public const string FallbackHostName = "sentinelai-core";

    public static (string HostName, string? FullyQualifiedName) ComputerNames()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        return ComputerNames(properties.HostName, properties.DomainName);
    }

    // The names are informational because Agents trust only the pin. Windows accepts computer names with
    // national letters, which become IDN A-labels; a name that has no DNS form never blocks the certificate.
    public static (string HostName, string? FullyQualifiedName) ComputerNames(string hostName, string domainName)
    {
        var host = AsciiDnsName(hostName.Trim().TrimEnd('.'));
        if (host is null) return (FallbackHostName, null);
        var domain = domainName.Trim().Trim('.');
        return (host, domain.Length == 0 ? null : AsciiDnsName(hostName.Trim().TrimEnd('.') + "." + domain));
    }

    private static string? AsciiDnsName(string value)
    {
        try
        {
            var ascii = value.All(char.IsAscii) ? value : new IdnMapping().GetAscii(value);
            return IsDnsName(ascii) ? ascii : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    public static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) Validity(DateTimeOffset now)
    {
        var start = now.ToUniversalTime().AddHours(-1);
        var notBefore = new DateTimeOffset(start.Year, start.Month, start.Day, start.Hour, start.Minute, start.Second, TimeSpan.Zero);
        return (notBefore, notBefore.AddYears(10));
    }

    public static CertificateRequest CreateRequest(ECDsa key, string hostName, string? fullyQualifiedName)
    {
        if (!IsDnsName(hostName) || fullyQualifiedName is not null && !IsDnsName(fullyQualifiedName))
            throw new ArgumentException("Certificate names must be DNS names.");
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(hostName);
        var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthentication)], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(hostName);
        if (fullyQualifiedName is not null && !string.Equals(fullyQualifiedName, hostName, StringComparison.OrdinalIgnoreCase))
            names.AddDnsName(fullyQualifiedName);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    // Creates a non-exportable ECDSA P-256 machine key whose DACL is set in the same creation,
    // a self-signed certificate valid for 10 years and adds it to LocalMachine\My only.
    // Returns the certificate's SHA-256, the value Agents pin. Requires administrator rights.
    [SupportedOSPlatform("windows")]
    public static string Create(DateTimeOffset now)
    {
        var (hostName, fullyQualifiedName) = ComputerNames();
        var descriptor = new RawSecurityDescriptor(KeySecurityDescriptorSddl);
        var binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);
        var parameters = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing
        };
        parameters.Parameters.Add(new CngProperty(SecurityDescriptorProperty, binary,
            CngPropertyOptions.Persist | DaclSecurityInformation));
        var key = CngKey.Create(CngAlgorithm.ECDsaP256, KeyNamePrefix + Guid.NewGuid().ToString("N"), parameters);
        var added = false;
        try
        {
            using var signer = new ECDsaCng(key);
            var (notBefore, notAfter) = Validity(now);
            using var certificate = CreateRequest(signer, hostName, fullyQualifiedName).CreateSelfSigned(notBefore, notAfter);
            certificate.FriendlyName = LocalNetworkCertificate.FriendlyName;
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            store.Add(certificate);
            added = true;
            return LocalNetworkCertificate.Sha256(certificate);
        }
        finally
        {
            if (added) key.Dispose();
            else key.Delete();
        }
    }

    // Removes the certificate with this exact SHA-256 from LocalMachine\My and deletes its key.
    [SupportedOSPlatform("windows")]
    public static int Remove(string sha256)
    {
        if (!LocalNetworkCertificate.IsSha256(sha256)) throw new ArgumentException("A SHA-256 certificate fingerprint is required.", nameof(sha256));
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
        var removed = 0;
        foreach (var certificate in store.Certificates)
        {
            using (certificate)
            {
                if (LocalNetworkCertificate.Sha256(certificate) != sha256) continue;
                if (certificate.HasPrivateKey)
                {
                    using var key = certificate.GetECDsaPrivateKey();
                    if (key is not ECDsaCng machineKey) throw new InvalidOperationException("The certificate key is not the expected CNG key.");
                    machineKey.Key.Delete();
                }

                store.Remove(certificate);
                removed++;
            }
        }

        return removed;
    }

    // Windows permits underscores in computer names; the names are informational because Agents trust the pin.
    private static bool IsDnsName(string value) =>
        value.Length is > 0 and <= 253 && value.Split('.').All(label =>
            label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-' &&
            label.All(character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_'));
}
