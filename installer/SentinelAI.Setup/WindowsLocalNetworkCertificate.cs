using SentinelAI.Hosting;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

/// <summary>Creates Core's local-network certificate in LocalMachine\My with its key ACL (elevated Setup only).</summary>
internal sealed class WindowsLocalNetworkCertificate : ISetupLocalNetworkCertificate
{
    public string Create() => LocalNetworkCertificateProvisioning.Create(DateTimeOffset.UtcNow);
    public void Remove(string sha256) => LocalNetworkCertificateProvisioning.Remove(sha256);
}
