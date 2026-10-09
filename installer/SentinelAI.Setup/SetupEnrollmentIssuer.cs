using System.IO;
using SentinelAI.Desktop.Services;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

internal sealed class SetupEnrollmentIssuer(WindowsCoreServices core) : ISetupEnrollmentIssuer
{
    public async Task<string> IssueAsync(string username, ReadOnlyMemory<char> password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        // Fresh Setup has just installed the service; console compatibility is
        // not selected here. The shared handler verifies the connected peer
        // against SCM before either credentials or bearer data can be written.
        var service = WindowsNativeCore.ReadService();
        if (service is null || service.State != 4 || service.ProcessId <= 0) throw new InvalidDataException("Local Core service unavailable.");
        using var issuer = new HttpSetupEnrollmentIssuer(core, WindowsCoreServices.CreatePeerTrustedHandler());
        return await issuer.IssueAsync(username, password, token).ConfigureAwait(false);
    }
}
