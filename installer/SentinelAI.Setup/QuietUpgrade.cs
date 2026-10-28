using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

/// <summary>
/// MVP-7: the full Setup's "/upgrade /quiet", run by the central computer's update task or an administrator. It is the
/// interactive Upgrade without a window: the same verified payload, ownership checks, pinned trust and transaction.
/// </summary>
internal static class QuietUpgrade
{
    public static async Task<SetupUpgradeExitCode> RunAsync(SafeFileHandle image)
    {
        string? work = null;
        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return SetupUpgradeExitCode.Failed;
            using var installation = EmbeddedInstallation.Open();
            if (installation.Metadata.Product != SetupMetadata.FullProduct) return SetupUpgradeExitCode.InvalidArguments;
            work = await installation.ExtractAsync(image, CancellationToken.None);
            var backend = new WindowsSetupLifecycle(work, installation.Metadata, new Progress<string>(_ => { }));
            return await SetupWorkflow.RunQuietUpgradeAsync(backend, installation.Metadata.Version, CancellationToken.None);
        }
        catch (Exception) { return SetupUpgradeExitCode.Failed; }
        finally { if (work is not null) ProtectedStaging.TryRemove(work); }
    }
}
