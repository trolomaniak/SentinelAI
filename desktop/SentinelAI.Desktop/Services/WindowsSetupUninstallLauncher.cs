using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

/// <summary>Opens the installed SentinelAI Setup with /uninstall, the same flow as Windows Settings → Apps.</summary>
internal sealed class WindowsSetupUninstallLauncher : ISetupUninstallLauncher
{
    private const int CancelledByUser = 1223;

    public UninstallLaunchOutcome Start()
    {
        try
        {
            using var setup = WindowsInstallationTrust.ValidateInstalledSetup();
            // Setup's manifest requires elevation; Windows shows the consent prompt.
            using var process = Process.Start(new ProcessStartInfo(WindowsInstallationTrust.InstalledSetupPath, "/uninstall")
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(WindowsInstallationTrust.InstalledSetupPath)!
            });
            return process is null ? UninstallLaunchOutcome.Unavailable : UninstallLaunchOutcome.Started;
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == CancelledByUser) { return UninstallLaunchOutcome.Cancelled; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or Win32Exception or InvalidOperationException)
        {
            return UninstallLaunchOutcome.Unavailable;
        }
    }
}
