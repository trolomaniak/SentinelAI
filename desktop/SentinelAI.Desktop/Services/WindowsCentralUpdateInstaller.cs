using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

/// <summary>
/// MVP-7 Install now: runs the installed Updater elevated. It verifies the downloaded Setup with the key pinned at
/// installation, starts it with Upgrade selected and exits; exit 0 means the Setup started, 6 that nothing newer is
/// downloaded and 3 that the download was rejected.
/// </summary>
internal sealed class WindowsCentralUpdateInstaller : ICentralUpdateInstaller
{
    private const int CancelledByUser = 1223;

    public async Task<CentralUpdateInstallOutcome> StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            Process? process;
            using (WindowsInstallationTrust.ValidateInstalledUpdater())
            {
                process = Process.Start(new ProcessStartInfo(WindowsInstallationTrust.InstalledUpdaterPath, "apply-central-update --now")
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = Path.GetDirectoryName(WindowsInstallationTrust.InstalledUpdaterPath)!
                });
            }
            if (process is null) return CentralUpdateInstallOutcome.Unavailable;
            using (process)
            {
                // Waits for the Updater, which ends within its own 30-minute deadline: until then it may still start the
                // Setup, so Desktop neither reports a result nor allows a second Install. The Setup itself is not waited for.
                await process.WaitForExitAsync(cancellationToken);
                return process.ExitCode switch
                {
                    0 => CentralUpdateInstallOutcome.Started,
                    6 => CentralUpdateInstallOutcome.NothingToInstall,
                    3 => CentralUpdateInstallOutcome.Rejected,
                    _ => CentralUpdateInstallOutcome.Unavailable
                };
            }
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == CancelledByUser) { return CentralUpdateInstallOutcome.Cancelled; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or Win32Exception or
                                              InvalidOperationException or OperationCanceledException)
        {
            return CentralUpdateInstallOutcome.Unavailable;
        }
    }
}
