using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Windows;
using Microsoft.Win32;
using SentinelAI.Contracts.Backups;
using SentinelAI.Desktop.Foundation;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Services;

public sealed class WindowsBackupFileService(Func<Window?> owner) : IBackupFileService
{
    public Task<BackupFileOutcome> SaveRecoveryKeyAsync(ReadOnlyMemory<byte> encryptedKey, CancellationToken cancellationToken) =>
        SaveAsync(".sakey", "SentinelAI-recovery-" + Guid.NewGuid().ToString("N"), T("Save encrypted recovery key"),
            T("Encrypted recovery key (*.sakey)|*.sakey"), false, async (stream, token) => { await stream.WriteAsync(encryptedKey, token); return true; }, cancellationToken);

    public Task<BackupFileOutcome> SaveArchiveAsync(BackupArchiveSummary archive,
        Func<Stream, CancellationToken, Task<BackupDownloadResult>> download, CancellationToken cancellationToken) =>
        SaveAsync(".sab", "SentinelAI-backup-" + archive.ArchiveId.ToString("N"), T("Export encrypted backup"),
            T("Encrypted backup (*.sab)|*.sab"), true, async (stream, token) => (await download(stream, token)).Outcome == BackupRequestOutcome.Success, cancellationToken);

    private async Task<BackupFileOutcome> SaveAsync(string extension, string filename, string title, string filter, bool allowReplacement,
        Func<Stream, CancellationToken, Task<bool>> write, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var window = owner();
        if (window is null || !window.Dispatcher.CheckAccess()) return BackupFileOutcome.Failed;
        var dialog = new SaveFileDialog { Title = title, FileName = filename + extension, DefaultExt = extension, Filter = filter,
            AddExtension = true, CheckPathExists = true, OverwritePrompt = true, ValidateNames = true };
        var overwrite = false;
        dialog.FileOk += (_, e) =>
        {
            overwrite = allowReplacement && File.Exists(dialog.FileName);
            if (!allowReplacement && File.Exists(dialog.FileName))
            {
                e.Cancel = true;
                MessageBox.Show(window, T("An existing recovery key file cannot be replaced. Choose a new filename."), "SentinelAI", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        };
        if (dialog.ShowDialog(window) != true) return BackupFileOutcome.Cancelled;
        string? temporary = null;
        try
        {
            token.ThrowIfCancellationRequested();
            var path = Path.GetFullPath(dialog.FileName);
            if (!string.Equals(Path.GetExtension(path), extension, StringComparison.OrdinalIgnoreCase) || !ValidTarget(path, overwrite)) return BackupFileOutcome.Failed;
            var directory = Path.GetDirectoryName(path)!;
            temporary = Path.Combine(directory, ".sentinelai-backup-" + Guid.NewGuid().ToString("N") + ".tmp");
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                if (!await write(stream, token)) return BackupFileOutcome.Failed;
                await stream.FlushAsync(token);
            }
            token.ThrowIfCancellationRequested();
            if (!ValidTarget(path, overwrite)) return BackupFileOutcome.Failed;
            File.Move(temporary, path, overwrite);
            temporary = null;
            return BackupFileOutcome.Saved;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return BackupFileOutcome.Failed; }
        finally { if (temporary is not null) try { File.Delete(temporary); } catch (Exception error) when (error is IOException or UnauthorizedAccessException) { } }
    }
    private static bool ValidTarget(string path, bool overwrite) => !Directory.Exists(path) && new FileInfo(path).LinkTarget is null &&
        (!File.Exists(path) || overwrite && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0);
}

public sealed class WindowsBackupRecoveryLauncher : IBackupRecoveryLauncher
{
    public bool Open()
    {
        try
        {
            var executable = Path.Combine(AppContext.BaseDirectory, "SentinelAI.Desktop.exe");
            using var trusted = WindowsInstallationTrust.ValidateInstalledDesktop();
            if (!string.Equals(Path.GetFullPath(executable), Path.GetFullPath(WindowsInstallationTrust.InstalledDesktopPath), StringComparison.OrdinalIgnoreCase)) return false;
            using var process = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = true, Verb = "runas", Arguments = "--recover-core", WorkingDirectory = AppContext.BaseDirectory
            });
            return process is not null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException) { return false; }
    }
    internal static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
