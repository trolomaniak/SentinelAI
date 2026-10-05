using System.IO;
using System.Windows;
using Microsoft.Win32;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Services;

public sealed class WindowsReportSaveService(Func<Window?> owner) : IReportSaveService
{
    public async Task<ReportSaveResult> SaveAsync(SecurityReportDocument document, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var window = owner();
        if (window is null || !window.Dispatcher.CheckAccess()) return new(ReportSaveOutcome.Failed);
        var dialog = new SaveFileDialog
        {
            Title = "Save security report",
            FileName = document.SuggestedFileName,
            DefaultExt = ".html",
            Filter = "HTML security report (*.html)|*.html",
            AddExtension = true,
            OverwritePrompt = true,
            CheckPathExists = true,
            ValidateNames = true
        };
        var replaceConfirmedDestination = false;
        dialog.FileOk += (_, _) => replaceConfirmedDestination = File.Exists(dialog.FileName);
        if (dialog.ShowDialog(window) != true) return new(ReportSaveOutcome.Cancelled);
        cancellationToken.ThrowIfCancellationRequested();
        // The dialog confirms replacing an existing file. A new destination that
        // appears during the write is preserved by the no-overwrite move.
        return await ReportFileWriter.SaveAsync(dialog.FileName, document, replaceConfirmedDestination, cancellationToken);
    }
}
