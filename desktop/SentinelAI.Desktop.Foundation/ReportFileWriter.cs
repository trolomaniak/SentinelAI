using System.Security.Cryptography;

namespace SentinelAI.Desktop.Foundation;

/// <summary>Writes only an explicitly confirmed report destination.</summary>
public static class ReportFileWriter
{
    public static async Task<ReportSaveResult> SaveAsync(string destination, SecurityReportDocument document,
        bool allowOverwrite, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? content = null;
        string? temporary = null;
        try
        {
            if (!Path.IsPathFullyQualified(destination) ||
                !string.Equals(Path.GetExtension(destination), ".html", StringComparison.OrdinalIgnoreCase))
                return new(ReportSaveOutcome.Failed);
            var path = Path.GetFullPath(destination);
            var directory = Path.GetDirectoryName(path);
            if (directory is null || !Directory.Exists(directory) || !ValidTarget(path, allowOverwrite))
                return new(ReportSaveOutcome.Failed);

            // Confirmation precedes copying: clearing the document while a native
            // picker is open prevents an obsolete download from being saved.
            content = document.CopyContent();
            cancellationToken.ThrowIfCancellationRequested();
            temporary = Path.Combine(directory, ".sentinelai-report-" + Guid.NewGuid().ToString("N") + ".tmp");
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (!ValidTarget(path, allowOverwrite)) return new(ReportSaveOutcome.Failed);
            File.Move(temporary, path, overwrite: allowOverwrite);
            temporary = null;
            return new(ReportSaveOutcome.Saved, Path.GetFileName(path));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            ArgumentException or NotSupportedException or ObjectDisposedException)
        {
            return new(ReportSaveOutcome.Failed);
        }
        finally
        {
            if (content is not null) CryptographicOperations.ZeroMemory(content);
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
            }
        }
    }

    private static bool ValidTarget(string path, bool allowOverwrite)
    {
        if (Directory.Exists(path)) return false;
        if (!File.Exists(path))
        {
            // Dangling links also cannot be adopted as report destinations.
            return new FileInfo(path).LinkTarget is null;
        }
        return allowOverwrite && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0;
    }
}
