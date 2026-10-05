using System.Text;
using SentinelAI.Desktop.Foundation;

internal static class ReportFileWriterTests
{
    private static int assertions;

    public static async Task<int> RunAsync()
    {
        assertions = 0;
        var directory = Path.Combine(Path.GetTempPath(), "sentinelai-report-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var bytes = Encoding.UTF8.GetBytes("<!doctype html><html><body>synthetic café &amp; report</body></html>");
            using var document = new SecurityReportDocument(new(new(2026, 9, 1), new(2026, 9, 30)), bytes);
            Array.Clear(bytes);
            var expected = document.CopyContent();
            var copy = document.CopyContent();
            Array.Clear(copy);
            Check(document.CopyContent().SequenceEqual(expected), "A caller copy mutated the owned report.");
            var destination = Path.Combine(directory, document.SuggestedFileName);
            var saved = await ReportFileWriter.SaveAsync(destination, document, false, CancellationToken.None);
            Check(saved.Outcome == ReportSaveOutcome.Saved && saved.FileName == Path.GetFileName(destination),
                "An explicit fresh destination did not return only its filename.");
            Check((await File.ReadAllBytesAsync(destination)).SequenceEqual(expected), "The export changed Core HTML bytes.");
            Check(!Directory.EnumerateFiles(directory, ".sentinelai-report-*.tmp").Any(), "A completed export retained temporary files.");

            await File.WriteAllTextAsync(destination, "existing operator file");
            var refused = await ReportFileWriter.SaveAsync(destination, document, false, CancellationToken.None);
            Check(refused.Outcome == ReportSaveOutcome.Failed && await File.ReadAllTextAsync(destination) == "existing operator file",
                "An unconfirmed overwrite changed an existing operator file.");
            saved = await ReportFileWriter.SaveAsync(destination, document, true, CancellationToken.None);
            Check(saved.Outcome == ReportSaveOutcome.Saved && (await File.ReadAllBytesAsync(destination)).SequenceEqual(expected),
                "A confirmed overwrite did not atomically replace the selected file.");

            var directoryTarget = Path.Combine(directory, "folder.html");
            Directory.CreateDirectory(directoryTarget);
            foreach (var invalid in new[] { "relative.html", Path.Combine(directory, "report.txt"),
                         Path.Combine(directory, "absent", "report.html"), directoryTarget })
            {
                var result = await ReportFileWriter.SaveAsync(invalid, document, true, CancellationToken.None);
                Check(result.Outcome == ReportSaveOutcome.Failed && result.FileName is null, "An invalid destination was adopted.");
            }

            // Windows may require a privilege to create links. Existing links are
            // still refused by the production writer on every platform.
            foreach (var dangling in new[] { false, true })
            {
                var target = Path.Combine(directory, dangling ? "missing.html" : "original.html");
                if (!dangling) await File.WriteAllTextAsync(target, "original link target");
                var link = Path.Combine(directory, dangling ? "dangling.html" : "linked.html");
                try { File.CreateSymbolicLink(link, target); }
                catch (Exception exception) when (OperatingSystem.IsWindows() &&
                    exception is UnauthorizedAccessException or IOException) { continue; }
                var result = await ReportFileWriter.SaveAsync(link, document, true, CancellationToken.None);
                Check(result.Outcome == ReportSaveOutcome.Failed && new FileInfo(link).LinkTarget is not null,
                    "A report export adopted or replaced a symbolic-link destination.");
                Check(dangling ? !File.Exists(target) : await File.ReadAllTextAsync(target) == "original link target",
                    "An export followed a symbolic link and changed its target.");
            }

            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            var cancelledPath = Path.Combine(directory, "cancelled.html");
            try
            {
                await ReportFileWriter.SaveAsync(cancelledPath, document, false, cancelled.Token);
                throw new InvalidOperationException("A canceled export completed.");
            }
            catch (OperationCanceledException) when (cancelled.IsCancellationRequested) { assertions++; }
            Check(!File.Exists(cancelledPath), "A canceled export created a file.");

            document.Dispose();
            Check(document.ByteCount == 0, "A cleared report retained readable document bytes.");
            try { document.CopyContent(); throw new InvalidOperationException("A disposed report was readable."); }
            catch (ObjectDisposedException) { assertions++; }
            var obsolete = Path.Combine(directory, "obsolete.html");
            var failed = await ReportFileWriter.SaveAsync(obsolete, document, false, CancellationToken.None);
            Check(failed.Outcome == ReportSaveOutcome.Failed && !File.Exists(obsolete),
                "A report cleared while choosing a destination was exported.");
            Check(!Directory.EnumerateFiles(directory, ".sentinelai-report-*.tmp").Any(), "A failed export retained temporary bytes.");
            Array.Clear(expected);
        }
        finally { Directory.Delete(directory, recursive: true); }
        Console.WriteLine($"Desktop report file saving: {assertions} assertions passed.");
        return assertions;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        assertions++;
    }
}
