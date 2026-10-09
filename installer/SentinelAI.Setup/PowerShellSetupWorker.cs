using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

internal sealed class PowerShellSetupWorker(string workDirectory, SetupMetadata metadata, IProgress<string> progress) : ISetupWorker
{
    public Task PrepareCoreAsync(CancellationToken token) => RunAsync("prepare-core", ReadOnlyMemory<char>.Empty, token);
    public Task StartCoreAsync(CancellationToken token) => RunAsync("start-core", ReadOnlyMemory<char>.Empty, token);
    public Task CompleteAsync(ReadOnlyMemory<char> enrollmentToken, CancellationToken token) => RunAsync("complete", enrollmentToken, token);

    private async Task RunAsync(string action, ReadOnlyMemory<char> enrollmentToken, CancellationToken token)
    {
        ProtectedStaging.Validate(workDirectory);
        var scriptPath = Path.Combine(workDirectory, "setup", "SetupWorker.ps1");
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell) || !File.Exists(scriptPath) || (File.GetAttributes(scriptPath) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Setup worker unavailable.");
        // This fixed loader contains only an administrator-protected staging path.
        // Private stdin carries only a one-use enrollment token, never administrator credentials.
        var command = "$ProgressPreference = 'SilentlyContinue'; [Console]::InputEncoding = New-Object Text.UTF8Encoding($false); [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); & ([ScriptBlock]::Create([IO.File]::ReadAllText('" + scriptPath.Replace("'", "''", StringComparison.Ordinal) + "')))";
        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = workDirectory,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-InputFormat", "Text", "-OutputFormat", "Text", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) }) start.ArgumentList.Add(argument);
        ChildProcessEnvironment.ConfigurePowerShell(start);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(10));
        using var process = Process.Start(start) ?? throw new IOException("Setup worker unavailable.");
        var input = new byte[8192];
        try
        {
            var output = ReadProgressAsync(process.StandardOutput.BaseStream, deadline);
            var errors = ReadErrorsAsync(process.StandardError.BaseStream, deadline);
            var length = SetupWorkflow.WriteWorkerRequest(input, action, workDirectory, metadata, enrollmentToken.Span);
            await process.StandardInput.BaseStream.WriteAsync(input.AsMemory(0, length), deadline.Token).ConfigureAwait(false);
            await process.StandardInput.BaseStream.FlushAsync(deadline.Token).ConfigureAwait(false);
            process.StandardInput.Close(); CryptographicOperations.ZeroMemory(input);
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            if (!await output.ConfigureAwait(false) || await errors.ConfigureAwait(false) || process.ExitCode != 0) throw new InvalidDataException("Installation step failed.");
        }
        catch { token.ThrowIfCancellationRequested(); throw new InvalidDataException("Installation step unavailable."); }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            deadline.Cancel();
            try { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } } catch { }
        }
    }

    private async Task<bool> ReadProgressAsync(Stream stream, CancellationTokenSource deadline)
    {
        var buffer = new byte[1]; var line = new byte[128]; var used = 0; var total = 0; var done = false; var failed = false;
        try
        {
            while (await stream.ReadAsync(buffer, deadline.Token).ConfigureAwait(false) != 0)
            {
                if (++total > 8192 || done || failed) throw new InvalidDataException();
                if (buffer[0] == '\r') continue;
                if (buffer[0] != '\n') { if (used == line.Length || buffer[0] is < 32 or > 126) throw new InvalidDataException(); line[used++] = buffer[0]; continue; }
                var marker = Encoding.ASCII.GetString(line, 0, used); used = 0;
                var text = SetupWorkflow.ProgressFor(marker);
                if (text is not null) progress.Report(text);
                else if (marker == "DONE") done = true;
                else if (marker is "FAILED|validate" or "FAILED|core" or "FAILED|services" or "FAILED|agent" or "FAILED|desktop" or "FAILED|shortcut") failed = true;
                else throw new InvalidDataException();
            }
            return used == 0 && done && !failed;
        }
        catch { deadline.Cancel(); throw; }
        finally { CryptographicOperations.ZeroMemory(buffer); CryptographicOperations.ZeroMemory(line); }
    }

    private static async Task<bool> ReadErrorsAsync(Stream stream, CancellationTokenSource deadline)
    {
        var buffer = new byte[1024]; var total = 0;
        try
        {
            while (true)
            {
                var count = await stream.ReadAsync(buffer, deadline.Token).ConfigureAwait(false);
                if (count == 0) return total != 0;
                total += count; CryptographicOperations.ZeroMemory(buffer);
                if (total > 4096) throw new InvalidDataException();
            }
        }
        catch { deadline.Cancel(); throw; }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
}
