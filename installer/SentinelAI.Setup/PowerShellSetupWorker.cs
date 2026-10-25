using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using SentinelAI.Enrollment;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

internal sealed class PowerShellSetupWorker(string workDirectory, SetupMetadata metadata, IProgress<string> progress) : ISetupWorker
{
    public async Task PrepareCoreAsync(string localNetworkCertificateSha256, CancellationToken token) =>
        _ = await RunAsync("prepare-core", ReadOnlyMemory<char>.Empty, true, token, localNetworkCertificateSha256).ConfigureAwait(false);
    public async Task StartCoreAsync(CancellationToken token) => _ = await RunAsync("start-core", ReadOnlyMemory<char>.Empty, true, token).ConfigureAwait(false);
    public async Task CompleteAsync(ReadOnlyMemory<char> enrollmentToken, CancellationToken token) => _ = await RunAsync("complete", enrollmentToken, true, token).ConfigureAwait(false);

    public async Task<SetupInstallation> InspectAsync(CancellationToken token) =>
        await RunAsync("inspect", ReadOnlyMemory<char>.Empty, true, token).ConfigureAwait(false) ?? throw new InvalidDataException("Installation state unavailable.");

    internal async Task CommandAsync(string action, bool preserveData, CancellationToken token) =>
        _ = await RunAsync(action, ReadOnlyMemory<char>.Empty, preserveData, token).ConfigureAwait(false);

    private async Task<SetupInstallation?> RunAsync(string action, ReadOnlyMemory<char> enrollmentToken, bool preserveData, CancellationToken token,
        string localNetworkCertificateSha256 = "")
    {
        var state = await RunScriptAsync(["SetupWorker.ps1"], buffer => SetupWorkflow.WriteWorkerRequest(buffer, action, workDirectory, metadata,
            enrollmentToken.Span, preserveData, localNetworkCertificateSha256), action == "inspect", reportPhase: false, token).ConfigureAwait(false);
        return state is null ? null : SetupWorkflow.ParseInstallationState(state);
    }

    /// <summary>Agent Setup (MVP-2): the shared worker functions, then the Agent worker. Only "agent-install" carries a code.</summary>
    internal Task<string?> RunAgentAsync(string action, EnrollmentCode? code, CancellationToken token) =>
        RunScriptAsync(["SetupWorker.ps1", "AgentSetupWorker.ps1"],
            buffer => AgentSetupWorkflow.WriteWorkerRequest(buffer, action, workDirectory, metadata, code), action == "agent-inspect", reportPhase: true, token);

    /// <param name="reportPhase">Agent Setup distinguishes the failed phase (<see cref="SetupStepException"/>); every full
    /// Setup step keeps failing with <see cref="InvalidDataException"/>, which its health polling treats as unhealthy.</param>
    private async Task<string?> RunScriptAsync(string[] scripts, Func<byte[], int> writeRequest, bool expectState, bool reportPhase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ProtectedStaging.Validate(workDirectory);
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell)) throw new InvalidDataException("Setup worker unavailable.");
        // This fixed loader contains only administrator-protected staging paths. Every script but the last only defines functions.
        var command = new StringBuilder("$ProgressPreference = 'SilentlyContinue'; [Console]::InputEncoding = New-Object Text.UTF8Encoding($false); [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)");
        for (var index = 0; index < scripts.Length; index++)
        {
            var scriptPath = Path.Combine(workDirectory, "setup", scripts[index]);
            if (!File.Exists(scriptPath) || (File.GetAttributes(scriptPath) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Setup worker unavailable.");
            command.Append(index == scripts.Length - 1 ? "; & " : "; . ").Append("([ScriptBlock]::Create([IO.File]::ReadAllText('")
                .Append(scriptPath.Replace("'", "''", StringComparison.Ordinal)).Append("')))");
        }
        // Private stdin carries only a one-use enrollment token, never administrator credentials.
        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = workDirectory,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-InputFormat", "Text", "-OutputFormat", "Text", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command.ToString())) }) start.ArgumentList.Add(argument);
        ChildProcessEnvironment.ConfigurePowerShell(start);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(10));
        using var process = Process.Start(start) ?? throw new IOException("Setup worker unavailable.");
        var input = new byte[8192];
        try
        {
            var output = ReadProgressAsync(process.StandardOutput.BaseStream, deadline, expectState);
            var errors = ReadErrorsAsync(process.StandardError.BaseStream, deadline);
            ObserveFailure(output); ObserveFailure(errors);
            var length = writeRequest(input);
            await process.StandardInput.BaseStream.WriteAsync(input.AsMemory(0, length), deadline.Token).ConfigureAwait(false);
            await process.StandardInput.BaseStream.FlushAsync(deadline.Token).ConfigureAwait(false);
            process.StandardInput.Close(); CryptographicOperations.ZeroMemory(input);
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            // An exited worker's output is already buffered; a descendant still holding the inherited pipes
            // (an Updater the worker could not release) must fail this step, not hold Setup to its deadline.
            await Task.WhenAll(output, errors).WaitAsync(TimeSpan.FromSeconds(5), deadline.Token).ConfigureAwait(false);
            var (state, failedPhase) = await output.ConfigureAwait(false); var errorOutput = await errors.ConfigureAwait(false);
            if (reportPhase && failedPhase is not null && !errorOutput && process.ExitCode == 1) throw new SetupStepException(failedPhase);
            if (errorOutput || process.ExitCode != 0 || failedPhase is not null || expectState && state is null) throw new InvalidDataException("Installation step failed.");
            return state;
        }
        catch (SetupStepException) { throw; }
        catch { token.ThrowIfCancellationRequested(); throw new InvalidDataException("Installation step unavailable."); }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            deadline.Cancel();
            try { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } } catch { }
        }
    }

    private static void ObserveFailure(Task task) =>
        _ = task.ContinueWith(static failed => _ = failed.Exception, CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

    private async Task<(string? State, string? FailedPhase)> ReadProgressAsync(Stream stream, CancellationTokenSource deadline, bool expectState)
    {
        var buffer = new byte[1]; var line = new byte[128]; var used = 0; var total = 0; var done = false; string? failed = null;
        string? state = null;
        try
        {
            while (await stream.ReadAsync(buffer, deadline.Token).ConfigureAwait(false) != 0)
            {
                if (++total > 8192 || done || failed is not null) throw new InvalidDataException();
                if (buffer[0] == '\r') continue;
                if (buffer[0] != '\n') { if (used == line.Length || buffer[0] is < 32 or > 126) throw new InvalidDataException(); line[used++] = buffer[0]; continue; }
                var marker = Encoding.ASCII.GetString(line, 0, used); used = 0;
                var text = SetupWorkflow.ProgressFor(marker);
                if (text is not null) progress.Report(text);
                else if (marker == "DONE") done = true;
                else if (marker.StartsWith("STATE|", StringComparison.Ordinal) && expectState && state is null) state = marker;
                else if (marker is "FAILED|validate" or "FAILED|core" or "FAILED|services" or "FAILED|network" or "FAILED|agent" or "FAILED|desktop" or "FAILED|shortcut" or "FAILED|inspect" or "FAILED|replace" or "FAILED|health" or "FAILED|rollback" or "FAILED|uninstall" or "FAILED|updater" or "FAILED|apps" or "FAILED|enroll") failed = marker[7..];
                else throw new InvalidDataException();
            }
            // A failed step reports its phase and exits without DONE; anything else must end with DONE.
            if (used != 0 || done == (failed is not null)) throw new InvalidDataException("Invalid setup response.");
            return (state, failed);
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

/// <summary>A worker step that failed in the phase it reported.</summary>
internal sealed class SetupStepException(string phase) : Exception("Installation step failed.")
{
    public string Phase { get; } = phase;
}
