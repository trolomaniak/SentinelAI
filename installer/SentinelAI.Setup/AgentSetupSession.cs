using System.IO;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Enrollment;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

/// <summary>SentinelAI-Agent-Setup.exe (MVP-2): the verified Agent payload in protected staging and its worker.</summary>
internal sealed class AgentSetupSession : IDisposable
{
    private readonly EmbeddedInstallation _installation;
    private readonly string _work;
    private AgentSetupSession(EmbeddedInstallation installation, string work, IProgress<string> progress)
    {
        _installation = installation; _work = work;
        Worker = new PowerShellAgentSetupWorker(new PowerShellSetupWorker(work, installation.Metadata, progress));
    }

    public IAgentSetupWorker Worker { get; }
    public string Version => _installation.Metadata.Version;

    public static async Task<AgentSetupSession> OpenAsync(SafeFileHandle image, IProgress<string> progress, CancellationToken token)
    {
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException("Administrator elevation is required.");
        var installation = EmbeddedInstallation.Open();
        try
        {
            if (installation.Metadata.Product != SetupMetadata.AgentProduct) throw new InvalidDataException("Not an Agent Setup.");
            return new(installation, await installation.ExtractAsync(image, token).ConfigureAwait(false), progress);
        }
        catch { installation.Dispose(); throw; }
    }

    /// <summary>"/quiet /codefile &lt;path&gt;" and "/uninstall /quiet": no window, only the documented exit code.</summary>
    public static async Task<AgentSetupExitCode> RunQuietAsync(SetupArguments arguments, SafeFileHandle image)
    {
        EnrollmentCode? code = null;
        if (arguments.Mode == SetupMode.QuietInstall && !AgentSetupWorkflow.TryReadCodeFile(arguments.CodeFile!, out code)) return AgentSetupExitCode.InvalidCode;
        var progress = new Progress<string>(_ => { });
        try
        {
            using var session = await OpenAsync(image, progress, CancellationToken.None).ConfigureAwait(true);
            using var operation = WindowsSetupLifecycle.AcquireOperationLock();
            return code is not null
                ? await AgentSetupWorkflow.InstallAsync(code, session.Worker, new HttpAgentCodeProbe(), progress, CancellationToken.None).ConfigureAwait(true)
                : await AgentSetupWorkflow.UninstallAsync(session.Worker, progress, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception) { return arguments.Mode == SetupMode.QuietInstall ? AgentSetupExitCode.InstallFailed : AgentSetupExitCode.UninstallFailed; }
    }

    public void Dispose() { ProtectedStaging.TryRemove(_work); _installation.Dispose(); }
}

internal sealed class PowerShellAgentSetupWorker(PowerShellSetupWorker runner) : IAgentSetupWorker
{
    public async Task<AgentSetupInstallation> InspectAsync(CancellationToken token) =>
        AgentSetupWorkflow.ParseState(await runner.RunAgentAsync("agent-inspect", null, token).ConfigureAwait(false) ?? throw new InvalidDataException("Installation state unavailable."));

    public async Task<AgentInstallOutcome> InstallAsync(EnrollmentCode code, CancellationToken token)
    {
        try
        {
            await runner.RunAgentAsync("agent-install", code, token).ConfigureAwait(false);
            return AgentInstallOutcome.Installed;
        }
        // The worker removed everything it created; "enroll" means the Agent ran but Core never acknowledged it.
        catch (SetupStepException failure) when (failure.Phase == "enroll") { return AgentInstallOutcome.NotAcknowledged; }
        catch (SetupStepException failure) when (failure.Phase == "rollback") { return AgentInstallOutcome.RollbackFailed; }
        catch (Exception) when (!token.IsCancellationRequested) { return AgentInstallOutcome.Failed; }
    }

    public Task UninstallAsync(CancellationToken token) => runner.RunAgentAsync("agent-uninstall", null, token);
}
