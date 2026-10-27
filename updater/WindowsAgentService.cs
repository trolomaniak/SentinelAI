using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using SentinelAI.Updates;

namespace SentinelAI.Updater;

/// <summary>
/// The installed <c>SentinelAIAgent</c> service of an Agent Setup installation. A replaced code tree gets Setup's exact
/// Agent code access (Administrators and SYSTEM full control, LocalService read and execute) before the service starts;
/// the Agent is healthy once its service has kept running for 15 seconds.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsAgentService(AgentUpdateLayout layout) : IServiceUpdateLifecycle
{
    private const string ServiceName = "SentinelAIAgent";
    private static readonly TimeSpan ControlTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(15);
    private DateTime? _runningSince;

    /// <summary>The service runs this installation's Agent with its configuration, as LocalService; otherwise nothing is touched.</summary>
    public void AssertOwned()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName)
                        ?? throw new InvalidDataException("The Agent service is not installed.");
        var expected = "\"" + Path.Combine(layout.AgentCode, "SentinelAI.Agent.exe") + "\" --config \"" +
                       Path.Combine(layout.AgentData, "pilot-config.json") + "\"";
        if (!string.Equals(key.GetValue("ImagePath") as string, expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(key.GetValue("ObjectName") as string, @"NT AUTHORITY\LocalService", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The Agent service does not belong to this installation.");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var controller = new ServiceController(ServiceName);
        if (controller.Status != ServiceControllerStatus.Stopped)
        {
            if (controller.Status != ServiceControllerStatus.StopPending) controller.Stop();
            controller.WaitForStatus(ServiceControllerStatus.Stopped, ControlTimeout);
        }

        _runningSince = null;
        return Task.CompletedTask;
    }

    public Task StartAsync(string installationDirectory, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ApplyCodeAccess(installationDirectory);
        using var controller = new ServiceController(ServiceName);
        if (controller.Status != ServiceControllerStatus.Running) controller.Start();
        controller.WaitForStatus(ServiceControllerStatus.Running, ControlTimeout);
        _runningSince = DateTime.UtcNow;
        return Task.CompletedTask;
    }

    public Task<bool> IsHealthyAsync(string installationDirectory, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var controller = new ServiceController(ServiceName);
        var running = controller.Status == ServiceControllerStatus.Running;
        if (!running) _runningSince = null;
        return Task.FromResult(running && _runningSince is { } since && DateTime.UtcNow - since >= Settle);
    }

    /// <summary>Windows Apps shows the installed version.</summary>
    public static void RecordAppsVersion(string version)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + ServiceName, writable: true);
        key?.SetValue("DisplayVersion", version, RegistryValueKind.String);
    }

    private static void ApplyCodeAccess(string directory)
    {
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var (sid, rights) in new[]
                 {
                     (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl),
                     (WellKnownSidType.LocalSystemSid, FileSystemRights.FullControl),
                     (WellKnownSidType.LocalServiceSid, FileSystemRights.ReadAndExecute)
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), rights, inheritance,
                PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(directory).SetAccessControl(security);
    }
}
