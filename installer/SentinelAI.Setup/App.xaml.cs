using System.Windows;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

public partial class App : Application
{
    private SafeFileHandle? _image;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ChildProcessEnvironment.SanitizeParent();
        // Before anything is created: what Setup installs is owned by Administrators, never by an account.
        AdministratorsDefaultOwner.Apply();
        // Only the native wrapper starts this host, with its canonical, allow-listed options.
        if (!SetupArguments.TryParse(e.Args, out var arguments)) { Finish(AgentSetupExitCode.InvalidArguments); return; }
        _image = new SafeFileHandle((IntPtr)arguments!.ImageHandle, ownsHandle: true);
        string? product = null;
        try { using var installation = EmbeddedInstallation.Open(); product = installation.Metadata.Product; }
        catch (Exception) { }
        var quiet = arguments.Mode is SetupMode.QuietInstall or SetupMode.QuietUninstall or SetupMode.QuietUpgrade;
        if (product == SetupMetadata.AgentProduct)
        {
            if (arguments.Mode == SetupMode.QuietUpgrade) { Finish(AgentSetupExitCode.InvalidArguments); return; }
            if (quiet) { RunQuiet(arguments, _image); return; }
            MainWindow = new AgentSetupWindow(_image, arguments.Mode == SetupMode.Uninstall);
        }
        else
        {
            // The full Setup's only quiet mode is the unattended upgrade; its interactive window reports an unreadable payload itself.
            if (arguments.Mode == SetupMode.QuietUpgrade && product is not null) { RunQuietUpgrade(_image); return; }
            if (quiet) { Finish(product is null ? AgentSetupExitCode.Failed : AgentSetupExitCode.InvalidArguments); return; }
            MainWindow = new SetupWindow(_image, arguments.Mode == SetupMode.Uninstall);
        }
        MainWindow.Show();
    }

    private async void RunQuiet(SetupArguments arguments, SafeFileHandle image)
    {
        var code = AgentSetupExitCode.Failed;
        try { code = await AgentSetupSession.RunQuietAsync(arguments, image); }
        finally { Finish(code); }
    }

    private async void RunQuietUpgrade(SafeFileHandle image)
    {
        var code = SetupUpgradeExitCode.Failed;
        try { code = await QuietUpgrade.RunAsync(image); }
        finally { Finish((int)code); }
    }

    private void Finish(AgentSetupExitCode code) => Finish((int)code);

    private void Finish(int code)
    {
        Properties["ExitCode"] = code;
        Shutdown(code);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        e.ApplicationExitCode = Properties["ExitCode"] is int code ? code : 0;
        _image?.Dispose();
        base.OnExit(e);
    }
}
