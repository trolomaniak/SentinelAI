using System.Windows;

namespace SentinelAI.Setup;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ChildProcessEnvironment.SanitizeParent();
        MainWindow = new SetupWindow();
        MainWindow.Show();
    }
    protected override void OnExit(ExitEventArgs e)
    {
        e.ApplicationExitCode = Properties["ExitCode"] is int code ? code : 0;
        base.OnExit(e);
    }
}
