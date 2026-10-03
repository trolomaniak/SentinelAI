using System.Reflection;
using System.Windows;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop;

public partial class App : Application
{
    private ShellViewModel? _shell;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ICoreClient? client = null;
        try
        {
            client = new HttpCoreClient();
            var assembly = typeof(App).Assembly;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion.Split('+')[0]
                ?? assembly.GetName().Version?.ToString(3)
                ?? "Unknown";
            _shell = new ShellViewModel(client, version);
            MainWindow = new MainWindow(_shell);
            MainWindow.Show();
        }
        catch (Exception)
        {
            if (_shell is not null)
                _shell.Dispose();
            else
                client?.Dispose();
            MessageBox.Show("SentinelAI could not start. Close the application and try again.",
                "SentinelAI", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shell?.Dispose();
        base.OnExit(e);
    }
}
