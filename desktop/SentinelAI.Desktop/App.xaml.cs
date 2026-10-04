using System.Reflection;
using System.Windows;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;

namespace SentinelAI.Desktop;

public partial class App : Application
{
    private ShellViewModel? _shell;
    private AuthenticationViewModel? _authentication;
    private DevicesViewModel? _devices;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ICoreClient? client = null;
        try
        {
            if (e.Args.Length != 0)
            {
                if (e.Args.Length != 1 || e.Args[0] != "--setup-administrator") throw new InvalidOperationException();
                MainWindow = new SetupWindow(new WindowsCoreServices().CreateAdministratorSetupClient());
                MainWindow.Show();
                return;
            }
            client = new HttpCoreClient();
            var coreServices = new WindowsCoreServices();
            var authenticationClient = coreServices.CreateAuthenticationClient();
            _authentication = new AuthenticationViewModel(authenticationClient, coreServices.CreateAdministratorSetupClient());
            _devices = new DevicesViewModel((IDevicesClient)authenticationClient);
            var assembly = typeof(App).Assembly;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion.Split('+')[0]
                ?? assembly.GetName().Version?.ToString(3)
                ?? "Unknown";
            _shell = new ShellViewModel(client, version);
            MainWindow = new MainWindow(_shell, _authentication, _devices);
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
        _devices?.Dispose();
        _authentication?.Dispose();
        base.OnExit(e);
    }
}
