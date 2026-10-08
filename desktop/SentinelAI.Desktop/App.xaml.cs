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
    private AlertsViewModel? _alerts;
    private RiskViewModel? _risk;
    private ReportsViewModel? _reports;
    private LicenseViewModel? _license;
    private AiExplanationViewModel? _aiExplanation;

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
            _alerts = new AlertsViewModel((IAlertsClient)authenticationClient, (IDevicesClient)authenticationClient);
            _risk = new RiskViewModel((IRiskClient)authenticationClient);
            _reports = new ReportsViewModel((IReportsClient)authenticationClient, new WindowsReportSaveService(() => MainWindow));
            _license = new LicenseViewModel((ILicenseClient)authenticationClient);
            _aiExplanation = new AiExplanationViewModel((IAiExplanationClient)authenticationClient);
            var assembly = typeof(App).Assembly;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion.Split('+')[0]
                ?? assembly.GetName().Version?.ToString(3)
                ?? "Unknown";
            _shell = new ShellViewModel(client, version);
            MainWindow = new MainWindow(_shell, _authentication, _devices, _alerts, _risk, _reports, _license, _aiExplanation);
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
        _alerts?.Dispose();
        _risk?.Dispose();
        _reports?.Dispose();
        _license?.Dispose();
        _aiExplanation?.Dispose();
        _authentication?.Dispose();
        base.OnExit(e);
    }
}
