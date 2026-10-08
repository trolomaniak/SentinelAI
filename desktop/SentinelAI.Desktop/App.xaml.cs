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
    private WindowsDesktopInstance? _instance;
    private WindowsServiceStatusModel? _serviceStatus;
    private WindowsDesktopTray? _tray;

    protected override async void OnStartup(StartupEventArgs e)
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
            _instance = WindowsDesktopInstance.AcquireForCurrentSession();
            if (!_instance.IsPrimary)
            {
                if (await _instance.ActivateExistingAsync()) Shutdown();
                else
                {
                    MessageBox.Show("SentinelAI is already running, but its window could not be opened. Wait for it to respond or close it, then try again.",
                        "SentinelAI", MessageBoxButton.OK, MessageBoxImage.Information);
                    Shutdown(1);
                }
                return;
            }
            _instance.StartListening(OpenSentinelAi);
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
            var integration = new DesktopIntegrationViewModel(new WindowsDesktopPreferences());
            _serviceStatus = new WindowsServiceStatusModel();
            var window = new MainWindow(_shell, _authentication, _devices, _alerts, _risk, _reports, _license, _aiExplanation,
                integration, _serviceStatus);
            MainWindow = window;
            _tray = new WindowsDesktopTray(window, integration, _serviceStatus, OpenSentinelAi, () => Shutdown());
            window.DesktopTray = _tray;
            _serviceStatus.Start();
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

    /// <summary>Shared native activation action for a duplicate launch and tray.</summary>
    public void OpenSentinelAi()
    {
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(OpenSentinelAi);
            return;
        }
        if (MainWindow is not { } window) return;
        window.Show();
        if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
        _ = window.Activate();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _serviceStatus?.Dispose();
        _shell?.Dispose();
        _devices?.Dispose();
        _alerts?.Dispose();
        _risk?.Dispose();
        _reports?.Dispose();
        _license?.Dispose();
        _aiExplanation?.Dispose();
        _authentication?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }
}
