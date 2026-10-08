using System.Windows;
using System.ComponentModel;
using System.Threading;
using System.Windows.Threading;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;

namespace SentinelAI.Desktop;

public partial class MainWindow : Window
{
    private readonly ShellViewModel _viewModel;
    private readonly AuthenticationViewModel? _authentication;
    private readonly DispatcherTimer? _sessionTimer;
    public DevicesViewModel? Devices { get; }
    public AlertsViewModel? Alerts { get; }
    public RiskViewModel? Risk { get; }
    public ReportsViewModel? Reports { get; }
    public LicenseViewModel? License { get; }
    public AiExplanationViewModel? AiExplanation { get; }
    public DesktopIntegrationViewModel? DesktopIntegration { get; }
    public WindowsServiceStatusModel? ServiceStatus { get; }
    public WindowsDesktopTray? DesktopTray { get; set; }
    private bool _closed;
    private bool _workspaceAuthorized;
    private long _workspaceSessionGeneration;

    public MainWindow(ShellViewModel viewModel) : this(viewModel, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication) : this(viewModel, authentication, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices) : this(viewModel, authentication, devices, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices, AlertsViewModel? alerts)
        : this(viewModel, authentication, devices, alerts, null, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices,
        AlertsViewModel? alerts, RiskViewModel? risk, ReportsViewModel? reports)
        : this(viewModel, authentication, devices, alerts, risk, reports, null, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices,
        AlertsViewModel? alerts, RiskViewModel? risk, ReportsViewModel? reports,
        LicenseViewModel? license, AiExplanationViewModel? aiExplanation)
        : this(viewModel, authentication, devices, alerts, risk, reports, license, aiExplanation, null, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices,
        AlertsViewModel? alerts, RiskViewModel? risk, ReportsViewModel? reports,
        LicenseViewModel? license, AiExplanationViewModel? aiExplanation,
        DesktopIntegrationViewModel? desktopIntegration, WindowsServiceStatusModel? serviceStatus)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        InitializeComponent();
        _viewModel = viewModel;
        _authentication = authentication;
        Devices = devices;
        Alerts = alerts;
        Risk = risk;
        Reports = reports;
        License = license;
        AiExplanation = aiExplanation;
        DesktopIntegration = desktopIntegration;
        ServiceStatus = serviceStatus;
        _viewModel.PropertyChanged += OnShellPageChanged;
        if (devices is not null) devices.SessionExpired += OnWorkspaceSessionExpired;
        if (alerts is not null) alerts.SessionExpired += OnWorkspaceSessionExpired;
        if (risk is not null) risk.SessionExpired += OnWorkspaceSessionExpired;
        if (reports is not null) reports.SessionExpired += OnWorkspaceSessionExpired;
        if (license is not null)
        {
            license.SessionExpired += OnWorkspaceSessionExpired;
            license.PropertyChanged += OnLicenseChanged;
        }
        if (aiExplanation is not null) aiExplanation.SessionExpired += OnWorkspaceSessionExpired;
        if (alerts is not null) alerts.PropertyChanged += OnAlertsChanged;
        AuthenticationPanel.DataContext = authentication;
        DataContext = viewModel;
        if (authentication is not null)
        {
            AuthenticationPanel.Visibility = Visibility.Visible;
            authentication.PropertyChanged += OnAuthenticationChanged;
            _sessionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _sessionTimer.Tick += OnSessionTick;
            SetWorkspaceAccess();
        }
        Loaded += OnLoaded;
        SetPagePresentation();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Core availability never delays the native window opening.
        await _viewModel.InitializeAsync();
        if (!_closed && _authentication is not null)
        {
            await _authentication.InitializeAsync();
            if (!_closed) _sessionTimer?.Start();
        }
    }

    private async void OnSessionTick(object? sender, EventArgs e)
    {
        if (!_closed && _authentication is not null) await _authentication.CheckSessionAsync();
    }

    private void OnAuthenticationChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(AuthenticationViewModel.IsSignedIn)) return;
        // Dispose retained report bytes before accepting the next UI operation.
        if (Dispatcher.CheckAccess()) SetWorkspaceAccess();
        else Dispatcher.InvokeAsync(SetWorkspaceAccess);
    }

    private void SetWorkspaceAccess()
    {
        var authorized = _authentication?.IsSignedIn ?? true;
        var authorizationChanged = authorized != _workspaceAuthorized;
        if (authorizationChanged) Interlocked.Increment(ref _workspaceSessionGeneration);
        _workspaceAuthorized = authorized;
        NavigationList.IsEnabled = authorized;
        PageContent.Visibility = authorized ? Visibility.Visible : Visibility.Collapsed;
        AuthenticationRow.Height = authorized ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
        PageRow.Height = authorized ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
        if (!authorized)
        {
            AiExplanation?.Clear(); License?.Clear();
            Devices?.Clear(); Alerts?.Clear(); Risk?.Clear(); Reports?.Clear();
        }
        else if (authorizationChanged)
        {
            RefreshCurrentPage();
            if (License is not null && _viewModel.CurrentPage.Id is not (PageId.Settings or PageId.Alerts))
                _ = License.RefreshAsync();
        }
    }

    private void OnShellPageChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (!_closed && e.PropertyName == nameof(ShellViewModel.CurrentPage))
        {
            if (_viewModel.CurrentPage.Id != PageId.Reports) Reports?.Clear();
            if (_viewModel.CurrentPage.Id != PageId.Alerts) AiExplanation?.SetAlert(null);
            SetPagePresentation();
            RefreshCurrentPage();
        }
    }

    private void SetPagePresentation() => PageContent.ContentTemplate = (DataTemplate)FindResource(
        Devices is not null && _viewModel.CurrentPage.Id == PageId.Devices ? "DevicesTemplate" :
        Alerts is not null && _viewModel.CurrentPage.Id == PageId.Alerts ? "AlertsTemplate" :
        Risk is not null && _viewModel.CurrentPage.Id == PageId.Risk ? "RiskTemplate" :
        Reports is not null && _viewModel.CurrentPage.Id == PageId.Reports ? "ReportsTemplate" :
        License is not null && _viewModel.CurrentPage.Id == PageId.Settings ? "SettingsTemplate" : "PlaceholderTemplate");

    private async void RefreshCurrentPage()
    {
        if (_closed || !(_authentication?.IsSignedIn ?? true)) return;
        // License availability never delays the local security pages.
        if (License is not null && _viewModel.CurrentPage.Id is PageId.Settings or PageId.Alerts)
            _ = License.RefreshAsync();
        if (Devices is not null && _viewModel.CurrentPage.Id == PageId.Devices) await Devices.RefreshAsync();
        else if (Alerts is not null && _viewModel.CurrentPage.Id == PageId.Alerts) await Alerts.RefreshAsync();
        else if (Risk is not null && _viewModel.CurrentPage.Id == PageId.Risk) await Risk.RefreshAsync();
    }

    private void OnLicenseChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(LicenseViewModel.Status)) return;
        DispatchWorkspaceUpdate(() =>
        {
            var status = License?.Status;
            AiExplanation?.SetAvailability(status is null ? null :
                status.Capabilities.PremiumFeatures && status.EnabledFeatures.Contains("cloud_ai", StringComparer.Ordinal));
        });
    }

    private void OnAlertsChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is not (nameof(AlertsViewModel.Detail) or nameof(AlertsViewModel.DetailState) or
            nameof(AlertsViewModel.NeedsDetailRefresh))) return;
        DispatchWorkspaceUpdate(() => AiExplanation?.SetAlert(
            _viewModel.CurrentPage.Id == PageId.Alerts && Alerts is { DetailState: AlertDetailState.Ready, NeedsDetailRefresh: false }
                ? Alerts.Detail?.Detail : null));
    }

    private void DispatchWorkspaceUpdate(Action update)
    {
        // Worker notifications must not acquire another view model's gate.
        void Apply() { if (!_closed && _workspaceAuthorized) update(); }
        if (Dispatcher.CheckAccess()) Apply();
        else Dispatcher.InvokeAsync(Apply);
    }

    private void OnWorkspaceSessionExpired(object? sender, EventArgs e)
    {
        if (_closed) return;
        var generation = Interlocked.Read(ref _workspaceSessionGeneration);
        void ExpireCurrentSession()
        {
            if (!_closed && generation == Interlocked.Read(ref _workspaceSessionGeneration) && _authentication?.IsSignedIn == true)
                _authentication.SignOut();
        }
        if (Dispatcher.CheckAccess()) ExpireCurrentSession();
        else Dispatcher.InvokeAsync(ExpireCurrentSession);
    }

    protected override void OnClosed(EventArgs e)
    {
        DesktopTray?.Dispose();
        ServiceStatus?.Dispose();
        _closed = true;
        Loaded -= OnLoaded;
        _viewModel.PropertyChanged -= OnShellPageChanged;
        if (Devices is not null) { Devices.SessionExpired -= OnWorkspaceSessionExpired; Devices.Dispose(); }
        if (Alerts is not null)
        {
            Alerts.PropertyChanged -= OnAlertsChanged;
            Alerts.SessionExpired -= OnWorkspaceSessionExpired; Alerts.Dispose();
        }
        if (Risk is not null) { Risk.SessionExpired -= OnWorkspaceSessionExpired; Risk.Dispose(); }
        if (Reports is not null) { Reports.SessionExpired -= OnWorkspaceSessionExpired; Reports.Dispose(); }
        if (License is not null)
        {
            License.PropertyChanged -= OnLicenseChanged;
            License.SessionExpired -= OnWorkspaceSessionExpired; License.Dispose();
        }
        if (AiExplanation is not null) { AiExplanation.SessionExpired -= OnWorkspaceSessionExpired; AiExplanation.Dispose(); }
        _sessionTimer?.Stop();
        if (_sessionTimer is not null) _sessionTimer.Tick -= OnSessionTick;
        if (_authentication is not null)
        {
            _authentication.PropertyChanged -= OnAuthenticationChanged;
            _authentication.Dispose();
        }
        _viewModel.Dispose();
        base.OnClosed(e);
    }
}
