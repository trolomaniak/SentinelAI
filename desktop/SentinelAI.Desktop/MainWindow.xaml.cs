using System.Windows;
using System.ComponentModel;
using System.Windows.Threading;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop;

public partial class MainWindow : Window
{
    private readonly ShellViewModel _viewModel;
    private readonly AuthenticationViewModel? _authentication;
    private readonly DispatcherTimer? _sessionTimer;
    public DevicesViewModel? Devices { get; }
    public AlertsViewModel? Alerts { get; }
    private bool _closed;
    private bool _workspaceAuthorized;

    public MainWindow(ShellViewModel viewModel) : this(viewModel, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication) : this(viewModel, authentication, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices) : this(viewModel, authentication, devices, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication, DevicesViewModel? devices, AlertsViewModel? alerts)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        InitializeComponent();
        _viewModel = viewModel;
        _authentication = authentication;
        Devices = devices;
        Alerts = alerts;
        _viewModel.PropertyChanged += OnShellPageChanged;
        if (devices is not null) devices.SessionExpired += OnDeviceSessionExpired;
        if (alerts is not null) alerts.SessionExpired += OnDeviceSessionExpired;
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
        if (e.PropertyName == nameof(AuthenticationViewModel.IsSignedIn)) Dispatcher.InvokeAsync(SetWorkspaceAccess);
    }

    private void SetWorkspaceAccess()
    {
        var authorized = _authentication?.IsSignedIn ?? true;
        var authorizationChanged = authorized != _workspaceAuthorized;
        _workspaceAuthorized = authorized;
        NavigationList.IsEnabled = authorized;
        PageContent.Visibility = authorized ? Visibility.Visible : Visibility.Collapsed;
        AuthenticationRow.Height = authorized ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
        PageRow.Height = authorized ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
        if (!authorized) { Devices?.Clear(); Alerts?.Clear(); }
        else if (authorizationChanged) RefreshCurrentPage();
    }

    private void OnShellPageChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (!_closed && e.PropertyName == nameof(ShellViewModel.CurrentPage))
        {
            SetPagePresentation();
            RefreshCurrentPage();
        }
    }

    private void SetPagePresentation() => PageContent.ContentTemplate = (DataTemplate)FindResource(
        Devices is not null && _viewModel.CurrentPage.Id == PageId.Devices ? "DevicesTemplate" :
        Alerts is not null && _viewModel.CurrentPage.Id == PageId.Alerts ? "AlertsTemplate" : "PlaceholderTemplate");

    private async void RefreshCurrentPage()
    {
        if (_closed || !(_authentication?.IsSignedIn ?? true)) return;
        if (Devices is not null && _viewModel.CurrentPage.Id == PageId.Devices) await Devices.RefreshAsync();
        else if (Alerts is not null && _viewModel.CurrentPage.Id == PageId.Alerts) await Alerts.RefreshAsync();
    }

    private void OnDeviceSessionExpired(object? sender, EventArgs e)
    {
        if (!_closed) Dispatcher.InvokeAsync(() => _authentication?.SignOut());
    }

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        Loaded -= OnLoaded;
        _viewModel.PropertyChanged -= OnShellPageChanged;
        if (Devices is not null) { Devices.SessionExpired -= OnDeviceSessionExpired; Devices.Dispose(); }
        if (Alerts is not null) { Alerts.SessionExpired -= OnDeviceSessionExpired; Alerts.Dispose(); }
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
