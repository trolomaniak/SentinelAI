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
    private bool _closed;

    public MainWindow(ShellViewModel viewModel) : this(viewModel, null) { }

    public MainWindow(ShellViewModel viewModel, AuthenticationViewModel? authentication)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        InitializeComponent();
        _viewModel = viewModel;
        _authentication = authentication;
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
        NavigationList.IsEnabled = authorized;
        PageContent.Visibility = authorized ? Visibility.Visible : Visibility.Collapsed;
        AuthenticationRow.Height = authorized ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
        PageRow.Height = authorized ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
    }

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        Loaded -= OnLoaded;
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
