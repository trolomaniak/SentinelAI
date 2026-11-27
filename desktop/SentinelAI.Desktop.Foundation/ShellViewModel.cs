using System.ComponentModel;
using System.Windows.Input;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed class ShellViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private readonly ICoreClient _client;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly RefreshCommand _refreshCommand;
    private readonly NavigationCommand _navigateCommand;
    private NavigationPage _currentPage;
    private string _coreStatusText = T("Core status not checked");
    private bool _isCheckingCore;
    private bool _disposed;
    private Task? _pendingRefresh;

    public ShellViewModel(ICoreClient client, string version)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        _client = client;
        Version = version;
        Pages = Array.AsReadOnly(new[]
        {
            new NavigationPage(PageId.Overview, T("Overview"), T("Your local security workspace.")),
            new NavigationPage(PageId.Devices, T("Devices"), T("Endpoint inventory and connection health.")),
            new NavigationPage(PageId.SoftwareCatalog, T("Software catalog"), T("Reported Windows applications, versions and changes.")),
            new NavigationPage(PageId.VulnerabilityCenter, T("Vulnerability center"), T("Fleet findings, affected computers and update guidance.")),
            new NavigationPage(PageId.Alerts, T("Alerts"), T("Security alerts and incident review.")),
            new NavigationPage(PageId.Risk, T("Risk"), T("Organization and endpoint risk.")),
            new NavigationPage(PageId.RiskRegister, T("Risk Register"), T("Business risks, owners, treatment and reviews.")),
            new NavigationPage(PageId.Reports, T("Reports"), T("Local security reports.")),
            new NavigationPage(PageId.Notifications, T("Notifications"), T("Local security notifications and optional delivery.")),
            new NavigationPage(PageId.MonitoringCoverage, T("Monitoring coverage"), T("Endpoint data freshness, source availability and continuity.")),
            new NavigationPage(PageId.Settings, T("Settings"), T("Local application settings and licensing."))
        });
        _currentPage = Pages.Single(page => page.Id == PageId.Devices);
        _refreshCommand = new RefreshCommand(this);
        _navigateCommand = new NavigationCommand(this);
    }

    public string Title => T("SentinelAI");
    public string Version { get; }
    public IReadOnlyList<NavigationPage> Pages { get; }
    public ICommand RefreshCoreCommand => _refreshCommand;
    public ICommand NavigateCommand => _navigateCommand;
    public event PropertyChangedEventHandler? PropertyChanged;

    public NavigationPage CurrentPage
    {
        get { lock (_gate) return _currentPage; }
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (!Pages.Any(page => ReferenceEquals(page, value)))
                    throw new ArgumentException("Select a page from the application navigation.", nameof(value));
                if (ReferenceEquals(_currentPage, value))
                    return;
                _currentPage = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CurrentPage)));
            }
        }
    }

    public string CoreStatusText { get { lock (_gate) return _coreStatusText; } }
    public bool IsCheckingCore { get { lock (_gate) return _isCheckingCore; } }

    public Task InitializeAsync() => RefreshCoreStatusAsync();

    public Task RefreshCoreStatusAsync()
    {
        lock (_gate)
        {
            if (_disposed)
                return Task.CompletedTask;
            if (_pendingRefresh is not null)
                return _pendingRefresh;

            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingRefresh = completion.Task;
            SetCoreState(T("Checking local Core…"), true);
            _ = CompleteRefreshAsync(completion, _lifetime.Token);
            return completion.Task;
        }
    }

    private async Task CompleteRefreshAsync(TaskCompletionSource completion, CancellationToken cancellationToken)
    {
        var result = CoreHealth.Unavailable;
        try
        {
            result = await _client.CheckHealthAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Application shutdown owns this cancellation and does not surface an error.
        }
        catch (Exception)
        {
            // Transport failures and service errors become a generic availability state.
        }

        lock (_gate)
        {
            _pendingRefresh = null;
            if (!_disposed)
                SetCoreState(result == CoreHealth.Available ? T("Local Core available") : T("Local Core unavailable"), false);
            else
                _lifetime.Dispose();
            completion.TrySetResult();
        }
    }

    private void SetCoreState(string status, bool checking)
    {
        var statusChanged = _coreStatusText != status;
        var checkingChanged = _isCheckingCore != checking;
        _coreStatusText = status;
        _isCheckingCore = checking;
        if (statusChanged)
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CoreStatusText)));
        if (checkingChanged)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsCheckingCore)));
            _refreshCommand.RaiseCanExecuteChanged();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;
            _disposed = true;
            _navigateCommand.RaiseCanExecuteChanged();
            SetCoreState(_coreStatusText, false);
            _refreshCommand.RaiseCanExecuteChanged();
            _lifetime.Cancel();
            _client.Dispose();
            if (_pendingRefresh is null)
                _lifetime.Dispose();
        }
    }

    private sealed class NavigationCommand(ShellViewModel owner) : ICommand
    {
        public event EventHandler? CanExecuteChanged;
        public bool CanExecute(object? parameter)
        {
            lock (owner._gate) return !owner._disposed && parameter is PageId id && owner.Pages.Any(page => page.Id == id);
        }

        public void Execute(object? parameter)
        {
            lock (owner._gate)
                if (CanExecute(parameter)) owner.CurrentPage = owner.Pages.Single(page => page.Id == (PageId)parameter!);
        }

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    private sealed class RefreshCommand(ShellViewModel owner) : ICommand
    {
        public event EventHandler? CanExecuteChanged;
        public bool CanExecute(object? parameter)
        {
            lock (owner._gate) return !owner._disposed && !owner._isCheckingCore;
        }

        public void Execute(object? parameter)
        {
            if (CanExecute(parameter))
                _ = owner.RefreshCoreStatusAsync();
        }

        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
