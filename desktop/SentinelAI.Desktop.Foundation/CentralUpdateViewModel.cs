using System.ComponentModel;
using System.Globalization;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum CentralUpdateState { NotLoaded, Loading, Ready, Saving, Unavailable }

/// <summary>
/// MVP-7 Settings → Updates: whether Core checks the provider's update server (off by default, so no internet
/// connection), whether a downloaded update installs at night (on once checking is on), and Install now, which opens
/// the verified Setup and closes Desktop.
/// </summary>
public sealed class CentralUpdateViewModel : INotifyPropertyChanged, IDisposable
{
    private const string NotLoaded = "Not loaded";
    private readonly object _gate = new();
    private readonly ICentralUpdateClient _client;
    private readonly ICentralUpdateInstaller? _installer;
    private CentralUpdateInfo? _info;
    private CentralUpdateState _state;
    private string _errorText = string.Empty;
    private string _installStatusText = string.Empty;
    private long _generation;
    private Pending? _pending;
    private bool _installing;
    private bool _disposed;

    public CentralUpdateViewModel(ICentralUpdateClient client, ICentralUpdateInstaller? installer)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
        _installer = installer;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    /// <summary>Setup refuses to upgrade beside Desktop, so Desktop exits once the verified Setup has started.</summary>
    public event EventHandler? ExitRequested;
    public CentralUpdateState State { get { lock (_gate) return _state; } }
    public CentralUpdateInfo? Info { get { lock (_gate) return _info; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public string InstallStatusText { get { lock (_gate) return _installStatusText; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _pending is null; } }
    public bool CanChangeSettings { get { lock (_gate) return !_disposed && _pending is null && _info is { Configured: true }; } }
    public bool CanChangeAutoInstall { get { lock (_gate) return CanChangeSettings && _info!.CheckEnabled; } }
    public bool CanCheckNow { get { lock (_gate) return CanChangeAutoInstall && _info!.LastCheck != "checking"; } }
    public bool CanInstall { get { lock (_gate) return !_disposed && _pending is null && !_installing && _installer is not null && _info?.ReadyVersion is not null; } }

    public bool CheckEnabled
    {
        get { lock (_gate) return _info?.CheckEnabled == true; }
        set
        {
            bool autoInstall;
            lock (_gate)
            {
                if (!CanChangeSettings || _info!.CheckEnabled == value) return;
                autoInstall = _info.AutoInstall;
            }
            _ = Begin(Operation.Save, value, autoInstall);
        }
    }

    public bool AutoInstall
    {
        get { lock (_gate) return _info?.AutoInstall == true; }
        set
        {
            lock (_gate)
            {
                if (!CanChangeAutoInstall || _info!.AutoInstall == value) return;
            }
            _ = Begin(Operation.Save, true, value);
        }
    }

    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (_info is not { } info) return _state == CentralUpdateState.Loading ? T("Reading update settings…") : NotLoaded;
                if (!info.Configured) return T("This installation has no update server. Your provider delivers new versions as a new SentinelAI Setup.");
                if (!info.CheckEnabled) return T("Off. SentinelAI connects to no update server. Turn on checking to download new versions from ") + info.Server + ".";
                if (info.ReadyVersion is { } ready)
                {
                    if (info.AutoInstall && info.InstallAttempts >= 3)
                        return "SentinelAI " + ready + T(" did not install after 3 nights. Select Install now, or contact your provider.");
                    var plan = info.AutoInstall
                        ? "SentinelAI " + ready + T(" is downloaded and installs tonight between 02:00 and 04:00. Desktop closes for the installation; monitoring continues.")
                        : "SentinelAI " + ready + T(" is downloaded. Select Install now to install it.");
                    return info.InstallAttempts > 0
                        ? plan + T(" Installation was started ") + info.InstallAttempts.ToString(CultureInfo.InvariantCulture) + T(" time(s) and this computer still runs ") + info.InstalledVersion + "."
                        : plan;
                }
                return info.LastCheck switch
                {
                    "checking" => "Checking " + info.Server + T(" for a newer version…"),
                    "current" => "SentinelAI " + info.InstalledVersion + T(" is up to date."),
                    "failed" => T("The last check did not succeed. SentinelAI tries again within an hour."),
                    _ => T("Not checked yet. SentinelAI checks a few minutes after start and every six hours.")
                };
            }
        }
    }

    public string InstalledVersionText { get { lock (_gate) return _info?.InstalledVersion ?? NotLoaded; } }
    public string ServerText { get { lock (_gate) return _info is null ? NotLoaded : _info.Server ?? T("Not configured"); } }
    public string LastCheckText
    {
        get
        {
            lock (_gate)
                return _info is null ? NotLoaded
                    : _info.LastCheckUtc?.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) ?? T("Not since Core started");
        }
    }

    public Task RefreshAsync() => Begin(Operation.Read, false, false);

    public Task CheckNowAsync()
    {
        lock (_gate) if (!CanCheckNow) return _pending?.Task ?? Task.CompletedTask;
        return Begin(Operation.Check, false, false);
    }

    public async Task InstallAsync()
    {
        ICentralUpdateInstaller installer;
        lock (_gate)
        {
            if (!CanInstall) return;
            installer = _installer!;
            _installing = true;
            _installStatusText = T("Windows asks for administrator permission, then SentinelAI checks the downloaded update…");
        }
        Notify(nameof(CanInstall), nameof(InstallStatusText));
        CentralUpdateInstallOutcome outcome;
        try { outcome = await installer.StartAsync(CancellationToken.None); }
        catch (Exception) { outcome = CentralUpdateInstallOutcome.Unavailable; }
        lock (_gate)
        {
            _installing = false;
            if (_disposed) return;
            _installStatusText = outcome switch
            {
                CentralUpdateInstallOutcome.Started => T("SentinelAI Setup opened with Upgrade selected, and Desktop closes so it can continue."),
                CentralUpdateInstallOutcome.Cancelled => T("Installation was not started."),
                CentralUpdateInstallOutcome.NothingToInstall => T("There is no newer downloaded version to install. Refresh the update status."),
                CentralUpdateInstallOutcome.Rejected => T("The downloaded update did not pass verification and was not run. Check for updates again or contact your provider."),
                _ => T("The update could not be started. Run the newer SentinelAI Setup from your provider instead.")
            };
        }
        Notify(nameof(CanInstall), nameof(InstallStatusText));
        if (outcome == CentralUpdateInstallOutcome.Started) ExitRequested?.Invoke(this, EventArgs.Empty);
    }

    private Task Begin(Operation operation, bool checkEnabled, bool autoInstall)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_pending is not null) return _pending.Task;
            var pending = new Pending(++_generation, operation, checkEnabled, autoInstall);
            _pending = pending;
            _state = operation == Operation.Read ? CentralUpdateState.Loading : CentralUpdateState.Saving;
            _errorText = string.Empty;
            NotifyAll();
            _ = CompleteAsync(pending);
            return pending.Task;
        }
    }

    private async Task CompleteAsync(Pending pending)
    {
        try
        {
            var result = pending.Operation switch
            {
                Operation.Save => await _client.SetCentralUpdateSettingsAsync(pending.CheckEnabled, pending.AutoInstall, pending.Token),
                Operation.Check => await _client.CheckCentralUpdateAsync(pending.Token),
                _ => await _client.GetCentralUpdateAsync(pending.Token)
            };
            lock (_gate)
            {
                if (!Current(pending)) return;
                if (result.Outcome == CentralUpdateRequestOutcome.Unauthenticated)
                {
                    ClearLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == CentralUpdateRequestOutcome.Success && result.Info is not null)
                {
                    _info = result.Info;
                    _state = CentralUpdateState.Ready;
                }
                else
                {
                    _state = _info is null ? CentralUpdateState.Unavailable : CentralUpdateState.Ready;
                    _errorText = result.Outcome switch
                    {
                        CentralUpdateRequestOutcome.NotConfigured => T("This installation has no update server."),
                        CentralUpdateRequestOutcome.NotEnabled => T("Turn on checking for updates first."),
                        CentralUpdateRequestOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
                        CentralUpdateRequestOutcome.InvalidResponse or CentralUpdateRequestOutcome.TooLarge or CentralUpdateRequestOutcome.Success =>
                            T("Core returned an invalid update response. Refresh the update status."),
                        _ => T("Local Core is unavailable. Restore Core, then refresh the update status.")
                    };
                }
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (Current(pending))
                {
                    _state = _info is null ? CentralUpdateState.Unavailable : CentralUpdateState.Ready;
                    _errorText = T("Local Core is unavailable. Restore Core, then refresh the update status.");
                    NotifyAll();
                }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
                pending.Complete();
                if (!_disposed) NotifyAll();
            }
        }
    }

    private bool Current(Pending pending) => !_disposed && pending.Generation == _generation && ReferenceEquals(_pending, pending) && !pending.Token.IsCancellationRequested;

    private void ClearLocked()
    {
        _generation++;
        _pending?.Cancel();
        _pending = null;
        _info = null;
        _state = CentralUpdateState.NotLoaded;
        _errorText = string.Empty;
        _installStatusText = string.Empty;
    }

    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            ClearLocked();
            NotifyAll();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            ClearLocked();
        }
    }

    private void NotifyAll() => Notify(nameof(State), nameof(Info), nameof(ErrorText), nameof(InstallStatusText), nameof(CanRefresh),
        nameof(CanChangeSettings), nameof(CanChangeAutoInstall), nameof(CanCheckNow), nameof(CanInstall), nameof(CheckEnabled), nameof(AutoInstall),
        nameof(StatusText), nameof(InstalledVersionText), nameof(ServerText), nameof(LastCheckText));

    private void Notify(params string[] names)
    {
        foreach (var name in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private enum Operation { Read, Save, Check }

    private sealed class Pending(long generation, Operation operation, bool checkEnabled, bool autoInstall)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal Operation Operation { get; } = operation;
        internal bool CheckEnabled { get; } = checkEnabled;
        internal bool AutoInstall { get; } = autoInstall;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _cancellation.Dispose(); _completion.TrySetResult(); }
    }
}
