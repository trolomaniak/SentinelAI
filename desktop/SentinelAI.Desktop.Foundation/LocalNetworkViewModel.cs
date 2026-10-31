using System.ComponentModel;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum LocalNetworkState { NotLoaded, Loading, Ready, Unavailable }

/// <summary>Core's local-network role for Settings: whether Agents can connect, where and with which fingerprint.</summary>
public sealed class LocalNetworkViewModel : INotifyPropertyChanged, IDisposable
{
    private const string NotLoaded = "Not loaded";
    private readonly object _gate = new();
    private readonly ILocalNetworkClient _client;
    private LocalNetworkStatus? _status;
    private LocalNetworkState _state;
    private string _errorText = string.Empty;
    private long _generation;
    private Pending? _pending;
    private bool _disposed;

    public LocalNetworkViewModel(ILocalNetworkClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public LocalNetworkState State { get { lock (_gate) return _state; } }
    public LocalNetworkStatus? Status { get { lock (_gate) return _status; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _pending is null; } }
    public string AccessText
    {
        get
        {
            lock (_gate)
            {
                if (_status is null) return _state == LocalNetworkState.Loading ? T("Reading Core's local-network settings…") : NotLoaded;
                if (!_status.Enabled) return T("Off. This installation is local to this computer; Agents on other computers cannot connect.");
                return _status.Listening
                    ? T("On. Agents on other computers in this local network connect to Core over HTTPS.")
                    : T("Configured, but Core is not listening on the local network: its certificate is unavailable or another program uses its port.");
            }
        }
    }
    public string AddressesText
    {
        get
        {
            lock (_gate)
            {
                if (_status is null) return NotLoaded;
                if (!_status.Enabled) return T("Not applicable");
                return _status.Addresses.Count == 0 ? T("No active IPv4 address") : string.Join(Environment.NewLine, _status.Addresses);
            }
        }
    }
    public string PortText { get { lock (_gate) return _status is null ? NotLoaded : _status.Port?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? T("Not applicable"); } }
    public string FingerprintText { get { lock (_gate) return _status is null ? NotLoaded : _status.CertificateSha256 ?? T("Not applicable"); } }
    public string ComputerNameText
    {
        get
        {
            lock (_gate)
                return _status is null ? NotLoaded
                    : _status.FullyQualifiedName is null ? _status.HostName : _status.HostName + " (" + _status.FullyQualifiedName + ")";
        }
    }

    public Task RefreshAsync()
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_pending is not null) return _pending.Task;
            var pending = new Pending(++_generation);
            _pending = pending;
            _status = null;
            _state = LocalNetworkState.Loading;
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
            var result = await _client.GetLocalNetworkAsync(pending.Token);
            lock (_gate)
            {
                if (!Current(pending)) return;
                if (result.Outcome == LocalNetworkRequestOutcome.Unauthenticated)
                {
                    ClearLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == LocalNetworkRequestOutcome.Success && result.Status is not null)
                {
                    _status = result.Status with { Addresses = Array.AsReadOnly(result.Status.Addresses.ToArray()) };
                    _state = LocalNetworkState.Ready;
                    _errorText = string.Empty;
                }
                else SetFailureLocked(result.Outcome);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (Current(pending))
                {
                    SetFailureLocked(LocalNetworkRequestOutcome.Unavailable);
                    NotifyAll();
                }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_pending, pending)) _pending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanRefresh));
            }
        }
    }

    private void SetFailureLocked(LocalNetworkRequestOutcome outcome)
    {
        _status = null;
        _state = LocalNetworkState.Unavailable;
        _errorText = outcome switch
        {
            LocalNetworkRequestOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
            LocalNetworkRequestOutcome.InvalidResponse or LocalNetworkRequestOutcome.Success => T("Core returned invalid local-network settings. Refresh to try again."),
            LocalNetworkRequestOutcome.TooLarge => T("The local-network settings exceed the supported size."),
            _ => T("Local Core is unavailable. Restore Core, then refresh the local-network settings.")
        };
    }

    private bool Current(Pending pending) => !_disposed && pending.Generation == _generation && ReferenceEquals(_pending, pending) && !pending.Token.IsCancellationRequested;

    private void ClearLocked()
    {
        _generation++;
        _pending?.Cancel();
        _pending = null;
        _status = null;
        _state = LocalNetworkState.NotLoaded;
        _errorText = string.Empty;
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

    private void NotifyAll() => Notify(nameof(State), nameof(Status), nameof(ErrorText), nameof(CanRefresh), nameof(AccessText),
        nameof(AddressesText), nameof(PortText), nameof(FingerprintText), nameof(ComputerNameText));

    private void Notify(params string[] names)
    {
        foreach (var name in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private sealed class Pending(long generation)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete() { _cancellation.Dispose(); _completion.TrySetResult(); }
    }
}
