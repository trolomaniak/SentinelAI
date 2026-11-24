using System.ComponentModel;
using SentinelAI.Contracts.Overview;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed class OperationsOverviewViewModel(IOperationsOverviewClient client) : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private CancellationTokenSource? _operation;
    private OperationsOverviewPresentation? _summary;
    private DeviceReadOutcome? _outcome;
    private bool _disposed;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public OperationsOverviewPresentation? Summary { get { lock (_gate) return _summary; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _operation is null; } }
    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (_operation is not null) return T("Reading operations overview…");
                if (_summary is not null) return F("Snapshot at {0}", AlertRow.Timestamp(_summary.GeneratedUtc));
                return _outcome switch
                {
                    null or DeviceReadOutcome.Unauthenticated => string.Empty,
                    DeviceReadOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
                    _ => T("Operations overview is unavailable. Refresh to try again.")
                };
            }
        }
    }

    public Task RefreshAsync()
    {
        lock (_gate) return CanRefresh ? ReadAsync() : Task.CompletedTask;
    }

    private async Task ReadAsync()
    {
        using var operation = new CancellationTokenSource();
        var token = operation.Token;
        _operation = operation;
        _summary = null;
        _outcome = null;
        Notify();
        DeviceReadResult<OperationsOverviewSnapshot> result;
        try { result = await client.GetOperationsOverviewAsync(token); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }

        lock (_gate)
        {
            // A canceled request can still finish after leaving the page or changing sessions.
            if (_operation != operation) return;
            _operation = null;
            _summary = result is { Outcome: DeviceReadOutcome.Success, Value: { } value } ? new(value) : null;
            _outcome = result.Outcome == DeviceReadOutcome.Success && _summary is null ? DeviceReadOutcome.InvalidResponse : result.Outcome;
            if (_outcome == DeviceReadOutcome.Unauthenticated) SessionExpired?.Invoke(this, EventArgs.Empty);
            Notify();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            Reset();
            Notify();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            Reset();
        }
    }

    private void Reset()
    {
        var operation = _operation;
        _operation = null;
        _summary = null;
        _outcome = null;
        operation?.Cancel();
    }

    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
}
