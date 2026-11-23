using System.ComponentModel;
using SentinelAI.Contracts.Monitoring;
using static SentinelAI.Localization.Localizer;
using static SentinelAI.Desktop.Foundation.MonitoringCoveragePresentation;

namespace SentinelAI.Desktop.Foundation;

public sealed class MonitoringCoverageViewModel(IMonitoringCoverageClient client) : INotifyPropertyChanged, IDisposable
{
    public const int EndpointPageSize = 25;
    public const int GapPageSize = 15;
    private readonly object _gate = new();
    private readonly ReadState<EndpointPage> _endpoints = new();
    private readonly ReadState<MonitoringDetailView> _detail = new();
    private readonly ReadState<GapPage> _gaps = new();
    private bool _issuesOnly;
    private bool _disposed;
    private MonitoringEndpointRow? _selected;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public bool IssuesOnly
    {
        get { lock (_gate) return _issuesOnly; }
        set => _ = SetIssuesOnlyAsync(value);
    }
    public IReadOnlyList<MonitoringEndpointRow> Rows { get { lock (_gate) return _endpoints.Value?.Rows ?? []; } }
    public MonitoringEndpointRow? SelectedEndpoint { get { lock (_gate) return _selected; } }
    public bool HasSelection { get { lock (_gate) return _selected is not null; } }
    public MonitoringDetailView? SourceDetail { get { lock (_gate) return _detail.Value; } }
    public IReadOnlyList<MonitoringGapRow> GapRows { get { lock (_gate) return _gaps.Value?.Rows ?? []; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _endpoints.Operation is null; } }
    public bool CanPreviousPage { get { lock (_gate) return _endpoints.Value is { Page.Offset: > 0 }; } }
    public bool CanNextPage { get { lock (_gate) return _endpoints.Value is { } value && CanAdvance(value.Page.Offset, EndpointPageSize, value.Page.Matching); } }
    public bool CanRefreshDetail { get { lock (_gate) return _selected is not null && _detail.Operation is null; } }
    public bool CanRefreshGaps { get { lock (_gate) return _selected is not null && _gaps.Operation is null; } }
    public bool CanPreviousGapPage { get { lock (_gate) return _gaps.Value is { Page.Offset: > 0 }; } }
    public bool CanNextGapPage { get { lock (_gate) return _gaps.Value is { } value && CanAdvance(value.Page.Offset, GapPageSize, value.Page.Total); } }

    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (_endpoints.Operation is not null) return T("Reading monitoring coverage…");
                if (_endpoints.Value is { } value)
                {
                    if (value.Page.Total == 0) return T("No active computers are enrolled.");
                    if (value.Page.Matching == 0) return T("No computers match the issue filter.");
                    if (value.Rows.Count == 0) return T("This page is empty. Use Previous or Refresh.");
                    return string.Empty;
                }
                return Failure(_endpoints.Outcome);
            }
        }
    }

    public string PageText
    {
        get
        {
            lock (_gate) return _endpoints.Value is not { } value ? string.Empty :
                F("Computers {0} · {1} matching · {2} active", Range(value.Page.Offset, value.Rows.Count), value.Page.Matching, value.Page.Total);
        }
    }

    public string FreshnessText
    {
        get
        {
            lock (_gate) return _endpoints.Value is not { } value ? string.Empty :
                F("Inventory is current within {0} h, endpoint telemetry within {1} h and event source reports within {2} h.",
                    value.Page.InventoryFreshHours, MonitoringCoverageContract.TelemetryFreshHours, MonitoringCoverageContract.EventFreshHours);
        }
    }

    public string DetailStatusText
    {
        get
        {
            lock (_gate) return _selected is null ? T("Select a computer to see its sources and continuity notices.") :
                _detail.Operation is not null ? T("Reading sources…") : Failure(_detail.Outcome);
        }
    }

    public string GapStatusText
    {
        get
        {
            lock (_gate)
            {
                if (_gaps.Operation is not null) return T("Reading continuity notices…");
                if (_gaps.Value is not { } value) return Failure(_gaps.Outcome);
                if (value.Page.Total == 0) return T("No retained continuity notices for this computer.");
                return value.Rows.Count == 0 ? T("This page is empty. Use Previous or Refresh.") : string.Empty;
            }
        }
    }

    public string GapPageText
    {
        get
        {
            lock (_gate) return _gaps.Value is not { } value ? string.Empty :
                F("Notices {0} of {1} · retained by receipt time for up to {2} days", Range(value.Page.Offset, value.Rows.Count), value.Page.Total, value.Page.RetentionDays);
        }
    }

    public Task RefreshAsync() { lock (_gate) return CanRefresh ? LoadEndpointsAsync(0) : Task.CompletedTask; }

    public Task SetIssuesOnlyAsync(bool issuesOnly)
    {
        lock (_gate)
        {
            if (_disposed || _issuesOnly == issuesOnly) return Task.CompletedTask;
            _issuesOnly = issuesOnly;
            return LoadEndpointsAsync(0);
        }
    }

    public Task PreviousPageAsync() { lock (_gate) return CanPreviousPage ? LoadEndpointsAsync(_endpoints.Value!.Page.Offset - EndpointPageSize) : Task.CompletedTask; }
    public Task NextPageAsync() { lock (_gate) return CanNextPage ? LoadEndpointsAsync(_endpoints.Value!.Page.Offset + EndpointPageSize) : Task.CompletedTask; }

    public Task SelectEndpointAsync(MonitoringEndpointRow? row)
    {
        lock (_gate)
        {
            if (_disposed || ReferenceEquals(_selected, row) || row is not null && !Rows.Any(item => ReferenceEquals(item, row)))
                return Task.CompletedTask;
            ResetSelection();
            _selected = row;
            if (row is not null) return Task.WhenAll(LoadDetailAsync(row), LoadGapsAsync(row, 0));
            Notify();
            return Task.CompletedTask;
        }
    }

    public Task RefreshDetailAsync() { lock (_gate) return CanRefreshDetail ? LoadDetailAsync(_selected!) : Task.CompletedTask; }
    public Task RefreshGapsAsync() { lock (_gate) return CanRefreshGaps ? LoadGapsAsync(_selected!, 0) : Task.CompletedTask; }
    public Task PreviousGapPageAsync() { lock (_gate) return CanPreviousGapPage ? LoadGapsAsync(_selected!, _gaps.Value!.Page.Offset - GapPageSize) : Task.CompletedTask; }
    public Task NextGapPageAsync() { lock (_gate) return CanNextGapPage ? LoadGapsAsync(_selected!, _gaps.Value!.Page.Offset + GapPageSize) : Task.CompletedTask; }

    private Task LoadEndpointsAsync(int offset)
    {
        ResetSelection();
        var filter = _issuesOnly;
        return ReadAsync(_endpoints, token => client.GetMonitoringEndpointsAsync(offset, EndpointPageSize, filter, token),
            value => value.Offset == offset && value.Limit == EndpointPageSize
                ? new EndpointPage(value, value.Items.Select(item => Endpoint(item, value.GeneratedUtc)).ToArray()) : null);
    }

    private Task LoadDetailAsync(MonitoringEndpointRow row) => ReadAsync(_detail,
        token => client.GetMonitoringEndpointAsync(row.EndpointId, token), value => value.Endpoint.EndpointId == row.EndpointId ? Detail(value) : null);

    private Task LoadGapsAsync(MonitoringEndpointRow row, int offset) => !ReferenceEquals(_selected, row) ? Task.CompletedTask : ReadAsync(_gaps,
        token => client.GetMonitoringGapsAsync(row.EndpointId, offset, GapPageSize, token),
        value => value.EndpointId == row.EndpointId && value.Offset == offset && value.Limit == GapPageSize
            ? new GapPage(value, value.Items.Select(item => Gap(item, value.GeneratedUtc)).ToArray()) : null);

    // Start under the gate. The identity check also covers callers that answer after cancellation.
    private async Task ReadAsync<T, TView>(ReadState<TView> state, Func<CancellationToken, Task<DeviceReadResult<T>>> read,
        Func<T, TView?> present) where T : class where TView : class
    {
        state.Reset();
        using var operation = new CancellationTokenSource();
        state.Operation = operation;
        Notify();
        DeviceReadResult<T> result;
        try { result = await read(operation.Token); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }

        lock (_gate)
        {
            if (state.Operation != operation) return;
            state.Operation = null;
            if (result.Outcome is DeviceReadOutcome.Unauthenticated or DeviceReadOutcome.UntrustedConnection)
            {
                Reset();
                _endpoints.Outcome = result.Outcome;
                if (result.Outcome == DeviceReadOutcome.Unauthenticated) SessionExpired?.Invoke(this, EventArgs.Empty);
            }
            else
            {
                state.Value = result is { Outcome: DeviceReadOutcome.Success, Value: { } value } ? present(value) : null;
                state.Outcome = result.Outcome == DeviceReadOutcome.Success && state.Value is null ? DeviceReadOutcome.InvalidResponse : result.Outcome;
            }
            Notify();
        }
    }

    public void Clear() { lock (_gate) { if (_disposed) return; Reset(); Notify(); } }
    public void Dispose() { lock (_gate) { if (_disposed) return; _disposed = true; Reset(); } }

    private void Reset()
    {
        _issuesOnly = false;
        _endpoints.Reset();
        ResetSelection();
    }

    private void ResetSelection()
    {
        _selected = null;
        _detail.Reset();
        _gaps.Reset();
    }

    private void Notify() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    private static bool CanAdvance(int offset, int pageSize, int total) => offset + pageSize < total && offset + pageSize <= MonitoringCoverageContract.MaximumOffset;
    private static string Range(int offset, int count) => count == 0 ? "0" : F("{0}–{1}", (long)offset + 1, (long)offset + count);
    private static string Failure(DeviceReadOutcome? outcome) => outcome switch
    {
        null or DeviceReadOutcome.Success or DeviceReadOutcome.Unauthenticated => string.Empty,
        DeviceReadOutcome.NotFound => T("This computer is no longer enrolled."),
        DeviceReadOutcome.UntrustedConnection => T("The local Core connection could not be trusted."),
        _ => T("Monitoring coverage is unavailable. Refresh to try again.")
    };

    private sealed record EndpointPage(MonitoringEndpointPage Page, IReadOnlyList<MonitoringEndpointRow> Rows);
    private sealed record GapPage(MonitoringGapPage Page, IReadOnlyList<MonitoringGapRow> Rows);

    private sealed class ReadState<T> where T : class
    {
        public CancellationTokenSource? Operation { get; set; }
        public DeviceReadOutcome? Outcome { get; set; }
        public T? Value { get; set; }

        public void Reset()
        {
            var operation = Operation;
            Operation = null;
            Value = null;
            Outcome = null;
            operation?.Cancel();
        }
    }
}
