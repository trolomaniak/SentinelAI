using System.ComponentModel;

namespace SentinelAI.Desktop.Foundation;

public enum AlertListState { NotLoaded, Loading, Ready, Empty, Unavailable }
public enum AlertDetailState { None, Loading, Ready, NotFound, Unavailable }
public enum AlertSeverityFilter { All, Info, Low, Medium, High, Critical }
public enum AlertStatusFilter { All, Open, Investigating, Accepted, Resolved }

/// <summary>
/// Native tracked-alert workspace. Core filters before 50-row paging and owns every
/// version/lifecycle change. The authentication owner clears this VM on sign-out and
/// owns both shared clients. UI callers retain their synchronization context across awaits.
/// </summary>
public sealed class AlertsViewModel : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 50;
    private static readonly AlertEndpointOption AllEndpoints = new(null, "All endpoints");
    private readonly object _gate = new();
    private readonly IAlertsClient _client;
    private readonly IDevicesClient _devices;
    private IReadOnlyList<AlertRow> _visibleAlerts = Array.Empty<AlertRow>();
    private IReadOnlyList<AlertEndpointOption> _endpointOptions = Array.AsReadOnly(new[] { AllEndpoints });
    private AlertEndpointOption _selectedEndpoint = AllEndpoints;
    private AlertRow? _selectedAlert;
    private AlertPresentation? _detail;
    private AlertSeverityFilter _severityFilter;
    private AlertStatusFilter _statusFilter;
    private AlertListState _listState;
    private AlertDetailState _detailState;
    private AlertQuery _appliedQuery = new();
    private long _totalAlerts;
    private string _listStatusText = "Open Alerts to load tracked alerts.";
    private string _detailStatusText = string.Empty;
    private string _errorText = string.Empty;
    private string _statusMessage = string.Empty;
    private string? _proposedStatus;
    private bool _needsDetailRefresh;
    private bool _optionsLoaded;
    private bool _disposed;
    private long _listGeneration;
    private long _detailGeneration;
    private Guid _detailAlertId;
    private Pending? _listPending;
    private Pending? _detailPending;
    private Pending? _writePending;

    public AlertsViewModel(IAlertsClient client, IDevicesClient devicesClient)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(devicesClient);
        _client = client;
        _devices = devicesClient;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public IReadOnlyList<AlertRow> VisibleAlerts { get { lock (_gate) return _visibleAlerts; } }
    public IReadOnlyList<AlertEndpointOption> EndpointOptions { get { lock (_gate) return _endpointOptions; } }
    public AlertPresentation? Detail { get { lock (_gate) return _detail; } }
    public AlertListState ListState { get { lock (_gate) return _listState; } }
    public AlertDetailState DetailState { get { lock (_gate) return _detailState; } }
    public bool IsLoading { get { lock (_gate) return _listState == AlertListState.Loading; } }
    public bool IsLoadingDetail { get { lock (_gate) return _detailState == AlertDetailState.Loading; } }
    public bool IsSavingStatus { get { lock (_gate) return _writePending is not null; } }
    public bool IsShowingDetail { get { lock (_gate) return _detailState != AlertDetailState.None; } }
    public bool NeedsDetailRefresh { get { lock (_gate) return _needsDetailRefresh; } }
    public string ListStatusText { get { lock (_gate) return _listStatusText; } }
    public string DetailStatusText { get { lock (_gate) return _detailStatusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public string StatusMessage { get { lock (_gate) return _statusMessage; } }
    public long TotalAlerts { get { lock (_gate) return _totalAlerts; } }
    public int PageIndex { get { lock (_gate) return _appliedQuery.Offset / PageSize; } }
    public long TotalPages { get { lock (_gate) return _totalAlerts / PageSize + (_totalAlerts % PageSize == 0 ? 0 : 1); } }
    public int PageNumber { get { lock (_gate) return _totalAlerts == 0 ? 0 : PageIndex + 1; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _listPending is null && _writePending is null; } }
    public bool CanApplyFilters => CanRefresh;
    public bool FiltersChanged { get { lock (_gate) return !SameFilters(CurrentQuery(0), _appliedQuery); } }
    public bool CanPreviousPage { get { lock (_gate) return CanRefresh && !FiltersChanged && _appliedQuery.Offset >= PageSize; } }
    public bool CanNextPage
    {
        get { lock (_gate) return CanRefresh && !FiltersChanged && _appliedQuery.Offset <= int.MaxValue - PageSize && (long)_appliedQuery.Offset + PageSize < _totalAlerts; }
    }
    public bool CanSaveStatus
    {
        get
        {
            lock (_gate) return CanWrite && IsStatus(_proposedStatus) && _proposedStatus != _detail!.Row.Status;
        }
    }

    public AlertRow? SelectedAlert
    {
        get { lock (_gate) return _selectedAlert; }
        set
        {
            lock (_gate)
            {
                if (_disposed || ReferenceEquals(value, _selectedAlert)) return;
                if (value is not null && !_visibleAlerts.Any(row => ReferenceEquals(row, value)))
                    throw new ArgumentException("Select an alert from the current page.", nameof(value));
                _selectedAlert = value;
                Notify(nameof(SelectedAlert));
            }
        }
    }
    public AlertEndpointOption SelectedEndpoint
    {
        get { lock (_gate) return _selectedEndpoint; }
        set
        {
            lock (_gate)
            {
                if (_disposed) return;
                value ??= AllEndpoints;
                if (!_endpointOptions.Any(option => ReferenceEquals(option, value)))
                    throw new ArgumentException("Select an endpoint from the available filters.", nameof(value));
                if (ReferenceEquals(_selectedEndpoint, value)) return;
                _selectedEndpoint = value;
                NotifyFilters();
            }
        }
    }
    public AlertSeverityFilter SeverityFilter
    {
        get { lock (_gate) return _severityFilter; }
        set
        {
            if (!Enum.IsDefined(value)) throw new ArgumentOutOfRangeException(nameof(value));
            lock (_gate)
            {
                if (_disposed || value == _severityFilter) return;
                _severityFilter = value;
                NotifyFilters();
            }
        }
    }
    public AlertStatusFilter StatusFilter
    {
        get { lock (_gate) return _statusFilter; }
        set
        {
            if (!Enum.IsDefined(value)) throw new ArgumentOutOfRangeException(nameof(value));
            lock (_gate)
            {
                if (_disposed || value == _statusFilter) return;
                _statusFilter = value;
                NotifyFilters();
            }
        }
    }
    public string? ProposedStatus
    {
        get { lock (_gate) return _proposedStatus; }
        set
        {
            lock (_gate)
            {
                if (_disposed) return;
                if (value is not null && !IsStatus(value)) throw new ArgumentException("Choose an existing alert status.", nameof(value));
                if (_proposedStatus == value) return;
                _proposedStatus = value;
                Notify(nameof(ProposedStatus), nameof(CanSaveStatus));
            }
        }
    }

    public Task RefreshAsync() => BeginListLoad(offset: 0, refreshOptions: true);
    public Task ApplyFiltersAsync() => BeginListLoad(offset: 0, refreshOptions: false);
    public Task NextPageAsync()
    {
        lock (_gate) return CanNextPage ? BeginListLoad(_appliedQuery.Offset + PageSize, false) : Task.CompletedTask;
    }
    public Task PreviousPageAsync()
    {
        lock (_gate) return CanPreviousPage ? BeginListLoad(_appliedQuery.Offset - PageSize, false) : Task.CompletedTask;
    }

    private Task BeginListLoad(int offset, bool refreshOptions)
    {
        lock (_gate)
        {
            if (_disposed || _writePending is not null) return Task.CompletedTask;
            if (_listPending is not null) return _listPending.Task;
            CloseDetailLocked();
            var pending = new Pending(++_listGeneration);
            _listPending = pending;
            var query = CurrentQuery(offset);
            _visibleAlerts = Array.Empty<AlertRow>();
            _selectedAlert = null;
            _listState = AlertListState.Loading;
            _listStatusText = "Loading tracked alerts…";
            _errorText = string.Empty;
            NotifyAll();
            _ = LoadListAsync(pending, query, refreshOptions || !_optionsLoaded);
            return pending.Task;
        }
    }

    private async Task LoadListAsync(Pending pending, AlertQuery query, bool refreshOptions)
    {
        try
        {
            if (refreshOptions)
            {
                var options = await _devices.GetDevicesAsync(pending.Token);
                lock (_gate)
                {
                    if (!ListCurrent(pending)) return;
                    if (options.Outcome == DeviceReadOutcome.Unauthenticated) { ExpireLocked(); return; }
                    if (options.Outcome != DeviceReadOutcome.Success || options.Value is null)
                    {
                        SetListFailure("Endpoint filters are unavailable. Restore Core, then refresh Alerts.");
                        NotifyAll();
                        return;
                    }
                    var previousId = query.EndpointId;
                    var oldOptions = _endpointOptions;
                    _endpointOptions = Array.AsReadOnly(new[] { AllEndpoints }.Concat(options.Value
                        .OrderBy(device => device.Name, StringComparer.OrdinalIgnoreCase).ThenBy(device => device.EndpointId)
                        .Select(device => oldOptions.FirstOrDefault(option => option.EndpointId == device.EndpointId && option.Name == device.Name)
                            ?? new AlertEndpointOption(device.EndpointId, DeviceRow.Known(device.Name)))).ToArray());
                    _selectedEndpoint = _endpointOptions.FirstOrDefault(option => option.EndpointId == previousId) ?? AllEndpoints;
                    query = query with { EndpointId = _selectedEndpoint.EndpointId };
                    _optionsLoaded = true;
                }
            }
            var (result, effectiveQuery) = await ReadPageAsync(query, pending, write: false);
            query = effectiveQuery;
            lock (_gate)
            {
                if (!ListCurrent(pending)) return;
                if (result.Outcome == AlertOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome == AlertOutcome.Success && ValidPage(result.Value, query))
                    SetPageLocked(result.Value!, query);
                else SetListFailure(FailureText(result.Outcome));
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (ListCurrent(pending)) { SetListFailure(FailureText(AlertOutcome.Unavailable)); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_listPending, pending)) _listPending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanRefresh), nameof(CanApplyFilters), nameof(CanNextPage), nameof(CanPreviousPage));
            }
        }
    }

    public Task OpenDetailAsync(Guid alertId)
    {
        lock (_gate)
        {
            if (_disposed || _writePending is not null) return Task.CompletedTask;
            if (!_visibleAlerts.Any(row => row.AlertId == alertId))
            {
                CloseDetailLocked();
                _detailState = AlertDetailState.NotFound;
                _detailStatusText = "This alert is no longer available. Refresh Alerts.";
                NotifyAll();
                return Task.CompletedTask;
            }
            _selectedAlert = _visibleAlerts.First(row => row.AlertId == alertId);
            return BeginDetailLoad(alertId, refresh: false);
        }
    }
    public Task RefreshDetailAsync()
    {
        lock (_gate) return !_disposed && _writePending is null && _detailAlertId != Guid.Empty
            ? BeginDetailLoad(_detailAlertId, refresh: true) : Task.CompletedTask;
    }
    private Task BeginDetailLoad(Guid alertId, bool refresh)
    {
        if (_detailPending is not null && _detailAlertId == alertId) return _detailPending.Task;
        _detailPending?.Cancel();
        _detailAlertId = alertId;
        var pending = new Pending(++_detailGeneration);
        _detailPending = pending;
        _detail = null;
        _detailState = AlertDetailState.Loading;
        _detailStatusText = "Loading alert details…";
        _proposedStatus = null;
        _statusMessage = string.Empty;
        _errorText = string.Empty;
        NotifyAll();
        _ = LoadDetailAsync(pending, alertId, refresh);
        return pending.Task;
    }
    private async Task LoadDetailAsync(Pending pending, Guid alertId, bool refresh)
    {
        try
        {
            var result = await _client.GetAlertDetailAsync(alertId, pending.Token);
            lock (_gate)
            {
                if (!DetailCurrent(pending)) return;
                if (result.Outcome == AlertOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome == AlertOutcome.Success && ValidDetail(result.Value, alertId))
                {
                    SetDetailLocked(result.Value!);
                    if (refresh) _statusMessage = "Latest alert detail loaded. Choose a status to change.";
                    ReconcileRowLocked(result.Value!.Alert);
                }
                else SetDetailFailure(result.Outcome);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate) if (DetailCurrent(pending)) { SetDetailFailure(AlertOutcome.Unavailable); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_detailPending, pending)) _detailPending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanSaveStatus));
            }
        }
    }

    public Task SaveStatusAsync(string status)
    {
        lock (_gate)
        {
            if (!CanWrite || !IsStatus(status) || status == _detail!.Row.Status) return Task.CompletedTask;
            var pending = new Pending(_detailGeneration);
            _writePending = pending;
            var alertId = _detail.Row.AlertId;
            var version = _detail.Version;
            _proposedStatus = null;
            _statusMessage = "Saving reviewed status…";
            _errorText = string.Empty;
            NotifyAll();
            _ = SaveAsync(pending, alertId, status, version);
            return pending.Task;
        }
    }

    private async Task SaveAsync(Pending pending, Guid alertId, string status, long version)
    {
        try
        {
            AlertResult<AlertDetail> result;
            try { result = await _client.UpdateAlertStatusAsync(alertId, status, version, pending.Token); }
            catch (Exception) { result = new(AlertOutcome.Indeterminate); }
            lock (_gate)
            {
                if (!WriteCurrent(pending)) return;
                if (result.Outcome == AlertOutcome.Unauthenticated) { ExpireLocked(); return; }
            }
            var conflict = result.Outcome == AlertOutcome.Conflict;
            if (conflict)
            {
                // One fresh read is allowed; the operator's old write is never replayed.
                try { result = await _client.GetAlertDetailAsync(alertId, pending.Token); }
                catch (Exception) { result = new(AlertOutcome.Unavailable); }
            }
            AlertQuery query;
            lock (_gate)
            {
                if (!WriteCurrent(pending)) return;
                if (result.Outcome == AlertOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome != AlertOutcome.Success || !ValidDetail(result.Value, alertId) ||
                    !conflict && (result.Value!.Alert.Version <= version || result.Value.Alert.Status != status))
                {
                    _proposedStatus = null;
                    _needsDetailRefresh = true;
                    if (result.Outcome == AlertOutcome.NotFound) SetDetailFailure(AlertOutcome.NotFound);
                    _statusMessage = conflict
                        ? "Status was not saved. Latest detail is unavailable; refresh it before choosing again."
                        : "Status change could not be confirmed. Refresh latest detail before choosing a status again.";
                    NotifyAll();
                    return;
                }
                SetDetailLocked(result.Value!);
                ReconcileRowLocked(result.Value!.Alert);
                _statusMessage = conflict
                    ? "Status was not saved because the alert changed. Review the latest detail and choose again."
                    : "Status saved.";
                query = _appliedQuery;
                NotifyAll();
            }

            // Re-read the current server page so status filters, counts and page boundaries
            // remain correct after a row leaves the filter. Endpoint options are retained.
            AlertResult<AlertPage> page;
            try { (page, query) = await ReadPageAsync(query, pending, write: true); }
            catch (Exception) { page = new(AlertOutcome.Unavailable); }
            lock (_gate)
            {
                if (!WriteCurrent(pending)) return;
                if (page.Outcome == AlertOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (page.Outcome == AlertOutcome.Success && ValidPage(page.Value, query)) SetPageLocked(page.Value!, query);
                else SetListFailure("The alert list could not refresh. The reviewed detail remains available; refresh Alerts before paging.");
                NotifyAll();
            }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_writePending, pending)) _writePending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(IsSavingStatus), nameof(CanSaveStatus), nameof(CanRefresh),
                    nameof(CanApplyFilters), nameof(CanNextPage), nameof(CanPreviousPage));
            }
        }
    }

    private async Task<(AlertResult<AlertPage> Result, AlertQuery Query)> ReadPageAsync(
        AlertQuery query, Pending pending, bool write)
    {
        var result = await _client.GetAlertsAsync(query, pending.Token);
        if (result.Outcome == AlertOutcome.Success && ValidPage(result.Value, query) &&
            result.Value!.Alerts.Count == 0 && query.Offset > 0 && query.Offset >= result.Value.Total)
        {
            lock (_gate)
                if (!(write ? WriteCurrent(pending) : ListCurrent(pending))) return (result, query);
            // A concurrent lifecycle change can empty the last filtered page. Correct its
            // offset with one bounded read; never replay a status write or chase changes.
            var lastOffset = result.Value.Total == 0 ? 0 : (int)((result.Value.Total - 1) / PageSize * PageSize);
            query = query with { Offset = lastOffset };
            result = await _client.GetAlertsAsync(query, pending.Token);
        }
        return (result, query);
    }

    private bool CanWrite => !_disposed && _detailState == AlertDetailState.Ready && _detail is not null &&
        !_needsDetailRefresh && _listPending is null && _detailPending is null && _writePending is null;
    private bool ListCurrent(Pending pending) => !_disposed && pending.Generation == _listGeneration && !pending.Token.IsCancellationRequested;
    private bool DetailCurrent(Pending pending) => !_disposed && pending.Generation == _detailGeneration && !pending.Token.IsCancellationRequested;
    private bool WriteCurrent(Pending pending) => DetailCurrent(pending) && ReferenceEquals(_writePending, pending);
    private AlertQuery CurrentQuery(int offset) => new(_selectedEndpoint.EndpointId,
        _severityFilter == AlertSeverityFilter.All ? null : _severityFilter.ToString().ToLowerInvariant(),
        _statusFilter == AlertStatusFilter.All ? null : _statusFilter.ToString().ToLowerInvariant(), offset, PageSize);
    private static bool SameFilters(AlertQuery first, AlertQuery second) => first.EndpointId == second.EndpointId && first.Severity == second.Severity && first.Status == second.Status;
    private static bool IsStatus(string? value) => value is "open" or "investigating" or "accepted" or "resolved";
    private static bool ValidDetail(AlertDetail? detail, Guid id) => detail is not null && detail.Alert.AlertId == id && detail.Alert.Version > 0 && IsStatus(detail.Alert.Status);
    private static bool ValidPage(AlertPage? page, AlertQuery query) => page is not null && page.Offset == query.Offset &&
        page.Limit == PageSize && page.Total >= 0 && page.Alerts.Count <= PageSize && page.Alerts.Count <= page.Total &&
        page.Alerts.All(alert => alert.AlertId != Guid.Empty && alert.EndpointId != Guid.Empty && alert.Version > 0 && IsStatus(alert.Status)) &&
        page.Alerts.Select(alert => alert.AlertId).Distinct().Count() == page.Alerts.Count;

    private void SetPageLocked(AlertPage page, AlertQuery query)
    {
        var selectedId = _selectedAlert?.AlertId;
        _visibleAlerts = Array.AsReadOnly(page.Alerts.Select(alert => new AlertRow(alert)).ToArray());
        _selectedAlert = _visibleAlerts.FirstOrDefault(row => row.AlertId == selectedId);
        _appliedQuery = query;
        _totalAlerts = page.Total;
        _listState = page.Alerts.Count == 0 ? AlertListState.Empty : AlertListState.Ready;
        _listStatusText = page.Alerts.Count == 0 ? "No tracked alerts match this page and its filters."
            : $"{page.Total} tracked alerts · page {PageNumber} of {TotalPages}";
        _errorText = string.Empty;
    }
    private void SetDetailLocked(AlertDetail detail)
    {
        _detail = new AlertPresentation(detail);
        _detailState = AlertDetailState.Ready;
        _detailStatusText = _detail.HistoryDisclosure;
        _needsDetailRefresh = false;
        _proposedStatus = null;
        _errorText = string.Empty;
    }
    private void ReconcileRowLocked(AlertSummary summary)
    {
        // A server read after writes repairs membership/page counts; immediate replacement
        // keeps the current detail version and its visible list row consistent meanwhile.
        _visibleAlerts = Array.AsReadOnly(_visibleAlerts.Select(row => row.AlertId == summary.AlertId ? new AlertRow(summary) : row).ToArray());
        if (_selectedAlert?.AlertId == summary.AlertId) _selectedAlert = _visibleAlerts.FirstOrDefault(row => row.AlertId == summary.AlertId);
    }
    private void SetListFailure(string message)
    {
        _visibleAlerts = Array.Empty<AlertRow>();
        _selectedAlert = null;
        _totalAlerts = 0;
        _listState = AlertListState.Unavailable;
        _listStatusText = message;
        _errorText = message;
    }
    private void SetDetailFailure(AlertOutcome outcome)
    {
        _detail = null;
        _detailState = outcome == AlertOutcome.NotFound ? AlertDetailState.NotFound : AlertDetailState.Unavailable;
        _detailStatusText = outcome == AlertOutcome.NotFound ? "This alert is no longer available. Refresh Alerts." : FailureText(outcome);
        _errorText = _detailStatusText;
        _proposedStatus = null;
    }
    private static string FailureText(AlertOutcome outcome) => outcome switch
    {
        AlertOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
        AlertOutcome.InvalidResponse or AlertOutcome.Success => "Core returned an invalid alert response.",
        AlertOutcome.TooLarge => "The alert response exceeds the supported size.",
        _ => "Local Core is unavailable. Restore Core, then refresh Alerts."
    };
    private void ExpireLocked()
    {
        ClearLocked();
        NotifyAll();
        SessionExpired?.Invoke(this, EventArgs.Empty);
    }
    public void CloseDetail()
    {
        lock (_gate)
        {
            if (_disposed || _writePending is not null) return;
            CloseDetailLocked();
            _errorText = string.Empty;
            NotifyAll();
        }
    }
    private void CloseDetailLocked()
    {
        _detailGeneration++;
        _detailPending?.Cancel();
        _writePending?.Cancel();
        _detailPending = null;
        _writePending = null;
        _detailAlertId = Guid.Empty;
        _detail = null;
        _detailState = AlertDetailState.None;
        _detailStatusText = string.Empty;
        _statusMessage = string.Empty;
        _proposedStatus = null;
        _needsDetailRefresh = false;
    }
    private void ClearLocked()
    {
        _listGeneration++;
        _listPending?.Cancel();
        _listPending = null;
        CloseDetailLocked();
        _visibleAlerts = Array.Empty<AlertRow>();
        _endpointOptions = Array.AsReadOnly(new[] { AllEndpoints });
        _selectedEndpoint = AllEndpoints;
        _selectedAlert = null;
        _optionsLoaded = false;
        _severityFilter = AlertSeverityFilter.All;
        _statusFilter = AlertStatusFilter.All;
        _appliedQuery = new();
        _totalAlerts = 0;
        _listState = AlertListState.NotLoaded;
        _listStatusText = "Open Alerts to load tracked alerts.";
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
    private void NotifyFilters() => Notify(nameof(SelectedEndpoint), nameof(SeverityFilter), nameof(StatusFilter),
        nameof(FiltersChanged), nameof(CanNextPage), nameof(CanPreviousPage), nameof(CanApplyFilters));
    private void NotifyAll() => Notify(nameof(VisibleAlerts), nameof(SelectedAlert), nameof(EndpointOptions),
        nameof(SelectedEndpoint), nameof(SeverityFilter), nameof(StatusFilter), nameof(FiltersChanged), nameof(Detail),
        nameof(ListState), nameof(DetailState), nameof(ListStatusText), nameof(DetailStatusText), nameof(ErrorText),
        nameof(StatusMessage), nameof(IsLoading), nameof(IsLoadingDetail), nameof(IsSavingStatus), nameof(IsShowingDetail),
        nameof(CanRefresh), nameof(CanApplyFilters), nameof(CanNextPage), nameof(CanPreviousPage), nameof(TotalAlerts),
        nameof(TotalPages), nameof(PageIndex), nameof(PageNumber), nameof(ProposedStatus), nameof(CanSaveStatus), nameof(NeedsDetailRefresh));
    private void Notify(params string[] properties)
    {
        foreach (var property in properties) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
    }

    private sealed class Pending(long generation)
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal CancellationToken Token => _cancellation.Token;
        internal Task Task => _completion.Task;
        internal void Cancel() => _cancellation.Cancel();
        internal void Complete()
        {
            _cancellation.Dispose();
            _completion.TrySetResult();
        }
    }
}
