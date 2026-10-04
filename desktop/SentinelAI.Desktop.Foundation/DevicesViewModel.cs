using System.ComponentModel;

namespace SentinelAI.Desktop.Foundation;

public enum DeviceListState { NotLoaded, Loading, Ready, Empty, FilteredEmpty, Unavailable }
public enum DeviceDetailState { None, Loading, Ready, NotFound, Unavailable }
public enum DeviceHealthFilter { All, Healthy, Warning, Offline, Unknown }
public enum DeviceSortColumn { Name, OperatingSystem, Health, LastSeen, InventoryCollected, AgentVersion }

/// <summary>
/// Read-only fleet presentation: filtering and stable sorting precede bounded 100-row
/// pages. Calls should originate on the UI context; async completions retain that context.
/// The authentication owner calls Clear on sign-out and owns the shared client lifetime.
/// </summary>
public sealed class DevicesViewModel : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 100;
    private readonly object _gate = new();
    private readonly IDevicesClient _client;
    private IReadOnlyList<DeviceRow> _allRows = Array.Empty<DeviceRow>();
    private IReadOnlyList<DeviceRow> _visibleDevices = Array.Empty<DeviceRow>();
    private DeviceRow? _selectedDevice;
    private EndpointPresentation? _detail;
    private DeviceListState _listState;
    private DeviceDetailState _detailState;
    private string _listStatusText = "Open Devices to load enrolled endpoints.";
    private string _detailStatusText = string.Empty;
    private string _errorText = string.Empty;
    private string _searchText = string.Empty;
    private DeviceHealthFilter _healthFilter;
    private DeviceSortColumn _sortBy;
    private bool _sortDescending;
    private int _pageIndex;
    private int _filteredCount;
    private bool _hasLoaded;
    private bool _disposed;
    private long _listGeneration;
    private long _detailGeneration;
    private Task? _listOperation;
    private Task? _detailOperation;
    private CancellationTokenSource? _listCancellation;
    private CancellationTokenSource? _detailCancellation;
    private Guid _detailEndpointId;

    public DevicesViewModel(IDevicesClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public IReadOnlyList<DeviceRow> VisibleDevices { get { lock (_gate) return _visibleDevices; } }
    public EndpointPresentation? Detail { get { lock (_gate) return _detail; } }
    public DeviceListState ListState { get { lock (_gate) return _listState; } }
    public DeviceDetailState DetailState { get { lock (_gate) return _detailState; } }
    public string ListStatusText { get { lock (_gate) return _listStatusText; } }
    public string DetailStatusText { get { lock (_gate) return _detailStatusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public bool IsLoading { get { lock (_gate) return _listState == DeviceListState.Loading; } }
    public bool IsLoadingDetail { get { lock (_gate) return _detailState == DeviceDetailState.Loading; } }
    public bool IsShowingDetail { get { lock (_gate) return _detailState != DeviceDetailState.None; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _listState != DeviceListState.Loading; } }
    public int TotalDevices { get { lock (_gate) return _allRows.Count; } }
    public int FilteredCount { get { lock (_gate) return _filteredCount; } }
    public int TotalPages { get { lock (_gate) return (_filteredCount + PageSize - 1) / PageSize; } }
    public int PageNumber { get { lock (_gate) return TotalPages == 0 ? 0 : _pageIndex + 1; } }
    public bool CanPreviousPage { get { lock (_gate) return _pageIndex > 0; } }
    public bool CanNextPage { get { lock (_gate) return _pageIndex + 1 < TotalPages; } }

    public DeviceRow? SelectedDevice
    {
        get { lock (_gate) return _selectedDevice; }
        set
        {
            lock (_gate)
            {
                if (_disposed || ReferenceEquals(_selectedDevice, value)) return;
                if (value is not null && !_visibleDevices.Any(row => ReferenceEquals(row, value)))
                    throw new ArgumentException("Select an endpoint from the current device page.", nameof(value));
                _selectedDevice = value;
                CloseDetailLocked();
                NotifyAll();
            }
        }
    }

    public string SearchText
    {
        get { lock (_gate) return _searchText; }
        set
        {
            lock (_gate)
            {
                if (_disposed) return;
                value ??= string.Empty;
                if (value.Length > 256) value = value[..256];
                if (_searchText == value) return;
                _searchText = value;
                RebuildVisibleLocked(resetPage: true);
                NotifyAll();
            }
        }
    }

    public DeviceHealthFilter HealthFilter
    {
        get { lock (_gate) return _healthFilter; }
        set
        {
            if (!Enum.IsDefined(value)) throw new ArgumentOutOfRangeException(nameof(value));
            lock (_gate)
            {
                if (_disposed || _healthFilter == value) return;
                _healthFilter = value;
                RebuildVisibleLocked(resetPage: true);
                NotifyAll();
            }
        }
    }

    public DeviceSortColumn SortBy
    {
        get { lock (_gate) return _sortBy; }
        set
        {
            if (!Enum.IsDefined(value)) throw new ArgumentOutOfRangeException(nameof(value));
            lock (_gate)
            {
                if (_disposed || _sortBy == value) return;
                _sortBy = value;
                RebuildVisibleLocked(resetPage: true);
                NotifyAll();
            }
        }
    }

    public bool SortDescending
    {
        get { lock (_gate) return _sortDescending; }
        set
        {
            lock (_gate)
            {
                if (_disposed || _sortDescending == value) return;
                _sortDescending = value;
                RebuildVisibleLocked(resetPage: true);
                NotifyAll();
            }
        }
    }

    public int PageIndex
    {
        get { lock (_gate) return _pageIndex; }
        set
        {
            lock (_gate)
            {
                if (_disposed) return;
                value = Math.Clamp(value, 0, Math.Max(0, TotalPages - 1));
                if (_pageIndex == value) return;
                _pageIndex = value;
                RebuildVisibleLocked(resetPage: false);
                NotifyAll();
            }
        }
    }

    public Task RefreshAsync()
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_listOperation is not null) return _listOperation;
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var cancellation = new CancellationTokenSource();
            _listOperation = completion.Task;
            _listCancellation = cancellation;
            var generation = ++_listGeneration;
            ClearRowsLocked();
            CloseDetailLocked();
            _listState = DeviceListState.Loading;
            _listStatusText = "Loading enrolled endpoints…";
            _errorText = string.Empty;
            NotifyAll();
            _ = LoadListAsync(completion, cancellation, generation);
            return completion.Task;
        }
    }

    public Task OpenDetailAsync(Guid endpointId)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            var row = _allRows.FirstOrDefault(candidate => candidate.EndpointId == endpointId);
            if (row is null)
            {
                CloseDetailLocked();
                _detailState = DeviceDetailState.NotFound;
                _detailStatusText = "This endpoint is no longer available. Refresh the device list.";
                NotifyAll();
                return Task.CompletedTask;
            }
            if (_detailOperation is not null && _detailEndpointId == endpointId) return _detailOperation;
            CloseDetailLocked();
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var cancellation = new CancellationTokenSource();
            _detailOperation = completion.Task;
            _detailCancellation = cancellation;
            _detailEndpointId = endpointId;
            var generation = ++_detailGeneration;
            _selectedDevice = row;
            _detailState = DeviceDetailState.Loading;
            _detailStatusText = "Loading endpoint details…";
            _errorText = string.Empty;
            NotifyAll();
            _ = LoadDetailAsync(completion, cancellation, generation, endpointId);
            return completion.Task;
        }
    }

    private async Task LoadListAsync(TaskCompletionSource completion, CancellationTokenSource cancellation, long generation)
    {
        DeviceReadResult<IReadOnlyList<DeviceSummary>> result;
        try { result = await _client.GetDevicesAsync(cancellation.Token); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }
        try
        {
            lock (_gate)
            {
                if (_disposed || generation != _listGeneration || cancellation.IsCancellationRequested) return;
                if (ReferenceEquals(_listOperation, completion.Task))
                {
                    _listOperation = null;
                    _listCancellation = null;
                }
                if (result.Outcome == DeviceReadOutcome.Unauthenticated)
                {
                    ClearLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == DeviceReadOutcome.Success && result.Value is not null &&
                    result.Value.All(device => device is not null && device.EndpointId != Guid.Empty) &&
                    result.Value.Select(device => device.EndpointId).Distinct().Count() == result.Value.Count)
                {
                    _allRows = Array.AsReadOnly(result.Value.Select(device => new DeviceRow(device)).ToArray());
                    _hasLoaded = true;
                    RebuildVisibleLocked(resetPage: true);
                }
                else
                {
                    _listState = DeviceListState.Unavailable;
                    _listStatusText = FailureText(result.Outcome);
                    _errorText = _listStatusText;
                }
                NotifyAll();
            }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_listOperation, completion.Task))
                {
                    _listOperation = null;
                    _listCancellation = null;
                }
                cancellation.Dispose();
                completion.TrySetResult();
            }
        }
    }

    private async Task LoadDetailAsync(TaskCompletionSource completion, CancellationTokenSource cancellation,
        long generation, Guid endpointId)
    {
        DeviceReadResult<EndpointDetail> result;
        try { result = await _client.GetDeviceDetailAsync(endpointId, cancellation.Token); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }
        try
        {
            lock (_gate)
            {
                if (_disposed || generation != _detailGeneration || cancellation.IsCancellationRequested) return;
                if (ReferenceEquals(_detailOperation, completion.Task))
                {
                    _detailOperation = null;
                    _detailCancellation = null;
                }
                if (result.Outcome == DeviceReadOutcome.Unauthenticated)
                {
                    ClearLocked();
                    NotifyAll();
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    return;
                }
                if (result.Outcome == DeviceReadOutcome.Success && result.Value is not null && result.Value.Device.EndpointId == endpointId)
                {
                    _detail = new EndpointPresentation(result.Value);
                    _detailState = DeviceDetailState.Ready;
                    _detailStatusText = _detail.InventoryStatusText;
                }
                else
                {
                    _detail = null;
                    _detailState = result.Outcome == DeviceReadOutcome.NotFound ? DeviceDetailState.NotFound : DeviceDetailState.Unavailable;
                    _detailStatusText = result.Outcome == DeviceReadOutcome.NotFound
                        ? "This endpoint is no longer available. Refresh the device list."
                        : FailureText(result.Outcome);
                    _errorText = _detailStatusText;
                }
                NotifyAll();
            }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_detailOperation, completion.Task))
                {
                    _detailOperation = null;
                    _detailCancellation = null;
                }
                cancellation.Dispose();
                completion.TrySetResult();
            }
        }
    }

    private void RebuildVisibleLocked(bool resetPage)
    {
        if (!_hasLoaded) return;
        var search = _searchText.Trim();
        var rows = _allRows.Where(row => MatchesHealth(row.Health) &&
            (search.Length == 0 || row.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             row.OperatingSystemText.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             row.AgentVersionText.Contains(search, StringComparison.OrdinalIgnoreCase) ||
             row.EndpointId.ToString("D").Contains(search, StringComparison.OrdinalIgnoreCase))).ToList();
        rows.Sort(CompareRows);
        _filteredCount = rows.Count;
        _pageIndex = resetPage ? 0 : Math.Clamp(_pageIndex, 0, Math.Max(0, TotalPages - 1));
        _visibleDevices = Array.AsReadOnly(rows.Skip(_pageIndex * PageSize).Take(PageSize).ToArray());
        if (_selectedDevice is not null && !_visibleDevices.Any(row => ReferenceEquals(row, _selectedDevice)))
        {
            _selectedDevice = null;
            CloseDetailLocked();
        }
        _listState = _allRows.Count == 0 ? DeviceListState.Empty
            : _filteredCount == 0 ? DeviceListState.FilteredEmpty : DeviceListState.Ready;
        _listStatusText = _listState switch
        {
            DeviceListState.Empty => "No enrolled endpoints. Enroll an Agent to report device inventory.",
            DeviceListState.FilteredEmpty => "No endpoints match the current filters.",
            _ => $"{_filteredCount} of {_allRows.Count} enrolled endpoints"
        };
    }

    private bool MatchesHealth(DeviceHealth health) => _healthFilter switch
    {
        DeviceHealthFilter.Healthy => health == DeviceHealth.Healthy,
        DeviceHealthFilter.Warning => health == DeviceHealth.Warning,
        DeviceHealthFilter.Offline => health == DeviceHealth.Offline,
        DeviceHealthFilter.Unknown => health == DeviceHealth.Unknown,
        _ => true
    };

    private int CompareRows(DeviceRow left, DeviceRow right)
    {
        int result;
        if (_sortBy is DeviceSortColumn.LastSeen or DeviceSortColumn.InventoryCollected)
        {
            var first = _sortBy == DeviceSortColumn.LastSeen ? left.LastSeenUtc : left.InventoryCollectedUtc;
            var second = _sortBy == DeviceSortColumn.LastSeen ? right.LastSeenUtc : right.InventoryCollectedUtc;
            // Missing observations stay last in both directions.
            if ((first is null) != (second is null)) return first is null ? 1 : -1;
            result = Nullable.Compare(first, second);
        }
        else
            result = _sortBy switch
            {
                DeviceSortColumn.OperatingSystem => StringComparer.OrdinalIgnoreCase.Compare(left.OperatingSystemText, right.OperatingSystemText),
                DeviceSortColumn.AgentVersion => StringComparer.OrdinalIgnoreCase.Compare(left.AgentVersionText, right.AgentVersionText),
                DeviceSortColumn.Health => left.Health.CompareTo(right.Health),
                _ => StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name)
            };
        if (_sortDescending) result = -Math.Sign(result);
        return result != 0 ? result : left.EndpointId.CompareTo(right.EndpointId);
    }

    public void CloseDetail()
    {
        lock (_gate)
        {
            if (_disposed) return;
            CloseDetailLocked();
            _errorText = string.Empty;
            NotifyAll();
        }
    }

    private void CloseDetailLocked()
    {
        _detailGeneration++;
        _detailCancellation?.Cancel();
        _detailCancellation = null;
        _detailOperation = null;
        _detailEndpointId = Guid.Empty;
        _detail = null;
        _detailState = DeviceDetailState.None;
        _detailStatusText = string.Empty;
    }

    private void ClearRowsLocked()
    {
        _allRows = Array.Empty<DeviceRow>();
        _visibleDevices = Array.Empty<DeviceRow>();
        _selectedDevice = null;
        _filteredCount = 0;
        _pageIndex = 0;
        _hasLoaded = false;
    }

    private void ClearLocked()
    {
        _listGeneration++;
        _listCancellation?.Cancel();
        _listCancellation = null;
        _listOperation = null;
        ClearRowsLocked();
        CloseDetailLocked();
        _listState = DeviceListState.NotLoaded;
        _listStatusText = "Open Devices to load enrolled endpoints.";
        _errorText = string.Empty;
        _searchText = string.Empty;
        _healthFilter = DeviceHealthFilter.All;
        _sortBy = DeviceSortColumn.Name;
        _sortDescending = false;
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

    private static string FailureText(DeviceReadOutcome outcome) => outcome switch
    {
        DeviceReadOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
        DeviceReadOutcome.InvalidResponse or DeviceReadOutcome.Success => "Core returned an invalid device response.",
        DeviceReadOutcome.TooLarge => "The device response exceeds the supported size.",
        _ => "Local Core is unavailable. Restore Core, then refresh Devices."
    };

    private void NotifyAll()
    {
        foreach (var property in new[]
        {
            nameof(VisibleDevices), nameof(SelectedDevice), nameof(Detail), nameof(ListState), nameof(DetailState),
            nameof(ListStatusText), nameof(DetailStatusText), nameof(ErrorText), nameof(IsLoading), nameof(IsLoadingDetail),
            nameof(IsShowingDetail), nameof(CanRefresh), nameof(TotalDevices), nameof(FilteredCount), nameof(TotalPages),
            nameof(PageNumber), nameof(PageIndex), nameof(CanPreviousPage), nameof(CanNextPage), nameof(SearchText),
            nameof(HealthFilter), nameof(SortBy), nameof(SortDescending)
        }) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
    }
}
