using System.ComponentModel;

namespace SentinelAI.Desktop.Foundation;

public enum RiskListState { NotLoaded, Loading, Ready, Empty, Unavailable }
public enum RiskDetailState { None, Loading, Ready, NotFound, Unavailable }

/// <summary>
/// Read-only, Core-ranked risk workspace with bounded 50-row server pages. Core supplies
/// all calculations and explanation factors. UI calls retain their synchronization context;
/// the authentication owner calls Clear on sign-out and owns the shared client lifetime.
/// </summary>
public sealed class RiskViewModel : INotifyPropertyChanged, IDisposable
{
    public const int PageSize = 50;
    private readonly object _gate = new();
    private readonly IRiskClient _client;
    private IReadOnlyList<EndpointRiskRow> _visibleEndpoints = Array.Empty<EndpointRiskRow>();
    private EndpointRiskRow? _selectedEndpoint;
    private OrganizationRiskPresentation? _organization;
    private EndpointRiskPresentation? _detail;
    private RiskListState _listState;
    private RiskDetailState _detailState;
    private string _listStatusText = "Open Risk to load the current Core evaluation.";
    private string _detailStatusText = string.Empty;
    private string _errorText = string.Empty;
    private int _offset;
    private long _totalEndpoints;
    private long _listGeneration;
    private long _detailGeneration;
    private Guid _detailEndpointId;
    private Pending? _listPending;
    private Pending? _detailPending;
    private bool _disposed;

    public RiskViewModel(IRiskClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public IReadOnlyList<EndpointRiskRow> VisibleEndpoints { get { lock (_gate) return _visibleEndpoints; } }
    public OrganizationRiskPresentation? Organization { get { lock (_gate) return _organization; } }
    public EndpointRiskPresentation? Detail { get { lock (_gate) return _detail; } }
    public RiskListState ListState { get { lock (_gate) return _listState; } }
    public RiskDetailState DetailState { get { lock (_gate) return _detailState; } }
    public string ListStatusText { get { lock (_gate) return _listStatusText; } }
    public string DetailStatusText { get { lock (_gate) return _detailStatusText; } }
    public string ErrorText { get { lock (_gate) return _errorText; } }
    public bool IsLoading { get { lock (_gate) return _listState == RiskListState.Loading; } }
    public bool IsLoadingDetail { get { lock (_gate) return _detailState == RiskDetailState.Loading; } }
    public bool IsShowingDetail { get { lock (_gate) return _detailState != RiskDetailState.None; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _listPending is null; } }
    public bool CanRefreshDetail { get { lock (_gate) return !_disposed && _listPending is null && _detailPending is null && _detailEndpointId != Guid.Empty; } }
    public long TotalEndpoints { get { lock (_gate) return _totalEndpoints; } }
    public int PageIndex { get { lock (_gate) return _offset / PageSize; } }
    public int PageNumber { get { lock (_gate) return _totalEndpoints == 0 ? 0 : PageIndex + 1; } }
    public long TotalPages { get { lock (_gate) return _totalEndpoints / PageSize + (_totalEndpoints % PageSize == 0 ? 0 : 1); } }
    public bool CanPreviousPage { get { lock (_gate) return CanRefresh && _offset >= PageSize; } }
    public bool CanNextPage { get { lock (_gate) return CanRefresh && _offset <= int.MaxValue - PageSize && (long)_offset + PageSize < _totalEndpoints; } }

    public EndpointRiskRow? SelectedEndpoint
    {
        get { lock (_gate) return _selectedEndpoint; }
        set
        {
            lock (_gate)
            {
                if (_disposed || ReferenceEquals(value, _selectedEndpoint)) return;
                if (value is not null && !_visibleEndpoints.Any(endpoint => ReferenceEquals(endpoint, value)))
                    throw new ArgumentException("Select an endpoint from the current risk page.", nameof(value));
                _selectedEndpoint = value;
                Notify(nameof(SelectedEndpoint));
            }
        }
    }

    public Task RefreshAsync() => BeginListLoad(0);
    public Task NextPageAsync()
    {
        lock (_gate) return CanNextPage ? BeginListLoad(_offset + PageSize) : Task.CompletedTask;
    }
    public Task PreviousPageAsync()
    {
        lock (_gate) return CanPreviousPage ? BeginListLoad(_offset - PageSize) : Task.CompletedTask;
    }
    private Task BeginListLoad(int offset)
    {
        lock (_gate)
        {
            if (_disposed) return Task.CompletedTask;
            if (_listPending is not null) return _listPending.Task;
            CloseDetailLocked();
            var pending = new Pending(++_listGeneration);
            _listPending = pending;
            _visibleEndpoints = Array.Empty<EndpointRiskRow>();
            _selectedEndpoint = null;
            _organization = null;
            _listState = RiskListState.Loading;
            _listStatusText = "Loading the current Core risk evaluation…";
            _errorText = string.Empty;
            NotifyAll();
            _ = LoadListAsync(pending, offset);
            return pending.Task;
        }
    }
    private async Task LoadListAsync(Pending pending, int offset)
    {
        try
        {
            var result = await _client.GetRiskPageAsync(offset, PageSize, pending.Token);
            if (result.Outcome == RiskReadOutcome.Success && ValidPage(result.Value, offset) &&
                result.Value!.Endpoints.Count == 0 && offset > 0 && offset >= result.Value.Total)
            {
                lock (_gate) if (!ListCurrent(pending)) return;
                // Fleet membership can change between pages. One bounded corrected read
                // avoids an impossible page label without chasing a changing dataset.
                offset = result.Value.Total == 0 ? 0 : (int)((result.Value.Total - 1) / PageSize * PageSize);
                result = await _client.GetRiskPageAsync(offset, PageSize, pending.Token);
            }
            lock (_gate)
            {
                if (!ListCurrent(pending)) return;
                if (result.Outcome == RiskReadOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome == RiskReadOutcome.Success && ValidPage(result.Value, offset) &&
                    (offset == 0 || offset < result.Value!.Total)) SetPageLocked(result.Value!, offset);
                else SetListFailure(FailureText(result.Outcome));
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate)
                if (ListCurrent(pending)) { SetListFailure(FailureText(RiskReadOutcome.Unavailable)); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_listPending, pending)) _listPending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanRefresh), nameof(CanRefreshDetail), nameof(CanNextPage), nameof(CanPreviousPage));
            }
        }
    }

    public Task OpenEndpointAsync(Guid endpointId)
    {
        lock (_gate)
        {
            if (_disposed || _listPending is not null) return Task.CompletedTask;
            if (!_visibleEndpoints.Any(endpoint => endpoint.EndpointId == endpointId))
            {
                CloseDetailLocked();
                _detailState = RiskDetailState.NotFound;
                _detailStatusText = "This endpoint is no longer on the current page. Refresh Risk.";
                NotifyAll();
                return Task.CompletedTask;
            }
            _selectedEndpoint = _visibleEndpoints.First(endpoint => endpoint.EndpointId == endpointId);
            return BeginDetailLoad(endpointId);
        }
    }
    public Task RefreshDetailAsync()
    {
        lock (_gate)
        {
            if (_disposed || _listPending is not null || _detailEndpointId == Guid.Empty) return Task.CompletedTask;
            return BeginDetailLoad(_detailEndpointId);
        }
    }
    private Task BeginDetailLoad(Guid endpointId)
    {
        if (_detailPending is not null && _detailEndpointId == endpointId) return _detailPending.Task;
        _detailPending?.Cancel();
        _detailEndpointId = endpointId;
        var pending = new Pending(++_detailGeneration);
        _detailPending = pending;
        _detail = null;
        _detailState = RiskDetailState.Loading;
        _detailStatusText = "Loading endpoint risk factors…";
        _errorText = string.Empty;
        NotifyAll();
        _ = LoadDetailAsync(pending, endpointId);
        return pending.Task;
    }
    private async Task LoadDetailAsync(Pending pending, Guid endpointId)
    {
        try
        {
            var result = await _client.GetEndpointRiskDetailAsync(endpointId, pending.Token);
            lock (_gate)
            {
                if (!DetailCurrent(pending)) return;
                if (result.Outcome == RiskReadOutcome.Unauthenticated) { ExpireLocked(); return; }
                if (result.Outcome == RiskReadOutcome.Success && ValidDetail(result.Value, endpointId))
                {
                    _detail = new EndpointRiskPresentation(result.Value!);
                    _detailState = RiskDetailState.Ready;
                    _detailStatusText = _detail.Contributions.Count == 0
                        ? "No scored alert contributions. Review coverage; a zero score is not a security assurance."
                        : $"{_detail.Contributions.Count} scored alert contributions · evaluated {RiskText.Timestamp(result.Value!.Risk.CalculatedUtc)}";
                    _errorText = string.Empty;
                }
                else SetDetailFailure(result.Outcome);
                NotifyAll();
            }
        }
        catch (Exception)
        {
            lock (_gate) if (DetailCurrent(pending)) { SetDetailFailure(RiskReadOutcome.Unavailable); NotifyAll(); }
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_detailPending, pending)) _detailPending = null;
                pending.Complete();
                if (!_disposed) Notify(nameof(CanRefreshDetail));
            }
        }
    }

    private bool ListCurrent(Pending pending) => !_disposed && pending.Generation == _listGeneration && !pending.Token.IsCancellationRequested;
    private bool DetailCurrent(Pending pending) => !_disposed && pending.Generation == _detailGeneration && !pending.Token.IsCancellationRequested;
    private static bool ValidPage(RiskPage? page, int offset) => page is not null && page.Offset == offset &&
        page.Limit == PageSize && page.Total >= 0 && page.Total == page.Organization.EndpointCount &&
        page.Endpoints.Count == Math.Min(PageSize, Math.Max(0, page.Total - offset)) &&
        page.Endpoints.All(endpoint => endpoint.EndpointId != Guid.Empty && endpoint.Score is >= 0 and <= 100 && endpoint.RawScore >= 0) &&
        page.Endpoints.Select(endpoint => endpoint.EndpointId).Distinct().Count() == page.Endpoints.Count;
    private static bool ValidDetail(EndpointRiskDetail? detail, Guid endpointId) => detail is not null &&
        detail.EndpointId == endpointId && detail.Risk.EndpointId == endpointId &&
        detail.Risk.Score is >= 0 and <= 100 && detail.Risk.RawScore >= 0;
    private void SetPageLocked(RiskPage page, int offset)
    {
        _organization = new OrganizationRiskPresentation(page);
        _visibleEndpoints = Array.AsReadOnly(page.Endpoints.Select((endpoint, index) => new EndpointRiskRow(endpoint, (long)offset + index + 1)).ToArray());
        _offset = offset;
        _totalEndpoints = page.Total;
        _listState = page.Total == 0 ? RiskListState.Empty : RiskListState.Ready;
        _listStatusText = page.Total == 0 ? "No enrolled endpoints. A zero organization score is not a security assurance."
            : $"{page.Total} endpoints · page {PageNumber} of {TotalPages} · ranked by Core";
        _errorText = string.Empty;
    }
    private void SetListFailure(string message)
    {
        _visibleEndpoints = Array.Empty<EndpointRiskRow>();
        _selectedEndpoint = null;
        _organization = null;
        _offset = 0;
        _totalEndpoints = 0;
        _listState = RiskListState.Unavailable;
        _listStatusText = message;
        _errorText = message;
    }
    private void SetDetailFailure(RiskReadOutcome outcome)
    {
        _detail = null;
        _detailState = outcome == RiskReadOutcome.NotFound ? RiskDetailState.NotFound : RiskDetailState.Unavailable;
        _detailStatusText = outcome == RiskReadOutcome.NotFound ? "This endpoint is no longer available. Refresh Risk." : FailureText(outcome);
        _errorText = _detailStatusText;
    }
    private static string FailureText(RiskReadOutcome outcome) => outcome switch
    {
        RiskReadOutcome.UntrustedConnection => "The local Core connection could not be trusted.",
        RiskReadOutcome.InvalidResponse or RiskReadOutcome.Success => "Core returned an invalid risk response. Refresh Risk.",
        RiskReadOutcome.TooLarge => "The risk response exceeds the supported size.",
        _ => "Local Core is unavailable. Restore Core, then refresh Risk."
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
            if (_disposed) return;
            CloseDetailLocked();
            _errorText = string.Empty;
            NotifyAll();
        }
    }
    private void CloseDetailLocked()
    {
        _detailGeneration++;
        _detailPending?.Cancel();
        _detailPending = null;
        _detailEndpointId = Guid.Empty;
        _detail = null;
        _detailState = RiskDetailState.None;
        _detailStatusText = string.Empty;
    }
    private void ClearLocked()
    {
        _listGeneration++;
        _listPending?.Cancel();
        _listPending = null;
        CloseDetailLocked();
        _visibleEndpoints = Array.Empty<EndpointRiskRow>();
        _selectedEndpoint = null;
        _organization = null;
        _offset = 0;
        _totalEndpoints = 0;
        _listState = RiskListState.NotLoaded;
        _listStatusText = "Open Risk to load the current Core evaluation.";
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
    private void NotifyAll() => Notify(nameof(VisibleEndpoints), nameof(SelectedEndpoint), nameof(Organization), nameof(Detail),
        nameof(ListState), nameof(DetailState), nameof(ListStatusText), nameof(DetailStatusText), nameof(ErrorText),
        nameof(IsLoading), nameof(IsLoadingDetail), nameof(IsShowingDetail), nameof(CanRefresh), nameof(CanRefreshDetail),
        nameof(CanNextPage), nameof(CanPreviousPage), nameof(TotalEndpoints), nameof(TotalPages), nameof(PageIndex), nameof(PageNumber));
    private void Notify(params string[] properties)
    {
        foreach (var property in properties) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
    }
    private sealed class Pending(long generation)
    {
        private readonly CancellationTokenSource cancellation = new();
        private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal long Generation { get; } = generation;
        internal CancellationToken Token => cancellation.Token;
        internal Task Task => completion.Task;
        internal void Cancel() => cancellation.Cancel();
        internal void Complete()
        {
            cancellation.Dispose();
            completion.TrySetResult();
        }
    }
}
