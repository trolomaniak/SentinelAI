using System.ComponentModel;
using System.Globalization;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Contracts.SoftwareCatalog;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public sealed record SoftwareProductRow(SoftwareProduct Product, string Publisher, string Counts);
public sealed record SoftwareInstallationRow(string Computer, string Version, string Observation);
public sealed record SoftwareChangeRow(string Application, string Observation, string Times, string Before, string After);

public sealed class SoftwareCatalogViewModel(ISoftwareCatalogClient client) : INotifyPropertyChanged, IDisposable
{
    private const int PageSize = SoftwareCatalogContract.DefaultPageSize;
    private readonly object _gate = new();
    private readonly ReadState<SoftwareProductRow> _products = new();
    private readonly ReadState<SoftwareInstallationRow> _installations = new();
    private readonly ReadState<SoftwareChangeRow> _changes = new();
    private SoftwareCatalogCoverage? _coverage;
    private SoftwareProductRow? _selected;
    private SoftwareProduct? _changeProduct;
    private string _searchText = string.Empty;
    private string _query = string.Empty;
    private int _selectedTabIndex;
    private bool _invalidQuery;
    private bool _active;
    private bool _disposed;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;

    public string SearchText
    {
        get { lock (_gate) return _searchText; }
        set
        {
            lock (_gate)
            {
                if (!_active || _searchText == value) return;
                _searchText = value;
                Notify(nameof(SearchText));
            }
        }
    }

    public IReadOnlyList<SoftwareProductRow> Products { get { lock (_gate) return _products.Page?.Rows ?? []; } }
    public IReadOnlyList<SoftwareInstallationRow> Installations { get { lock (_gate) return _installations.Page?.Rows ?? []; } }
    public IReadOnlyList<SoftwareChangeRow> Changes { get { lock (_gate) return _changes.Page?.Rows ?? []; } }
    public SoftwareProductRow? SelectedProduct { get { lock (_gate) return _selected; } }
    public bool HasSelection { get { lock (_gate) return _selected is not null; } }
    public int SelectedTabIndex
    {
        get { lock (_gate) return _selectedTabIndex; }
        set
        {
            lock (_gate)
            {
                if (!_active || value is not (0 or 1) || value == _selectedTabIndex) return;
                _selectedTabIndex = value;
                Notify(nameof(SelectedTabIndex));
                if (value == 1) _ = OpenChangesAsync();
            }
        }
    }
    public bool CanRefreshProducts { get { lock (_gate) return _active && _products.Operation is null; } }
    public bool CanPreviousProducts { get { lock (_gate) return CanPrevious(_products); } }
    public bool CanNextProducts { get { lock (_gate) return CanNext(_products); } }
    public bool CanRefreshInstallations { get { lock (_gate) return _active && _selected is not null && _installations.Operation is null; } }
    public bool CanPreviousInstallations { get { lock (_gate) return CanPrevious(_installations); } }
    public bool CanNextInstallations { get { lock (_gate) return CanNext(_installations); } }
    public bool CanRefreshChanges { get { lock (_gate) return _active && _changes.Operation is null; } }
    public bool CanShowFleetChanges { get { lock (_gate) return _active && _changeProduct is not null; } }
    public bool CanPreviousChanges { get { lock (_gate) return CanPrevious(_changes); } }
    public bool CanNextChanges { get { lock (_gate) return CanNext(_changes); } }

    public string CoverageText
    {
        get
        {
            lock (_gate) return _coverage is not { } coverage ? string.Empty :
                F("{0} active computers · {1} complete reports · {2} partial · {3} unavailable · {4} missing · {6} older than {5} h",
                    coverage.ActiveEndpoints, coverage.CompleteEndpoints, coverage.PartialEndpoints, coverage.UnavailableEndpoints,
                    coverage.MissingEndpoints, SoftwareCatalogContract.StaleAfterHours, coverage.StaleEndpoints);
        }
    }

    public string ProductsStatus
    {
        get
        {
            lock (_gate)
            {
                if (_invalidQuery) return T("Enter a valid application name or publisher.");
                if (_coverage is { ActiveEndpoints: 0 }) return T("No active computers are enrolled.");
                return Status(_products, "Reading software catalog…", _query.Length == 0
                    ? "No applications have been reported."
                    : "No application matches the search.");
            }
        }
    }

    public string InstallationsStatus { get { lock (_gate) return Status(_installations, "Reading reported versions…", "No computer currently reports this application."); } }
    public string ChangesStatus { get { lock (_gate) return Status(_changes, "Reading software changes…", "No retained software changes for this selection."); } }
    public string ProductsPageText { get { lock (_gate) return PageText(_products, "Applications {0} of {1}"); } }
    public string InstallationsPageText { get { lock (_gate) return PageText(_installations, "Device and version pairs {0} of {1}"); } }
    public string ChangesPageText { get { lock (_gate) return PageText(_changes, "Observations {0} of {1}"); } }
    public string ChangesScopeText { get { lock (_gate) return _changeProduct is null ? T("All computers and applications") : _changeProduct.Name; } }

    public Task RefreshAsync()
    {
        lock (_gate)
        {
            if (_disposed || _products.Operation is not null) return Task.CompletedTask;
            _active = true;
            return LoadProducts(0);
        }
    }

    public Task SearchAsync()
    {
        lock (_gate)
        {
            if (!_active) return Task.CompletedTask;
            var query = _searchText.Trim();
            _invalidQuery = query.Length > 0 && !SecurityEventContract.IsBoundedText(query, SoftwareCatalogContract.MaximumQueryLength);
            if (_invalidQuery)
            {
                Notify(nameof(ProductsStatus));
                return Task.CompletedTask;
            }
            _query = _searchText = query;
            return LoadProducts(0);
        }
    }

    public Task ClearSearchAsync()
    {
        lock (_gate)
        {
            if (!_active) return Task.CompletedTask;
            _searchText = _query = string.Empty;
            return LoadProducts(0);
        }
    }

    public Task PreviousProductsAsync() { lock (_gate) return CanPreviousProducts ? LoadProducts(_products.Page!.Offset - PageSize) : Task.CompletedTask; }
    public Task NextProductsAsync() { lock (_gate) return CanNextProducts ? LoadProducts(_products.Page!.Offset + PageSize) : Task.CompletedTask; }

    public Task SelectProductAsync(SoftwareProductRow? product)
    {
        lock (_gate)
        {
            if (!_active || ReferenceEquals(_selected, product) || product is not null && !Products.Any(row => ReferenceEquals(row, product)))
                return Task.CompletedTask;
            _selected = product;
            if (product is not null) return LoadInstallations(product, 0);
            _installations.Reset();
            Notify();
            return Task.CompletedTask;
        }
    }

    public Task RefreshInstallationsAsync() { lock (_gate) return CanRefreshInstallations ? LoadInstallations(_selected!, 0) : Task.CompletedTask; }
    public Task PreviousInstallationsAsync() { lock (_gate) return CanPreviousInstallations ? LoadInstallations(_selected!, _installations.Page!.Offset - PageSize) : Task.CompletedTask; }
    public Task NextInstallationsAsync() { lock (_gate) return CanNextInstallations ? LoadInstallations(_selected!, _installations.Page!.Offset + PageSize) : Task.CompletedTask; }

    public Task OpenChangesAsync()
    {
        lock (_gate) return CanRefreshChanges && _changes.Page is null ? LoadChanges(0) : Task.CompletedTask;
    }

    public Task ShowProductChangesAsync()
    {
        lock (_gate)
        {
            if (!_active || _selected is null) return Task.CompletedTask;
            _changeProduct = _selected.Product;
            _selectedTabIndex = 1;
            return LoadChanges(0);
        }
    }

    public Task ShowFleetChangesAsync()
    {
        lock (_gate)
        {
            if (!CanShowFleetChanges) return Task.CompletedTask;
            _changeProduct = null;
            return LoadChanges(0);
        }
    }

    public Task RefreshChangesAsync() { lock (_gate) return CanRefreshChanges ? LoadChanges(0) : Task.CompletedTask; }
    public Task PreviousChangesAsync() { lock (_gate) return CanPreviousChanges ? LoadChanges(_changes.Page!.Offset - PageSize) : Task.CompletedTask; }
    public Task NextChangesAsync() { lock (_gate) return CanNextChanges ? LoadChanges(_changes.Page!.Offset + PageSize) : Task.CompletedTask; }

    private Task LoadProducts(int offset)
    {
        _selected = null;
        _installations.Reset();
        _coverage = null;
        _invalidQuery = false;
        var query = _query;
        return ReadAsync(_products, token => client.GetSoftwareCatalogAsync(query, offset, PageSize, token), value =>
        {
            if (value.Offset != offset || value.Limit != PageSize) return null;
            _coverage = value.Coverage;
            return new(value.Offset, value.Total, value.Items.Select(ProductRow).ToArray());
        });
    }

    private Task LoadInstallations(SoftwareProductRow selected, int offset)
    {
        var productId = selected.Product.ProductId;
        return ReadAsync(_installations, token => client.GetSoftwareInstallationsAsync(productId, offset, PageSize, token), value =>
            value.ProductId == productId && value.Offset == offset && value.Limit == PageSize
                ? new(value.Offset, value.Total, value.Items.Select(InstallationRow).ToArray()) : null);
    }

    private Task LoadChanges(int offset)
    {
        var productId = _changeProduct?.ProductId;
        return ReadAsync(_changes, token => client.GetSoftwareChangesAsync(productId, offset, PageSize, token), value =>
            value.ProductId == productId && value.Offset == offset && value.Limit == PageSize
                ? new(value.Offset, value.Total, value.Items.Select(ChangeRow).ToArray()) : null);
    }

    // The operation identity also rejects responses from a caller that completes after cancellation.
    private async Task ReadAsync<TDto, TRow>(ReadState<TRow> state, Func<CancellationToken, Task<DeviceReadResult<TDto>>> read,
        Func<TDto, Page<TRow>?> present) where TDto : class
    {
        state.Reset();
        using var operation = new CancellationTokenSource();
        state.Operation = operation;
        Notify();
        if (state.Operation != operation) return;
        DeviceReadResult<TDto> result;
        try { result = await read(operation.Token); }
        catch (Exception) { result = new(DeviceReadOutcome.Unavailable); }

        lock (_gate)
        {
            if (state.Operation != operation) return;
            state.Operation = null;
            if (result.Outcome is DeviceReadOutcome.Unauthenticated or DeviceReadOutcome.UntrustedConnection)
            {
                Reset();
                _products.Outcome = _changes.Outcome = result.Outcome;
                if (result.Outcome == DeviceReadOutcome.Unauthenticated)
                {
                    _active = false;
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                }
            }
            else
            {
                state.Page = result is { Outcome: DeviceReadOutcome.Success, Value: { } value } ? present(value) : null;
                state.Outcome = result.Outcome == DeviceReadOutcome.Success && state.Page is null ? DeviceReadOutcome.InvalidResponse : result.Outcome;
            }
            Notify();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _active = false;
            Reset();
            Notify();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _active = false;
            _disposed = true;
            Reset();
        }
    }

    private void Reset()
    {
        _searchText = _query = string.Empty;
        _selectedTabIndex = 0;
        _invalidQuery = false;
        _selected = null;
        _changeProduct = null;
        _coverage = null;
        _products.Reset();
        _installations.Reset();
        _changes.Reset();
    }

    private void Notify(string propertyName = "") => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    private static bool CanPrevious<T>(ReadState<T> state) => state.Page is { Offset: > 0 };
    private static bool CanNext<T>(ReadState<T> state) => state.Page is { } page &&
        page.Offset + PageSize < page.Total && page.Offset + PageSize <= SoftwareCatalogContract.MaximumOffset;

    private static string PageText<T>(ReadState<T> state, string format)
    {
        if (state.Page is not { } page) return string.Empty;
        var range = page.Rows.Count == 0 ? "0" : F("{0}–{1}", page.Offset + 1, page.Offset + page.Rows.Count);
        return F(format, range, page.Total);
    }

    private static string Status<TRow>(ReadState<TRow> state, string loading, string empty) => state switch
    {
        { Operation: not null } => T(loading),
        { Page.Total: 0 } => T(empty),
        { Page.Rows.Count: 0 } => T("This page is empty. Use Previous or Refresh."),
        { Outcome: DeviceReadOutcome.UntrustedConnection } => T("The local Core connection could not be trusted."),
        { Outcome: not (null or DeviceReadOutcome.Success or DeviceReadOutcome.Unauthenticated) } => T("Software catalog data is unavailable. Refresh to try again."),
        _ => string.Empty
    };

    private static SoftwareProductRow ProductRow(SoftwareProduct product) => new(product,
        product.Publisher ?? T("Unknown publisher"), F("{0} computers · {1} version variants", product.EndpointCount, product.VariantCount));

    private static SoftwareInstallationRow InstallationRow(SoftwareInstallation installation)
    {
        var timestamp = Timestamp(installation.CollectedUtc);
        var report = installation.Partial ? T("Partial report") : T("Complete report");
        var freshness = installation.Stale ? T("Stale") : T("Current");
        return new(installation.EndpointName, VariantText(new(installation.Version, installation.Architecture)),
            F("Report · {0} · {1} · {2}", timestamp, report, freshness));
    }

    private static SoftwareChangeRow ChangeRow(SoftwareChange change) => new(
        F("{0} ({1})", change.Name, change.Publisher ?? T("Unknown publisher")),
        F("{0} · {1}", change.EndpointName, change.Kind switch
        {
            "appeared" => T("Appeared in report"),
            "disappeared" => T("Disappeared from report"),
            _ => T("Reported versions or architecture changed")
        }),
        F("Compared reports · {0} → {1}", Timestamp(change.PreviousCollectedUtc), Timestamp(change.CollectedUtc)),
        F("Before · {0}", VariantsText(change.Before, change.BeforeCount)), F("After · {0}", VariantsText(change.After, change.AfterCount)));

    private static string VariantsText(IReadOnlyList<SoftwareVariant> variants, int count)
    {
        if (count == 0) return T("None");
        var values = string.Join(", ", variants.Select(VariantText));
        return count == variants.Count ? values : F("{0} · {1} more", values, count - variants.Count);
    }

    private static string VariantText(SoftwareVariant variant) => F("{0} ({1})", variant.Version ?? T("Unknown version"),
        variant.Architecture ?? T("Unknown architecture"));

    private static string Timestamp(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.FFFFFFF 'UTC'", CultureInfo.InvariantCulture);

    private sealed record Page<T>(int Offset, int Total, IReadOnlyList<T> Rows);

    private sealed class ReadState<T>
    {
        public CancellationTokenSource? Operation { get; set; }
        public DeviceReadOutcome? Outcome { get; set; }
        public Page<T>? Page { get; set; }

        public void Reset()
        {
            var operation = Operation;
            Operation = null;
            Page = null;
            Outcome = null;
            operation?.Cancel();
        }
    }
}
