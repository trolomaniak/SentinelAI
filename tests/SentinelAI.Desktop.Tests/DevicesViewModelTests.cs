using System.Globalization;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Desktop.Foundation;

internal static class DevicesViewModelTests
{
    private static int assertions;
    private static readonly DateTimeOffset Observation = new(2026, 10, 3, 12, 0, 0, TimeSpan.Zero);

    public static async Task<int> RunAsync()
    {
        PresentationTests();
        await PagingFilteringSortingAsync();
        await ListStatesAndFailuresAsync();
        await DetailStatesAndRacesAsync();
        await SignOutAndDisposeRacesAsync();
        Console.WriteLine($"Desktop devices: {assertions} assertions passed.");
        return assertions;
    }

    private static void PresentationTests()
    {
        foreach (var (value, expected) in new[]
        {
            ("healthy", DeviceHealth.Healthy), ("warning", DeviceHealth.Warning),
            ("offline", DeviceHealth.Offline), ("unknown", DeviceHealth.Unknown),
            ("future-health-state", DeviceHealth.Unknown), ("Healthy", DeviceHealth.Unknown)
        })
        {
            var row = new DeviceRow(Summary(1) with { HealthState = value, LastSeenUtc = Observation.AddYears(1) });
            Check(row.Health == expected && row.HealthLabel == expected.ToString(), "Desktop reinterpreted Core connectivity health.");
        }
        var healthyUnprotected = new DeviceRow(Summary(1) with { HealthState = "healthy", SecurityPostureSummary = "Firewall disabled on one or more profiles" });
        Check(healthyUnprotected.Health == DeviceHealth.Healthy && healthyUnprotected.FirewallSummary.StartsWith("Disabled", StringComparison.Ordinal), "Connectivity health was conflated with configured firewall posture.");
        var missing = new DeviceRow(MissingSummary(2));
        Check(missing.Health == DeviceHealth.Healthy && !missing.HasInventory, "Heartbeat health implied that inventory was present.");
        Check(missing.OperatingSystemText == "Unknown" && missing.AgentVersionText == "Unknown" && missing.FirewallSummary == "Unknown", "Absent inventory supplied inferred operating system, version or firewall values.");
        Check(missing.InventoryCollectedText == "Unknown / not reported", "Missing inventory time was not explicit.");
        Check(new DeviceRow(Summary(3) with { LastSeenUtc = null }).LastSeenText == "Unknown", "Missing heartbeat time was not Unknown.");
        Check(new DeviceRow(Summary(3) with { SecurityPostureSummary = "future-posture-state" }).FirewallSummary == "Unknown", "An unknown firewall summary was interpreted as protection.");

        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("pl-PL");
            var row = new DeviceRow(Summary(4) with { InventoryCollectedUtc = Observation.ToOffset(TimeSpan.FromHours(2)) });
            Check(row.InventoryCollectedText == "2026-10-03 12:00:00 UTC", "Observation timestamps were not explicit, culture-independent UTC.");
        }
        finally { CultureInfo.CurrentCulture = previousCulture; }

        var emptyDetail = new EndpointPresentation(Detail(MissingSummary(5), inventory: false));
        Check(emptyDetail.InventoryStatusText == "No inventory reported", "Endpoint detail obscured missing inventory.");
        Check(emptyDetail.PostureFacts.All(fact => fact.Value == "Unknown"), "Missing configured posture was displayed as enabled or disabled.");
        Check(emptyDetail.Facts.Single(fact => fact.Label == "Disks").Value == "Unknown", "No reported disk inventory was displayed as an empty known machine.");
        var configured = new EndpointPresentation(Detail(Summary(6)));
        Check(configured.PostureFacts.Single(fact => fact.Label == "Configured Domain firewall").Value == "Enabled", "Known enabled Domain firewall was lost.");
        Check(configured.PostureFacts.Single(fact => fact.Label == "Configured Private firewall").Value == "Disabled", "Known disabled Private firewall was lost.");
        Check(configured.PostureFacts.Single(fact => fact.Label == "Configured Public firewall").Value == "Unknown", "Null Public firewall was inferred.");
        Check(configured.PostureFacts.Single(fact => fact.Label == "Automatic updates").Value == "Disabled", "AutomaticUpdatesDisabled was inverted incorrectly.");
        Check(configured.PostureFacts.Single(fact => fact.Label == "Remote Desktop").Value == "Unknown", "An absent configuration observation was inferred.");
        Check(configured.Facts.Any(fact => fact.Label == "Release / build" && fact.Value == "24H2 10.0.26100.1"), "OS release/build information was lost.");
        Check(configured.Facts.Any(fact => fact.Label == "Disk" && fact.Value.Contains("256,000 bytes total", StringComparison.Ordinal)), "Disk capacity was not rendered as explicit bytes.");
        Check(((ICollection<DisplayFact>)configured.Facts).IsReadOnly && ((ICollection<DisplayFact>)configured.PostureFacts).IsReadOnly, "A view can mutate detail facts.");
        Throws<ArgumentNullException>(() => _ = new DeviceRow(null!), "Null summary was accepted.");
        Throws<ArgumentNullException>(() => _ = new EndpointPresentation(null!), "Null detail was accepted.");
    }

    private static async Task PagingFilteringSortingAsync()
    {
        var client = new ControlledClient();
        using var viewModel = new DevicesViewModel(client);
        Check(viewModel.ListState == DeviceListState.NotLoaded && viewModel.CanRefresh && viewModel.VisibleDevices.Count == 0, "The Devices screen began with fabricated data.");
        var changes = new List<string?>();
        viewModel.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
        var loading = viewModel.RefreshAsync();
        Check(viewModel.IsLoading && !viewModel.CanRefresh && !loading.IsCompleted, "Device loading blocked or failed to expose its busy state.");
        Check(ReferenceEquals(loading, viewModel.RefreshAsync()) && client.ListRequests.Count == 1, "Concurrent refreshes created duplicate list requests.");
        var summaries = Enumerable.Range(0, 231).Reverse().Select(index => Summary(index + 1) with
        {
            Name = $"device{index:D3}",
            HealthState = new[] { "healthy", "warning", "offline", "unknown" }[index % 4],
            OperatingSystem = index % 2 == 0 ? "Windows 11 24H2 10.0.26100.1" : "Windows Server 2025 10.0.26100.1"
        }).ToArray();
        client.ListRequests[0].Complete(summaries);
        await Done(loading);
        Check(viewModel.ListState == DeviceListState.Ready && viewModel.TotalDevices == 231 && viewModel.FilteredCount == 231, "The enrolled fleet counts were incorrect.");
        Check(viewModel.VisibleDevices.Count == 100 && viewModel.TotalPages == 3 && viewModel.PageNumber == 1, "The first device page did not enforce the 100-row bound.");
        Check(viewModel.VisibleDevices[0].Name == "device000" && viewModel.VisibleDevices[^1].Name == "device099", "Default hostname sorting was unstable.");
        Check(((ICollection<DeviceRow>)viewModel.VisibleDevices).IsReadOnly, "A view can mutate the current device page.");
        Check(!viewModel.CanPreviousPage && viewModel.CanNextPage && changes.Contains(nameof(viewModel.VisibleDevices)) && changes.Contains(nameof(viewModel.IsLoading)), "Paging or binding notifications were missing.");
        viewModel.PageIndex = 1;
        Check(viewModel.VisibleDevices[0].Name == "device100" && viewModel.VisibleDevices.Count == 100 && viewModel.PageNumber == 2, "The second page was incorrect.");
        viewModel.PageIndex = int.MaxValue;
        Check(viewModel.PageIndex == 2 && viewModel.VisibleDevices.Count == 31 && !viewModel.CanNextPage, "The final page did not clamp its index and size.");
        viewModel.PageIndex = -1;
        Check(viewModel.PageIndex == 0, "A negative page index was accepted.");
        viewModel.SearchText = " DEVICE00 ";
        Check(viewModel.FilteredCount == 10 && viewModel.PageIndex == 0 && viewModel.TotalPages == 1, "Search was not case-insensitive or did not reset paging.");
        viewModel.HealthFilter = DeviceHealthFilter.Warning;
        Check(viewModel.FilteredCount == 3 && viewModel.VisibleDevices.All(row => row.Health == DeviceHealth.Warning), "Search and health filters were not combined.");
        viewModel.SearchText = "does-not-exist";
        Check(viewModel.ListState == DeviceListState.FilteredEmpty && viewModel.TotalDevices == 231 && viewModel.PageNumber == 0, "Filtered-empty was conflated with an empty fleet.");
        viewModel.SearchText = string.Empty;
        viewModel.HealthFilter = DeviceHealthFilter.All;
        viewModel.SortDescending = true;
        Check(viewModel.VisibleDevices[0].Name == "device230", "Descending hostname sort was ignored.");
        viewModel.SortDescending = false;
        viewModel.SortBy = DeviceSortColumn.OperatingSystem;
        Check(viewModel.VisibleDevices.All(row => row.OperatingSystemText.StartsWith("Windows 11", StringComparison.Ordinal)), "Operating system sort did not precede paging.");
        viewModel.SortBy = DeviceSortColumn.Health;
        Check(viewModel.VisibleDevices[0].Health == DeviceHealth.Healthy && viewModel.VisibleDevices[^1].Health == DeviceHealth.Warning, "Health sort did not use Core state ordering.");
        viewModel.SearchText = summaries[0].EndpointId.ToString("D");
        Check(viewModel.FilteredCount == 1 && viewModel.VisibleDevices[0].EndpointId == summaries[0].EndpointId, "Endpoint ID search did not select the exact enrolled row.");
        viewModel.SearchText = new string('x', 300);
        Check(viewModel.SearchText.Length == 256, "The search input was not bounded.");
        Throws<ArgumentOutOfRangeException>(() => viewModel.HealthFilter = (DeviceHealthFilter)99, "An undefined health filter was accepted.");
        Throws<ArgumentOutOfRangeException>(() => viewModel.SortBy = (DeviceSortColumn)99, "An undefined sort column was accepted.");

        viewModel.SearchText = string.Empty;
        var refresh = viewModel.RefreshAsync();
        var sameName = new[]
        {
            Summary(20) with { Name = "same", LastSeenUtc = null, InventoryCollectedUtc = null, AgentVersion = "2.0" },
            Summary(10) with { Name = "same", LastSeenUtc = Observation.AddMinutes(-10), InventoryCollectedUtc = Observation.AddDays(-2), AgentVersion = "1.0" },
            Summary(30) with { Name = "same", LastSeenUtc = Observation, InventoryCollectedUtc = Observation, AgentVersion = "3.0" }
        };
        client.ListRequests[^1].Complete(sameName);
        await Done(refresh);
        viewModel.SortBy = DeviceSortColumn.Name;
        Check(viewModel.VisibleDevices.Select(row => row.EndpointId).SequenceEqual(sameName.OrderBy(row => row.EndpointId).Select(row => row.EndpointId)), "Equal display names lacked a deterministic endpoint-ID tie break.");
        viewModel.SortBy = DeviceSortColumn.LastSeen;
        Check(viewModel.VisibleDevices[0].EndpointId == Identifier(10) && viewModel.VisibleDevices[^1].LastSeenUtc is null, "Ascending heartbeat sort did not keep missing observations explicit and last.");
        viewModel.SortDescending = true;
        Check(viewModel.VisibleDevices[0].EndpointId == Identifier(30) && viewModel.VisibleDevices[^1].LastSeenUtc is null, "Descending heartbeat sort moved Unknown observations ahead of known times.");
        viewModel.SortBy = DeviceSortColumn.InventoryCollected;
        Check(viewModel.VisibleDevices[0].EndpointId == Identifier(30) && viewModel.VisibleDevices[^1].InventoryCollectedUtc is null, "Inventory timestamp sort was incorrect.");
        viewModel.SortBy = DeviceSortColumn.AgentVersion;
        Check(viewModel.VisibleDevices[0].AgentVersionText == "3.0", "Agent version sorting was ignored.");
    }

    private static async Task ListStatesAndFailuresAsync()
    {
        var client = new ControlledClient();
        using var viewModel = new DevicesViewModel(client);
        var empty = viewModel.RefreshAsync();
        client.ListRequests[^1].Complete([]);
        await Done(empty);
        Check(viewModel.ListState == DeviceListState.Empty && viewModel.TotalDevices == 0 && viewModel.VisibleDevices.Count == 0, "A real empty list was not represented as no enrolled devices.");
        foreach (var outcome in new[] { DeviceReadOutcome.Unavailable, DeviceReadOutcome.UntrustedConnection, DeviceReadOutcome.InvalidResponse, DeviceReadOutcome.TooLarge })
        {
            var failed = viewModel.RefreshAsync();
            client.ListRequests[^1].Completion.SetResult(new(outcome));
            await Done(failed);
            Check(viewModel.ListState == DeviceListState.Unavailable && viewModel.VisibleDevices.Count == 0 && viewModel.CanRefresh, "A failed list request retained data or disabled explicit retry.");
            Check(viewModel.ErrorText.Length > 0, "A list failure had no explicit safe error.");
        }
        var malformed = viewModel.RefreshAsync();
        client.ListRequests[^1].Complete([Summary(1), Summary(1)]);
        await Done(malformed);
        Check(viewModel.ListState == DeviceListState.Unavailable, "Duplicate enrolled endpoint IDs were accepted.");
        var failedException = viewModel.RefreshAsync();
        client.ListRequests[^1].Completion.SetException(new IOException("test-only-secret-error"));
        await Done(failedException);
        Check(viewModel.ListState == DeviceListState.Unavailable && !viewModel.ErrorText.Contains("secret", StringComparison.Ordinal), "A transport exception escaped or revealed its message.");
        var recovered = viewModel.RefreshAsync();
        client.ListRequests[^1].Complete([Summary(2)]);
        await Done(recovered);
        Check(viewModel.ListState == DeviceListState.Ready && viewModel.ErrorText.Length == 0, "Explicit refresh did not recover from an unavailable Core.");
    }

    private static async Task DetailStatesAndRacesAsync()
    {
        var client = new ControlledClient();
        using var viewModel = new DevicesViewModel(client);
        await SeedAsync(viewModel, client, [Summary(1), MissingSummary(2)]);
        viewModel.SelectedDevice = viewModel.VisibleDevices[0];
        Check(viewModel.SelectedDevice?.EndpointId == Identifier(1), "The current page selection was ignored.");
        Throws<ArgumentException>(() => viewModel.SelectedDevice = new DeviceRow(Summary(99)), "An injected row entered the selection.");
        var missing = viewModel.OpenDetailAsync(Identifier(99));
        await Done(missing);
        Check(viewModel.DetailState == DeviceDetailState.NotFound && client.DetailRequests.Count == 0, "An absent list endpoint caused an arbitrary detail request.");
        var first = viewModel.OpenDetailAsync(Identifier(1));
        Check(viewModel.IsShowingDetail && viewModel.IsLoadingDetail && viewModel.Detail is null, "Detail loading was not native, asynchronous or explicit.");
        Check(ReferenceEquals(first, viewModel.OpenDetailAsync(Identifier(1))) && client.DetailRequests.Count == 1, "Repeated detail opens duplicated the same request.");
        var second = viewModel.OpenDetailAsync(Identifier(2));
        Check(client.DetailRequests[0].CancellationToken.IsCancellationRequested, "Selecting a different endpoint did not cancel its pending detail.");
        client.DetailRequests[1].Complete(Detail(MissingSummary(2), inventory: false));
        await Done(second);
        Check(viewModel.DetailState == DeviceDetailState.Ready && viewModel.Detail?.EndpointId == Identifier(2) && viewModel.Detail.InventoryStatusText == "No inventory reported", "Missing inventory detail did not open with explicit Unknown values.");
        client.DetailRequests[0].Complete(Detail(Summary(1)));
        await Done(first);
        Check(viewModel.Detail?.EndpointId == Identifier(2), "An obsolete detail response replaced the new endpoint.");
        viewModel.CloseDetail();
        Check(!viewModel.IsShowingDetail && viewModel.Detail is null, "Back navigation retained the previous detail page.");

        var closed = viewModel.OpenDetailAsync(Identifier(1));
        viewModel.CloseDetail();
        Check(client.DetailRequests[^1].CancellationToken.IsCancellationRequested, "Closing detail did not cancel its request.");
        client.DetailRequests[^1].Complete(Detail(Summary(1)));
        await Done(closed);
        Check(viewModel.DetailState == DeviceDetailState.None && viewModel.Detail is null, "A response reopened closed endpoint detail.");

        var notFound = viewModel.OpenDetailAsync(Identifier(1));
        client.DetailRequests[^1].Completion.SetResult(new(DeviceReadOutcome.NotFound));
        await Done(notFound);
        Check(viewModel.DetailState == DeviceDetailState.NotFound && viewModel.Detail is null, "A deleted endpoint was displayed as a valid detail page.");
        var wrongEndpoint = viewModel.OpenDetailAsync(Identifier(1));
        client.DetailRequests[^1].Complete(Detail(Summary(2)));
        await Done(wrongEndpoint);
        Check(viewModel.DetailState == DeviceDetailState.Unavailable && viewModel.Detail is null, "A mismatched endpoint response was accepted.");
        var unavailable = viewModel.OpenDetailAsync(Identifier(1));
        client.DetailRequests[^1].Completion.SetResult(new(DeviceReadOutcome.Unavailable));
        await Done(unavailable);
        Check(viewModel.DetailState == DeviceDetailState.Unavailable && viewModel.TotalDevices == 2, "A detail outage erased a still-current fleet unnecessarily.");

        var filtered = viewModel.OpenDetailAsync(Identifier(1));
        viewModel.SearchText = "device0002";
        Check(client.DetailRequests[^1].CancellationToken.IsCancellationRequested && viewModel.SelectedDevice is null, "Filtering away the selected row retained its request or selection.");
        client.DetailRequests[^1].Complete(Detail(Summary(1)));
        await Done(filtered);
        Check(viewModel.DetailState == DeviceDetailState.None && viewModel.Detail is null, "A filtered-away endpoint detail resurfaced.");
        viewModel.SearchText = string.Empty;
        var refreshedAway = viewModel.OpenDetailAsync(Identifier(1));
        var refresh = viewModel.RefreshAsync();
        Check(client.DetailRequests[^1].CancellationToken.IsCancellationRequested, "Refreshing the list did not invalidate old detail work.");
        client.DetailRequests[^1].Complete(Detail(Summary(1)));
        await Done(refreshedAway);
        Check(viewModel.Detail is null && viewModel.ListState == DeviceListState.Loading, "Old detail survived fleet refresh.");
        client.ListRequests[^1].Complete([Summary(2)]);
        await Done(refresh);
    }

    private static async Task SignOutAndDisposeRacesAsync()
    {
        var client = new ControlledClient();
        using var viewModel = new DevicesViewModel(client);
        var old = viewModel.RefreshAsync();
        viewModel.SearchText = "old";
        viewModel.Clear();
        Check(client.ListRequests[0].CancellationToken.IsCancellationRequested && viewModel.ListState == DeviceListState.NotLoaded && viewModel.SearchText.Length == 0, "Sign-out Clear did not cancel and erase fleet/filter state.");
        var fresh = viewModel.RefreshAsync();
        client.ListRequests[0].Complete([Summary(1)]);
        await Done(old);
        Check(viewModel.ListState == DeviceListState.Loading && viewModel.VisibleDevices.Count == 0, "An old account's response restored devices into the new loading operation.");
        client.ListRequests[1].Complete([Summary(2)]);
        await Done(fresh);
        Check(viewModel.VisibleDevices.Single().EndpointId == Identifier(2), "The current account's fleet response was discarded by obsolete cleanup.");

        var expirations = 0;
        viewModel.SessionExpired += (_, _) => expirations++;
        var expired = viewModel.RefreshAsync();
        client.ListRequests[^1].Completion.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await Done(expired);
        Check(expirations == 1 && viewModel.VisibleDevices.Count == 0 && viewModel.Detail is null && viewModel.ListState == DeviceListState.NotLoaded, "List unauthorized did not clear data and tell the authentication owner to sign out.");
        await SeedAsync(viewModel, client, [Summary(3)]);
        var expiredDetail = viewModel.OpenDetailAsync(Identifier(3));
        client.DetailRequests[^1].Completion.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await Done(expiredDetail);
        Check(expirations == 2 && viewModel.TotalDevices == 0 && !viewModel.IsShowingDetail, "Detail unauthorized retained data or failed to signal session expiration.");

        var obsoleteUnauthorized = viewModel.RefreshAsync();
        var oldListRequest = client.ListRequests[^1];
        viewModel.Clear();
        await SeedAsync(viewModel, client, [Summary(6)]);
        oldListRequest.Completion.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await Done(obsoleteUnauthorized);
        Check(expirations == 2 && viewModel.VisibleDevices.Single().EndpointId == Identifier(6), "An old account's unauthorized list result signed out the current session.");
        var obsoleteUnauthorizedDetail = viewModel.OpenDetailAsync(Identifier(6));
        var oldDetailRequest = client.DetailRequests[^1];
        viewModel.Clear();
        await SeedAsync(viewModel, client, [Summary(7)]);
        oldDetailRequest.Completion.SetResult(new(DeviceReadOutcome.Unauthenticated));
        await Done(obsoleteUnauthorizedDetail);
        Check(expirations == 2 && viewModel.VisibleDevices.Single().EndpointId == Identifier(7), "An old account's unauthorized detail result signed out the current session.");

        await SeedAsync(viewModel, client, [Summary(4)]);
        var pendingDetail = viewModel.OpenDetailAsync(Identifier(4));
        viewModel.Clear();
        client.DetailRequests[^1].Complete(Detail(Summary(4)));
        await Done(pendingDetail);
        Check(viewModel.Detail is null && viewModel.SelectedDevice is null && viewModel.VisibleDevices.Count == 0, "Sign-out restored pending endpoint data.");

        var disposed = new DevicesViewModel(client);
        var pending = disposed.RefreshAsync();
        disposed.Dispose();
        var notifications = 0;
        disposed.PropertyChanged += (_, _) => notifications++;
        Check(client.ListRequests[^1].CancellationToken.IsCancellationRequested && client.DisposeCalls == 0, "Disposal did not cancel work or disposed the shared authentication client.");
        client.ListRequests[^1].Complete([Summary(5)]);
        await Done(pending);
        Check(notifications == 0 && disposed.VisibleDevices.Count == 0 && !disposed.CanRefresh, "A response changed the disposed view model.");
        var calls = client.ListRequests.Count;
        disposed.Dispose();
        await disposed.RefreshAsync();
        await disposed.OpenDetailAsync(Identifier(5));
        disposed.Clear();
        Check(client.ListRequests.Count == calls && client.DisposeCalls == 0, "Disposed operations touched the shared client.");
    }

    private static async Task SeedAsync(DevicesViewModel viewModel, ControlledClient client, DeviceSummary[] devices)
    {
        var refresh = viewModel.RefreshAsync();
        client.ListRequests[^1].Complete(devices);
        await Done(refresh);
    }

    private static Task Done(Task task) => task.WaitAsync(TimeSpan.FromSeconds(3));
    private static Guid Identifier(int number) => Guid.ParseExact(number.ToString("x32", CultureInfo.InvariantCulture), "N");
    private static DeviceSummary Summary(int number) => new(Identifier(number), $"device{number:D4}",
        "Windows 11 24H2 10.0.26100.1", "healthy", Observation.AddMinutes(-number), "1.0.0",
        "Firewall enabled on all profiles", Observation.AddMinutes(-number));
    private static DeviceSummary MissingSummary(int number) => Summary(number) with
    {
        OperatingSystem = null, AgentVersion = null, SecurityPostureSummary = "Firewall status unknown", InventoryCollectedUtc = null
    };
    private static EndpointDetail Detail(DeviceSummary summary, bool inventory = true) => new(summary,
        inventory ? Observation : null, inventory ? "24H2 10.0.26100.1" : null, inventory ? "X64" : null,
        inventory ? new CpuInventory("Synthetic CPU", 4) : null, inventory ? 8_000_000_000 : null,
        inventory ? [new DiskInventory("Synthetic disk", 256_000, 128_000)] : [],
        inventory ? new SecurityPostureInventory(true, false, null, new WindowsSecurityConfiguration(UacEnabled: true, AutomaticUpdatesDisabled: true)) : null,
        inventory ? "Windows 11" : null);

    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }
    private static void Throws<TException>(Action action, string message) where TException : Exception
    {
        assertions++;
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException(message);
    }

    private sealed class ControlledClient : IDevicesClient, IDisposable
    {
        public List<ListRequest> ListRequests { get; } = [];
        public List<DetailRequest> DetailRequests { get; } = [];
        public int DisposeCalls { get; private set; }
        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken)
        {
            var request = new ListRequest(cancellationToken);
            ListRequests.Add(request);
            return request.Completion.Task;
        }
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken)
        {
            var request = new DetailRequest(endpointId, cancellationToken);
            DetailRequests.Add(request);
            return request.Completion.Task;
        }
        public void Dispose() => DisposeCalls++;
    }
    private sealed class ListRequest(CancellationToken cancellationToken)
    {
        public CancellationToken CancellationToken { get; } = cancellationToken;
        public TaskCompletionSource<DeviceReadResult<IReadOnlyList<DeviceSummary>>> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Complete(IReadOnlyList<DeviceSummary> summaries) => Completion.SetResult(new(DeviceReadOutcome.Success, summaries));
    }
    private sealed class DetailRequest(Guid endpointId, CancellationToken cancellationToken)
    {
        public Guid EndpointId { get; } = endpointId;
        public CancellationToken CancellationToken { get; } = cancellationToken;
        public TaskCompletionSource<DeviceReadResult<EndpointDetail>> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Complete(EndpointDetail detail) => Completion.SetResult(new(DeviceReadOutcome.Success, detail));
    }
}
