using System.Threading.Channels;
using SentinelAI.Desktop.Foundation;

internal static class AlertsViewModelConcurrencyTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset Observed = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static int assertions;

    public static async Task<int> RunAsync()
    {
        await CanceledEndpointOptionsAsync();
        await CanceledPageCannotExpireReplacementSessionAsync();
        await SupersededDetailsAsync();
        await CanceledDetailCannotExpireReplacementSessionAsync();
        await CanceledWritesAsync();
        await CanceledWriteCannotExpireReplacementSessionAsync();
        await CanceledWritePageCannotExpireReplacementSessionAsync();
        await PendingWriteGatesAsync();
        Console.WriteLine($"Desktop alerts concurrency: {assertions} assertions passed.");
        return assertions;
    }

    private static async Task CanceledEndpointOptionsAsync()
    {
        foreach (var dispose in new[] { false, true })
        foreach (var outcome in new[] { DeviceReadOutcome.Success, DeviceReadOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            vm.SeverityFilter = AlertSeverityFilter.High;
            vm.StatusFilter = AlertStatusFilter.Accepted;
            var loading = vm.RefreshAsync();
            var options = await client.TakeOptionsAsync();
            Check(vm.IsLoading && !loading.IsCompleted, "Endpoint options were not held as part of list loading.");
            Reset(vm, dispose);
            await options.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, dispose);
            options.Completion.SetResult(new(outcome,
                outcome == DeviceReadOutcome.Success ? [Device(Summary(1))] : null));
            await Done(loading);
            CheckCleared(vm, dispose);
            Check(client.PageCalls == 0 && expired == 0,
                "Canceled endpoint options started an alert read or expired a cleared session.");
            Check(client.DisposeCalls == 0, "The alert workspace disposed a shared client.");
        }
    }

    private static async Task CanceledPageCannotExpireReplacementSessionAsync()
    {
        foreach (var dispose in new[] { false, true })
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = Summary(2);
            await SeedAsync(vm, client, [old]);
            SelectFilters(vm);
            var loading = vm.ApplyFiltersAsync();
            var canceled = await client.TakePageAsync();
            Check(canceled.Query.EndpointId == old.EndpointId && canceled.Query.Severity == "high" &&
                  canceled.Query.Status == "open", "The held old-session query did not use its reviewed filters.");
            Reset(vm, dispose);
            await canceled.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, dispose);

            Task? replacement = null;
            PageRequest? current = null;
            var fresh = Summary(3);
            if (!dispose)
            {
                replacement = vm.RefreshAsync();
                var options = await client.TakeOptionsAsync();
                options.Completion.SetResult(new(DeviceReadOutcome.Success, [Device(fresh)]));
                current = await client.TakePageAsync();
                Check(current.Query == new AlertQuery(), "A replacement session retained old-session filters.");
            }

            canceled.Completion.SetResult(new(outcome,
                outcome == AlertOutcome.Success ? Page(canceled.Query, [old]) : null));
            await Done(loading);
            Check(expired == 0, "A canceled list response expired a replacement session.");
            if (dispose) CheckCleared(vm, disposed: true);
            else
            {
                Check(vm.IsLoading && !vm.CanRefresh && vm.VisibleAlerts.Count == 0 &&
                      vm.EndpointOptions.Count == 2 && vm.EndpointOptions[1].EndpointId == fresh.EndpointId,
                    "A canceled list response overwrote a replacement load or released its busy state.");
                current!.Completion.SetResult(new(AlertOutcome.Success, Page(current.Query, [fresh])));
                await Done(replacement!);
                Check(vm.ListState == AlertListState.Ready && vm.VisibleAlerts.Single().AlertId == fresh.AlertId &&
                      vm.CanRefresh && expired == 0, "The replacement session could not finish after a stale list response.");
            }
            Check(client.DisposeCalls == 0, "Clear or Dispose took ownership of the shared alert clients.");
        }
    }

    private static async Task SupersededDetailsAsync()
    {
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var first = Summary(4);
            var second = Summary(5);
            await SeedAsync(vm, client, [first, second]);
            var oldLoading = vm.OpenDetailAsync(first.AlertId);
            var old = await client.TakeDetailAsync();
            var newLoading = vm.OpenDetailAsync(second.AlertId);
            var current = await client.TakeDetailAsync();
            await old.CancellationObserved.Task.WaitAsync(Deadline);
            old.Completion.SetResult(new(outcome, outcome == AlertOutcome.Success ? Detail(first) : null));
            await Done(oldLoading);
            Check(vm.IsLoadingDetail && vm.Detail is null && expired == 0,
                "A superseded detail response overwrote or expired the current detail request.");
            current.Completion.SetResult(new(AlertOutcome.Success, Detail(second)));
            await Done(newLoading);
            Check(vm.DetailState == AlertDetailState.Ready && vm.Detail?.Row.AlertId == second.AlertId,
                "The current detail did not survive a superseded response.");

            vm.ProposedStatus = "accepted";
            var refresh = vm.RefreshDetailAsync();
            var closed = await client.TakeDetailAsync();
            vm.CloseDetail();
            await closed.CancellationObserved.Task.WaitAsync(Deadline);
            closed.Completion.SetResult(new(AlertOutcome.Unauthenticated));
            await Done(refresh);
            Check(vm.DetailState == AlertDetailState.None && vm.Detail is null && vm.ProposedStatus is null &&
                  vm.StatusMessage.Length == 0 && vm.DetailStatusText.Length == 0 && expired == 0 &&
                  vm.VisibleAlerts.Count == 2,
                "A response arriving after Back restored detail, erased the list, or expired the session.");
        }
    }

    private static async Task CanceledDetailCannotExpireReplacementSessionAsync()
    {
        foreach (var dispose in new[] { false, true })
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = Summary(6);
            await SeedAsync(vm, client, [old]);
            SelectFilters(vm);
            var loading = vm.OpenDetailAsync(old.AlertId);
            var canceled = await client.TakeDetailAsync();
            Reset(vm, dispose);
            await canceled.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, dispose);

            Task? replacement = null;
            DetailRequest? current = null;
            var fresh = Summary(7);
            if (!dispose)
            {
                await SeedAsync(vm, client, [fresh]);
                replacement = vm.OpenDetailAsync(fresh.AlertId);
                current = await client.TakeDetailAsync();
            }
            canceled.Completion.SetResult(new(outcome, outcome == AlertOutcome.Success ? Detail(old) : null));
            await Done(loading);
            Check(expired == 0, "Canceled detail authentication affected a replacement session.");
            if (dispose) CheckCleared(vm, disposed: true);
            else
            {
                Check(vm.IsLoadingDetail && vm.Detail is null && vm.VisibleAlerts.Single().AlertId == fresh.AlertId,
                    "A canceled detail response populated or cleared replacement-session data.");
                current!.Completion.SetResult(new(AlertOutcome.Success, Detail(fresh)));
                await Done(replacement!);
                Check(vm.Detail?.Row.AlertId == fresh.AlertId && vm.DetailState == AlertDetailState.Ready,
                    "Replacement detail did not finish after a canceled previous-session response.");
            }
        }
    }

    private static async Task CanceledWritesAsync()
    {
        foreach (var dispose in new[] { false, true })
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated, AlertOutcome.Indeterminate })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = Summary(8);
            await SeedDetailAsync(vm, client, old);
            SelectFilters(vm);
            vm.ProposedStatus = "accepted";
            var saving = vm.SaveStatusAsync("accepted");
            var canceled = await client.TakeWriteAsync();
            Check(canceled.AlertId == old.AlertId && canceled.Status == "accepted" && canceled.ExpectedVersion == old.Version,
                "A status write did not retain the reviewed alert and version.");
            Check(vm.IsSavingStatus && vm.StatusMessage.Length > 0,
                "The held status write had no pending state to clear.");
            Reset(vm, dispose);
            await canceled.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm, dispose);

            // Core may have committed before sign-out; its eventual success must
            // never reintroduce the old administrator's locally cleared data.
            canceled.Completion.SetResult(new(outcome,
                outcome == AlertOutcome.Success ? Detail(old with { Status = "accepted", Version = old.Version + 1 }) : null));
            await Done(saving);
            CheckCleared(vm, dispose);
            Check(client.PageCalls == 1 && client.DetailCalls == 1 && client.WriteCalls == 1 && expired == 0,
                "A canceled write replayed work, refreshed cleared data, or emitted a late expiry.");
            Check(client.DisposeCalls == 0, "The alert view model disposed shared clients after a pending write.");
        }
    }

    private static async Task CanceledWritePageCannotExpireReplacementSessionAsync()
    {
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = Summary(9);
            await SeedDetailAsync(vm, client, old);
            var saving = vm.SaveStatusAsync("resolved");
            var write = await client.TakeWriteAsync();
            var saved = old with { Status = "resolved", Version = old.Version + 1 };
            write.Completion.SetResult(new(AlertOutcome.Success, Detail(saved)));
            var canceledPage = await client.TakePageAsync();
            Check(vm.IsSavingStatus && vm.Detail?.Row.Status == "resolved",
                "The confirmed status was not held busy while its filtered page refreshed.");
            vm.Clear();
            await canceledPage.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm);

            var fresh = Summary(10);
            var replacement = vm.RefreshAsync();
            var options = await client.TakeOptionsAsync();
            options.Completion.SetResult(new(DeviceReadOutcome.Success, [Device(fresh)]));
            var current = await client.TakePageAsync();
            canceledPage.Completion.SetResult(new(outcome,
                outcome == AlertOutcome.Success ? Page(canceledPage.Query, [saved]) : null));
            await Done(saving);
            Check(expired == 0 && vm.IsLoading && !vm.IsSavingStatus && vm.Detail is null &&
                  vm.VisibleAlerts.Count == 0 && vm.EndpointOptions[1].EndpointId == fresh.EndpointId,
                "An old write's page response expired or populated the replacement session.");
            current.Completion.SetResult(new(AlertOutcome.Success, Page(current.Query, [fresh])));
            await Done(replacement);
            Check(vm.VisibleAlerts.Single().AlertId == fresh.AlertId && vm.ListState == AlertListState.Ready &&
                  client.WriteCalls == 1 && expired == 0,
                "Replacement data was lost or a committed old status write was retried.");
        }
    }

    private static async Task CanceledWriteCannotExpireReplacementSessionAsync()
    {
        foreach (var outcome in new[] { AlertOutcome.Success, AlertOutcome.Unauthenticated })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var expired = 0;
            vm.SessionExpired += (_, _) => expired++;
            var old = Summary(13);
            await SeedDetailAsync(vm, client, old);
            var saving = vm.SaveStatusAsync("accepted");
            var write = await client.TakeWriteAsync();
            vm.Clear();
            await write.CancellationObserved.Task.WaitAsync(Deadline);
            CheckCleared(vm);
            var fresh = Summary(14);
            await SeedAsync(vm, client, [fresh]);
            var opening = vm.OpenDetailAsync(fresh.AlertId);
            var current = await client.TakeDetailAsync();
            write.Completion.SetResult(new(outcome, outcome == AlertOutcome.Success
                ? Detail(old with { Status = "accepted", Version = old.Version + 1 }) : null));
            await Done(saving);
            Check(vm.VisibleAlerts.Single().AlertId == fresh.AlertId && vm.IsLoadingDetail && vm.Detail is null &&
                  expired == 0 && client.PageCalls == 2 && client.DetailCalls == 2 && client.WriteCalls == 1,
                "A canceled status result expired or replaced the new session's alert workspace.");
            current.Completion.SetResult(new(AlertOutcome.Success, Detail(fresh)));
            await Done(opening);
            Check(vm.Detail?.Row.AlertId == fresh.AlertId && vm.DetailState == AlertDetailState.Ready &&
                  vm.StatusMessage.Length == 0 && expired == 0,
                "An old status result leaked a message or prevented new-session detail from completing.");
        }
    }

    private static async Task PendingWriteGatesAsync()
    {
        var client = new ControlledClient();
        var vm = new AlertsViewModel(client, client);
        var first = Summary(11);
        var second = Summary(12);
        await SeedAsync(vm, client, [first, second], total: 100);
        var opening = vm.OpenDetailAsync(first.AlertId);
        var detail = await client.TakeDetailAsync();
        detail.Completion.SetResult(new(AlertOutcome.Success, Detail(first)));
        await Done(opening);
        vm.ProposedStatus = "accepted";
        var saving = vm.SaveStatusAsync("accepted");
        var write = await client.TakeWriteAsync();
        await CheckWriteGatesAsync(vm, client, first, second);
        Check(write.ExpectedVersion == first.Version && write.Status == "accepted",
            "Concurrent UI actions changed the reviewed write's version or proposed status.");
        var saved = first with { Status = "accepted", Version = first.Version + 1 };
        write.Completion.SetResult(new(AlertOutcome.Success, Detail(saved)));
        var page = await client.TakePageAsync();
        await CheckWriteGatesAsync(vm, client, saved, second, pageCalls: 2);
        page.Completion.SetResult(new(AlertOutcome.Success, Page(page.Query, [saved, second], total: 100)));
        await Done(saving);
        Check(!vm.IsSavingStatus && vm.CanRefresh && vm.CanNextPage && vm.Detail?.Version == saved.Version &&
              vm.Detail.Row.Status == "accepted" && vm.VisibleAlerts.Single(row => row.AlertId == first.AlertId).Version == saved.Version,
            "A completed write failed to release the UI gates or reconcile its authoritative version.");
        Check(vm.StatusMessage == "Status saved." && vm.ProposedStatus is null && client.WriteCalls == 1,
            "Duplicate Save caused another write or retained an obsolete proposed status.");
        vm.Dispose();
        vm.Dispose();
        CheckCleared(vm, disposed: true);
        Check(client.DisposeCalls == 0, "Disposing the workspace disposed authentication-owned clients.");
    }

    private static async Task CheckWriteGatesAsync(AlertsViewModel vm, ControlledClient client,
        AlertSummary reviewed, AlertSummary other, int pageCalls = 1)
    {
        Check(vm.IsSavingStatus && !vm.CanSaveStatus && !vm.CanRefresh && !vm.CanApplyFilters &&
              !vm.CanNextPage && !vm.CanPreviousPage,
            "A pending status write enabled an action that can change the reviewed workspace.");
        vm.CloseDetail();
        var ignored = new[]
        {
            vm.SaveStatusAsync("accepted"), vm.SaveStatusAsync("resolved"), vm.RefreshAsync(),
            vm.ApplyFiltersAsync(), vm.NextPageAsync(), vm.PreviousPageAsync(),
            vm.RefreshDetailAsync(), vm.OpenDetailAsync(other.AlertId)
        };
        await Task.WhenAll(ignored).WaitAsync(Deadline);
        Check(vm.Detail?.Row.AlertId == reviewed.AlertId && vm.Detail.Version == reviewed.Version && vm.IsSavingStatus,
            "Back, refresh, or a duplicate status action replaced a pending write's reviewed detail.");
        Check(client.WriteCalls == 1 && client.DetailCalls == 1 && client.PageCalls == pageCalls && client.OptionsCalls == 1,
            "Actions during a pending write caused duplicate writes or conflicting reads.");
    }

    private static async Task SeedAsync(AlertsViewModel vm, ControlledClient client,
        IReadOnlyList<AlertSummary> summaries, long? total = null)
    {
        var loading = vm.RefreshAsync();
        var options = await client.TakeOptionsAsync();
        options.Completion.SetResult(new(DeviceReadOutcome.Success,
            summaries.DistinctBy(summary => summary.EndpointId).Select(Device).ToArray()));
        var page = await client.TakePageAsync();
        page.Completion.SetResult(new(AlertOutcome.Success, Page(page.Query, summaries, total)));
        await Done(loading);
    }

    private static async Task SeedDetailAsync(AlertsViewModel vm, ControlledClient client, AlertSummary summary)
    {
        await SeedAsync(vm, client, [summary]);
        var loading = vm.OpenDetailAsync(summary.AlertId);
        var detail = await client.TakeDetailAsync();
        detail.Completion.SetResult(new(AlertOutcome.Success, Detail(summary)));
        await Done(loading);
    }

    private static void SelectFilters(AlertsViewModel vm)
    {
        vm.SelectedEndpoint = vm.EndpointOptions[1];
        vm.SeverityFilter = AlertSeverityFilter.High;
        vm.StatusFilter = AlertStatusFilter.Open;
    }

    private static void Reset(AlertsViewModel vm, bool dispose)
    {
        if (dispose) vm.Dispose();
        else vm.Clear();
    }

    private static void CheckCleared(AlertsViewModel vm, bool disposed = false)
    {
        Check(vm.ListState == AlertListState.NotLoaded && vm.VisibleAlerts.Count == 0 && vm.SelectedAlert is null &&
              vm.TotalAlerts == 0 && vm.TotalPages == 0 && vm.PageIndex == 0 && vm.PageNumber == 0,
            "Clearing the workspace retained old alert rows, selection, or page metadata.");
        Check(vm.EndpointOptions.Count == 1 && vm.EndpointOptions[0].EndpointId is null &&
              ReferenceEquals(vm.SelectedEndpoint, vm.EndpointOptions[0]) &&
              vm.SeverityFilter == AlertSeverityFilter.All && vm.StatusFilter == AlertStatusFilter.All && !vm.FiltersChanged,
            "Clearing the workspace retained endpoint names or old-session filters.");
        Check(vm.Detail is null && vm.DetailState == AlertDetailState.None && !vm.IsShowingDetail &&
              !vm.IsLoading && !vm.IsLoadingDetail && !vm.IsSavingStatus && !vm.NeedsDetailRefresh &&
              vm.ProposedStatus is null && vm.DetailStatusText.Length == 0 && vm.StatusMessage.Length == 0 && vm.ErrorText.Length == 0,
            "Clearing the workspace retained detail, proposed status, messages, or pending state.");
        Check(vm.CanRefresh == !disposed && !vm.CanSaveStatus && !vm.CanNextPage && !vm.CanPreviousPage,
            "Cleared or disposed workspace actions had an inconsistent lifetime.");
    }

    private static AlertSummary Summary(int value) => new(Identifier(value), Identifier(value + 100),
        $"synthetic-endpoint-{value}", "SA-FW001", $"Synthetic alert {value}", "high", "open",
        Observed, Observed, Observed, 7);
    private static Guid Identifier(int value) => Guid.Parse($"10000000-0000-0000-0000-{value:D12}");
    private static DeviceSummary Device(AlertSummary summary) => new(summary.EndpointId, summary.EndpointName,
        "Synthetic Windows", "healthy", Observed, "test-agent", "Synthetic posture", Observed);
    private static AlertDetail Detail(AlertSummary summary) => new(summary, "Synthetic reason",
        [new("domainFirewallEnabled", AlertEvidenceKind.Boolean, BooleanValue: false)],
        "Synthetic recommendation", Observed, Observed,
        [new(null, summary.Status, Observed, "system")], 1);
    private static AlertPage Page(AlertQuery query, IReadOnlyList<AlertSummary> summaries, long? total = null) =>
        new(summaries, total ?? summaries.Count, query.Offset, query.Limit);
    private static Task Done(Task task) => task.WaitAsync(Deadline);
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    // Deliberately ignores cancellation: the server can finish after a session
    // closes, so the view model must reject late results independently of I/O.
    private class Request<T>
    {
        public Request(CancellationToken token)
        {
            CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
            token.Register(() => CancellationObserved.TrySetResult());
        }
        public TaskCompletionSource<T> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CancellationObserved { get; }
    }

    private sealed class PageRequest(AlertQuery query, CancellationToken token) : Request<AlertResult<AlertPage>>(token)
    {
        public AlertQuery Query { get; } = query;
    }
    private sealed class DetailRequest(Guid alertId, CancellationToken token) : Request<AlertResult<AlertDetail>>(token)
    {
        public Guid AlertId { get; } = alertId;
    }
    private sealed class WriteRequest(Guid alertId, string status, long expectedVersion, CancellationToken token)
        : Request<AlertResult<AlertDetail>>(token)
    {
        public Guid AlertId { get; } = alertId;
        public string Status { get; } = status;
        public long ExpectedVersion { get; } = expectedVersion;
    }

    private sealed class ControlledClient : IAlertsClient, IDevicesClient, IDisposable
    {
        private readonly Channel<Request<DeviceReadResult<IReadOnlyList<DeviceSummary>>>> options = Channel.CreateUnbounded<Request<DeviceReadResult<IReadOnlyList<DeviceSummary>>>>();
        private readonly Channel<PageRequest> pages = Channel.CreateUnbounded<PageRequest>();
        private readonly Channel<DetailRequest> details = Channel.CreateUnbounded<DetailRequest>();
        private readonly Channel<WriteRequest> writes = Channel.CreateUnbounded<WriteRequest>();
        private int optionsCalls, pageCalls, detailCalls, writeCalls, disposeCalls;
        public int OptionsCalls => Volatile.Read(ref optionsCalls);
        public int PageCalls => Volatile.Read(ref pageCalls);
        public int DetailCalls => Volatile.Read(ref detailCalls);
        public int WriteCalls => Volatile.Read(ref writeCalls);
        public int DisposeCalls => Volatile.Read(ref disposeCalls);
        public Task<Request<DeviceReadResult<IReadOnlyList<DeviceSummary>>>> TakeOptionsAsync() => options.Reader.ReadAsync().AsTask().WaitAsync(Deadline);
        public Task<PageRequest> TakePageAsync() => pages.Reader.ReadAsync().AsTask().WaitAsync(Deadline);
        public Task<DetailRequest> TakeDetailAsync() => details.Reader.ReadAsync().AsTask().WaitAsync(Deadline);
        public Task<WriteRequest> TakeWriteAsync() => writes.Reader.ReadAsync().AsTask().WaitAsync(Deadline);

        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken)
        {
            var request = new Request<DeviceReadResult<IReadOnlyList<DeviceSummary>>>(cancellationToken);
            Interlocked.Increment(ref optionsCalls);
            options.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The alert endpoint filter must not read endpoint inventory detail.");
        public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken cancellationToken)
        {
            var request = new PageRequest(query, cancellationToken);
            Interlocked.Increment(ref pageCalls);
            pages.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken cancellationToken)
        {
            var request = new DetailRequest(alertId, cancellationToken);
            Interlocked.Increment(ref detailCalls);
            details.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status, long expectedVersion,
            CancellationToken cancellationToken)
        {
            var request = new WriteRequest(alertId, status, expectedVersion, cancellationToken);
            Interlocked.Increment(ref writeCalls);
            writes.Writer.TryWrite(request);
            return request.Completion.Task;
        }
        public void Dispose() => Interlocked.Increment(ref disposeCalls);
    }
}
