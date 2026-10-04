using System.Globalization;
using SentinelAI.Desktop.Foundation;

internal static class AlertsViewModelTests
{
    private static int assertions;
    private static readonly DateTimeOffset Observation = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    public static async Task<int> RunAsync()
    {
        PresentationTests();
        await QueriesOptionsAndPagingAsync();
        await ReadStatesAsync();
        await ReviewedStatusAsync();
        await ConflictAsync();
        await IndeterminateAsync();
        await ShrinkingLastPageAsync();
        Console.WriteLine($"Desktop alerts: {assertions} assertions passed.");
        return assertions;
    }

    private static void PresentationTests()
    {
        const string literal = "<script>alert('literal')</script> {Binding Password} https://example.invalid";
        var summary = Summary(1) with { EndpointName = literal, RuleId = literal, Title = literal };
        var detail = Detail(summary) with
        {
            Reason = literal, RecommendedAction = literal,
            Evidence = new[]
            {
                new AlertEvidence(literal, AlertEvidenceKind.Boolean, BooleanValue: false),
                new AlertEvidence("count", AlertEvidenceKind.Integer, IntegerValue: -123456789),
                new AlertEvidence("value", AlertEvidenceKind.String, StringValue: literal),
                new AlertEvidence("missing", AlertEvidenceKind.Boolean),
                new AlertEvidence("future", (AlertEvidenceKind)999, StringValue: literal)
            },
            StatusHistory = new[]
            {
                new AlertStatusChange(null, "open", Observation, "system"),
                new AlertStatusChange("open", "resolved", Observation.AddMinutes(1), literal),
                new AlertStatusChange("resolved", "open", Observation.AddMinutes(2), "system"),
                new AlertStatusChange("resolved", "open", Observation.AddMinutes(3), literal)
            }, StatusHistoryCount = 4
        };
        var presentation = new AlertPresentation(detail);
        Check(presentation.Name == literal && presentation.Reason == literal && presentation.RecommendedAction == literal, "Alert content was interpreted or modified instead of remaining literal text.");
        Check(presentation.Row.EndpointName == literal && presentation.Row.RuleId == literal, "Endpoint/rule text was not preserved literally.");
        Check(presentation.Evidence[0] == new AlertEvidenceRow(literal, "Boolean", "False"), "False Boolean evidence was lost or inferred.");
        Check(presentation.Evidence[1].Value == "-123456789" && presentation.Evidence[1].TypeLabel == "Integer", "Integer evidence lost its type or value.");
        Check(presentation.Evidence[2].Value == literal && presentation.Evidence[2].Kind == "String", "String evidence was treated as markup.");
        Check(presentation.Evidence[3].Value == "Unknown" && presentation.Evidence[4].Kind == "Unknown" && presentation.Evidence[4].DisplayValue == "Unknown", "Missing or future evidence was inferred.");
        Check(presentation.History[0].PreviousStatus == "None" && presentation.History[0].ChangeType == "Created", "Initial history was not explicitly marked as creation.");
        Check(presentation.History[1].Status == "Resolved" && presentation.History[1].ChangedBy == literal, "Core status/actor history was not preserved.");
        Check(presentation.History[2].ChangeType == "Reopened" && presentation.History[3].ChangeType == "Status changed", "A manual transition was inferred to be a Core reopening.");
        Check(presentation.HistoryDisclosure == "Showing the last 4 of 4 status changes.", "History count disclosure was incorrect.");
        Check(presentation.Facts.Single(fact => fact.Label == "Alert ID").Value == summary.AlertId.ToString("D") &&
            presentation.Facts.Single(fact => fact.Label == "Endpoint ID").Value == summary.EndpointId.ToString("D") &&
            presentation.Facts.Single(fact => fact.Label == "Version").Value == "1" &&
            presentation.Facts.Single(fact => fact.Label == "Status").Value == "Open", "Required public identity, status or reviewed-version facts were missing.");
        Check(((ICollection<DisplayFact>)presentation.Facts).IsReadOnly && ((ICollection<AlertEvidenceRow>)presentation.Evidence).IsReadOnly &&
            ((ICollection<AlertHistoryRow>)presentation.History).IsReadOnly, "A native view could mutate Core presentation data.");
        var retained = new AlertPresentation(detail with
        {
            StatusHistory = Enumerable.Range(0, 105).Select(index => new AlertStatusChange("open", "investigating", Observation.AddMinutes(index), $"actor-{index}")).ToArray(),
            StatusHistoryCount = 205
        });
        Check(retained.History.Count == 100 && retained.History[0].ChangedBy == "actor-5" && retained.History[^1].ChangedBy == "actor-104", "History did not retain only the latest 100 chronological changes.");
        Check(retained.HistoryDisclosure == "Showing the last 100 of 205 status changes.", "Retained history obscured the total count.");
        Check(new AlertPresentation(detail with { StatusHistory = Array.Empty<AlertStatusChange>(), StatusHistoryCount = 0 }).HistoryDisclosure == "No status history reported.", "Missing history was not explicit.");
        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("pl-PL");
            var row = new AlertRow(summary with { FirstObservedUtc = Observation.ToOffset(TimeSpan.FromHours(3)) });
            Check(row.FirstObservedText == "2026-10-04 12:00:00 UTC" && row.LastObservedText.EndsWith(" UTC", StringComparison.Ordinal), "Alert observations were not culture-independent explicit UTC.");
        }
        finally { CultureInfo.CurrentCulture = previousCulture; }
        Check(new AlertRow(summary with { Status = "future", Severity = "future" }).StatusLabel == "Unknown" &&
            new AlertRow(summary with { Severity = "future" }).SeverityLabel == "Unknown", "A future lifecycle/severity was inferred.");
        var option = new AlertEndpointOption(summary.EndpointId, literal);
        Check(option.DisplayName == $"{literal} ({summary.EndpointId:D})" && new AlertEndpointOption(null, "ignored").DisplayName == "All endpoints", "Endpoint filters lacked unambiguous public IDs.");
        Throws<ArgumentNullException>(() => _ = new AlertRow(null!), "Null alert summary was accepted.");
        Throws<ArgumentNullException>(() => _ = new AlertPresentation(null!), "Null alert detail was accepted.");
    }

    private static async Task QueriesOptionsAndPagingAsync()
    {
        var client = new ControlledClient();
        using var vm = new AlertsViewModel(client, client);
        Check(vm.ListState == AlertListState.NotLoaded && vm.EndpointOptions.Count == 1 && vm.VisibleAlerts.Count == 0, "Alerts began with fabricated data or endpoint options.");
        var notifications = new List<string?>();
        vm.PropertyChanged += (_, args) => notifications.Add(args.PropertyName);
        var first = vm.RefreshAsync();
        Check(vm.IsLoading && !vm.CanRefresh && !first.IsCompleted && client.DeviceCalls == 1, "Initial alert loading blocked or failed to fetch endpoint options.");
        Check(ReferenceEquals(first, vm.RefreshAsync()) && client.Pages.Count == 1, "Concurrent refreshes duplicated alert requests.");
        Check(client.Pages[0].Query == new AlertQuery(), "Initial list did not use the fixed server-side 50-row query.");
        client.Pages[0].Complete(Page(client.Pages[0].Query, 121, Enumerable.Range(1, 50).Select(Summary)));
        await Done(first);
        Check(vm.ListState == AlertListState.Ready && vm.VisibleAlerts.Count == 50 && vm.PageNumber == 1 && vm.TotalPages == 3 && vm.TotalAlerts == 121, "Initial server page/counts were incorrect.");
        Check(vm.CanNextPage && !vm.CanPreviousPage && !vm.FiltersChanged, "Initial paging controls were incorrect.");
        Check(vm.EndpointOptions.Count == 3 && vm.EndpointOptions[1].DisplayName != vm.EndpointOptions[2].DisplayName, "Same-hostname endpoint options were not disambiguated.");
        Check(((ICollection<AlertRow>)vm.VisibleAlerts).IsReadOnly && ((ICollection<AlertEndpointOption>)vm.EndpointOptions).IsReadOnly, "The view could mutate list/options.");
        Check(notifications.Contains(nameof(vm.VisibleAlerts)) && notifications.Contains(nameof(vm.IsLoading)) && notifications.Contains(nameof(vm.EndpointOptions)), "Loading/list/filter binding notifications were missing.");
        var next = vm.NextPageAsync();
        Check(client.Pages[^1].Query.Offset == 50 && client.DeviceCalls == 1, "Paging refetched devices or used an incorrect offset.");
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 121, Enumerable.Range(51, 50).Select(Summary)));
        await Done(next);
        Check(vm.PageIndex == 1 && vm.CanPreviousPage && vm.CanNextPage, "The middle page state was incorrect.");
        next = vm.NextPageAsync();
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 121, Enumerable.Range(101, 21).Select(Summary)));
        await Done(next);
        Check(vm.PageNumber == 3 && vm.VisibleAlerts.Count == 21 && !vm.CanNextPage, "The final page was not bounded by Core's result.");
        var calls = client.Pages.Count;
        await Done(vm.NextPageAsync());
        Check(client.Pages.Count == calls, "Next fetched beyond the final server page.");

        vm.SelectedEndpoint = vm.EndpointOptions.Single(option => option.EndpointId == Id(2));
        vm.SeverityFilter = AlertSeverityFilter.Critical;
        vm.StatusFilter = AlertStatusFilter.Investigating;
        Check(vm.FiltersChanged && !vm.CanNextPage && !vm.CanPreviousPage && client.Pages.Count == calls, "Staged filters triggered network requests or allowed paging a stale query.");
        var filtered = vm.ApplyFiltersAsync();
        var query = client.Pages[^1].Query;
        Check(query == new AlertQuery(Id(2), "critical", "investigating", 0, 50) && client.DeviceCalls == 1, "Endpoint/severity/status filters were not sent together before server paging.");
        client.Pages[^1].Complete(Page(query, 1, new[] { Summary(7) with { EndpointId = Id(2), Status = "investigating" } }));
        await Done(filtered);
        Check(!vm.FiltersChanged && vm.PageIndex == 0 && vm.TotalAlerts == 1, "Applying filters did not reset paging and mark the query current.");
        var selectedOption = vm.SelectedEndpoint;
        var refresh = vm.RefreshAsync();
        Check(client.DeviceCalls == 2 && ReferenceEquals(selectedOption, vm.SelectedEndpoint), "Explicit refresh did not refresh endpoint options or needlessly replaced the selection.");
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 0, Array.Empty<AlertSummary>()));
        await Done(refresh);
        Check(vm.ListState == AlertListState.Empty && vm.PageNumber == 0 && !vm.CanSaveStatus, "Filtered-empty was not explicitly represented.");
        vm.SelectedEndpoint = vm.EndpointOptions[0];
        vm.SeverityFilter = AlertSeverityFilter.All;
        vm.StatusFilter = AlertStatusFilter.All;
        var clearFilters = vm.ApplyFiltersAsync();
        Check(client.Pages[^1].Query == new AlertQuery(), "All filters were not represented as absent server parameters.");
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 0, Array.Empty<AlertSummary>()));
        await Done(clearFilters);
        Throws<ArgumentException>(() => vm.SelectedEndpoint = new AlertEndpointOption(Id(3), "outsider"), "An endpoint outside the public options was accepted.");
        Throws<ArgumentException>(() => vm.SelectedAlert = new AlertRow(Summary(99)), "An alert outside the current page was accepted.");
        Throws<ArgumentOutOfRangeException>(() => vm.SeverityFilter = (AlertSeverityFilter)999, "An undefined severity filter was accepted.");
        Throws<ArgumentOutOfRangeException>(() => vm.StatusFilter = (AlertStatusFilter)999, "An undefined status filter was accepted.");
        Check(client.DisposeCalls == 0, "The view model disposed its shared authentication client.");
    }

    private static async Task ReadStatesAsync()
    {
        foreach (var outcome in new[] { AlertOutcome.Unavailable, AlertOutcome.UntrustedConnection, AlertOutcome.InvalidResponse, AlertOutcome.TooLarge })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            var task = vm.RefreshAsync();
            client.Pages[0].Complete(new AlertResult<AlertPage>(outcome));
            await Done(task);
            Check(vm.ListState == AlertListState.Unavailable && vm.VisibleAlerts.Count == 0 && vm.ErrorText.Length > 0 && vm.CanRefresh, $"{outcome} did not produce a safe, retryable list failure.");
        }
        var failedDevices = new ControlledClient { DeviceOutcome = DeviceReadOutcome.Unavailable };
        using (var vm = new AlertsViewModel(failedDevices, failedDevices))
        {
            await Done(vm.RefreshAsync());
            Check(vm.ListState == AlertListState.Unavailable && failedDevices.Pages.Count == 0, "Unavailable endpoint filters were silently replaced by fabricated choices.");
        }
        var client2 = new ControlledClient();
        using var vm2 = new AlertsViewModel(client2, client2);
        var invalid = vm2.RefreshAsync();
        client2.Pages[0].Complete(new AlertResult<AlertPage>(AlertOutcome.Success, new AlertPage(new[] { Summary(1) }, 1, 99, 50)));
        await Done(invalid);
        Check(vm2.ListState == AlertListState.Unavailable, "A server page for the wrong offset was accepted.");
        var throws = vm2.RefreshAsync();
        client2.Pages[^1].Fail(new InvalidOperationException("private diagnostic"));
        await Done(throws);
        Check(vm2.ListState == AlertListState.Unavailable && !vm2.ErrorText.Contains("private diagnostic", StringComparison.Ordinal), "A transport exception leaked into product UI.");
        await Seed(vm2, client2, Summary(1));
        var missing = vm2.OpenDetailAsync(Summary(99).AlertId);
        await Done(missing);
        Check(vm2.DetailState == AlertDetailState.NotFound && client2.Details.Count == 0, "An arbitrary alert ID triggered an unreviewed detail request.");
        var detailTask = vm2.OpenDetailAsync(Summary(1).AlertId);
        Check(vm2.IsLoadingDetail && !vm2.CanSaveStatus && ReferenceEquals(detailTask, vm2.OpenDetailAsync(Summary(1).AlertId)), "Duplicate detail opens did not coalesce or failed to expose loading.");
        client2.Details[^1].Complete(new(AlertOutcome.NotFound));
        await Done(detailTask);
        Check(vm2.DetailState == AlertDetailState.NotFound && vm2.Detail is null && vm2.DetailStatusText.Contains("no longer", StringComparison.Ordinal), "A disappeared tracked alert was not explicit.");
        vm2.CloseDetail();
        Check(!vm2.IsShowingDetail && vm2.DetailState == AlertDetailState.None, "Back did not restore the list workspace.");
        detailTask = vm2.OpenDetailAsync(Summary(1).AlertId);
        client2.Details[^1].Complete(new(AlertOutcome.Success, Detail(Summary(2))));
        await Done(detailTask);
        Check(vm2.DetailState == AlertDetailState.Unavailable && vm2.Detail is null, "Detail from a different alert was accepted.");
    }

    private static async Task ReviewedStatusAsync()
    {
        var client = new ControlledClient();
        using var vm = new AlertsViewModel(client, client);
        var summary = Summary(1) with { Version = 8 };
        await Seed(vm, client, summary);
        await Open(vm, client, Detail(summary));
        Check(vm.DetailState == AlertDetailState.Ready && !vm.CanSaveStatus && vm.ProposedStatus is null, "Opening detail silently selected a status write.");
        vm.ProposedStatus = "open";
        Check(!vm.CanSaveStatus, "An unchanged status was writable.");
        vm.ProposedStatus = "investigating";
        Check(vm.CanSaveStatus, "A reviewed explicit status choice was not writable.");
        Throws<ArgumentException>(() => vm.ProposedStatus = "closed", "An unsupported status was accepted.");
        var save = vm.SaveStatusAsync("investigating");
        var request = client.Writes[^1];
        Check(request.AlertId == summary.AlertId && request.Status == "investigating" && request.Version == 8, "The write did not use the exact reviewed alert version/status.");
        Check(vm.IsSavingStatus && !vm.CanSaveStatus && !vm.CanRefresh && vm.ProposedStatus is null, "A pending write allowed another mutation or list reload.");
        vm.CloseDetail();
        await Done(vm.RefreshAsync());
        await Done(vm.SaveStatusAsync("resolved"));
        Check(vm.IsShowingDetail && client.Writes.Count == 1 && client.Pages.Count == 1, "Back/refresh/repeated saves bypassed a pending reviewed write.");
        var changed = Detail(summary with { Status = "investigating", Version = 9 }) with
        {
            StatusHistory = new[] { new AlertStatusChange(null, "open", Observation, "system"), new AlertStatusChange("open", "investigating", Observation.AddMinutes(1), "administrator") },
            StatusHistoryCount = 2
        };
        request.Complete(new(AlertOutcome.Success, changed));
        await Until(() => client.Pages.Count == 2);
        Check(vm.Detail!.Version == 9 && vm.Detail.Row.Status == "investigating" && vm.VisibleAlerts.Single().Version == 9, "Confirmed authoritative detail/list versions were not reconciled before the page read.");
        Check(vm.Detail.History[^1].ChangedBy == "administrator" && vm.StatusMessage == "Status saved.", "Confirmed history or save feedback was lost.");
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 1, new[] { changed.Alert }));
        await Done(save);
        Check(client.Writes.Count == 1 && client.DeviceCalls == 1 && !vm.IsSavingStatus && vm.ProposedStatus is null && !vm.CanSaveStatus, "Confirmed save replayed a mutation/options fetch or retained the old choice.");
        vm.ProposedStatus = "resolved";
        Check(vm.CanSaveStatus && vm.Detail.Version == 9, "A fresh explicit operator choice did not use the newly reviewed version.");
    }

    private static async Task ConflictAsync()
    {
        var client = new ControlledClient();
        using var vm = new AlertsViewModel(client, client);
        await Seed(vm, client, Summary(1));
        await Open(vm, client, Detail(Summary(1)));
        vm.ProposedStatus = "accepted";
        var save = vm.SaveStatusAsync("accepted");
        client.Writes[^1].Complete(new(AlertOutcome.Conflict));
        await Until(() => client.Details.Count == 2);
        Check(client.Writes.Count == 1 && vm.IsSavingStatus, "Conflict replayed the operator's stale write.");
        var latest = Detail(Summary(1) with { Version = 3, Status = "resolved" });
        client.Details[^1].Complete(new(AlertOutcome.Success, latest));
        await Until(() => client.Pages.Count == 2);
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, 1, new[] { latest.Alert }));
        await Done(save);
        Check(client.Details.Count == 2 && client.Writes.Count == 1 && vm.Detail!.Version == 3 && vm.Detail.Row.Status == "resolved", "409 did not perform exactly one fresh authoritative detail read without write replay.");
        Check(vm.StatusMessage.Contains("not saved", StringComparison.Ordinal) && vm.ProposedStatus is null && !vm.CanSaveStatus && !vm.NeedsDetailRefresh, "409 hid its failed choice or did not require a fresh operator selection.");
        vm.ProposedStatus = "open";
        Check(vm.CanSaveStatus, "A conflict's fresh reviewed detail did not allow a new explicit choice.");
        save = vm.SaveStatusAsync("open");
        Check(client.Writes[^1].Version == 3, "The next explicit write reused the stale pre-conflict version.");
        client.Writes[^1].Complete(new(AlertOutcome.Conflict));
        await Until(() => client.Details.Count == 3);
        client.Details[^1].Complete(new(AlertOutcome.Unavailable));
        await Done(save);
        Check(vm.NeedsDetailRefresh && !vm.CanSaveStatus && vm.StatusMessage.Contains("not saved", StringComparison.Ordinal) && client.Writes.Count == 2 && client.Details.Count == 3, "Failed conflict reload allowed stale writes or repeated the read automatically.");
    }

    private static async Task IndeterminateAsync()
    {
        foreach (var failByException in new[] { false, true })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            await Seed(vm, client, Summary(1));
            await Open(vm, client, Detail(Summary(1)));
            vm.ProposedStatus = "resolved";
            var save = vm.SaveStatusAsync("resolved");
            if (failByException) client.Writes[^1].Fail(new IOException("private socket diagnostic"));
            else client.Writes[^1].Complete(new(AlertOutcome.Indeterminate));
            await Done(save);
            Check(vm.NeedsDetailRefresh && !vm.CanSaveStatus && vm.ProposedStatus is null && !vm.IsSavingStatus, "An unconfirmed write left stale detail writable.");
            Check(vm.StatusMessage == "Status change could not be confirmed. Refresh latest detail before choosing a status again." && vm.ErrorText.Length == 0, "Unconfirmed-write feedback was missing, leaked diagnostics or duplicated messages.");
            Check(client.Writes.Count == 1 && client.Details.Count == 1 && client.Pages.Count == 1, "An indeterminate mutation was automatically retried or assumed committed by an automatic read.");
            vm.ProposedStatus = "accepted";
            await Done(vm.SaveStatusAsync("accepted"));
            Check(!vm.CanSaveStatus && client.Writes.Count == 1, "Choosing another status bypassed the mandatory fresh detail review.");
            var refresh = vm.RefreshDetailAsync();
            client.Details[^1].Complete(new(AlertOutcome.Success, Detail(Summary(1) with { Status = "resolved", Version = 2 })));
            await Done(refresh);
            Check(!vm.NeedsDetailRefresh && vm.Detail!.Version == 2 && vm.ProposedStatus is null && !vm.CanSaveStatus, "Explicit detail refresh did not replace the unconfirmed reviewed version and reset the choice.");
            vm.ProposedStatus = "accepted";
            Check(vm.CanSaveStatus, "A freshly reviewed detail could not accept a new explicit status choice.");
        }
    }

    private static async Task ShrinkingLastPageAsync()
    {
        foreach (var conflict in new[] { false, true })
        {
            var client = new ControlledClient();
            using var vm = new AlertsViewModel(client, client);
            vm.StatusFilter = AlertStatusFilter.Open;
            var load = vm.RefreshAsync();
            client.Pages[^1].Complete(Page(client.Pages[^1].Query, 51, Enumerable.Range(1, 50).Select(Summary)));
            await Done(load);
            var next = vm.NextPageAsync();
            var last = Summary(51);
            client.Pages[^1].Complete(Page(client.Pages[^1].Query, 51, new[] { last }));
            await Done(next);
            Check(vm.PageNumber == 2 && vm.TotalPages == 2 && vm.VisibleAlerts.Single().AlertId == last.AlertId, "The final filtered-page fixture was not established.");
            await Open(vm, client, Detail(last));
            vm.ProposedStatus = "resolved";
            var save = vm.SaveStatusAsync("resolved");
            var updated = Detail(last with { Status = "resolved", Version = 2 });
            if (conflict)
            {
                client.Writes[^1].Complete(new(AlertOutcome.Conflict));
                await Until(() => client.Details.Count == 2);
                client.Details[^1].Complete(new(AlertOutcome.Success, updated));
            }
            else client.Writes[^1].Complete(new(AlertOutcome.Success, updated));
            await Until(() => client.Pages.Count == 3);
            Check(client.Pages[^1].Query == new AlertQuery(Status: "open", Offset: 50), "Post-write refresh lost the applied status filter or current page.");
            client.Pages[^1].Complete(Page(client.Pages[^1].Query, 50, Array.Empty<AlertSummary>()));
            await Until(() => client.Pages.Count == 4);
            Check(client.Pages[^1].Query == new AlertQuery(Status: "open", Offset: 0), "A shrinking last page did not request the last valid 50-row offset.");
            client.Pages[^1].Complete(Page(client.Pages[^1].Query, 50, Enumerable.Range(1, 50).Select(Summary)));
            await Done(save);
            Check(vm.PageNumber == 1 && vm.TotalPages == 1 && vm.PageIndex == 0 && vm.VisibleAlerts.Count == 50 && vm.TotalAlerts == 50 && !vm.CanPreviousPage && !vm.CanNextPage, "A removed final matching row produced an impossible page or stale paging controls.");
            Check(vm.Detail!.Version == 2 && vm.Detail.Row.Status == "resolved" && vm.IsShowingDetail &&
                vm.StatusMessage == (conflict ? "Status was not saved because the alert changed. Review the latest detail and choose again." : "Status saved."), "Correcting the page erased authoritative detail or mutation/conflict feedback.");
            Check(client.Writes.Count == 1 && client.Pages.Count == 4 && client.DeviceCalls == 1 && client.Details.Count == (conflict ? 2 : 1), "Page correction replayed a write or used unbounded reads/options reloads.");
        }

        var shrinking = new ControlledClient();
        using var normal = new AlertsViewModel(shrinking, shrinking);
        var first = normal.RefreshAsync();
        shrinking.Pages[^1].Complete(Page(shrinking.Pages[^1].Query, 51, Enumerable.Range(1, 50).Select(Summary)));
        await Done(first);
        var staleNext = normal.NextPageAsync();
        shrinking.Pages[^1].Complete(Page(shrinking.Pages[^1].Query, 0, Array.Empty<AlertSummary>()));
        await Until(() => shrinking.Pages.Count == 3);
        Check(shrinking.Pages[^1].Query.Offset == 0, "A list-only shrink to zero retained a stale offset.");
        shrinking.Pages[^1].Complete(Page(shrinking.Pages[^1].Query, 0, Array.Empty<AlertSummary>()));
        await Done(staleNext);
        Check(normal.ListState == AlertListState.Empty && normal.PageIndex == 0 && normal.PageNumber == 0 && !normal.CanPreviousPage, "An empty fleet left stale Previous navigation enabled.");
    }

    private static async Task Seed(AlertsViewModel vm, ControlledClient client, params AlertSummary[] alerts)
    {
        var task = vm.RefreshAsync();
        client.Pages[^1].Complete(Page(client.Pages[^1].Query, alerts.Length, alerts));
        await Done(task);
    }
    private static async Task Open(AlertsViewModel vm, ControlledClient client, AlertDetail detail)
    {
        var task = vm.OpenDetailAsync(detail.Alert.AlertId);
        client.Details[^1].Complete(new(AlertOutcome.Success, detail));
        await Done(task);
    }
    private static AlertPage Page(AlertQuery query, long total, IEnumerable<AlertSummary> alerts) => new(alerts.ToArray(), total, query.Offset, query.Limit);
    private static AlertSummary Summary(int number) => new(Id(number + 1000), Id(1), "same-host", "firewall.disabled", "Configured firewall disabled", "critical", "open", Observation, Observation.AddMinutes(1), Observation.AddMinutes(1), 1);
    private static AlertDetail Detail(AlertSummary summary) => new(summary, "Configured firewall observation", new[] { new AlertEvidence("domainEnabled", AlertEvidenceKind.Boolean, BooleanValue: false) }, "Review the endpoint firewall configuration.", Observation, Observation, new[] { new AlertStatusChange(null, "open", Observation, "system") }, 1);
    private static Guid Id(int number) => Guid.ParseExact(number.ToString("x32", CultureInfo.InvariantCulture), "N");
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }
    private static void Throws<T>(Action action, string message) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new InvalidOperationException(message);
    }
    private static async Task Done(Task task) => await task.WaitAsync(TimeSpan.FromSeconds(5));
    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline) throw new TimeoutException("Expected alert client operation did not start.");
            await Task.Delay(1);
        }
    }

    private sealed class Request<T>(CancellationToken cancellation)
    {
        private readonly TaskCompletionSource<AlertResult<T>> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken Cancellation { get; } = cancellation;
        public Task<AlertResult<T>> Task => completion.Task;
        public void Complete(AlertResult<T> result) => completion.SetResult(result);
        public void Complete(T value) => Complete(new AlertResult<T>(AlertOutcome.Success, value));
        public void Fail(Exception error) => completion.SetException(error);
    }
    private sealed record PageRequest(AlertQuery Query, Request<AlertPage> Response)
    {
        public void Complete(AlertPage page) => Response.Complete(page);
        public void Complete(AlertResult<AlertPage> result) => Response.Complete(result);
        public void Fail(Exception error) => Response.Fail(error);
    }
    private sealed record DetailRequest(Guid AlertId, Request<AlertDetail> Response)
    {
        public void Complete(AlertResult<AlertDetail> result) => Response.Complete(result);
    }
    private sealed record WriteRequest(Guid AlertId, string Status, long Version, Request<AlertDetail> Response)
    {
        public void Complete(AlertResult<AlertDetail> result) => Response.Complete(result);
        public void Fail(Exception error) => Response.Fail(error);
    }
    private sealed class ControlledClient : IAlertsClient, IDevicesClient, IDisposable
    {
        private readonly object gate = new();
        private readonly List<PageRequest> pages = [];
        private readonly List<DetailRequest> details = [];
        private readonly List<WriteRequest> writes = [];
        private int deviceCalls;
        public DeviceReadOutcome DeviceOutcome { get; init; } = DeviceReadOutcome.Success;
        public int DisposeCalls { get; private set; }
        public int DeviceCalls { get { lock (gate) return deviceCalls; } }
        public IReadOnlyList<PageRequest> Pages { get { lock (gate) return pages.ToArray(); } }
        public IReadOnlyList<DetailRequest> Details { get { lock (gate) return details.ToArray(); } }
        public IReadOnlyList<WriteRequest> Writes { get { lock (gate) return writes.ToArray(); } }
        public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken cancellationToken)
        {
            var request = new Request<AlertPage>(cancellationToken);
            lock (gate) pages.Add(new(query, request));
            return request.Task;
        }
        public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken cancellationToken)
        {
            var request = new Request<AlertDetail>(cancellationToken);
            lock (gate) details.Add(new(alertId, request));
            return request.Task;
        }
        public Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status, long expectedVersion, CancellationToken cancellationToken)
        {
            var request = new Request<AlertDetail>(cancellationToken);
            lock (gate) writes.Add(new(alertId, status, expectedVersion, request));
            return request.Task;
        }
        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken)
        {
            lock (gate) deviceCalls++;
            IReadOnlyList<DeviceSummary> endpoints = new[]
            {
                new DeviceSummary(Id(2), "same-host", null, "unknown", null, null, "Firewall status unknown"),
                new DeviceSummary(Id(1), "same-host", null, "unknown", null, null, "Firewall status unknown")
            };
            return Task.FromResult(new DeviceReadResult<IReadOnlyList<DeviceSummary>>(DeviceOutcome, DeviceOutcome == DeviceReadOutcome.Success ? endpoints : null));
        }
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public void Dispose() => DisposeCalls++;
    }
}
