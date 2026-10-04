using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Interop;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    private static async Task AlertsViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "alerts-test");
        var authentication = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authentication, new FakeAdministratorSetup { Created = true });
        var client = new NativeAlertsClient();
        var endpoints = new NativeAlertEndpointsClient(client.EndpointIds);
        using var alerts = new AlertsViewModel(client, endpoints);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, alerts);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Native Alerts installation did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Alerts);
            await FlushAsync();
            Ensure(client.Queries.Count == 0 && endpoints.ListCalls == 0, "Native Alerts read protected data before authentication.");
            auth.Username = "native-alert-admin";
            await auth.SignInAsync("Synthetic-Wpf-Alerts!".AsMemory());
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready, "Authenticated native Alerts did not load.");
            await FlushAsync();
            var view = Descendants<AlertsView>(window).Single();
            var grid = (DataGrid)view.FindName("AlertsGrid");
            var handle = new WindowInteropHelper(window).Handle;
            Ensure(handle != IntPtr.Zero && NativeMethods.IsWindowVisible(handle), "Native Alerts did not use a visible real HWND.");
            Ensure(grid.IsVisible && grid.IsReadOnly && grid.Items.Count == 50 && alerts.TotalAlerts == 125,
                "Native Alerts did not present Core's bounded 50-item server page.");
            Ensure(client.Queries.Single().Offset == 0 && client.Queries.Single().Limit == 50,
                "Native Alerts requested an unbounded or incorrect initial page.");
            Ensure(grid.EnableRowVirtualization && VirtualizingPanel.GetIsVirtualizing(grid) &&
                VirtualizingPanel.GetVirtualizationMode(grid) == VirtualizationMode.Recycling,
                "Native Alerts disabled recycling row virtualization.");
            grid.UpdateLayout();
            var realized = Enumerable.Range(0, grid.Items.Count)
                .Count(index => grid.ItemContainerGenerator.ContainerFromIndex(index) is DataGridRow);
            Ensure(realized > 0 && realized < grid.Items.Count, "Native Alerts eagerly realized the complete server page.");
            Ensure(grid.Columns.Count == 7 && grid.Columns.Any(column => Equals(column.Header, "First observed (UTC)")) &&
                grid.Columns.Any(column => Equals(column.Header, "Latest observed (UTC)")),
                "Native Alerts omitted lifecycle observations from its list.");

            AlertButton(view, "NextAlertsPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.PageNumber == 2 && alerts.ListState == AlertListState.Ready, "Native Alerts next-page action did not finish.");
            Ensure(client.Queries[^1].Offset == 50 && grid.Items.Count == 50, "Native Alerts paged only a local subset.");
            AlertButton(view, "NextAlertsPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.PageNumber == 3 && alerts.ListState == AlertListState.Ready, "Native Alerts final-page action did not finish.");
            Ensure(client.Queries[^1].Offset == 100 && grid.Items.Count == 25 && !alerts.CanNextPage,
                "Native Alerts omitted the partial final server page or enabled nonexistent pages.");

            var queriesBeforeFilters = client.Queries.Count;
            var endpointFilter = AlertControl<ComboBox>(view, "AlertEndpointFilter");
            endpointFilter.SelectedItem = alerts.EndpointOptions.Single(option => option.EndpointId == client.EndpointIds[0]);
            endpointFilter.GetBindingExpression(ComboBox.SelectedItemProperty)?.UpdateSource();
            var severityFilter = AlertControl<ComboBox>(view, "AlertSeverityFilter");
            severityFilter.SelectedValue = AlertSeverityFilter.High;
            severityFilter.GetBindingExpression(ComboBox.SelectedValueProperty)?.UpdateSource();
            var statusFilter = AlertControl<ComboBox>(view, "AlertStatusFilter");
            statusFilter.SelectedValue = AlertStatusFilter.Open;
            statusFilter.GetBindingExpression(ComboBox.SelectedValueProperty)?.UpdateSource();
            await FlushAsync();
            Ensure(alerts.FiltersChanged && client.Queries.Count == queriesBeforeFilters,
                "Native filter edits prematurely queried Core or failed to mark unapplied filters.");
            AlertButton(view, "ApplyAlertFiltersButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready && !alerts.FiltersChanged, "Native Alerts filter application did not finish.");
            var filtered = client.Queries[^1];
            Ensure(filtered.EndpointId == client.EndpointIds[0] && filtered.Severity == "high" && filtered.Status == "open" && filtered.Offset == 0,
                "Native filters did not send the selected endpoint, severity and status to Core or reset paging.");
            Ensure(alerts.VisibleAlerts.Count > 0 && alerts.VisibleAlerts.All(row => row.EndpointId == client.EndpointIds[0] &&
                row.Severity == "high" && row.Status == "open"), "Native filtered rows differ from Core's result.");

            endpointFilter.SelectedItem = alerts.EndpointOptions.Single(option => option.EndpointId is null);
            severityFilter.SelectedValue = AlertSeverityFilter.All;
            statusFilter.SelectedValue = AlertStatusFilter.All;
            await FlushAsync();
            AlertButton(view, "ApplyAlertFiltersButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready && !alerts.FiltersChanged, "Native Alerts filter reset did not finish.");
            await FlushAsync();
            grid.SelectedItem = alerts.VisibleAlerts.Single(row => row.AlertId == client.PrimaryId);
            await FlushAsync();
            AlertButton(view, "OpenAlertButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.DetailState == AlertDetailState.Ready, "Native alert detail did not open.");
            await FlushAsync();
            Ensure(alerts.Detail?.Version == 10 && alerts.Detail.Row.AlertId == client.PrimaryId,
                "Native detail lost the authoritative alert identity or reviewed version.");
            AssertLiteralAlertText(view, "AlertDetailTitle", NativeAlertsClient.LiteralTitle);
            AssertLiteralAlertText(view, "AlertReason", NativeAlertsClient.LiteralReason);
            AssertLiteralAlertText(view, "AlertRecommendation", NativeAlertsClient.LiteralRecommendation);
            var evidenceGrid = (DataGrid)view.FindName("AlertEvidenceGrid");
            var historyGrid = (DataGrid)view.FindName("AlertHistoryGrid");
            Ensure(evidenceGrid.IsReadOnly && evidenceGrid.Columns.Count == 3 && evidenceGrid.Items.Count == 4,
                "Native detail did not display typed evidence in a read-only native grid.");
            Ensure(alerts.Detail!.Evidence.Any(row => row.Field == "boolean-value" && row.TypeLabel == "Boolean") &&
                alerts.Detail.Evidence.Any(row => row.Field == "integer-value" && row.TypeLabel == "Integer" && row.Value == "7") &&
                alerts.Detail.Evidence.Any(row => row.Field == "string-value" && row.TypeLabel == "String" && row.Value == NativeAlertsClient.LiteralEvidence) &&
                alerts.Detail.Evidence.Any(row => row.Field == "unknown-value" && row.TypeLabel == "Unknown"),
                "Native evidence presentation lost typed values or treated unknown evidence as a positive observation.");
            evidenceGrid.UpdateLayout();
            Ensure(Descendants<TextBlock>(evidenceGrid).Any(text => text.Text == "False") &&
                Descendants<TextBlock>(evidenceGrid).Any(text => text.Text == NativeAlertsClient.LiteralEvidence && text.Inlines.Cast<Inline>().All(inline => inline is Run)),
                "Native evidence cells failed to render a negative Boolean or rendered literal evidence as content.");
            Ensure(historyGrid.IsReadOnly && historyGrid.Columns.Count == 5 && historyGrid.Items.Count == 2 &&
                alerts.Detail.History.Any(row => row.ChangedBy == NativeAlertsClient.LiteralActor),
                "Native detail omitted Core's retained status history or modified literal actor text.");
            historyGrid.UpdateLayout();
            Ensure(Descendants<TextBlock>(historyGrid).Any(text => text.Text == NativeAlertsClient.LiteralActor) &&
                Descendants<TextBlock>(view).Any(text => text.Text == "SYNTHETIC_RULE") &&
                Descendants<TextBlock>(view).Any(text => text.Text == alerts.Detail.Row.FirstObservedText) &&
                Descendants<TextBlock>(view).Any(text => text.Text == alerts.Detail.Row.LastObservedText),
                "Native detail omitted literal history actors, rule identity, or observation timestamps.");
            var queriesBeforeValidation = client.Queries.Count;
            var reviewed = alerts.Detail;
            await auth.CheckSessionAsync();
            await FlushAsync();
            Ensure(client.Queries.Count == queriesBeforeValidation && ReferenceEquals(alerts.Detail, reviewed),
                "Periodic session validation refreshed Alerts or discarded reviewed detail.");

            var statusChoice = AlertControl<ComboBox>(view, "AlertProposedStatus");
            Ensure(statusChoice.Items.Cast<ComboBoxItem>().Select(item => item.Tag?.ToString())
                .SequenceEqual(new[] { "open", "investigating", "accepted", "resolved" }),
                "Native status control did not expose all four existing canonical lifecycle choices.");
            SetNativeAlertStatus(view, "open");
            Ensure(!AlertButton(view, "SaveAlertStatusButton").IsEnabled, "Native status control enabled an unchanged status write.");
            SetNativeAlertStatus(view, "investigating");
            Ensure(AlertButton(view, "SaveAlertStatusButton").IsEnabled, "Native valid status choice did not enable a write.");
            var delayedWrite = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextWriteGate = delayedWrite;
            AlertButton(view, "SaveAlertStatusButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.IsSavingStatus, "Native deferred status write never entered its pending state.");
            await FlushAsync();
            Ensure(!AlertButton(view, "SaveAlertStatusButton").IsEnabled && !statusChoice.IsEnabled &&
                !AlertButton(view, "RefreshAlertDetailButton").IsEnabled && !AlertButton(view, "BackToAlertsButton").IsEnabled,
                "Native pending status write allowed another write, status edit, refresh, or premature navigation.");
            Ensure(alerts.Detail?.Version == 10 && alerts.Detail.Row.Status == "open",
                "Native pending status write displayed an unconfirmed transition.");
            delayedWrite.SetResult(true);
            await WaitForAsync(() => !alerts.IsSavingStatus && alerts.Detail?.Row.Status == "investigating", "Native status write did not display Core's persisted result.");
            Ensure(client.Writes.Count == 1 && client.Writes[0] == (client.PrimaryId, "investigating", 10) &&
                alerts.Detail?.Version == 11 && alerts.Detail.History.Count == 3,
                "Native status write omitted the reviewed version or lost persisted transition history.");

            var readsBeforeConflict = client.DetailCalls;
            client.NextWriteOutcome = AlertOutcome.Conflict;
            SetNativeAlertStatus(view, "resolved");
            AlertButton(view, "SaveAlertStatusButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => !alerts.IsSavingStatus && alerts.Detail?.Version == 12, "Native conflicting write did not reload the current reviewed detail.");
            await FlushAsync();
            Ensure(client.Writes.Count == 2 && client.Writes[^1].Item3 == 11 && client.DetailCalls == readsBeforeConflict + 1 &&
                alerts.Detail?.Row.Status == "accepted" && !AlertButton(view, "SaveAlertStatusButton").IsEnabled &&
                alerts.StatusMessage.Contains("not saved", StringComparison.OrdinalIgnoreCase),
                "Native conflict handling retried a stale write, hid the conflict, or retained an actionable old choice.");
            Ensure(AlertControl<TextBlock>(view, "AlertStatusMessage").IsVisible &&
                AlertControl<TextBlock>(view, "AlertStatusMessage").Text == alerts.StatusMessage,
                "Native conflicting status write feedback was not visible in the bound control.");

            client.NextWriteOutcome = AlertOutcome.Indeterminate;
            SetNativeAlertStatus(view, "resolved");
            AlertButton(view, "SaveAlertStatusButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => !alerts.IsSavingStatus && alerts.NeedsDetailRefresh, "Native uncertain status response was not marked for explicit refresh.");
            await FlushAsync();
            Ensure(client.Writes.Count == 3 && alerts.Detail?.Row.Status == "accepted" &&
                !AlertButton(view, "SaveAlertStatusButton").IsEnabled &&
                alerts.StatusMessage.Contains("could not be confirmed", StringComparison.OrdinalIgnoreCase),
                "Native uncertain write invented success or remained available for an automatic retry.");
            Ensure(AlertControl<TextBlock>(view, "AlertStatusMessage").IsVisible &&
                AlertControl<TextBlock>(view, "AlertStatusMessage").Text == alerts.StatusMessage,
                "Native uncertain status write feedback was not visible in the bound control.");
            AlertButton(view, "RefreshAlertDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.DetailState == AlertDetailState.Ready && !alerts.NeedsDetailRefresh,
                "Native explicit refresh did not reconcile an uncertain status write.");
            SetNativeAlertStatus(view, "resolved");
            AlertButton(view, "SaveAlertStatusButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => !alerts.IsSavingStatus && alerts.Detail?.Row.Status == "resolved", "Native reviewed resolution did not persist.");
            Ensure(client.Writes.Count == 4 && client.Writes[^1].Item3 == 12 && alerts.Detail?.Version == 13,
                "Native retry after review did not use the fresh authoritative version.");
            client.ReopenPrimary();
            AlertButton(view, "RefreshAlertDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.Detail?.Row.Status == "open" && alerts.Detail.Version == 14,
                "Native detail failed to display a Core-authoritative reopening after a new positive observation.");
            Ensure(alerts.Detail!.History.Any(row => row.PreviousStatus == "Resolved" && row.Status == "Open" && row.ChangeType == "Reopened") && client.Writes.Count == 4,
                "Native reopening lost history or manufactured an additional operator write.");

            var defaultSize = new Size(window.Width, window.Height);
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                AssertInsideWindow(window, AlertButton(view, "BackToAlertsButton"));
                ((ScrollViewer)view.FindName("PageScroller")).ScrollToEnd();
                await FlushAsync();
                AssertInsideWindow(window, AlertButton(view, "BackToAlertsButton"));
            }
            window.Width = defaultSize.Width; window.Height = defaultSize.Height;
            AlertButton(view, "BackToAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                Ensure(double.IsFinite(grid.Height) && grid.Height >= 160 && grid.IsVisible,
                    "Native Alerts lost its bounded list viewport at a supported window size.");
            }
            window.Width = defaultSize.Width; window.Height = defaultSize.Height;
            await FlushAsync();

            client.NextDetailOutcome = AlertOutcome.NotFound;
            grid.SelectedItem = alerts.VisibleAlerts.First();
            AlertButton(view, "OpenAlertButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.DetailState == AlertDetailState.NotFound, "Native missing alert was not shown explicitly.");
            Ensure(alerts.Detail is null && Descendants<TextBlock>(view).Any(text => text.IsVisible && text.Text == alerts.DetailStatusText),
                "Native missing alert retained successful detail or hid the state.");
            AlertButton(view, "BackToAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();

            var delayedList = new TaskCompletionSource<AlertResult<AlertPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextList = delayedList;
            AlertButton(view, "RefreshAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Loading, "Native Alerts omitted its in-flight loading state.");
            Ensure(!AlertButton(view, "RefreshAlertsButton").IsEnabled &&
                Descendants<TextBlock>(view).Any(text => text.IsVisible && text.Text == alerts.ListStatusText),
                "Native loading state hid progress or allowed overlapping refreshes.");
            delayedList.SetResult(client.Page(client.Queries[^1]));
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready, "Native delayed refresh failed to finish.");
            client.ListOutcome = AlertOutcome.Unavailable;
            AlertButton(view, "RefreshAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Unavailable, "Native Alerts omitted Core-unavailable state.");
            Ensure(grid.Items.Count == 0 && Descendants<TextBlock>(view).Any(text => text.IsVisible && text.Text == alerts.ListStatusText),
                "Native Core failure left a successful alert page displayed.");
            client.ListOutcome = AlertOutcome.Success;
            client.Items = [];
            AlertButton(view, "RefreshAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Empty, "Native Alerts omitted its no-data state.");
            Ensure(Descendants<TextBlock>(view).Any(text => text.IsVisible && text.Text == alerts.ListStatusText), "Native empty alert state was not visible.");

            client.RestoreItems();
            AlertButton(view, "RefreshAlertsButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready, "Native Alerts did not recover after Core became available.");
            grid.SelectedItem = alerts.VisibleAlerts.Single(row => row.AlertId == client.PrimaryId);
            await FlushAsync();
            AlertButton(view, "OpenAlertButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.DetailState == AlertDetailState.Ready, "Native detail did not reopen before sign-out.");
            auth.SignOut();
            await FlushAsync();
            Ensure(alerts.TotalAlerts == 0 && alerts.VisibleAlerts.Count == 0 && alerts.Detail is null && !view.IsVisible,
                "Sign-out retained native protected alert data.");
            Ensure(trace.Messages.Count == 0, "Native Alerts bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
            window.Close();
        }
        finally
        {
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static T AlertControl<T>(AlertsView view, string id) where T : FrameworkElement => Descendants<T>(view)
        .Single(control => AutomationProperties.GetAutomationId(control) == id);

    private static Button AlertButton(AlertsView view, string id) => AlertControl<Button>(view, id);

    private static void SetNativeAlertStatus(AlertsView view, string status)
    {
        var choice = AlertControl<ComboBox>(view, "AlertProposedStatus");
        choice.SelectedValue = status;
        choice.GetBindingExpression(ComboBox.SelectedValueProperty)?.UpdateSource();
    }

    private static void AssertLiteralAlertText(AlertsView view, string id, string value)
    {
        var text = AlertControl<TextBlock>(view, id);
        Ensure(text.IsVisible && text.Text == value && text.Inlines.Cast<Inline>().All(inline => inline is Run),
            "Native untrusted alert text was modified or rendered as executable/interactive content: " + id);
    }

    private sealed class NativeAlertEndpointsClient(Guid[] endpointIds) : IDevicesClient
    {
        public int ListCalls;
        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            ListCalls++;
            IReadOnlyList<DeviceSummary> devices = endpointIds.Select((id, index) => new DeviceSummary(id,
                $"native-endpoint-{index}", "Synthetic Windows", "healthy", DateTimeOffset.UtcNow,
                "1.0.0", "Firewall enabled on all profiles", DateTimeOffset.UtcNow)).ToArray();
            return Task.FromResult(new DeviceReadResult<IReadOnlyList<DeviceSummary>>(DeviceReadOutcome.Success, devices));
        }
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken token) =>
            Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.NotFound));
    }

    private sealed class NativeAlertsClient : IAlertsClient
    {
        public const string LiteralTitle = "<script>alert('synthetic-title')</script> & <b>Title</b>";
        public const string LiteralReason = "<img src=x onerror=alert('synthetic-reason')> & {Binding Secret}";
        public const string LiteralRecommendation = "<a href='file:///synthetic'>Review locally</a> & <Run>literal</Run>";
        public const string LiteralEvidence = "<script>synthetic-evidence</script> & <Hyperlink>literal</Hyperlink>";
        public const string LiteralActor = "<b>synthetic-operator</b> & {Binding Credential}";
        public Guid[] EndpointIds { get; } = [Guid.NewGuid(), Guid.NewGuid()];
        public IReadOnlyList<AlertSummary> Items;
        public Guid PrimaryId { get; }
        public List<AlertQuery> Queries { get; } = [];
        public List<(Guid, string, long)> Writes { get; } = [];
        public int DetailCalls;
        public AlertOutcome ListOutcome = AlertOutcome.Success;
        public AlertOutcome NextWriteOutcome = AlertOutcome.Success;
        public AlertOutcome NextDetailOutcome = AlertOutcome.Success;
        public TaskCompletionSource<AlertResult<AlertPage>>? NextList;
        public TaskCompletionSource<bool>? NextWriteGate;
        private readonly Dictionary<Guid, AlertDetail> _details;

        public NativeAlertsClient()
        {
            var now = new DateTimeOffset(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
            Items = Enumerable.Range(0, 125).Select(index => new AlertSummary(Guid.NewGuid(), EndpointIds[index % 2],
                $"native-endpoint-{index % 2}", "SYNTHETIC_RULE", index == 0 ? LiteralTitle : $"Synthetic alert {index:000}",
                index % 3 == 0 ? "high" : "low", index % 4 == 0 ? "open" : "investigating",
                now.AddDays(-1).AddMinutes(-index), now.AddMinutes(-index), now.AddMinutes(-index), 10)).ToArray();
            PrimaryId = Items[0].AlertId;
            _details = Items.ToDictionary(item => item.AlertId, item => new AlertDetail(item, LiteralReason,
                [new("boolean-value", AlertEvidenceKind.Boolean, BooleanValue: false),
                 new("integer-value", AlertEvidenceKind.Integer, IntegerValue: 7),
                 new("string-value", AlertEvidenceKind.String, StringValue: LiteralEvidence),
                 new("unknown-value", AlertEvidenceKind.Unknown)], LiteralRecommendation,
                item.FirstObservedUtc, item.UpdatedUtc,
                [new(null, "open", item.FirstObservedUtc, "system"),
                 new("open", item.Status, item.UpdatedUtc, LiteralActor)], 2));
        }

        public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Queries.Add(query);
            if (NextList is { } delayed) { NextList = null; return delayed.Task; }
            return Task.FromResult(Page(query));
        }

        public AlertResult<AlertPage> Page(AlertQuery query)
        {
            if (ListOutcome != AlertOutcome.Success) return new(ListOutcome);
            var filtered = Items.Where(item => (query.EndpointId is null || item.EndpointId == query.EndpointId) &&
                (query.Severity is null || item.Severity == query.Severity) && (query.Status is null || item.Status == query.Status)).ToArray();
            return new(AlertOutcome.Success, new(filtered.Skip(query.Offset).Take(query.Limit).ToArray(), filtered.LongLength, query.Offset, query.Limit));
        }

        public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid alertId, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            DetailCalls++;
            var outcome = NextDetailOutcome;
            NextDetailOutcome = AlertOutcome.Success;
            return Task.FromResult(outcome == AlertOutcome.Success
                ? new AlertResult<AlertDetail>(AlertOutcome.Success, _details[alertId]) : new(outcome));
        }

        public async Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid alertId, string status, long expectedVersion, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Writes.Add((alertId, status, expectedVersion));
            if (NextWriteGate is { } delayed)
            {
                NextWriteGate = null;
                await delayed.Task.WaitAsync(token);
            }
            var outcome = NextWriteOutcome;
            NextWriteOutcome = AlertOutcome.Success;
            if (outcome == AlertOutcome.Conflict)
            {
                Transition(alertId, "accepted", "another-synthetic-operator");
                return new(AlertOutcome.Conflict);
            }
            if (outcome != AlertOutcome.Success) return new(outcome);
            if (_details[alertId].Alert.Version != expectedVersion)
                return new(AlertOutcome.Conflict);
            Transition(alertId, status, "native-alert-admin");
            return new(AlertOutcome.Success, _details[alertId]);
        }

        public void ReopenPrimary() => Transition(PrimaryId, "open", "system");

        public void RestoreItems() => Items = _details.Values.Select(detail => detail.Alert).ToArray();

        private void Transition(Guid alertId, string status, string actor)
        {
            var previous = _details[alertId];
            var now = previous.Alert.UpdatedUtc.AddSeconds(1);
            var current = previous.Alert with { Status = status, UpdatedUtc = now, Version = previous.Alert.Version + 1 };
            var history = previous.StatusHistory.Append(new AlertStatusChange(previous.Alert.Status, status, now, actor)).ToArray();
            _details[alertId] = previous with { Alert = current, StatusChangedUtc = now, StatusHistory = history, StatusHistoryCount = history.LongLength };
            Items = Items.Select(item => item.AlertId == alertId ? current : item).ToArray();
        }
    }
}
