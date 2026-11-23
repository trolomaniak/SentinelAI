using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task MonitoringCoverageViewsAsync()
    {
        try
        {
            foreach (var language in new[] { UiLanguage.English, UiLanguage.Polish })
            {
                Localizer.Use(language);
                using var shell = new ShellViewModel(new FakeCoreClient(), "monitoring-coverage-test");
                using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
                var client = new NativeMonitoringClient();
                using var model = new MonitoringCoverageViewModel(client);
                var window = new MainWindow(shell, auth, null, null, null, null, null, null, null, null, monitoringCoverage: model);
                try
                {
                    window.Width = window.MinWidth;
                    window.Height = window.MinHeight;
                    window.Show();
                    await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "The monitoring test fixture did not reach sign-in.");
                    var page = shell.Pages.Single(p => p.Id == PageId.MonitoringCoverage);
                    shell.CurrentPage = page;
                    await FlushAsync();
                    Ensure(client.ListReads == 0 && !RequireControl<ContentControl>(window, "PageContent").IsVisible,
                        "Monitoring coverage read or displayed data before sign-in.");

                    auth.Username = "native-coverage-admin";
                    await auth.SignInAsync("Synthetic-Native-Coverage!".AsMemory());
                    await WaitForAsync(() => model.Rows.Count == 25, "Signing in did not load the native coverage list.");
                    await FlushAsync();
                    var view = Descendants<MonitoringCoverageView>(window).Single();
                    var heading = Descendants<TextBlock>(view).Single(t => AutomationProperties.GetAutomationId(t) == "PageHeading");
                    var headingPeer = UIElementAutomationPeer.CreatePeerForElement(heading);
                    Ensure(heading.IsVisible && page.Title == (language == UiLanguage.Polish ? "Pokrycie monitoringu" : "Monitoring coverage") &&
                        heading.Text == page.Title && headingPeer?.GetName() == page.Title && headingPeer.GetAutomationId() == "PageHeading",
                        "The page failed to expose the common localized native heading.");
                    var scroll = Descendants<ScrollViewer>(view).Single(s => AutomationProperties.GetAutomationId(s) == "MonitoringCoverageScroll");
                    Ensure(scroll.ViewportWidth > 0 && scroll.ViewportHeight > 0 && scroll.ScrollableHeight > 0 && scroll.ScrollableWidth == 0,
                        "Monitoring coverage could not scroll at 640×480.");
                    var next = CoverageControl<Button>(view, "MonitoringNext");
                    next.BringIntoView();
                    await FlushAsync();
                    AssertInsideWindow(window, next);
                    next.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    await WaitForAsync(() => model.Rows.Count == 1 && client.LastOffset == 25, "The native device page did not advance.");

                    var filter = CoverageControl<CheckBox>(view, "MonitoringIssuesOnly");
                    filter.BringIntoView();
                    await FlushAsync();
                    AssertInsideWindow(window, filter);
                    var filterPeer = UIElementAutomationPeer.CreatePeerForElement(filter);
                    ((IToggleProvider)filterPeer!.GetPattern(PatternInterface.Toggle)).Toggle();
                    await WaitForAsync(() => client.IssuesOnly && client.LastOffset == 0, "The accessible issue filter did not start from the first page.");
                    await FlushAsync();
                    var list = CoverageControl<ListBox>(view, "MonitoringEndpoints");
                    var item = (ListBoxItem)list.ItemContainerGenerator.ContainerFromIndex(0);
                    var itemPeer = UIElementAutomationPeer.CreatePeerForElement(item);
                    Ensure(itemPeer?.GetName() == NativeMonitoringClient.Name, "The endpoint row lacked a literal accessible label.");
                    list.SelectedIndex = 0;
                    await WaitForAsync(() => model.SourceDetail is not null && model.GapRows.Count == 15, "Selecting a computer did not load sources and notices.");
                    await FlushAsync();
                    var texts = Descendants<TextBlock>(view).Select(t => t.Text).ToArray();
                    Ensure(texts.Contains(NativeMonitoringClient.Name) && texts.Contains(Localizer.T("Microsoft Defender Antivirus status")) &&
                        texts.Contains(Localizer.T("Microsoft Defender Operational event log")) &&
                        texts.Any(t => t.Contains(Localizer.T("First coverage baseline"), StringComparison.Ordinal)) &&
                        texts.Any(t => t.Contains(Localizer.T("Coverage restarted"), StringComparison.Ordinal)),
                        "One or more literal endpoint, source or continuity labels were lost in the view.");
                    var gapNext = CoverageControl<Button>(view, "MonitoringNextGap");
                    gapNext.BringIntoView();
                    await FlushAsync();
                    AssertInsideWindow(window, gapNext);
                    Ensure(gapNext.IsEnabled && gapNext.Focusable, "Continuity paging was unreachable at the minimum viewport.");
                    gapNext.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    await WaitForAsync(() => model.GapRows.Count == 1 && client.LastGapOffset == 15, "Native continuity paging did not advance independently.");
                    Ensure(model.Rows.Count == 1 && model.SourceDetail is not null, "Native continuity paging dropped device or source data.");

                    shell.CurrentPage = shell.Pages.Single(p => p.Id == PageId.Overview);
                    await FlushAsync();
                    Ensure(model.Rows.Count == 0 && model.SourceDetail is null && model.GapRows.Count == 0, "Leaving monitoring coverage retained active data.");
                    shell.CurrentPage = page;
                    await WaitForAsync(() => model.Rows.Count == 25, "Returning to monitoring coverage did not reload data.");
                    auth.SignOut();
                    await FlushAsync();
                    Ensure(model.Rows.Count == 0 && !model.HasSelection && !RequireControl<ContentControl>(window, "PageContent").IsVisible,
                        "Signing out retained monitoring coverage data in the native workspace.");
                }
                finally { if (window.IsVisible) window.Close(); }
            }
        }
        finally { Localizer.Use(UiLanguage.English); }
    }

    private static T CoverageControl<T>(DependencyObject parent, string id) where T : FrameworkElement =>
        Descendants<T>(parent).Single(c => AutomationProperties.GetAutomationId(c) == id);

    private sealed class NativeMonitoringClient : IMonitoringCoverageClient
    {
        public const string Name = "{Binding literal}<synthetic endpoint>";
        private static readonly DateTimeOffset Now = new(2099, 1, 12, 12, 0, 0, TimeSpan.Zero);
        public int ListReads, LastOffset, LastGapOffset;
        public bool IssuesOnly;

        private static MonitoringEndpointSummary Summary(Guid id) => new(id, Name, "warning", Now.AddMinutes(-3), "missing", null,
            "missing", null, null, 0, 0, true, true);

        public Task<DeviceReadResult<MonitoringEndpointPage>> GetMonitoringEndpointsAsync(int offset, int limit, bool issuesOnly, CancellationToken token)
        {
            ListReads++;
            LastOffset = offset;
            IssuesOnly = issuesOnly;
            var matching = issuesOnly ? 1 : 26;
            var items = Enumerable.Range(0, Math.Min(limit, matching - offset)).Select(_ => Summary(Guid.NewGuid())).ToArray();
            return Task.FromResult(new DeviceReadResult<MonitoringEndpointPage>(DeviceReadOutcome.Success, new(Now, 26, matching, offset, limit, 12, items)));
        }

        public Task<DeviceReadResult<MonitoringEndpointDetail>> GetMonitoringEndpointAsync(Guid endpointId, CancellationToken token) =>
            Task.FromResult(new DeviceReadResult<MonitoringEndpointDetail>(DeviceReadOutcome.Success, new(Now, Summary(endpointId), 12, 30,
                MonitoringCoverageContract.TelemetrySourceIds.Select(id => new MonitoringTelemetrySource(id, "unknown", "missing")).ToArray(),
                SecurityEventChannels.All.Select(name => new MonitoringEventChannel(name, "unknown", "missing", null, null, null, null, null, null, null, null, null)).ToArray())));

        public Task<DeviceReadResult<MonitoringGapPage>> GetMonitoringGapsAsync(Guid endpointId, int offset, int limit, CancellationToken token)
        {
            LastGapOffset = offset;
            var items = Enumerable.Range(offset, Math.Min(limit, 16 - offset)).Select(index => new MonitoringCoverageGap(SecurityEventChannels.Security,
                "coverageStarted", index == 0 ? "noCheckpoint" : "checkpointInvalid", 7, null, Now.AddHours(-2), Now.AddHours(-1), index != 0)).ToArray();
            return Task.FromResult(new DeviceReadResult<MonitoringGapPage>(DeviceReadOutcome.Success, new(Now, endpointId, 16, offset, limit, 30, items)));
        }
    }
}
