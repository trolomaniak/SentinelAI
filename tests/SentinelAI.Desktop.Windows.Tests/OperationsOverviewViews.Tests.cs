using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.Overview;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task OperationsOverviewViewsAsync()
    {
        try
        {
            foreach (var language in new[] { UiLanguage.English, UiLanguage.Polish })
            {
                Localizer.Use(language);
                using var shell = new ShellViewModel(new FakeCoreClient(), "overview-test");
                using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
                var client = new NativeOverviewClient();
                using var model = new OperationsOverviewViewModel(client);
                var window = new MainWindow(shell, auth, null, null, null, null, null, null, null, null, overview: model);
                try
                {
                    window.Width = window.MinWidth;
                    window.Height = window.MinHeight;
                    window.Show();
                    await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "The Overview fixture did not reach sign-in.");
                    var page = shell.Pages.Single(item => item.Id == PageId.Overview);
                    shell.CurrentPage = page;
                    await FlushAsync();
                    var content = RequireControl<ContentControl>(window, "PageContent");
                    Ensure(client.Reads == 0 && !content.IsVisible, "The Overview was read or shown before sign-in.");

                    auth.Username = "native-overview-admin";
                    await auth.SignInAsync("Synthetic-Native-Overview!".AsMemory());
                    await WaitForAsync(() => model.Summary is not null, "Signing in did not load the Overview.");
                    await FlushAsync();
                    var view = Descendants<OverviewView>(content).Single();
                    var heading = OverviewControl<TextBlock>(view, "PageHeading");
                    var headingPeer = UIElementAutomationPeer.CreatePeerForElement(heading);
                    Ensure(heading.IsVisible && page.Title == (language == UiLanguage.Polish ? "Przegląd" : "Overview") &&
                        heading.Text == page.Title && headingPeer?.GetName() == page.Title && headingPeer.GetAutomationId() == "PageHeading",
                        "The Overview did not expose the common localized native heading.");
                    var scroll = OverviewControl<ScrollViewer>(view, "OverviewScroll");
                    Ensure(scroll.ViewportWidth > 0 && scroll.ViewportHeight > 0 && scroll.ScrollableHeight > 0 && scroll.ScrollableWidth == 0,
                        "The Overview could not scroll at 640×480.");
                    var text = Descendants<TextBlock>(view).Select(block => block.Text).ToArray();
                    Ensure(text.Contains(NativeOverviewClient.Title) && text.Contains(Localizer.F("Active computers · {0} · Monitoring issues · {1}", 3, 1)) &&
                        text.Contains(Localizer.F("High and critical alerts awaiting a decision · {0}", 1)) &&
                        text.Contains(Localizer.F("Unread notifications · {0}", 1)) && text.Contains(Localizer.F("Risks requiring attention · {0}", 1)) &&
                        text.Any(line => line.StartsWith(Localizer.T("Reopened") + " · ", StringComparison.Ordinal)) &&
                        text.Contains(Localizer.F("Last successful backup: {0}", "2026-11-23 10:00:00 UTC")),
                        "The minimum-size Overview lost a localized count, literal row, status change, or backup timestamp.");

                    foreach (var (id, target) in new[]
                    {
                        ("OverviewCoverageButton", PageId.MonitoringCoverage), ("OverviewNotificationsButton", PageId.Notifications),
                        ("OverviewRiskRegisterButton", PageId.RiskRegister), ("OverviewAlertChangesButton", PageId.Alerts),
                        ("OverviewBackupSettingsButton", PageId.Settings)
                    })
                    {
                        view = Descendants<OverviewView>(content).Single();
                        var button = OverviewControl<Button>(view, id);
                        button.BringIntoView();
                        await FlushAsync();
                        AssertInsideWindow(window, button);
                        Ensure(button.IsEnabled && button.Focusable, "An Overview shortcut was unreachable at the minimum viewport.");
                        InvokeOverviewButton(button);
                        await FlushAsync();
                        Ensure(shell.CurrentPage.Id == target && model.Summary is null, "An Overview shortcut missed its workspace or retained the snapshot.");
                        var reads = client.Reads;
                        shell.CurrentPage = page;
                        await FlushAsync();
                        Ensure(client.Reads == reads + 1 && model.Summary is not null, "Returning to the Overview did not reload its snapshot.");
                    }

                    view = Descendants<OverviewView>(content).Single();
                    var refresh = OverviewControl<Button>(view, "OverviewRefreshButton");
                    refresh.BringIntoView();
                    await FlushAsync();
                    AssertInsideWindow(window, refresh);
                    client.Response = new(DeviceReadOutcome.Unavailable);
                    InvokeOverviewButton(refresh);
                    var status = OverviewControl<TextBlock>(view, "OverviewStatus");
                    await WaitForAsync(() => status.Text == Localizer.T("Operations overview is unavailable. Refresh to try again."),
                        "The Overview failed to show a read error.");
                    Ensure(model.Summary is null && !OverviewControl<ContentControl>(view, "OverviewBackup").IsVisible,
                        "A failed Overview read showed stale details or an empty backup result.");

                    var held = new TaskCompletionSource<DeviceReadResult<OperationsOverviewSnapshot>>();
                    client.Held = held.Task;
                    var readsBeforeRefresh = client.Reads;
                    InvokeOverviewButton(refresh);
                    await WaitForAsync(() => client.Reads == readsBeforeRefresh + 1 && !model.CanRefresh
                        && status.Text == Localizer.T("Reading operations overview…"), "A native refresh did not start one Overview read.");
                    var pendingToken = client.LastToken;
                    auth.SignOut();
                    await FlushAsync();
                    Ensure(model.Summary is null && pendingToken.IsCancellationRequested && !content.IsVisible,
                        "Signing out did not hide the Overview and cancel its active read.");

                    client.Held = null;
                    client.Response = new(DeviceReadOutcome.Success, NativeOverviewClient.Empty);
                    auth.Username = "native-overview-admin";
                    await auth.SignInAsync("Synthetic-Native-Overview!".AsMemory());
                    held.SetResult(new(DeviceReadOutcome.Success, NativeOverviewClient.Populated));
                    await FlushAsync();
                    view = Descendants<OverviewView>(content).Single();
                    text = Descendants<TextBlock>(view).Select(block => block.Text).ToArray();
                    Ensure(model.Summary?.PriorityAlerts.Rows.Count == 0 && !text.Contains(NativeOverviewClient.Title) &&
                        text.Contains(Localizer.F("Active computers · {0} · Monitoring issues · {1}", 0, 0)) &&
                        text.Contains(Localizer.T("No alert status changes in this period.")) &&
                        text.Contains(Localizer.T("No successful backup recorded.")),
                        "After sign-in the empty Overview lost its state or showed an older session's data.");
                }
                finally { if (window.IsVisible) window.Close(); }
            }
        }
        finally { Localizer.Use(UiLanguage.English); }
    }

    private static T OverviewControl<T>(DependencyObject parent, string id) where T : FrameworkElement =>
        Descendants<T>(parent).Single(control => AutomationProperties.GetAutomationId(control) == id);

    private static void InvokeOverviewButton(Button button)
    {
        var peer = new ButtonAutomationPeer(button);
        ((IInvokeProvider)peer.GetPattern(PatternInterface.Invoke)).Invoke();
    }

    private sealed class NativeOverviewClient : IOperationsOverviewClient
    {
        internal const string Title = "{Binding literal}<native overview alert>";
        private static readonly Guid Id = Guid.Parse("91f7d870-6020-456a-8337-7ac380df5ec8");
        private static readonly DateTimeOffset Now = new(2026, 11, 24, 10, 0, 0, TimeSpan.Zero);
        internal static readonly OperationsOverviewSnapshot Empty = new(Now, new(0, 0, 0, 0, 0), [], [], [], [], [], null);
        internal static readonly OperationsOverviewSnapshot Populated = new(Now, new(3, 1, 1, 1, 1),
            [new(Id, "Synthetic endpoint", Title, "critical", "open", Now)],
            [new MonitoringEndpointSummary(Id, "Synthetic endpoint", "offline", Now.AddMinutes(-30), "missing", null,
                "missing", null, null, 0, 0, false, true)],
            [new(Id, "Synthetic endpoint", "criticalAlertReopened", 3, Now)],
            [new(Id, "RISK-01", "Synthetic risk", true, false, false)],
            [new(Id, "Synthetic endpoint", Title, "resolved", "open", Now)],
            Now.AddDays(-1));

        public DeviceReadResult<OperationsOverviewSnapshot> Response = new(DeviceReadOutcome.Success, Populated);
        public Task<DeviceReadResult<OperationsOverviewSnapshot>>? Held;
        public CancellationToken LastToken;
        public int Reads;

        public Task<DeviceReadResult<OperationsOverviewSnapshot>> GetOperationsOverviewAsync(CancellationToken cancellationToken)
        {
            LastToken = cancellationToken;
            Reads++;
            return Held ?? Task.FromResult(Response);
        }
    }
}
