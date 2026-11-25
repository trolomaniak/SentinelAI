using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using SentinelAI.Contracts.RiskHistory;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task RiskHistoryViewsAsync()
    {
        var previousLanguage = Localizer.Current;
        try
        {
            foreach (var language in new[] { UiLanguage.English, UiLanguage.Polish })
            {
                Localizer.Use(language);
                await RiskHistoryViewAsync(language);
            }
        }
        finally { Localizer.Use(previousLanguage); }
    }

    private static async Task RiskHistoryViewAsync(UiLanguage language)
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "history-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
        var current = new NativeRiskClient();
        var client = new NativeHistoryClient(current.PrimaryId);
        using var risk = new RiskViewModel(current, client);
        var window = new MainWindow(shell, auth, null, null, risk, null) { Width = 640, Height = 480 };
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Native history did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Risk);
            await FlushAsync();
            Ensure(client.Requests.Count == 0, "Native history requested protected data before sign-in.");
            auth.Username = "native-history-admin";
            await auth.SignInAsync("Synthetic-Wpf-History!".AsMemory());
            await WaitForAsync(() => risk.History?.Points.Count == 2 && risk.ListState == RiskListState.Ready, "Organization history did not load.");
            await FlushAsync();
            var view = Descendants<RiskView>(window).Single();
            var history = RiskControl<Expander>(view, "RiskHistoryExpander");
            Ensure(Equals(history.Header, language == UiLanguage.Polish ? "Historia ryzyka organizacji" : "Organization risk history") &&
                client.Requests.Single() == (null, 168), "Native history showed the wrong language, scope, or default period.");
            history.IsExpanded = true;
            await FlushAsync();
            var period = RiskControl<ComboBox>(view, "RiskHistoryPeriod");
            Ensure(period.SelectedValue is 168 && period.Items.Cast<RiskHistoryPeriod>().Select(item => item.Hours).SequenceEqual(RiskHistoryContract.PeriodHours) &&
                ((RiskHistoryPeriod)period.SelectedItem).Label == (language == UiLanguage.Polish ? "7 dni" : "7 days"), "Native history period choices were missing or untranslated.");
            period.BringIntoView();
            await FlushAsync();
            AssertInsideWindow(window, period);
            period.SetCurrentValue(Selector.SelectedValueProperty, 24);
            period.GetBindingExpression(Selector.SelectedValueProperty)?.UpdateSource();
            await WaitForAsync(() => client.Requests.LastOrDefault() == (null, 24), "Changing the native period did not request the selected period.");
            await FlushAsync();

            var chart = RiskControl<RiskHistoryChart>(view, "RiskHistoryChart");
            chart.BringIntoView();
            await FlushAsync();
            var chartName = language == UiLanguage.Polish ? "Zapisane wyniki ryzyka w czasie" : "Recorded risk scores over time";
            Ensure(UIElementAutomationPeer.CreatePeerForElement(chart)?.GetName() == chartName, "The history plot has no localized automation name.");
            var geometries = DrawingGeometries(VisualTreeHelper.GetDrawing(chart)).ToArray();
            var dots = geometries.OfType<EllipseGeometry>().OrderBy(dot => dot.Center.X).ToArray();
            var lines = geometries.OfType<LineGeometry>().ToArray();
            Ensure(dots.Length == 2 && dots[1].Center.X - dots[0].Center.X > chart.ActualWidth / 2 &&
                dots[1].Center.Y < dots[0].Center.Y && lines.Length == 3 && lines.All(line => line.StartPoint.Y == line.EndPoint.Y),
                "Native history did not plot actual capture spacing and score or connected missing captures.");

            var table = RiskControl<DataGrid>(view, "RiskHistoryTable");
            table.BringIntoView();
            await FlushAsync();
            AssertInsideWindow(window, table);
            Ensure(table.IsReadOnly && table.Items.Count == 2 && table.Columns.Count == 3 &&
                Equals(table.Columns[2].Header, language == UiLanguage.Polish ? "Wynik surowy" : "Raw score") &&
                (UIElementAutomationPeer.CreatePeerForElement(table) ?? new DataGridAutomationPeer(table)).GetPattern(PatternInterface.Table) is not null,
                "The native history table lost its localized columns or table automation pattern.");
            var newest = (RiskHistoryPointRow)table.Items[0];
            var earliest = (RiskHistoryPointRow)table.Items[1];
            Ensure(newest.Score == 100 && newest.RawScoreText == "142.125" && earliest.RecordedAtText.Contains(".1234567 UTC", StringComparison.Ordinal),
                "Native history lost raw-score or timestamp precision.");
            table.SelectedIndex = 0;
            await FlushAsync();
            var details = RiskControl<ItemsControl>(view, "RiskHistoryDetails");
            var facts = details.Items.Cast<DisplayFact>().ToArray();
            Ensure(facts.Any(fact => fact.Value == earliest.RecordedAtText) && facts.Any(fact => fact.Value == NativeHistoryClient.Fingerprint) &&
                facts.Any(fact => fact.Value == NativeHistoryClient.PolicyVersion) && facts.Any(fact => fact.Value == "SA-FW-001") &&
                facts.Any(fact => fact.Value == (language == UiLanguage.Polish ? "Zmienił się stan ustalenia" : "Finding status changed")),
                "The native selected measurement lost its comparison, policy, rules, or observed changes.");

            var endpoints = (DataGrid)view.FindName("RiskGrid");
            endpoints.SelectedIndex = 0;
            await FlushAsync();
            RiskButton(view, "OpenEndpointRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Ready && client.Requests.LastOrDefault() == (current.PrimaryId, 24),
                "Native endpoint history did not use the selected endpoint and period.");
            await FlushAsync();
            Ensure(Equals(history.Header, language == UiLanguage.Polish ? "Historia ryzyka komputera" : "Endpoint risk history") &&
                risk.SelectedHistoryPoint?.Details.All(fact => fact.Value != current.PrimaryId.ToString("D")) == true,
                "Native endpoint history retained organization facts.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Devices);
            await FlushAsync();
            Ensure(!risk.CanShowHistory && risk.History is null, "Switching native workspaces retained risk history.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Risk);
            await WaitForAsync(() => risk.History?.Points.Count == 2, "Returning to native Risk did not restore organization history.");
            auth.SignOut();
            await FlushAsync();
            Ensure(!risk.CanShowHistory && risk.History is null && risk.HistoryPeriodHours == 168, "Native sign-out retained history or its selected period.");
        }
        finally { window.Close(); }
    }

    private static IEnumerable<Geometry> DrawingGeometries(Drawing drawing)
    {
        if (drawing is GeometryDrawing geometry) yield return geometry.Geometry;
        if (drawing is DrawingGroup group)
            foreach (var item in group.Children)
                foreach (var child in DrawingGeometries(item)) yield return child;
    }

    private sealed class NativeHistoryClient(Guid governingEndpoint) : IRiskHistoryClient
    {
        private static readonly DateTimeOffset Now = new(2026, 11, 25, 16, 30, 0, TimeSpan.Zero);
        public static readonly string Fingerprint = new('b', 64);
        public const string PolicyVersion = "Pilot A & B";
        public List<(Guid? Endpoint, int Hours)> Requests { get; } = [];

        public Task<RiskReadResult<RiskHistoryView>> GetRiskHistoryAsync(Guid? endpointId, int periodHours, CancellationToken cancellationToken)
        {
            Requests.Add((endpointId, periodHours));
            var first = Now.AddHours(-20).AddTicks(1234567);
            int? count = endpointId is null ? 1 : null;
            Guid? governing = endpointId is null ? governingEndpoint : null;
            var history = new RiskHistoryView(endpointId, periodHours, Now, Now.AddHours(-periodHours),
            [
                new(first, 30, 30m, PolicyVersion, Fingerprint, null, ["firstCapture"], [], count, governing),
                new(Now.AddHours(-1), 100, 142.125m, PolicyVersion, Fingerprint, first, ["statusChanged"], ["SA-FW-001"], count, governing)
            ]);
            return Task.FromResult(new RiskReadResult<RiskHistoryView>(RiskReadOutcome.Success, history));
        }
    }
}
