using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Scoring;

internal static partial class Program
{
    private static async Task RiskReportsViewsAsync()
    {
        await RiskViewsAsync();
        await ReportsViewsAsync();
        await WorkspaceSessionExpiryOrderingAsync();
    }

    private static async Task RiskViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "risk-test");
        var authentication = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authentication, new FakeAdministratorSetup { Created = true });
        var client = new NativeRiskClient();
        using var risk = new RiskViewModel(client);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, risk, null);
        var defaultSize = new Size(window.Width, window.Height);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Native Risk did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Risk);
            await FlushAsync();
            Ensure(client.Queries.Count == 0, "Native Risk queried protected data before authentication.");
            auth.Username = "native-risk-admin";
            await auth.SignInAsync("Synthetic-Wpf-Risk!".AsMemory());
            await WaitForAsync(() => risk.ListState == RiskListState.Ready, "Authenticated native Risk did not load.");
            await FlushAsync();
            var view = Descendants<RiskView>(window).Single();
            var grid = (DataGrid)view.FindName("RiskGrid");
            Ensure(grid.IsVisible && grid.IsReadOnly && grid.Items.Count == 50 && risk.TotalEndpoints == 125 &&
                client.Queries.Single() == (0, 50), "Native Risk did not use Core's bounded 50-endpoint server page.");
            Ensure(risk.VisibleEndpoints.Select(row => row.EndpointId).SequenceEqual(client.Items.Take(50).Select(row => row.EndpointId)) &&
                risk.VisibleEndpoints[0].Rank == 1 && risk.VisibleEndpoints[0].Score == 100 && risk.VisibleEndpoints[0].RawScore == 172.5m,
                "Native Risk changed Core's ranking, capped score or precise raw score.");
            Ensure(grid.EnableRowVirtualization && VirtualizingPanel.GetIsVirtualizing(grid) &&
                VirtualizingPanel.GetVirtualizationMode(grid) == VirtualizationMode.Recycling,
                "Native Risk disabled recycling row virtualization.");
            grid.UpdateLayout();
            var realized = Enumerable.Range(0, grid.Items.Count)
                .Count(index => grid.ItemContainerGenerator.ContainerFromIndex(index) is DataGridRow);
            Ensure(realized > 0 && realized < grid.Items.Count, "Native Risk eagerly realized its entire server page.");
            Ensure(grid.Columns.Count == 8 && grid.Columns.Any(column => Equals(column.Header, "Raw points")) &&
                grid.Columns.Any(column => Equals(column.Header, "Signal coverage")),
                "Native Risk omitted raw values or separated coverage information.");
            Ensure(RiskControl<TextBlock>(view, "RiskOrganizationScore").Text.Contains("100", StringComparison.Ordinal),
                "Native Risk omitted Core's organization score.");
            foreach (var expander in Descendants<Expander>(view)) expander.IsExpanded = true;
            await FlushAsync();
            Ensure(Descendants<TextBlock>(view).Any(text => text.IsVisible && text.Text == NativeRiskClient.OrganizationExplanation &&
                text.Inlines.Cast<Inline>().All(inline => inline is Run)), "Native organization explanation was modified or rendered as content.");
            foreach (var expander in Descendants<Expander>(view)) expander.IsExpanded = false;
            await FlushAsync();
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                Ensure(double.IsFinite(grid.Height) && grid.ActualHeight > 0, "Native Risk lost its bounded list viewport.");
            }
            window.Width = defaultSize.Width; window.Height = defaultSize.Height;
            await FlushAsync();

            RiskButton(view, "NextRiskPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.PageNumber == 2 && risk.ListState == RiskListState.Ready, "Native Risk next-page action did not finish.");
            await FlushAsync();
            Ensure(client.Queries[^1] == (50, 50) && risk.VisibleEndpoints[0].Rank == 51 && grid.Items.Count == 50,
                "Native Risk paged or ranked only a local subset.");
            RiskButton(view, "NextRiskPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.PageNumber == 3 && risk.ListState == RiskListState.Ready, "Native Risk final-page action did not finish.");
            await FlushAsync();
            Ensure(client.Queries[^1] == (100, 50) && grid.Items.Count == 25 && !RiskButton(view, "NextRiskPageButton").IsEnabled,
                "Native Risk omitted the partial final page or offered a nonexistent page.");
            RiskButton(view, "PreviousRiskPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.PageNumber == 2 && risk.ListState == RiskListState.Ready, "Native Risk previous-page action did not finish.");
            RiskButton(view, "PreviousRiskPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.PageNumber == 1 && risk.ListState == RiskListState.Ready, "Native Risk did not return to its first page.");
            await FlushAsync();
            grid.SelectedItem = risk.VisibleEndpoints[0];
            await FlushAsync();
            RiskButton(view, "OpenEndpointRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Ready, "Native endpoint Risk did not open.");
            await FlushAsync();
            Ensure(risk.Detail?.EndpointId == client.PrimaryId && risk.Detail.Score == 100 && risk.Detail.RawScore == 172.5m && risk.Detail.Saturated,
                "Native detail changed Core's identity, precise score or saturation flag.");
            AssertLiteralRiskText(view, "RiskDetailName", NativeRiskClient.LiteralName);
            AssertLiteralRiskText(view, "RiskDetailExplanation", NativeRiskClient.EndpointExplanation);
            foreach (var expander in Descendants<Expander>(view).ToArray()) expander.IsExpanded = true;
            await FlushAsync();
            AssertRiskFacts(view, "RiskFact_", new Dictionary<string, string>
            {
                ["Endpoint score"] = "100", ["Raw score"] = "172.5", ["Saturated"] = "True",
                ["Asset criticality"] = "critical", ["Asset criticality source"] = "userDeclared",
                ["Asset criticality multiplier"] = "2", ["Declared exposure"] = "internet",
                ["Exposure source"] = "userDeclared", ["Exposure multiplier"] = "1.5",
                ["Correlation base bonus"] = "5", ["Correlation bonus"] = "15"
            });
            AssertRiskFacts(view, "RiskCoverage_", new Dictionary<string, string>
            {
                ["Inventory state"] = "stale", ["Signal coverage"] = "partial", ["Known rule signals"] = "11",
                ["Total rule signals"] = "13", ["Inventory freshness (hours)"] = "12", ["Coverage caution"] = NativeRiskClient.LiteralCaution
            });
            AssertRiskFacts(view, "RiskPolicy_", new Dictionary<string, string>
            {
                ["Policy version"] = "risk-v1", ["Maximum score"] = "100", ["Remaining risk: accepted"] = "1",
                ["Remaining risk: resolved"] = "0", ["Default confidence weight"] = "1"
            });
            Ensure(risk.Detail!.Contributions.Count == 3, "Native detail omitted deterministic contributions.");
            foreach (var contribution in risk.Detail.Contributions)
            {
                var expander = RiskControl<Expander>(view, "RiskContribution_" + contribution.AlertId);
                expander.IsExpanded = true;
                await FlushAsync();
                Ensure(contribution.Factors.Count == 23, "Native contribution omitted part of Core's factor explanation.");
                foreach (var factor in contribution.Factors)
                    AssertLiteralRiskText(expander, "RiskFactor_" + factor.Label, factor.Value);
            }
            var first = risk.Detail.Contributions[0];
            var firstExpander = RiskControl<Expander>(view, "RiskContribution_" + first.AlertId);
            AssertRiskFacts(firstExpander, "RiskFactor_", new Dictionary<string, string>
            {
                ["Severity points"] = "50", ["Confidence weight"] = "0.75", ["Confidence source"] = "rulePolicyOverride",
                ["Asset multiplier"] = "2", ["Exposure multiplier"] = "1.5", ["Age multiplier"] = "1",
                ["Remaining risk multiplier"] = "1", ["Points before status effect"] = "112.5",
                ["Status reduction"] = "0", ["Contribution"] = "112.5", ["Correlation group"] = "FW",
                ["Latest snapshot confirmed"] = "True", ["Correlation eligible"] = "True"
            });
            var resolved = risk.Detail.Contributions.Single(row => row.Status == "resolved");
            AssertRiskFacts(RiskControl<Expander>(view, "RiskContribution_" + resolved.AlertId), "RiskFactor_", new Dictionary<string, string>
            {
                ["Age (days)"] = "40", ["Age band"] = "old", ["Age multiplier"] = "0.5",
                ["Remaining risk multiplier"] = "0", ["Points before status effect"] = "3.75",
                ["Status reduction"] = "3.75", ["Contribution"] = "0"
            });
            var reviewed = risk.Detail;
            var queryCount = client.Queries.Count;
            var detailCalls = client.DetailCalls;
            await auth.CheckSessionAsync();
            await FlushAsync();
            Ensure(client.Queries.Count == queryCount && client.DetailCalls == detailCalls && ReferenceEquals(risk.Detail, reviewed),
                "Periodic authentication validation refreshed Risk or discarded reviewed detail.");
            client.NextSuccessfulDetail = client.EmptyDetail;
            RiskButton(view, "RefreshRiskDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Ready && risk.Detail?.Score == 0,
                "Native Risk did not show Core's zero-score, missing-inventory result.");
            await FlushAsync();
            Ensure(risk.Detail!.Contributions.Count == 0 && RiskControl<TextBlock>(view, "RiskNoContributions").Text.Contains("No recorded", StringComparison.Ordinal),
                "Native Risk hid the absence of recorded contributions.");
            AssertRiskFacts(view, "RiskCoverage_", new Dictionary<string, string>
            {
                ["Inventory state"] = "missing", ["Signal coverage"] = "unknown", ["Known rule signals"] = "0",
                ["Inventory collected"] = "Unknown / not reported"
            });
            Ensure(RiskControl<TextBlock>(view, "RiskFact_Score interpretation").Text.Contains("A zero score does not establish", StringComparison.Ordinal),
                "Native Risk implied that a zero score established effective protection.");
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                AssertInsideWindow(window, RiskButton(view, "BackToRiskButton"));
            }
            var delayedDetail = new TaskCompletionSource<RiskReadResult<EndpointRiskDetail>>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextDetail = delayedDetail;
            RiskButton(view, "RefreshRiskDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Loading, "Native Risk omitted pending detail state.");
            await FlushAsync();
            Ensure(risk.Detail is null && !RiskButton(view, "RefreshRiskDetailButton").IsEnabled &&
                RiskControl<TextBlock>(view, "RiskDetailStatus").Text == risk.DetailStatusText,
                "Native loading detail retained a successful explanation or allowed overlapping reads.");
            delayedDetail.SetResult(new(RiskReadOutcome.Success, client.PrimaryDetail));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Ready, "Native delayed Risk detail did not finish.");
            client.DetailOutcome = RiskReadOutcome.Unavailable;
            RiskButton(view, "RefreshRiskDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.Unavailable, "Native Risk omitted unavailable detail state.");
            await FlushAsync();
            Ensure(risk.Detail is null && RiskControl<TextBlock>(view, "RiskDetailStatus").Text == risk.DetailStatusText,
                "Native unavailable detail retained a successful explanation or hid its state.");
            client.DetailOutcome = RiskReadOutcome.NotFound;
            RiskButton(view, "RefreshRiskDetailButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.DetailState == RiskDetailState.NotFound, "Native Risk omitted missing-endpoint state.");
            await FlushAsync();
            Ensure(risk.Detail is null && RiskControl<TextBlock>(view, "RiskDetailStatus").Text == risk.DetailStatusText,
                "Native missing-endpoint state retained a successful explanation.");
            RiskButton(view, "BackToRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();

            var delayed = new TaskCompletionSource<RiskReadResult<RiskPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextPage = delayed;
            RiskButton(view, "RefreshRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.ListState == RiskListState.Loading, "Native Risk omitted its loading state.");
            await FlushAsync();
            Ensure(!RiskButton(view, "RefreshRiskButton").IsEnabled && RiskControl<TextBlock>(view, "RiskListStatus").Text == risk.ListStatusText,
                "Native Risk loading state hid progress or allowed overlapping refreshes.");
            delayed.SetResult(client.Page(client.Queries[^1].Offset, client.Queries[^1].Limit));
            await WaitForAsync(() => risk.ListState == RiskListState.Ready, "Native delayed Risk refresh did not finish.");
            client.ListOutcome = RiskReadOutcome.Unavailable;
            RiskButton(view, "RefreshRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.ListState == RiskListState.Unavailable, "Native Risk omitted Core-unavailable state.");
            await FlushAsync();
            Ensure(grid.Items.Count == 0 && risk.Organization is null && RiskControl<TextBlock>(view, "RiskErrorText").Text == risk.ErrorText,
                "Native Core failure left successful Risk information displayed.");
            client.ListOutcome = RiskReadOutcome.Success;
            client.Items = [];
            RiskButton(view, "RefreshRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.ListState == RiskListState.Empty, "Native Risk omitted its no-endpoint state.");
            await FlushAsync();
            Ensure(RiskControl<TextBlock>(view, "RiskListStatus").Text == risk.ListStatusText, "Native empty Risk state was not visible.");
            client.RestoreItems();
            RiskButton(view, "RefreshRiskButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => risk.ListState == RiskListState.Ready, "Native Risk did not recover after Core became available.");
            auth.SignOut();
            await FlushAsync();
            Ensure(risk.TotalEndpoints == 0 && risk.VisibleEndpoints.Count == 0 && risk.Detail is null && risk.Organization is null && !view.IsVisible,
                "Sign-out retained native protected Risk data.");
            Ensure(trace.Messages.Count == 0, "Native Risk bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
            window.Close();
        }
        finally
        {
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static async Task ReportsViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "reports-test");
        var authentication = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authentication, new FakeAdministratorSetup { Created = true });
        var client = new NativeReportsClient();
        var saver = new NativeReportSaver();
        using var reports = new ReportsViewModel(client, saver, new NativeReportTimeProvider());
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, reports);
        var defaultSize = new Size(window.Width, window.Height);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Native Reports did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Reports);
            await FlushAsync();
            Ensure(client.Periods.Count == 0 && saver.Calls == 0, "Native Reports read or saved protected content before authentication.");
            auth.Username = "native-report-admin";
            await auth.SignInAsync("Synthetic-Wpf-Reports!".AsMemory());
            await FlushAsync();
            var view = Descendants<ReportsView>(window).Single();
            var from = ReportControl<DatePicker>(view, "ReportFromDate");
            var to = ReportControl<DatePicker>(view, "ReportToDate");
            Ensure(from.SelectedDate == new DateTime(2026, 2, 1) && to.SelectedDate == new DateTime(2026, 2, 28) &&
                reports.FromDate?.Kind == DateTimeKind.Unspecified && reports.ToDate?.Kind == DateTimeKind.Unspecified,
                "Native Reports did not default to the previous complete UTC month as calendar dates.");
            Ensure(client.Periods.Count == 0 && reports.State == ReportState.NotGenerated && ReportButton(view, "GenerateReportButton").IsEnabled &&
                !ReportButton(view, "SaveReportButton").IsEnabled, "Opening native Reports implicitly generated or offered an absent report.");
            SetReportDate(from, new DateTime(2026, 3, 3));
            SetReportDate(to, new DateTime(2026, 3, 2));
            await FlushAsync();
            Ensure(!ReportButton(view, "GenerateReportButton").IsEnabled && client.Periods.Count == 0 &&
                ReportControl<TextBlock>(view, "ReportValidationText").Text == reports.ValidationText && reports.ValidationText.Length > 0,
                "Native Reports accepted an unordered range or hid its date validation.");
            SetReportDate(from, new DateTime(2026, 1, 1));
            SetReportDate(to, new DateTime(2026, 1, 31));
            await FlushAsync();
            Ensure(client.Periods.Count == 0 && reports.CanGenerate, "Native report date edits generated a report automatically.");

            var delayed = new TaskCompletionSource<SecurityReportResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextGeneration = delayed;
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.IsGenerating, "Native Reports omitted its pending generation state.");
            await FlushAsync();
            Ensure(client.Periods.Single() == new ReportDateRange(new(2026, 1, 1), new(2026, 1, 31)) &&
                !ReportButton(view, "GenerateReportButton").IsEnabled && !ReportButton(view, "SaveReportButton").IsEnabled &&
                ReportControl<TextBlock>(view, "ReportStatus").Text == reports.StatusText,
                "Native generation sent wrong dates, hid progress or allowed overlapping work.");
            var document = client.Document(client.Periods[^1]);
            delayed.SetResult(new(ReportOutcome.Success, document));
            await WaitForAsync(() => reports.State == ReportState.Ready && !reports.IsBusy, "Native report generation did not finish.");
            await FlushAsync();
            Ensure(reports.ByteCount == NativeReportsClient.Content.Length && ReportButton(view, "SaveReportButton").IsEnabled &&
                ReportControl<TextBlock>(view, "ReportPeriod").Text == reports.PeriodText &&
                ReportControl<TextBlock>(view, "ReportFileName").Text == reports.SuggestedFileName &&
                ReportControl<TextBlock>(view, "ReportSize").Text == reports.ReportSizeText,
                "Native report metadata did not describe Core's generated download.");
            Ensure(!Descendants<WebBrowser>(view).Any() && !Descendants<TextBlock>(view).Any(text => text.Text.Contains("synthetic-report-script", StringComparison.Ordinal)),
                "Native Reports rendered the HTML body instead of keeping it as a download.");
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                Ensure(ReportControl<DatePicker>(view, "ReportFromDate").ActualWidth > 0 &&
                    ReportControl<DatePicker>(view, "ReportToDate").ActualWidth > 0,
                    "Native Reports lost usable date selection at a supported window size.");
            }
            var generatedCalls = client.Periods.Count;
            await auth.CheckSessionAsync();
            await FlushAsync();
            Ensure(client.Periods.Count == generatedCalls && reports.ByteCount == NativeReportsClient.Content.Length,
                "Periodic authentication validation regenerated or discarded an available report.");
            saver.Outcome = ReportSaveOutcome.Cancelled;
            ReportButton(view, "SaveReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => saver.Calls == 1 && !reports.IsSaving, "Native report save cancellation did not finish.");
            await FlushAsync();
            Ensure(reports.HasReport && reports.CanSave && reports.SaveStatusText.Contains("cancelled", StringComparison.OrdinalIgnoreCase) &&
                ReportControl<TextBlock>(view, "ReportSaveStatus").Text == reports.SaveStatusText,
                "Canceling native saving erased the generated report or hid feedback.");
            saver.Outcome = ReportSaveOutcome.Saved;
            ReportButton(view, "SaveReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => saver.Calls == 2 && !reports.IsSaving, "Native report save did not finish.");
            await FlushAsync();
            Ensure(saver.LastContent?.SequenceEqual(NativeReportsClient.Content) == true && saver.LastFileName == reports.SuggestedFileName &&
                reports.SaveStatusText.Contains("saved", StringComparison.OrdinalIgnoreCase),
                "Native Save did not pass the exact Core report and safe suggested filename to the save service.");

            var dateEditedGeneration = new TaskCompletionSource<SecurityReportResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextGeneration = dateEditedGeneration;
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.IsGenerating, "Native date-edit cancellation test did not begin generation.");
            var dateEditedPeriod = client.Periods[^1];
            SetReportDate(from, new DateTime(2026, 1, 2));
            await FlushAsync();
            Ensure(client.LastToken.IsCancellationRequested && reports.State == ReportState.NotGenerated && !reports.HasReport &&
                document.ByteCount == 0 && !ReportButton(view, "SaveReportButton").IsEnabled,
                "Native date edits retained a replaced report or failed to cancel generation.");
            var dateEditedDocument = client.Document(dateEditedPeriod);
            dateEditedGeneration.SetResult(new(ReportOutcome.Success, dateEditedDocument));
            await WaitForAsync(() => dateEditedDocument.ByteCount == 0, "Native Reports did not erase a response for obsolete selected dates.");
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.State == ReportState.Ready && !reports.IsBusy, "Native Reports did not generate the newly selected period.");
            document = client.LastDocument!;
            await FlushAsync();

            var heldSave = new TaskCompletionSource<ReportSaveResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            saver.NextSave = heldSave;
            ReportButton(view, "SaveReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.IsSaving, "Native report save never entered its pending state.");
            var saveOperation = reports.SaveAsync();
            await FlushAsync();
            Ensure(!ReportButton(view, "SaveReportButton").IsEnabled && !ReportButton(view, "GenerateReportButton").IsEnabled,
                "Native saving allowed overlapping generation or a second save.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Overview);
            await FlushAsync();
            Ensure(!reports.HasReport && reports.ByteCount == 0 && document.ByteCount == 0 && saver.LastToken.IsCancellationRequested,
                "Navigation retained an owned report or failed to cancel pending saving.");
            heldSave.SetResult(new(ReportSaveOutcome.Saved, "stale-synthetic.html"));
            await saveOperation;
            await FlushAsync();
            Ensure(reports.SaveStatusText.Length == 0 && reports.State == ReportState.NotGenerated,
                "A stale native save completion restored report feedback after navigation.");

            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Reports);
            await FlushAsync();
            view = Descendants<ReportsView>(window).Single();
            var staleGeneration = new TaskCompletionSource<SecurityReportResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextGeneration = staleGeneration;
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.IsGenerating, "Native stale-response test did not begin generation.");
            var stalePeriod = client.Periods[^1];
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Overview);
            await FlushAsync();
            Ensure(client.LastToken.IsCancellationRequested && !reports.IsBusy && !reports.HasReport,
                "Native navigation failed to cancel report generation.");
            var staleDocument = client.Document(stalePeriod);
            staleGeneration.SetResult(new(ReportOutcome.Success, staleDocument));
            await WaitForAsync(() => staleDocument.ByteCount == 0, "Native Reports did not erase a report returned after navigation.");
            Ensure(reports.State == ReportState.NotGenerated && reports.ByteCount == 0, "Stale report generation restored cleared content.");

            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Reports);
            await FlushAsync();
            view = Descendants<ReportsView>(window).Single();
            client.Outcome = ReportOutcome.Unavailable;
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.State == ReportState.Unavailable && !reports.IsBusy, "Native Reports omitted Core-unavailable state.");
            await FlushAsync();
            Ensure(!reports.HasReport && !ReportButton(view, "SaveReportButton").IsEnabled &&
                ReportControl<TextBlock>(view, "ReportErrorText").Text == reports.ErrorText && reports.ErrorText.Length > 0,
                "Native generation failure left a successful download or hid its error.");
            client.Outcome = ReportOutcome.Success;
            var signedOutGeneration = new TaskCompletionSource<SecurityReportResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.NextGeneration = signedOutGeneration;
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.IsGenerating, "Native sign-out test did not begin report generation.");
            var signedOutPeriod = client.Periods[^1];
            auth.SignOut();
            await FlushAsync();
            Ensure(!view.IsVisible && !reports.HasReport && reports.ByteCount == 0 && client.LastToken.IsCancellationRequested,
                "Sign-out retained native protected report content or pending generation.");
            var signedOutDocument = client.Document(signedOutPeriod);
            signedOutGeneration.SetResult(new(ReportOutcome.Success, signedOutDocument));
            await WaitForAsync(() => signedOutDocument.ByteCount == 0, "A report returned after sign-out was not erased.");
            auth.Username = "native-report-admin";
            await auth.SignInAsync("Synthetic-Wpf-Reports!".AsMemory());
            await FlushAsync();
            ReportButton(view, "GenerateReportButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => reports.State == ReportState.Ready && !reports.IsBusy, "Native Reports did not recover after explicit sign-in.");
            authentication.Session = SessionStatus.Expired;
            await auth.CheckSessionAsync();
            await FlushAsync();
            Ensure(!reports.HasReport && reports.ByteCount == 0 && !view.IsVisible && !auth.IsSignedIn,
                "Session expiry retained native protected report content.");
            Ensure(trace.Messages.Count == 0, "Native Reports bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
            window.Close();
        }
        finally
        {
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static async Task WorkspaceSessionExpiryOrderingAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "session-ordering-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        var riskClient = new NativeRiskClient();
        using var risk = new RiskViewModel(riskClient);
        var reportClient = new NativeReportsClient();
        using var reports = new ReportsViewModel(reportClient, new NativeReportSaver(), new NativeReportTimeProvider());
        Action? duringSignOut = null;
        // Register before MainWindow so a public notification holds sign-out in
        // progress before its workspace-clear subscriber executes.
        System.ComponentModel.PropertyChangedEventHandler signOutOverlap = (_, change) =>
        {
            if (change.PropertyName == nameof(AuthenticationViewModel.IsSignedIn) && !auth.IsSignedIn &&
                duringSignOut is { } overlap)
            {
                duringSignOut = null;
                overlap();
            }
        };
        auth.PropertyChanged += signOutOverlap;
        var window = new MainWindow(shell, auth, null, null, risk, reports);
        var navigation = RequireControl<ListBox>(window, "NavigationList");
        Task? pendingWorker = null;
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var uiThread = Environment.CurrentManagedThreadId;
        var riskExpiryThread = 0;
        var reportExpiryThread = 0;
        var riskExpiries = 0;
        var reportExpiries = 0;
        risk.SessionExpired += (_, _) =>
        {
            Volatile.Write(ref riskExpiryThread, Environment.CurrentManagedThreadId);
            Interlocked.Increment(ref riskExpiries);
        };
        reports.SessionExpired += (_, _) =>
        {
            Volatile.Write(ref reportExpiryThread, Environment.CurrentManagedThreadId);
            Interlocked.Increment(ref reportExpiries);
        };
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut,
                "Session-ordering fixture did not reach sign-in.");
            SignInWithoutDispatcherYield();
            await FlushAsync();
            Ensure(shell.CurrentPage.Id == PageId.Overview, "Session-ordering fixture must not automatically refresh a protected page.");
            await reports.GenerateAsync();
            var retainedDocument = reportClient.LastDocument;
            Ensure(reports.HasReport && retainedDocument?.ByteCount > 0,
                "Session-ordering fixture did not retain a synthetic report before sign-out.");
            foreach (var useReports in new[] { false, true })
            {
                var label = useReports ? "Reports" : "Risk";
                var riskResponse = new TaskCompletionSource<RiskReadResult<RiskPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
                var reportResponse = new TaskCompletionSource<SecurityReportResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (useReports) reportClient.NextGeneration = reportResponse;
                else riskClient.NextPage = riskResponse;
                pendingWorker = Task.Run(() => useReports ? reports.GenerateAsync() : risk.RefreshAsync());
                await WaitForAsync(() => useReports ? reports.IsGenerating : risk.IsLoading,
                    "Worker " + label + " request did not start before sign-out.");
                var worker = pendingWorker;
                duringSignOut = () =>
                {
                    ResolveUnauthorized();
                    Ensure(worker.Wait(TimeSpan.FromSeconds(3)),
                        "Worker " + label + " session expiry blocked while UI sign-out was in progress.");
                    Ensure(worker.IsCompletedSuccessfully,
                        "Worker " + label + " request failed during overlapping sign-out.");
                };
                // Keep dispatcher callbacks queued until the replacement session
                // exists; the expired request still belongs to the prior session.
                using (window.Dispatcher.DisableProcessing())
                {
                    auth.SignOut();
                    Ensure(duringSignOut is null && !auth.IsSignedIn && !navigation.IsEnabled &&
                        risk.ListState == RiskListState.NotLoaded && !reports.HasReport && retainedDocument!.ByteCount == 0,
                        "UI sign-out did not synchronously clear the native workspace.");
                    SignInWithoutDispatcherYield();
                }
                await worker.WaitAsync(TimeSpan.FromSeconds(5));
                await FlushAsync();
                var expiryThread = useReports ? Volatile.Read(ref reportExpiryThread) : Volatile.Read(ref riskExpiryThread);
                var expiryCount = useReports ? Volatile.Read(ref reportExpiries) : Volatile.Read(ref riskExpiries);
                Ensure(expiryThread != 0 && expiryThread != uiThread && expiryCount == 1,
                    label + " expiry did not execute on the worker used by this concurrency regression.");
                Ensure(auth.IsSignedIn && navigation.IsEnabled,
                    "Stale queued " + label + " expiry signed out the replacement native session.");

                // An unauthorized response from the current session must still
                // close access, rather than being suppressed with stale callbacks.
                pendingWorker = Task.Run(() =>
                {
                    if (useReports) reportClient.Outcome = ReportOutcome.Unauthenticated;
                    else riskClient.ListOutcome = RiskReadOutcome.Unauthenticated;
                    return useReports ? reports.GenerateAsync() : risk.RefreshAsync();
                });
                await pendingWorker.WaitAsync(TimeSpan.FromSeconds(5));
                await WaitForAsync(() => !auth.IsSignedIn && !navigation.IsEnabled,
                    "Current worker " + label + " expiry did not end the native session.");
                expiryCount = useReports ? Volatile.Read(ref reportExpiries) : Volatile.Read(ref riskExpiries);
                Ensure(!reports.HasReport && risk.ListState == RiskListState.NotLoaded && expiryCount == 2,
                    "Current " + label + " expiry retained protected workspace data.");
                riskClient.ListOutcome = RiskReadOutcome.Success;
                reportClient.Outcome = ReportOutcome.Success;
                SignInWithoutDispatcherYield();
                await FlushAsync();

                void ResolveUnauthorized()
                {
                    if (useReports) reportResponse.SetResult(new(ReportOutcome.Unauthenticated));
                    else riskResponse.SetResult(new(RiskReadOutcome.Unauthenticated));
                }
            }
            Ensure(trace.Messages.Count == 0, "Native session-ordering bindings produced warnings/errors: " +
                string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            duringSignOut = null;
            auth.PropertyChanged -= signOutOverlap;
            // On an assertion failure, releasing the public notification permits
            // an old blocked worker to unwind before window disposal takes locks.
            try
            {
                if (pendingWorker is not null) await pendingWorker.WaitAsync(TimeSpan.FromSeconds(5));
            }
            finally
            {
                if (window.IsVisible) window.Close();
                bindingSource.Listeners.Remove(trace);
                bindingSource.Switch.Level = originalLevel;
            }
        }

        void SignInWithoutDispatcherYield()
        {
            auth.Username = "native-session-ordering-admin";
            var signIn = auth.SignInAsync("Synthetic-Wpf-Session-Ordering!".AsMemory());
            Ensure(signIn.IsCompletedSuccessfully,
                "Session-ordering fixture requires an immediate synthetic sign-in before dispatcher callbacks run.");
            signIn.GetAwaiter().GetResult();
            Ensure(auth.IsSignedIn, "Session-ordering fixture did not establish a replacement session.");
        }
    }

    private static T RiskControl<T>(DependencyObject view, string id) where T : FrameworkElement => Descendants<T>(view)
        .Single(control => control.IsVisible && AutomationProperties.GetAutomationId(control) == id);
    private static Button RiskButton(RiskView view, string id) => RiskControl<Button>(view, id);
    private static T ReportControl<T>(ReportsView view, string id) where T : FrameworkElement => Descendants<T>(view)
        .Single(control => control.IsVisible && AutomationProperties.GetAutomationId(control) == id);
    private static Button ReportButton(ReportsView view, string id) => ReportControl<Button>(view, id);

    private static void AssertLiteralRiskText(DependencyObject view, string id, string value)
    {
        var text = RiskControl<TextBlock>(view, id);
        Ensure(text.Text == value && text.Inlines.Cast<Inline>().All(inline => inline is Run),
            "Native Risk text was modified or rendered as executable/interactive content: " + id);
    }

    private static void AssertRiskFacts(DependencyObject view, string prefix, IReadOnlyDictionary<string, string> facts)
    {
        foreach (var (label, value) in facts) AssertLiteralRiskText(view, prefix + label, value);
    }

    private static void SetReportDate(DatePicker picker, DateTime value)
    {
        picker.SelectedDate = value;
        picker.GetBindingExpression(DatePicker.SelectedDateProperty)?.UpdateSource();
    }

    private sealed class NativeRiskClient : IRiskClient
    {
        public const string LiteralName = "<script>synthetic-endpoint</script> & {Binding Credential}";
        public const string OrganizationExplanation = "<b>synthetic-organization</b> & <Hyperlink>literal</Hyperlink>";
        public const string EndpointExplanation = "<script>synthetic-risk</script> & <Run>literal</Run>";
        public const string LiteralCaution = "<img src=x onerror=synthetic()> & Unknown protection";
        private const string LiteralTitle = "<a href='file:///synthetic'>finding</a> & {Binding Secret}";
        private const string LiteralReason = "<script>synthetic-reason</script> & <Hyperlink>literal</Hyperlink>";
        private static readonly DateTimeOffset EvaluatedUtc = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
        private readonly IReadOnlyList<EndpointRiskSummary> _initialItems;
        private readonly ScoringPolicySnapshot _policy;
        private readonly EndpointRiskDetail _primaryDetail;
        public Guid PrimaryId { get; } = Guid.NewGuid();
        public IReadOnlyList<EndpointRiskSummary> Items;
        public List<(int Offset, int Limit)> Queries { get; } = [];
        public int DetailCalls;
        public RiskReadOutcome ListOutcome = RiskReadOutcome.Success;
        public RiskReadOutcome DetailOutcome = RiskReadOutcome.Success;
        public TaskCompletionSource<RiskReadResult<RiskPage>>? NextPage;
        public TaskCompletionSource<RiskReadResult<EndpointRiskDetail>>? NextDetail;
        public EndpointRiskDetail PrimaryDetail => _primaryDetail;
        public EndpointRiskDetail? NextSuccessfulDetail;
        public EndpointRiskDetail EmptyDetail => _primaryDetail with
        {
            InventoryCollectedUtc = null,
            Risk = _primaryDetail.Risk with
            {
                Score = 0, RawScore = 0m, Saturated = false, Context = new(), AssetCriticalityMultiplier = 1m,
                ExposureMultiplier = 1m, Contributions = [], CorrelatedGroups = [], CorrelationBaseBonus = 0m, CorrelationBonus = 0m
            },
            Coverage = new("missing", "unknown", 0, 13, LiteralCaution), Alerts = []
        };

        public NativeRiskClient()
        {
            var policy = new ScoringPolicy();
            policy.ConfidenceByRule.Add("SA-FW-001", 0.75m);
            policy.ConfidenceByRule.Add("SA-RDP-001", 0.5m);
            _policy = new(policy.Version, policy.SeverityPoints, policy.DefaultConfidence, policy.ConfidenceByRule,
                policy.AssetMultipliers, policy.ExposureMultipliers, policy.RemainingRiskByStatus, policy.FreshForDays,
                policy.AgingForDays, policy.AgingMultiplier, policy.OldMultiplier, policy.CorrelationPointsPerExtraGroup,
                policy.MaximumCorrelationBaseBonus, policy.CorrelationGroupsByRule, 100);
            var coverage = new RiskCoverage("stale", "partial", 11, 13, LiteralCaution);
            Items = _initialItems = Enumerable.Range(0, 125).Select(index => new EndpointRiskSummary(index == 0 ? PrimaryId : Guid.NewGuid(),
                index == 0 ? LiteralName : $"synthetic-risk-endpoint-{index:000}", index == 1 ? null : EvaluatedUtc.AddDays(-1),
                index == 0 ? 100 : Math.Max(0, 100 - index), index == 0 ? 172.5m : Math.Max(0, 100 - index),
                index == 1 ? new RiskCoverage("missing", "unknown", 0, 13, LiteralCaution) : coverage,
                index == 0 ? 2 : 0, LiteralReason, EvaluatedUtc)).ToArray();
            var contributions = new[]
            {
                new AlertRiskContribution(Guid.NewGuid(), "SA-FW-001", "critical", "accepted", EvaluatedUtc.AddDays(-1),
                    1m, "fresh", false, 50m, 0.75m, "rulePolicyOverride", 2m, 1.5m, 1m, 1m, 112.5m, 0m, 112.5m, "FW", true, true),
                new AlertRiskContribution(Guid.NewGuid(), "SA-UAC-001", "medium", "investigating", EvaluatedUtc.AddDays(-1),
                    1m, "fresh", false, 15m, 1m, "policyDefault", 2m, 1.5m, 1m, 1m, 45m, 0m, 45m, "UAC", true, true),
                new AlertRiskContribution(Guid.NewGuid(), "SA-RDP-001", "low", "resolved", EvaluatedUtc.AddDays(-40),
                    40m, "old", false, 5m, 0.5m, "rulePolicyOverride", 2m, 1.5m, 0.5m, 0m, 3.75m, 3.75m, 0m, "RDP", false, false)
            };
            var context = new EndpointScoringContext("critical", "internet", EvaluatedUtc.AddDays(-1), "userDeclared", "userDeclared");
            var score = new EndpointRiskScore(PrimaryId, 100, 172.5m, true, EvaluatedUtc, context, 2m, 1.5m,
                contributions, ["FW", "UAC"], 5m, 15m, EndpointExplanation);
            _primaryDetail = new(PrimaryId, LiteralName, context.LatestInventoryUtc, score, coverage,
                contributions.Select(item => new RiskAlertView(item.AlertId, item.RuleId, LiteralTitle, item.Severity,
                    item.Status, item.LastObservedUtc, LiteralReason)).ToArray(), _policy, 12);
        }

        public Task<RiskReadResult<RiskPage>> GetRiskPageAsync(int offset, int limit, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Queries.Add((offset, limit));
            if (NextPage is { } delayed) { NextPage = null; return delayed.Task; }
            return Task.FromResult(Page(offset, limit));
        }

        public RiskReadResult<RiskPage> Page(int offset, int limit)
        {
            if (ListOutcome != RiskReadOutcome.Success) return new(ListOutcome);
            var organization = new OrganizationRiskView(Items.Count == 0 ? 0 : 100, Items.Count, Items.Count == 0 ? [] : [PrimaryId],
                Items.Count == 0 ? 0 : 1, false, "maximumEndpointScore", OrganizationExplanation, EvaluatedUtc,
                Math.Max(0, Items.Count - 1), Math.Min(1, Items.Count), Math.Min(1, Items.Count), Math.Max(0, Items.Count - 1),
                Math.Max(0, Items.Count - 1), new(4, 3, 2, 1));
            return new(RiskReadOutcome.Success, new(organization, Items.Skip(offset).Take(limit).ToArray(), Items.Count, offset, limit, _policy, 12));
        }

        public Task<RiskReadResult<EndpointRiskDetail>> GetEndpointRiskDetailAsync(Guid endpointId, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            DetailCalls++;
            if (NextDetail is { } delayed) { NextDetail = null; return delayed.Task; }
            var outcome = DetailOutcome;
            DetailOutcome = RiskReadOutcome.Success;
            var detail = NextSuccessfulDetail ?? _primaryDetail;
            NextSuccessfulDetail = null;
            return Task.FromResult(outcome == RiskReadOutcome.Success
                ? new RiskReadResult<EndpointRiskDetail>(RiskReadOutcome.Success, detail) : new(outcome));
        }

        public void RestoreItems() => Items = _initialItems;
    }

    private sealed class NativeReportTimeProvider : TimeProvider
    {
        // UTC is March even though this instant's offset date is February.
        public override DateTimeOffset GetUtcNow() => new(2026, 2, 28, 23, 30, 0, TimeSpan.FromHours(-2));
    }

    private sealed class NativeReportsClient : IReportsClient
    {
        public static readonly byte[] Content = Encoding.UTF8.GetBytes("<!doctype html><html><body>synthetic-report-script &lt;script&gt;literal&lt;/script&gt;</body></html>");
        public List<ReportDateRange> Periods { get; } = [];
        public ReportOutcome Outcome = ReportOutcome.Success;
        public CancellationToken LastToken;
        public TaskCompletionSource<SecurityReportResult>? NextGeneration;
        public SecurityReportDocument? LastDocument;
        public Task<SecurityReportResult> GenerateSecurityReportAsync(ReportDateRange period, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Periods.Add(period);
            LastToken = token;
            if (NextGeneration is { } delayed) { NextGeneration = null; return delayed.Task; }
            return Task.FromResult(Outcome == ReportOutcome.Success ? new SecurityReportResult(Outcome, Document(period)) : new(Outcome));
        }
        public SecurityReportDocument Document(ReportDateRange period) => LastDocument = new(period, Content);
    }

    private sealed class NativeReportSaver : IReportSaveService
    {
        public int Calls;
        public ReportSaveOutcome Outcome = ReportSaveOutcome.Saved;
        public byte[]? LastContent;
        public string? LastFileName;
        public CancellationToken LastToken;
        public TaskCompletionSource<ReportSaveResult>? NextSave;
        public Task<ReportSaveResult> SaveAsync(SecurityReportDocument document, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Calls++;
            LastToken = token;
            LastFileName = document.SuggestedFileName;
            if (NextSave is { } delayed) { NextSave = null; return delayed.Task; }
            if (Outcome == ReportSaveOutcome.Saved) LastContent = document.CopyContent();
            return Task.FromResult(new ReportSaveResult(Outcome, Outcome == ReportSaveOutcome.Saved ? LastFileName : null));
        }
    }
}
