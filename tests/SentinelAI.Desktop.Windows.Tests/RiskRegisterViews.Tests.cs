using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    // TASK-032: the Risk Register page lists Core's records with their attention flags, keeps business risk apart from
    // the technical score and saves a new record through Core.
    private static async Task RiskRegisterViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "risk-register-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        var client = new NativeRiskRegisterClient();
        using var register = new RiskRegisterViewModel(client);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, riskRegister: register);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Risk Register fixture did not reach sign-in.");
            auth.Username = "native-risk-register-admin";
            await auth.SignInAsync("Synthetic-Risk-Register-Admin!".AsMemory());
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.RiskRegister);
            await WaitForAsync(() => register.ListState == RiskRegisterListState.Ready, "The Risk Register page did not read Core's records.");
            await FlushAsync();
            var view = Descendants<RiskRegisterView>(window).Single();
            var grid = Descendants<DataGrid>(view).Single(control => AutomationProperties.GetAutomationId(control) == "RiskRegisterGrid");
            Ensure(grid.Items.Count == 1 && grid.Items[0] is RiskRegisterRow { Reference: "R-0001", Attention: "Review overdue" } &&
                   RegisterText(view, "RiskRegisterDistinction").Contains("never change alerts, detection or the technical risk score", StringComparison.Ordinal) &&
                   RegisterText(view, "RiskRegisterCounts").Contains("Needing attention: 1", StringComparison.Ordinal),
                "The register list, its attention flag or the distinction from the technical score was not shown.");
            var editor = Descendants<Border>(view).Single(control => AutomationProperties.GetAutomationId(control) == "RiskRegisterEditor");
            Ensure(!editor.IsVisible, "The editor was shown before a record was opened.");

            RegisterButton(view, "RiskRegisterNew").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => register.EditorMode == RiskRegisterEditorMode.Create, "New risk did not open the editor.");
            await FlushAsync();
            Ensure(editor.IsVisible && RegisterText(view, "RiskRegisterEditorTitle") == "New risk", "The new-risk editor was not shown.");
            register.Title = "Synthetic supplier outage";
            register.Treatment = "transfer";
            await FlushAsync();
            RegisterButton(view, "RiskRegisterSave").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => client.Created == 1 && register.EditorMode == RiskRegisterEditorMode.Edit, "Save did not send the record to Core.");
            await FlushAsync();
            Ensure(RegisterText(view, "RiskRegisterMessage") == "Risk recorded." &&
                   Descendants<StackPanel>(view).Single(panel => AutomationProperties.GetAutomationId(panel) == "RiskRegisterReview").IsVisible,
                "The saved record and its review section were not shown.");
            Ensure(trace.Messages.Count == 0, "Native Risk Register bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
            if (window.IsVisible) window.Close();
        }
    }

    private static string RegisterText(DependencyObject view, string id) =>
        Descendants<TextBlock>(view).Single(control => AutomationProperties.GetAutomationId(control) == id).Text;

    private static Button RegisterButton(DependencyObject view, string id) =>
        Descendants<Button>(view).Single(control => AutomationProperties.GetAutomationId(control) == id);

    private sealed class NativeRiskRegisterClient : IRiskRegisterClient
    {
        private static readonly Guid RiskId = Guid.Parse("4b1d3c5e-8f20-4a6b-9c7d-1e2f3a4b5c6d");
        public int Created;

        private static RiskRegisterDetail Record() => new(RiskId, "R-0002", "Synthetic supplier outage", null, null, new(3, 3, 9, "medium"), null,
            new(2, 2, 4, "low"), "transfer", null, null, null, "2099-04-05", "open", new(false, false, false, false), [], [], [],
            new DateTimeOffset(2099, 1, 5, 9, 0, 0, TimeSpan.Zero), "native-risk-register-admin", new DateTimeOffset(2099, 1, 5, 9, 0, 0, TimeSpan.Zero),
            "native-risk-register-admin", null, null, 1,
            [new RiskRegisterHistoryEntry(1, new DateTimeOffset(2099, 1, 5, 9, 0, 0, TimeSpan.Zero), "native-risk-register-admin", "created",
                [new RiskRegisterFieldChange("title", null, "Synthetic supplier outage")], null)], "2099-01-05");

        public Task<RiskRegisterResult<RiskRegisterPage>> GetRiskRegisterAsync(RiskRegisterQuery query, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterPage>(RiskRegisterOutcome.Success, new RiskRegisterPage(
                [new RiskRegisterSummary(Guid.Parse("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"), "R-0001", "Legacy application", "open", "accept", "Finance lead",
                    new(3, 4, 12, "high"), new(2, 3, 6, "medium"), "2099-01-01", null, "2099-02-01", new(true, false, false, true), 1, 0, 2,
                    new DateTimeOffset(2099, 1, 2, 10, 0, 0, TimeSpan.Zero))], 1, 0, 50, new(1, 0, 0, 1), "2099-01-05")));

        public Task<RiskRegisterResult<RiskRegisterDetail>> GetRiskRecordAsync(Guid riskId, CancellationToken cancellationToken) =>
            Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, Record()));

        public Task<RiskRegisterResult<RiskRegisterDetail>> CreateRiskRecordAsync(RiskRegisterDraft draft, CancellationToken cancellationToken)
        {
            Created++;
            return Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, Record()));
        }

        public Task<RiskRegisterResult<RiskRegisterDetail>> UpdateRiskRecordAsync(Guid riskId, long expectedVersion, RiskRegisterDraft draft,
            CancellationToken cancellationToken) => Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, Record()));

        public Task<RiskRegisterResult<RiskRegisterDetail>> ReviewRiskRecordAsync(Guid riskId, long expectedVersion, string nextReviewDate, string? note,
            CancellationToken cancellationToken) => Task.FromResult(new RiskRegisterResult<RiskRegisterDetail>(RiskRegisterOutcome.Success, Record()));
    }
}
