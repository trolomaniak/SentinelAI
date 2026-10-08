using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Documents;
using SentinelAI.Contracts.Ai;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    private static async Task AiLicenseSettingsViewsAsync()
    {
        await AiLicenseWorkspaceAsync();
        await AiLicenseSessionExpiryOrderingAsync();
    }

    private static async Task AiLicenseWorkspaceAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "ai-license-settings-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        var licenseClient = new NativeLicenseClient();
        using var license = new LicenseViewModel(licenseClient);
        var aiClient = new NativeAiClient();
        using var ai = new AiExplanationViewModel(aiClient);
        var alertsClient = new NativeAiAlertsClient();
        using var alerts = new AlertsViewModel(alertsClient, new NativeAlertEndpointsClient([alertsClient.EndpointId]));
        var riskClient = new NativeRiskClient();
        using var risk = new RiskViewModel(riskClient);
        var reportsClient = new NativeReportsClient();
        using var reports = new ReportsViewModel(reportsClient, new NativeReportSaver(), new NativeReportTimeProvider());
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, alerts, risk, reports, license, ai);
        var defaultSize = new Size(window.Width, window.Height);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "AI/Settings fixture did not reach sign-in.");
            await NavigateAsync(PageId.Settings);
            await FlushAsync();
            Ensure(licenseClient.ReadCalls == 0 && licenseClient.RenewCalls == 0 && aiClient.RequestedIds.Count == 0,
                "Native AI/Settings queried protected data before authentication.");
            auth.Username = "native-ai-settings-admin";
            await auth.SignInAsync("Synthetic-Wpf-Ai-Settings!".AsMemory());
            await WaitForAsync(() => license.State == LicenseState.Ready, "Authenticated Settings did not read licensing.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            var cloudPreference = AiSettingsControl<CheckBox>(settings, "CloudAiRequestsEnabled");
            Ensure(cloudPreference.IsChecked == false && !ai.CloudRequestsEnabled && aiClient.RequestedIds.Count == 0,
                "Cloud AI did not default to explicit session opt-in.");
            AiSettingsText(settings, "SettingsDesktopVersion", shell.Version);
            AiSettingsText(settings, "SettingsCoreAddress", "http://127.0.0.1:5000");
            Ensure(!Descendants<PasswordBox>(settings).Any() && !Descendants<TextBox>(settings).Any(),
                "Settings exposed an editable credential or arbitrary service destination.");
            foreach (var mode in new[] { "FULL", "GRACE", "SAFE_MODE", "RECOVERING" })
            {
                licenseClient.Status = NativeLicenseClient.Snapshot(mode);
                AiSettingsButton(settings, "RefreshLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                await WaitForAsync(() => license.State == LicenseState.Ready && license.ModeText == mode,
                    "Native Settings did not bind Core's license mode " + mode + ".");
                await FlushAsync();
                AiSettingsText(settings, "LicenseMode", mode);
                AiSettingsText(settings, "LicenseFeatures", license.FeaturesText);
                Ensure(AiSettingsButton(settings, "RenewLicenseButton").IsEnabled == (mode != "RECOVERING"),
                    "Native renewal ignored Core's already recovering state.");
                foreach (var expander in Descendants<Expander>(settings)) expander.IsExpanded = true;
                await FlushAsync();
                AiSettingsText(settings, "LicenseCriticalTelemetry", "Critical telemetry collection: True");
                AiSettingsText(settings, "LicenseLocalDetection", "Local detection rules: True");
                AiSettingsText(settings, "LicenseCriticalAlerts", "Critical alerts: True");
                AiSettingsText(settings, "LicenseRecentIncidents", "Recent incidents: True");
                AiSettingsText(settings, "LicenseEmergencyExport", "Emergency export: True");
                AiSettingsText(settings, "LicensePremiumFeatures", "Premium features: " + (mode != "SAFE_MODE"));
                AiSettingsText(settings, "LicenseEffectiveTime", "2026-10-08 12:00:00 UTC");
                AiSettingsText(settings, "LicenseClockRollback", license.ClockRollbackText);
                Ensure(aiClient.RequestedIds.Count == 0, "A license mode change automatically requested cloud AI.");
            }
            // Rendering must retain every Core capability, including an unusual
            // false public capability, without inventing local permissions.
            licenseClient.Status = NativeLicenseClient.Snapshot("FULL") with
            {
                Capabilities = new(false, false, false, false, false, true)
            };
            await license.RefreshAsync();
            await FlushAsync();
            AiSettingsText(settings, "LicenseCriticalTelemetry", "Critical telemetry collection: False");
            AiSettingsText(settings, "LicenseLocalDetection", "Local detection rules: False");
            AiSettingsText(settings, "LicenseCriticalAlerts", "Critical alerts: False");
            AiSettingsText(settings, "LicenseRecentIncidents", "Recent incidents: False");
            AiSettingsText(settings, "LicenseEmergencyExport", "Emergency export: False");
            licenseClient.Status = NativeLicenseClient.Snapshot("FULL");
            await license.RefreshAsync();
            var renewal = new TaskCompletionSource<LicenseRequestResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            licenseClient.NextRenewal = renewal;
            var renewalsBefore = licenseClient.RenewCalls;
            AiSettingsButton(settings, "RenewLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => license.IsBusy && license.State == LicenseState.Renewing,
                "Native manual renewal did not enter its pending state.");
            await FlushAsync();
            Ensure(!AiSettingsButton(settings, "RenewLicenseButton").IsEnabled &&
                !AiSettingsButton(settings, "RefreshLicenseButton").IsEnabled,
                "A pending native renewal allowed overlapping reads or writes.");
            AiSettingsButton(settings, "RenewLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Ensure(licenseClient.RenewCalls == renewalsBefore + 1,
                "Native renewal duplicated an explicit non-idempotent request.");
            renewal.SetResult(new(LicenseRequestOutcome.Success, NativeLicenseClient.Snapshot("GRACE")));
            await WaitForAsync(() => !license.IsBusy && license.ModeText == "GRACE", "Native renewal lost Core's failed-renewal GRACE result.");
            await FlushAsync();
            AiSettingsText(settings, "LicenseRenewalStatus", license.RenewalStatusText);
            Ensure(license.RenewalStatusText.Contains("without restoring FULL", StringComparison.Ordinal),
                "A completed failed renewal was presented as restored licensing.");
            licenseClient.RenewalOutcome = LicenseRequestOutcome.Unavailable;
            AiSettingsButton(settings, "RenewLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => !license.IsBusy && license.State == LicenseState.Unavailable,
                "An unconfigured native renewal did not show explicit unavailability.");
            await FlushAsync();
            AiSettingsText(settings, "LicenseErrorText", license.ErrorText);
            Ensure(!AiSettingsButton(settings, "RenewLicenseButton").IsEnabled && auth.IsSignedIn,
                "An unavailable renewal allowed an unreviewed retry or blocked the local session.");
            AiSettingsButton(settings, "RefreshLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => license.State == LicenseState.Ready, "Explicit native refresh did not restore licensing status.");
            licenseClient.RenewalOutcome = LicenseRequestOutcome.Indeterminate;
            AiSettingsButton(settings, "RenewLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => !license.IsBusy && license.RequiresRefresh, "An uncertain renewal was not marked for explicit reconciliation.");
            await FlushAsync();
            var uncertainCalls = licenseClient.RenewCalls;
            AiSettingsButton(settings, "RenewLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Ensure(licenseClient.RenewCalls == uncertainCalls && !AiSettingsButton(settings, "RenewLicenseButton").IsEnabled,
                "A lost renewal response was automatically retried.");
            AiSettingsText(settings, "LicenseRenewalStatus", license.RenewalStatusText);
            AiSettingsButton(settings, "RefreshLicenseButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => license.State == LicenseState.Ready && !license.RequiresRefresh,
                "Native explicit refresh did not reconcile uncertain renewal.");
            var healthCalls = health.Calls;
            var checkConnection = AiSettingsButton(settings, "SettingsCheckCoreButton");
            var checkPeer = new ButtonAutomationPeer(checkConnection);
            ((IInvokeProvider)checkPeer.GetPattern(PatternInterface.Invoke)!).Invoke();
            await WaitForAsync(() => health.Calls > healthCalls && !shell.IsCheckingCore,
                "Settings' native Core connection action was not bound to the local shell.");
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, settings);
                AssertInsideWindow(window, AiSettingsButton(settings, "RefreshLicenseButton"));
                AssertInsideWindow(window, AiSettingsButton(settings, "RenewLicenseButton"));
                var scroller = (ScrollViewer)settings.FindName("SettingsPageScroller");
                scroller.ScrollToEnd();
                await FlushAsync();
                Ensure(scroller.ViewportWidth > 0 && scroller.ViewportHeight > 0,
                    "Native Settings had no usable viewport at a supported window size.");
                cloudPreference.BringIntoView();
                await FlushAsync();
                AssertInsideWindow(window, cloudPreference);
            }
            window.Width = defaultSize.Width; window.Height = defaultSize.Height;
            SetCloudPreference(cloudPreference, true);
            Ensure(ai.CloudRequestsEnabled && aiClient.RequestedIds.Count == 0,
                "Opting into cloud AI started a request without an Explain action.");
            await NavigateAsync(PageId.Alerts);
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready, "Native AI fixture did not load local Alerts.");
            await OpenAlertAsync(alertsClient.PrimaryId);
            var alertView = Descendants<AlertsView>(window).Single();
            var aiView = Descendants<AiExplanationView>(window).Single();
            Ensure(ai.SelectedAlertId == alertsClient.PrimaryId && ai.IsSupportedAlert && ai.CanExplain &&
                AiSettingsButton(aiView, "ExplainAlertWithAiButton").IsEnabled && aiClient.RequestedIds.Count == 0,
                "Supported native alert detail was not eligible for one explicit licensed AI action.");
            var reviewedVersion = alerts.Detail!.Version;
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => ai.State == AiExplanationState.Ready, "Native explicit AI action did not display typed analysis.");
            await FlushAsync();
            AssertNativeAnalysis(aiView);
            Ensure(aiClient.RequestedIds.SequenceEqual(new[] { alertsClient.PrimaryId }) && alertsClient.Writes.Count == 0 &&
                alerts.Detail.Version == reviewedVersion,
                "Assistive AI changed the reviewed local alert or selected another stored alert.");
            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                var outer = (ScrollViewer)alertView.FindName("PageScroller");
                aiView.BringIntoView();
                await FlushAsync();
                var inner = (ScrollViewer)aiView.FindName("AiAnalysisScroller");
                inner.ScrollToEnd();
                await FlushAsync();
                Ensure(outer.ViewportWidth > 0 && outer.ViewportHeight > 0 && inner.ViewportWidth > 0 && inner.ViewportHeight > 0,
                    "Native assistive analysis lost scroll access at a supported window size.");
                AssertInsideWindow(window, AiSettingsButton(alertView, "BackToAlertsButton"));
            }
            window.Width = defaultSize.Width; window.Height = defaultSize.Height;
            // AI unavailability must leave the independent local lifecycle and
            // report workflows usable, even while the cloud operation is held.
            var unavailable = new TaskCompletionSource<AiExplanationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            aiClient.NextExplanation = unavailable;
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => ai.IsBusy, "Held native AI request did not become pending.");
            SetNativeAlertStatus(alertView, "investigating");
            await FlushAsync();
            Ensure(AiSettingsButton(alertView, "SaveAlertStatusButton").IsEnabled &&
                !AiSettingsButton(aiView, "ExplainAlertWithAiButton").IsEnabled,
                "A pending cloud explanation blocked local status review or allowed duplicate AI.");
            AiSettingsButton(alertView, "SaveAlertStatusButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => alerts.Detail?.Row.Status == "investigating" && !alerts.IsSavingStatus,
                "Local alert lifecycle was blocked by a pending AI request.");
            unavailable.SetResult(new(AiExplanationOutcome.Unavailable));
            await WaitForAsync(() => !ai.IsBusy, "Canceled/outage AI request did not finish.");
            // The status transition changes the reviewed version, so its old
            // explanation must be discarded before a fresh explicit request.
            Ensure(!ai.HasAnalysis && alertsClient.Writes.Count == 1 && alerts.Detail!.Version == reviewedVersion + 1,
                "A local status change retained stale assistive analysis or lost Core's version.");
            aiClient.Outcome = AiExplanationOutcome.Unavailable;
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => ai.State == AiExplanationState.Unavailable, "Native AI outage did not show its explicit unavailable state.");
            await FlushAsync();
            AiSettingsText(aiView, "AiExplanationError", ai.ErrorText);
            Ensure(auth.IsSignedIn && alerts.DetailState == AlertDetailState.Ready && alerts.CanRefresh,
                "AI outage disabled local security review.");
            await NavigateAsync(PageId.Risk);
            await WaitForAsync(() => risk.ListState == RiskListState.Ready, "AI outage blocked native local Risk.");
            Ensure(ai.SelectedAlertId is null && !ai.HasAnalysis && ai.CloudRequestsEnabled,
                "Leaving Alerts retained selected analysis or erased the operator's session preference.");
            await NavigateAsync(PageId.Reports);
            await reports.GenerateAsync();
            Ensure(reports.HasReport, "AI outage blocked local report generation.");
            await NavigateAsync(PageId.Settings);
            await WaitForAsync(() => license.State == LicenseState.Ready, "Settings did not reload after an AI outage.");
            settings = Descendants<SettingsView>(window).Single();
            cloudPreference = AiSettingsControl<CheckBox>(settings, "CloudAiRequestsEnabled");
            SetCloudPreference(cloudPreference, false);
            await NavigateAsync(PageId.Alerts);
            await WaitForAsync(() => alerts.ListState == AlertListState.Ready, "Native alerts did not reload with AI opted out.");
            await OpenAlertAsync(alertsClient.PrimaryId);
            aiView = Descendants<AiExplanationView>(window).Single();
            var callsBeforeDisabled = aiClient.RequestedIds.Count;
            Ensure(!ai.CloudRequestsEnabled && !ai.CanExplain && !AiSettingsButton(aiView, "ExplainAlertWithAiButton").IsEnabled,
                "Cloud opt-out did not disable the native Explain action.");
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Ensure(aiClient.RequestedIds.Count == callsBeforeDisabled, "Disabled native AI issued a cloud request.");
            ai.CloudRequestsEnabled = true;
            licenseClient.Status = NativeLicenseClient.Snapshot("SAFE_MODE");
            await license.RefreshAsync();
            await FlushAsync();
            Ensure(ai.State == AiExplanationState.Disabled && !ai.CanExplain && !ai.HasAnalysis,
                "Safe Mode did not withdraw native optional AI.");
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Ensure(aiClient.RequestedIds.Count == callsBeforeDisabled && alerts.DetailState == AlertDetailState.Ready,
                "Safe Mode issued AI or blocked native local alert review.");
            await risk.RefreshAsync();
            await reports.GenerateAsync();
            Ensure(risk.ListState == RiskListState.Ready && reports.HasReport,
                "Safe Mode did not preserve local Risk and report generation.");
            licenseClient.Status = NativeLicenseClient.Snapshot("FULL");
            await license.RefreshAsync();
            await OpenAlertAsync(alertsClient.UnsupportedId);
            await FlushAsync();
            aiView = Descendants<AiExplanationView>(window).Single();
            Ensure(ai.State == AiExplanationState.Unsupported && !ai.CanExplain &&
                !AiSettingsButton(aiView, "ExplainAlertWithAiButton").IsEnabled,
                "Unsupported alert evidence enabled native AI.");
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Ensure(aiClient.RequestedIds.Count == callsBeforeDisabled, "An unsupported native alert issued AI.");
            aiClient.Outcome = AiExplanationOutcome.Success;
            await OpenAlertAsync(alertsClient.PrimaryId);
            aiView = Descendants<AiExplanationView>(window).Single();
            AiSettingsButton(aiView, "ExplainAlertWithAiButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => ai.HasAnalysis, "Native analysis did not recover after an explicit licensed request.");
            await OpenAlertAsync(alertsClient.SecondaryId);
            Ensure(ai.SelectedAlertId == alertsClient.SecondaryId && !ai.HasAnalysis && aiClient.RequestedIds[^1] == alertsClient.PrimaryId,
                "Selecting another local alert retained the prior explanation or automatically requested new AI.");
            await reports.GenerateAsync();
            var retainedReport = reportsClient.LastDocument;
            auth.SignOut();
            Ensure(!ai.HasAnalysis && ai.SelectedAlertId is null && !ai.CloudRequestsEnabled && license.Status is null &&
                !reports.HasReport && retainedReport!.ByteCount == 0,
                "Sign-out did not synchronously clear native licensing, selected AI, opt-in and report bytes.");
            await FlushAsync();
            Ensure(!RequireControl<ListBox>(window, "NavigationList").IsEnabled &&
                !RequireControl<ContentControl>(window, "PageContent").IsVisible,
                "Sign-out retained access to native protected output.");
            Ensure(trace.Messages.Count == 0, "Native AI/Settings bindings produced warnings/errors: " +
                string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
        }

        async Task NavigateAsync(PageId id)
        {
            shell.CurrentPage = shell.Pages.Single(page => page.Id == id);
            await FlushAsync();
        }
        async Task OpenAlertAsync(Guid id)
        {
            if (alerts.IsShowingDetail) alerts.CloseDetail();
            alerts.SelectedAlert = alerts.VisibleAlerts.Single(row => row.AlertId == id);
            await alerts.OpenDetailAsync(id);
            await FlushAsync();
            Ensure(alerts.DetailState == AlertDetailState.Ready && alerts.Detail!.Row.AlertId == id,
                "Native AI fixture failed to review the selected local alert.");
        }
    }

    private static async Task AiLicenseSessionExpiryOrderingAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "optional-session-ordering");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
        var licenses = new NativeLicenseClient();
        using var license = new LicenseViewModel(licenses);
        var explanations = new NativeAiClient();
        using var ai = new AiExplanationViewModel(explanations);
        Action? duringSignOut = null;
        System.ComponentModel.PropertyChangedEventHandler overlap = (_, change) =>
        {
            if (change.PropertyName == nameof(AuthenticationViewModel.IsSignedIn) && !auth.IsSignedIn && duringSignOut is { } action)
            { duringSignOut = null; action(); }
        };
        auth.PropertyChanged += overlap;
        var window = new MainWindow(shell, auth, null, null, null, null, license, ai);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Optional expiry fixture did not reach sign-in.");
            SignIn();
            foreach (var useLicense in new[] { true, false })
            {
                var licenseResponse = new TaskCompletionSource<LicenseRequestResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                var aiResponse = new TaskCompletionSource<AiExplanationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                var alertClient = new NativeAiAlertsClient();
                ai.SetAlert(alertClient.Detail(alertClient.PrimaryId));
                ai.SetAvailability(true); ai.CloudRequestsEnabled = true;
                if (useLicense) licenses.NextRead = licenseResponse;
                else explanations.NextExplanation = aiResponse;
                var worker = Task.Run(() => useLicense ? license.RefreshAsync() : ai.ExplainAsync());
                await WaitForAsync(() => useLicense ? license.IsBusy : ai.IsBusy, "Optional worker request did not begin.");
                duringSignOut = () =>
                {
                    if (useLicense) licenseResponse.SetResult(new(LicenseRequestOutcome.Unauthenticated));
                    else aiResponse.SetResult(new(AiExplanationOutcome.Unauthenticated));
                    Ensure(worker.Wait(TimeSpan.FromSeconds(3)) && worker.IsCompletedSuccessfully,
                        "Optional worker expiry deadlocked against UI sign-out.");
                };
                using (window.Dispatcher.DisableProcessing())
                {
                    auth.SignOut();
                    Ensure(!ai.CloudRequestsEnabled && ai.SelectedAlertId is null && license.Status is null,
                        "Sign-out did not synchronously clear optional workspace state.");
                    SignIn();
                }
                await FlushAsync();
                Ensure(auth.IsSignedIn, "Queued old optional expiry ended a replacement session.");
                if (useLicense) licenses.ReadOutcome = LicenseRequestOutcome.Unauthenticated;
                else
                {
                    ai.SetAlert(alertClient.Detail(alertClient.PrimaryId)); ai.SetAvailability(true); ai.CloudRequestsEnabled = true;
                    explanations.Outcome = AiExplanationOutcome.Unauthenticated;
                }
                await Task.Run(() => useLicense ? license.RefreshAsync() : ai.ExplainAsync()).WaitAsync(TimeSpan.FromSeconds(5));
                await WaitForAsync(() => !auth.IsSignedIn, "Current optional worker 401 did not expire the session.");
                Ensure(license.Status is null && !ai.CloudRequestsEnabled && !ai.HasAnalysis, "Current optional expiry retained private workspace output.");
                licenses.ReadOutcome = LicenseRequestOutcome.Success; explanations.Outcome = AiExplanationOutcome.Success;
                SignIn();
                await FlushAsync();
            }
        }
        finally
        {
            duringSignOut = null; auth.PropertyChanged -= overlap;
            if (window.IsVisible) window.Close();
        }
        void SignIn()
        {
            auth.Username = "native-optional-session-admin";
            var task = auth.SignInAsync("Synthetic-Optional-Session!".AsMemory());
            Ensure(task.IsCompletedSuccessfully, "Optional expiry fixture needs immediate synthetic authentication.");
            task.GetAwaiter().GetResult();
        }
    }

    private static T AiSettingsControl<T>(DependencyObject view, string id) where T : FrameworkElement => Descendants<T>(view)
        .Single(control => AutomationProperties.GetAutomationId(control) == id);
    private static Button AiSettingsButton(DependencyObject view, string id) => AiSettingsControl<Button>(view, id);
    private static void AiSettingsText(DependencyObject view, string id, string value)
    {
        var text = AiSettingsControl<TextBlock>(view, id);
        Ensure(text.IsVisible && text.Text == value && text.Inlines.Cast<Inline>().All(inline => inline is Run),
            "Native AI/Settings text was missing, modified or rendered as active content: " + id);
    }
    private static void SetCloudPreference(CheckBox checkbox, bool value)
    {
        checkbox.IsChecked = value;
        checkbox.GetBindingExpression(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty)?.UpdateSource();
    }
    private static void AssertNativeAnalysis(AiExplanationView view)
    {
        AiSettingsText(view, "AiAssistiveLabel", AiContract.AssistiveLabel);
        AiSettingsText(view, "AiExplanationText", NativeAiClient.Analysis.Explanation);
        AiSettingsText(view, "AiWhyItMatters", NativeAiClient.Analysis.WhyItMatters);
        AiSettingsText(view, "AiConfidence", NativeAiClient.Analysis.Confidence);
        AiSettingsText(view, "AiUncertainty", NativeAiClient.Analysis.Uncertainty);
        var investigation = Descendants<TextBlock>(view).Where(text => AutomationProperties.GetAutomationId(text) == "AiInvestigationStep").ToArray();
        var remediation = Descendants<TextBlock>(view).Where(text => AutomationProperties.GetAutomationId(text) == "AiRemediationStep").ToArray();
        Ensure(investigation.Select(text => text.Text).SequenceEqual(NativeAiClient.Analysis.RecommendedInvestigation) &&
            remediation.Select(text => text.Text).SequenceEqual(NativeAiClient.Analysis.SuggestedRemediation) &&
            investigation.Concat(remediation).All(text => text.Inlines.Cast<Inline>().All(inline => inline is Run)),
            "Native AI step lists lost order or interpreted assistive text as active content.");
        Ensure(!Descendants<System.Windows.Documents.Hyperlink>(view).Any(),
            "Native assistive analysis exposed an executable link.");
    }

    private sealed class NativeLicenseClient : ILicenseClient
    {
        public LicenseStatus Status = Snapshot("FULL");
        public LicenseRequestOutcome ReadOutcome = LicenseRequestOutcome.Success;
        public LicenseRequestOutcome RenewalOutcome = LicenseRequestOutcome.Success;
        public int ReadCalls, RenewCalls;
        public TaskCompletionSource<LicenseRequestResult>? NextRead, NextRenewal;
        public CancellationToken LastToken;
        public static LicenseStatus Snapshot(string mode) => new(mode, new(true, true, true, true, true, mode != "SAFE_MODE"),
            new DateTimeOffset(2026, 10, 7, 12, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero), false, mode == "SAFE_MODE" ? [] : ["cloud_ai", "premium_reporting"]);
        public Task<LicenseRequestResult> GetLicenseAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            ReadCalls++; LastToken = token;
            if (NextRead is { } delayed) { NextRead = null; return delayed.Task; }
            return Task.FromResult(ReadOutcome == LicenseRequestOutcome.Success ? new LicenseRequestResult(ReadOutcome, Status) : new(ReadOutcome));
        }
        public Task<LicenseRequestResult> RenewLicenseAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            RenewCalls++; LastToken = token;
            if (NextRenewal is { } delayed) { NextRenewal = null; return delayed.Task; }
            return Task.FromResult(RenewalOutcome == LicenseRequestOutcome.Success ? new LicenseRequestResult(RenewalOutcome, Status) : new(RenewalOutcome));
        }
    }

    private sealed class NativeAiClient : IAiExplanationClient
    {
        public static readonly AiExplanation Analysis = new("<script>synthetic explanation</script> & {Binding Secret}",
            "<b>Review locally</b> & <Hyperlink>literal</Hyperlink>", ["<Run>First investigation</Run>", "Second & investigation"],
            ["<a href='file:///synthetic'>Review remediation</a>", "Do not apply automatically"], "medium", "<img src=x> Synthetic uncertainty");
        public List<Guid> RequestedIds { get; } = [];
        public AiExplanationOutcome Outcome = AiExplanationOutcome.Success;
        public TaskCompletionSource<AiExplanationResult>? NextExplanation;
        public CancellationToken LastToken;
        public Task<AiExplanationResult> ExplainAlertAsync(Guid alertId, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            RequestedIds.Add(alertId); LastToken = token;
            if (NextExplanation is { } delayed) { NextExplanation = null; return delayed.Task; }
            return Task.FromResult(Outcome == AiExplanationOutcome.Success ? new AiExplanationResult(Outcome, Analysis) : new(Outcome));
        }
    }

    private sealed class NativeAiAlertsClient : IAlertsClient
    {
        public Guid EndpointId { get; } = Guid.NewGuid();
        public Guid PrimaryId { get; } = Guid.NewGuid();
        public Guid SecondaryId { get; } = Guid.NewGuid();
        public Guid UnsupportedId { get; } = Guid.NewGuid();
        private readonly Dictionary<Guid, AlertDetail> _details;
        public List<(Guid Id, string Status, long Version)> Writes { get; } = [];
        public NativeAiAlertsClient()
        {
            var now = new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero);
            _details = new[] { PrimaryId, SecondaryId, UnsupportedId }.ToDictionary(id => id, id =>
            {
                var summary = new AlertSummary(id, EndpointId, "synthetic-ai-endpoint", id == UnsupportedId ? "SYNTHETIC_UNKNOWN" : "SA-FW-001",
                    "Synthetic supported firewall alert", "high", "open", now.AddHours(-1), now, now, 7);
                return new AlertDetail(summary, "Synthetic minimized rule evidence",
                    [new("securityPosture.domainFirewallEnabled", AlertEvidenceKind.Boolean, BooleanValue: false)],
                    "Review local firewall configuration", summary.FirstObservedUtc, now, [new(null, "open", now, "system")], 1);
            });
        }
        public AlertDetail Detail(Guid id) => _details[id];
        public Task<AlertResult<AlertPage>> GetAlertsAsync(AlertQuery query, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var items = _details.Values.Select(detail => detail.Alert).ToArray();
            return Task.FromResult(new AlertResult<AlertPage>(AlertOutcome.Success,
                new(items.Skip(query.Offset).Take(query.Limit).ToArray(), items.Length, query.Offset, query.Limit)));
        }
        public Task<AlertResult<AlertDetail>> GetAlertDetailAsync(Guid id, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult(new AlertResult<AlertDetail>(AlertOutcome.Success, _details[id]));
        }
        public Task<AlertResult<AlertDetail>> UpdateAlertStatusAsync(Guid id, string status, long version, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Writes.Add((id, status, version));
            var detail = _details[id];
            if (detail.Alert.Version != version) return Task.FromResult(new AlertResult<AlertDetail>(AlertOutcome.Conflict));
            var now = detail.Alert.UpdatedUtc.AddMinutes(1);
            var updated = detail with
            {
                Alert = detail.Alert with { Status = status, Version = version + 1, UpdatedUtc = now }, StatusChangedUtc = now,
                StatusHistory = detail.StatusHistory.Concat(new[] { new AlertStatusChange(detail.Alert.Status, status, now, "synthetic-admin") }).ToArray(),
                StatusHistoryCount = detail.StatusHistoryCount + 1
            };
            _details[id] = updated;
            return Task.FromResult(new AlertResult<AlertDetail>(AlertOutcome.Success, updated));
        }
    }
}
