using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Interop;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    private static async Task BrowserlessViewsAsync()
    {
        var preferences = new NativeDesktopPreferencesStore();
        await BrowserlessSettingsAsync(preferences);
        await BrowserlessReopenAsync(preferences);
    }

    private static async Task BrowserlessSettingsAsync(NativeDesktopPreferencesStore preferences)
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "browserless-settings-test");
        var authClient = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authClient, new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        using var ai = new AiExplanationViewModel(new NativeAiClient());
        var integration = new DesktopIntegrationViewModel(preferences);
        using var serviceReader = new NativeDesktopServiceReader();
        using var services = new WindowsServiceStatusModel(serviceReader);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var bindings = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(bindings);
        var window = new MainWindow(shell, auth, null, null, null, null, license, ai, integration, services);
        var defaultSize = new Size(window.Width, window.Height);
        try
        {
            window.Show();
            var handle = new WindowInteropHelper(window).Handle;
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut,
                "Browserless Desktop did not offer native sign-in.");
            Ensure(!integration.TrayEnabled && !integration.NotificationsEnabled && !integration.AutoStartEnabled &&
                preferences.SaveCalls == 0 && !auth.IsSignedIn,
                "A fresh Desktop enabled an optional integration or changed preferences without consent.");
            auth.Username = "native-browserless-admin";
            await auth.SignInAsync("Synthetic-Browserless-Wpf!".AsMemory());
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await WaitForAsync(() => license.State == LicenseState.Ready, "Browserless Settings did not load public licensing.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            BrowserlessControl<Expander>(settings, "DesktopIntegrationSettings").IsExpanded = true;
            await FlushAsync();
            var tray = BrowserlessControl<CheckBox>(settings, "DesktopTrayEnabled");
            var notifications = BrowserlessControl<CheckBox>(settings, "DesktopNotificationsEnabled");
            var autoStart = BrowserlessControl<CheckBox>(settings, "DesktopAutoStartEnabled");
            Ensure(tray.IsChecked == false && notifications.IsChecked == false && autoStart.IsChecked == false &&
                !notifications.IsEnabled && tray.IsEnabled && autoStart.IsEnabled,
                "Native integration controls did not present safe defaults and the tray notification dependency.");

            SetCloudPreference(tray, true);
            await FlushAsync();
            Ensure(integration.TrayEnabled && notifications.IsEnabled && !integration.NotificationsEnabled &&
                preferences.Preferences == new DesktopPreferences(true, false, false),
                "Native tray opt-in enabled unrequested notifications or failed to reach the local preference store.");
            SetCloudPreference(notifications, true);
            SetCloudPreference(autoStart, true);
            await FlushAsync();
            Ensure(integration.NotificationsEnabled && integration.AutoStartEnabled &&
                preferences.Preferences == new DesktopPreferences(true, true, true) && auth.IsSignedIn &&
                authClient.SignInCalls == 1,
                "Native integration choices changed authentication or failed to persist independent Desktop startup.");
            SetCloudPreference(tray, false);
            await FlushAsync();
            Ensure(!integration.TrayEnabled && !integration.NotificationsEnabled && integration.AutoStartEnabled &&
                notifications.IsChecked == false && !notifications.IsEnabled && autoStart.IsChecked == true && auth.IsSignedIn,
                "Disabling the tray retained notifications or changed independent Desktop auto-start/authentication.");

            // A preserved foreign startup entry must remain visibly unchanged;
            // the native checkbox must not imply that a rejected edit succeeded.
            preferences.SaveOutcome = DesktopPreferenceOutcome.OwnershipConflict;
            SetCloudPreference(autoStart, false);
            await FlushAsync();
            Ensure(integration.AutoStartEnabled && autoStart.IsChecked == true && !integration.PreferencesAvailable &&
                preferences.Preferences.AutoStartEnabled && auth.IsSignedIn,
                "A rejected startup edit did not roll back the actual native binding or disturbed the local session.");
            BrowserlessText(settings, "DesktopIntegrationError", integration.ErrorText);
            Ensure(integration.ErrorText.Contains("existing entry was preserved", StringComparison.Ordinal),
                "An owned startup conflict did not explain the preserved entry safely.");
            preferences.SaveOutcome = DesktopPreferenceOutcome.Success;
            BrowserlessControl<Button>(settings, "RefreshDesktopSettings").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => integration.PreferencesAvailable && !services.IsRefreshing,
                "The actual native refresh action did not reload Desktop preferences and local service observations.");
            await FlushAsync();
            Ensure(integration.PreferencesAvailable && autoStart.IsEnabled && tray.IsEnabled,
                "Refreshing local preferences did not restore native configuration after an access conflict.");
            Ensure(BrowserlessControl<TextBlock>(settings, "DesktopIntegrationError").Text.Length == 0,
                "Refreshing preferences retained the resolved native error message.");
            SetCloudPreference(tray, true);
            SetCloudPreference(notifications, true);
            await FlushAsync();

            await services.RefreshAsync();
            await FlushAsync();
            BrowserlessText(settings, "SettingsCoreServiceStatus", "Core service: " + services.CoreStatusText);
            BrowserlessText(settings, "SettingsAgentServiceStatus", "Agent service: " + services.AgentStatusText);
            BrowserlessText(window, "DesktopServiceStatus", BrowserlessServiceSummary(services));
            Ensure(services.CoreState == LocalServiceState.Running && services.AgentState == LocalServiceState.Stopped,
                "Native Settings did not display the observed local service states.");
            serviceReader.Snapshot = new(LocalServiceState.Unknown, LocalServiceState.NotInstalled);
            await services.RefreshAsync();
            await FlushAsync();
            BrowserlessText(settings, "SettingsCoreServiceStatus", "Core service: " + services.CoreStatusText);
            BrowserlessText(settings, "SettingsAgentServiceStatus", "Agent service: " + services.AgentStatusText);
            BrowserlessText(window, "DesktopServiceStatus", BrowserlessServiceSummary(services));
            Ensure(services.CoreStatusText == "Unknown" && services.AgentStatusText == "Not installed" &&
                shell.CoreStatusText == "Local Core available" && auth.IsSignedIn,
                "Unknown or absent SCM services were represented as running or replaced independent Core connection health.");
            Ensure(!Descendants<Button>(settings).Any(button => button.Content is string text &&
                new[] { "Start Core", "Stop Core", "Start Agent", "Stop Agent" }.Contains(text, StringComparer.Ordinal)),
                "The read-only Desktop service indication exposed monitoring lifecycle controls.");

            foreach (var size in new[] { new Size(640, 480), defaultSize, new Size(1600, 1000) })
            {
                window.Width = size.Width;
                window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, settings);
                AssertInsideWindow(window, BrowserlessControl<TextBlock>(window, "DesktopServiceStatus"));
                var scroller = (ScrollViewer)settings.FindName("SettingsPageScroller");
                Ensure(scroller.ViewportWidth > 0 && scroller.ViewportHeight > 0,
                    "Browserless Settings lost its scroll viewport at a supported window size.");
                foreach (var control in new FrameworkElement[] { tray, notifications, autoStart,
                    BrowserlessControl<TextBlock>(settings, "SettingsCoreServiceStatus"),
                    BrowserlessControl<TextBlock>(settings, "SettingsAgentServiceStatus") })
                {
                    control.BringIntoView();
                    await FlushAsync();
                    AssertInsideWindow(window, control);
                }
            }
            window.Width = defaultSize.Width;
            window.Height = defaultSize.Height;
            SetCloudPreference(BrowserlessControl<CheckBox>(settings, "CloudAiRequestsEnabled"), true);
            Ensure(ai.CloudRequestsEnabled, "Native cloud consent setup failed before sign-out isolation.");
            var retainedPreferences = preferences.Preferences;
            var savesBeforeSignOut = preferences.SaveCalls;
            auth.SignOut();
            await FlushAsync();
            Ensure(!auth.IsSignedIn && !ai.CloudRequestsEnabled && preferences.Preferences == retainedPreferences &&
                preferences.SaveCalls == savesBeforeSignOut && integration.TrayEnabled && integration.NotificationsEnabled &&
                integration.AutoStartEnabled && !RequireControl<ListBox>(window, "NavigationList").IsEnabled,
                "Signing out retained cloud consent, discarded nonsecret Desktop choices or left the protected workspace open.");
            auth.Username = "native-browserless-admin";
            await auth.SignInAsync("Synthetic-Browserless-Wpf!".AsMemory());
            await FlushAsync();
            settings = Descendants<SettingsView>(window).Single();
            BrowserlessControl<Expander>(settings, "DesktopIntegrationSettings").IsExpanded = true;
            await FlushAsync();
            Ensure(BrowserlessControl<CheckBox>(settings, "DesktopTrayEnabled").IsChecked == true &&
                BrowserlessControl<CheckBox>(settings, "DesktopNotificationsEnabled").IsChecked == true &&
                BrowserlessControl<CheckBox>(settings, "DesktopAutoStartEnabled").IsChecked == true && !ai.CloudRequestsEnabled,
                "Native reconnect lost Desktop choices or implicitly re-enabled cloud requests.");

            // Closing during a local status observation only ends the UI
            // lifetime. A late observation must not publish into disposed views.
            serviceReader.HoldNextRead = true;
            var pendingStatus = services.RefreshAsync();
            await WaitForAsync(() => serviceReader.HeldReadEntered.IsSet,
                "Native service observation did not reach its held local read.");
            var serviceNotifications = 0;
            services.PropertyChanged += (_, _) => serviceNotifications++;
            window.Close();
            var afterClose = serviceNotifications;
            serviceReader.ReleaseHeldRead.Set();
            await pendingStatus;
            await WaitForAsync(() => serviceReader.HeldReadCompleted.IsSet,
                "Released local status read did not finish after Desktop closed.");
            await FlushAsync();
            var readsAfterClose = serviceReader.Calls;
            await services.RefreshAsync();
            Ensure(!NativeMethods.IsWindow(handle) && health.Disposed && authClient.Disposed &&
                !services.IsRefreshing && serviceNotifications == afterClose && serviceReader.Calls == readsAfterClose &&
                preferences.Preferences == retainedPreferences,
                "Closing Desktop retained a native window, restarted polling, published stale status or changed persistent preferences.");
            Ensure(bindings.Messages.Count == 0,
                $"Browserless native binding warnings/errors: {string.Join(Environment.NewLine, bindings.Messages)}");
        }
        finally
        {
            serviceReader.ReleaseHeldRead.Set();
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(bindings);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static async Task BrowserlessReopenAsync(NativeDesktopPreferencesStore preferences)
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "browserless-reopen-test");
        var authClient = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authClient, new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        using var ai = new AiExplanationViewModel(new NativeAiClient());
        var integration = new DesktopIntegrationViewModel(preferences);
        using var services = new WindowsServiceStatusModel();
        var window = new MainWindow(shell, auth, null, null, null, null, license, ai, integration, services);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut && health.Calls > 0 && !shell.IsCheckingCore,
                "Reopening native Desktop did not reconnect its local health check and offer sign-in.");
            Ensure(!auth.IsSignedIn && authClient.SignInCalls == 0 && !ai.CloudRequestsEnabled &&
                integration.TrayEnabled && integration.NotificationsEnabled && integration.AutoStartEnabled,
                "A reopened Desktop persisted authentication/cloud consent or lost explicit current-user preferences.");
            Ensure(!RequireControl<ListBox>(window, "NavigationList").IsEnabled,
                "Reopening Desktop bypassed native authentication.");
            auth.Username = "native-browserless-admin";
            await auth.SignInAsync("Synthetic-Browserless-Wpf!".AsMemory());
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            BrowserlessControl<Expander>(settings, "DesktopIntegrationSettings").IsExpanded = true;
            await FlushAsync();
            Ensure(auth.IsSignedIn && BrowserlessControl<CheckBox>(settings, "DesktopAutoStartEnabled").IsChecked == true,
                "Native reopening could not complete explicit sign-in with retained Desktop startup choices.");
            await services.RefreshAsync();
            await FlushAsync();
            BrowserlessText(settings, "SettingsCoreServiceStatus", "Core service: " + services.CoreStatusText);
            BrowserlessText(settings, "SettingsAgentServiceStatus", "Agent service: " + services.AgentStatusText);
            // The real SCM reader may report running, absent or unavailable
            // services on this runner. The view must display its observation.
            Ensure(Enum.IsDefined(services.CoreState) && Enum.IsDefined(services.AgentState),
                "Reopened Desktop exposed an unsupported service state.");
        }
        finally { if (window.IsVisible) window.Close(); }
        Ensure(health.Disposed && authClient.Disposed,
            "Reopened Desktop did not release its own local adapters on close.");
    }

    private static T BrowserlessControl<T>(DependencyObject view, string id) where T : FrameworkElement =>
        Descendants<T>(view).Single(control => AutomationProperties.GetAutomationId(control) == id);

    private static string BrowserlessServiceSummary(WindowsServiceStatusModel services) =>
        $"Core service: {services.CoreStatusText} · Agent service: {services.AgentStatusText}";

    private static void BrowserlessText(DependencyObject view, string id, string expected)
    {
        var control = BrowserlessControl<TextBlock>(view, id);
        Ensure(control.IsVisible && control.Text == expected,
            "Native browserless status or preference feedback was not bound correctly: " + id);
    }

    private sealed class NativeDesktopPreferencesStore : IDesktopPreferencesStore
    {
        public DesktopPreferences Preferences = new();
        public DesktopPreferenceOutcome SaveOutcome = DesktopPreferenceOutcome.Success;
        public int SaveCalls;
        public DesktopPreferencesResult Read() => new(DesktopPreferenceOutcome.Success, Preferences);
        public DesktopPreferencesResult Save(DesktopPreferences preferences)
        {
            SaveCalls++;
            if (SaveOutcome == DesktopPreferenceOutcome.Success) Preferences = preferences;
            return new(SaveOutcome, Preferences);
        }
    }

    private sealed class NativeDesktopServiceReader : ILocalServiceStatusReader, IDisposable
    {
        public volatile LocalServiceStatusSnapshot Snapshot = new(LocalServiceState.Running, LocalServiceState.Stopped);
        public bool HoldNextRead;
        public int Calls;
        public ManualResetEventSlim HeldReadEntered { get; } = new(false);
        public ManualResetEventSlim ReleaseHeldRead { get; } = new(false);
        public ManualResetEventSlim HeldReadCompleted { get; } = new(false);
        public LocalServiceStatusSnapshot Read()
        {
            Interlocked.Increment(ref Calls);
            if (HoldNextRead)
            {
                HoldNextRead = false;
                HeldReadEntered.Set();
                ReleaseHeldRead.Wait(TimeSpan.FromSeconds(4));
                HeldReadCompleted.Set();
            }
            return Snapshot;
        }
        public void Dispose()
        {
            ReleaseHeldRead.Set();
            HeldReadEntered.Dispose();
            ReleaseHeldRead.Dispose();
            HeldReadCompleted.Dispose();
        }
    }
}
