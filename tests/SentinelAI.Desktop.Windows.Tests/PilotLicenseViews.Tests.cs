using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Documents;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    // MVP-3: Settings → License shows the pilot and accepts a new key; the shell shows the warning and the ended
    // notice with contact details, a session-only hide and "Uninstall SentinelAI" through the Setup launcher.
    private static async Task PilotLicenseViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "pilot-license-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        var pilotClient = new NativePilotClient();
        var launcher = new NativeUninstallLauncher();
        using var pilot = new PilotLicenseViewModel(pilotClient, launcher);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, null, null, pilot);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Pilot fixture did not reach sign-in.");
            await FlushAsync();
            var notice = (Border)window.FindName("PilotNotice");
            Ensure(pilotClient.Reads == 0 && !notice.IsVisible, "The pilot was read or shown before authentication.");
            auth.Username = "native-pilot-admin";
            await auth.SignInAsync("Synthetic-Pilot-Admin!".AsMemory());
            await WaitForAsync(() => pilot.State == PilotLicenseState.Ready, "Sign-in did not read the pilot license.");
            await FlushAsync();
            Ensure(notice.IsVisible, "The seven-day warning was not shown in the shell.");
            PilotText(notice, "PilotNoticeTitle", "Pilot ends in 5 days — contact us");
            PilotText(notice, "PilotNoticeContact", string.Join(Environment.NewLine, "Example Company", "E-mail: pilot@example.invalid",
                "Phone: +00 000 000 000", "Website: https://example.invalid"));
            Ensure(!PilotButton(notice, "UninstallSentinelAiButton").IsVisible, "Uninstall was offered before the pilot ended.");

            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await WaitForAsync(() => pilot.State == PilotLicenseState.Ready && pilotClient.Reads >= 2, "Settings did not reread the pilot license.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            PilotText(settings, "PilotLicenseCustomer", "Zażółć Example");
            PilotText(settings, "PilotLicenseExpires", "2026-01-15 00:00 UTC");
            PilotText(settings, "PilotLicenseDaysLeft", "5");
            var keyBox = Descendants<TextBox>(settings).Single(box => AutomationProperties.GetAutomationId(box) == "PilotLicenseKeyBox");
            var apply = PilotButton(settings, "ApplyPilotKeyButton");
            Ensure(keyBox.IsVisible && !apply.IsEnabled, "A pilot key could be applied before one was typed.");
            keyBox.Text = "  extension.pilot.key  ";
            await FlushAsync();
            Ensure(apply.IsEnabled, "Typing a pilot key did not enable Apply key.");
            pilotClient.Info = Info("active", 65);
            apply.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => pilot.State == PilotLicenseState.Ready && pilotClient.Keys.Count == 1, "Apply key did not submit the key.");
            await FlushAsync();
            Ensure(pilotClient.Keys.Single() == "  extension.pilot.key  " && keyBox.Text.Length == 0 && !notice.IsVisible,
                "An extension key did not clear the entry and the warning.");
            PilotText(settings, "PilotLicenseDaysLeft", "65");

            pilotClient.Info = Info("ended", 0);
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Overview);
            await WaitForAsync(() => pilot.IsEnded, "Navigation did not reread the pilot license.");
            await FlushAsync();
            var uninstall = PilotButton(notice, "UninstallSentinelAiButton");
            Ensure(notice.IsVisible && uninstall.IsVisible && uninstall.IsEnabled, "The ended notice or its uninstall action was not shown.");
            PilotText(notice, "PilotNoticeTitle", "Your SentinelAI pilot has ended");
            Ensure(launcher.Calls == 0, "Showing the ended notice started the uninstall flow.");
            var exits = 0;
            pilot.ExitRequested += (_, _) => exits++;
            uninstall.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            Ensure(launcher.Calls == 1 && exits == 1, "Uninstall SentinelAI did not start the Setup uninstall flow and ask Desktop to close.");
            PilotText(notice, "UninstallSentinelAiStatus", pilot.UninstallStatusText);

            PilotButton(notice, "HidePilotNoticeButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            Ensure(!notice.IsVisible, "The ended notice could not be hidden.");
            var reads = pilotClient.Reads;
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await WaitForAsync(() => pilotClient.Reads > reads && pilot.State == PilotLicenseState.Ready, "Settings did not reread the ended pilot.");
            await FlushAsync();
            Ensure(!notice.IsVisible && pilot.StatusText.Contains("has ended", StringComparison.Ordinal),
                "A hidden notice returned in the same session, or Settings hid the ended state.");

            auth.SignOut();
            await FlushAsync();
            Ensure(!notice.IsVisible && pilot.Info is null, "Sign-out kept the pilot license.");
            Ensure(trace.Messages.Count == 0, "Native pilot bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
            if (window.IsVisible) window.Close();
        }
    }

    private static void PilotText(DependencyObject view, string id, string value)
    {
        var text = Descendants<TextBlock>(view).Single(control => AutomationProperties.GetAutomationId(control) == id);
        Ensure(text.IsVisible && text.Text == value && text.Inlines.Cast<Inline>().All(inline => inline is Run),
            "Native pilot text was missing, modified or rendered as active content: " + id);
    }

    private static Button PilotButton(DependencyObject view, string id) =>
        Descendants<Button>(view).Single(button => AutomationProperties.GetAutomationId(button) == id);

    private static PilotLicenseInfo Info(string state, int daysLeft) => new(state, "Zażółć Example",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 1, 15, 0, 0, 0, TimeSpan.Zero), daysLeft,
        new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero),
        new("Example Company", "pilot@example.invalid", "+00 000 000 000", "https://example.invalid"));

    private sealed class NativePilotClient : IPilotLicenseClient
    {
        public PilotLicenseInfo Info = Program.Info("ending", 5);
        public int Reads;
        public List<string> Keys { get; } = [];
        public Task<PilotLicenseResult> GetPilotLicenseAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            return Task.FromResult(new PilotLicenseResult(PilotLicenseOutcome.Success, Info));
        }
        public Task<PilotLicenseResult> SetPilotLicenseKeyAsync(string key, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Keys.Add(key);
            return Task.FromResult(new PilotLicenseResult(PilotLicenseOutcome.Success, Info));
        }
    }

    private sealed class NativeUninstallLauncher : ISetupUninstallLauncher
    {
        public int Calls;
        public UninstallLaunchOutcome Start() { Calls++; return UninstallLaunchOutcome.Started; }
    }
}
