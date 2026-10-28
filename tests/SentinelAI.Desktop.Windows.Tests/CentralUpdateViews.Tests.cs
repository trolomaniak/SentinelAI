using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    // MVP-7: Settings → Updates: checking off by default, night-time installation on once checking is on, Check now and
    // Install now, which starts the verified Setup through the installer and asks Desktop to close.
    private static async Task CentralUpdateViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "central-update-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        var client = new NativeCentralUpdateClient();
        var installer = new NativeCentralUpdateInstaller();
        using var updates = new CentralUpdateViewModel(client, installer);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, null, null, null, updates);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Update fixture did not reach sign-in.");
            auth.Username = "native-update-admin";
            await auth.SignInAsync("Synthetic-Update-Admin!".AsMemory());
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await WaitForAsync(() => updates.State == CentralUpdateState.Ready, "Settings did not read the update settings.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            var check = Descendants<CheckBox>(settings).Single(box => AutomationProperties.GetAutomationId(box) == "CentralUpdateCheckEnabled");
            var automatic = Descendants<CheckBox>(settings).Single(box => AutomationProperties.GetAutomationId(box) == "CentralUpdateAutoInstall");
            var install = UpdateButton(settings, "CentralUpdateInstallNow");
            Ensure(check.IsVisible && check.IsChecked == false && check.IsEnabled && !automatic.IsEnabled && !install.IsEnabled &&
                   UpdateText(settings, "CentralUpdateServer") == "updates.example.invalid",
                "Updates were not shown off by default with the provider's server.");

            client.Info = client.Info with { CheckEnabled = true, ReadyVersion = "1.1.0", LastCheck = "ready" };
            check.IsChecked = true;
            await WaitForAsync(() => updates.State == CentralUpdateState.Ready && client.Saved == (true, true), "Turning on checking did not save it.");
            await FlushAsync();
            Ensure(automatic.IsEnabled && automatic.IsChecked == true && install.IsEnabled &&
                   UpdateText(settings, "CentralUpdateStatus").Contains("installs tonight", StringComparison.Ordinal),
                "A downloaded update was not offered for night-time installation and Install now.");

            var exits = 0;
            updates.ExitRequested += (_, _) => exits++;
            install.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => installer.Calls == 1 && exits == 1, "Install now did not start the installer and ask Desktop to close.");
            Ensure(trace.Messages.Count == 0, "Native update bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
            if (window.IsVisible) window.Close();
        }
    }

    private static string UpdateText(DependencyObject view, string id) =>
        Descendants<TextBlock>(view).Single(control => AutomationProperties.GetAutomationId(control) == id).Text;

    private static Button UpdateButton(DependencyObject view, string id) =>
        Descendants<Button>(view).Single(button => AutomationProperties.GetAutomationId(button) == id);

    private sealed class NativeCentralUpdateClient : ICentralUpdateClient
    {
        public CentralUpdateInfo Info = new(true, "updates.example.invalid", false, true, "1.0.0", "never", null, null, 0, null);
        public (bool, bool)? Saved;
        public Task<CentralUpdateRequestResult> GetCentralUpdateAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new CentralUpdateRequestResult(CentralUpdateRequestOutcome.Success, Info));
        public Task<CentralUpdateRequestResult> SetCentralUpdateSettingsAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken)
        {
            Saved = (checkEnabled, autoInstall);
            return GetCentralUpdateAsync(cancellationToken);
        }
        public Task<CentralUpdateRequestResult> CheckCentralUpdateAsync(CancellationToken cancellationToken) => GetCentralUpdateAsync(cancellationToken);
    }

    private sealed class NativeCentralUpdateInstaller : ICentralUpdateInstaller
    {
        public int Calls;
        public Task<CentralUpdateInstallOutcome> StartAsync(CancellationToken cancellationToken) { Calls++; return Task.FromResult(CentralUpdateInstallOutcome.Started); }
    }
}
