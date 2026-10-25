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
    // MVP-1: Settings renders Core's local-network addresses, HTTPS port and certificate fingerprint literally.
    private static async Task LocalNetworkSettingsViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "local-network-settings-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true },
            new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        var networkClient = new NativeLocalNetworkClient();
        using var network = new LocalNetworkViewModel(networkClient);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, network);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Local-network Settings fixture did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await FlushAsync();
            Ensure(networkClient.Calls == 0, "Settings read Core's local-network role before authentication.");
            auth.Username = "native-local-network-admin";
            await auth.SignInAsync("Synthetic-Local-Network!".AsMemory());
            await WaitForAsync(() => network.State == LocalNetworkState.Ready, "Authenticated Settings did not read the local-network role.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            NetworkText(settings, "LocalNetworkAccess", network.AccessText);
            NetworkText(settings, "LocalNetworkComputerName", "SYNTHETIC-CORE (SYNTHETIC-CORE.corp.example)");
            NetworkText(settings, "LocalNetworkAddresses", "10.0.0.5" + Environment.NewLine + "192.168.1.20");
            NetworkText(settings, "LocalNetworkPort", "5443");
            NetworkText(settings, "LocalNetworkFingerprint", NativeLocalNetworkClient.Pin);
            Ensure(network.AccessText.StartsWith("On.", StringComparison.Ordinal), "Settings did not state that Agents can connect.");
            Ensure(!Descendants<PasswordBox>(settings).Any() && Descendants<TextBox>(settings).All(box => AutomationProperties.GetAutomationId(box) == "PilotLicenseKeyBox"),
                "Settings exposed an editable credential, address or fingerprint.");

            networkClient.Status = new(false, false, null, null, "SYNTHETIC-CORE", null, []);
            var refresh = Descendants<Button>(settings).Single(button => AutomationProperties.GetAutomationId(button) == "RefreshLocalNetworkButton");
            refresh.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => network.State == LocalNetworkState.Ready && network.Status?.Enabled == false, "Explicit refresh did not reread Core.");
            await FlushAsync();
            NetworkText(settings, "LocalNetworkPort", "Not applicable");
            NetworkText(settings, "LocalNetworkFingerprint", "Not applicable");
            Ensure(network.AccessText.StartsWith("Off.", StringComparison.Ordinal) && networkClient.Calls == 2, "A local-only installation was not shown as local-only.");

            auth.SignOut();
            await FlushAsync();
            Ensure(network.Status is null && network.FingerprintText == "Not loaded", "Sign-out kept Core's local-network values.");
            Ensure(trace.Messages.Count == 0, "Native local-network Settings bindings produced warnings/errors: " +
                string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
            if (window.IsVisible) window.Close();
        }
    }

    private static void NetworkText(DependencyObject view, string id, string value)
    {
        var text = Descendants<TextBlock>(view).Single(control => AutomationProperties.GetAutomationId(control) == id);
        Ensure(text.IsVisible && text.Text == value && text.Inlines.Cast<Inline>().All(inline => inline is Run),
            "Native local-network Settings text was missing, modified or rendered as active content: " + id);
    }

    private sealed class NativeLocalNetworkClient : ILocalNetworkClient
    {
        public static readonly string Pin = string.Concat(Enumerable.Repeat("0123456789ABCDEF", 4));
        public LocalNetworkStatus Status = new(true, true, 5443, Pin, "SYNTHETIC-CORE", "SYNTHETIC-CORE.corp.example", ["10.0.0.5", "192.168.1.20"]);
        public int Calls;
        public Task<LocalNetworkRequestResult> GetLocalNetworkAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(new LocalNetworkRequestResult(LocalNetworkRequestOutcome.Success, Status));
        }
    }
}
