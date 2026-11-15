using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;
using SentinelAI.Localization;

internal static partial class Program
{
    private static async Task DefenderDetectionViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "defender-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
        var deviceClient = new NativeDefenderDeviceClient();
        using var devices = new DevicesViewModel(deviceClient);
        var client = new NativeDefenderHistoryClient();
        using var defender = new DefenderDetectionsViewModel(client);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var previousLevel = bindingSource.Switch.Level;
        using var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, devices, null, null, null, null, null, null, null, defenderDetections: defender);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Defender fixture did not reach sign-in.");
            auth.Username = "native-defender-admin";
            await auth.SignInAsync("Synthetic-Defender-Admin!".AsMemory());
            await WaitForAsync(() => devices.ListState == DeviceListState.Ready, "Defender fixture did not load devices.");
            await FlushAsync();
            await devices.OpenDetailAsync(devices.VisibleDevices[0].EndpointId);
            await WaitForAsync(() => defender.State == DefenderHistoryState.Ready, "Native device detail did not read Defender history.");
            await FlushAsync();
            var view = Descendants<DevicesView>(window).Single();
            var card = Descendants<Border>(view).Single(item => AutomationProperties.GetAutomationId(item) == "DeviceDefenderHistory");
            card.BringIntoView();
            await FlushAsync();
            Ensure(ReferenceEquals(card.DataContext, defender) && card.IsVisible && Descendants<TextBlock>(card).Any(text => text.Text == NativeDefenderHistoryClient.ThreatName),
                "Defender history did not bind to its real view model or render the synthetic markup-like name literally.");
            Ensure(Descendants<TextBlock>(card).Any(text => text.Text == "Defender action failed") &&
                   Descendants<TextBlock>(card).Any(text => text.Text.Contains("current collection is unknown", StringComparison.Ordinal)) &&
                   Descendants<TextBlock>(card).Any(text => text.Text.Contains("currently active or removed", StringComparison.Ordinal)),
                "Defender action failures, stale collection and historical scope were not visible.");
            var refresh = Descendants<Button>(card).Single(button => AutomationProperties.GetAutomationId(button) == "RefreshDefenderHistory");
            refresh.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => client.Reads == 2 && defender.State == DefenderHistoryState.Ready, "Native Defender refresh did not read Core.");
            Localizer.Use(UiLanguage.Polish);
            try
            {
                Ensure(defender.Detections.Single().EventText == "Działanie Defendera nie powiodło się", "Native Defender result did not use Polish localization.");
            }
            finally { Localizer.Use(UiLanguage.English); }

            // A detail response may arrive after its page was unloaded. The old view must not start new history reads.
            devices.CloseDetail();
            await FlushAsync();
            var endpoint = deviceClient.Inner.Items[0].EndpointId;
            var held = new TaskCompletionSource<DeviceReadResult<EndpointDetail>>(TaskCreationOptions.RunContinuationsAsynchronously);
            deviceClient.Pending = held.Task;
            var opening = devices.OpenDetailAsync(endpoint);
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Overview);
            await FlushAsync();
            Ensure(!view.IsLoaded && defender.State == DefenderHistoryState.None, "Leaving Devices did not unload and clear Defender history.");
            held.SetResult(await deviceClient.Inner.GetDeviceDetailAsync(endpoint, default));
            await opening;
            await FlushAsync();
            Ensure(client.Reads == 2 && defender.State == DefenderHistoryState.None && defender.Detections.Count == 0,
                "An unloaded Devices view repopulated Defender history from a late endpoint-detail response.");
            deviceClient.Pending = null;
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Devices);
            await WaitForAsync(() => devices.ListState == DeviceListState.Ready, "Returning to Devices did not reload the list.");
            await FlushAsync();
            await devices.OpenDetailAsync(endpoint);
            await WaitForAsync(() => defender.State == DefenderHistoryState.Ready, "Returning to native detail did not reload Defender history.");
            Ensure(client.Reads == 3, "Old Devices views started duplicate Defender reads after navigation.");
            auth.SignOut();
            await FlushAsync();
            Ensure(defender.State == DefenderHistoryState.None && defender.Detections.Count == 0, "Sign-out retained Defender detection metadata.");
            Ensure(trace.Messages.Count == 0, "Native Defender bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
        }
        finally
        {
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = previousLevel;
            if (window.IsVisible) window.Close();
        }
    }

    private sealed class NativeDefenderDeviceClient : IDevicesClient
    {
        internal NativeDeviceClient Inner { get; } = new();
        internal Task<DeviceReadResult<EndpointDetail>>? Pending;
        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken cancellationToken) => Inner.GetDevicesAsync(cancellationToken);
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken cancellationToken) => Pending ?? Inner.GetDeviceDetailAsync(endpointId, cancellationToken);
    }
    private sealed class NativeDefenderHistoryClient : IDefenderDetectionsClient
    {
        internal const string ThreatName = "Synthetic:<script>&{Binding Password}";
        internal int Reads;
        public Task<DeviceReadResult<DefenderDetectionsView>> GetDefenderDetectionsAsync(Guid endpointId, int offset, int limit, CancellationToken cancellationToken)
        {
            Reads++;
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new DeviceReadResult<DefenderDetectionsView>(DeviceReadOutcome.Success,
                new(endpointId, now, "collecting", now.AddHours(-3), now.AddHours(-3), 30, offset, limit, 1,
                    [new(now.AddHours(-4), now.AddHours(-3), 1118, SecurityEventKinds.MalwareActionFailed, Guid.NewGuid(), 12345, ThreatName, 5, 8, 2, 5)])));
        }
    }
}
