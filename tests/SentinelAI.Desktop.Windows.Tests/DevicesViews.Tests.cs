using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using System.Windows.Data;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    private static async Task DevicesViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "devices-test");
        var authentication = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authentication, new FakeAdministratorSetup { Created = true });
        var client = new NativeDeviceClient();
        using var devices = new DevicesViewModel(client);
        var bindingSource = PresentationTraceSources.DataBindingSource;
        var originalLevel = bindingSource.Switch.Level;
        var trace = new BindingTrace();
        bindingSource.Switch.Level = SourceLevels.Warning;
        bindingSource.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, devices);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Existing native installation did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Devices);
            Ensure(client.ListCalls == 0, "Native Devices queried Core before authentication.");
            auth.Username = "native-device-admin";
            await auth.SignInAsync("Synthetic-Wpf-Devices!".AsMemory());
            await WaitForAsync(() => devices.ListState == DeviceListState.Ready, "Authenticated native Devices did not load.");
            await FlushAsync();
            var view = Descendants<DevicesView>(window).Single();
            var grid = (DataGrid)view.FindName("DevicesGrid");
            Ensure(grid.IsVisible && grid.Items.Count == 100 && devices.TotalDevices == 205,
                "Native fleet presentation did not use bounded pages.");
            Ensure(grid.EnableRowVirtualization && VirtualizingPanel.GetIsVirtualizing(grid) &&
                VirtualizingPanel.GetVirtualizationMode(grid) == VirtualizationMode.Recycling,
                "Native fleet row virtualization was disabled.");
            grid.UpdateLayout();
            var realized = Enumerable.Range(0, grid.Items.Count).Count(index => grid.ItemContainerGenerator.ContainerFromIndex(index) is DataGridRow);
            Ensure(realized > 0 && realized < grid.Items.Count, "The real native grid eagerly realized the entire page.");
            Ensure(grid.Columns.Count == 7 && grid.Columns.Any(column => Equals(column.Header, "Connectivity")) &&
                grid.Columns.Any(column => Equals(column.Header, "Configured firewall posture")),
                "Connectivity and configured security posture were not distinct columns.");
            DeviceButton(view, "NextDevicesPageButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            Ensure(devices.PageNumber == 2 && grid.Items.Count == 100, "Native paging did not move through the fleet.");
            var search = Descendants<TextBox>(view).Single();
            search.Text = "device-000";
            search.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            await FlushAsync();
            Ensure(devices.VisibleDevices.Count == 1 && devices.PageNumber == 1, "Native search did not filter/reset paging.");
            grid.SelectedItem = devices.VisibleDevices[0];
            await FlushAsync();
            DeviceButton(view, "OpenDeviceButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => devices.DetailState == DeviceDetailState.Ready, "Endpoint detail did not open natively.");
            await FlushAsync();
            Ensure(devices.Detail?.EndpointId == client.Items[0].EndpointId &&
                Descendants<TextBlock>(view).Any(text => text.Text == "26H2 10.0.26200.0") &&
                Descendants<TextBlock>(view).Any(text => text.Text == "Synthetic CPU"),
                "Native endpoint details lost Core release/build or hardware data.");
            Ensure(devices.Detail?.PostureFacts.Any(fact => fact.Value == "Disabled") == true &&
                devices.Detail.Device.Health == DeviceHealth.Healthy,
                "Native detail inferred security posture from healthy connectivity.");
            var readsBeforeValidation = client.ListCalls;
            var openDetail = devices.Detail;
            await auth.CheckSessionAsync();
            await FlushAsync();
            Ensure(client.ListCalls == readsBeforeValidation && ReferenceEquals(devices.Detail, openDetail) &&
                devices.DetailState == DeviceDetailState.Ready,
                "Periodic authentication validation refreshed the fleet or closed native detail.");
            DeviceButton(view, "BackToDevicesButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            search.Text = "device-003";
            search.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            await FlushAsync();
            grid.SelectedItem = devices.VisibleDevices.Single();
            await FlushAsync();
            DeviceButton(view, "OpenDeviceButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => devices.DetailState == DeviceDetailState.Ready, "Inventory-free native detail did not open.");
            Ensure(devices.Detail!.Device.Health == DeviceHealth.Unknown &&
                devices.Detail.InventoryStatusText.Contains("No inventory", StringComparison.OrdinalIgnoreCase) &&
                devices.Detail.PostureFacts.All(fact => fact.Value == "Unknown"),
                "Native missing inventory was inferred as known or protected.");
            devices.CloseDetail();
            devices.SearchText = "";
            devices.HealthFilter = DeviceHealthFilter.Warning;
            await FlushAsync();
            Ensure(devices.VisibleDevices.All(row => row.Health == DeviceHealth.Warning), "Native warning filter changed Core semantics.");
            devices.HealthFilter = DeviceHealthFilter.Offline;
            Ensure(devices.VisibleDevices.All(row => row.Health == DeviceHealth.Offline), "Native offline filter changed Core semantics.");
            devices.HealthFilter = DeviceHealthFilter.All;
            devices.SortDescending = true;
            await FlushAsync();
            Ensure(devices.VisibleDevices[0].Name == "device-204", "Native global sort only sorted the visible page.");
            client.Items = [];
            await devices.RefreshAsync();
            await FlushAsync();
            Ensure(devices.ListState == DeviceListState.Empty && Descendants<TextBlock>(view).Any(text => text.Text == devices.ListStatusText),
                "Native no-data state was missing.");
            client.Outcome = DeviceReadOutcome.Unavailable;
            await devices.RefreshAsync();
            await FlushAsync();
            Ensure(devices.ListState == DeviceListState.Unavailable && devices.VisibleDevices.Count == 0 &&
                Descendants<TextBlock>(view).Any(text => text.Text == devices.ListStatusText),
                "Native Core failure left a successful fleet displayed.");
            foreach (var size in new[] { new Size(640, 480), new Size(960, 640), new Size(1600, 1000) })
            {
                window.Width = size.Width; window.Height = size.Height;
                await FlushAsync();
                AssertInsideWindow(window, view);
                Ensure(double.IsFinite(grid.Height) && grid.Height >= 160, "Native grid lost its bounded viewport at a supported size.");
            }
            auth.SignOut();
            await FlushAsync();
            Ensure(devices.TotalDevices == 0 && devices.Detail is null && !view.IsVisible,
                "Sign-out retained native endpoint data.");
            Ensure(trace.Messages.Count == 0, "Native Devices bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
            window.Close();
        }
        finally
        {
            if (window.IsVisible) window.Close();
            bindingSource.Listeners.Remove(trace);
            bindingSource.Switch.Level = originalLevel;
        }
    }

    private static Button DeviceButton(DevicesView view, string id) => Descendants<Button>(view)
        .Single(button => AutomationProperties.GetAutomationId(button) == id);

    private sealed class NativeDeviceClient : IDevicesClient
    {
        public IReadOnlyList<DeviceSummary> Items = Enumerable.Range(0, 205).Select(index => new DeviceSummary(
            Guid.NewGuid(), $"device-{index:000}", index == 3 ? null : "Windows 11 26H2 10.0.26200.0",
            new[] { "healthy", "warning", "offline", "unknown" }[index % 4],
            index == 3 ? null : DateTimeOffset.UtcNow.AddDays(-1), index == 3 ? null : "1.0.0",
            index == 3 ? "Firewall status unknown" : "Firewall disabled on one or more profiles",
            index == 3 ? null : DateTimeOffset.UtcNow.AddMinutes(-1))).ToArray();
        public DeviceReadOutcome Outcome = DeviceReadOutcome.Success;
        public int ListCalls;
        public Task<DeviceReadResult<IReadOnlyList<DeviceSummary>>> GetDevicesAsync(CancellationToken token)
        {
            ListCalls++;
            return Task.FromResult(new DeviceReadResult<IReadOnlyList<DeviceSummary>>(Outcome, Outcome == DeviceReadOutcome.Success ? Items : null));
        }
        public Task<DeviceReadResult<EndpointDetail>> GetDeviceDetailAsync(Guid endpointId, CancellationToken token)
        {
            var summary = Items.Single(item => item.EndpointId == endpointId);
            var absent = summary.InventoryCollectedUtc is null;
            return Task.FromResult(new DeviceReadResult<EndpointDetail>(DeviceReadOutcome.Success,
                new(summary, summary.InventoryCollectedUtc, absent ? null : "26H2 10.0.26200.0", absent ? null : "X64",
                    absent ? null : new CpuInventory("Synthetic CPU", 8), absent ? null : 8589934592L, [],
                    absent ? null : new SecurityPostureInventory(true, false, null), absent ? null : "Windows 11")));
        }
    }
}
