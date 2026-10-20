using System.Windows;
using System.Windows.Controls;
using System.Windows.Automation;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

// MVP-2: Devices -> "Add computers" and "Remove computer" in the real WPF view.
internal static partial class Program
{
    private static async Task ComputerEnrollmentViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "enrollment-test");
        var authentication = new FakeAuthenticationClient { AllowSignIn = true };
        using var auth = new AuthenticationViewModel(authentication, new FakeAdministratorSetup { Created = true });
        var deviceClient = new NativeDeviceClient();
        using var devices = new DevicesViewModel(deviceClient);
        var enrollmentClient = new NativeEnrollmentClient();
        using var enrollment = new ComputerEnrollmentViewModel(enrollmentClient);
        var window = new MainWindow(shell, auth, devices, null, null, null, null, null, null, null, null, enrollment);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Native enrollment test did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Devices);
            auth.Username = "native-enrollment-admin";
            await auth.SignInAsync("Synthetic-Wpf-Enrollment!".AsMemory());
            await WaitForAsync(() => devices.ListState == DeviceListState.Ready, "Native Devices did not load.");
            await FlushAsync();
            var view = Descendants<DevicesView>(window).Single();

            // Add computers: the recommended computer name, 24 hours, the secret notice; then a batch of codes.
            var expander = Descendants<Expander>(view).Single(item => AutomationProperties.GetAutomationId(item) == "AddComputersExpander");
            Ensure(expander.IsVisible && !expander.IsExpanded && enrollmentClient.OptionsCalls == 0, "Add computers was not offered collapsed on Devices.");
            expander.IsExpanded = true;
            await WaitForAsync(() => enrollment.IsAvailable && !enrollment.IsBusy, "Add computers did not load its options.");
            await FlushAsync();
            var address = ComboBoxById(view, "EnrollmentAddress");
            var count = ComboBoxById(view, "EnrollmentCodeCount");
            var validity = ComboBoxById(view, "EnrollmentValidity");
            Ensure(address.Items.Count == 2 && ((EnrollmentAddressChoice)address.SelectedItem).Value == "central-pc" &&
                   (int)count.SelectedItem == 1 && count.Items.Count == 50 && ((ValidityChoice)validity.SelectedItem).Hours == 24 &&
                   TextById(view, "EnrollmentCodeSecretNotice") == ComputerEnrollmentViewModel.SecretNotice,
                "Add computers did not show the address, count, validity and secret notice.");
            count.SelectedItem = 3;
            validity.SelectedItem = ComputerEnrollmentViewModel.ValidityChoices[^1];
            DeviceButton(view, "CreateEnrollmentCodesButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => enrollment.IssuedCodes.Count == 3 && !enrollment.IsBusy, "Add computers did not create the codes.");
            await FlushAsync();
            var shown = TextById(view, "IssuedEnrollmentCodes");
            Ensure(enrollmentClient.Issued == (3, 168, "central-pc") && shown.Split(Environment.NewLine).Length == 3 && shown.StartsWith("SAI1-", StringComparison.Ordinal) &&
                   DeviceButton(view, "CopyEnrollmentCodesButton").IsVisible && DeviceButton(view, "SaveEnrollmentCodesButton").IsVisible,
                "The new codes were not shown with copy and save actions.");
            var revoke = Descendants<Button>(view).Where(button => AutomationProperties.GetAutomationId(button).StartsWith("RevokeEnrollmentCode_", StringComparison.Ordinal)).ToArray();
            Ensure(revoke.Length == 3, "Unused codes were not listed with a revoke action.");
            revoke[0].RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => enrollment.UnusedCodes.Count == 2 && !enrollment.IsBusy, "Revoking a code did not update the list.");
            Ensure(Descendants<TextBox>(view).Count() == 1, "Add computers showed codes in an editable text field.");

            // Remove computer: a confirmation, then Core removes the endpoint and the list refreshes.
            var target = devices.VisibleDevices[0].EndpointId;
            var listCalls = deviceClient.ListCalls;
            await devices.OpenDetailAsync(target);
            await FlushAsync();
            var confirmation = (StackPanel)view.FindName("RemoveComputerConfirmation");
            Ensure(DeviceButton(view, "RemoveComputerButton").IsVisible && !confirmation.IsVisible, "Remove computer was not offered on the device.");
            DeviceButton(view, "RemoveComputerButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            Ensure(confirmation.IsVisible && enrollmentClient.Removed.Count == 0, "Remove computer did not ask for confirmation first.");
            DeviceButton(view, "CancelRemoveComputerButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await FlushAsync();
            Ensure(!confirmation.IsVisible && enrollmentClient.Removed.Count == 0, "Cancel removed the computer.");
            DeviceButton(view, "RemoveComputerButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            DeviceButton(view, "ConfirmRemoveComputerButton").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => enrollmentClient.Removed.Count == 1 && !devices.IsShowingDetail && deviceClient.ListCalls > listCalls,
                "Remove computer did not remove the endpoint and refresh the list.");
            Ensure(enrollmentClient.Removed[0] == target, "Remove computer removed another endpoint.");

            // Sign-out forgets the codes.
            auth.SignOut();
            await FlushAsync();
            Ensure(enrollment.IssuedCodes.Count == 0 && enrollment.IssuedCodesText == "", "Sign-out kept the enrollment codes.");
        }
        finally
        {
            window.Close();
        }
    }

    private static ComboBox ComboBoxById(DependencyObject root, string id) => Descendants<ComboBox>(root).Single(item => AutomationProperties.GetAutomationId(item) == id);
    private static string TextById(DependencyObject root, string id) => Descendants<TextBlock>(root).Single(item => AutomationProperties.GetAutomationId(item) == id).Text;

    private sealed class NativeEnrollmentClient : IComputerEnrollmentClient
    {
        private const string Pin = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        private readonly List<UnusedComputerCode> _unused = [];
        internal int OptionsCalls;
        internal (int, int, string)? Issued;
        internal List<Guid> Removed { get; } = [];

        public Task<ComputerEnrollmentResult<ComputerEnrollmentOptions>> GetEnrollmentOptionsAsync(CancellationToken cancellationToken)
        {
            OptionsCalls++;
            return Task.FromResult(new ComputerEnrollmentResult<ComputerEnrollmentOptions>(ComputerEnrollmentOutcome.Success,
                new ComputerEnrollmentOptions(true, true, 5443, "central-pc", [new("central-pc", true, true), new("10.0.0.5", false, true)])));
        }

        public Task<ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>> IssueCodesAsync(int count, int validityHours, string address, CancellationToken cancellationToken)
        {
            Issued = (count, validityHours, address);
            var codes = Enumerable.Range(1, count).Select(index => new IssuedComputerCode(Guid.NewGuid(),
                SyntheticCode(address, index), DateTimeOffset.UtcNow.AddHours(validityHours))).ToArray();
            _unused.AddRange(codes.Select(code => new UnusedComputerCode(code.Id, DateTimeOffset.UtcNow, code.ExpiresUtc)));
            return Task.FromResult(new ComputerEnrollmentResult<IReadOnlyList<IssuedComputerCode>>(ComputerEnrollmentOutcome.Success, codes));
        }

        public Task<ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>> GetUnusedCodesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ComputerEnrollmentResult<IReadOnlyList<UnusedComputerCode>>(ComputerEnrollmentOutcome.Success, _unused.ToArray()));

        public Task<ComputerEnrollmentOutcome> RevokeCodeAsync(Guid id, CancellationToken cancellationToken)
        {
            _unused.RemoveAll(code => code.Id == id);
            return Task.FromResult(ComputerEnrollmentOutcome.Success);
        }

        public Task<ComputerEnrollmentOutcome> RemoveComputerAsync(Guid endpointId, CancellationToken cancellationToken)
        {
            Removed.Add(endpointId);
            return Task.FromResult(ComputerEnrollmentOutcome.Success);
        }

        // A synthetic code in the documented text form; only its prefix and line count matter to the view.
        private static string SyntheticCode(string address, int index) =>
            "SAI1-" + string.Join("-", Enumerable.Range(0, 32).Select(group => ((index * 7 + group) % 90000 + 10000).ToString())) + "-" + address.Length + Pin[..2];
    }
}
