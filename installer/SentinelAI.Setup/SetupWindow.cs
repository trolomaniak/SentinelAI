using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using SentinelAI.Desktop.Services;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

public sealed class SetupWindow : Window
{
    private readonly TextBox _username = new() { MaxLength = 128 };
    private readonly PasswordBox _password = new() { MaxLength = 1024 };
    private readonly PasswordBox _confirmation = new() { MaxLength = 1024 };
    private readonly StackPanel _credentials = new() { Visibility = Visibility.Collapsed };
    private readonly StackPanel _maintenance = new() { Visibility = Visibility.Collapsed };
    private readonly ComboBox _action = new() { MinHeight = 30 };
    private readonly CheckBox _preserveData = new() { Content = "Keep security history and protected configuration", IsChecked = true, Margin = new Thickness(0, 12, 0, 8) };
    private readonly StackPanel _removal = new() { Visibility = Visibility.Collapsed };
    private readonly TextBox _removalConfirmation = new() { MaxLength = 6 };
    private readonly Button _lifecycle = new() { Content = "Continue", MinHeight = 36, Margin = new Thickness(0, 12, 0, 12) };
    private readonly TextBlock _version = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
    private readonly Button _install = new() { Content = "Install SentinelAI", MinHeight = 36 };
    private readonly Button _open = new() { Content = "Open Desktop", MinHeight = 36, Visibility = Visibility.Collapsed };
    private readonly TextBlock _progress = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _finished = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkRed, Visibility = Visibility.Collapsed };
    private readonly CancellationTokenSource _lifetime = new();
    private EmbeddedInstallation? _installation;
    private ISetupLifecycleBackend? _backend;
    private SetupInstallation? _state;
    private string? _work;
    private bool _working;
    private bool _closing;
    private bool _attempted;

    public SetupWindow()
    {
        Title = "SentinelAI Setup"; Width = 660; Height = 640; MinWidth = 480; MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock { Text = "SentinelAI Setup", FontSize = 26, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 14) });
        panel.Children.Add(new TextBlock { Text = "Administrator elevation is required and was requested before this window opened. Setup checks the protected local deployment before offering installation, repair, upgrade or uninstall. Repair and upgrade preserve security history, identity and protected configuration.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) });
        AutomationProperties.SetAutomationId(_version, "SetupInstallationVersion"); panel.Children.Add(_version);
        AddField(_credentials, "Administrator username", _username, "SetupAdministratorUsername");
        AddField(_credentials, "Administrator password (12–1024 characters)", _password, "SetupAdministratorPassword");
        AddField(_credentials, "Confirm administrator password", _confirmation, "SetupAdministratorConfirmPassword");
        AutomationProperties.SetAutomationId(_install, "SetupInstallButton"); AutomationProperties.SetAutomationId(_open, "SetupOpenDesktopButton");
        AutomationProperties.SetAutomationId(_progress, "SetupProgressText"); AutomationProperties.SetAutomationId(_finished, "SetupFinishedText"); AutomationProperties.SetAutomationId(_error, "SetupErrorText");
        _install.Margin = new Thickness(0, 12, 0, 12); _credentials.Children.Add(_install); panel.Children.Add(_credentials);
        AddField(_maintenance, "Operation", _action, "SetupLifecycleAction");
        AutomationProperties.SetAutomationId(_preserveData, "SetupPreserveData"); _maintenance.Children.Add(_preserveData);
        _removal.Children.Add(new TextBlock { Text = "This permanently removes the owned security history, identity and protected configuration. Type DELETE to confirm data removal.", TextWrapping = TextWrapping.Wrap });
        AddField(_removal, "Data removal confirmation", _removalConfirmation, "SetupDataRemovalConfirmation");
        _maintenance.Children.Add(_removal); AutomationProperties.SetAutomationId(_lifecycle, "SetupLifecycleButton"); _maintenance.Children.Add(_lifecycle); panel.Children.Add(_maintenance);
        foreach (var text in new[] { _progress, _error, _finished }) { text.Margin = new Thickness(0, 6, 0, 6); panel.Children.Add(text); }
        _open.Margin = new Thickness(0, 12, 0, 0); panel.Children.Add(_open);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _install.Click += Install; _lifecycle.Click += Maintain; _open.Click += (_, _) => OpenDesktop();
        _action.SelectionChanged += (_, _) => UpdateMaintenanceInputs(); _preserveData.Checked += (_, _) => UpdateMaintenanceInputs(); _preserveData.Unchecked += (_, _) => UpdateMaintenanceInputs(); _removalConfirmation.TextChanged += (_, _) => UpdateMaintenanceInputs();
        Closing += ClosingWindow; Closed += (_, _) => { if (_work is not null) ProtectedStaging.TryRemove(_work); _installation?.Dispose(); _lifetime.Dispose(); };
        SetInputs(false);
        Loaded += (_, _) => Initialize();
    }

    private static void AddField(Panel panel, string label, Control control, string id)
    {
        var text = new Label { Content = label, Target = control, Padding = new Thickness(0, 8, 0, 4) };
        AutomationProperties.SetAutomationId(control, id); AutomationProperties.SetName(control, label);
        control.MinHeight = 30; panel.Children.Add(text); panel.Children.Add(control);
    }

    private async void Initialize()
    {
        _working = true; _progress.Text = "Checking installation files and the local deployment...";
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException();
            _installation = EmbeddedInstallation.Open();
            _work = await _installation.ExtractAsync(_lifetime.Token);
            _backend = new WindowsSetupLifecycle(_work, _installation.Metadata, new Progress<string>(value => _progress.Text = value));
            _state = await _backend.InspectAsync(_lifetime.Token); _lifetime.Token.ThrowIfCancellationRequested();
            _version.Text = _state.Version is null ? $"Setup version: {_installation.Metadata.Version}" : $"Installed version: {_state.Version}. Setup version: {_installation.Metadata.Version}.";
            if (_state.Kind == SetupInstallationKind.Fresh)
            {
                _credentials.Visibility = Visibility.Visible; _progress.Text = "Ready for a fresh local installation. Create the Core administrator below.";
            }
            else if (_state.Kind is SetupInstallationKind.Installed or SetupInstallationKind.Retained or SetupInstallationKind.RecoveryPending)
            {
                _action.ItemsSource = SetupWorkflow.AllowedLifecycleActions(_state, _installation.Metadata.Version); _action.SelectedIndex = 0;
                _maintenance.Visibility = Visibility.Visible;
                _progress.Text = _state.Kind switch
                {
                    SetupInstallationKind.Retained => "Protected data from an owned installation is retained.",
                    SetupInstallationKind.RecoveryPending => "An interrupted code replacement was detected. Recover the verified installation before continuing.",
                    _ => "The owned installation was detected. Select an available operation."
                };
            }
            else ShowError("This deployment could not be verified as owned. No operation is available. Support code: SETUP-OWNERSHIP.");
        }
        catch (OperationCanceledException) { Application.Current.Properties["ExitCode"] = 1; }
        catch { ShowError("Setup is unavailable. Use a complete package and approve Windows administrator elevation. Support code: SETUP-INSPECT."); }
        finally
        {
            _working = false; SetInputs(!_closing); if (_state?.Kind == SetupInstallationKind.Fresh && !_closing) _username.Focus();
            if (_closing) Close();
        }
    }

    private async void Install(object sender, RoutedEventArgs e)
    {
        if (_working || _attempted || _installation is null || _work is null || _state?.Kind != SetupInstallationKind.Fresh) return;
        var password = Copy(_password.SecurePassword); var confirmation = Copy(_confirmation.SecurePassword);
        if (!SetupWorkflow.ValidCredentials(_username.Text, password, confirmation))
        {
            Array.Clear(password); Array.Clear(confirmation); _password.Clear(); _confirmation.Clear();
            ShowError("Enter a valid username and matching password with 12–1024 characters."); return;
        }
        Array.Clear(confirmation); var username = _username.Text.Trim();
        _password.Clear(); _confirmation.Clear(); _username.Clear();
        _attempted = true; _working = true; SetInputs(false); _error.Visibility = Visibility.Collapsed;
        _progress.Text = "Validating installation files...";
        var progress = new Progress<string>(value => _progress.Text = value);
        try
        {
            using var operation = WindowsSetupLifecycle.AcquireOperationLock();
            using var core = new WindowsCoreServices(); using var administrator = core.CreateAdministratorSetupClient();
            var worker = new PowerShellSetupWorker(_work, _installation.Metadata, progress);
            var issuer = new SetupEnrollmentIssuer(core);
            await SetupWorkflow.InstallAsync(worker, administrator, issuer, username, password, progress, _lifetime.Token);
            _progress.Text = "Installation finished.";
            Application.Current.Properties["ExitCode"] = 0;
            _finished.Text = "SentinelAI installation completed. Open Desktop and sign in with the administrator account you created.";
            _finished.Visibility = Visibility.Visible; _open.Visibility = Visibility.Visible;
        }
        catch (OperationCanceledException) { Application.Current.Properties["ExitCode"] = 1; }
        catch { ShowError("Installation failed safely. No existing installation was replaced. Close Setup and check the installation state before continuing."); }
        finally
        {
            Array.Clear(password);
            _working = false; if (_closing) Close();
        }
    }

    private async void Maintain(object sender, RoutedEventArgs e)
    {
        if (_working || _attempted || _backend is null || _installation is null || _state is null || _action.SelectedItem is not SetupLifecycleAction action) return;
        var preserveData = _preserveData.IsChecked != false;
        var removalConfirmation = _removalConfirmation.Text;
        if (!SetupWorkflow.CanExecuteLifecycle(_state, _installation.Metadata.Version, action, preserveData, removalConfirmation)) return;
        _working = true; _attempted = true; SetInputs(false); _error.Visibility = Visibility.Collapsed; _removalConfirmation.Clear();
        try
        {
            var result = await SetupWorkflow.ExecuteLifecycleAsync(_backend, _state, _installation.Metadata.Version, action, preserveData, removalConfirmation, _lifetime.Token);
            if (!result.Success)
            {
                ShowError(result.FailureCode switch
                {
                    "desktop_running" => "Close SentinelAI Desktop and run Setup again. Support code: SETUP-DESKTOP.",
                    "finish_uninstall" => "Complete Uninstall with data retained, then run Setup again to restore the installation. Support code: SETUP-RETAINED.",
                    "rollback_failed" => "Installation recovery could not complete. Run Setup again to recover the verified installation. Support code: SETUP-RECOVERY.",
                    _ when result.RolledBack => "The operation failed. The previous working code was restored. Support code: SETUP-ROLLBACK.",
                    _ => "The operation could not be completed. Close Setup and inspect the installation state. Support code: SETUP-LIFECYCLE."
                });
                return;
            }
            Application.Current.Properties["ExitCode"] = 0; _progress.Text = "Operation finished.";
            _finished.Text = action switch
            {
                SetupLifecycleAction.Repair when _state.Kind == SetupInstallationKind.RecoveryPending => "The verified installation was recovered. Close Setup and reopen it to select another operation.",
                SetupLifecycleAction.Uninstall when preserveData => "SentinelAI services and owned program files were removed. Security history, identity and protected configuration were retained.",
                SetupLifecycleAction.Uninstall => "SentinelAI services, owned program files and explicitly selected installation data were removed.",
                SetupLifecycleAction.Repair => "SentinelAI program files were repaired. Security history, identity and protected configuration were preserved.",
                _ => "SentinelAI was upgraded. Security history, identity and protected configuration were preserved."
            };
            _finished.Visibility = Visibility.Visible;
            if (action != SetupLifecycleAction.Uninstall && _state.Kind != SetupInstallationKind.RecoveryPending) _open.Visibility = Visibility.Visible;
        }
        catch (OperationCanceledException) { Application.Current.Properties["ExitCode"] = 1; }
        catch { ShowError("The operation could not be completed. Close Setup and inspect the installation state. Support code: SETUP-LIFECYCLE."); }
        finally { _working = false; if (_closing) Close(); }
    }

    private static char[] Copy(SecureString secure)
    {
        using (secure)
        {
            var characters = new char[secure.Length]; var pointer = Marshal.SecureStringToGlobalAllocUnicode(secure);
            try { Marshal.Copy(pointer, characters, 0, characters.Length); return characters; }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
        }
    }
    private void SetInputs(bool enabled)
    {
        var fresh = enabled && !_working && !_attempted && _state?.Kind == SetupInstallationKind.Fresh;
        _username.IsEnabled = fresh; _password.IsEnabled = fresh; _confirmation.IsEnabled = fresh; _install.IsEnabled = fresh;
        UpdateMaintenanceInputs();
    }
    private void UpdateMaintenanceInputs()
    {
        var available = !_working && !_attempted && !_closing && _state?.Kind is SetupInstallationKind.Installed or SetupInstallationKind.Retained or SetupInstallationKind.RecoveryPending;
        var uninstall = _action.SelectedItem is SetupLifecycleAction.Uninstall;
        _action.IsEnabled = available; _preserveData.IsEnabled = available && uninstall;
        _lifecycle.Content = _state?.Kind == SetupInstallationKind.RecoveryPending ? "Recover installation" : "Continue";
        if (!uninstall && _preserveData.IsChecked != true) _preserveData.IsChecked = true;
        _removal.Visibility = uninstall && _preserveData.IsChecked == false ? Visibility.Visible : Visibility.Collapsed;
        _removalConfirmation.IsEnabled = available && _removal.Visibility == Visibility.Visible;
        _lifecycle.IsEnabled = available && _installation is not null && _state is not null && _action.SelectedItem is SetupLifecycleAction action &&
            SetupWorkflow.CanExecuteLifecycle(_state, _installation.Metadata.Version, action, _preserveData.IsChecked != false, _removalConfirmation.Text);
    }
    private void ShowError(string text) { _error.Text = text; _error.Visibility = Visibility.Visible; Application.Current.Properties["ExitCode"] = 1; }
    private void OpenDesktop()
    {
        _open.IsEnabled = false;
        if (OrdinaryDesktopLauncher.TryOpen()) Close();
        else { _progress.Text = "Open SentinelAI from the Windows Start Menu to sign in. Setup does not launch an elevated Desktop."; _open.IsEnabled = true; }
    }
    private void ClosingWindow(object? sender, CancelEventArgs e)
    {
        _password.Clear(); _confirmation.Clear(); _username.Clear(); _removalConfirmation.Clear(); _lifetime.Cancel();
        if (_working) { _closing = true; e.Cancel = true; _progress.Text = "Stopping setup..."; SetInputs(false); }
    }
}
