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
    private readonly Button _install = new() { Content = "Install SentinelAI", MinHeight = 36 };
    private readonly Button _open = new() { Content = "Open Desktop", MinHeight = 36, Visibility = Visibility.Collapsed };
    private readonly TextBlock _progress = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _finished = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkRed, Visibility = Visibility.Collapsed };
    private readonly CancellationTokenSource _lifetime = new();
    private EmbeddedInstallation? _installation;
    private bool _working;
    private bool _closing;
    private bool _attempted;

    public SetupWindow()
    {
        Title = "SentinelAI Setup"; Width = 660; Height = 640; MinWidth = 480; MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock { Text = "Install SentinelAI", FontSize = 26, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 14) });
        panel.Children.Add(new TextBlock { Text = "Administrator elevation is required and was requested before this window opened. Setup installs a fresh local deployment in protected Program Files and ProgramData folders. Create the local Core administrator account below.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) });
        AddField(panel, "Administrator username", _username, "SetupAdministratorUsername");
        AddField(panel, "Administrator password (12–1024 characters)", _password, "SetupAdministratorPassword");
        AddField(panel, "Confirm administrator password", _confirmation, "SetupAdministratorConfirmPassword");
        AutomationProperties.SetAutomationId(_install, "SetupInstallButton"); AutomationProperties.SetAutomationId(_open, "SetupOpenDesktopButton");
        AutomationProperties.SetAutomationId(_progress, "SetupProgressText"); AutomationProperties.SetAutomationId(_finished, "SetupFinishedText"); AutomationProperties.SetAutomationId(_error, "SetupErrorText");
        _install.Margin = new Thickness(0, 12, 0, 12); panel.Children.Add(_install);
        foreach (var text in new[] { _progress, _error, _finished }) { text.Margin = new Thickness(0, 6, 0, 6); panel.Children.Add(text); }
        _open.Margin = new Thickness(0, 12, 0, 0); panel.Children.Add(_open);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _install.Click += Install; _open.Click += (_, _) => OpenDesktop(); Closing += ClosingWindow; Closed += (_, _) => { _installation?.Dispose(); _lifetime.Dispose(); };
        Loaded += (_, _) => Initialize();
    }

    private static void AddField(Panel panel, string label, Control control, string id)
    {
        var text = new Label { Content = label, Target = control, Padding = new Thickness(0, 8, 0, 4) };
        AutomationProperties.SetAutomationId(control, id); AutomationProperties.SetName(control, label);
        control.MinHeight = 30; panel.Children.Add(text); panel.Children.Add(control);
    }

    private void Initialize()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new InvalidOperationException();
            _installation = EmbeddedInstallation.Open(); _username.Focus();
            _progress.Text = "Ready to install a fresh local deployment. Existing installations are preserved and will be refused.";
        }
        catch { SetInputs(false); ShowError("Setup is unavailable. Use a complete SentinelAI setup package and approve Windows administrator elevation."); }
    }

    private async void Install(object sender, RoutedEventArgs e)
    {
        if (_working || _attempted || _installation is null) return;
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
        string? work = null;
        try
        {
            work = await _installation.ExtractAsync(_lifetime.Token);
            using var core = new WindowsCoreServices(); using var administrator = core.CreateAdministratorSetupClient();
            var worker = new PowerShellSetupWorker(work, _installation.Metadata, progress);
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
            Array.Clear(password); if (work is not null) ProtectedStaging.TryRemove(work);
            _working = false; if (_closing) Close();
        }
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
    private void SetInputs(bool enabled) { _username.IsEnabled = enabled; _password.IsEnabled = enabled; _confirmation.IsEnabled = enabled; _install.IsEnabled = enabled; }
    private void ShowError(string text) { _error.Text = text; _error.Visibility = Visibility.Visible; Application.Current.Properties["ExitCode"] = 1; }
    private void OpenDesktop()
    {
        _open.IsEnabled = false;
        if (OrdinaryDesktopLauncher.TryOpen()) Close();
        else { _progress.Text = "Open SentinelAI from the Windows Start Menu to sign in. Setup does not launch an elevated Desktop."; _open.IsEnabled = true; }
    }
    private void ClosingWindow(object? sender, CancelEventArgs e)
    {
        _password.Clear(); _confirmation.Clear(); _username.Clear(); _lifetime.Cancel();
        if (_working) { _closing = true; e.Cancel = true; _progress.Text = "Stopping setup..."; SetInputs(false); }
    }
}
