using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Enrollment;
using SentinelAI.Setup.Foundation;

namespace SentinelAI.Setup;

/// <summary>SentinelAI-Agent-Setup.exe (MVP-2): paste an enrollment code or open a code file, then install; or uninstall.</summary>
public sealed class AgentSetupWindow : Window
{
    private readonly PasswordBox _code = new() { MaxLength = EnrollmentCode.MaximumTextLength };
    private readonly Button _openFile = new() { Content = "Open code file...", MinHeight = 32, HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(12, 0, 12, 0) };
    private readonly TextBlock _fileStatus = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly StackPanel _installPanel = new() { Visibility = Visibility.Collapsed };
    private readonly Button _install = new() { Content = "Install SentinelAI Agent", MinHeight = 36, Margin = new Thickness(0, 16, 0, 12) };
    private readonly StackPanel _uninstallPanel = new() { Visibility = Visibility.Collapsed };
    private readonly Button _uninstallButton = new() { Content = "Uninstall SentinelAI Agent", MinHeight = 36, Margin = new Thickness(0, 12, 0, 12) };
    private readonly TextBlock _version = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
    private readonly TextBlock _progress = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _finished = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkRed, Visibility = Visibility.Collapsed };
    private readonly SafeFileHandle _image;
    private readonly bool _uninstallRequested;
    private AgentSetupSession? _session;
    private AgentSetupInstallation? _state;
    private EnrollmentCode? _fileCode;
    private bool _working;
    private bool _closing;
    private bool _done;

    public AgentSetupWindow(SafeFileHandle image, bool uninstall)
    {
        _image = image; _uninstallRequested = uninstall;
        Title = "SentinelAI Agent Setup"; Width = 620; Height = 560; MinWidth = 460; MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock { Text = "SentinelAI Agent Setup", FontSize = 26, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 14) });
        panel.Children.Add(new TextBlock { Text = "Installs SentinelAI Agent on this computer and connects it to your company's central SentinelAI computer. Your administrator creates one enrollment code per computer in SentinelAI Desktop under Devices > Add computers.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) });
        AutomationProperties.SetAutomationId(_version, "AgentSetupVersion"); panel.Children.Add(_version);
        var label = new Label { Content = "Enrollment code", Target = _code, Padding = new Thickness(0, 8, 0, 4) };
        AutomationProperties.SetAutomationId(_code, "AgentSetupCode"); AutomationProperties.SetName(_code, "Enrollment code"); _code.MinHeight = 30;
        _installPanel.Children.Add(label); _installPanel.Children.Add(_code);
        _installPanel.Children.Add(new TextBlock { Text = "Paste the code, or open the code file you received. The code is a secret and works for one computer only.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 8) });
        AutomationProperties.SetAutomationId(_openFile, "AgentSetupOpenCodeFile"); _installPanel.Children.Add(_openFile);
        AutomationProperties.SetAutomationId(_fileStatus, "AgentSetupCodeFileStatus"); _installPanel.Children.Add(_fileStatus);
        AutomationProperties.SetAutomationId(_install, "AgentSetupInstallButton"); _installPanel.Children.Add(_install);
        panel.Children.Add(_installPanel);
        _uninstallPanel.Children.Add(new TextBlock { Text = "Uninstall removes the Agent service, its program files, its enrollment with SentinelAI Core and its data from this computer. Core keeps the computer's history until an administrator removes it in Desktop.", TextWrapping = TextWrapping.Wrap });
        AutomationProperties.SetAutomationId(_uninstallButton, "AgentSetupUninstallButton"); _uninstallPanel.Children.Add(_uninstallButton);
        panel.Children.Add(_uninstallPanel);
        AutomationProperties.SetAutomationId(_progress, "AgentSetupProgressText"); AutomationProperties.SetAutomationId(_finished, "AgentSetupFinishedText"); AutomationProperties.SetAutomationId(_error, "AgentSetupErrorText");
        foreach (var text in new[] { _progress, _error, _finished }) { text.Margin = new Thickness(0, 6, 0, 6); panel.Children.Add(text); }
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _install.Click += Install; _uninstallButton.Click += Uninstall; _openFile.Click += OpenFile;
        _code.PasswordChanged += (_, _) => { if (_code.Password.Length != 0) { _fileCode = null; _fileStatus.Text = ""; } };
        Closing += ClosingWindow; Closed += (_, _) => _session?.Dispose();
        SetInputs();
        Loaded += (_, _) => Initialize();
    }

    private async void Initialize()
    {
        _working = true; SetInputs(); _progress.Text = "Checking installation files and this computer...";
        Application.Current.Properties["ExitCode"] = (int)AgentSetupExitCode.Failed;
        try
        {
            _session = await AgentSetupSession.OpenAsync(_image, new Progress<string>(value => _progress.Text = value), CancellationToken.None);
            _state = await _session.Worker.InspectAsync(CancellationToken.None);
            _version.Text = _state.Version is null ? $"Agent Setup version: {_session.Version}" : $"Installed version: {_state.Version}. Agent Setup version: {_session.Version}.";
            switch (_state.Kind)
            {
                case AgentSetupInstallationKind.Installed:
                    _uninstallPanel.Visibility = Visibility.Visible; _progress.Text = "SentinelAI Agent is installed on this computer.";
                    break;
                case AgentSetupInstallationKind.Fresh when _uninstallRequested:
                    _progress.Text = ""; ShowError(AgentSetupExitCode.NotInstalled, true);
                    break;
                case AgentSetupInstallationKind.Fresh:
                    _installPanel.Visibility = Visibility.Visible; _progress.Text = "Ready to install.";
                    break;
                default:
                    _progress.Text = ""; ShowError(_uninstallRequested ? AgentSetupExitCode.NotInstalled : AgentSetupExitCode.AlreadyInstalled, _uninstallRequested);
                    break;
            }
        }
        catch (Exception) { _progress.Text = ""; ShowText(_error, "Agent Setup is unavailable. Use a complete Agent Setup file and approve Windows administrator elevation. Support code: AGENT-SETUP-INSPECT."); }
        finally { _working = false; SetInputs(); if (_closing) Close(); else if (_installPanel.IsVisible) _code.Focus(); }
    }

    private void OpenFile(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "SentinelAI enrollment code (*" + EnrollmentCode.FileExtension + ")|*" + EnrollmentCode.FileExtension, CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        _code.Clear();
        if (AgentSetupWorkflow.TryReadCodeFile(dialog.FileName, out var code))
        {
            _fileCode = code; _fileStatus.Text = "Code file loaded: " + Path.GetFileName(dialog.FileName); _error.Visibility = Visibility.Collapsed;
        }
        else { _fileCode = null; _fileStatus.Text = ""; ShowError(AgentSetupExitCode.InvalidCode, false); }
    }

    private async void Install(object sender, RoutedEventArgs e)
    {
        if (_working || _done || _session is null || _state?.Kind != AgentSetupInstallationKind.Fresh) return;
        var code = _fileCode;
        if (code is null && !EnrollmentCode.TryParse(_code.Password, out code)) { ShowError(AgentSetupExitCode.InvalidCode, false); return; }
        _working = true; SetInputs(); _error.Visibility = Visibility.Collapsed;
        var result = AgentSetupExitCode.InstallFailed;
        try
        {
            using var operation = WindowsSetupLifecycle.AcquireOperationLock();
            // Never canceled once started: a half-finished install is always completed or removed by the worker.
            result = await AgentSetupWorkflow.InstallAsync(code!, _session.Worker, new HttpAgentCodeProbe(),
                new Progress<string>(value => _progress.Text = value), CancellationToken.None);
        }
        catch (Exception) { result = AgentSetupExitCode.InstallFailed; }
        finally
        {
            _working = false;
            if (result == AgentSetupExitCode.Success)
            {
                _done = true; _code.Clear(); _fileCode = null; _progress.Text = "Installation finished.";
                Application.Current.Properties["ExitCode"] = 0; ShowText(_finished, AgentSetupWorkflow.Describe(result, false));
            }
            else { _progress.Text = ""; ShowError(result, false); }
            SetInputs(); if (_closing) Close();
        }
    }

    private async void Uninstall(object sender, RoutedEventArgs e)
    {
        if (_working || _done || _session is null || _state?.Kind != AgentSetupInstallationKind.Installed) return;
        _working = true; SetInputs(); _error.Visibility = Visibility.Collapsed;
        var result = AgentSetupExitCode.UninstallFailed;
        try
        {
            using var operation = WindowsSetupLifecycle.AcquireOperationLock();
            result = await AgentSetupWorkflow.UninstallAsync(_session.Worker, new Progress<string>(value => _progress.Text = value), CancellationToken.None);
        }
        catch (Exception) { result = AgentSetupExitCode.UninstallFailed; }
        finally
        {
            _working = false;
            if (result == AgentSetupExitCode.Success)
            {
                _done = true; _progress.Text = "Uninstall finished.";
                Application.Current.Properties["ExitCode"] = 0; ShowText(_finished, AgentSetupWorkflow.Describe(result, true));
            }
            else { _progress.Text = ""; ShowError(result, true); }
            SetInputs(); if (_closing) Close();
        }
    }

    private void SetInputs()
    {
        var install = !_working && !_done && !_closing && _session is not null && _state?.Kind == AgentSetupInstallationKind.Fresh;
        _code.IsEnabled = install; _openFile.IsEnabled = install; _install.IsEnabled = install;
        _uninstallButton.IsEnabled = !_working && !_done && !_closing && _session is not null && _state?.Kind == AgentSetupInstallationKind.Installed;
    }

    private void ShowError(AgentSetupExitCode code, bool uninstall)
    {
        Application.Current.Properties["ExitCode"] = (int)code;
        ShowText(_error, AgentSetupWorkflow.Describe(code, uninstall));
    }

    private void ShowText(TextBlock block, string text)
    {
        block.Text = text; block.Visibility = Visibility.Visible;
        Dispatcher.BeginInvoke(new Action(block.BringIntoView), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void ClosingWindow(object? sender, CancelEventArgs e)
    {
        if (!_working) { _code.Clear(); return; }
        // An install or uninstall in progress always runs to its end, including its own cleanup.
        _closing = true; e.Cancel = true; _progress.Text = "Finishing the current step before closing..."; SetInputs();
    }
}
