using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Enrollment;
using SentinelAI.Localization;
using SentinelAI.Setup.Foundation;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Setup;

/// <summary>SentinelAI-Agent-Setup.exe (MVP-2): paste an enrollment code or open a code file, then install; or uninstall.</summary>
public sealed class AgentSetupWindow : Window
{
    private readonly PasswordBox _code = new() { MaxLength = EnrollmentCode.MaximumTextLength };
    private readonly Button _openFile = new() { MinHeight = 32, HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(12, 0, 12, 0) };
    private readonly TextBlock _fileStatus = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
    private readonly StackPanel _installPanel = new() { Visibility = Visibility.Collapsed };
    private readonly Button _install = new() { MinHeight = 36, Margin = new Thickness(0, 16, 0, 12) };
    private readonly StackPanel _uninstallPanel = new() { Visibility = Visibility.Collapsed };
    private readonly Button _uninstallButton = new() { MinHeight = 36, Margin = new Thickness(0, 12, 0, 12) };
    private readonly TextBlock _version = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
    private readonly TextBlock _progress = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _finished = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DarkRed, Visibility = Visibility.Collapsed };
    private readonly ComboBox _language = new() { MinHeight = 30, Width = 180, HorizontalAlignment = HorizontalAlignment.Left };
    // Every text is applied through these, so choosing another language redraws the window in place.
    private readonly List<Action> _texts = [];
    private readonly Dictionary<TextBlock, Func<string>> _shown = [];
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
        // Agent Setup has no installation language of its own: it starts in Windows' language.
        Use(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "pl" ? UiLanguage.Polish : UiLanguage.English);
        Text(() => Title = T("SentinelAI Agent Setup")); Width = 620; Height = 560; MinWidth = 460; MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var panel = new StackPanel { Margin = new Thickness(28) };
        var languageRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
        languageRow.Children.Add(new TextBlock { Text = "Język / Language", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
        _language.ItemsSource = LanguageSettingsViewModel.Options; _language.DisplayMemberPath = nameof(LanguageOption.Text);
        _language.SelectedValuePath = nameof(LanguageOption.Language); _language.SelectedValue = Current;
        AutomationProperties.SetAutomationId(_language, "AgentSetupLanguage"); AutomationProperties.SetName(_language, "Język / Language");
        _language.SelectionChanged += (_, _) => { if (_language.SelectedValue is UiLanguage chosen && chosen != Current) ApplyLanguage(chosen); };
        languageRow.Children.Add(_language); panel.Children.Add(languageRow);
        panel.Children.Add(Localized(new TextBlock { FontSize = 26, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 14) }, () => T("SentinelAI Agent Setup")));
        panel.Children.Add(Localized(new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) },
            () => T("Installs SentinelAI Agent on this computer and connects it to your company's central SentinelAI computer. Your administrator creates one enrollment code per computer in SentinelAI Desktop under Devices > Add computers.")));
        AutomationProperties.SetAutomationId(_version, "AgentSetupVersion"); panel.Children.Add(_version);
        var label = new Label { Target = _code, Padding = new Thickness(0, 8, 0, 4) };
        AutomationProperties.SetAutomationId(_code, "AgentSetupCode"); _code.MinHeight = 30;
        Text(() => { label.Content = T("Enrollment code"); AutomationProperties.SetName(_code, T("Enrollment code")); });
        _installPanel.Children.Add(label); _installPanel.Children.Add(_code);
        _installPanel.Children.Add(Localized(new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 8) },
            () => T("Paste the code, or open the code file you received. The code is a secret and works for one computer only.")));
        Text(() => _openFile.Content = T("Open code file..."));
        AutomationProperties.SetAutomationId(_openFile, "AgentSetupOpenCodeFile"); _installPanel.Children.Add(_openFile);
        AutomationProperties.SetAutomationId(_fileStatus, "AgentSetupCodeFileStatus"); _installPanel.Children.Add(_fileStatus);
        Text(() => _install.Content = T("Install SentinelAI Agent"));
        AutomationProperties.SetAutomationId(_install, "AgentSetupInstallButton"); _installPanel.Children.Add(_install);
        panel.Children.Add(_installPanel);
        _uninstallPanel.Children.Add(Localized(new TextBlock { TextWrapping = TextWrapping.Wrap },
            () => T("Uninstall removes the Agent service, its program files, its enrollment with SentinelAI Core and its data from this computer. Core keeps the computer's history until an administrator removes it in Desktop.")));
        Text(() => _uninstallButton.Content = T("Uninstall SentinelAI Agent"));
        AutomationProperties.SetAutomationId(_uninstallButton, "AgentSetupUninstallButton"); _uninstallPanel.Children.Add(_uninstallButton);
        panel.Children.Add(_uninstallPanel);
        AutomationProperties.SetAutomationId(_progress, "AgentSetupProgressText"); AutomationProperties.SetAutomationId(_finished, "AgentSetupFinishedText"); AutomationProperties.SetAutomationId(_error, "AgentSetupErrorText");
        foreach (var text in new[] { _progress, _error, _finished }) { text.Margin = new Thickness(0, 6, 0, 6); panel.Children.Add(text); }
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _install.Click += Install; _uninstallButton.Click += Uninstall; _openFile.Click += OpenFile;
        _code.PasswordChanged += (_, _) => { if (_code.Password.Length != 0) { _fileCode = null; Say(_fileStatus, () => ""); } };
        Closing += ClosingWindow; Closed += (_, _) => _session?.Dispose();
        SetInputs();
        Loaded += (_, _) => Initialize();
    }

    private void Text(Action apply) { _texts.Add(apply); apply(); }

    private TextBlock Localized(TextBlock block, Func<string> text) { Text(() => block.Text = text()); return block; }

    /// <summary>Shows a status text that is redrawn when the language changes.</summary>
    private void Say(TextBlock block, Func<string> text) { _shown[block] = text; block.Text = text(); }

    private void ApplyLanguage(UiLanguage language)
    {
        Use(language);
        foreach (var apply in _texts) apply();
        foreach (var (block, text) in _shown) block.Text = text();
    }

    private async void Initialize()
    {
        _working = true; SetInputs(); Say(_progress, () => T("Checking installation files and this computer..."));
        Application.Current.Properties["ExitCode"] = (int)AgentSetupExitCode.Failed;
        try
        {
            _session = await AgentSetupSession.OpenAsync(_image, new Progress<string>(value => Say(_progress, () => value)), CancellationToken.None);
            _state = await _session.Worker.InspectAsync(CancellationToken.None);
            var setupVersion = _session.Version; var installedVersion = _state.Version;
            Say(_version, () => installedVersion is null ? F("Agent Setup version: {0}", setupVersion) : F("Installed version: {0}. Agent Setup version: {1}.", installedVersion, setupVersion));
            switch (_state.Kind)
            {
                case AgentSetupInstallationKind.Installed:
                    _uninstallPanel.Visibility = Visibility.Visible; Say(_progress, () => T("SentinelAI Agent is installed on this computer."));
                    break;
                case AgentSetupInstallationKind.Fresh when _uninstallRequested:
                    Say(_progress, () => ""); ShowError(AgentSetupExitCode.NotInstalled, true);
                    break;
                case AgentSetupInstallationKind.Fresh:
                    _installPanel.Visibility = Visibility.Visible; Say(_progress, () => T("Ready to install."));
                    break;
                default:
                    Say(_progress, () => ""); ShowError(_uninstallRequested ? AgentSetupExitCode.NotInstalled : AgentSetupExitCode.AlreadyInstalled, _uninstallRequested);
                    break;
            }
        }
        catch (Exception)
        {
            Say(_progress, () => "");
            ShowText(_error, () => T("Agent Setup is unavailable. Use a complete Agent Setup file and approve Windows administrator elevation. Support code: AGENT-SETUP-INSPECT."));
        }
        finally { _working = false; SetInputs(); if (_closing) Close(); else if (_installPanel.IsVisible) _code.Focus(); }
    }

    private void OpenFile(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = F("SentinelAI enrollment code (*{0})|*{0}", EnrollmentCode.FileExtension), CheckFileExists = true, Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;
        _code.Clear();
        if (AgentSetupWorkflow.TryReadCodeFile(dialog.FileName, out var code))
        {
            var name = Path.GetFileName(dialog.FileName);
            _fileCode = code; Say(_fileStatus, () => F("Code file loaded: {0}", name)); _error.Visibility = Visibility.Collapsed;
        }
        else { _fileCode = null; Say(_fileStatus, () => ""); ShowError(AgentSetupExitCode.InvalidCode, false); }
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
                new Progress<string>(value => Say(_progress, () => value)), CancellationToken.None);
        }
        catch (Exception) { result = AgentSetupExitCode.InstallFailed; }
        finally
        {
            _working = false;
            if (result == AgentSetupExitCode.Success)
            {
                _done = true; _code.Clear(); _fileCode = null; Say(_progress, () => T("Installation finished."));
                Application.Current.Properties["ExitCode"] = 0; ShowText(_finished, () => AgentSetupWorkflow.Describe(result, false));
            }
            else { Say(_progress, () => ""); ShowError(result, false); }
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
            result = await AgentSetupWorkflow.UninstallAsync(_session.Worker, new Progress<string>(value => Say(_progress, () => value)), CancellationToken.None);
        }
        catch (Exception) { result = AgentSetupExitCode.UninstallFailed; }
        finally
        {
            _working = false;
            if (result == AgentSetupExitCode.Success)
            {
                _done = true; Say(_progress, () => T("Uninstall finished."));
                Application.Current.Properties["ExitCode"] = 0; ShowText(_finished, () => AgentSetupWorkflow.Describe(result, true));
            }
            else { Say(_progress, () => ""); ShowError(result, true); }
            SetInputs(); if (_closing) Close();
        }
    }

    private void SetInputs()
    {
        var install = !_working && !_done && !_closing && _session is not null && _state?.Kind == AgentSetupInstallationKind.Fresh;
        _code.IsEnabled = install; _openFile.IsEnabled = install; _install.IsEnabled = install;
        _uninstallButton.IsEnabled = !_working && !_done && !_closing && _session is not null && _state?.Kind == AgentSetupInstallationKind.Installed;
        _language.IsEnabled = !_working && !_done && !_closing;
    }

    private void ShowError(AgentSetupExitCode code, bool uninstall)
    {
        Application.Current.Properties["ExitCode"] = (int)code;
        ShowText(_error, () => AgentSetupWorkflow.Describe(code, uninstall));
    }

    private void ShowText(TextBlock block, Func<string> text)
    {
        Say(block, text); block.Visibility = Visibility.Visible;
        Dispatcher.BeginInvoke(new Action(block.BringIntoView), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void ClosingWindow(object? sender, CancelEventArgs e)
    {
        if (!_working) { _code.Clear(); return; }
        // An install or uninstall in progress always runs to its end, including its own cleanup.
        _closing = true; e.Cancel = true; Say(_progress, () => T("Finishing the current step before closing...")); SetInputs();
    }
}
