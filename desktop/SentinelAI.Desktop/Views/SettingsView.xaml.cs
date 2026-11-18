using System.Windows;
using System.Runtime.InteropServices;
using System.ComponentModel;
using static SentinelAI.Localization.Localizer;
using System.Windows.Controls;
using SentinelAI.Desktop.Foundation;

namespace SentinelAI.Desktop.Views;

public partial class SettingsView : UserControl
{
    private BackupViewModel? _backupWatch;
    public SettingsView()
    {
        InitializeComponent();
        Loaded += (_, _) => { if (_backupWatch is not null) _backupWatch.PropertyChanged -= OnBackupChanged; _backupWatch = (Window.GetWindow(this) as MainWindow)?.Backups; if (_backupWatch is not null) _backupWatch.PropertyChanged += OnBackupChanged; };
        Unloaded += (_, _) => { if (_backupWatch is not null) _backupWatch.PropertyChanged -= OnBackupChanged; _backupWatch = null; ClearRecoveryPasswords(); };
    }
    private void OnBackupChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(BackupViewModel.State) && _backupWatch?.State == BackupViewState.None)
        {
            if (Dispatcher.CheckAccess()) ClearRecoveryPasswords(); else Dispatcher.BeginInvoke(new Action(ClearRecoveryPasswords));
        }
    }
    private void ClearRecoveryPasswords() { BackupRecoveryPassword.Clear(); BackupRecoveryPasswordConfirm.Clear(); }
    private async void OnConfigureBackupRecovery(object sender, RoutedEventArgs e)
    {
        if ((Window.GetWindow(this) as MainWindow)?.Backups is not { CanConfigureRecovery: true } model) return;
        static char[] Read(PasswordBox box)
        {
            using var secret = box.SecurePassword;
            var pointer = Marshal.SecureStringToGlobalAllocUnicode(secret);
            var chars = new char[secret.Length];
            try { for (var i = 0; i < chars.Length; i++) chars[i] = (char)Marshal.ReadInt16(pointer, i * 2); }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(pointer); box.Clear(); }
            return chars;
        }
        var password = Read(BackupRecoveryPassword);
        var confirmation = Read(BackupRecoveryPasswordConfirm);
        try
        {
            if (!password.AsSpan().SequenceEqual(confirmation)) { MessageBox.Show(Window.GetWindow(this), T("The recovery passwords do not match."), "SentinelAI", MessageBoxButton.OK, MessageBoxImage.Information); return; }
            await model.ConfigureRecoveryAsync(password);
        }
        finally { Array.Clear(password); Array.Clear(confirmation); }
    }
    private async void OnRefreshBackups(object sender, RoutedEventArgs e) { if ((Window.GetWindow(this) as MainWindow)?.Backups is { } model) await model.RefreshAsync(); }
    private async void OnSaveBackupPolicy(object sender, RoutedEventArgs e) { if ((Window.GetWindow(this) as MainWindow)?.Backups is { } model) await model.SavePolicyAsync(); }
    private async void OnCreateBackup(object sender, RoutedEventArgs e) { if ((Window.GetWindow(this) as MainWindow)?.Backups is { } model) await model.CreateAsync(); }
    private async void OnVerifyBackup(object sender, RoutedEventArgs e) { if ((Window.GetWindow(this) as MainWindow)?.Backups is { } model) await model.VerifySelectedAsync(); }
    private async void OnExportBackup(object sender, RoutedEventArgs e) { if ((Window.GetWindow(this) as MainWindow)?.Backups is { } model) await model.ExportSelectedAsync(); }
    private void OnOpenBackupRecovery(object sender, RoutedEventArgs e) => (Window.GetWindow(this) as MainWindow)?.Backups?.OpenRecovery();
    private LicenseViewModel? Model => DataContext as LicenseViewModel;

    private async void OnSaveLanguage(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { LanguageSettings: { CanSave: true } language }) await language.SaveAsync();
    }

    private async void OnRefreshLicense(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { Pilot: { CanRefresh: true } pilot }) _ = pilot.RefreshAsync();
        if (Model is { CanRefresh: true } model) await model.RefreshAsync();
    }

    private async void OnRenewLicense(object sender, RoutedEventArgs e)
    {
        if (Model is { CanRenew: true } model) await model.RenewAsync();
    }

    private async void OnApplyPilotKey(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { Pilot: { CanSubmit: true } model }) await model.SubmitAsync();
    }

    private async void OnRefreshLocalNetwork(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { LocalNetwork: { CanRefresh: true } model }) await model.RefreshAsync();
    }

    private async void OnRefreshUpdates(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { CentralUpdate: { CanRefresh: true } model }) await model.RefreshAsync();
    }

    private async void OnCheckForUpdates(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { CentralUpdate: { CanCheckNow: true } model }) await model.CheckNowAsync();
    }

    private async void OnInstallUpdate(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { CentralUpdate: { CanInstall: true } model }) await model.InstallAsync();
    }

    private async void OnRefreshVulnerabilityFeed(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { VulnerabilityFeed: { CanRefresh: true } model }) await model.RefreshAsync();
    }

    private async void OnImportVulnerabilityFeed(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is MainWindow { VulnerabilityFeed: { CanImport: true } model }) await model.ImportAsync();
    }

    private async void OnRefreshDesktopSettings(object sender, RoutedEventArgs e)
    {
        if (Window.GetWindow(this) is not MainWindow window) return;
        window.DesktopIntegration?.RefreshPreferences();
        if (window.ServiceStatus is not null) await window.ServiceStatus.RefreshAsync();
    }

    private void OnViewSizeChanged(object sender, SizeChangedEventArgs e) =>
        SettingsActionsScroller.MaxHeight = Math.Max(36, e.NewSize.Height / 2);
}
