using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SentinelAI.Contracts.Backups;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Services;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop;

public partial class BackupRecoveryWindow : Window
{
    private readonly BackupRecoveryCoordinator _recovery;
    private readonly Func<bool, string?> _picker;
    private readonly CancellationTokenSource _lifetime = new();
    private string? _archive, _key;
    private BackupRecoveryPreview? _preview;
    private bool _busy, _pending, _updatingMode;
    public BackupRecoveryWindow(BackupRecoveryCoordinator? recovery = null, Func<bool, string?>? picker = null)
    {
        InitializeComponent();
        var service = new WindowsBackupRecoveryService();
        _recovery = recovery ?? new BackupRecoveryCoordinator(service, service);
        _picker = picker ?? PickFile;
        Loaded += async (_, _) => { UpdateMode(); await ReadStatusAsync(); };
        Closing += (_, e) => { if (_busy) e.Cancel = true; };
        Closed += (_, _) => { RecoveryPassword.Clear(); _lifetime.Cancel(); _lifetime.Dispose(); };
    }
    private string Mode => (ModeBox.SelectedItem as ComboBoxItem)?.Tag as string ?? BackupRecoveryContract.SameMachine;
    private string ExpectedConfirmation => Mode == BackupRecoveryContract.Migration ? BackupRecoveryContract.MigrationConfirmation : BackupRecoveryContract.RestoreConfirmation;
    private string? PickFile(bool key)
    {
        var picker = new OpenFileDialog { Title = key ? T("Choose recovery key") : T("Choose encrypted backup"),
            Filter = key ? T("Encrypted recovery key (*.sakey)|*.sakey") : T("Encrypted backup (*.sab)|*.sab"), CheckFileExists = true, Multiselect = false };
        return picker.ShowDialog(this) == true ? picker.FileName : null;
    }
    private void OnChooseArchive(object sender, RoutedEventArgs e)
    {
        if (_picker(false) is { } path) { _archive = path; ArchiveText.Text = Path.GetFileName(path); InvalidatePreview(); }
    }
    private void OnChooseKey(object sender, RoutedEventArgs e)
    {
        if (_picker(true) is { } path) { _key = path; KeyText.Text = Path.GetFileName(path); InvalidatePreview(); }
    }
    private void OnModeChanged(object sender, SelectionChangedEventArgs e) { if (RecoveryPassword is null || _updatingMode) return; UpdateMode(); InvalidatePreview(); }
    private void UpdateMode()
    {
        ConfirmationLabel.Text = F("After reviewing the restore point, type {0} to confirm replacement of Core data.", ExpectedConfirmation);
        MigrationText.Text = Mode == BackupRecoveryContract.Migration
            ? T("Migration requires a fresh central installation created within the last 24 hours, without configured backups or remote Agents. Remote Agents must be reinstalled and enrolled again using the new certificate pin. Retained history is preserved.")
            : T("This mode keeps this installation's certificate, service configuration and local Agent state.");
    }
    private void InvalidatePreview()
    {
        _preview = null; PreviewText.Text = string.Empty; ConfirmationText.Clear(); RecoveryPassword.Clear(); UpdateButtons();
    }
    private void UpdateButtons()
    {
        RecoveryControls.IsEnabled = !_busy;
        PreviewButton.IsEnabled = !_busy && !_pending && _archive is not null && _key is not null;
        RestoreButton.IsEnabled = !_busy && !_pending && _preview is not null;
        RollbackButton.IsEnabled = !_busy && _pending && _preview is not null;
    }
    private char[] ReadPassword()
    {
        using var secret = RecoveryPassword.SecurePassword;
        RecoveryPassword.Clear();
        var chars = new char[secret.Length];
        var pointer = Marshal.SecureStringToGlobalAllocUnicode(secret);
        try { for (var i = 0; i < chars.Length; i++) chars[i] = (char)Marshal.ReadInt16(pointer, i * 2); }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
        return chars;
    }
    private async Task RunAsync(Func<Task<BackupRecoveryResult>> operation)
    {
        if (_busy) return;
        _busy = true; UpdateButtons(); RecoveryStatus.Text = T("Verifying or restoring Core. Keep this window open until the operation finishes.");
        try { ShowResult(await operation()); }
        catch (Exception) { RecoveryStatus.Text = T("Recovery could not be completed. Refresh recovery status before trying another operation."); }
        finally { RecoveryPassword.Clear(); _busy = false; UpdateButtons(); }
    }
    private Task ReadStatusAsync() => RunAsync(() => _recovery.StatusAsync(_lifetime.Token));
    private async void OnRefreshStatus(object sender, RoutedEventArgs e) => await ReadStatusAsync();
    private async void OnPreview(object sender, RoutedEventArgs e)
    {
        if (_archive is null || _key is null) return;
        var password = ReadPassword();
        try { await RunAsync(() => _recovery.PreviewAsync(_archive, _key, password, Mode, _lifetime.Token)); }
        finally { Array.Clear(password); }
    }
    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if (_preview is not { } preview || _archive is null || _key is null) return;
        if (ConfirmationText.Text != ExpectedConfirmation) { RecoveryStatus.Text = F("Type {0} exactly to confirm this restore point.", ExpectedConfirmation); return; }
        var password = ReadPassword();
        try { await RunAsync(() => _recovery.RestoreAsync(preview, _archive, _key, password, ConfirmationText.Text, _lifetime.Token)); }
        finally { Array.Clear(password); ConfirmationText.Clear(); }
    }
    private async void OnRollback(object sender, RoutedEventArgs e)
    {
        if (_preview is not { } preview || !_pending) return;
        if (ConfirmationText.Text != (preview.Mode == BackupRecoveryContract.Migration ? BackupRecoveryContract.MigrationConfirmation : BackupRecoveryContract.RestoreConfirmation))
        { RecoveryStatus.Text = T("Review the pending restore point and enter its confirmation word before undoing it."); return; }
        await RunAsync(() => _recovery.RollbackAsync(preview, _lifetime.Token));
        ConfirmationText.Clear();
    }
    private void ShowResult(BackupRecoveryResult result)
    {
        _pending = result.Outcome == BackupRecoveryContract.Pending;
        if (result.Preview is { } preview)
        {
            _preview = preview;
            PreviewText.Text = F("Restore point: {0} UTC\nArchive: {1}\nOrganization: {2}\nAdministrator accounts: {3}; enrolled computers: {4}",
                preview.CreatedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), preview.ArchiveId, preview.OrganizationId, preview.AdministratorCount, preview.EndpointCount);
            if (_pending)
            {
                _updatingMode = true;
                try { ModeBox.SelectedIndex = preview.Mode == BackupRecoveryContract.Migration ? 1 : 0; UpdateMode(); }
                finally { _updatingMode = false; }
            }
        }
        RecoveryStatus.Text = result.Outcome switch
        {
            "ready" => T("No unfinished restore was found. Choose an archive and recovery key to verify a restore point."),
            BackupRecoveryContract.Verified => T("The archive and database were verified. Review the restore point, enter the password again and type the confirmation word."),
            BackupRecoveryContract.Committed => T("Core was restored and started successfully. Scheduled backups are disabled until reviewed. Sign in again using the restored administrator account."),
            BackupRecoveryContract.RolledBack => T("The previous Core data was restored. Review the service status before continuing."),
            BackupRecoveryContract.Pending => T("An unfinished restore requires a decision. Review its restore point and use Undo unfinished restore before beginning another recovery."),
            BackupRecoveryContract.IdentityMismatch => T("This backup belongs to a different installation. Check the selected recovery mode and restore point."),
            BackupRecoveryContract.ServiceRunning => T("Core is still running. Recovery cannot replace its active database."),
            BackupRecoveryContract.InvalidInput => T("Check the selected files, recovery password and confirmation word."),
            _ => T("Recovery was rejected or unavailable. Check the recovery key, archive and installation before trying again.")
        };
        if (result.Outcome is BackupRecoveryContract.Committed or BackupRecoveryContract.RolledBack) { _preview = null; PreviewText.Text = string.Empty; _pending = false; }
    }
}
