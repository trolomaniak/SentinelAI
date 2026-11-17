using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using SentinelAI.Desktop;
using SentinelAI.Desktop.Foundation;
using SentinelAI.Desktop.Views;

internal static partial class Program
{
    private static async Task BackupViewsAsync()
    {
        using var health = new FakeCoreClient();
        using var shell = new ShellViewModel(health, "backup-test");
        using var auth = new AuthenticationViewModel(new FakeAuthenticationClient { AllowSignIn = true }, new FakeAdministratorSetup { Created = true });
        using var license = new LicenseViewModel(new NativeLicenseClient());
        var client = new NativeBackupClient();
        var files = new NativeBackupFiles();
        using var backup = new BackupViewModel(client, files);
        var source = PresentationTraceSources.DataBindingSource;
        var level = source.Switch.Level;
        using var trace = new BindingTrace();
        source.Switch.Level = SourceLevels.Warning; source.Listeners.Add(trace);
        var window = new MainWindow(shell, auth, null, null, null, null, license, null, null, null, backups: backup);
        try
        {
            window.Show();
            await WaitForAsync(() => auth.State == AuthenticationState.SignedOut, "Backup fixture did not reach sign-in.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            auth.Username = "native-backup-admin";
            await auth.SignInAsync("Synthetic-Native-Backup!".AsMemory());
            await WaitForAsync(() => backup.State == BackupViewState.Ready, "Native Settings did not read backup status.");
            await FlushAsync();
            var settings = Descendants<SettingsView>(window).Single();
            var card = Descendants<Border>(settings).Single(item => AutomationProperties.GetAutomationId(item) == "BackupSettings");
            card.BringIntoView(); await FlushAsync();
            var password = (PasswordBox)settings.FindName("BackupRecoveryPassword");
            var confirm = (PasswordBox)settings.FindName("BackupRecoveryPasswordConfirm");
            Ensure(ReferenceEquals(card.DataContext, backup) && card.IsVisible && password.IsEnabled && confirm.IsEnabled,
                "Backup card did not bind to the real model and native password controls.");
            password.Password = "Synthetic-Native-Backup-Key!"; confirm.Password = password.Password;
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Overview);
            await FlushAsync();
            Ensure(password.Password.Length == 0 && confirm.Password.Length == 0 && backup.State == BackupViewState.None,
                "Leaving Settings retained recovery passphrases or backup state.");
            shell.CurrentPage = shell.Pages.Single(page => page.Id == PageId.Settings);
            await WaitForAsync(() => backup.State == BackupViewState.Ready, "Returning to Settings did not reload backup status.");
            await FlushAsync();
            settings = Descendants<SettingsView>(window).Single();
            card = Descendants<Border>(settings).Single(item => AutomationProperties.GetAutomationId(item) == "BackupSettings");
            password = (PasswordBox)settings.FindName("BackupRecoveryPassword"); confirm = (PasswordBox)settings.FindName("BackupRecoveryPasswordConfirm");
            files.OnSaveKey = () => Ensure(password.Password.Length == 0 && confirm.Password.Length == 0, "Native password controls retained secrets while saving a key.");
            password.Password = "Synthetic-Native-Backup-Key!"; confirm.Password = password.Password;
            BackupButton(card, "ConfigureBackupRecovery").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => backup.Status?.Policy.RecoveryKeyId is not null && backup.CanCreate, "Native recovery key setup did not save the key before Core configuration.");
            await FlushAsync();
            Ensure(files.KeySaved && client.KeyWrites == 1 && !password.IsEnabled && !confirm.IsEnabled && password.Password.Length == 0,
                "Native key setup did not complete or retained editable/visible recovery secrets.");
            var boxes = Descendants<ComboBox>(card).ToArray();
            boxes[0].SelectedItem = 12; boxes[1].SelectedItem = 3;
            await FlushAsync();
            Ensure(client.PolicyWrites == 0, "Editing native backup schedule immediately wrote settings.");
            BackupButton(card, "SaveBackupPolicy").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => client.PolicyWrites == 1 && backup.CanRefresh, "Native explicit schedule save did not reach Core.");
            Ensure(client.LastPolicy is { IntervalHours: 12, RetentionCount: 3 }, "Native schedule selection lost its values.");
            var list = Descendants<ListBox>(card).Single(item => AutomationProperties.GetAutomationId(item) == "BackupArchiveList");
            list.SelectedItem = backup.Archives.Single(); await FlushAsync();
            BackupButton(card, "ExportBackup").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => files.Exports == 1 && backup.CanRefresh, "Native encrypted backup export did not use the selected archive.");
            auth.SignOut(); await FlushAsync();
            Ensure(backup.Status is null && backup.Archives.Count == 0 && password.Password.Length == 0 && confirm.Password.Length == 0,
                "Sign-out retained backup metadata or recovery passphrases.");
            Ensure(trace.Messages.Count == 0, "Native backup bindings produced warnings/errors: " + string.Join(Environment.NewLine, trace.Messages));
        }
        finally { source.Listeners.Remove(trace); source.Switch.Level = level; if (window.IsVisible) window.Close(); }
        await BackupRecoveryViewsAsync();
    }
    private static Button BackupButton(DependencyObject root, string id) => Descendants<Button>(root).Single(button => AutomationProperties.GetAutomationId(button) == id);
    private static async Task BackupRecoveryViewsAsync()
    {
        var preview = new BackupRecoveryPreview(Guid.NewGuid(), DateTimeOffset.UtcNow, Guid.NewGuid(), Guid.NewGuid(), 1, 3, new string('a', 64), BackupRecoveryContract.SameMachine);
        var worker = new NativeRecoveryWorker(preview);
        var host = new NativeRecoveryHost();
        var window = new BackupRecoveryWindow(new BackupRecoveryCoordinator(worker, host), key => key ? @"C:\synthetic\recovery.sakey" : @"C:\synthetic\{Binding}-archive.sab");
        try
        {
            window.Show(); await WaitForAsync(() => worker.Operations.Contains("status"), "Native recovery did not inspect interrupted operations."); await FlushAsync();
            BackupButton(window, "ChooseRecoveryArchive").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            BackupButton(window, "ChooseRecoveryKey").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            var password = (PasswordBox)window.FindName("RecoveryPassword");
            password.Password = "Synthetic-Native-Recovery!";
            BackupButton(window, "PreviewRecovery").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => BackupButton(window, "RestoreCoreBackup").IsEnabled, "Native recovery did not render a verified restore point.");
            Ensure(password.Password.Length == 0 && Descendants<TextBlock>(window).Any(text => text.Text.Contains(preview.ArchiveId.ToString(), StringComparison.Ordinal)),
                "Native recovery retained the passphrase or hid the verified archive identity.");
            Ensure(Descendants<TextBlock>(window).Any(text => text.Text == "{Binding}-archive.sab"), "Native recovery interpreted the archive filename as markup.");
            var confirmation = (TextBox)window.FindName("ConfirmationText");
            confirmation.Text = "wrong";
            BackupButton(window, "RestoreCoreBackup").RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); await FlushAsync();
            Ensure(host.Stops == 0 && !worker.Operations.Contains("restore"), "Native recovery stopped Core without explicit confirmation.");
            confirmation.Text = "RESTORE"; password.Password = "Synthetic-Native-Recovery!";
            BackupButton(window, "RestoreCoreBackup").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => worker.Operations.Contains("commit"), "Native recovery did not verify and commit the healthy restored Core."); await FlushAsync();
            Ensure(host.Stops == 1 && host.Starts == 1 && password.Password.Length == 0 && confirmation.Text.Length == 0,
                "Native recovery service orchestration or secret/confirmation clearing failed.");
        }
        finally { if (window.IsVisible) window.Close(); }
        var pending = preview with { Mode = BackupRecoveryContract.Migration };
        worker = new NativeRecoveryWorker(pending) { Pending = true }; host = new NativeRecoveryHost();
        window = new BackupRecoveryWindow(new BackupRecoveryCoordinator(worker, host), _ => null);
        try
        {
            window.Show(); await WaitForAsync(() => BackupButton(window, "RollbackCoreBackup").IsEnabled, "Interrupted migration did not expose the verified rollback decision.");
            var confirmation = (TextBox)window.FindName("ConfirmationText"); confirmation.Text = "MIGRATE";
            BackupButton(window, "RollbackCoreBackup").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await WaitForAsync(() => worker.Operations.Contains("rollback"), "Native interrupted migration could not be rolled back.");
            Ensure(host.Stops == 1, "Native migration rollback did not stop the owned service first.");
        }
        finally { if (window.IsVisible) window.Close(); }
    }
    private sealed class NativeBackupClient : IBackupClient
    {
        internal int KeyWrites, PolicyWrites;
        internal BackupPolicyRequest? LastPolicy;
        private BackupStatus _status = new(Guid.NewGuid(), Guid.NewGuid(), "keyUnavailable", false, new(0, false, 24, 7, null), null, null, null, []);
        public Task<BackupRequestResult> GetBackupStatusAsync(CancellationToken token) => Task.FromResult(new BackupRequestResult(BackupRequestOutcome.Success, _status));
        public Task<BackupRequestResult> SetBackupKeyAsync(long version, ReadOnlyMemory<byte> key, CancellationToken token)
        {
            KeyWrites++;
            var id = BackupArchive.KeyId(key.Span);
            _status = _status with { Availability = "available", Policy = _status.Policy with { Version = 1, RecoveryKeyId = id }, Archives = [new(Guid.NewGuid(), DateTimeOffset.UtcNow, 1024, new string('b', 64), id, "verified", DateTimeOffset.UtcNow)] };
            return GetBackupStatusAsync(token);
        }
        public Task<BackupRequestResult> SetBackupPolicyAsync(BackupPolicyRequest value, CancellationToken token) { PolicyWrites++; LastPolicy = value; _status = _status with { Policy = new(value.ExpectedVersion + 1, value.Enabled, value.IntervalHours, value.RetentionCount, _status.Policy.RecoveryKeyId) }; return GetBackupStatusAsync(token); }
        public Task<BackupRequestResult> CreateBackupAsync(CancellationToken token) => GetBackupStatusAsync(token);
        public Task<BackupRequestResult> VerifyBackupAsync(Guid id, CancellationToken token) => GetBackupStatusAsync(token);
        public Task<BackupDownloadResult> DownloadBackupAsync(BackupArchiveSummary archive, Stream stream, CancellationToken token) => Task.FromResult(new BackupDownloadResult(BackupRequestOutcome.Success));
    }
    private sealed class NativeBackupFiles : IBackupFileService
    {
        internal bool KeySaved;
        internal int Exports;
        internal Action? OnSaveKey;
        public Task<BackupFileOutcome> SaveRecoveryKeyAsync(ReadOnlyMemory<byte> key, CancellationToken token) { OnSaveKey?.Invoke(); KeySaved = true; return Task.FromResult(BackupFileOutcome.Saved); }
        public Task<BackupFileOutcome> SaveArchiveAsync(BackupArchiveSummary archive, Func<Stream, CancellationToken, Task<BackupDownloadResult>> download, CancellationToken token) { Exports++; return Task.FromResult(BackupFileOutcome.Saved); }
    }
    private sealed class NativeRecoveryWorker(BackupRecoveryPreview preview) : IBackupRecoveryWorker
    {
        internal bool Pending;
        internal readonly List<string> Operations = [];
        public Task<BackupRecoveryResult> ExecuteAsync(BackupRecoveryRequest request, ReadOnlyMemory<char> password, CancellationToken token)
        {
            Operations.Add(request.Operation);
            return Task.FromResult(request.Operation switch
            {
                "status" => new BackupRecoveryResult(Pending ? "pending" : "ready", Pending ? preview : null, Pending ? preview.ArchiveId : null),
                "preview" => new("verified", preview), "restore" => new("restored", preview, preview.ArchiveId), "commit" => new("committed"), "rollback" => new("rolledBack"), _ => new("rejected")
            });
        }
    }
    private sealed class NativeRecoveryHost : IBackupRecoveryHost
    {
        internal int Stops, Starts;
        public Task<bool> IsRunningAsync(CancellationToken token) => Task.FromResult(true);
        public Task StopAsync(CancellationToken token) { Stops++; return Task.CompletedTask; }
        public Task<bool> StartAndCheckAsync(CancellationToken token) { Starts++; return Task.FromResult(true); }
    }
}
