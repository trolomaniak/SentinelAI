using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using SentinelAI.Backup;
using SentinelAI.Contracts.Backups;
using static SentinelAI.Localization.Localizer;

namespace SentinelAI.Desktop.Foundation;

public enum BackupViewState { None, Loading, Ready, Unavailable }
public sealed record BackupArchiveRow(BackupArchiveSummary Archive)
{
    public Guid ArchiveId => Archive.ArchiveId;
    public string Summary => F("{0} UTC · {1:N0} bytes · {2}", Archive.CreatedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), Archive.SizeBytes,
        Archive.VerificationState switch { "verified" => T("Verified"), "unknown" => T("Not verified"), "missing" => T("Archive file is missing"), _ => T("Verification failed") });
}

/// <summary>Explicit backup writes and bounded status polling; recovery secrets never become view-model properties.</summary>
public sealed class BackupViewModel(IBackupClient client, IBackupFileService files, IBackupRecoveryLauncher? recovery = null) : INotifyPropertyChanged, IDisposable
{
    private readonly object _gate = new();
    private BackupStatus? _status;
    private BackupViewState _state;
    private string _message = string.Empty;
    private bool _enabled;
    private int _interval = BackupContract.DefaultIntervalHours;
    private int _retention = BackupContract.DefaultRetentionCount;
    private bool _needsRefresh;
    private long _generation;
    private CancellationTokenSource? _pending;
    private bool _disposed;
    private BackupArchiveRow? _selected;
    private IReadOnlyList<BackupArchiveRow> _archives = [];
    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? SessionExpired;
    public BackupViewState State { get { lock (_gate) return _state; } }
    public BackupStatus? Status { get { lock (_gate) return _status; } }
    public string Message { get { lock (_gate) return _message; } }
    public bool NeedsRefresh { get { lock (_gate) return _needsRefresh; } }
    public bool CanRefresh { get { lock (_gate) return !_disposed && _pending is null; } }
    public bool CanConfigureRecovery { get { lock (_gate) return CanRefresh && !_needsRefresh && _status is { Policy.RecoveryKeyId: null, Busy: false } && _status.Availability is BackupContract.Available or BackupContract.KeyUnavailable; } }
    public bool CanSavePolicy { get { lock (_gate) return CanRefresh && !_needsRefresh && _status is { Policy.RecoveryKeyId: not null, Busy: false, Availability: BackupContract.Available } && _interval is >= 1 and <= 168 && _retention is >= 1 and <= 30; } }
    public bool CanCreate { get { lock (_gate) return CanSavePolicy; } }
    public bool CanUseSelectedArchive => CanVerifySelectedArchive;
    public bool CanVerifySelectedArchive { get { lock (_gate) return CanRefresh && !_needsRefresh && _status is { Busy: false, Availability: BackupContract.Available } && _selected is { Archive.VerificationState: not "missing" }; } }
    public bool CanExportSelectedArchive { get { lock (_gate) return CanVerifySelectedArchive && _selected is { Archive.VerificationState: "verified" }; } }
    public bool CanRecover => recovery is not null;
    public IReadOnlyList<int> IntervalChoices { get; } = Enumerable.Range(1, BackupContract.MaximumIntervalHours).ToArray();
    public IReadOnlyList<int> RetentionChoices { get; } = Enumerable.Range(1, BackupContract.MaximumRetentionCount).ToArray();
    public bool Enabled { get { lock (_gate) return _enabled; } set { lock (_gate) _enabled = value; NotifyAll(); } }
    public int IntervalHours { get { lock (_gate) return _interval; } set { lock (_gate) _interval = value; NotifyAll(); } }
    public int RetentionCount { get { lock (_gate) return _retention; } set { lock (_gate) _retention = value; NotifyAll(); } }
    public BackupArchiveRow? SelectedArchive { get { lock (_gate) return _selected; } set { lock (_gate) { if (_selected?.ArchiveId == value?.ArchiveId) return; _selected = value; } PropertyChanged?.Invoke(this, new(nameof(SelectedArchive))); PropertyChanged?.Invoke(this, new(nameof(CanUseSelectedArchive))); PropertyChanged?.Invoke(this, new(nameof(CanVerifySelectedArchive))); PropertyChanged?.Invoke(this, new(nameof(CanExportSelectedArchive))); } }
    public IReadOnlyList<BackupArchiveRow> Archives { get { lock (_gate) return _archives; } }
    public string StatusText
    {
        get
        {
            lock (_gate)
            {
                if (_status is null) return _state switch { BackupViewState.Loading => T("Reading backup status…"), BackupViewState.Unavailable => T("Backup status is unavailable. Refresh to try again."), _ => T("Backup status has not been read.") };
                if (_status.Availability != BackupContract.Available) return _status.Availability switch
                {
                    BackupContract.Unsupported => T("Protected backup storage is supported by the installed Windows Core."),
                    BackupContract.StorageUnavailable => T("Backup storage is unavailable. Repair the SentinelAI installation and refresh."),
                    BackupContract.KeyUnavailable when _status.Policy.RecoveryKeyId is not null => T("Core cannot unlock its recovery key on this computer. Use the saved recovery key file through Core recovery."),
                    BackupContract.KeyUnavailable => T("Save a recovery key before enabling backups. Keep that file and its password outside this computer."),
                    _ => T("Backup status is unavailable. Refresh to try again.")
                };
                return _status.Busy ? T("Core is creating or verifying a backup. Status is refreshed automatically.") :
                    _status.Policy.Enabled ? T("Scheduled encrypted backups are enabled.") : T("Scheduled backups are off. You can create an encrypted backup manually.");
            }
        }
    }
    public string KeyText { get { lock (_gate) return _status?.Policy.RecoveryKeyId is { } id ? F("Recovery key ID: {0}", id) : T("No recovery key is configured."); } }
    public string NextBackupText { get { lock (_gate) return F("Next scheduled backup: {0}", Date(_status?.NextDueUtc)); } }
    public string LastSuccessfulText { get { lock (_gate) return F("Last successful backup: {0}", Date(_status?.LastSuccessfulBackupUtc)); } }
    public string LastAttemptText
    {
        get
        {
            lock (_gate) return _status?.LastAttempt is not { } value ? T("No backup operation has been recorded.") :
                F("Last operation: {0}; result: {1}; started: {2}; completed: {3}", value.Kind == "verify" ? T("Verify backup") : T("Create backup"),
                    value.Outcome switch { "inProgress" => T("In progress"), "succeeded" => T("Succeeded"), "failed" => T("Failed"), "interrupted" => T("Interrupted"), _ => T("Unknown") }, Date(value.StartedUtc), Date(value.CompletedUtc));
        }
    }
    public Task RefreshAsync() => RunAsync("read", null);
    public Task SavePolicyAsync() { lock (_gate) return CanSavePolicy ? RunAsync("policy", null) : Task.CompletedTask; }
    public Task CreateAsync() { lock (_gate) return CanCreate ? RunAsync("create", null) : Task.CompletedTask; }
    public Task VerifySelectedAsync() { lock (_gate) return CanUseSelectedArchive ? RunAsync("verify", _selected!.Archive) : Task.CompletedTask; }
    public Task ExportSelectedAsync() { lock (_gate) return CanExportSelectedArchive ? RunAsync("export", _selected!.Archive) : Task.CompletedTask; }
    public void OpenRecovery() { if (recovery?.Open() != true) { lock (_gate) _message = T("Recovery could not be opened. Run the installed SentinelAI as a Windows administrator and try again."); NotifyAll(); } }
    public Task ConfigureRecoveryAsync(ReadOnlyMemory<char> password) => RunAsync("key", null, password);

    private async Task RunAsync(string operation, BackupArchiveSummary? archive, ReadOnlyMemory<char> password = default)
    {
        CancellationTokenSource pending;
        long generation;
        BackupPolicy? policy;
        bool enabled;
        int interval, retention;
        lock (_gate)
        {
            if (_disposed || _pending is not null || operation == "key" && !CanConfigureRecovery) return;
            pending = _pending = new CancellationTokenSource();
            generation = ++_generation;
            policy = _status?.Policy;
            enabled = _enabled; interval = _interval; retention = _retention;
            _state = BackupViewState.Loading; _message = string.Empty;
        }
        NotifyAll();
        BackupRequestResult? result = null;
        string message = string.Empty;
        var uncertain = false;
        try
        {
            if (operation == "key")
            {
                if (password.Length is < 12 or > 1024) message = T("Use a recovery password between 12 and 1024 characters.");
                else
                {
                    var key = RandomNumberGenerator.GetBytes(32);
                    byte[]? encrypted = null;
                    try
                    {
                        // The recovery file must exist before the only copy needed after machine loss is sent to Core.
                        encrypted = RecoveryKeyFile.Create(key, password.Span);
                        var saved = await files.SaveRecoveryKeyAsync(encrypted, pending.Token);
                        if (saved == BackupFileOutcome.Saved) result = await client.SetBackupKeyAsync(policy!.Version, key, pending.Token);
                        else message = saved == BackupFileOutcome.Cancelled ? T("Recovery key setup was cancelled. Core settings were not changed.") : T("The recovery key could not be saved. Core settings were not changed.");
                    }
                    finally { CryptographicOperations.ZeroMemory(key); if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted); }
                }
            }
            else if (operation == "export")
            {
                BackupDownloadResult? downloadResult = null;
                var saved = await files.SaveArchiveAsync(archive!, async (destination, token) => downloadResult = await client.DownloadBackupAsync(archive!, destination, token), pending.Token);
                if (downloadResult?.Outcome == BackupRequestOutcome.Unauthenticated) result = new(BackupRequestOutcome.Unauthenticated);
                else message = saved switch { BackupFileOutcome.Saved => T("The encrypted backup was exported. Keep a copy on another device or storage location."), BackupFileOutcome.Cancelled => T("Backup export was cancelled."), _ => T("The encrypted backup could not be exported. No completed file was published.") };
            }
            else
            {
                result = operation switch
                {
                    "policy" => await client.SetBackupPolicyAsync(new(policy!.Version, enabled, interval, retention), pending.Token),
                    "create" => await client.CreateBackupAsync(pending.Token),
                    "verify" => await client.VerifyBackupAsync(archive!.ArchiveId, pending.Token),
                    _ => await client.GetBackupStatusAsync(pending.Token)
                };
            }
            if (result is { Outcome: BackupRequestOutcome.Success, Status: { Busy: true } })
            {
                var deadline = DateTimeOffset.UtcNow.AddMinutes(10);
                while (result is { Outcome: BackupRequestOutcome.Success, Status: { Busy: true } } && DateTimeOffset.UtcNow < deadline)
                {
                    PublishStatus(generation, result.Status);
                    await Task.Delay(TimeSpan.FromSeconds(2), pending.Token);
                    result = await client.GetBackupStatusAsync(pending.Token);
                }
                if (result is { Status.Busy: true }) { uncertain = true; message = T("Core is still processing the backup. Refresh status before starting another operation."); }
            }
            if (result is { Outcome: not (BackupRequestOutcome.Success or BackupRequestOutcome.Conflict or BackupRequestOutcome.Unauthenticated) })
            {
                uncertain = operation is "policy" or "key" or "create" or "verify";
                message = result.Outcome == BackupRequestOutcome.UntrustedConnection ? T("The local Core connection could not be trusted.") :
                    uncertain ? T("The result could not be confirmed. Refresh backup status before another change.") : T("Backup status is unavailable. Refresh to try again.");
            }
            else if (result?.Outcome == BackupRequestOutcome.Conflict) message = T("Backup settings changed or another operation is running. Review the refreshed status before trying again.");
        }
        catch (OperationCanceledException) { }
        catch (Exception) { uncertain = operation is "policy" or "key" or "create" or "verify"; message = T("The backup operation could not be completed. Refresh status before trying again."); }
        var expired = false;
        lock (_gate)
        {
            pending.Dispose();
            if (generation != _generation || _disposed) return;
            _pending = null;
            if (result?.Outcome == BackupRequestOutcome.Unauthenticated) { ClearLocked(); expired = true; }
            else
            {
                if (result?.Status is { } value) AcceptStatusLocked(value);
                _needsRefresh = uncertain || result is { Outcome: not (BackupRequestOutcome.Success or BackupRequestOutcome.Conflict) };
                _state = _status is null ? BackupViewState.Unavailable : BackupViewState.Ready;
                _message = message;
            }
        }
        NotifyAll();
        if (expired) SessionExpired?.Invoke(this, EventArgs.Empty);
    }
    private void PublishStatus(long generation, BackupStatus status)
    {
        lock (_gate) { if (_disposed || generation != _generation) return; AcceptStatusLocked(status); }
        NotifyAll();
    }
    private void AcceptStatusLocked(BackupStatus status)
    {
        var selected = _selected?.ArchiveId;
        _status = status; _enabled = status.Policy.Enabled; _interval = status.Policy.IntervalHours; _retention = status.Policy.RetentionCount; _needsRefresh = false;
        _archives = status.Archives.Select(item => new BackupArchiveRow(item)).ToArray();
        _selected = _archives.SingleOrDefault(item => item.ArchiveId == selected);
    }
    public void Clear() { lock (_gate) { if (_disposed) return; ClearLocked(); } NotifyAll(); }
    private void ClearLocked() { _generation++; _pending?.Cancel(); _pending = null; _status = null; _selected = null; _archives = []; _state = BackupViewState.None; _message = string.Empty; _needsRefresh = false; _enabled = false; _interval = 24; _retention = 7; }
    public void Dispose() { lock (_gate) { if (_disposed) return; ClearLocked(); _disposed = true; } }
    private static string Date(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? T("Not recorded");
    private void NotifyAll() { foreach (var name in new[] { nameof(State), nameof(Status), nameof(Message), nameof(NeedsRefresh), nameof(CanRefresh), nameof(CanConfigureRecovery), nameof(CanSavePolicy), nameof(CanCreate), nameof(CanUseSelectedArchive), nameof(CanVerifySelectedArchive), nameof(CanExportSelectedArchive), nameof(Archives), nameof(SelectedArchive), nameof(Enabled), nameof(IntervalHours), nameof(RetentionCount), nameof(StatusText), nameof(KeyText), nameof(NextBackupText), nameof(LastSuccessfulText), nameof(LastAttemptText) }) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)); }
}
