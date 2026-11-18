using SentinelAI.Contracts.Backups;

namespace SentinelAI.Desktop.Foundation;

public interface IBackupRecoveryWorker
{
    Task<BackupRecoveryResult> ExecuteAsync(BackupRecoveryRequest request, ReadOnlyMemory<char> password, CancellationToken cancellationToken);
}
public interface IBackupRecoveryHost
{
    Task<bool> IsRunningAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    Task<bool> StartAndCheckAsync(CancellationToken cancellationToken);
}

/// <summary>Restore is committed only after the owned service is healthy and the worker checks its restored identity.</summary>
public sealed class BackupRecoveryCoordinator(IBackupRecoveryWorker worker, IBackupRecoveryHost host)
{
    private readonly SemaphoreSlim _single = new(1, 1);
    public Task<BackupRecoveryResult> StatusAsync(CancellationToken token) => worker.ExecuteAsync(new("status"), default, token);
    public Task<BackupRecoveryResult> PreviewAsync(string archive, string key, ReadOnlyMemory<char> password, string mode, CancellationToken token) =>
        worker.ExecuteAsync(new(BackupRecoveryContract.Preview, archive, key, Mode: mode), password, token);

    public async Task<BackupRecoveryResult> RestoreAsync(BackupRecoveryPreview preview, string archive, string key,
        ReadOnlyMemory<char> password, string confirmation, CancellationToken token)
    {
        if (password.Length is < 12 or > 1024) return new(BackupRecoveryContract.InvalidInput);
        if (confirmation != (preview.Mode == BackupRecoveryContract.Migration ? BackupRecoveryContract.MigrationConfirmation : BackupRecoveryContract.RestoreConfirmation))
            return new(BackupRecoveryContract.InvalidInput);
        if (!await _single.WaitAsync(0, token)) return new(BackupRecoveryContract.Pending);
        var originallyRunning = false;
        var stopped = false;
        var mayHaveChanged = false;
        try
        {
            // Revalidate the re-entered password and the exact reviewed archive before interrupting monitoring.
            var verified = await worker.ExecuteAsync(new(BackupRecoveryContract.Preview, archive, key, Mode: preview.Mode), password, token);
            if (verified.Outcome != BackupRecoveryContract.Verified) return verified;
            if (verified.Preview is not { } current || current.ArchiveId != preview.ArchiveId || current.ArchiveSha256 != preview.ArchiveSha256 ||
                current.CoreInstallationId != preview.CoreInstallationId || current.OrganizationId != preview.OrganizationId || current.Mode != preview.Mode)
                return new(BackupRecoveryContract.Rejected);
            originallyRunning = await host.IsRunningAsync(token);
            stopped = true;
            await host.StopAsync(token);
            // Once mutation may begin, recovery cleanup is independent of a cancelled UI request.
            mayHaveChanged = true;
            var restored = await worker.ExecuteAsync(new(BackupRecoveryContract.Restore, archive, key, Mode: preview.Mode,
                ConfirmedArchiveId: preview.ArchiveId, ExpectedArchiveSha256: preview.ArchiveSha256, Confirmation: confirmation), password, token);
            if (restored.Outcome != BackupRecoveryContract.Restored)
            {
                var state = await worker.ExecuteAsync(new("status"), default, CancellationToken.None);
                if (TerminalFor(state, preview, BackupRecoveryContract.Committed)) return state;
                if (state.PendingArchiveId == preview.ArchiveId) return await RollbackAfterFailureAsync(preview, originallyRunning);
                if (state.PendingArchiveId is not null) return state;
                if (state.Outcome is not ("ready" or BackupRecoveryContract.RolledBack)) return new(BackupRecoveryContract.Pending, preview, preview.ArchiveId);
                mayHaveChanged = false;
                if (originallyRunning) await host.StartAndCheckAsync(CancellationToken.None);
                return restored;
            }
            if (await host.StartAndCheckAsync(token))
            {
                var committed = await worker.ExecuteAsync(new(BackupRecoveryContract.Commit, Mode: preview.Mode,
                    ConfirmedArchiveId: preview.ArchiveId, Confirmation: confirmation), default, token);
                if (committed.Outcome == BackupRecoveryContract.Committed) return committed with { Preview = preview };
                var state = await worker.ExecuteAsync(new("status"), default, CancellationToken.None);
                if (TerminalFor(state, preview, BackupRecoveryContract.Committed)) return state;
                if (state.PendingArchiveId is null) return new(BackupRecoveryContract.Unavailable);
                if (state.PendingArchiveId != preview.ArchiveId) return state;
            }
            return await RollbackAfterFailureAsync(preview, originallyRunning);
        }
        catch (Exception)
        {
            if (stopped && mayHaveChanged)
            {
                try
                {
                    var state = await worker.ExecuteAsync(new("status"), default, CancellationToken.None);
                    if (TerminalFor(state, preview, BackupRecoveryContract.Committed)) return state;
                    if (state.PendingArchiveId == preview.ArchiveId) return await RollbackAfterFailureAsync(preview, originallyRunning);
                    if (state.PendingArchiveId is not null) return state;
                    if (state.Outcome is not ("ready" or BackupRecoveryContract.RolledBack)) return new(BackupRecoveryContract.Pending, preview, preview.ArchiveId);
                }
                catch { return new(BackupRecoveryContract.Pending, PendingArchiveId: preview.ArchiveId); }
            }
            if (stopped && originallyRunning) try { await host.StartAndCheckAsync(CancellationToken.None); } catch { }
            return new(BackupRecoveryContract.Unavailable);
        }
        finally { _single.Release(); }
    }

    public async Task<BackupRecoveryResult> RollbackAsync(BackupRecoveryPreview preview, CancellationToken token)
    {
        if (!await _single.WaitAsync(0, token)) return new(BackupRecoveryContract.Pending);
        try { return await RollbackAfterFailureAsync(preview, restart: true); }
        catch { return new(BackupRecoveryContract.Pending, PendingArchiveId: preview.ArchiveId); }
        finally { _single.Release(); }
    }
    private static bool TerminalFor(BackupRecoveryResult state, BackupRecoveryPreview preview, string outcome) =>
        state.Outcome == outcome && state.Preview?.ArchiveId == preview.ArchiveId;
    private async Task<BackupRecoveryResult> RollbackAfterFailureAsync(BackupRecoveryPreview preview, bool restart)
    {
        await host.StopAsync(CancellationToken.None);
        var rolledBack = await worker.ExecuteAsync(new(BackupRecoveryContract.Rollback, Mode: preview.Mode,
            ConfirmedArchiveId: preview.ArchiveId, Confirmation: preview.Mode == BackupRecoveryContract.Migration ? BackupRecoveryContract.MigrationConfirmation : BackupRecoveryContract.RestoreConfirmation), default, CancellationToken.None);
        if (rolledBack.Outcome != BackupRecoveryContract.RolledBack)
        {
            var state = await worker.ExecuteAsync(new("status"), default, CancellationToken.None);
            if (TerminalFor(state, preview, BackupRecoveryContract.Committed))
            {
                if (!await host.StartAndCheckAsync(CancellationToken.None)) return new(BackupRecoveryContract.Unavailable);
                return state;
            }
            if (!TerminalFor(state, preview, BackupRecoveryContract.RolledBack)) return state.PendingArchiveId is not null ? state : new(BackupRecoveryContract.Pending, preview, preview.ArchiveId);
            rolledBack = state;
        }
        if (restart && !await host.StartAndCheckAsync(CancellationToken.None)) return new(BackupRecoveryContract.Unavailable);
        return rolledBack;
    }
}
