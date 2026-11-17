using SentinelAI.Contracts.Backups;

namespace SentinelAI.Desktop.Foundation;

public enum BackupRequestOutcome { Success, Unauthenticated, Unavailable, UntrustedConnection, InvalidResponse, Conflict, NotFound, TooLarge }
public sealed record BackupRequestResult(BackupRequestOutcome Outcome, BackupStatus? Status = null);
public sealed record BackupDownloadResult(BackupRequestOutcome Outcome);

public interface IBackupClient
{
    Task<BackupRequestResult> GetBackupStatusAsync(CancellationToken cancellationToken);
    Task<BackupRequestResult> SetBackupPolicyAsync(BackupPolicyRequest policy, CancellationToken cancellationToken);
    Task<BackupRequestResult> SetBackupKeyAsync(long expectedVersion, ReadOnlyMemory<byte> key, CancellationToken cancellationToken);
    Task<BackupRequestResult> CreateBackupAsync(CancellationToken cancellationToken);
    Task<BackupRequestResult> VerifyBackupAsync(Guid archiveId, CancellationToken cancellationToken);
    /// <summary>Writes provisional ciphertext; the caller must publish its destination only after Success.</summary>
    Task<BackupDownloadResult> DownloadBackupAsync(BackupArchiveSummary archive, Stream destination, CancellationToken cancellationToken);
}

public enum BackupFileOutcome { Saved, Cancelled, Failed }
public interface IBackupFileService
{
    Task<BackupFileOutcome> SaveRecoveryKeyAsync(ReadOnlyMemory<byte> encryptedKey, CancellationToken cancellationToken);
    Task<BackupFileOutcome> SaveArchiveAsync(BackupArchiveSummary archive,
        Func<Stream, CancellationToken, Task<BackupDownloadResult>> download, CancellationToken cancellationToken);
}

public interface IBackupRecoveryLauncher { bool Open(); }
