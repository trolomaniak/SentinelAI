namespace SentinelAI.Contracts.Backups;

/// <summary>Public backup state. No recovery material, protected key or filesystem path crosses this contract.</summary>
public sealed record BackupPolicy(long Version, bool Enabled, int IntervalHours, int RetentionCount, string? RecoveryKeyId);

public sealed record BackupAttempt(Guid OperationId, string Kind, string Outcome, DateTimeOffset StartedUtc,
    DateTimeOffset? CompletedUtc, Guid? ArchiveId);

public sealed record BackupArchiveSummary(Guid ArchiveId, DateTimeOffset CreatedUtc, long SizeBytes, string Sha256,
    string RecoveryKeyId, string VerificationState, DateTimeOffset? VerifiedUtc);

public sealed record BackupStatus(Guid CoreInstallationId, Guid OrganizationId, string Availability, bool Busy,
    BackupPolicy Policy, DateTimeOffset? NextDueUtc, DateTimeOffset? LastSuccessfulBackupUtc,
    BackupAttempt? LastAttempt, IReadOnlyList<BackupArchiveSummary> Archives);

public sealed record BackupPolicyRequest(long ExpectedVersion, bool Enabled, int IntervalHours, int RetentionCount);

public static class BackupContract
{
    public const int DefaultIntervalHours = 24;
    public const int DefaultRetentionCount = 7;
    public const int MaximumRetentionCount = 30;
    public const int MaximumIntervalHours = 168;
    public const int MaximumStatusBytes = 64 * 1024;
    public const string Available = "available";
    public const string Unsupported = "unsupported";
    public const string StorageUnavailable = "storageUnavailable";
    public const string KeyUnavailable = "keyUnavailable";
}
