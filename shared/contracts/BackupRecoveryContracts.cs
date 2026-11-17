namespace SentinelAI.Contracts.Backups;

/// <summary>Local elevated worker input only. Never used by an HTTP endpoint or retained in state.</summary>
public sealed record BackupRecoveryRequest(string Operation, string? ArchivePath = null, string? RecoveryKeyPath = null,
    string? Passphrase = null, string Mode = BackupRecoveryContract.SameMachine, Guid? ConfirmedArchiveId = null,
    string? ExpectedArchiveSha256 = null, string? Confirmation = null)
{
    public override string ToString() => nameof(BackupRecoveryRequest);
}

public sealed record BackupRecoveryPreview(Guid ArchiveId, DateTimeOffset CreatedUtc, Guid CoreInstallationId,
    Guid OrganizationId, int AdministratorCount, int EndpointCount, string ArchiveSha256, string Mode);

public sealed record BackupRecoveryResult(string Outcome, BackupRecoveryPreview? Preview = null, Guid? PendingArchiveId = null);

public static class BackupRecoveryContract
{
    public const string Command = "--restore-backup";
    public const string Preview = "preview";
    public const string Status = "status";
    public const string Restore = "restore";
    public const string Rollback = "rollback";
    public const string Commit = "commit";
    public const string SameMachine = "sameMachine";
    public const string Migration = "migration";
    public const string Verified = "verified";
    public const string Restored = "restored";
    public const string RolledBack = "rolledBack";
    public const string Committed = "committed";
    public const string Pending = "pending";
    public const string Ready = "ready";
    public const string InvalidInput = "invalidInput";
    public const string Unavailable = "unavailable";
    public const string Rejected = "rejected";
    public const string ServiceRunning = "serviceRunning";
    public const string IdentityMismatch = "identityMismatch";
    public const string RestoreConfirmation = "RESTORE";
    public const string MigrationConfirmation = "MIGRATE";
    public const int MaximumInputBytes = 32 * 1024;
    public const int MaximumOutputBytes = 8 * 1024;
}
