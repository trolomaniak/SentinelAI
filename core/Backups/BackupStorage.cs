using System.Text.RegularExpressions;
using SentinelAI.Backup;

namespace SentinelAI.Core.Backups;

internal sealed class BackupStorage(string dataDirectory, bool managedService)
{
    internal string DirectoryPath { get; } = Path.Combine(Path.GetFullPath(dataDirectory), "backups");
    private static readonly Regex ArchiveName = new("\\A[0-9a-f]{32}\\.sab\\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex WorkName = new("\\Awork-[0-9a-f]{32}\\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex IdentityTemporary = new("\\Abackup-identity\\.json\\.[0-9a-f]{32}\\.tmp\\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly HashSet<string> WorkFiles = new(StringComparer.Ordinal)
    {
        "snapshot.db", "snapshot.db-journal", "snapshot.db-wal", "snapshot.db-shm", "core.db", "core.db-journal", "core.db-wal", "core.db-shm",
        "payload.tmp", "archive.tmp", "verify.tmp", "configuration.json", "manifest.json"
    };
    internal void EnsureAvailable()
    {
        AssertDirectory(Path.GetDirectoryName(DirectoryPath)!);
        if (!Directory.Exists(DirectoryPath))
        {
            if (managedService) throw new IOException("Backup storage requires installation repair.");
            CreatePrivateDirectory(DirectoryPath);
        }
        AssertDirectory(DirectoryPath);
        var archives = 0; var works = 0; var total = 0;
        foreach (var entry in new DirectoryInfo(DirectoryPath).EnumerateFileSystemInfos())
        {
            if (++total > 64) throw new IOException("Backup storage is unavailable.");
            if (entry is DirectoryInfo)
            {
                if (!WorkName.IsMatch(entry.Name) || ++works > 4) throw new IOException("Backup storage is unavailable.");
                ValidateWork(entry.FullName);
            }
            else
            {
                if (ArchiveName.IsMatch(entry.Name))
                {
                    if (++archives > 31) throw new IOException("Backup storage is unavailable.");
                    AssertFile(entry.FullName, BackupArchive.MaximumArchiveBytes);
                }
                else if (entry.Name is "backup-identity.json" or "restore-journal.json" or "restore-old.db" or "restore-old.db-wal" or "restore-old.db-shm" or "restore-old.db-journal" or "restore.lock" || IdentityTemporary.IsMatch(entry.Name) || Regex.IsMatch(entry.Name, @"\Arestore-journal\.json\.[0-9a-f]{32}\.tmp\z", RegexOptions.CultureInvariant))
                    AssertFile(entry.FullName, entry.Name.StartsWith("restore-old.db", StringComparison.Ordinal) ? BackupArchive.MaximumPayloadBytes : 64 * 1024);
                else throw new IOException("Backup storage is unavailable.");
            }
        }
    }
    internal string ArchivePath(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("A backup identifier is required.");
        return Path.Combine(DirectoryPath, id.ToString("N") + ".sab");
    }
    internal string CreateWorkDirectory(Guid? operationId = null)
    {
        EnsureAvailable();
        var path = Path.Combine(DirectoryPath, "work-" + (operationId ?? Guid.NewGuid()).ToString("N"));
        CreatePrivateDirectory(path);
        return path;
    }
    internal void DeleteWork(string path)
    {
        if (!Directory.Exists(path)) return;
        if (!string.Equals(Path.GetDirectoryName(path), DirectoryPath, StringComparison.OrdinalIgnoreCase) ||
            !WorkName.IsMatch(Path.GetFileName(path))) throw new IOException("Backup storage is unavailable.");
        ValidateWork(path);
        Directory.Delete(path, recursive: true);
    }
    private static void ValidateWork(string path)
    {
        AssertDirectory(path);
        var count = 0;
        foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos())
        {
            if (++count > 18) throw new IOException("Backup storage is unavailable.");
            if (entry is DirectoryInfo)
            {
                if (entry.Name != "extracted") throw new IOException("Backup storage is unavailable.");
                AssertDirectory(entry.FullName);
                var children = new DirectoryInfo(entry.FullName).EnumerateFileSystemInfos().ToArray();
                if (children.Length > 6) throw new IOException("Backup storage is unavailable.");
                foreach (var child in children)
                {
                    if (child is DirectoryInfo || child.Name is not ("core.db" or "configuration.json" or "core.db-journal" or "core.db-wal" or "core.db-shm"))
                        throw new IOException("Backup storage is unavailable.");
                    AssertFile(child.FullName, BackupArchive.MaximumPayloadBytes);
                }
            }
            else
            {
                if (!WorkFiles.Contains(entry.Name)) throw new IOException("Backup storage is unavailable.");
                AssertFile(entry.FullName, BackupArchive.MaximumArchiveBytes);
            }
        }
    }
    internal static void CreatePrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        AssertDirectory(path);
    }
    internal static FileStream CreateFile(string path)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }
    internal static void AssertDirectory(string path)
    {
        var current = new DirectoryInfo(Path.GetFullPath(path));
        for (; current is not null; current = current.Parent)
            if (!current.Exists || current.LinkTarget is not null || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Backup storage is unavailable.");
    }
    internal static void AssertFile(string path, long maximumBytes)
    {
        AssertDirectory(Path.GetDirectoryName(path)!);
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
            file.Length > maximumBytes || file.Length < 0) throw new IOException("Backup storage is unavailable.");
    }
}
