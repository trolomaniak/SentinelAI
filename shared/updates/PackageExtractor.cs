using System.IO.Compression;

namespace SentinelAI.Updates;

public static class PackageExtractor
{
    public const int MaximumEntries = 1024;
    public const long MaximumExpandedBytes = 512L * 1024 * 1024;

    // The caller supplies a private, already hash-verified copy, never the original download path.
    public static async Task ExtractAsync(string verifiedPackagePath, string newDestinationDirectory,
        string expectedExecutable, CancellationToken cancellationToken = default)
    {
        if (expectedExecutable is not ("SentinelAI.Agent.exe" or "SentinelAI.Core.exe"))
            throw new ArgumentException("An explicit supported SentinelAI executable is required.", nameof(expectedExecutable));
        UpdateFileSystem.RejectReparseAncestors(verifiedPackagePath);
        UpdateFileSystem.CreatePrivateDirectory(newDestinationDirectory);
        try
        {
            using var file = new FileStream(verifiedPackagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(file, ZipArchiveMode.Read, leaveOpen: false);
            if (archive.Entries.Count is 0 or > MaximumEntries) throw new InvalidDataException("The package entry count is invalid.");
            var paths = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            long declaredTotal = 0;
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (relativePath, directory) = ValidateEntry(entry);
                if (!paths.TryAdd(relativePath, directory)) throw new InvalidDataException("The package contains colliding paths.");
                if (entry.Length < 0 || entry.Length > MaximumExpandedBytes || declaredTotal > MaximumExpandedBytes - entry.Length)
                    throw new InvalidDataException("The expanded package exceeds its byte limit.");
                declaredTotal += entry.Length;
            }
            foreach (var (path, _) in paths)
            {
                for (var slash = path.LastIndexOf('/'); slash >= 0; slash = path.LastIndexOf('/', slash - 1))
                {
                    if (paths.TryGetValue(path[..slash], out var isDirectory) && !isDirectory)
                        throw new InvalidDataException("A package file is also used as a directory.");
                    if (slash == 0) break;
                }
            }
            var executable = archive.Entries.SingleOrDefault(e => e.FullName.Equals(expectedExecutable, StringComparison.Ordinal));
            if (!paths.TryGetValue(expectedExecutable, out var executableIsDirectory) || executableIsDirectory ||
                executable is null || executable.Length == 0)
                throw new InvalidDataException("The package does not contain its expected executable.");
            long actualTotal = 0;
            var buffer = new byte[64 * 1024];
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (relativePath, directory) = ValidateEntry(entry);
                var destination = Path.Combine(newDestinationDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar));
                UpdateFileSystem.RejectReparseAncestors(destination);
                if (directory) { Directory.CreateDirectory(destination); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                await using var output = UpdateFileSystem.CreatePrivateFile(destination);
                using var input = entry.Open();
                long actualEntry = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken)) != 0)
                {
                    if (actualEntry > entry.Length - read || actualTotal > MaximumExpandedBytes - read)
                        throw new InvalidDataException("The expanded package exceeds its declared length or byte limit.");
                    actualEntry += read;
                    actualTotal += read;
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
                if (actualEntry != entry.Length) throw new InvalidDataException("The package entry length is inconsistent.");
                await output.FlushAsync(cancellationToken);
                output.Flush(flushToDisk: true);
            }
        }
        catch
        {
            UpdateFileSystem.DeleteOwnedDirectory(newDestinationDirectory);
            throw;
        }
    }

    private static (string Path, bool Directory) ValidateEntry(ZipArchiveEntry entry)
    {
        var name = entry.FullName;
        if (name.Length is < 1 or > 240 || name[0] == '/' || name.Contains('\\') || name.Contains(':'))
            throw new InvalidDataException("The package contains an unsafe path.");
        var directory = name.EndsWith('/');
        var path = directory ? name[..^1] : name;
        foreach (var component in path.Split('/'))
        {
            UpdateFileSystem.ValidateComponent(component);
            UpdateFileSystem.RejectPersistentStateFile(component);
        }
        var unixKind = (entry.ExternalAttributes >> 16) & 0xF000;
        if ((unixKind != 0 && unixKind != (directory ? 0x4000 : 0x8000)) ||
            (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 || (directory && entry.Length != 0))
            throw new InvalidDataException("The package cannot contain links, special files or nonempty directory entries.");
        return (path, directory);
    }
}
