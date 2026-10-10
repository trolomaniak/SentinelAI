using System.IO.Compression;

namespace SentinelAI.Updates;

public static class PackageExtractor
{
    public const int MaximumEntries = 1024;
    public const long MaximumExpandedBytes = 512L * 1024 * 1024;
    public const string DeploymentArtifactId = "sentinelai-deployment-win-x64";
    public const int MaximumDeploymentEntries = 4096;
    public const long MaximumDeploymentExpandedBytes = 1024L * 1024 * 1024;
    internal static readonly string[] DeploymentExecutables =
    [
        "Core/SentinelAI.Core.exe", "Agent/SentinelAI.Agent.exe",
        "Desktop/SentinelAI.Desktop.exe", "Updater/SentinelAI.Updater.exe"
    ];
    internal static readonly string[] DeploymentDirectories = ["Core", "Agent", "Desktop", "Updater"];

    // The caller supplies a private, already hash-verified copy, never the original download path.
    public static async Task ExtractAsync(string verifiedPackagePath, string newDestinationDirectory,
        string expectedExecutable, CancellationToken cancellationToken = default)
    {
        if (expectedExecutable is not ("SentinelAI.Agent.exe" or "SentinelAI.Core.exe"))
            throw new ArgumentException("An explicit supported SentinelAI executable is required.", nameof(expectedExecutable));
        await ExtractCoreAsync(verifiedPackagePath, newDestinationDirectory, [expectedExecutable],
            MaximumEntries, MaximumExpandedBytes, deployment: false, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Extracts one signed deployment containing all four code components and no persistent data.</summary>
    public static Task ExtractDeploymentAsync(string verifiedPackagePath, string newDestinationDirectory,
        CancellationToken cancellationToken = default) => ExtractCoreAsync(verifiedPackagePath, newDestinationDirectory,
            DeploymentExecutables, MaximumDeploymentEntries, MaximumDeploymentExpandedBytes, deployment: true, cancellationToken);

    private static async Task ExtractCoreAsync(string verifiedPackagePath, string newDestinationDirectory,
        string[] expectedExecutables, int maximumEntries, long maximumExpandedBytes, bool deployment, CancellationToken cancellationToken)
    {
        UpdateFileSystem.RejectReparseAncestors(verifiedPackagePath);
        UpdateFileSystem.CreatePrivateDirectory(newDestinationDirectory);
        try
        {
            using var file = new FileStream(verifiedPackagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(file, ZipArchiveMode.Read, leaveOpen: false);
            if (archive.Entries.Count == 0 || archive.Entries.Count > maximumEntries) throw new InvalidDataException("The package entry count is invalid.");
            var paths = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var deploymentPaths = deployment ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : null;
            long declaredTotal = 0;
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (relativePath, directory) = ValidateEntry(entry);
                if (!paths.TryAdd(relativePath, directory)) throw new InvalidDataException("The package contains colliding paths.");
                if (deployment)
                {
                    ValidateDeploymentEntry(relativePath, directory);
                    var path = relativePath;
                    while (true)
                    {
                        deploymentPaths!.Add(path);
                        if (deploymentPaths.Count > maximumEntries) throw new InvalidDataException("The deployment path count exceeds its limit.");
                        var slash = path.LastIndexOf('/');
                        if (slash < 0) break;
                        path = path[..slash];
                    }
                }
                if (entry.Length < 0 || entry.Length > maximumExpandedBytes || declaredTotal > maximumExpandedBytes - entry.Length)
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
            foreach (var expectedExecutable in expectedExecutables)
            {
                var executable = archive.Entries.SingleOrDefault(e => e.FullName.Equals(expectedExecutable, StringComparison.Ordinal));
                if (!paths.TryGetValue(expectedExecutable, out var executableIsDirectory) || executableIsDirectory ||
                    executable is null || executable.Length == 0)
                    throw new InvalidDataException("The package does not contain its expected executable.");
            }
            if (deployment)
            {
                var marker = archive.Entries.SingleOrDefault(entry => entry.FullName == DeploymentPackageVersion.FileName);
                if (marker is null || marker.Length is < 1 or > DeploymentPackageVersion.MaximumDocumentBytes)
                    throw new InvalidDataException("The package does not contain its bounded deployment version metadata.");
                using var source = marker.Open();
                var bytes = new byte[checked((int)marker.Length)];
                await source.ReadExactlyAsync(bytes, cancellationToken);
                if (source.ReadByte() != -1) throw new InvalidDataException("Invalid deployment version metadata.");
                _ = DeploymentPackageVersion.Read(bytes);
            }
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
                    if (actualEntry > entry.Length - read || actualTotal > maximumExpandedBytes - read)
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

    private static void ValidateDeploymentEntry(string path, bool directory)
    {
        if (path == DeploymentPackageVersion.FileName && !directory) return;
        var slash = path.IndexOf('/');
        var root = slash < 0 ? path : path[..slash];
        if (!DeploymentDirectories.Contains(root, StringComparer.Ordinal) || slash < 0 && !directory)
            throw new InvalidDataException("The deployment package contains an unsupported component.");
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
