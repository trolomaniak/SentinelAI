namespace SentinelAI.Updates;

internal static class UpdateFileSystem
{
    internal static string ValidateInstallationPath(string path, bool mustExist = true)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("The installation directory must be an absolute code-only directory.", nameof(path));
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (Path.GetDirectoryName(full) is not { Length: > 0 } || Path.GetPathRoot(full) == full)
            throw new ArgumentException("A filesystem root cannot be an installation directory.", nameof(path));
        ValidateComponent(Path.GetFileName(full));
        RejectReparseAncestors(full);
        var parent = Path.GetDirectoryName(full)!;
        if (!OperatingSystem.IsWindows() && Directory.Exists(parent) &&
            (File.GetUnixFileMode(parent) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new IOException("The installation parent must not be writable by other users.");
        if (mustExist && !Directory.Exists(full)) throw new DirectoryNotFoundException("The installation directory does not exist.");
        return full;
    }

    internal static void RejectReparseAncestors(string path)
    {
        for (var current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                // File.Exists deliberately returns false for some broken links.
                if (new FileInfo(current).LinkTarget is not null || new DirectoryInfo(current).LinkTarget is not null)
                    throw new IOException("Update paths cannot contain symbolic links.");
                continue;
            }
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Update paths cannot contain links or reparse points.");
        }
    }

    internal static void ValidateTree(string directory)
    {
        RejectReparseAncestors(directory);
        var pending = new Stack<string>();
        pending.Push(directory);
        var count = 0;
        while (pending.TryPop(out var current))
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                if (++count > 4096) throw new IOException("The installation code directory contains too many entries.");
                RejectPersistentStateFile(Path.GetFileName(entry));
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("The installation code directory cannot contain links or reparse points.");
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
            }
        }
    }

    internal static void CreatePrivateDirectory(string path)
    {
        RejectReparseAncestors(path);
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("An update staging path already exists.");
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    internal static FileStream CreatePrivateFile(string path)
    {
        RejectReparseAncestors(path);
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.WriteThrough
        };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }

    internal static void DeleteOwnedDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return;
        ValidateTree(directory);
        Directory.Delete(directory, recursive: true);
    }

    internal static void ValidateComponent(string component)
    {
        if (component.Length is < 1 or > 120 || component is "." or ".." || component[^1] is '.' or ' ' ||
            component.Any(c => c < 32 || c > 126 || c is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*'))
            throw new InvalidDataException("The update path contains an unsupported filename.");
        var stem = component.Split('.')[0].TrimEnd(' ');
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("CLOCK$", StringComparison.OrdinalIgnoreCase) || stem.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase) ||
            (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && stem[3] is >= '1' and <= '9'))
            throw new InvalidDataException("Windows device names cannot be update paths.");
    }

    internal static void RejectPersistentStateFile(string component)
    {
        if (component.Equals("sentinelai.db", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("sentinelai.db-wal", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("sentinelai.db-shm", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("enrollment-state", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("installation-id", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("endpoint-id", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("pilot-enrollment-token", StringComparison.OrdinalIgnoreCase) ||
            component.Equals("pilot-config.json", StringComparison.OrdinalIgnoreCase) ||
            component.StartsWith(".enrollment-state.", StringComparison.OrdinalIgnoreCase) ||
            component.StartsWith(".installation-id.", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Persistent SentinelAI state must be outside the update code directory.");
    }
}
