using System.IO.Compression;
using System.Security.Cryptography;

namespace SentinelAI.Setup.Foundation;

/// <summary>Validates the complete embedded archive before writing any extracted file.</summary>
public static class SetupPayload
{
    public const long MaximumCompressedBytes = 512L * 1024 * 1024;
    public const long MaximumExpandedBytes = 1024L * 1024 * 1024;
    public const int MaximumEntries = 4096;
    public const long MaximumFileBytes = 512L * 1024 * 1024;

    public static async Task VerifyAsync(Stream payload, SetupMetadata metadata, CancellationToken token)
    {
        if (!payload.CanSeek || payload.Length != metadata.PayloadLength || payload.Length is <= 0 or > MaximumCompressedBytes)
            throw new InvalidDataException("Invalid setup payload size.");
        payload.Position = 0;
        var hash = await SHA256.HashDataAsync(payload, token).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(metadata.PayloadSha256))) throw new InvalidDataException("Invalid setup payload hash.");
        payload.Position = 0;
        using var zip = new ZipArchive(payload, ZipArchiveMode.Read, leaveOpen: true);
        _ = ValidateEntries(zip);
        payload.Position = 0;
    }

    public static async Task ExtractAsync(Stream payload, string protectedEmptyDirectory, CancellationToken token)
    {
        var root = Path.GetFullPath(protectedEmptyDirectory);
        if (!Directory.Exists(root) || Directory.EnumerateFileSystemEntries(root).Any()) throw new InvalidDataException("Setup destination must be fresh.");
        payload.Position = 0;
        using var zip = new ZipArchive(payload, ZipArchiveMode.Read, leaveOpen: true);
        var entries = ValidateEntries(zip);
        var buffer = new byte[64 * 1024];
        try
        {
            foreach (var entry in entries)
            {
                token.ThrowIfCancellationRequested();
                var destination = Path.GetFullPath(Path.Combine(root, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
                if (!destination.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Invalid setup path.");
                var directory = entry.FullName.EndsWith('/');
                Directory.CreateDirectory(directory ? destination : Path.GetDirectoryName(destination)!);
                if (directory) continue;
                using var source = entry.Open();
                using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, buffer.Length, FileOptions.Asynchronous);
                long written = 0;
                while (true)
                {
                    var count = await source.ReadAsync(buffer, token).ConfigureAwait(false);
                    if (count == 0) break;
                    written = checked(written + count);
                    if (written > entry.Length) throw new InvalidDataException("Invalid expanded setup size.");
                    await target.WriteAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
                }
                if (written != entry.Length) throw new InvalidDataException("Incomplete setup file.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static ZipArchiveEntry[] ValidateEntries(ZipArchive archive)
    {
        if (archive.Entries.Count is <= 0 or > MaximumEntries) throw new InvalidDataException("Invalid setup entry count.");
        var paths = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        foreach (var entry in archive.Entries)
        {
            var path = entry.FullName; var directory = path.EndsWith('/');
            var segments = (directory ? path[..^1] : path).Split('/');
            if (path.Length is <= 0 or > 240 || path.Contains('\\') || segments.Length < 2 ||
                segments[0] is not ("bundle" or "desktop" or "setup") ||
                segments.Any(part => !ValidSegment(part)) || !paths.TryAdd(path.TrimEnd('/'), directory) ||
                (entry.ExternalAttributes & 0x400) != 0 || // Windows reparse attribute
                ((entry.ExternalAttributes >> 16) & 0xf000) is not (0 or 0x8000 or 0x4000) ||
                directory && entry.Length != 0 || entry.Length < 0 || entry.Length > MaximumFileBytes)
                throw new InvalidDataException("Unsafe setup archive entry.");
            expanded = checked(expanded + entry.Length);
            if (expanded > MaximumExpandedBytes) throw new InvalidDataException("Setup archive is too large.");
        }
        foreach (var path in paths.Keys)
        {
            var parent = path;
            while (parent.Contains('/'))
            {
                parent = parent[..parent.LastIndexOf('/')];
                if (paths.TryGetValue(parent, out var directory) && !directory) throw new InvalidDataException("Ambiguous setup archive path.");
            }
        }
        foreach (var required in new[] { "setup/SetupWorker.ps1", "desktop/SentinelAI.Desktop.exe", "bundle/installer/Install-SentinelAIPilot.ps1" })
            if (!paths.TryGetValue(required, out var directory) || directory) throw new InvalidDataException("Incomplete setup archive.");
        return archive.Entries.ToArray();
    }

    private static bool ValidSegment(string value)
    {
        if (value.Length == 0 || value is "." or ".." || value.EndsWith('.') || value.EndsWith(' ') ||
            value.Any(character => char.IsControl(character) || character is ':' or '<' or '>' or '"' or '|' or '?' or '*')) return false;
        var stem = value.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return stem is not ("CON" or "PRN" or "AUX" or "NUL") &&
            !(stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³'));
    }
}
