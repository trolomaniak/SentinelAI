using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace SentinelAI.Backup;

public sealed record BackupManifest(int SchemaVersion, Guid ArchiveId, DateTimeOffset CreatedUtc,
    Guid CoreInstallationId, Guid OrganizationId, string ProductVersion, string RecoveryKeyId,
    long DatabaseBytes, string DatabaseSha256, string ConfigurationSha256);

/// <summary>
/// The authenticated archive's plaintext container. Exactly three entries are permitted;
/// archive names never select destination paths. Configuration is reference data, not a
/// command or a replacement for locally trusted installation/ownership documents.
/// </summary>
public static class BackupPackage
{
    public const int MaximumManifestBytes = 16 * 1024;
    public const int MaximumConfigurationBytes = 64 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly DateTimeOffset ZipTime = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] Fields = ["schemaVersion", "archiveId", "createdUtc", "coreInstallationId",
        "organizationId", "productVersion", "recoveryKeyId", "databaseBytes", "databaseSha256", "configurationSha256"];

    public static async Task CreateAsync(Stream output, string databasePath, BackupManifest manifest,
        ReadOnlyMemory<byte> configurationJson, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(manifest);
        if (!output.CanWrite || output.CanSeek && (output.Position != 0 || output.Length != 0))
            throw new ArgumentException("A new writable package stream is required.");
        ValidateManifest(manifest);
        ValidateConfiguration(configurationJson);
        if (Hash(configurationJson.Span) != manifest.ConfigurationSha256) throw Invalid();
        var file = new FileInfo(databasePath);
        if (!file.Exists || file.LinkTarget is not null || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw Invalid();
        await using var database = new FileStream(databasePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (database.Length != manifest.DatabaseBytes) throw Invalid();
        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
        if (manifestJson.Length > MaximumManifestBytes) throw Invalid();
        using var bounded = new BoundedWriteStream(output, BackupArchive.MaximumPayloadBytes);
        using var zip = new ZipArchive(bounded, ZipArchiveMode.Create, leaveOpen: true);
        await WriteEntryAsync(zip, "manifest.json", manifestJson, cancellationToken);
        await WriteEntryAsync(zip, "configuration.json", configurationJson, cancellationToken);
        var entry = NewEntry(zip, "core.db");
        await using var destination = entry.Open();
        if (await CopyHashAsync(database, destination, manifest.DatabaseBytes, cancellationToken) != manifest.DatabaseSha256)
            throw Invalid();
    }

    /// <summary>
    /// Requires a seekable stream at position zero to avoid ZipArchive's unbounded buffering
    /// of non-seekable input. The caller owns an existing empty, private staging directory.
    /// Only core.db and configuration.json are written; the manifest is returned in memory.
    /// </summary>
    public static async Task<BackupManifest> ExtractAndVerifyAsync(Stream input, string privateStagingDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead || !input.CanSeek || input.Position != 0) throw Invalid();
        ValidateEnvelope(input);
        var directory = new DirectoryInfo(privateStagingDirectory);
        if (!directory.Exists || directory.LinkTarget is not null || (directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
            directory.EnumerateFileSystemInfos().Any()) throw Invalid();
        var created = new List<string>();
        try
        {
            using var zip = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
            if (zip.Entries.Count != 3) throw Invalid();
            var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
            foreach (var entry in zip.Entries)
            {
                if (entry.FullName is not ("manifest.json" or "configuration.json" or "core.db") ||
                    !entries.TryAdd(entry.FullName, entry) || !Regular(entry)) throw Invalid();
            }
            var manifestBytes = await ReadEntryAsync(entries["manifest.json"], MaximumManifestBytes, cancellationToken);
            var manifest = ReadManifest(manifestBytes);
            var configuration = await ReadEntryAsync(entries["configuration.json"], MaximumConfigurationBytes, cancellationToken);
            ValidateConfiguration(configuration);
            if (Hash(configuration) != manifest.ConfigurationSha256 || entries["core.db"].Length != manifest.DatabaseBytes)
                throw Invalid();

            var configurationPath = Path.Combine(directory.FullName, "configuration.json");
            await using (var destination = CreatePrivate(configurationPath))
            {
                created.Add(configurationPath);
                await destination.WriteAsync(configuration, cancellationToken);
            }
            var databasePath = Path.Combine(directory.FullName, "core.db");
            await using (var destination = CreatePrivate(databasePath))
            {
                created.Add(databasePath);
                await using var source = entries["core.db"].Open();
                if (await CopyHashAsync(source, destination, manifest.DatabaseBytes, cancellationToken) != manifest.DatabaseSha256)
                    throw Invalid();
            }
            return manifest;
        }
        catch
        {
            foreach (var path in created)
                try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
    }

    private static ZipArchiveEntry NewEntry(ZipArchive zip, string name)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = ZipTime;
        entry.ExternalAttributes = 0;
        return entry;
    }

    private static async Task WriteEntryAsync(ZipArchive zip, string name, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        await using var stream = NewEntry(zip, name).Open();
        await stream.WriteAsync(bytes, cancellationToken);
    }

    private static async Task<byte[]> ReadEntryAsync(ZipArchiveEntry entry, int maximum, CancellationToken cancellationToken)
    {
        if (entry.Length is < 1 || entry.Length > maximum) throw Invalid();
        var bytes = new byte[checked((int)entry.Length)];
        await using var stream = entry.Open();
        var read = 0;
        while (read < bytes.Length)
        {
            var count = await stream.ReadAsync(bytes.AsMemory(read), cancellationToken);
            if (count == 0) throw Invalid();
            read += count;
        }
        if (await stream.ReadAsync(new byte[1], cancellationToken) != 0) throw Invalid();
        return bytes;
    }

    private static async Task<string> CopyHashAsync(Stream source, Stream destination, long expected,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        try
        {
            long total = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken);
                if (read == 0) break;
                if (read > expected - total) throw Invalid();
                hash.AppendData(buffer, 0, read);
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                total += read;
            }
            if (total != expected) throw Invalid();
            return Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static BackupManifest ReadManifest(ReadOnlyMemory<byte> bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw Invalid();
            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var item in document.RootElement.EnumerateObject())
                if (!Fields.Contains(item.Name, StringComparer.Ordinal) || !fields.TryAdd(item.Name, item.Value)) throw Invalid();
            if (fields.Count != Fields.Length) throw Invalid();
            string Text(string name) => fields[name].ValueKind == JsonValueKind.String
                ? fields[name].GetString()! : throw Invalid();
            Guid Identifier(string name) => Guid.TryParseExact(Text(name), "D", out var value) ? value : throw Invalid();
            if (!fields["schemaVersion"].TryGetInt32(out var schema) || !fields["databaseBytes"].TryGetInt64(out var length) ||
                !fields["createdUtc"].TryGetDateTimeOffset(out var created)) throw Invalid();
            var manifest = new BackupManifest(schema, Identifier("archiveId"), created, Identifier("coreInstallationId"),
                Identifier("organizationId"), Text("productVersion"), Text("recoveryKeyId"), length,
                Text("databaseSha256"), Text("configurationSha256"));
            ValidateManifest(manifest);
            return manifest;
        }
        catch (JsonException) { throw Invalid(); }
        catch (InvalidOperationException) { throw Invalid(); }
    }

    private static void ValidateManifest(BackupManifest manifest)
    {
        if (manifest.SchemaVersion != 1 || manifest.ArchiveId == Guid.Empty || manifest.CoreInstallationId == Guid.Empty ||
            manifest.OrganizationId == Guid.Empty || manifest.CreatedUtc.Offset != TimeSpan.Zero || manifest.CreatedUtc.Year < 2020 ||
            manifest.ProductVersion is not { Length: > 0 and <= 256 } || manifest.ProductVersion.Any(value => value is < '!' or > '~') ||
            manifest.DatabaseBytes is < 1 or > BackupArchive.MaximumPayloadBytes || !IsHash(manifest.RecoveryKeyId) ||
            !IsHash(manifest.DatabaseSha256) || !IsHash(manifest.ConfigurationSha256)) throw Invalid();
    }

    private static void ValidateConfiguration(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is < 2 or > MaximumConfigurationBytes) throw Invalid();
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw Invalid();
            void Check(JsonElement element)
            {
                if (element.ValueKind == JsonValueKind.Object)
                {
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in element.EnumerateObject())
                    {
                        if (property.Name.Length > 256 || !names.Add(property.Name)) throw Invalid();
                        Check(property.Value);
                    }
                }
                else if (element.ValueKind == JsonValueKind.Array)
                    foreach (var item in element.EnumerateArray()) Check(item);
            }
            Check(document.RootElement);
        }
        catch (JsonException) { throw Invalid(); }
    }

    private static bool IsHash(string value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static bool Regular(ZipArchiveEntry entry)
    {
        var unixKind = (entry.ExternalAttributes >> 16) & 0xf000;
        return (unixKind is 0 or 0x8000) &&
               (entry.ExternalAttributes & ((int)FileAttributes.Directory | (int)FileAttributes.ReparsePoint)) == 0;
    }

    private static FileStream CreatePrivate(string path)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan, BufferSize = 64 * 1024
        };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }

    private static void ValidateEnvelope(Stream input)
    {
        // Our package has three entries, no comment/multi-disk/ZIP64 envelope or trailing bytes.
        // Check the fixed end record before ZipArchive follows its offsets.
        var length = input.Length;
        if (length is < 26 or > BackupArchive.MaximumPayloadBytes) throw Invalid();
        Span<byte> end = stackalloc byte[22];
        input.Position = length - end.Length;
        input.ReadExactly(end);
        if (BinaryPrimitives.ReadUInt32LittleEndian(end) != 0x06054b50 ||
            BinaryPrimitives.ReadUInt16LittleEndian(end[4..]) != 0 || BinaryPrimitives.ReadUInt16LittleEndian(end[6..]) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(end[8..]) != 3 || BinaryPrimitives.ReadUInt16LittleEndian(end[10..]) != 3 ||
            BinaryPrimitives.ReadUInt16LittleEndian(end[20..]) != 0 ||
            (long)BinaryPrimitives.ReadUInt32LittleEndian(end[12..]) + BinaryPrimitives.ReadUInt32LittleEndian(end[16..]) != length - 22)
            throw Invalid();
        input.Position = 0;
        Span<byte> start = stackalloc byte[4];
        input.ReadExactly(start);
        if (BinaryPrimitives.ReadUInt32LittleEndian(start) != 0x04034b50) throw Invalid();
        input.Position = 0;
    }

    private static InvalidDataException Invalid() => new("The backup package is invalid or inconsistent.");

    private sealed class BoundedWriteStream(Stream destination, long maximum) : Stream
    {
        private long _written;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => destination.CanWrite;
        public override long Length => _written;
        public override long Position { get => _written; set => throw new NotSupportedException(); }
        public override void Flush() => destination.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check(buffer.Length);
            destination.Write(buffer);
            _written += buffer.Length;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Check(buffer.Length);
            await destination.WriteAsync(buffer, cancellationToken);
            _written += buffer.Length;
        }
        private void Check(int count) { if (count > maximum - _written) throw Invalid(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
