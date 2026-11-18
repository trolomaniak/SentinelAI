using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Backup;

/// <summary>Synthetic backup bytes and disposable keys only; no installed/customer state is read.</summary>
internal static class BackupCryptographyTests
{
    private static int _checks;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static async Task RunAsync()
    {
        _checks = 0;
        await ArchiveAsync();
        RecoveryFile();
        await PackageAsync();
        Console.WriteLine($"Backup cryptography/package tests passed ({_checks} checks: authenticated frames, truncation/reordering, key files, strict package bounds and paths).");
    }

    private static async Task ArchiveAsync()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrong = RandomNumberGenerator.GetBytes(32);
        var data = RandomNumberGenerator.GetBytes(BackupArchive.ChunkBytes * 2 + 37);
        try
        {
            byte[] encrypted;
            using (var source = new ChunkedReadStream(data, 4093))
            using (var output = new MemoryStream())
            {
                await BackupArchive.EncryptAsync(source, output, key);
                encrypted = output.ToArray();
            }
            using (var source = new ChunkedReadStream(encrypted, 4091))
            using (var output = new MemoryStream())
            {
                await BackupArchive.DecryptAsync(source, output, key);
                Check(output.ToArray().SequenceEqual(data), "Streaming backup round trip changed bytes or mishandled partial reads.");
            }
            using (var output = new MemoryStream())
            {
                await BackupArchive.EncryptAsync(new MemoryStream(data, writable: false), output, key);
                Check(!encrypted.SequenceEqual(output.ToArray()), "A repeated backup reused its encryption salt/key stream.");
            }
            using (var output = new MemoryStream())
            {
                await BackupArchive.EncryptAsync(new MemoryStream(), output, key);
                output.Position = 0;
                using var restored = new MemoryStream();
                await BackupArchive.DecryptAsync(output, restored, key);
                Check(restored.Length == 0, "An empty payload lost its authenticated final marker.");
            }
            Check(BackupArchive.KeyId(key) == Convert.ToHexStringLower(SHA256.HashData(key)) &&
                  BackupArchive.KeyId(key) != BackupArchive.KeyId(wrong), "Recovery key identity is not a stable full SHA-256 digest.");

            async Task Reject(byte[] bytes, byte[]? suppliedKey = null, bool noPlaintext = false)
            {
                using var input = new MemoryStream(bytes, writable: false);
                using var output = new MemoryStream();
                await RejectedAsync(() => BackupArchive.DecryptAsync(input, output, suppliedKey ?? key));
                if (noPlaintext) Check(output.Length == 0, "An unauthenticated first frame published plaintext.");
            }
            byte[] Changed(int index) { var bytes = encrypted.ToArray(); bytes[index] ^= 1; return bytes; }
            await Reject(encrypted, wrong, noPlaintext: true);
            await Reject(Changed(0), noPlaintext: true); // Magic/version.
            await Reject(Changed(17), noPlaintext: true); // Salt is authenticated and participates in derivation.
            await Reject(Changed(53), noPlaintext: true); // First ciphertext.
            await Reject(Changed(53 + BackupArchive.ChunkBytes), noPlaintext: true); // First tag.
            await Reject(Changed(47), noPlaintext: true); // Sequence.
            var excessive = encrypted.ToArray();
            BinaryPrimitives.WriteInt32BigEndian(excessive.AsSpan(48, 4), int.MaxValue);
            await Reject(excessive, noPlaintext: true); // Length checked before allocating/reading frame data.
            var badFlag = encrypted.ToArray(); badFlag[52] = 2;
            await Reject(badFlag, noPlaintext: true);
            await Reject(encrypted[..20]);
            await Reject(encrypted[..^1]);
            await Reject(encrypted[..^29]); // A valid prefix without the authenticated EOF is incomplete.
            await Reject([..encrypted, 0]);

            const int header = 40;
            var frameLength = BackupArchive.ChunkBytes + 29;
            await Reject([..encrypted.AsSpan(0, header), ..encrypted.AsSpan(header + frameLength, frameLength),
                ..encrypted.AsSpan(header, frameLength), ..encrypted.AsSpan(header + frameLength * 2)]);
            await Reject([..encrypted.AsSpan(0, header + frameLength), ..encrypted.AsSpan(header, frameLength),
                ..encrypted.AsSpan(header + frameLength)]);
            await Reject([..encrypted.AsSpan(0, header), ..encrypted.AsSpan(header + frameLength)]);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            using var cancelledOutput = new MemoryStream();
            try
            {
                await BackupArchive.EncryptAsync(new MemoryStream(data), cancelledOutput, key, cancelled.Token);
                throw new InvalidOperationException("Backup encryption ignored cancellation.");
            }
            catch (OperationCanceledException) { Check(cancelledOutput.Length == 0, "Cancelled encryption wrote an archive header."); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(wrong);
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private static void RecoveryFile()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        const string password = "Synthetic-Recovery-Only-😀";
        byte[]? restored = null;
        try
        {
            var file = RecoveryKeyFile.Create(key, password);
            restored = RecoveryKeyFile.Open(file, password);
            Check(restored.SequenceEqual(key) && file.Length == RecoveryKeyFile.MaximumFileBytes,
                "The bounded owner key file did not restore the same secret.");
            Check(file.AsSpan().IndexOf(key) < 0, "The portable recovery file contains the plaintext key.");
            Check(!file.SequenceEqual(RecoveryKeyFile.Create(key, password)), "Recovery key files reused their salt/nonce.");
            Rejected(() => RecoveryKeyFile.Open(file, "Synthetic-Wrong-Password"));
            foreach (var index in new[] { 0, 11, 19, 47, 61, 103 })
            {
                var changed = file.ToArray(); changed[index] ^= 1;
                Rejected(() => RecoveryKeyFile.Open(changed, password));
            }
            Rejected(() => RecoveryKeyFile.Open(file[..^1], password));
            Rejected(() => RecoveryKeyFile.Open([..file, 0], password));
            ArgumentRejected(() => RecoveryKeyFile.Create(key, "too-short"));
            ArgumentRejected(() => RecoveryKeyFile.Create(new byte[31], password));
            ArgumentRejected(() => RecoveryKeyFile.Create(key, "Synthetic-invalid-\ud800"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (restored is not null) CryptographicOperations.ZeroMemory(restored);
        }
    }

    private static async Task PackageAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentinelai-backup-package-" + Guid.NewGuid().ToString("N"));
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(root);
        else Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var database = RandomNumberGenerator.GetBytes(65_537);
            var configuration = "{\"format\":\"synthetic-reference-only\",\"port\":5443}"u8.ToArray();
            var path = Path.Combine(root, "snapshot.db");
            await File.WriteAllBytesAsync(path, database);
            var manifest = new BackupManifest(1, Guid.NewGuid(), new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero),
                Guid.NewGuid(), Guid.NewGuid(), "1.0.0+synthetic-backup-test", new string('a', 64),
                database.Length, Hash(database), Hash(configuration));
            byte[] package;
            using (var output = new MemoryStream())
            {
                await BackupPackage.CreateAsync(output, path, manifest, configuration);
                package = output.ToArray();
            }
            var stage = NewStage(root);
            var result = await BackupPackage.ExtractAndVerifyAsync(new MemoryStream(package), stage);
            Check(result == manifest && (await File.ReadAllBytesAsync(Path.Combine(stage, "core.db"))).SequenceEqual(database) &&
                  (await File.ReadAllBytesAsync(Path.Combine(stage, "configuration.json"))).SequenceEqual(configuration),
                "The allowlisted package did not retain the exact manifest/database/configuration.");
            Check(Directory.EnumerateFiles(stage).Select(Path.GetFileName).Order().SequenceEqual(["configuration.json", "core.db"]),
                "Package extraction created an unexpected file.");

            async Task RejectPackage(byte[] bytes)
            {
                var destination = NewStage(root);
                await RejectedAsync(() => BackupPackage.ExtractAndVerifyAsync(new MemoryStream(bytes), destination));
                Check(!Directory.EnumerateFileSystemEntries(destination).Any(), "A rejected package retained a partial extracted payload.");
            }
            var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
            byte[] Zip(string dbName = "core.db", byte[]? dbBytes = null, byte[]? metadata = null,
                byte[]? config = null, int dbAttributes = 0, string configName = "configuration.json")
            {
                using var output = new MemoryStream();
                using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
                {
                    foreach (var (name, body, attributes) in new[]
                    {
                        ("manifest.json", metadata ?? manifestJson, 0),
                        (configName, config ?? configuration, 0),
                        (dbName, dbBytes ?? database, dbAttributes)
                    })
                    {
                        var entry = zip.CreateEntry(name, CompressionLevel.NoCompression);
                        entry.ExternalAttributes = attributes;
                        using var stream = entry.Open(); stream.Write(body);
                    }
                }
                return output.ToArray();
            }
            await RejectPackage(Zip(dbName: "../escaped.db"));
            Check(!File.Exists(Path.Combine(root, "escaped.db")), "An archive escaped its staging directory.");
            await RejectPackage(Zip(dbName: "CORE.DB"));
            await RejectPackage(Zip(configName: "core.db"));
            await RejectPackage(Zip(dbAttributes: unchecked((int)0xa0000000))); // Unix symlink.
            await RejectPackage(Zip(dbAttributes: (int)FileAttributes.ReparsePoint));
            var damagedDb = database.ToArray(); damagedDb[0] ^= 1;
            await RejectPackage(Zip(dbBytes: damagedDb));
            await RejectPackage(Zip(dbBytes: database[..^1]));
            await RejectPackage(Zip(metadata: Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(manifestJson).Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal))));
            await RejectPackage(Zip(metadata: JsonSerializer.SerializeToUtf8Bytes(manifest with { SchemaVersion = 2 }, Json)));
            await RejectPackage(Zip(metadata: JsonSerializer.SerializeToUtf8Bytes(manifest with { CoreInstallationId = Guid.Empty }, Json)));
            await RejectPackage(Zip(metadata: JsonSerializer.SerializeToUtf8Bytes(manifest with { CreatedUtc = manifest.CreatedUtc.ToOffset(TimeSpan.FromHours(1)) }, Json)));
            await RejectPackage(Zip(metadata: JsonSerializer.SerializeToUtf8Bytes(manifest with { DatabaseBytes = BackupArchive.MaximumPayloadBytes + 1 }, Json)));
            var duplicateConfig = "{\"same\":1,\"same\":2}"u8.ToArray();
            await RejectPackage(Zip(config: duplicateConfig, metadata: JsonSerializer.SerializeToUtf8Bytes(manifest with { ConfigurationSha256 = Hash(duplicateConfig) }, Json)));
            await RejectPackage(Zip(config: new byte[BackupPackage.MaximumConfigurationBytes + 1]));
            await RejectPackage([..package, 0]);
            await RejectPackage(package[..^1]);
            using (var nonseekable = new ChunkedReadStream(package, 73))
                await RejectedAsync(() => BackupPackage.ExtractAndVerifyAsync(nonseekable, NewStage(root)));

            var occupied = NewStage(root);
            var marker = Path.Combine(occupied, "core.db");
            await File.WriteAllTextAsync(marker, "synthetic-existing-file");
            await RejectedAsync(() => BackupPackage.ExtractAndVerifyAsync(new MemoryStream(package), occupied));
            Check(await File.ReadAllTextAsync(marker) == "synthetic-existing-file", "Package extraction replaced a pre-existing destination.");
            if (!OperatingSystem.IsWindows())
            {
                var linkedStage = Path.Combine(root, "linked-stage");
                Directory.CreateSymbolicLink(linkedStage, NewStage(root));
                await RejectedAsync(() => BackupPackage.ExtractAndVerifyAsync(new MemoryStream(package), linkedStage));
                var linkedDb = Path.Combine(root, "linked.db");
                File.CreateSymbolicLink(linkedDb, path);
                await RejectedAsync(() => BackupPackage.CreateAsync(new MemoryStream(), linkedDb, manifest, configuration));
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static string NewStage(string root)
    {
        var path = Path.Combine(root, "stage-" + Guid.NewGuid().ToString("N"));
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); _checks++; }
    private static async Task RejectedAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (InvalidDataException) { _checks++; return; }
        throw new InvalidOperationException("A malformed or unauthenticated backup was accepted.");
    }
    private static void Rejected(Action operation)
    {
        try { operation(); }
        catch (InvalidDataException) { _checks++; return; }
        throw new InvalidOperationException("A malformed or unauthenticated key file was accepted.");
    }
    private static void ArgumentRejected(Action operation)
    {
        try { operation(); }
        catch (ArgumentException) { _checks++; return; }
        throw new InvalidOperationException("Invalid recovery material was accepted.");
    }
    private sealed class ChunkedReadStream(byte[] bytes, int maximumRead) : Stream
    {
        private readonly MemoryStream _stream = new(bytes, writable: false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _stream.Read(buffer, offset, Math.Min(count, maximumRead));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _stream.ReadAsync(buffer[..Math.Min(buffer.Length, maximumRead)], cancellationToken);
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _stream.Dispose(); base.Dispose(disposing); }
    }
}
