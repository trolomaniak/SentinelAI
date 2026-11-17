using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SentinelAI.Backup;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core.Backups;

/// <summary>Recovery identity remains available when SQLite itself is lost. Its MAC requires the owner's recovery key.</summary>
internal static class BackupIdentityAnchor
{
    private const string Name = "backup-identity.json";
    private sealed record Document(int SchemaVersion, Guid CoreInstallationId, Guid OrganizationId, string RecoveryKeyId, string MachineBinding, string Mac);
    public static void Ensure(string directory, CoreIdentity identity, ReadOnlySpan<byte> key)
    {
        var path = Path.Combine(directory, Name);
        if (File.Exists(path))
        {
            if (Read(directory, key) != identity) throw new InvalidDataException("Backup identity is unavailable.");
            return;
        }
        Write(directory, identity, key, overwrite: false);
    }
    public static CoreIdentity Read(string directory, ReadOnlySpan<byte> key)
    {
        var path = Path.Combine(directory, Name);
        BackupStorage.AssertFile(path, 8192);
        var bytes = File.ReadAllBytes(path);
        using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
        var fields = json.RootElement.EnumerateObject().ToArray();
        if (fields.Length != 6 || fields.Select(field => field.Name).Distinct(StringComparer.Ordinal).Count() != 6 ||
            fields.Any(field => field.Name is not ("SchemaVersion" or "CoreInstallationId" or "OrganizationId" or "RecoveryKeyId" or "MachineBinding" or "Mac")))
            throw new InvalidDataException("Backup identity is unavailable.");
        var document = JsonSerializer.Deserialize<Document>(bytes) ?? throw new InvalidDataException("Backup identity is unavailable.");
        if (document.SchemaVersion != 1 || document.CoreInstallationId == Guid.Empty || document.OrganizationId == Guid.Empty ||
            document.RecoveryKeyId != BackupArchive.KeyId(key) || document.MachineBinding != CurrentBinding(directory) || document.Mac is not { Length: 64 })
            throw new InvalidDataException("Backup identity is unavailable.");
        byte[] supplied;
        try { supplied = Convert.FromHexString(document.Mac); }
        catch (FormatException) { throw new InvalidDataException("Backup identity is unavailable."); }
        var expected = Authenticate(document.CoreInstallationId, document.OrganizationId, document.RecoveryKeyId, document.MachineBinding, key);
        if (!CryptographicOperations.FixedTimeEquals(expected, supplied)) throw new InvalidDataException("Backup identity is unavailable.");
        return new CoreIdentity(document.CoreInstallationId, document.OrganizationId);
    }
    // Only the elevated explicit migration path can call this; ordinary backup setup uses immutable Ensure.
    internal static void ReplaceForMigration(string directory, CoreIdentity identity, ReadOnlySpan<byte> key) =>
        Write(directory, identity, key, overwrite: true);
    private static void Write(string directory, CoreIdentity identity, ReadOnlySpan<byte> key, bool overwrite)
    {
        if (key.Length != 32 || identity.CoreInstallationId == Guid.Empty || identity.OrganizationId == Guid.Empty)
            throw new InvalidDataException("Backup identity is unavailable.");
        var id = BackupArchive.KeyId(key);
        var binding = CurrentBinding(directory);
        var document = new Document(1, identity.CoreInstallationId, identity.OrganizationId, id, binding,
            Convert.ToHexStringLower(Authenticate(identity.CoreInstallationId, identity.OrganizationId, id, binding, key)));
        var target = Path.Combine(directory, Name);
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = BackupStorage.CreateFile(temporary))
            {
                JsonSerializer.Serialize(stream, document);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, target, overwrite);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private static string CurrentBinding(string directory)
    {
        string machine;
        if (OperatingSystem.IsWindows())
        {
            using var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var cryptography = registry.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            if (cryptography?.GetValue("MachineGuid") is not string value || !Guid.TryParse(value, out var id))
                throw new IOException("Backup identity is unavailable.");
            machine = id.ToString("D");
        }
        else machine = Environment.MachineName; // Non-Windows production protection is unsupported; portable tests only.
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetDirectoryName(directory)!));
        if (OperatingSystem.IsWindows()) data = data.ToUpperInvariant();
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"SentinelAI/backup-host/v1\n{machine}\n{data}\n")));
    }
    private static byte[] Authenticate(Guid core, Guid organization, string keyId, string binding, ReadOnlySpan<byte> key) =>
        HMACSHA256.HashData(key, Encoding.ASCII.GetBytes($"SentinelAI/backup-identity/v1\n{core:D}\n{organization:D}\n{keyId}\n{binding}\n"));
}
