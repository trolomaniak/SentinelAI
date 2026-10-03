using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentinelAI.Desktop.Services;

/// <summary>Checks the existing pilot installation using the invoking operator's authority.</summary>
internal static class WindowsInstallationTrust
{
    internal const string CoreServiceSid = "S-1-5-80-1772522954-4099193962-4247269631-2556497313-4219375900";
    internal static string CodeDirectory { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SentinelAI", "Core");
    internal static string DataDirectory { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI", "Core");
    internal static string ExecutablePath { get; } = Path.Combine(CodeDirectory, "SentinelAI.Core.exe");
    internal static string ConfigurationPath { get; } = Path.Combine(DataDirectory, "pilot-config.json");
    internal static Uri Origin { get; } = new("http://127.0.0.1:5000/");
    private static readonly string[] SystemWriters = ["S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

    internal static FileStream ValidateOperatorInstallation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var writers = new HashSet<string>(SystemWriters, StringComparer.Ordinal);
        if (identity.User is not null) writers.Add(identity.User.Value);
        ValidatePath(CodeDirectory, writers, serviceOnAncestors: false);
        var pending = new Queue<string>();
        pending.Enqueue(CodeDirectory);
        var count = 0;
        while (pending.TryDequeue(out var path))
        {
            if (++count > 8192) throw new InvalidDataException("Installation exceeds its work bound.");
            ValidatePath(path, writers, serviceOnAncestors: false);
            if (Directory.Exists(path))
                foreach (var child in Directory.EnumerateFileSystemEntries(path)) pending.Enqueue(child);
        }
        ValidatePath(ConfigurationPath, writers, serviceOnAncestors: true);
        var pilotPath = Path.Combine(DataDirectory, "pilot-installation.json");
        ValidatePath(pilotPath, writers, serviceOnAncestors: true);
        using var configuration = ReadDocument(ConfigurationPath, 8192);
        var settings = ExactObject(configuration.RootElement, "urls", "SentinelAI");
        var data = ExactObject(settings["SentinelAI"], "DataDirectory");
        if (!string.Equals(String(settings["urls"]), Origin.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal) ||
            !string.Equals(String(data["DataDirectory"]), DataDirectory, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Unexpected fixed Core configuration.");
        using var pilot = ReadDocument(pilotPath, 4096);
        var fields = ExactObject(pilot.RootElement, "format", "component", "version", "codeDirectory", "dataDirectory", "coreUrl", "environment", "channel", "serviceName", "serviceAccountSid");
        if (String(fields["format"]) != "sentinelai-pilot-v1" || String(fields["component"]) != "Core" ||
            !SamePath(String(fields["codeDirectory"]), CodeDirectory) || !SamePath(String(fields["dataDirectory"]), DataDirectory) ||
            String(fields["coreUrl"]) != Origin.GetLeftPart(UriPartial.Authority) || String(fields["serviceName"]) != "" || String(fields["serviceAccountSid"]) != "" ||
            !Regex.IsMatch(String(fields["version"]), @"\A(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z") ||
            String(fields["environment"]) is not ("development" or "production") || String(fields["channel"]) is not ("stable" or "pilot" or "beta"))
            throw new InvalidDataException("Unexpected Core ownership receipt.");

        // Retain a read lock through the child process or console connection so
        // the validated executable cannot be replaced or written during use.
        var executable = new FileStream(ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            var servicePath = Path.Combine(DataDirectory, "core-service-installation.json");
            if (File.Exists(servicePath))
            {
                ValidatePath(servicePath, writers, serviceOnAncestors: true);
                using var service = ReadDocument(servicePath, 4096);
                var proof = ExactObject(service.RootElement, "format", "serviceName", "serviceAccount", "serviceAccountSid", "codeDirectory", "dataDirectory", "configurationSha256", "executableSha256", "version");
                var executableHash = Convert.ToHexString(SHA256.HashData(executable));
                executable.Position = 0;
                var configurationHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ConfigurationPath)));
                if (String(proof["format"]) != "sentinelai-core-service-v1" || String(proof["serviceName"]) != "SentinelAICore" ||
                    String(proof["serviceAccount"]) != "NT SERVICE\\SentinelAICore" || String(proof["serviceAccountSid"]) != CoreServiceSid ||
                    !SamePath(String(proof["codeDirectory"]), CodeDirectory) || !SamePath(String(proof["dataDirectory"]), DataDirectory) ||
                    String(proof["version"]) != String(fields["version"]) || String(proof["executableSha256"]) != executableHash ||
                    String(proof["configurationSha256"]) != configurationHash)
                    throw new InvalidDataException("Unexpected Core service ownership receipt.");
            }
            return executable;
        }
        catch { executable.Dispose(); throw; }
    }

    internal static void RejectReadableReparsePoints(string path)
    {
        for (var current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("An installed path is a link.");
            }
            catch (UnauthorizedAccessException) { /* SCM remains authoritative for ordinary service sign-in. */ }
        }
    }

    private static void ValidatePath(string path, HashSet<string> writers, bool serviceOnAncestors)
    {
        if (!Regex.IsMatch(path, @"\A[A-Za-z]:\\") || path.Length > 220 || path.Contains('/') ||
            path.AsSpan(2).Contains(':') || path.Any(character => character < 32 || "<>\"|?*".Contains(character)) ||
            !SamePath(Path.GetFullPath(path).TrimEnd('\\'), path.TrimEnd('\\')) || path.Length <= 3)
            throw new InvalidDataException("Unsupported installation path.");
        var drive = new DriveInfo(Path.GetPathRoot(path)!);
        if (!drive.IsReady || drive.DriveType != DriveType.Fixed || drive.DriveFormat != "NTFS")
            throw new InvalidDataException("A local fixed NTFS installation is required.");
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            // Exists deliberately hides access errors; probe attributes so a
            // protected existing path requests elevation instead of first-run.
            _ = File.GetAttributes(path);
            throw new FileNotFoundException("Installation is unavailable.");
        }
        for (var current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Links are unsupported.");
            var directory = (attributes & FileAttributes.Directory) != 0;
            if (!directory && WindowsNativeCore.GetHardLinkCount(current) != 1) throw new InvalidDataException("Hard links are unsupported.");
            FileSystemSecurity security = directory
                ? new DirectoryInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var ancestor = !SamePath(current, path);
            var serviceAllowed = serviceOnAncestors && ancestor && (SamePath(current, DataDirectory) || current.StartsWith(DataDirectory + "\\", StringComparison.OrdinalIgnoreCase));
            var owner = (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value
                ?? throw new InvalidDataException("Missing installation owner.");
            if (!writers.Contains(owner) && !(serviceAllowed && owner == CoreServiceSid)) throw new InvalidDataException("Untrusted installation owner.");
            var unsafeRights = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            if (ancestor && directory) unsafeRights &= ~FileSystemRights.AppendData;
            if (ancestor && SamePath(current, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData))) unsafeRights &= ~FileSystemRights.Write;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                var sid = ((SecurityIdentifier)rule.IdentityReference).Value;
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                    (rule.FileSystemRights & unsafeRights) != 0 && !writers.Contains(sid) && !(serviceAllowed && sid == CoreServiceSid))
                    throw new InvalidDataException("Untrusted installation writer.");
            }
        }
    }

    private static JsonDocument ReadDocument(string path, int limit)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 || stream.Length > limit) throw new InvalidDataException("Invalid installation metadata size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Installation metadata changed.");
        return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
    }

    private static Dictionary<string, JsonElement> ExactObject(JsonElement element, params string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid installation metadata.");
        var result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
            if (!names.Contains(property.Name, StringComparer.Ordinal) || !result.TryAdd(property.Name, property.Value)) throw new InvalidDataException("Ambiguous installation metadata.");
        if (result.Count != names.Length) throw new InvalidDataException("Incomplete installation metadata.");
        return result;
    }
    private static string String(JsonElement element) => element.ValueKind == JsonValueKind.String ? element.GetString()! : throw new InvalidDataException("Invalid installation metadata value.");
    private static bool SamePath(string first, string second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
}
