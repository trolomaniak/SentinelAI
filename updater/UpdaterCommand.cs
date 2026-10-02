using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updater;

/// <summary>Operator-controlled local verification, staging and fresh code preparation; never starts services or downloads code.</summary>
public static class UpdaterCommand
{
    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        string? temporary = null;
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                await output.WriteLineAsync("verify|stage|prepare --manifest FILE --package ZIP --public-key PEM --key-id ID --environment development|production --channel stable|pilot|beta --artifact-id ID --installed-version X.Y.Z [stage: --output ABSOLUTE_NEW_FILE; prepare: --output ABSOLUTE_NEW_DIRECTORY]");
                return 0;
            }
            var allowed = new[] { "manifest", "package", "public-key", "key-id", "environment", "channel", "artifact-id", "installed-version" };
            var command = args.FirstOrDefault();
            if (command is not ("verify" or "stage" or "prepare")) throw new ArgumentException();
            var options = Parse(args, command is "stage" or "prepare" ? [.. allowed, "output"] : allowed);
            var manifest = await ReadBoundedAsync(options["manifest"], 8192);
            var publicKey = System.Text.Encoding.UTF8.GetString(await ReadBoundedAsync(options["public-key"], 16384));
            var policy = new UpdateVerificationPolicy(options["environment"], options["channel"], options["artifact-id"],
                options["installed-version"], new Dictionary<string, string>(StringComparer.Ordinal)
                { [options["key-id"]] = publicKey });
            var verified = UpdateManifestVerifier.Verify(manifest, policy);
            string? preparedDirectory = null;
            string? expectedExecutable = null;
            if (command == "prepare")
            {
                expectedExecutable = verified.Manifest.ArtifactId switch
                {
                    "sentinelai-agent-win-x64" => "SentinelAI.Agent.exe",
                    "sentinelai-core-win-x64" => "SentinelAI.Core.exe",
                    _ => throw new ArgumentException()
                };
                preparedDirectory = ValidatePrepareDestination(options["output"]);
            }
            string destination;
            if (command == "stage")
            {
                destination = Path.GetFullPath(options["output"]);
                if (!Path.IsPathFullyQualified(options["output"])) throw new ArgumentException();
                RejectLinks(destination);
            }
            else
            {
                temporary = Path.Combine(Path.GetTempPath(), $"sentinelai-update-verify-{Guid.NewGuid():N}");
                if (OperatingSystem.IsWindows()) Directory.CreateDirectory(temporary);
                else Directory.CreateDirectory(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                RejectLinks(temporary);
                destination = Path.Combine(temporary, "verified.zip");
            }
            await UpdateArtifactVerifier.CopyAndVerifyAsync(options["package"], destination, verified);
            if (preparedDirectory is not null)
            {
                await PackageExtractor.ExtractAsync(destination, preparedDirectory, expectedExecutable!);
                try
                {
                    if (Directory.EnumerateFileSystemEntries(preparedDirectory, "*", SearchOption.AllDirectories)
                        .Any(path => Path.GetFileName(path).Equals(TransactionalUpdater.ReceiptFileName, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidDataException();
                }
                catch
                {
                    // ExtractAsync succeeded into our new directory; an existing caller-owned destination is never removed.
                    Directory.Delete(preparedDirectory, recursive: true);
                    throw;
                }
            }
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                version = verified.Manifest.Version, artifactId = verified.Manifest.ArtifactId,
                channel = verified.Manifest.Channel, environment = verified.Manifest.Environment
            }));
            return 0;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or InvalidDataException or UnauthorizedAccessException or
                                         UpdateValidationException or System.Security.Cryptography.CryptographicException or JsonException)
        {
            await error.WriteLineAsync("Update verification failed. Check the manifest, package and explicitly configured trust policy.");
            return 1;
        }
        finally
        {
            if (temporary is not null && Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true);
        }
    }

    private static Dictionary<string, string> Parse(string[] args, string[] required)
    {
        if (args.Length != 1 + required.Length * 2) throw new ArgumentException();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            var flag = args[index];
            if (!flag.StartsWith("--", StringComparison.Ordinal) || !required.Contains(flag[2..], StringComparer.Ordinal) ||
                string.IsNullOrWhiteSpace(args[index + 1]) || !result.TryAdd(flag[2..], args[index + 1])) throw new ArgumentException();
        }
        return result;
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, int maximum)
    {
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (input.Length is <= 0 || input.Length > maximum) throw new ArgumentException();
        var bytes = new byte[checked((int)input.Length)];
        await input.ReadExactlyAsync(bytes);
        if (input.ReadByte() != -1) throw new ArgumentException();
        return bytes;
    }

    private static void RejectLinks(string path)
    {
        for (var current = path; current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new ArgumentException();
    }

    private static string ValidatePrepareDestination(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException();
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var parent = Path.GetDirectoryName(full);
        if (parent is null || !Directory.Exists(parent) || Directory.Exists(full) || File.Exists(full))
            throw new ArgumentException();
        RejectLinks(full);
        for (var current = full; current is not null; current = Path.GetDirectoryName(current))
            if (new FileInfo(current).LinkTarget is not null || new DirectoryInfo(current).LinkTarget is not null)
                throw new ArgumentException();
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(parent) & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            throw new ArgumentException();
        return full;
    }
}
