using System.Text.Json;
using SentinelAI.Updates;

namespace SentinelAI.Updater;

/// <summary>
/// Operator-controlled local verification, staging and fresh code preparation, and (MVP-7) the scheduled SYSTEM
/// installation of an Agent update that the Agent fetched from Core. It never downloads code.
/// </summary>
public static class UpdaterCommand
{
    // A local package prepares in seconds, and in well under a minute on a slow disk; a stalled
    // installer step fails closed long before Setup's ten-minute worker limit.
    internal static readonly TimeSpan PrepareDeadline = TimeSpan.FromMinutes(5);
    internal const int DeadlineExitCode = 2;
    internal static readonly TimeSpan AgentUpdateDeadline = TimeSpan.FromMinutes(15);

    public static Task<int> RunAsync(string[] args, TextWriter output, TextWriter error) =>
        RunAsync(args, output, error, PrepareDeadline);

    internal static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, TimeSpan prepareDeadline)
    {
        string? temporary = null;
        using var deadline = new CancellationTokenSource();
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                await output.WriteLineAsync("verify|stage|prepare --manifest FILE --package ZIP --public-key PEM --key-id ID --environment development|production --channel stable|pilot|beta --artifact-id ID --installed-version X.Y.Z [stage: --output ABSOLUTE_NEW_FILE; prepare: --output ABSOLUTE_NEW_DIRECTORY] | apply-agent-update");
                return 0;
            }
            if (args is ["apply-agent-update"]) return await ApplyAgentUpdateAsync(output, error);
            var allowed = new[] { "manifest", "package", "public-key", "key-id", "environment", "channel", "artifact-id", "installed-version" };
            var command = args.FirstOrDefault();
            if (command is not ("verify" or "stage" or "prepare")) throw new ArgumentException();
            if (command == "prepare") deadline.CancelAfter(prepareDeadline);
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
            await UpdateArtifactVerifier.CopyAndVerifyAsync(options["package"], destination, verified, deadline.Token);
            if (preparedDirectory is not null)
            {
                await PackageExtractor.ExtractAsync(destination, preparedDirectory, expectedExecutable!, deadline.Token);
                try
                {
                    deadline.Token.ThrowIfCancellationRequested();
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
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            await error.WriteLineAsync("Update preparation did not finish within its time limit.");
            return DeadlineExitCode;
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

    /// <summary>Agent Setup's hourly SYSTEM task: installs a newer Agent the Agent staged, or does nothing.</summary>
    private static async Task<int> ApplyAgentUpdateAsync(TextWriter output, TextWriter error)
    {
        if (!OperatingSystem.IsWindows()) throw new ArgumentException();
        using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
        {
            if (!identity.IsSystem && !new System.Security.Principal.WindowsPrincipal(identity)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException();
        }

        var layout = AgentUpdateLayout.Default;
        var service = new WindowsAgentService(layout);
        service.AssertOwned();
        using var deadline = new CancellationTokenSource(AgentUpdateDeadline);
        var applier = new AgentUpdateApplier(layout, service,
            new TransactionalUpdater(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(3)),
            WindowsAgentService.RecordAppsVersion);
        var outcome = await applier.ApplyAsync(deadline.Token);
        await output.WriteLineAsync(outcome switch
        {
            AgentUpdateOutcome.NoUpdate => "No Agent update to install.",
            AgentUpdateOutcome.Installed => "The Agent update was installed.",
            AgentUpdateOutcome.Rejected => "The staged Agent update was rejected; the Agent was not changed.",
            AgentUpdateOutcome.RolledBack => "The Agent update failed and the previous Agent was restored.",
            AgentUpdateOutcome.NotRetried => "This Agent update failed before and is not retried; the previous Agent keeps running.",
            _ => "The Agent update and its rollback failed; recovery is retried at the next run."
        });
        return outcome switch
        {
            AgentUpdateOutcome.NoUpdate or AgentUpdateOutcome.Installed => 0,
            AgentUpdateOutcome.Rejected => 3,
            AgentUpdateOutcome.RolledBack or AgentUpdateOutcome.NotRetried => 4,
            _ => 5
        };
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
