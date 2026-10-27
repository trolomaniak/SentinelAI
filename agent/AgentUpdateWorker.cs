using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Updates;

namespace SentinelAI.Agent;

public enum AgentUpdateCheck { NotOffered, Current, Staged, AlreadyStaged, Rejected, Failed }

/// <summary>
/// MVP-7: fetches a newer signed Agent package that Core offers into <c>&lt;data&gt;\update</c>. The Agent only
/// checks that the transfer matches the manifest; the computer's SYSTEM updater (Agent Setup's scheduled task)
/// verifies the signature, channel and version before installing, and never writes into this directory. A package
/// that is not newer than this Agent is removed, which also clears it after a successful update.
/// </summary>
public sealed class AgentUpdateStager(HttpClient httpClient, AgentOptions options, ILogger<AgentUpdateStager> logger)
{
    public const string DirectoryName = "update";
    public const string ManifestFileName = "agent-update.manifest.json";
    public const string PackageFileName = "agent-update.zip";
    public const string ArtifactId = "sentinelai-agent-win-x64";

    public string StagingDirectory => Path.Combine(options.DataDirectory, DirectoryName);

    /// <summary>This Agent's release, as <c>major.minor.patch</c>.</summary>
    public static Version CurrentVersion { get; } = Release(typeof(AgentUpdateStager).Assembly.GetName().Version);

    public async Task<AgentUpdateCheck> CheckAsync(EnrollmentState enrollment, Version installed, CancellationToken cancellationToken)
    {
        byte[] manifestBytes;
        using (var response = await SendAsync(options.UpdateManifestUrl, enrollment, cancellationToken))
        {
            if (response is null) return AgentUpdateCheck.Failed;
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                Clear();
                return AgentUpdateCheck.NotOffered;
            }

            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength is not (> 0 and <= UpdateManifestFormat.MaximumDocumentBytes))
                return AgentUpdateCheck.Failed;
            manifestBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        }

        if (manifestBytes.Length is 0 or > UpdateManifestFormat.MaximumDocumentBytes ||
            UpdateManifestFormat.ReadUnauthenticated(manifestBytes) is not { ArtifactId: ArtifactId } manifest ||
            !UpdateManifestFormat.TryParseVersion(manifest.Version, out var offered))
        {
            logger.LogWarning("Core offered an Agent update that is not a well-formed Agent manifest");
            return AgentUpdateCheck.Rejected;
        }

        if (offered <= installed)
        {
            Clear();
            return AgentUpdateCheck.Current;
        }

        var directory = StagingDirectory;
        var manifestPath = Path.Combine(directory, ManifestFileName);
        var packagePath = Path.Combine(directory, PackageFileName);
        // A staged copy that no longer matches the manifest is downloaded again rather than offered to the updater forever.
        if (File.Exists(manifestPath) && File.Exists(packagePath) &&
            (await File.ReadAllBytesAsync(manifestPath, cancellationToken)).AsSpan().SequenceEqual(manifestBytes) &&
            new FileInfo(packagePath).Length == manifest.SizeBytes && await MatchesAsync(packagePath, manifest.Sha256, cancellationToken))
            return AgentUpdateCheck.AlreadyStaged;

        Directory.CreateDirectory(directory);
        var partialPackage = packagePath + ".partial";
        var partialManifest = manifestPath + ".partial";
        try
        {
            using (var response = await SendAsync(options.UpdatePackageUrl, enrollment, cancellationToken))
            {
                if (response is null || !response.IsSuccessStatusCode) return AgentUpdateCheck.Failed;
                if (!await DownloadAsync(response, partialPackage, manifest, cancellationToken))
                {
                    logger.LogWarning("The Agent update {Version} from Core did not match its manifest", manifest.Version);
                    return AgentUpdateCheck.Rejected;
                }
            }

            await File.WriteAllBytesAsync(partialManifest, manifestBytes, cancellationToken);
            // The updater reads the manifest first: without one, a package being replaced is never picked up.
            File.Delete(manifestPath);
            File.Move(partialPackage, packagePath, overwrite: true);
            File.Move(partialManifest, manifestPath, overwrite: true);
            logger.LogInformation("Agent update {Version} downloaded from Core for installation", manifest.Version);
            return AgentUpdateCheck.Staged;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or HttpRequestException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Downloading the Agent update failed with {ExceptionType}", exception.GetType().Name);
            return AgentUpdateCheck.Failed;
        }
        finally
        {
            foreach (var partial in new[] { partialPackage, partialManifest })
            {
                try { File.Delete(partial); }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
            }
        }
    }

    /// <summary>Removes a staged package; nothing else in the directory is touched.</summary>
    public void Clear()
    {
        foreach (var name in new[] { ManifestFileName, PackageFileName })
        {
            try { File.Delete(Path.Combine(StagingDirectory, name)); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }
    }

    public static Version Release(Version? version) =>
        version is null ? new Version(0, 0, 0) : new Version(version.Major, Math.Max(version.Minor, 0), Math.Max(version.Build, 0));

    private async Task<HttpResponseMessage?> SendAsync(Uri url, EnrollmentState enrollment, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "SentinelAgent", $"{enrollment.EndpointId:D}.{enrollment.AgentCredential}");
        try
        {
            return await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static async Task<bool> MatchesAsync(string path, string sha256, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous);
        return string.Equals(Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken)), sha256, StringComparison.Ordinal);
    }

    /// <summary>Streams at most the manifest's size into a new file and checks its exact size and SHA-256.</summary>
    private static async Task<bool> DownloadAsync(HttpResponseMessage response, string path, UpdateManifest manifest,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is { } length && length != manifest.SizeBytes) return false;
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var target = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            total += read;
            if (total > manifest.SizeBytes) return false;
            hash.AppendData(buffer, 0, read);
            await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        await target.FlushAsync(cancellationToken);
        return total == manifest.SizeBytes &&
               string.Equals(Convert.ToHexStringLower(hash.GetHashAndReset()), manifest.Sha256, StringComparison.Ordinal);
    }
}

/// <summary>
/// Checks Core for a newer Agent shortly after the Agent links to Core and then every
/// <see cref="AgentOptions.UpdateCheckInterval"/>; a failed check is retried after a quarter of it.
/// </summary>
public sealed class AgentUpdateWorker(
    AgentLink link,
    AgentUpdateStager stager,
    AgentOptions options,
    TimeProvider time,
    ILogger<AgentUpdateWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Guid? endpointId = null;
        long? since = null;
        var delay = options.UpdateCheckDelay;
        while (!stoppingToken.IsCancellationRequested)
        {
            // Capture the signal before reading the link so that a concurrent change still wakes the wait.
            var changed = link.Changed;
            var linked = link.Current;
            try
            {
                if (linked is null)
                {
                    await changed.WaitAsync(stoppingToken);
                    continue;
                }

                if (linked.EndpointId != endpointId)
                {
                    endpointId = linked.EndpointId;
                    since = time.GetTimestamp();
                    delay = options.UpdateCheckDelay;
                }

                var remaining = delay - time.GetElapsedTime(since!.Value);
                if (remaining <= TimeSpan.Zero)
                {
                    AgentUpdateCheck result;
                    try
                    {
                        result = await stager.CheckAsync(linked, AgentUpdateStager.CurrentVersion, stoppingToken);
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
                    {
                        // An update check never stops the Agent host.
                        logger.LogWarning("Checking for an Agent update failed with {ExceptionType}", exception.GetType().Name);
                        result = AgentUpdateCheck.Failed;
                    }

                    since = time.GetTimestamp();
                    delay = result == AgentUpdateCheck.Failed ? options.UpdateCheckInterval / 4 : options.UpdateCheckInterval;
                    continue;
                }

                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                await Task.WhenAny(Task.Delay(remaining, time, wait.Token), changed.WaitAsync(wait.Token));
                await wait.CancelAsync();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
