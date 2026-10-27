using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using SentinelAI.Core.Persistence;
using SentinelAI.Updates;

namespace SentinelAI.Core;

/// <summary>
/// MVP-7: the owner's HTTPS update server, built into the deployment as <c>update-server.json</c> next to Core. The
/// server offers <c>SentinelAI-Setup.manifest.json</c> at its URL and the signed Setup at
/// <c>&lt;URL&gt;/&lt;version&gt;/SentinelAI-Setup.exe</c>; nothing else is ever requested.
/// </summary>
public sealed partial record CentralUpdateServer(string Url, string Channel)
{
    public const int MaximumUrlLength = 256;

    public Uri ManifestUri => new(Url + "/" + CentralUpdateService.ManifestFileName);
    public string PackageUrl(string version) => Url + "/" + version + "/" + CentralUpdateService.PackageFileName;
    public string Host => new Uri(Url).Authority;

    /// <summary>A lowercase https:// URL without credentials, query, fragment, encoded characters or trailing slash.</summary>
    public static bool IsServerUrl(string? url) => url is { Length: > 0 and <= MaximumUrlLength } && ServerUrl().IsMatch(url);

    [GeneratedRegex(@"\Ahttps://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~-]+)*\z",
        RegexOptions.CultureInvariant)]
    private static partial Regex ServerUrl();
}

public sealed record CentralUpdateStatus(bool Configured, string? Server, bool CheckEnabled, bool AutoInstall, string InstalledVersion,
    string LastCheck, DateTimeOffset? LastCheckUtc, string? ReadyVersion, int InstallAttempts, DateTimeOffset? LastAttemptUtc);

public sealed record CentralUpdateSettingsRequest(bool? CheckEnabled, bool? AutoInstall);

/// <summary>
/// The update server and the update task's record. <c>SentinelAI:CentralUpdate</c> accepts <c>Directory</c> (the
/// folder holding update-server.json) and <c>StateFile</c>, for tests only.
/// </summary>
public sealed class CentralUpdateOptions
{
    public const string ServerFileName = "update-server.json";

    private CentralUpdateOptions(CentralUpdateServer? server, string? stateFile)
    {
        Server = server;
        StateFile = stateFile;
    }

    public CentralUpdateServer? Server { get; }
    /// <summary>The SYSTEM update task's record of its attempts; Core only reads it.</summary>
    public string? StateFile { get; }

    public static CentralUpdateOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:CentralUpdate");
        if (section.GetChildren().Any(child => child.Key is not ("Directory" or "StateFile")))
            throw new InvalidOperationException("Unknown SentinelAI:CentralUpdate setting.");
        var directory = section["Directory"] ?? AppContext.BaseDirectory;
        var stateFile = section["StateFile"] ?? (OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelAI-Setup", "central-update", "state.json")
            : null);
        if (!Path.IsPathFullyQualified(directory) || stateFile is not null && !Path.IsPathFullyQualified(stateFile))
            throw new InvalidOperationException("Central update paths must be absolute.");
        var path = Path.Combine(directory, ServerFileName);
        if (!File.Exists(path)) return new CentralUpdateOptions(null, stateFile);
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length is 0 or > 1024) throw new JsonException();
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Name is not ("url" or "channel") || property.Value.ValueKind != JsonValueKind.String ||
                    !fields.TryAdd(property.Name, property.Value.GetString()!)) throw new JsonException();
            }
            if (fields.Count != 2 || !CentralUpdateServer.IsServerUrl(fields["url"]) || fields["channel"] is not ("stable" or "pilot" or "beta"))
                throw new JsonException();
            return new CentralUpdateOptions(new CentralUpdateServer(fields["url"], fields["channel"]), stateFile);
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException("update-server.json must hold exactly an https:// url and a channel.");
        }
    }
}

/// <summary>Administrator choices: checking is off until enabled; night-time installation is on once it is.</summary>
public sealed class CentralUpdateStore(AdminStore admins)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS CentralUpdateSettings (
                Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1),
                CheckEnabled INTEGER NOT NULL CHECK (CheckEnabled IN (0, 1)),
                AutoInstall INTEGER NOT NULL CHECK (AutoInstall IN (0, 1))
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<(bool CheckEnabled, bool AutoInstall)> LoadAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT CheckEnabled, AutoInstall FROM CentralUpdateSettings WHERE Singleton = 1;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? (reader.GetInt64(0) == 1, reader.GetInt64(1) == 1) : (false, true);
    }

    public async Task SaveAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO CentralUpdateSettings (Singleton, CheckEnabled, AutoInstall) VALUES (1, $check, $auto)
            ON CONFLICT(Singleton) DO UPDATE SET CheckEnabled = excluded.CheckEnabled, AutoInstall = excluded.AutoInstall;
            """;
        command.Parameters.AddWithValue("$check", checkEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$auto", autoInstall ? 1 : 0);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private SqliteConnection CreateConnection() => new(new SqliteConnectionStringBuilder
    {
        DataSource = admins.DatabasePath,
        Mode = SqliteOpenMode.ReadWrite,
        DefaultTimeout = 30
    }.ToString());
}

/// <summary>
/// MVP-7: while an administrator has enabled it, checks the owner's update server shortly after start, every six hours
/// and on request, and downloads a newer Setup into <c>&lt;data&gt;\central-update</c>. Core only checks that the
/// transfer matches the manifest; the central computer's SYSTEM update task verifies the signature with the key pinned
/// at installation before it runs that Setup, at night when <c>auto-install</c> is present, or when an administrator
/// selects Install in Desktop. Core never follows redirects or URLs other than the configured server's.
/// </summary>
public sealed class CentralUpdateService(
    CentralUpdateOptions options,
    string stagingDirectory,
    CentralUpdateStore store,
    HttpClient httpClient,
    TimeProvider time,
    ILogger<CentralUpdateService> logger) : BackgroundService
{
    public const string ManifestFileName = "SentinelAI-Setup.manifest.json";
    public const string PackageFileName = "SentinelAI-Setup.exe";
    public const string AutoInstallMarker = "auto-install";
    public const string ArtifactId = UpdateManifestFormat.SetupArtifactId;
    public static readonly TimeSpan FirstCheckDelay = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    public static readonly TimeSpan RetryInterval = TimeSpan.FromHours(1);
    private const int MaximumStateBytes = 4096;

    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _wake = new(0, 1);
    private string _lastCheck = "never";
    private DateTimeOffset? _lastCheckUtc;
    private bool _checkRequested;

    /// <summary>This Core's release, as <c>major.minor.patch</c>.</summary>
    public static Version InstalledVersion { get; } = Release(typeof(CentralUpdateService).Assembly.GetName().Version);

    public async Task<CentralUpdateStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var (checkEnabled, autoInstall) = await store.LoadAsync(cancellationToken);
        string lastCheck;
        DateTimeOffset? lastCheckUtc;
        lock (_gate) { lastCheck = _lastCheck; lastCheckUtc = _lastCheckUtc; }
        var ready = ReadStaged();
        var (attempts, lastAttempt) = ready is null ? (0, (DateTimeOffset?)null) : ReadAttempts(ready.Value.Fingerprint);
        return new CentralUpdateStatus(options.Server is not null, options.Server?.Host, options.Server is not null && checkEnabled, autoInstall,
            Format(InstalledVersion), lastCheck, lastCheckUtc, ready?.Version, attempts, lastAttempt);
    }

    /// <summary>Saves the administrator's choices; null when this build has no update server.</summary>
    public async Task<CentralUpdateStatus?> SetSettingsAsync(bool checkEnabled, bool autoInstall, CancellationToken cancellationToken)
    {
        if (options.Server is null) return null;
        await store.SaveAsync(checkEnabled, autoInstall, cancellationToken);
        if (checkEnabled) RequestCheck();
        ApplySettings(checkEnabled, autoInstall);
        return await GetStatusAsync(cancellationToken);
    }

    /// <summary>Starts a check now; false when updates are not configured or not enabled.</summary>
    public async Task<CentralUpdateStatus?> CheckNowAsync(CancellationToken cancellationToken)
    {
        if (options.Server is null || !(await store.LoadAsync(cancellationToken)).CheckEnabled) return null;
        RequestCheck();
        lock (_gate) if (_lastCheck != "checking") _lastCheck = "checking";
        return await GetStatusAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var due = time.GetUtcNow() + FirstCheckDelay;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var (checkEnabled, autoInstall) = await store.LoadAsync(stoppingToken);
                ApplySettings(checkEnabled, autoInstall);
                bool requested;
                lock (_gate) { requested = _checkRequested; _checkRequested = false; }
                if (options.Server is not null && checkEnabled && (requested || time.GetUtcNow() >= due))
                {
                    var result = await CheckAsync(options.Server, stoppingToken);
                    lock (_gate) { _lastCheck = result; _lastCheckUtc = time.GetUtcNow(); }
                    // The download may have finished after the administrator turned checking off.
                    var current = await store.LoadAsync(stoppingToken);
                    ApplySettings(current.CheckEnabled, current.AutoInstall);
                    due = time.GetUtcNow() + (result == "failed" ? RetryInterval : CheckInterval);
                    continue;
                }

                var wait = options.Server is not null && checkEnabled ? due - time.GetUtcNow() : Timeout.InfiniteTimeSpan;
                if (wait != Timeout.InfiniteTimeSpan && wait <= TimeSpan.Zero) continue;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                await Task.WhenAny(_wake.WaitAsync(cancellation.Token), Task.Delay(wait, time, cancellation.Token));
                await cancellation.CancelAsync();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                // Updates never stop Core; the next attempt follows the retry interval.
                logger.LogWarning("Checking for a SentinelAI update failed with {ExceptionType}", exception.GetType().Name);
                due = time.GetUtcNow() + RetryInterval;
                try { await Task.Delay(TimeSpan.FromSeconds(30), time, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    /// <summary>One check: "current", "ready" or "failed".</summary>
    internal async Task<string> CheckAsync(CentralUpdateServer server, CancellationToken cancellationToken)
    {
        byte[] manifestBytes;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            try
            {
                using var response = await httpClient.GetAsync(server.ManifestUri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    ClearStaged();
                    return "current";
                }
                if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength is > UpdateManifestFormat.MaximumDocumentBytes)
                    return Fail("manifest-status-" + (int)response.StatusCode);
                manifestBytes = await ReadBoundedAsync(response, UpdateManifestFormat.MaximumDocumentBytes, timeout.Token);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException ||
                                              exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                return Fail("server-unreachable-" + exception.GetType().Name);
            }
        }

        // A filter only: the SYSTEM update task authenticates the manifest before it runs anything.
        if (UpdateManifestFormat.ReadUnauthenticated(manifestBytes) is not { ArtifactId: ArtifactId, Environment: "development" } manifest ||
            manifest.Channel != server.Channel || !UpdateManifestFormat.TryParseVersion(manifest.Version, out var offered) ||
            manifest.ArtifactUrl != server.PackageUrl(manifest.Version))
            return Fail("manifest-not-this-channels-setup");
        if (offered <= InstalledVersion)
        {
            ClearStaged();
            return "current";
        }

        var directory = stagingDirectory;
        var manifestPath = Path.Combine(directory, ManifestFileName);
        var packagePath = Path.Combine(directory, PackageFileName);
        if (File.Exists(manifestPath) && File.Exists(packagePath) &&
            (await File.ReadAllBytesAsync(manifestPath, cancellationToken)).AsSpan().SequenceEqual(manifestBytes) &&
            new FileInfo(packagePath).Length == manifest.SizeBytes && await MatchesAsync(packagePath, manifest.Sha256, cancellationToken))
            return "ready";

        Directory.CreateDirectory(directory);
        var partial = packagePath + ".partial";
        // A stalled server cannot hold the check forever.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromHours(2));
        try
        {
            using var response = await httpClient.GetAsync(new Uri(manifest.ArtifactUrl), HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.StatusCode != HttpStatusCode.OK) return Fail("setup-status-" + (int)response.StatusCode);
            if (!await DownloadAsync(response, partial, manifest, deadline.Token)) return Fail("setup-does-not-match-manifest");
            // The update task reads the manifest first: without one, a Setup being replaced is never picked up.
            File.Delete(manifestPath);
            File.Move(partial, packagePath, overwrite: true);
            await File.WriteAllBytesAsync(manifestPath, manifestBytes, cancellationToken);
            logger.LogInformation("SentinelAI {Version} downloaded from the update server", manifest.Version);
            return "ready";
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return Fail("setup-download-" + exception.GetType().Name);
        }
        finally
        {
            try { File.Delete(partial); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }
    }

    public override void Dispose()
    {
        _wake.Dispose();
        base.Dispose();
    }

    private void RequestCheck()
    {
        lock (_gate) _checkRequested = true;
        try { _wake.Release(); }
        catch (SemaphoreFullException) { }
    }

    /// <summary>Logs a fixed reason only, never server text.</summary>
    private string Fail(string reason)
    {
        logger.LogWarning("Checking for a SentinelAI update failed: {Reason}", reason);
        return "failed";
    }

    /// <summary>The night-time marker exists exactly while checking and automatic installation are on; off removes the download.</summary>
    private void ApplySettings(bool checkEnabled, bool autoInstall)
    {
        var marker = Path.Combine(stagingDirectory, AutoInstallMarker);
        try
        {
            if (options.Server is null || !checkEnabled)
            {
                ClearStaged();
                File.Delete(marker);
            }
            else
            {
                // After an upgrade the downloaded Setup is this version or older: it is removed without waiting for a check.
                if (File.Exists(Path.Combine(stagingDirectory, ManifestFileName)) && ReadStaged() is null) ClearStaged();
                if (autoInstall)
                {
                    Directory.CreateDirectory(stagingDirectory);
                    if (!File.Exists(marker)) File.WriteAllBytes(marker, []);
                }
                else File.Delete(marker);
            }
        }
        catch (DirectoryNotFoundException) { }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // For example the update task is copying the Setup; the next check applies the settings again.
            logger.LogWarning("Applying the SentinelAI update settings to the download folder failed with {ExceptionType}", exception.GetType().Name);
        }
    }

    private void ClearStaged()
    {
        foreach (var name in new[] { ManifestFileName, PackageFileName, PackageFileName + ".partial" })
        {
            try { File.Delete(Path.Combine(stagingDirectory, name)); }
            catch (DirectoryNotFoundException) { }
        }
    }

    /// <summary>The downloaded release and its manifest's SHA-256, when a newer one is ready.</summary>
    private (string Version, string Fingerprint)? ReadStaged()
    {
        try
        {
            var path = Path.Combine(stagingDirectory, ManifestFileName);
            if (!File.Exists(path) || !File.Exists(Path.Combine(stagingDirectory, PackageFileName))) return null;
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length > UpdateManifestFormat.MaximumDocumentBytes || UpdateManifestFormat.ReadUnauthenticated(bytes) is not { } manifest ||
                !UpdateManifestFormat.TryParseVersion(manifest.Version, out var version) || version <= InstalledVersion) return null;
            return (manifest.Version, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The update task's attempts for exactly this download; anything unreadable counts as none.</summary>
    private (int Attempts, DateTimeOffset? Last) ReadAttempts(string fingerprint)
    {
        try
        {
            if (options.StateFile is null || !File.Exists(options.StateFile)) return (0, null);
            var bytes = File.ReadAllBytes(options.StateFile);
            if (bytes.Length is 0 or > MaximumStateBytes) return (0, null);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("manifestSha256", out var sha) || sha.GetString() != fingerprint ||
                !root.TryGetProperty("attempts", out var attempts) || !attempts.TryGetInt32(out var count) || count is < 0 or > 1000 ||
                !root.TryGetProperty("lastAttemptUtc", out var last) || !DateTimeOffset.TryParse(last.GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var lastAttempt)) return (0, null);
            return (count, lastAttempt);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return (0, null);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, int maximum, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maximum) throw new InvalidDataException("The update manifest exceeds its limit.");
            buffer.Write(chunk, 0, read);
        }
        if (buffer.Length == 0) throw new InvalidDataException("The update manifest is empty.");
        return buffer.ToArray();
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

    private static async Task<bool> MatchesAsync(string path, string sha256, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous);
        return string.Equals(Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken)), sha256, StringComparison.Ordinal);
    }

    private static Version Release(Version? version) =>
        version is null ? new Version(0, 0, 0) : new Version(version.Major, Math.Max(version.Minor, 0), Math.Max(version.Build, 0));

    private static string Format(Version version) => version.ToString(3);
}
