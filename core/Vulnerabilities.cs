using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core.Persistence;
using SentinelAI.Rules.Vulnerabilities;
using SentinelAI.Updates;

namespace SentinelAI.Core;

/// <summary>
/// TASK-030: the update signing key, environment and channel built into Core (<c>update-trust.json</c>), with which Core
/// verifies vulnerability feeds. Public data only; a build without it accepts no feed.
/// </summary>
public sealed record UpdateTrust(string KeyId, string Channel, string PublicKeyPem)
{
    public const string FileName = "update-trust.json";
    public const string Environment = "development";

    internal static UpdateTrust Parse(byte[] bytes)
    {
        if (bytes.Length is 0 or > 4096) throw new InvalidDataException();
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 2 });
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Name is not ("format" or "keyId" or "environment" or "channel" or "publicKey") ||
                property.Value.ValueKind != JsonValueKind.String || !fields.TryAdd(property.Name, property.Value.GetString()!))
                throw new InvalidDataException();
        }

        if (fields.Count != 5 || fields["format"] != "sentinelai-update-trust-v1" || fields["environment"] != Environment ||
            !System.Text.RegularExpressions.Regex.IsMatch(fields["keyId"], @"\Adev-[A-Za-z0-9_-]{1,48}\z") ||
            fields["channel"] is not ("stable" or "pilot" or "beta")) throw new InvalidDataException();
        using var key = ECDsa.Create();
        key.ImportFromPem(fields["publicKey"]);
        if (key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new InvalidDataException();
        return new UpdateTrust(fields["keyId"], fields["channel"], fields["publicKey"]);
    }
}

public sealed record VulnerabilityOptions(UpdateTrust? Trust)
{
    public static VulnerabilityOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:Vulnerabilities");
        if (section.GetChildren().Any(child => child.Key != "Directory")) throw new InvalidOperationException("Unknown SentinelAI:Vulnerabilities setting.");
        var directory = section["Directory"] ?? AppContext.BaseDirectory;
        if (!Path.IsPathFullyQualified(directory)) throw new InvalidOperationException("The update trust directory must be absolute.");
        var path = Path.Combine(directory, UpdateTrust.FileName);
        if (!File.Exists(path)) return new VulnerabilityOptions((UpdateTrust?)null);
        try { return new VulnerabilityOptions(UpdateTrust.Parse(File.ReadAllBytes(path))); }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException or InvalidDataException or
                                              ArgumentException or CryptographicException or KeyNotFoundException)
        {
            throw new InvalidOperationException("update-trust.json must hold a development key ID, channel and P-256 public key.");
        }
    }
}

public sealed record VulnerabilityFeedInfo(
    string Version,
    DateTimeOffset GeneratedUtc,
    DateTimeOffset ImportedUtc,
    string Origin,
    IReadOnlyList<VulnerabilityFeedSourceView> Sources,
    int ProductCount,
    int VulnerabilityCount,
    int KnownExploitedCount,
    int SkippedAmbiguousConfigurations,
    int SkippedUnboundedVersions);

public sealed record VulnerabilityFeedSourceView(string Name, string Url, DateTimeOffset RetrievedUtc);

/// <summary>The feed's freshness is shown with every result; a feed older than <see cref="VulnerabilityService.StaleAfterDays"/> is stale.</summary>
public sealed record VulnerabilityStatus(
    bool Trusted,
    VulnerabilityFeedInfo? Feed,
    int? AgeDays,
    bool Stale,
    int StaleAfterDays,
    string LastServerCheck,
    DateTimeOffset? LastServerCheckUtc);

public sealed record VulnerabilityProgramView(string Name, string? Version, string? Publisher, string Coverage, string? ProductId);

public sealed record VulnerabilityFindingView(
    string Cve,
    string Product,
    string InstalledName,
    string InstalledVersion,
    string Severity,
    decimal? CvssScore,
    string? CvssVector,
    bool KnownExploited,
    string? KevDateAdded,
    string? FixedVersion,
    string Remediation);

public sealed record VulnerabilityCoverageCounts(int Covered, int Ambiguous, int UnsupportedVersion, int NotCovered);

/// <summary>One endpoint's assessment against the current feed, with the data it rests on.</summary>
public sealed record EndpointVulnerabilityView(
    Guid EndpointId,
    VulnerabilityStatus Status,
    DateTimeOffset? SoftwareCollectedUtc,
    string SoftwareAvailability,
    bool SoftwareTruncated,
    VulnerabilityProgramView? OperatingSystem,
    IReadOnlyList<VulnerabilityProgramView> Programs,
    VulnerabilityCoverageCounts Counts,
    IReadOnlyList<VulnerabilityFindingView> Findings);

public enum VulnerabilityImportResult { Imported, NotNewer, Rejected, Untrusted }

/// <summary>The verified feed in use and its matcher, shared by telemetry ingest and the routes.</summary>
public sealed class VulnerabilityFeedCache
{
    private volatile Loaded? _current;

    internal sealed record Loaded(VulnerabilityMatcher Matcher, VulnerabilityFeedInfo Info);

    internal Loaded? Current => _current;

    internal void Set(Loaded loaded) => _current = loaded;
}

public sealed class VulnerabilityFeedStore(AdminStore admins)
{
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS VulnerabilityFeed (
                Singleton INTEGER PRIMARY KEY CHECK (Singleton = 1),
                Version TEXT NOT NULL,
                ImportedUtcTicks INTEGER NOT NULL,
                Origin TEXT NOT NULL CHECK (Origin IN ('import', 'server')),
                Manifest BLOB NOT NULL,
                Feed BLOB NOT NULL
            );
            """;
        await create.ExecuteNonQueryAsync(cancellationToken);
    }

    internal async Task<(byte[] Manifest, byte[] Feed, DateTimeOffset ImportedUtc, string Origin)?> LoadAsync(CancellationToken cancellationToken)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT Manifest, Feed, ImportedUtcTicks, Origin FROM VulnerabilityFeed WHERE Singleton = 1;";
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? ((byte[])reader.GetValue(0), (byte[])reader.GetValue(1), new DateTimeOffset(reader.GetInt64(2), TimeSpan.Zero), reader.GetString(3))
            : null;
    }

    internal async Task SaveAsync(string version, byte[] manifest, byte[] feed, DateTimeOffset importedUtc, string origin, CancellationToken cancellationToken)
    {
        await using var connection = CreateConnection();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO VulnerabilityFeed (Singleton, Version, ImportedUtcTicks, Origin, Manifest, Feed)
            VALUES (1, $version, $imported, $origin, $manifest, $feed)
            ON CONFLICT (Singleton) DO UPDATE SET Version = excluded.Version, ImportedUtcTicks = excluded.ImportedUtcTicks,
                Origin = excluded.Origin, Manifest = excluded.Manifest, Feed = excluded.Feed;
            """;
        command.Parameters.AddWithValue("$version", version);
        command.Parameters.AddWithValue("$imported", importedUtc.UtcDateTime.Ticks);
        command.Parameters.AddWithValue("$origin", origin);
        command.Parameters.Add("$manifest", SqliteType.Blob).Value = manifest;
        command.Parameters.Add("$feed", SqliteType.Blob).Value = feed;
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
/// TASK-030: imports a signed vulnerability feed (from an administrator's file or the owner's update server), keeps it in
/// SQLite and assesses endpoints with it. The feed must verify with the built-in update trust, name the vulnerability feed
/// artifact, match its signed size and SHA-256 exactly and be newer than the feed in use, so an older feed is never
/// restored. Results rest only on the feed's deterministic product and version rules; no model decides them.
/// </summary>
public sealed class VulnerabilityService(
    VulnerabilityOptions options,
    VulnerabilityFeedStore store,
    VulnerabilityFeedCache cache,
    InventoryStore inventories,
    EndpointTelemetryStore telemetry,
    TimeProvider time,
    ILogger<VulnerabilityService> logger)
{
    public const int StaleAfterDays = 14;
    public const string ManifestFileName = "vulnerability-feed.manifest.json";
    public const string FeedFileName = "vulnerability-feed.json";
    private readonly object _gate = new();
    private readonly SemaphoreSlim _import = new(1, 1);
    private string _lastServerCheck = "never";
    private DateTimeOffset? _lastServerCheckUtc;

    public bool Trusted => options.Trust is not null;

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await store.InitializeAsync(cancellationToken);
        if (await store.LoadAsync(cancellationToken) is not { } stored) return;
        // Verified again, as on import: the database is no substitute for the signature.
        if (Verify(stored.Manifest, stored.Feed) is { } feed) cache.Set(Load(feed, stored.ImportedUtc, stored.Origin));
        else logger.LogWarning("The stored vulnerability feed did not verify with this installation's update trust; import a current feed.");
    }

    public async Task<(VulnerabilityImportResult Result, VulnerabilityStatus Status)> ImportAsync(byte[] manifest, byte[] feed, string origin,
        CancellationToken cancellationToken)
    {
        if (options.Trust is null) return (VulnerabilityImportResult.Untrusted, Status());
        await _import.WaitAsync(cancellationToken);
        try
        {
            if (Verify(manifest, feed) is not { } parsed) return (VulnerabilityImportResult.Rejected, Status());

            if (cache.Current is { } current && UpdateManifestFormat.TryParseVersion(current.Info.Version, out var installed) &&
                UpdateManifestFormat.TryParseVersion(parsed.Version, out var offered) && offered <= installed)
                return (VulnerabilityImportResult.NotNewer, Status());
            var now = time.GetUtcNow();
            await store.SaveAsync(parsed.Version, manifest, feed, now, origin, cancellationToken);
            cache.Set(Load(parsed, now, origin));
            logger.LogInformation("Vulnerability feed {Version} imported", parsed.Version);
            return (VulnerabilityImportResult.Imported, Status());
        }
        finally
        {
            _import.Release();
        }
    }

    /// <summary>The parsed feed when the manifest verifies with the update trust and describes exactly these bytes.</summary>
    private VulnerabilityFeed? Verify(byte[] manifest, byte[] feed)
    {
        if (options.Trust is not { } trust) return null;
        try
        {
            var verified = UpdateManifestVerifier.Verify(manifest, new UpdateVerificationPolicy(UpdateTrust.Environment, trust.Channel,
                VulnerabilityFeedFormat.ArtifactId, "0.0.0", new Dictionary<string, string>(StringComparer.Ordinal) { [trust.KeyId] = trust.PublicKeyPem }));
            if (feed.LongLength != verified.Manifest.SizeBytes || Convert.ToHexStringLower(SHA256.HashData(feed)) != verified.Manifest.Sha256) return null;
            var parsed = VulnerabilityFeedFormat.Parse(feed);
            return parsed.Version == verified.Manifest.Version ? parsed : null;
        }
        catch (Exception exception) when (exception is UpdateValidationException or InvalidDataException or ArgumentException)
        {
            return null;
        }
    }

    public VulnerabilityStatus Status()
    {
        var current = cache.Current;
        int? age = current is null ? null : (int)Math.Max(0, Math.Floor((time.GetUtcNow() - current.Info.GeneratedUtc).TotalDays));
        lock (_gate)
            return new VulnerabilityStatus(Trusted, current?.Info, age, age is null or > StaleAfterDays, StaleAfterDays, _lastServerCheck, _lastServerCheckUtc);
    }

    public async Task<EndpointVulnerabilityView> AssessAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        var stored = await telemetry.FindLatestAsync(endpointId, cancellationToken);
        var inventory = await inventories.FindLatestAsync(endpointId, cancellationToken);
        var software = stored?.Report.Software;
        var status = Status();
        if (cache.Current is not { } current)
            return new EndpointVulnerabilityView(endpointId, status, stored?.Report.CollectedUtc, software?.Availability ?? "missing",
                software?.Truncated ?? false, null, [], new VulnerabilityCoverageCounts(0, 0, 0, 0), []);
        var assessment = Assess(current.Matcher, software, inventory);
        var programs = assessment.Programs.Select(View).ToArray();
        return new EndpointVulnerabilityView(endpointId, status, stored?.Report.CollectedUtc, software?.Availability ?? "missing",
            software?.Truncated ?? false, assessment.OperatingSystem is { } system ? View(system) : null, programs,
            new VulnerabilityCoverageCounts(
                programs.Count(program => program.Coverage == VulnerabilityCoverage.Covered),
                programs.Count(program => program.Coverage == VulnerabilityCoverage.Ambiguous),
                programs.Count(program => program.Coverage == VulnerabilityCoverage.UnsupportedVersion),
                programs.Count(program => program.Coverage == VulnerabilityCoverage.NotCovered)),
            assessment.Findings.Select(finding => new VulnerabilityFindingView(finding.Cve, finding.ProductName, finding.InstalledName,
                finding.InstalledVersion, finding.Severity, finding.CvssScore, finding.CvssVector, finding.KnownExploited, finding.KevDateAdded,
                finding.FixedVersion, finding.Remediation)).ToArray());
    }

    /// <summary>
    /// TASK-030: fetches a newer feed from the owner's update server while checking is on: the manifest at the server
    /// root and the feed exactly at <c>&lt;URL&gt;/vulnerability-feed/&lt;version&gt;/vulnerability-feed.json</c>, without
    /// redirects. Returns "current", "imported" or "failed"; only the signature check decides what is used.
    /// </summary>
    internal async Task<string> CheckServerAsync(CentralUpdateServer server, HttpClient http, CancellationToken cancellationToken)
    {
        string result;
        try
        {
            result = await FetchAsync(server, http, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // A failure here (the network, a timeout or the database) never ends the update check it runs with; it is
            // recorded and retried with the next check. Only turning checking off cancels it.
            logger.LogWarning("Checking for a vulnerability feed failed with {ExceptionType}", exception.GetType().Name);
            result = "failed";
        }

        lock (_gate) { _lastServerCheck = result; _lastServerCheckUtc = time.GetUtcNow(); }
        return result;
    }

    private async Task<string> FetchAsync(CentralUpdateServer server, HttpClient http, CancellationToken cancellationToken)
    {
        if (!Trusted) return "failed";
        byte[] manifest;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            using var response = await http.GetAsync(new Uri(server.Url + "/" + ManifestFileName), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode == HttpStatusCode.NotFound) return "current";
            if (response.StatusCode != HttpStatusCode.OK) return "failed";
            manifest = await ReadBoundedAsync(response, UpdateManifestFormat.MaximumDocumentBytes, timeout.Token);
        }

        if (UpdateManifestFormat.ReadUnauthenticated(manifest) is not { ArtifactId: VulnerabilityFeedFormat.ArtifactId } offered ||
            offered.Channel != server.Channel || offered.ArtifactUrl != server.Url + "/vulnerability-feed/" + offered.Version + "/" + FeedFileName ||
            offered.SizeBytes is <= 0 or > VulnerabilityFeedFormat.MaximumBytes) return "failed";
        if (cache.Current is { } current && UpdateManifestFormat.TryParseVersion(current.Info.Version, out var installed) &&
            UpdateManifestFormat.TryParseVersion(offered.Version, out var version) && version <= installed) return "current";
        byte[] feed;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromMinutes(5));
            using var response = await http.GetAsync(new Uri(offered.ArtifactUrl), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK) return "failed";
            feed = await ReadBoundedAsync(response, (int)offered.SizeBytes, timeout.Token);
        }

        var (imported, _) = await ImportAsync(manifest, feed, "server", cancellationToken);
        return imported switch { VulnerabilityImportResult.Imported => "imported", VulnerabilityImportResult.NotNewer => "current", _ => "failed" };
    }

    /// <summary>The ingest-time assessment: the latest inventory supplies the Windows release, the report the programs.</summary>
    internal static VulnerabilityAssessment Assess(VulnerabilityMatcher matcher, InstalledSoftwareTelemetry? software, InventoryReport? inventory)
    {
        var programs = software is { Availability: TelemetryAvailability.Collected, Items: { } items }
            ? items.Select(item => new InstalledProgram(item.Name, item.Version, item.Publisher))
            : [];
        var system = inventory is { } report ? new OperatingSystemRelease(report.OsName, report.OsDisplayVersion, report.OsVersion) : null;
        return matcher.Assess(programs, system);
    }

    private static VulnerabilityProgramView View(ProgramAssessment assessment) =>
        new(assessment.Name, assessment.Version, assessment.Publisher, assessment.Coverage, assessment.ProductId);

    private static VulnerabilityFeedCache.Loaded Load(VulnerabilityFeed feed, DateTimeOffset importedUtc, string origin) =>
        new(new VulnerabilityMatcher(feed), new VulnerabilityFeedInfo(feed.Version, feed.GeneratedUtc, importedUtc, origin,
            feed.Sources.Select(source => new VulnerabilityFeedSourceView(source.Name, source.Url, source.RetrievedUtc)).ToArray(),
            feed.Products.Count, feed.Vulnerabilities.Count, feed.Vulnerabilities.Count(entry => entry.KnownExploited),
            feed.Skipped.AmbiguousConfigurations, feed.Skipped.UnboundedVersions));

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, int maximum, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > 0 and var length && length > maximum) throw new InvalidDataException();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maximum) throw new InvalidDataException();
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}

/// <summary>Strict import request: the signed manifest and the feed, each base64.</summary>
public sealed record VulnerabilityFeedImportRequest(string? Manifest, string? Feed);

internal static class VulnerabilityRequests
{
    /// <summary>Base64 for a feed at the maximum size plus the manifest and JSON.</summary>
    public const long MaximumImportRequestBytes = (VulnerabilityFeedFormat.MaximumBytes + UpdateManifestFormat.MaximumDocumentBytes + 2L) / 3 * 4 + 4096;

    public static bool TryDecode(VulnerabilityFeedImportRequest? request, out byte[] manifest, out byte[] feed)
    {
        manifest = [];
        feed = [];
        if (request is not { Manifest: { Length: > 0 } manifestText, Feed: { Length: > 0 } feedText }) return false;
        try
        {
            manifest = Convert.FromBase64String(manifestText);
            feed = Convert.FromBase64String(feedText);
        }
        catch (FormatException) { return false; }

        return manifest.Length is > 0 and <= UpdateManifestFormat.MaximumDocumentBytes && feed.Length is > 0 and <= VulnerabilityFeedFormat.MaximumBytes;
    }
}
