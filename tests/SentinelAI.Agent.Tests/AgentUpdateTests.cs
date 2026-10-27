using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Agent;
using SentinelAI.Updates;

/// <summary>
/// MVP-7: the Agent fetches a newer Agent package that Core offers, checks only that the transfer matches the manifest
/// and leaves signature verification to the SYSTEM updater. Synthetic manifests carry a random, never-verified
/// signature: no key is generated or used here.
/// </summary>
internal static class AgentUpdateTests
{
    public static async Task RunAsync(string root)
    {
        Directory.CreateDirectory(root);
        var enrollment = new EnrollmentState(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), "https://core.example.invalid:5443", null);
        var installed = new Version(1, 0, 0);
        var package = RandomNumberGenerator.GetBytes(48 * 1024 + 5);
        var newer = Manifest("1.1.0", package);
        var core = new FakeCore();
        var options = new AgentOptions(new Uri("https://core.example.invalid:5443"), Path.Combine(root, "data"),
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(1), null, null);
        var stager = new AgentUpdateStager(new HttpClient(core), options, NullLogger<AgentUpdateStager>.Instance);
        var manifestPath = Path.Combine(stager.StagingDirectory, AgentUpdateStager.ManifestFileName);
        var packagePath = Path.Combine(stager.StagingDirectory, AgentUpdateStager.PackageFileName);
        bool Staged() => File.Exists(manifestPath) && File.Exists(packagePath);
        bool NoPartials() => !Directory.Exists(stager.StagingDirectory) ||
                             !Directory.EnumerateFiles(stager.StagingDirectory, "*.partial").Any();

        Check(AgentUpdateStager.Release(new Version(1, 2, 3, 0)) == new Version(1, 2, 3) &&
              AgentUpdateStager.Release(new Version(4, 5)) == new Version(4, 5, 0) &&
              AgentUpdateStager.Release(null) == new Version(0, 0, 0), "The Agent release version is not major.minor.patch.");

        // Nothing offered: nothing is fetched or kept.
        Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.NotOffered &&
              core.PackageRequests == 0 && !Staged(), "A Core without an Agent package caused a download.");
        Check(core.LastAuthorization == $"SentinelAgent {enrollment.EndpointId:D}.{enrollment.AgentCredential}",
            "The update check did not authenticate as the enrolled Agent.");

        // A newer package is fetched exactly once and kept byte for byte.
        core.Offer(newer, package);
        Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.Staged &&
              Staged() && File.ReadAllBytes(manifestPath).AsSpan().SequenceEqual(newer) &&
              File.ReadAllBytes(packagePath).AsSpan().SequenceEqual(package) && NoPartials() && core.PackageRequests == 1,
            "A newer Agent package was not staged exactly.");
        Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.AlreadyStaged &&
              core.PackageRequests == 1, "A staged Agent package was downloaded again.");

        // Once this Agent runs that release (or a newer one), the staged copy is removed.
        Check(await stager.CheckAsync(enrollment, new Version(1, 1, 0), CancellationToken.None) == AgentUpdateCheck.Current &&
              !Staged(), "The staged package survived the update it carried.");
        core.Offer(Manifest("0.9.9", package), package);
        Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.Current &&
              !Staged() && core.PackageRequests == 1, "An older Agent package was fetched.");

        // A transfer that does not match the manifest is never kept.
        foreach (var (served, label) in new (byte[], string)[]
                 {
                     (Tamper(package), "a changed byte"), (package[..^1], "a short package"), ([.. package, 0], "a long package")
                 })
        {
            core.Offer(newer, served);
            Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.Rejected &&
                  !Staged() && NoPartials(), $"The Agent staged a package with {label}.");
        }

        // A malformed or foreign manifest is refused before any package request.
        var requests = core.PackageRequests;
        foreach (var manifest in new[]
                 {
                     "{}"u8.ToArray(), Manifest("1.1.0", package, artifactId: "sentinelai-core-win-x64"), Manifest("1.1", package)
                 })
        {
            core.Offer(manifest, package);
            Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.Rejected &&
                  !Staged(), "The Agent accepted a manifest that is not a well-formed Agent manifest.");
        }

        Check(core.PackageRequests == requests, "A rejected manifest still caused a package download.");

        // Core unreachable: a failure, retried later, with nothing kept.
        core.Fail = true;
        Check(await stager.CheckAsync(enrollment, installed, CancellationToken.None) == AgentUpdateCheck.Failed && !Staged(),
            "An unreachable Core was not reported as a failed check.");
        core.Fail = false;

        // The worker checks soon after the Agent links to Core, and only then.
        core.Offer(newer, package);
        var link = new AgentLink();
        var quick = options with { UpdateCheckDelay = TimeSpan.FromMilliseconds(100), UpdateCheckInterval = TimeSpan.FromHours(1) };
        var worker = new AgentUpdateWorker(link, new AgentUpdateStager(new HttpClient(core), quick, NullLogger<AgentUpdateStager>.Instance),
            quick, TimeProvider.System, NullLogger<AgentUpdateWorker>.Instance);
        var before = core.ManifestRequests;
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await Task.Delay(400);
            Check(core.ManifestRequests == before, "The Agent checked for an update before it was linked to Core.");
            link.Publish(enrollment);
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!Staged() && DateTime.UtcNow < deadline) await Task.Delay(50);
            Check(Staged() && core.ManifestRequests == before + 1, "The linked Agent did not check for an update once.");
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }

        Console.WriteLine("Agent update staging tests passed (version decision, exact transfer, no re-download, cleanup, " +
                          "malformed manifests, unreachable Core, linked schedule).");
    }

    private static byte[] Manifest(string version, byte[] package, string artifactId = AgentUpdateStager.ArtifactId)
    {
        // Version text that is not canonical cannot be written; such a manifest is built by hand.
        if (!UpdateManifestFormat.TryParseVersion(version, out _))
            return System.Text.Encoding.UTF8.GetBytes(
                "{\"format\":\"sentinelai-update-v1\",\"keyId\":\"dev-test\",\"manifest\":{\"version\":\"" + version + "\"}}");
        var manifest = new UpdateManifest(version, artifactId, "https://updates.example.invalid/agent.zip",
            Convert.ToHexStringLower(SHA256.HashData(package)), package.Length, "pilot", "development");
        return UpdateManifestFormat.SerializeSigned(manifest, "dev-test", RandomNumberGenerator.GetBytes(64));
    }

    private static byte[] Tamper(byte[] package)
    {
        var copy = package.ToArray();
        copy[copy.Length / 2] ^= 0x5A;
        return copy;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private sealed class FakeCore : HttpMessageHandler
    {
        private byte[]? _manifest;
        private byte[]? _package;
        public bool Fail { get; set; }
        public int ManifestRequests { get; private set; }
        public int PackageRequests { get; private set; }
        public string? LastAuthorization { get; private set; }

        public void Offer(byte[] manifest, byte[] package) => (_manifest, _package) = (manifest, package);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Fail) throw new HttpRequestException("Synthetic unreachable Core.");
            LastAuthorization = request.Headers.Authorization?.ToString();
            var path = request.RequestUri!.AbsolutePath;
            byte[]? body;
            string type;
            if (request.Method == HttpMethod.Get && path == "/api/agent/update/manifest")
            {
                ManifestRequests++;
                (body, type) = (_manifest, "application/json");
            }
            else if (request.Method == HttpMethod.Get && path == "/api/agent/update/package")
            {
                PackageRequests++;
                (body, type) = (_package, "application/zip");
            }
            else return Task.FromResult(new HttpResponseMessage(HttpStatusCode.MethodNotAllowed));

            if (body is null) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(type);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }
}
