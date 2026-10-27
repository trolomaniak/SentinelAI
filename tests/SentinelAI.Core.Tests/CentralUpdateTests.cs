using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Core;
using SentinelAI.Updates;

/// <summary>
/// MVP-7: the optional central update from the owner's server. A scripted in-process server and synthetic Setup bytes
/// only; manifests carry a random signature because Core never decides trust (the SYSTEM update task does).
/// </summary>
internal static class CentralUpdateTests
{
    private const string ServerUrl = "https://updates.example.invalid/sentinelai/pilot";

    public static async Task VerifyAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-central-update-tests-{Guid.NewGuid():N}");
        var serverDirectory = Path.Combine(root, "server");
        Directory.CreateDirectory(serverDirectory);
        try
        {
            VerifyOptions(root);
            await File.WriteAllTextAsync(Path.Combine(serverDirectory, CentralUpdateOptions.ServerFileName),
                "{\"url\":\"" + ServerUrl + "\",\"channel\":\"pilot\"}");
            await VerifyCheckerAsync(root, serverDirectory);
            await VerifyRoutesAsync(root, serverDirectory);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }

        Console.WriteLine("Central update tests passed (server file, off by default, settings and night marker, exact download, " +
                          "no re-download, damaged copy, channel/artifact/URL/redirect/size refusals, older offers, attempts, routes).");
    }

    private static void VerifyOptions(string root)
    {
        var directory = Path.Combine(root, "options");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, CentralUpdateOptions.ServerFileName);
        CentralUpdateOptions Load() => CentralUpdateOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SentinelAI:CentralUpdate:Directory"] = directory,
            ["SentinelAI:CentralUpdate:StateFile"] = Path.Combine(directory, "state.json")
        }).Build());

        Check(Load().Server is null, "A build without update-server.json offered central updates.");
        File.WriteAllText(path, "{\"url\":\"" + ServerUrl + "\",\"channel\":\"pilot\"}");
        Check(Load().Server is { Url: ServerUrl, Channel: "pilot", Host: "updates.example.invalid" }, "A valid update server was not loaded.");
        foreach (var invalid in new[]
                 {
                     "{\"url\":\"http://updates.example.invalid/sentinelai\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://updates.example.invalid/sentinelai/\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://Updates.example.invalid\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://updates.example.invalid/x?y=1\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://user@updates.example.invalid\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://updates.example.invalid/%2e%2e\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://updates.example.invalid:65536/sentinelai\",\"channel\":\"pilot\"}",
                     "{\"url\":\"https://updates.example.invalid:99999/sentinelai\",\"channel\":\"pilot\"}",
                     "{\"url\":\"" + ServerUrl + "\",\"channel\":\"nightly\"}",
                     "{\"url\":\"" + ServerUrl + "\"}",
                     "{\"url\":\"" + ServerUrl + "\",\"channel\":\"pilot\",\"key\":\"x\"}",
                     "[]"
                 })
        {
            File.WriteAllText(path, invalid);
            Reject(() => Load(), "An invalid update-server.json was accepted: " + invalid);
        }

        Reject(() => CentralUpdateOptions.Load(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SentinelAI:CentralUpdate:Url"] = ServerUrl
        }).Build()), "An unknown central update setting was accepted.");
    }

    private static async Task VerifyCheckerAsync(string root, string serverDirectory)
    {
        var stateFile = Path.Combine(root, "state", "state.json");
        await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "checker")}",
            $"--SentinelAI:CentralUpdate:Directory={serverDirectory}", $"--SentinelAI:CentralUpdate:StateFile={stateFile}"]);
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        try
        {
            var options = app.Services.GetRequiredService<CentralUpdateOptions>();
            var store = app.Services.GetRequiredService<CentralUpdateStore>();
            var staging = Path.Combine(root, "staging");
            var server = new FakeServer();
            using var service = new CentralUpdateService(options, staging, store, new HttpClient(server), TimeProvider.System,
                NullLogger<CentralUpdateService>.Instance);
            var manifestPath = Path.Combine(staging, CentralUpdateService.ManifestFileName);
            var packagePath = Path.Combine(staging, CentralUpdateService.PackageFileName);
            var marker = Path.Combine(staging, CentralUpdateService.AutoInstallMarker);
            bool Staged() => File.Exists(manifestPath) || File.Exists(packagePath);

            var status = await service.GetStatusAsync(CancellationToken.None);
            Check(status is { Configured: true, CheckEnabled: false, AutoInstall: true, LastCheck: "never", ReadyVersion: null } &&
                  status.InstalledVersion == CentralUpdateService.InstalledVersion.ToString(3), "Checking was not off by default with night-time installation on.");
            Check(await service.CheckNowAsync(CancellationToken.None) is null, "A check started while checking was off.");

            status = (await service.SetSettingsAsync(true, true, CancellationToken.None))!;
            Check(status.CheckEnabled && status.AutoInstall && File.Exists(marker), "Enabling checking did not mark the night-time installation.");

            var installed = CentralUpdateService.InstalledVersion;
            var newer = $"{installed.Major + 1}.0.0";
            var setup = RandomNumberGenerator.GetBytes(256 * 1024 + 3);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "current" && server.PackageRequests == 0,
                "A server without a manifest was not reported as current.");

            server.Offer(Manifest(newer, setup), setup);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "ready" && server.PackageRequests == 1 &&
                  File.ReadAllBytes(packagePath).AsSpan().SequenceEqual(setup) &&
                  File.ReadAllBytes(manifestPath).AsSpan().SequenceEqual(server.ManifestBytes!) &&
                  !File.Exists(packagePath + ".partial"), "A newer Setup was not downloaded exactly.");
            status = await service.GetStatusAsync(CancellationToken.None);
            Check(status.ReadyVersion == newer && status.InstallAttempts == 0, "The downloaded release was not reported as ready.");
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "ready" && server.PackageRequests == 1,
                "A downloaded Setup was downloaded again.");
            var damaged = File.ReadAllBytes(packagePath);
            damaged[damaged.Length / 2] ^= 0x01;
            File.WriteAllBytes(packagePath, damaged);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "ready" && server.PackageRequests == 2 &&
                  File.ReadAllBytes(packagePath).AsSpan().SequenceEqual(setup), "A damaged download was not replaced.");

            // The update task's attempts count only for exactly this download.
            Directory.CreateDirectory(Path.GetDirectoryName(stateFile)!);
            var fingerprint = Convert.ToHexStringLower(SHA256.HashData(server.ManifestBytes!));
            File.WriteAllText(stateFile, "{\"manifestSha256\":\"" + fingerprint + "\",\"version\":\"" + newer + "\",\"attempts\":2,\"lastAttemptUtc\":\"2026-10-27T02:30:00Z\"}");
            status = await service.GetStatusAsync(CancellationToken.None);
            Check(status.InstallAttempts == 2 && status.LastAttemptUtc == new DateTimeOffset(2026, 10, 27, 2, 30, 0, TimeSpan.Zero),
                "The update task's attempts were not reported.");
            File.WriteAllText(stateFile, "{\"manifestSha256\":\"" + new string('0', 64) + "\",\"attempts\":2,\"lastAttemptUtc\":\"2026-10-27T02:30:00Z\"}");
            Check((await service.GetStatusAsync(CancellationToken.None)).InstallAttempts == 0, "Another release's attempts were reported.");

            status = (await service.SetSettingsAsync(true, false, CancellationToken.None))!;
            Check(!status.AutoInstall && !File.Exists(marker) && Staged(), "Turning off night-time installation removed the download or kept the marker.");
            await service.SetSettingsAsync(false, true, CancellationToken.None);
            Check(!Staged() && !File.Exists(marker), "Turning checking off kept the download.");
            await service.SetSettingsAsync(true, true, CancellationToken.None);

            // Offers that are not this channel's newer SentinelAI Setup at the server's own address are never downloaded.
            var requests = server.PackageRequests;
            foreach (var (label, document) in new (string, byte[])[]
                     {
                         ("another channel", Manifest(newer, setup, channel: "beta")),
                         ("another artifact", Manifest(newer, setup, artifactId: "sentinelai-deployment-win-x64")),
                         ("another address", Manifest(newer, setup, url: "https://elsewhere.example.invalid/" + newer + "/SentinelAI-Setup.exe")),
                         ("production trust", Manifest(newer, setup, environment: "production")),
                         ("malformed", Encoding.UTF8.GetBytes("{\"format\":\"sentinelai-update-v1\"}")),
                         ("oversized", new byte[UpdateManifestFormat.MaximumDocumentBytes + 1])
                     })
            {
                server.Offer(document, setup);
                Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "failed" && server.PackageRequests == requests && !Staged(),
                    $"Core downloaded an offer with {label}.");
            }

            server.Offer(Manifest(newer, setup), RandomNumberGenerator.GetBytes(setup.Length));
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "failed" && !Staged(), "A Setup that does not match its manifest was kept.");
            server.Redirect = true;
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "failed" && !Staged(), "Core followed a redirect.");
            server.Redirect = false;

            server.Offer(Manifest(newer, setup), setup);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "ready" && Staged(), "The release was not downloaded again.");
            // After an upgrade, applying the settings again removes a download that is no longer newer.
            File.WriteAllBytes(manifestPath, Manifest(installed.ToString(3), setup));
            await service.SetSettingsAsync(true, true, CancellationToken.None);
            Check(!Staged() && File.Exists(marker), "A download that is not newer survived the settings.");
            server.Offer(Manifest(newer, setup), setup);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "ready" && Staged(), "The release was not downloaded once more.");
            server.Offer(Manifest(installed.ToString(3), setup), setup);
            Check(await service.CheckAsync(options.Server!, CancellationToken.None) == "current" && !Staged(),
                "A download survived the update it carried.");

            // Check now through the running worker: its result is never overwritten by "checking".
            await service.StartAsync(CancellationToken.None);
            Check((await service.CheckNowAsync(CancellationToken.None))?.LastCheck is "checking" or "current", "Check now did not report the check.");
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while ((await service.GetStatusAsync(CancellationToken.None)).LastCheck != "current" && DateTime.UtcNow < deadline) await Task.Delay(50);
            Check((await service.GetStatusAsync(CancellationToken.None)).LastCheck == "current", "The worker's check result was not kept.");

            // Turning checking off ends a download in progress: no update connection stays open and nothing is staged.
            server.Offer(Manifest(newer, setup), setup);
            server.HoldPackage = true;
            requests = server.PackageRequests;
            Check((await service.CheckNowAsync(CancellationToken.None))?.LastCheck == "checking", "Check now did not report a check in progress.");
            await server.PackageHeld.Task.WaitAsync(TimeSpan.FromSeconds(30));
            status = (await service.SetSettingsAsync(false, true, CancellationToken.None))!;
            Check(!status.CheckEnabled && status.LastCheck == "never", "Turning checking off still reported a check.");
            await server.PackageReleased.Task.WaitAsync(TimeSpan.FromSeconds(30));
            await service.StopAsync(CancellationToken.None);
            Check(server.PackageRequests == requests + 1 && !Staged() && !File.Exists(packagePath + ".partial") && !File.Exists(marker),
                "A download continued after checking was turned off.");
            server.HoldPackage = false;
            Check(server.Requests.All(uri => uri.AbsoluteUri.StartsWith(ServerUrl + "/", StringComparison.Ordinal)),
                "Core requested an address outside the configured update server.");
        }
        finally
        {
            await app.StopAsync();
        }

        // A build without an update server accepts no settings and starts no check.
        await using var plain = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "plain")}",
            $"--SentinelAI:CentralUpdate:Directory={Path.Combine(root, "no-server")}"]);
        plain.Urls.Clear();
        plain.Urls.Add("http://127.0.0.1:0");
        await plain.StartAsync();
        try
        {
            var service = plain.Services.GetRequiredService<CentralUpdateService>();
            Check((await service.GetStatusAsync(CancellationToken.None)).Configured == false &&
                  await service.SetSettingsAsync(true, true, CancellationToken.None) is null &&
                  await service.CheckNowAsync(CancellationToken.None) is null, "A build without an update server accepted update settings.");
        }
        finally
        {
            await plain.StopAsync();
        }
    }

    private static async Task VerifyRoutesAsync(string root, string serverDirectory)
    {
        await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "routes")}",
            $"--SentinelAI:CentralUpdate:Directory={serverDirectory}", $"--SentinelAI:CentralUpdate:StateFile={Path.Combine(root, "routes-state.json")}"]);
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        try
        {
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
            };
            using (var anonymous = await client.GetAsync("/api/admin/updates"))
                Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Update status was readable without signing in.");
            using var login = await client.PostAsJsonAsync("/api/auth/login", new
            {
                username = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME"),
                password = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD")
            });
            Check(login.StatusCode == HttpStatusCode.OK, "The test administrator could not sign in.");
            using var auth = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auth.RootElement.GetProperty("accessToken").GetString());

            var status = await ReadAsync(client, HttpMethod.Get, "/api/admin/updates", null, HttpStatusCode.OK);
            Check(status.GetProperty("configured").GetBoolean() && !status.GetProperty("checkEnabled").GetBoolean() &&
                  status.GetProperty("autoInstall").GetBoolean() && status.GetProperty("server").GetString() == "updates.example.invalid" &&
                  status.GetProperty("lastCheck").GetString() == "never", "The update status route did not report the default settings.");
            await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/check", null, HttpStatusCode.Conflict);
            foreach (var invalid in new[] { "{}", "{\"checkEnabled\":true}", "{\"checkEnabled\":\"yes\",\"autoInstall\":true}", "[]" })
                await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/settings", invalid, HttpStatusCode.BadRequest);
            status = await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/settings", "{\"checkEnabled\":true,\"autoInstall\":false}", HttpStatusCode.OK);
            Check(status.GetProperty("checkEnabled").GetBoolean() && !status.GetProperty("autoInstall").GetBoolean(), "The update settings were not saved.");
            status = await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/check", null, HttpStatusCode.OK);
            Check(status.GetProperty("lastCheck").GetString() is "checking" or "failed" or "current" or "ready", "A requested check was not reported.");
            status = await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/settings", "{\"checkEnabled\":false,\"autoInstall\":true}", HttpStatusCode.OK);
            Check(!status.GetProperty("checkEnabled").GetBoolean(), "Checking could not be turned off.");
            await ReadAsync(client, HttpMethod.Post, "/api/admin/updates/check", null, HttpStatusCode.Conflict);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static async Task<JsonElement> ReadAsync(HttpClient client, HttpMethod method, string path, string? body, HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == expected, $"{method} {path} answered {(int)response.StatusCode}, expected {(int)expected}.");
        if (response.StatusCode != HttpStatusCode.OK) return default;
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    private static byte[] Manifest(string version, byte[] package, string channel = "pilot", string artifactId = CentralUpdateService.ArtifactId,
        string? url = null, string environment = "development")
    {
        var manifest = new UpdateManifest(version, artifactId, url ?? ServerUrl + "/" + version + "/SentinelAI-Setup.exe",
            Convert.ToHexStringLower(SHA256.HashData(package)), package.Length, channel, environment);
        return UpdateManifestFormat.SerializeSigned(manifest, "dev-test", RandomNumberGenerator.GetBytes(64));
    }

    private sealed class FakeServer : HttpMessageHandler
    {
        private byte[]? _package;
        public byte[]? ManifestBytes { get; private set; }
        public bool Redirect { get; set; }
        public int PackageRequests { get; private set; }
        public List<Uri> Requests { get; } = [];
        /// <summary>Package requests wait until the client cancels them.</summary>
        public bool HoldPackage { get; set; }
        public TaskCompletionSource PackageHeld { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource PackageReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Offer(byte[] manifest, byte[] package)
        {
            ManifestBytes = manifest;
            _package = package;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            Requests.Add(uri);
            if (Redirect)
            {
                var moved = new HttpResponseMessage(HttpStatusCode.Found);
                moved.Headers.Location = new Uri("https://elsewhere.example.invalid/");
                return Task.FromResult(moved);
            }

            if (uri.AbsoluteUri == ServerUrl + "/SentinelAI-Setup.manifest.json")
                return Task.FromResult(ManifestBytes is null
                    ? new HttpResponseMessage(HttpStatusCode.NotFound)
                    : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(ManifestBytes) });
            if (uri.AbsolutePath.EndsWith("/SentinelAI-Setup.exe", StringComparison.Ordinal) && _package is not null)
            {
                PackageRequests++;
                if (HoldPackage) return HoldAsync(cancellationToken);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(_package) });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private async Task<HttpResponseMessage> HoldAsync(CancellationToken cancellationToken)
        {
            PackageHeld.TrySetResult();
            try { await Task.Delay(Timeout.Infinite, cancellationToken); }
            finally { PackageReleased.TrySetResult(); }
            throw new InvalidOperationException("A held package request completed.");
        }
    }

    private static void Reject(Action action, string message)
    {
        try { action(); }
        catch (InvalidOperationException) { return; }
        throw new InvalidOperationException(message);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
