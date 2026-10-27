using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

/// <summary>
/// MVP-7: Core serves this release's signed Agent package to enrolled Agents, unchanged and only after authentication.
/// Synthetic manifest text and package bytes only; Core never interprets them.
/// </summary>
internal static class AgentUpdateApiTests
{
    private const string ManifestPath = "/api/agent/update/manifest";
    private const string PackagePath = "/api/agent/update/package";

    public static async Task VerifyAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-agent-update-tests-{Guid.NewGuid():N}");
        var packageDirectory = Path.Combine(root, "agent-update");
        Directory.CreateDirectory(packageDirectory);
        try
        {
            Reject(() => Build(Path.Combine(root, "relative"), "agent-update"), "A relative Agent update directory was accepted.");
            Reject(() => CoreHost.Build([$"--SentinelAI:DataDirectory={Path.Combine(root, "unknown")}",
                "--SentinelAI:AgentUpdate:Url=https://updates.example.invalid/"]), "An unknown Agent update setting was accepted.");

            await using var app = Build(Path.Combine(root, "data"), packageDirectory);
            using var client = await StartAsync(app);
            var agent = await EnrollAsync(app);

            // A build without the package offers none.
            Check(await StatusAsync(client, ManifestPath, agent) == HttpStatusCode.NotFound &&
                  await StatusAsync(client, PackagePath, agent) == HttpStatusCode.NotFound, "Core offered a missing Agent package.");

            var manifest = Encoding.UTF8.GetBytes("{\"format\":\"synthetic-test-manifest\",\"marker\":\"" + Guid.NewGuid().ToString("N") + "\"}");
            var package = RandomNumberGenerator.GetBytes(64 * 1024 + 17);
            await File.WriteAllBytesAsync(Path.Combine(packageDirectory, AgentUpdatePackage.ManifestFileName), manifest);
            // Only both files together are an Agent package.
            Check(await StatusAsync(client, ManifestPath, agent) == HttpStatusCode.NotFound, "Core offered a manifest without its package.");
            await File.WriteAllBytesAsync(Path.Combine(packageDirectory, AgentUpdatePackage.PackageFileName), package);

            using (var response = await SendAsync(client, ManifestPath, agent))
            {
                Check(response.StatusCode == HttpStatusCode.OK && response.Content.Headers.ContentType?.MediaType == "application/json" &&
                      response.Headers.CacheControl?.NoStore == true &&
                      (await response.Content.ReadAsByteArrayAsync()).AsSpan().SequenceEqual(manifest),
                    "Core did not serve the signed manifest bytes unchanged.");
            }

            using (var response = await SendAsync(client, PackagePath, agent))
            {
                Check(response.StatusCode == HttpStatusCode.OK && response.Content.Headers.ContentType?.MediaType == "application/zip" &&
                      (await response.Content.ReadAsByteArrayAsync()).AsSpan().SequenceEqual(package),
                    $"Core did not serve the Agent package bytes unchanged ({response.StatusCode}, {response.Content.Headers.ContentType?.MediaType}, {response.Content.Headers.ContentLength}).");
            }

            // A manifest above the signed envelope's limit is never served.
            await File.WriteAllBytesAsync(Path.Combine(packageDirectory, AgentUpdatePackage.ManifestFileName),
                new byte[AgentUpdatePackage.MaximumManifestBytes + 1]);
            Check(await StatusAsync(client, ManifestPath, agent) == HttpStatusCode.NotFound, "Core served an oversized manifest.");

            await app.StopAsync();

            // A second Core, so these requests do not count against the first one's allowance.
            await using var guarded = Build(Path.Combine(root, "guarded"), packageDirectory);
            using var guardedClient = await StartAsync(guarded);
            var enrolled = await EnrollAsync(guarded);
            // Anonymous, malformed and wrong credentials are refused before any file is read.
            foreach (var path in new[] { ManifestPath, PackagePath })
            {
                Check(await StatusAsync(guardedClient, path, null) == HttpStatusCode.Unauthorized &&
                      await StatusAsync(guardedClient, path, enrolled with { Credential = new string('0', 64) }) == HttpStatusCode.Unauthorized &&
                      await StatusAsync(guardedClient, path, enrolled with { Credential = "short" }) == HttpStatusCode.Unauthorized,
                    "Core served the Agent package without a valid Agent credential.");
            }

            // Agents check hourly: the per-address allowance is ten requests a minute.
            var limited = false;
            for (var attempt = 0; attempt < 6 && !limited; attempt++)
                limited = await StatusAsync(guardedClient, PackagePath, enrolled) == HttpStatusCode.TooManyRequests;
            Check(limited, "Core did not rate-limit Agent update requests.");
            await guarded.StopAsync();
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }

        Console.WriteLine("Agent update API tests passed (absent package, authentication, unchanged bytes, size bound, rate limit).");
    }

    private sealed record Agent(Guid EndpointId, string Credential);

    private static WebApplication Build(string directory, string updateDirectory) =>
        CoreHost.Build([$"--SentinelAI:DataDirectory={directory}", $"--SentinelAI:AgentUpdate:Directory={updateDirectory}"]);

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private static async Task<Agent> EnrollAsync(WebApplication app)
    {
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrollment = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        var response = enrollment.Response ?? throw new InvalidOperationException("A synthetic endpoint could not enroll.");
        return new Agent(response.EndpointId, response.AgentCredential);
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string path, Agent? agent)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (agent is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{agent.EndpointId:D}.{agent.Credential}");
        return await client.SendAsync(request);
    }

    private static async Task<HttpStatusCode> StatusAsync(HttpClient client, string path, Agent? agent)
    {
        using var response = await SendAsync(client, path, agent);
        return response.StatusCode;
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
