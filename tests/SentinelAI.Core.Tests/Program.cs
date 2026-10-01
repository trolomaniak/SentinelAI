using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

var coreAssembly = typeof(CoreHost).Assembly;
Ensure(coreAssembly.GetName().Name == "SentinelAI.Core", "The Core project did not produce the expected assembly.");
Ensure(coreAssembly.EntryPoint is not null, "The Core assembly must be executable.");

var dataDirectory = Path.Combine(Path.GetTempPath(), $"sentinelai-core-tests-{Guid.NewGuid():N}");
var username = $"test-admin-{Guid.NewGuid():N}";
var password = $"Test-Only-{Guid.NewGuid():N}!";
var originalDataDirectory = Environment.GetEnvironmentVariable("SentinelAI__DataDirectory");
var originalUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
var originalPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");

try
{
    Environment.SetEnvironmentVariable("SentinelAI__DataDirectory", dataDirectory);
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);

    string firstAccessToken;
    var installationId = Guid.NewGuid();
    DateTimeOffset lastHeartbeatUtc;
    await using (var app = CoreHost.Build([]))
    {
        Ensure(app.Services.GetService<IServer>() is not null, "The Core host did not register a web server.");
        using var client = await StartCoreAsync(app);

        using (var health = await client.GetAsync("/api/health"))
        {
            Ensure(health.StatusCode == HttpStatusCode.OK, "The health endpoint did not return HTTP 200.");
            using var healthJson = JsonDocument.Parse(await health.Content.ReadAsStringAsync());
            Ensure(healthJson.RootElement.ValueKind == JsonValueKind.Object, "The health endpoint did not return JSON.");
        }

        using (var anonymous = await client.GetAsync("/api/admin/me"))
        {
            Ensure(anonymous.StatusCode == HttpStatusCode.Unauthorized, "The administrator endpoint allowed an anonymous request.");
        }

        string wrongPasswordBody;
        using (var wrongPassword = await LoginAsync(client, username, "Incorrect-Test-Password"))
        {
            Ensure(wrongPassword.StatusCode == HttpStatusCode.Unauthorized, "The login endpoint accepted a wrong password.");
            wrongPasswordBody = await EnsureNoCredentialLeakAsync(wrongPassword, username, password);
        }

        string unknownAdminBody;
        using (var unknownAdmin = await LoginAsync(client, $"unknown-{Guid.NewGuid():N}", password))
        {
            Ensure(unknownAdmin.StatusCode == HttpStatusCode.Unauthorized, "The login endpoint accepted an unknown administrator.");
            unknownAdminBody = await EnsureNoCredentialLeakAsync(unknownAdmin, username, password);
        }
        Ensure(wrongPasswordBody == unknownAdminBody, "Authentication failures reveal whether an administrator exists.");

        firstAccessToken = await GetAccessTokenAsync(client, username, password);
        using (var authorized = await GetAsBearerAsync(client, "/api/admin/me", firstAccessToken))
        {
            Ensure(authorized.StatusCode == HttpStatusCode.OK, "The administrator endpoint rejected a valid bearer token.");
        }

        var store = app.Services.GetRequiredService<AdminStore>();
        Ensure(File.Exists(store.DatabasePath), "Core did not create the SQLite database on startup.");
        var admin = await store.FindByUsernameAsync(username)
            ?? throw new Exception("Core did not persist the bootstrap administrator.");
        Ensure(admin.PasswordHash != password, "The administrator password was stored in plaintext.");
        Ensure(!admin.PasswordHash.Contains(password, StringComparison.Ordinal), "The password hash contains the plaintext password.");

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        foreach (var file in Directory.EnumerateFiles(dataDirectory, "*", SearchOption.AllDirectories))
        {
            var contents = await File.ReadAllBytesAsync(file);
            Ensure(contents.AsSpan().IndexOf(passwordBytes) < 0, "A Core data file contains the plaintext password.");
        }

        var devices = app.Services.GetRequiredService<DeviceStore>();
        Ensure(await devices.CountAsync() == 0, "The fresh Core database already contains devices.");

        using (var invalidHeartbeat = await SendHeartbeatAsync(client, Guid.Empty))
        {
            Ensure(invalidHeartbeat.StatusCode == HttpStatusCode.BadRequest,
                "The heartbeat endpoint accepted an empty installation ID.");
        }
        Ensure(await devices.CountAsync() == 0, "An invalid heartbeat created a device.");

        var firstHeartbeat = await SendValidHeartbeatAsync(client, installationId);
        Ensure(firstHeartbeat.HealthStatus == DeviceHealthStatus.Reporting,
            "The first heartbeat did not report a healthy device.");
        Ensure(firstHeartbeat.LastSeenUtc.Offset == TimeSpan.Zero,
            "The heartbeat timestamp was not in UTC.");
        Ensure(await devices.CountAsync() == 1, "The first heartbeat did not create exactly one device.");
        var firstDevice = await devices.FindByInstallationIdAsync(installationId)
            ?? throw new Exception("Core did not persist the first heartbeat.");
        Ensure(firstDevice.LastSeenUtc == firstHeartbeat.LastSeenUtc,
            "The persisted first heartbeat time differs from the response.");
        Ensure(firstDevice.HealthStatus == DeviceHealthStatus.Reporting,
            "The persisted device health status is incorrect.");
        Ensure(firstDevice.EnrollmentStatus == "unverified",
            "Heartbeat incorrectly treated a device as enrolled.");

        await Task.Delay(100);
        var secondHeartbeat = await SendValidHeartbeatAsync(client, installationId);
        Ensure(secondHeartbeat.LastSeenUtc > firstHeartbeat.LastSeenUtc,
            "A repeated heartbeat did not advance last_seen.");
        Ensure(await devices.CountAsync() == 1, "A repeated heartbeat duplicated the device.");
        var updatedDevice = await devices.FindByInstallationIdAsync(installationId);
        Ensure(updatedDevice?.LastSeenUtc == secondHeartbeat.LastSeenUtc,
            "Core did not persist the updated last_seen time.");
        lastHeartbeatUtc = secondHeartbeat.LastSeenUtc;
    }

    // Existing installations must work without retaining the bootstrap secret in configuration.
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", null);
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", null);

    await using (var restartedApp = CoreHost.Build([]))
    {
        using var client = await StartCoreAsync(restartedApp);
        var devices = restartedApp.Services.GetRequiredService<DeviceStore>();
        var persistedDevice = await devices.FindByInstallationIdAsync(installationId);
        Ensure(persistedDevice?.LastSeenUtc == lastHeartbeatUtc,
            "The device heartbeat did not survive Core restart.");
        Ensure(await devices.CountAsync() == 1,
            "Core restart changed the number of persisted devices.");

        using (var oldToken = await GetAsBearerAsync(client, "/api/admin/me", firstAccessToken))
        {
            Ensure(oldToken.StatusCode == HttpStatusCode.Unauthorized, "A bearer token survived Core restart.");
        }
        using (var anonymous = await client.GetAsync("/api/admin/me"))
        {
            Ensure(anonymous.StatusCode == HttpStatusCode.Unauthorized, "The restarted Core allowed an anonymous request.");
        }

        var accessToken = await GetAccessTokenAsync(client, username, password);
        using var authorized = await GetAsBearerAsync(client, "/api/admin/me", accessToken);
        Ensure(authorized.StatusCode == HttpStatusCode.OK, "The persisted administrator could not log in after restart.");
    }

    Console.WriteLine("Core integration tests passed.");
}
finally
{
    Environment.SetEnvironmentVariable("SentinelAI__DataDirectory", originalDataDirectory);
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", originalUsername);
    Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", originalPassword);
    if (Directory.Exists(dataDirectory))
    {
        Directory.Delete(dataDirectory, recursive: true);
    }
}

static async Task<HttpClient> StartCoreAsync(WebApplication app)
{
    app.Urls.Clear();
    app.Urls.Add("http://127.0.0.1:0");
    await app.StartAsync();

    var addresses = app.Urls.ToArray();
    Ensure(addresses.Length == 1 && !addresses[0].EndsWith(":0", StringComparison.Ordinal),
        "Core did not bind to an ephemeral loopback port.");
    return new HttpClient(new HttpClientHandler { UseProxy = false })
    {
        BaseAddress = new Uri(addresses[0]),
        Timeout = TimeSpan.FromSeconds(10)
    };
}

static Task<HttpResponseMessage> LoginAsync(HttpClient client, string username, string password) =>
    client.PostAsJsonAsync("/api/auth/login", new { username, password });

static Task<HttpResponseMessage> SendHeartbeatAsync(HttpClient client, Guid installationId) =>
    client.PostAsJsonAsync("/api/agent/heartbeat", new HeartbeatRequest(installationId));

static async Task<HeartbeatResponse> SendValidHeartbeatAsync(HttpClient client, Guid installationId)
{
    using var response = await SendHeartbeatAsync(client, installationId);
    Ensure(response.StatusCode == HttpStatusCode.OK, "Core rejected a valid heartbeat.");
    var heartbeat = await response.Content.ReadFromJsonAsync<HeartbeatResponse>()
        ?? throw new Exception("The heartbeat endpoint returned no response body.");
    Ensure(heartbeat.InstallationId == installationId,
        "The heartbeat response changed the installation ID.");
    return heartbeat;
}

static async Task<string> GetAccessTokenAsync(HttpClient client, string username, string password)
{
    using var login = await LoginAsync(client, username, password);
    Ensure(login.StatusCode == HttpStatusCode.OK, "The administrator could not log in.");
    using var body = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
    Ensure(body.RootElement.TryGetProperty("accessToken", out var token), "Login did not return an access token.");
    var accessToken = token.GetString();
    Ensure(!string.IsNullOrWhiteSpace(accessToken), "Login returned an empty access token.");
    return accessToken!;
}

static async Task<HttpResponseMessage> GetAsBearerAsync(HttpClient client, string path, string accessToken)
{
    using var request = new HttpRequestMessage(HttpMethod.Get, path);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    return await client.SendAsync(request);
}

static async Task<string> EnsureNoCredentialLeakAsync(HttpResponseMessage response, string username, string password)
{
    var body = await response.Content.ReadAsStringAsync();
    Ensure(!body.Contains(username, StringComparison.Ordinal), "An authentication failure revealed the administrator username.");
    Ensure(!body.Contains(password, StringComparison.Ordinal), "An authentication failure revealed the administrator password.");
    return body;
}

static void Ensure(bool condition, string message)
{
    if (!condition)
    {
        throw new Exception(message);
    }
}
