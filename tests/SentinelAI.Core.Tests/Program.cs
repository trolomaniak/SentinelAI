using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
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
    Guid endpointId;
    string agentCredential;
    CoreIdentity coreIdentity;
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
        (endpointId, agentCredential, coreIdentity, lastHeartbeatUtc) = await VerifyEnrollmentAsync(
            client, app, installationId, firstAccessToken, secondHeartbeat.LastSeenUtc, dataDirectory);
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
        Ensure(persistedDevice?.EnrollmentStatus == DeviceEnrollmentStatus.Enrolled,
            "Core restart lost the device enrollment status.");
        var persistedEnrollment = await restartedApp.Services.GetRequiredService<EnrollmentStore>()
            .FindByInstallationIdAsync(installationId);
        Ensure(persistedEnrollment?.EndpointId == endpointId,
            "Core restart changed the assigned endpoint ID.");
        Ensure(await restartedApp.Services.GetRequiredService<EnrollmentStore>()
                   .GetCoreIdentityAsync() == coreIdentity,
            "Core restart changed the organization or Core installation ID.");
        using (var authenticatedHeartbeat = await SendAgentHeartbeatAsync(
                   client, installationId, endpointId, agentCredential))
        {
            Ensure(authenticatedHeartbeat.StatusCode == HttpStatusCode.OK,
                "Core rejected the enrolled Agent after restart.");
        }

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

    await using (var remoteHttpApp = CoreHost.Build([]))
    {
        // Exercise the request transport guard without exposing a test listener on the LAN.
        remoteHttpApp.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
            await next(context);
        });
        using var client = await StartCoreAsync(remoteHttpApp);
        var accessToken = await GetAccessTokenAsync(client, username, password);
        using (var issue = await PostAsBearerAsync(client, "/api/admin/enrollment-tokens", accessToken))
        {
            Ensure(issue.StatusCode == HttpStatusCode.Forbidden,
                "Core issued an enrollment token over remote HTTP.");
        }
        using (var enroll = await EnrollAsync(client, Guid.NewGuid(), new string('0', 64)))
        {
            Ensure(enroll.StatusCode == HttpStatusCode.Forbidden,
                "Core accepted remote HTTP enrollment traffic.");
        }
        using (var heartbeat = await SendAgentHeartbeatAsync(
                   client, installationId, endpointId, agentCredential))
        {
            Ensure(heartbeat.StatusCode == HttpStatusCode.Forbidden,
                "Core accepted an Agent credential over remote HTTP.");
        }
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

static async Task<(Guid EndpointId, string Credential, CoreIdentity CoreIdentity, DateTimeOffset LastSeenUtc)>
    VerifyEnrollmentAsync(
        HttpClient client,
        WebApplication app,
        Guid installationId,
        string adminAccessToken,
        DateTimeOffset previousLastSeenUtc,
        string dataDirectory)
{
    var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
    var devices = app.Services.GetRequiredService<DeviceStore>();
    using (var anonymousIssue = await client.PostAsync("/api/admin/enrollment-tokens", null))
    {
        Ensure(anonymousIssue.StatusCode == HttpStatusCode.Unauthorized,
            "An anonymous caller could issue an enrollment token.");
    }

    var coreIdentity = await enrollments.GetCoreIdentityAsync();
    EnrollmentTokenResponse issuedToken;
    using (var issue = await PostAsBearerAsync(client, "/api/admin/enrollment-tokens", adminAccessToken))
    {
        Ensure(issue.StatusCode == HttpStatusCode.OK, "The administrator could not issue an enrollment token.");
        Ensure(issue.Headers.CacheControl?.NoStore == true, "The enrollment token response permits caching.");
        issuedToken = await issue.Content.ReadFromJsonAsync<EnrollmentTokenResponse>()
            ?? throw new Exception("Core did not return an enrollment token.");
    }
    Ensure(issuedToken.Token.Length == 64 && issuedToken.ExpiresUtc > DateTimeOffset.UtcNow,
        "The enrollment token was not long-lived enough for provisioning.");
    Ensure(issuedToken.CoreInstallationId == coreIdentity.CoreInstallationId &&
           issuedToken.OrganizationId == coreIdentity.OrganizationId,
        "The enrollment token is not bound to this Core and organization.");

    var tokenBytes = Encoding.ASCII.GetBytes(issuedToken.Token);
    foreach (var file in Directory.EnumerateFiles(dataDirectory, "*", SearchOption.AllDirectories))
    {
        Ensure((await File.ReadAllBytesAsync(file)).AsSpan().IndexOf(tokenBytes) < 0,
            "Core stored an enrollment token in plaintext.");
    }

    using (var invalid = await EnrollAsync(client, Guid.NewGuid(), new string('0', 64)))
    {
        Ensure(invalid.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted an invalid enrollment token.");
    }

    var expiredToken = await enrollments.IssueTokenAsync(TimeSpan.FromMilliseconds(20));
    await Task.Delay(70);
    using (var expired = await EnrollAsync(client, Guid.NewGuid(), expiredToken.Token))
    {
        Ensure(expired.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted an expired enrollment token.");
    }

    EnrollmentResponse enrollment;
    using (var success = await EnrollAsync(client, installationId, issuedToken.Token))
    {
        Ensure(success.StatusCode == HttpStatusCode.OK, "Core rejected a valid enrollment token.");
        Ensure(success.Headers.CacheControl?.NoStore == true, "The Agent credential response permits caching.");
        enrollment = await success.Content.ReadFromJsonAsync<EnrollmentResponse>()
            ?? throw new Exception("Core did not return an endpoint identity.");
    }
    Ensure(enrollment.InstallationId == installationId && enrollment.EndpointId != Guid.Empty &&
           enrollment.AgentCredential.Length == 64 &&
           enrollment.CoreInstallationId == coreIdentity.CoreInstallationId &&
           enrollment.OrganizationId == coreIdentity.OrganizationId,
        "Core returned an invalid endpoint identity or association.");
    var persistedEnrollment = await enrollments.FindByInstallationIdAsync(installationId);
    Ensure(persistedEnrollment?.EndpointId == enrollment.EndpointId &&
           persistedEnrollment?.CoreInstallationId == coreIdentity.CoreInstallationId &&
           persistedEnrollment?.OrganizationId == coreIdentity.OrganizationId,
        "Core did not persist the endpoint identity and organization association.");
    Ensure((await devices.FindByInstallationIdAsync(installationId))?.EnrollmentStatus ==
           DeviceEnrollmentStatus.Enrolled,
        "Enrollment did not mark the existing device as enrolled.");

    using (var replay = await EnrollAsync(client, Guid.NewGuid(), issuedToken.Token))
    {
        Ensure(replay.StatusCode == HttpStatusCode.Unauthorized,
            "A consumed enrollment token could enroll another endpoint.");
    }

    var duplicateToken = await enrollments.IssueTokenAsync();
    using (var duplicate = await EnrollAsync(client, installationId, duplicateToken.Token))
    {
        Ensure(duplicate.StatusCode == HttpStatusCode.Conflict,
            "Re-enrollment silently created a duplicate endpoint.");
    }
    Ensure((await enrollments.FindByInstallationIdAsync(installationId))?.EndpointId ==
           enrollment.EndpointId,
        "A repeated enrollment changed the assigned endpoint ID.");

    using (var anonymousHeartbeat = await SendHeartbeatAsync(client, installationId))
    {
        Ensure(anonymousHeartbeat.StatusCode == HttpStatusCode.Unauthorized,
            "An anonymous heartbeat updated an enrolled endpoint.");
    }
    using (var wrongCredential = await SendAgentHeartbeatAsync(
               client, installationId, enrollment.EndpointId, new string('F', 64)))
    {
        Ensure(wrongCredential.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted an invalid Agent credential.");
    }
    Ensure((await devices.FindByInstallationIdAsync(installationId))?.LastSeenUtc == previousLastSeenUtc,
        "A rejected heartbeat changed last_seen.");

    await Task.Delay(100);
    using (var validHeartbeat = await SendAgentHeartbeatAsync(
               client, installationId, enrollment.EndpointId, enrollment.AgentCredential))
    {
        Ensure(validHeartbeat.StatusCode == HttpStatusCode.OK,
            "Core rejected the enrolled Agent heartbeat.");
    }
    var updatedDevice = await devices.FindByInstallationIdAsync(installationId);
    Ensure(updatedDevice?.LastSeenUtc > previousLastSeenUtc &&
           updatedDevice?.EnrollmentStatus == DeviceEnrollmentStatus.Enrolled,
        "The enrolled Agent heartbeat did not update last_seen.");

    var concurrentToken = await enrollments.IssueTokenAsync();
    var firstCandidate = Guid.NewGuid();
    var secondCandidate = Guid.NewGuid();
    var concurrentAttempts = await Task.WhenAll(
        EnrollAsync(client, firstCandidate, concurrentToken.Token),
        EnrollAsync(client, secondCandidate, concurrentToken.Token));
    using var firstAttempt = concurrentAttempts[0];
    using var secondAttempt = concurrentAttempts[1];
    Ensure(concurrentAttempts.Count(response => response.StatusCode == HttpStatusCode.OK) == 1 &&
           concurrentAttempts.Count(response => response.StatusCode == HttpStatusCode.Unauthorized) == 1,
        "Concurrent attempts reused a one-time enrollment token.");

    return (enrollment.EndpointId, enrollment.AgentCredential, coreIdentity, updatedDevice!.LastSeenUtc);
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

static Task<HttpResponseMessage> EnrollAsync(HttpClient client, Guid installationId, string token) =>
    client.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(installationId, token));

static async Task<HttpResponseMessage> SendAgentHeartbeatAsync(
    HttpClient client, Guid installationId, Guid endpointId, string credential)
{
    using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat")
    {
        Content = JsonContent.Create(new HeartbeatRequest(installationId))
    };
    request.Headers.Authorization = new AuthenticationHeaderValue(
        "SentinelAgent", $"{endpointId:D}.{credential}");
    return await client.SendAsync(request);
}

static async Task<HttpResponseMessage> PostAsBearerAsync(
    HttpClient client, string path, string accessToken)
{
    using var request = new HttpRequestMessage(HttpMethod.Post, path);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    return await client.SendAsync(request);
}

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
