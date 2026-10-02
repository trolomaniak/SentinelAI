using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Contracts.Inventory;
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
    InventoryReport latestInventory;
    AlertApiTestState alertTestState;
    await using (var app = CoreHost.Build([]))
    {
        Ensure(app.Services.GetService<IServer>() is not null, "The Core host did not register a web server.");
        using var client = await StartCoreAsync(app);

        using (var dashboard = await client.GetAsync("/"))
        {
            Ensure(dashboard.StatusCode == HttpStatusCode.OK &&
                   dashboard.Content.Headers.ContentType?.MediaType == "text/html" &&
                   (await dashboard.Content.ReadAsStringAsync()).Contains("./assets/app.js", StringComparison.Ordinal) &&
                   dashboard.Headers.Contains("Content-Security-Policy"),
                "Core did not serve the dashboard from its own origin.");
        }
        using (var script = await client.GetAsync("/assets/app.js"))
        {
            Ensure(script.StatusCode == HttpStatusCode.OK &&
                   (await script.Content.ReadAsStringAsync()).Contains("/api/admin/devices", StringComparison.Ordinal),
                "Core did not serve the dashboard application script.");
        }

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
        using (var anonymousDevices = await client.GetAsync("/api/admin/devices"))
        {
            Ensure(anonymousDevices.StatusCode == HttpStatusCode.Unauthorized,
                "The device list allowed an anonymous request.");
        }
        using (var anonymousDetail = await client.GetAsync($"/api/admin/devices/{Guid.NewGuid():D}"))
        {
            Ensure(anonymousDetail.StatusCode == HttpStatusCode.Unauthorized,
                "The device detail allowed an anonymous request.");
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
        using (var emptyDevices = await GetAsBearerAsync(client, "/api/admin/devices", firstAccessToken))
        {
            Ensure(emptyDevices.StatusCode == HttpStatusCode.OK &&
                   emptyDevices.Headers.CacheControl?.NoStore == true &&
                   (await emptyDevices.Content.ReadFromJsonAsync<DeviceListItem[]>()) is { Length: 0 },
                "A fresh Core did not return an uncached empty device list.");
        }

        await AlertApiTests.VerifyEmptyAsync(client, firstAccessToken);

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
        using (var unverifiedList = await GetAsBearerAsync(client, "/api/admin/devices", firstAccessToken))
        {
            Ensure((await unverifiedList.Content.ReadFromJsonAsync<DeviceListItem[]>()) is { Length: 0 },
                "An unverified loopback heartbeat appeared as an enrolled dashboard endpoint.");
        }
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
        latestInventory = await VerifyInventoryAsync(client, app, endpointId, agentCredential);
        await VerifyDeviceReadApiAsync(
            client, store.DatabasePath, installationId, endpointId,
            lastHeartbeatUtc, latestInventory, agentCredential, firstAccessToken);
        latestInventory = await RuleApiTests.VerifyAsync(
            client, app, endpointId, agentCredential, firstAccessToken, latestInventory);
        alertTestState = await AlertApiTests.VerifyAsync(
            client, app, endpointId, agentCredential, firstAccessToken, latestInventory, username, password);
        latestInventory = alertTestState.LatestInventory;
    }

    await OperatingSystemApiTests.VerifyAsync(username, password);
    await ReportApiTests.VerifyAsync(username, password);
    await RiskApiTests.VerifyAsync(username, password);

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
        var persistedInventory = await restartedApp.Services.GetRequiredService<InventoryStore>()
            .FindLatestAsync(endpointId);
        Ensure(persistedInventory?.Hostname == latestInventory.Hostname &&
               persistedInventory.CollectedUtc == latestInventory.CollectedUtc &&
               persistedInventory.Cpu.Model == latestInventory.Cpu.Model &&
               persistedInventory.OsDisplayVersion == latestInventory.OsDisplayVersion &&
               persistedInventory.OsInstallationType == latestInventory.OsInstallationType &&
               persistedInventory.Disks[0].TotalBytes == latestInventory.Disks[0].TotalBytes,
            "Core restart lost the latest endpoint inventory.");
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
        using var persistedList = await GetAsBearerAsync(client, "/api/admin/devices", accessToken);
        var persistedDevices = await persistedList.Content.ReadFromJsonAsync<DeviceListItem[]>() ?? [];
        Ensure(persistedList.StatusCode == HttpStatusCode.OK &&
               persistedDevices.Any(device => device.EndpointId == endpointId &&
                   device.Name == latestInventory.Hostname && device.HealthState == "healthy"),
            "The dashboard device list did not survive Core restart.");
        using var persistedDetail = await GetAsBearerAsync(
            client, $"/api/admin/devices/{endpointId:D}", accessToken);
        var restoredDetail = await persistedDetail.Content.ReadFromJsonAsync<DeviceDetail>();
        Ensure(persistedDetail.StatusCode == HttpStatusCode.OK &&
               restoredDetail?.InventoryCollectedUtc == latestInventory.CollectedUtc &&
               restoredDetail.OsName == latestInventory.OsName &&
               restoredDetail.Disks.Count == latestInventory.Disks.Count,
            "The dashboard device detail did not survive Core restart.");
        await RuleApiTests.VerifyAfterRestartAsync(client, endpointId, accessToken, latestInventory.CollectedUtc);
        await AlertApiTests.VerifyAfterRestartAsync(client, accessToken, alertTestState);
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
        using (var inventory = await SendInventoryAsync(
                   client, CreateInventory(endpointId), endpointId, agentCredential))
        {
            Ensure(inventory.StatusCode == HttpStatusCode.Forbidden,
                "Core accepted inventory and an Agent credential over remote HTTP.");
        }
        using (var deviceList = await GetAsBearerAsync(client, "/api/admin/devices", accessToken))
        {
            Ensure(deviceList.StatusCode == HttpStatusCode.Forbidden,
                "Core exposed the administrator device list over remote HTTP.");
        }
        using (var deviceDetail = await GetAsBearerAsync(
                   client, $"/api/admin/devices/{endpointId:D}", accessToken))
        {
            Ensure(deviceDetail.StatusCode == HttpStatusCode.Forbidden,
                "Core exposed administrator device details over remote HTTP.");
        }
        using (var alerts = await GetAsBearerAsync(
                   client, $"/api/admin/devices/{endpointId:D}/alerts", accessToken))
        {
            Ensure(alerts.StatusCode == HttpStatusCode.Forbidden,
                "Core exposed security findings over remote HTTP.");
        }
        await AlertApiTests.VerifyRemoteHttpAsync(client, accessToken, alertTestState.AlertId);
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
        SqliteConnection.ClearAllPools();
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

static async Task VerifyDeviceReadApiAsync(
    HttpClient client,
    string databasePath,
    Guid installationId,
    Guid endpointId,
    DateTimeOffset lastHeartbeatUtc,
    InventoryReport inventory,
    string agentCredential,
    string adminAccessToken)
{
    using (var agentRequest = new HttpRequestMessage(HttpMethod.Get, "/api/admin/devices"))
    {
        agentRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "SentinelAgent", $"{endpointId:D}.{agentCredential}");
        using var agentRead = await client.SendAsync(agentRequest);
        Ensure(agentRead.StatusCode == HttpStatusCode.Unauthorized,
            "An Agent credential could read the administrator device list.");
    }

    using (var list = await GetAsBearerAsync(client, "/api/admin/devices", adminAccessToken))
    {
        var devices = await list.Content.ReadFromJsonAsync<DeviceListItem[]>() ?? [];
        var enrolled = devices.FirstOrDefault(device => device.EndpointId == endpointId);
        Ensure(list.StatusCode == HttpStatusCode.OK && list.Headers.CacheControl?.NoStore == true &&
               enrolled?.Name == inventory.Hostname &&
               enrolled.OperatingSystem == "Windows 11 26H2 10.0.26200.0" &&
               enrolled.AgentVersion == inventory.AgentVersion && enrolled.HealthState == "healthy" &&
               enrolled.LastSeenUtc == lastHeartbeatUtc &&
               enrolled.SecurityPostureSummary == "Firewall enabled on all profiles",
            "The administrator device list did not expose current, display-ready endpoint data.");

        var awaitingHeartbeat = devices.FirstOrDefault(device => device.HealthState == "unknown")
            ?? throw new Exception("An enrolled endpoint without a heartbeat was omitted from the device list.");
        Ensure(awaitingHeartbeat.LastSeenUtc is null &&
               awaitingHeartbeat.OperatingSystem is null && awaitingHeartbeat.AgentVersion is null &&
               awaitingHeartbeat.SecurityPostureSummary == "Firewall status unknown",
            "An enrolled endpoint without a heartbeat or inventory was not shown as unknown.");
        using var unknownDetail = await GetAsBearerAsync(
            client, $"/api/admin/devices/{awaitingHeartbeat.EndpointId:D}", adminAccessToken);
        var unknown = await unknownDetail.Content.ReadFromJsonAsync<DeviceDetail>();
        Ensure(unknownDetail.StatusCode == HttpStatusCode.OK &&
               unknown?.Device.HealthState == "unknown" &&
               unknown.InventoryCollectedUtc is null && unknown.Cpu is null &&
               unknown.Disks.Count == 0 && unknown.SecurityPosture is null,
            "An enrolled endpoint without inventory did not have a usable detail view.");
    }

    using (var detail = await GetAsBearerAsync(
               client, $"/api/admin/devices/{endpointId:D}", adminAccessToken))
    {
        var content = await detail.Content.ReadAsStringAsync();
        var device = JsonSerializer.Deserialize<DeviceDetail>(content, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Ensure(detail.StatusCode == HttpStatusCode.OK && detail.Headers.CacheControl?.NoStore == true &&
               device?.Device.EndpointId == endpointId &&
               device.InventoryCollectedUtc == inventory.CollectedUtc &&
               device.OsName == "Windows 11" && device.OsVersion == "26H2 10.0.26200.0" &&
               device.Architecture == inventory.Architecture &&
               device.Cpu?.LogicalProcessorCount == inventory.Cpu.LogicalProcessorCount &&
               device.InstalledRamBytes == inventory.InstalledRamBytes &&
               device.Disks.Count == inventory.Disks.Count &&
               device.SecurityPosture?.DomainFirewallEnabled == true &&
               !content.Contains(agentCredential, StringComparison.Ordinal) &&
               !content.Contains("credentialHash", StringComparison.OrdinalIgnoreCase),
            "The endpoint detail omitted inventory fields or exposed an Agent credential.");
    }

    using (var missing = await GetAsBearerAsync(
               client, $"/api/admin/devices/{Guid.NewGuid():D}", adminAccessToken))
    {
        Ensure(missing.StatusCode == HttpStatusCode.NotFound &&
               missing.Headers.CacheControl?.NoStore == true,
            "A nonexistent endpoint detail did not return uncached HTTP 404.");
    }

    try
    {
        await SetLastSeenUtcAsync(databasePath, installationId, DateTimeOffset.UtcNow.AddMinutes(-3));
        await AssertDeviceHealthAsync(client, endpointId, adminAccessToken, "warning");
        await SetLastSeenUtcAsync(databasePath, installationId, DateTimeOffset.UtcNow.AddMinutes(-6));
        await AssertDeviceHealthAsync(client, endpointId, adminAccessToken, "offline");
    }
    finally
    {
        await SetLastSeenUtcAsync(databasePath, installationId, lastHeartbeatUtc);
    }
}

static async Task AssertDeviceHealthAsync(
    HttpClient client, Guid endpointId, string adminAccessToken, string expected)
{
    using var list = await GetAsBearerAsync(client, "/api/admin/devices", adminAccessToken);
    var devices = await list.Content.ReadFromJsonAsync<DeviceListItem[]>() ?? [];
    Ensure(list.StatusCode == HttpStatusCode.OK &&
           devices.FirstOrDefault(device => device.EndpointId == endpointId)?.HealthState == expected,
        $"The device list did not classify a stale heartbeat as {expected}.");
    using var detail = await GetAsBearerAsync(
        client, $"/api/admin/devices/{endpointId:D}", adminAccessToken);
    var deviceDetail = await detail.Content.ReadFromJsonAsync<DeviceDetail>();
    Ensure(detail.StatusCode == HttpStatusCode.OK && deviceDetail?.Device.HealthState == expected,
        $"The device detail did not classify a stale heartbeat as {expected}.");
}

static async Task SetLastSeenUtcAsync(string databasePath, Guid installationId, DateTimeOffset lastSeenUtc)
{
    await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadWrite
    }.ToString());
    await connection.OpenAsync();
    await using var update = connection.CreateCommand();
    update.CommandText = "UPDATE Devices SET LastSeenUtcTicks = $ticks WHERE InstallationId = $installationId;";
    update.Parameters.AddWithValue("$ticks", lastSeenUtc.UtcDateTime.Ticks);
    update.Parameters.AddWithValue("$installationId", installationId.ToString("D"));
    Ensure(await update.ExecuteNonQueryAsync() == 1, "The heartbeat fixture could not be updated.");
}

static async Task<InventoryReport> VerifyInventoryAsync(
    HttpClient client,
    WebApplication app,
    Guid endpointId,
    string credential)
{
    var inventories = app.Services.GetRequiredService<InventoryStore>();
    var report = CreateInventory(endpointId);
    Ensure(await inventories.FindLatestAsync(endpointId) is null,
        "A fresh endpoint already has inventory.");

    using (var anonymous = await client.PostAsJsonAsync("/api/agent/inventory", report))
    {
        Ensure(anonymous.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted anonymous inventory.");
    }
    using (var wrongCredential = await SendInventoryAsync(
               client, report, endpointId, new string('F', 64)))
    {
        Ensure(wrongCredential.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted an invalid inventory credential.");
    }
    using (var wrongEndpoint = await SendInventoryAsync(
               client, report with { EndpointId = Guid.NewGuid() }, endpointId, credential))
    {
        Ensure(wrongEndpoint.StatusCode == HttpStatusCode.Unauthorized,
            "An Agent could report inventory for another endpoint.");
    }
    using (var wrongHeader = await SendInventoryAsync(
               client, report, Guid.NewGuid(), credential))
    {
        Ensure(wrongHeader.StatusCode == HttpStatusCode.Unauthorized,
            "Core accepted an inventory credential under another endpoint ID.");
    }

    var secondToken = await app.Services.GetRequiredService<EnrollmentStore>().IssueTokenAsync();
    using (var secondEnrollment = await EnrollAsync(client, Guid.NewGuid(), secondToken.Token))
    {
        Ensure(secondEnrollment.StatusCode == HttpStatusCode.OK,
            "Core could not enroll a second endpoint for credential isolation tests.");
        var secondIdentity = await secondEnrollment.Content.ReadFromJsonAsync<EnrollmentResponse>()
            ?? throw new Exception("The second enrollment returned no identity.");
        using var swappedCredential = await SendInventoryAsync(
            client, report, endpointId, secondIdentity.AgentCredential);
        Ensure(swappedCredential.StatusCode == HttpStatusCode.Unauthorized,
            "Another enrolled Agent's credential could overwrite endpoint inventory.");
    }

    using (var malformedJson = await client.PostAsync("/api/agent/inventory",
               new StringContent("{", Encoding.UTF8, "application/json")))
    {
        Ensure(malformedJson.StatusCode == HttpStatusCode.BadRequest,
            "Core accepted malformed inventory JSON.");
    }
    using (var missingHostname = await SendInventoryAsync(
               client, report with { Hostname = " " }, endpointId, credential))
    {
        Ensure(missingHostname.StatusCode == HttpStatusCode.BadRequest,
            "Core accepted an inventory without a hostname.");
    }
    using (var invalidCpu = await SendInventoryAsync(
               client, report with { Cpu = new CpuInventory("Test CPU", 0) }, endpointId, credential))
    {
        Ensure(invalidCpu.StatusCode == HttpStatusCode.BadRequest,
            "Core accepted an invalid logical processor count.");
    }
    using (var invalidDisk = await SendInventoryAsync(
               client, report with { Disks = [new DiskInventory("C:\\", 1, 2)] },
               endpointId, credential))
    {
        Ensure(invalidDisk.StatusCode == HttpStatusCode.BadRequest,
            "Core accepted impossible disk capacity values.");
    }
    using (var futureTimestamp = await SendInventoryAsync(
               client, report with { CollectedUtc = DateTimeOffset.UtcNow.AddHours(1) },
               endpointId, credential))
    {
        Ensure(futureTimestamp.StatusCode == HttpStatusCode.BadRequest,
            "Core accepted an inventory timestamp far in the future.");
    }
    using (var oversized = await SendInventoryAsync(
               client, report with { Hostname = new string('X', 17_000) }, endpointId, credential))
    {
        Ensure(oversized.StatusCode == HttpStatusCode.RequestEntityTooLarge,
            "Core did not limit the inventory request body.");
    }
    Ensure(await inventories.FindLatestAsync(endpointId) is null,
        "Rejected inventory changed Core state.");

    using (var accepted = await SendInventoryAsync(client, report, endpointId, credential))
    {
        Ensure(accepted.StatusCode == HttpStatusCode.NoContent,
            "Core rejected a valid enrolled Agent inventory report.");
    }
    var stored = await inventories.FindLatestAsync(endpointId);
    Ensure(stored?.CollectedUtc == report.CollectedUtc &&
           stored.Hostname == report.Hostname &&
           stored.AgentVersion == report.AgentVersion &&
           stored.InstalledRamBytes == report.InstalledRamBytes &&
           stored.Disks.Count == 1 &&
           stored.SecurityPosture.DomainFirewallEnabled == true,
        "Core did not persist the reported inventory fields.");

    var older = report with
    {
        CollectedUtc = report.CollectedUtc.AddMinutes(-1),
        Hostname = "stale-endpoint"
    };
    using (var stale = await SendInventoryAsync(client, older, endpointId, credential))
    {
        Ensure(stale.StatusCode == HttpStatusCode.NoContent,
            "Core rejected an otherwise valid older inventory report.");
    }
    Ensure((await inventories.FindLatestAsync(endpointId))?.Hostname == report.Hostname,
        "An older inventory report replaced the latest state.");

    var newer = report with
    {
        CollectedUtc = report.CollectedUtc.AddTicks(1),
        Hostname = "updated-endpoint",
        OsVersion = "10.0.26200.0",
        OsDisplayVersion = "26H2",
        OsInstallationType = "Client"
    };
    using (var updated = await SendInventoryAsync(client, newer, endpointId, credential))
    {
        Ensure(updated.StatusCode == HttpStatusCode.NoContent,
            "Core rejected the newer inventory report.");
    }
    Ensure((await inventories.FindLatestAsync(endpointId))?.Hostname == newer.Hostname,
        "A newer inventory report did not replace the latest state.");
    return newer;
}

static InventoryReport CreateInventory(Guid endpointId) => new(
    endpointId,
    DateTimeOffset.UtcNow,
    "0.1.0-test",
    "test-endpoint",
    "Windows 11",
    "10.0.26100",
    "X64",
    new CpuInventory("Test CPU", 8),
    16L * 1024 * 1024 * 1024,
    [new DiskInventory("C:\\", 512L * 1024 * 1024 * 1024, 256L * 1024 * 1024 * 1024)],
    new SecurityPostureInventory(true, true, true));

static async Task<HttpResponseMessage> SendInventoryAsync(
    HttpClient client,
    InventoryReport report,
    Guid authorizationEndpointId,
    string credential)
{
    using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory")
    {
        Content = JsonContent.Create(report)
    };
    request.Headers.Authorization = new AuthenticationHeaderValue(
        "SentinelAgent", $"{authorizationEndpointId:D}.{credential}");
    return await client.SendAsync(request);
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
    Ensure(login.Headers.CacheControl?.NoStore == true, "The administrator token response permits caching.");
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
