using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Rules;

static class OperatingSystemApiTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static async Task VerifyAsync(string username, string password)
    {
        // A separate real host keeps these requests within the existing per-IP upload budget.
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-os-tests-{Guid.NewGuid():N}");
        try
        {
            await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"],
                builder => builder.Logging.ClearProviders());
            app.Urls.Clear();
            app.Urls.Add("http://127.0.0.1:0");
            await app.StartAsync();
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
                { BaseAddress = new Uri(app.Urls.Single()) };
            using var authenticated = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
            Check(authenticated.StatusCode == HttpStatusCode.OK, "The OS test administrator could not log in.");
            using var authentication = JsonDocument.Parse(await authenticated.Content.ReadAsStringAsync());
            var administratorToken = authentication.RootElement.GetProperty("accessToken").GetString()!;
            var token = await app.Services.GetRequiredService<EnrollmentStore>().IssueTokenAsync();
            using var enrolled = await client.PostAsJsonAsync("/api/agent/enroll", new EnrollmentRequest(Guid.NewGuid(), token.Token));
            Check(enrolled.StatusCode == HttpStatusCode.OK, "The synthetic OS test Agent could not enroll.");
            var identity = (await enrolled.Content.ReadFromJsonAsync<EnrollmentResponse>())!;
            var initial = new InventoryReport(identity.EndpointId, DateTimeOffset.UtcNow, "0.1.0-test",
                "synthetic-os-endpoint", "Windows", "10.0.19045.0", "X64", new("Synthetic CPU", 4),
                null, [], new(true, true, true));
            await VerifyReportsAsync(client, identity.EndpointId, identity.AgentCredential, administratorToken, initial);
            await app.StopAsync();
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task VerifyReportsAsync(HttpClient client, Guid endpointId,
        string agentCredential, string administratorToken, InventoryReport initial)
    {
        // Actual older wire payload: the new optional properties are absent, not just null.
        var legacy = initial with { CollectedUtc = initial.CollectedUtc.AddTicks(1) };
        var body = JsonSerializer.SerializeToNode(legacy, Json)!.AsObject();
        body.Remove("osDisplayVersion");
        body.Remove("osInstallationType");
        using (var uploaded = await UploadAsync(client, endpointId, agentCredential, body.ToJsonString()))
            Check(uploaded.StatusCode == HttpStatusCode.NoContent, "An older Agent's inventory was rejected.");
        await CheckDisplayAsync(client, endpointId, administratorToken,
            $"{legacy.OsName} {legacy.OsVersion}", legacy.OsName, legacy.OsVersion);

        var windows = legacy with
        {
            CollectedUtc = legacy.CollectedUtc.AddTicks(1),
            OsName = "Windows 11", OsVersion = "10.0.26200.0",
            OsDisplayVersion = "26H2", OsInstallationType = "Client"
        };
        using (var uploaded = await UploadAsync(client, endpointId, agentCredential, JsonSerializer.Serialize(windows, Json)))
            Check(uploaded.StatusCode == HttpStatusCode.NoContent, "Core rejected Windows release/build metadata.");
        await CheckDisplayAsync(client, endpointId, administratorToken,
            "Windows 11 26H2 10.0.26200.0", "Windows 11", "26H2 10.0.26200.0");
        Check(EndpointState.FromInventory(windows).IsWindows &&
            RuleEngine.CreateDefault().Evaluate(EndpointState.FromInventory(windows with
            { SecurityPosture = windows.SecurityPosture with { PublicFirewallEnabled = false } }))
                .Any(alert => alert.RuleId == "SA-FW-003"),
            "The descriptive Windows name stopped deterministic Windows detection.");

        foreach (var invalid in new[]
        {
            windows with { OsDisplayVersion = new string('x', 33) },
            windows with { OsDisplayVersion = "26H2\n" },
            windows with { OsDisplayVersion = " " },
            windows with { OsInstallationType = new string('x', 33) },
            windows with { OsInstallationType = "Client\u0000" }
        })
        {
            using var rejected = await UploadAsync(client, endpointId, agentCredential, JsonSerializer.Serialize(invalid, Json));
            Check(rejected.StatusCode == HttpStatusCode.BadRequest, "Core accepted invalid/unbounded OS metadata.");
        }
        await CheckDisplayAsync(client, endpointId, administratorToken,
            "Windows 11 26H2 10.0.26200.0", "Windows 11", "26H2 10.0.26200.0");

        var server = windows with
        {
            CollectedUtc = windows.CollectedUtc.AddTicks(1),
            OsName = "Windows Server 2025", OsDisplayVersion = "24H2",
            OsInstallationType = "Server Core", OsVersion = "10.0.26100.1000"
        };
        using (var uploaded = await UploadAsync(client, endpointId, agentCredential, JsonSerializer.Serialize(server, Json)))
            Check(uploaded.StatusCode == HttpStatusCode.NoContent, "Core rejected Server Core metadata.");
        await CheckDisplayAsync(client, endpointId, administratorToken,
            "Windows Server 2025 24H2 Server Core 10.0.26100.1000", "Windows Server 2025", "24H2 10.0.26100.1000");

        Console.WriteLine("Operating system API tests passed (legacy payload, release/build, Server Core, validation, Windows detection).");
    }

    private static async Task CheckDisplayAsync(HttpClient client, Guid endpointId, string token,
        string full, string name, string version)
    {
        using var listRequest = new HttpRequestMessage(HttpMethod.Get, "/api/admin/devices");
        listRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var list = await client.SendAsync(listRequest);
        var devices = await list.Content.ReadFromJsonAsync<DeviceListItem[]>();
        Check(list.StatusCode == HttpStatusCode.OK && devices?.Single(device => device.EndpointId == endpointId)
            .OperatingSystem == full, "The device list did not display name, release, installation type and build.");
        using var detailRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/devices/{endpointId:D}");
        detailRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var detail = await client.SendAsync(detailRequest);
        var data = await detail.Content.ReadFromJsonAsync<DeviceDetail>();
        Check(detail.StatusCode == HttpStatusCode.OK && data?.OsName == name && data.OsVersion == version,
            "The device detail did not separate the OS name from release/build.");
    }

    private static Task<HttpResponseMessage> UploadAsync(HttpClient client, Guid endpointId, string credential, string json)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory")
        { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{endpointId:D}.{credential}");
        return SendAndDisposeAsync(client, request);
    }

    private static async Task<HttpResponseMessage> SendAndDisposeAsync(HttpClient client, HttpRequestMessage request)
    {
        using (request) return await client.SendAsync(request);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
