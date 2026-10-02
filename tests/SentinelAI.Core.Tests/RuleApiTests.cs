using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core.Persistence;

internal static class RuleApiTests
{
    public static async Task<InventoryReport> VerifyAsync(HttpClient client, WebApplication app,
        Guid endpointId, string credential, string adminToken, InventoryReport original)
    {
        var path = $"/api/admin/devices/{endpointId:D}/alerts";
        using (var anonymous = await client.GetAsync(path))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Anonymous alert read succeeded.");
        using (var agent = await GetAsync(client, path, "SentinelAgent", $"{endpointId:D}.{credential}"))
            Check(agent.StatusCode == HttpStatusCode.Unauthorized, "Agent credential permitted an admin alert read.");
        using (var missing = await GetAsync(client, $"/api/admin/devices/{Guid.NewGuid():D}/alerts", "Bearer", adminToken))
            Check(missing.StatusCode == HttpStatusCode.NotFound, "Unknown endpoint returned security findings.");

        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrolled = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        Check(enrolled.Response is not null, "Could not enroll endpoint for unknown inventory test.");
        using (var empty = await GetAsync(client, $"/api/admin/devices/{enrolled.Response!.EndpointId:D}/alerts", "Bearer", adminToken))
        {
            Check(empty.StatusCode == HttpStatusCode.OK, "Endpoint without inventory rejected.");
            using var json = JsonDocument.Parse(await empty.Content.ReadAsStringAsync());
            Check(json.RootElement.GetProperty("observedUtc").ValueKind == JsonValueKind.Null &&
                  json.RootElement.GetProperty("alerts").GetArrayLength() == 0,
                "Missing inventory inferred a security condition.");
        }

        var invalid = original with
        {
            CollectedUtc = original.CollectedUtc.AddTicks(1),
            SecurityPosture = original.SecurityPosture with
            {
                Configuration = new WindowsSecurityConfiguration(RdpSecurityLayer: 99)
            }
        };
        using (var rejected = await PostInventoryAsync(client, invalid, credential))
            Check(rejected.StatusCode == HttpStatusCode.BadRequest, "Invalid configuration enum accepted.");

        // The endpoint's latest accepted state is the only detection input. Read findings,
        // repeat the request, then submit stale and remediated snapshots through Agent auth.
        var risky = original with
        {
            CollectedUtc = original.CollectedUtc.AddTicks(2),
            SecurityPosture = new SecurityPostureInventory(false, true, true,
                new WindowsSecurityConfiguration(RdpEnabled: true, RdpNetworkLevelAuthenticationRequired: false))
        };
        using (var accepted = await PostInventoryAsync(client, risky, credential))
            Check(accepted.StatusCode == HttpStatusCode.NoContent, "Valid risky state rejected.");
        string first;
        using (var findings = await GetAsync(client, path, "Bearer", adminToken))
        {
            Check(findings.StatusCode == HttpStatusCode.OK && findings.Headers.CacheControl?.NoStore == true,
                "Administrator findings were unavailable or cacheable.");
            first = await findings.Content.ReadAsStringAsync();
            using var json = JsonDocument.Parse(first);
            var alerts = json.RootElement.GetProperty("alerts");
            Check(alerts.GetArrayLength() == 2, "Expected firewall and RDP detections were not generated.");
            foreach (var alert in alerts.EnumerateArray())
            {
                foreach (var field in new[] { "ruleId", "title", "severity", "reason", "recommendedAction" })
                    Check(!string.IsNullOrWhiteSpace(alert.GetProperty(field).GetString()), $"Missing {field}.");
                Check(alert.GetProperty("endpointId").GetGuid() == endpointId &&
                      alert.GetProperty("timestamp").GetDateTimeOffset() == risky.CollectedUtc &&
                      alert.GetProperty("evidence").GetArrayLength() > 0,
                    "Finding lost endpoint, observation time or evidence.");
            }
        }
        using (var repeat = await GetAsync(client, path, "Bearer", adminToken))
            Check(await repeat.Content.ReadAsStringAsync() == first, "Repeated evaluation was nondeterministic.");
        using (var stale = await PostInventoryAsync(client, original, credential))
            Check(stale.StatusCode == HttpStatusCode.NoContent, "Stale report failed unexpectedly.");
        using (var unchanged = await GetAsync(client, path, "Bearer", adminToken))
            Check(await unchanged.Content.ReadAsStringAsync() == first, "Stale report changed security findings.");

        // Return the remediated latest snapshot for the surrounding restart assertions.
        var restored = original with { CollectedUtc = risky.CollectedUtc.AddTicks(1) };
        using (var remediation = await PostInventoryAsync(client, restored, credential))
            Check(remediation.StatusCode == HttpStatusCode.NoContent, "Normal state update rejected.");
        using (var cleared = await GetAsync(client, path, "Bearer", adminToken))
        {
            using var json = JsonDocument.Parse(await cleared.Content.ReadAsStringAsync());
            Check(json.RootElement.GetProperty("alerts").GetArrayLength() == 0,
                "Remediated condition kept stale findings.");
        }
        return restored;
    }

    public static async Task VerifyAfterRestartAsync(HttpClient client, Guid endpointId,
        string token, DateTimeOffset previousObservation)
    {
        using var response = await GetAsync(client, $"/api/admin/devices/{endpointId:D}/alerts", "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.OK, "Restart lost security evaluation access.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Check(json.RootElement.GetProperty("alerts").GetArrayLength() == 0 &&
              json.RootElement.GetProperty("observedUtc").GetDateTimeOffset() >= previousObservation,
            "Restart did not evaluate the persisted latest state.");
    }

    private static async Task<HttpResponseMessage> PostInventoryAsync(HttpClient client,
        InventoryReport report, string credential)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory")
        {
            Content = JsonContent.Create(report)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{report.EndpointId:D}.{credential}");
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string scheme, string credential)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, credential);
        return await client.SendAsync(request);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
