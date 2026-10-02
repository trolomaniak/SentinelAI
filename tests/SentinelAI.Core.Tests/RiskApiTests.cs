using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class RiskApiTests
{
    private const string ListPath = "/api/admin/risk";

    public static async Task VerifyAsync(string username, string password)
    {
        // A private synthetic installation keeps these scenarios independent of
        // existing device-count assertions and the inventory ingestion rate limit.
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-risk-tests-{Guid.NewGuid():N}");
        Guid endpointId;
        string persistedRisk;
        try
        {
            await using (var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"]))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                await VerifyEmptyAsync(client, token);

                var enrolled = await EnrollAsync(app);
                endpointId = enrolled.EndpointId;
                var path = DetailPath(endpointId);
                await VerifyAccessAsync(client, token, enrolled);
                await VerifyPaginationValidationAsync(client, token);
                var awaiting = await ReadAsync(client, path, token);
                Check(awaiting.GetProperty("inventoryCollectedUtc").ValueKind == JsonValueKind.Null &&
                      awaiting.GetProperty("risk").GetProperty("contributions").GetArrayLength() == 0,
                    "Missing inventory fabricated a contributing alert.");

                // Two kinds of unavailable posture plus a known clean endpoint
                // prevent a zero score from being mistaken for complete coverage.
                var missing = await EnrollAsync(app);
                var unknown = await EnrollAsync(app);
                var clean = await EnrollAsync(app);
                var timestamp = DateTimeOffset.UtcNow.AddHours(-2);
                await UploadAsync(client, Inventory(unknown.EndpointId, timestamp) with
                {
                    Hostname = "synthetic-unknown-posture",
                    SecurityPosture = new SecurityPostureInventory(null, null, null)
                }, unknown.AgentCredential);
                await UploadAsync(client, Inventory(clean.EndpointId, timestamp), clean.AgentCredential);
                using (var unverified = await client.PostAsJsonAsync("/api/agent/heartbeat",
                           new { installationId = Guid.NewGuid() }))
                    Check(unverified.StatusCode == HttpStatusCode.OK, "Could not create synthetic unverified heartbeat.");

                var risky = Inventory(endpointId, timestamp) with
                {
                    Hostname = "synthetic-risk-endpoint",
                    SecurityPosture = Inventory(endpointId, timestamp).SecurityPosture with
                    {
                        DomainFirewallEnabled = false
                    }
                };
                await UploadAsync(client, risky, enrolled.AgentCredential);
                var initial = await ReadAsync(client, path, token);
                Check(Score(initial) > 0 && initial.GetProperty("risk").GetProperty("contributions").GetArrayLength() == 1,
                    "Accepted risky inventory did not produce endpoint risk.");
                VerifyExplanation(initial, token, password, enrolled.AgentCredential);
                await VerifyOrganizationAsync(client, token, endpointId, missing.EndpointId, unknown.EndpointId,
                    clean.EndpointId, Score(initial));

                var partial = Inventory(unknown.EndpointId, timestamp.AddTicks(1)) with
                {
                    SecurityPosture = new SecurityPostureInventory(true, null, null)
                };
                await UploadAsync(client, partial, unknown.AgentCredential);
                var partialView = await ReadAsync(client, DetailPath(unknown.EndpointId), token);
                var partialOrganization = await ReadAsync(client, ListPath, token);
                Check(partialView.GetProperty("coverage").GetProperty("signalCoverage").GetString() == "partial" &&
                      partialView.GetProperty("coverage").GetProperty("knownRuleSignals").GetInt32() == 1 &&
                      partialOrganization.GetProperty("organization").GetProperty("partialSignalCount").GetInt32() == 1,
                    "Partially reported posture was counted as complete or unavailable coverage.");
                await UploadAsync(client, partial with
                {
                    CollectedUtc = partial.CollectedUtc.AddTicks(1),
                    SecurityPosture = new SecurityPostureInventory(null, null, null)
                }, unknown.AgentCredential);

                var alertId = initial.GetProperty("alerts")[0].GetProperty("alertId").GetGuid();
                await SetStatusAsync(client, token, alertId, "investigating");
                var investigating = await ReadAsync(client, path, token);
                Check(Score(investigating) == Score(initial) && Contribution(investigating, alertId).GetProperty("status").GetString() == "investigating",
                    "Investigation acknowledged risk as mitigation or failed to update contributing state.");
                await SetStatusAsync(client, token, alertId, "accepted");
                var accepted = await ReadAsync(client, path, token);
                Check(Score(accepted) == Score(initial) && Contribution(accepted, alertId).GetProperty("status").GetString() == "accepted",
                    "Accepted risk was counted as remediation or contributing status stayed stale.");
                await SetStatusAsync(client, token, alertId, "resolved");
                var resolved = await ReadAsync(client, path, token);
                var resolvedFactor = Contribution(resolved, alertId);
                Check(Score(resolved) == 0 && resolvedFactor.GetProperty("contribution").GetDecimal() == 0 &&
                      resolvedFactor.GetProperty("remainingRiskMultiplier").GetDecimal() == 0 &&
                      resolvedFactor.GetProperty("mitigationReduction").GetDecimal() > 0,
                    "Resolved alert did not reduce endpoint risk with an explicit mitigation explanation.");
                var resolvedOrganization = await ReadAsync(client, ListPath, token);
                Check(resolvedOrganization.GetProperty("organization").GetProperty("score").GetInt32() == 0,
                    "Organization risk did not respond to the relevant alert state change.");

                await UploadAsync(client, risky, enrolled.AgentCredential);
                await UploadAsync(client, risky with { CollectedUtc = timestamp.AddTicks(-1) }, enrolled.AgentCredential);
                Check(Score(await ReadAsync(client, path, token)) == 0,
                    "Equal or stale inventory reopened risk after resolution.");
                risky = risky with { CollectedUtc = timestamp.AddTicks(1) };
                await UploadAsync(client, risky, enrolled.AgentCredential);
                var reopened = await ReadAsync(client, path, token);
                Check(Score(reopened) == Score(initial) && Contribution(reopened, alertId).GetProperty("status").GetString() == "open",
                    "A newer positive observation did not restore endpoint risk.");

                risky = risky with
                {
                    CollectedUtc = risky.CollectedUtc.AddTicks(1),
                    SecurityPosture = risky.SecurityPosture with
                    {
                        Configuration = risky.SecurityPosture.Configuration! with
                        {
                            RdpEnabled = true,
                            RdpNetworkLevelAuthenticationRequired = false
                        }
                    }
                };
                await UploadAsync(client, risky, enrolled.AgentCredential);
                var correlated = await ReadAsync(client, path, token);
                Check(correlated.GetProperty("risk").GetProperty("correlatedGroups").GetArrayLength() == 2 &&
                      correlated.GetProperty("risk").GetProperty("correlationBonus").GetDecimal() > 0,
                    "Two distinct signals confirmed by the current inventory did not contribute correlation.");

                var normal = Inventory(endpointId, risky.CollectedUtc.AddTicks(1)) with { Hostname = risky.Hostname };
                await UploadAsync(client, normal, enrolled.AgentCredential);
                var historical = await ReadAsync(client, path, token);
                Check(Score(historical) > 0 && Score(historical) < Score(correlated) &&
                      historical.GetProperty("risk").GetProperty("correlationBonus").GetDecimal() == 0 &&
                      historical.GetProperty("risk").GetProperty("correlatedGroups").GetArrayLength() == 0 &&
                      historical.GetProperty("risk").GetProperty("contributions").EnumerateArray().All(c =>
                          !c.GetProperty("latestSnapshotConfirmed").GetBoolean() && !c.GetProperty("correlationEligible").GetBoolean()),
                    "Historical alerts were silently resolved or correlated without current confirming evidence.");
                await UploadAsync(client, risky, enrolled.AgentCredential);
                Check(StableRisk(await ReadAsync(client, path, token)) == StableRisk(historical),
                    "Stale inventory changed risk or reintroduced a correlation bonus.");
                persistedRisk = StableRisk(historical);
            }

            // Score is derived from persisted lifecycle/inventory state rather
            // than a process cache or an additional mutable score table.
            await using (var restarted = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"]))
            {
                using var client = await StartAsync(restarted);
                var token = await LoginAsync(client, username, password);
                Check(StableRisk(await ReadAsync(client, DetailPath(endpointId), token)) == persistedRisk,
                    "Core restart changed risk factors derived from persisted observations and alert status.");
            }

            await VerifyConfiguredPolicyAsync(directory, endpointId, username, password);
            await VerifyRemoteHttpAsync(directory, endpointId, username, password);
            await VerifyConfigurationValidationAsync(directory, endpointId);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task VerifyEmptyAsync(HttpClient client, string token)
    {
        var list = await ReadAsync(client, ListPath, token);
        var organization = list.GetProperty("organization");
        Check(list.GetProperty("total").GetInt64() == 0 && list.GetProperty("endpoints").GetArrayLength() == 0 &&
              list.GetProperty("offset").GetInt32() == 0 && list.GetProperty("limit").GetInt32() == 50 &&
              organization.GetProperty("score").GetInt32() == 0 && organization.GetProperty("endpointCount").GetInt32() == 0 &&
              organization.GetProperty("highestRiskEndpointIds").GetArrayLength() == 0,
            "Fresh Core did not return an explicit empty, bounded organization risk view.");
    }

    private static async Task VerifyAccessAsync(HttpClient client, string token, EnrollmentResponse enrolled)
    {
        foreach (var path in new[] { ListPath, DetailPath(enrolled.EndpointId) })
        {
            using (var anonymous = await client.GetAsync(path))
                Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Anonymous risk read succeeded.");
            using (var agent = await SendAsync(client, HttpMethod.Get, path, "SentinelAgent",
                       $"{enrolled.EndpointId:D}.{enrolled.AgentCredential}"))
                Check(agent.StatusCode == HttpStatusCode.Unauthorized, "Agent credential granted administrative risk access.");
        }
        using var missing = await SendAsync(client, HttpMethod.Get, DetailPath(Guid.NewGuid()), "Bearer", token);
        Check(missing.StatusCode == HttpStatusCode.NotFound, "Unknown endpoint fabricated risk data.");
    }

    private static async Task VerifyPaginationValidationAsync(HttpClient client, string token)
    {
        foreach (var query in new[] { "offset=-1", "offset=no", "offset=2147483648", "offset=0&offset=1",
                     "limit=0", "limit=201", "limit=no", "limit=1&limit=2" })
        {
            using var invalid = await SendAsync(client, HttpMethod.Get, ListPath + "?" + query, "Bearer", token);
            Check(invalid.StatusCode == HttpStatusCode.BadRequest, "Invalid risk pagination was accepted: " + query);
        }
    }

    private static async Task VerifyOrganizationAsync(HttpClient client, string token, Guid endpointId,
        Guid missingId, Guid unknownId, Guid cleanId, int maximumScore)
    {
        var list = await ReadAsync(client, ListPath, token);
        var organization = list.GetProperty("organization");
        var endpoints = list.GetProperty("endpoints").EnumerateArray().ToArray();
        Check(list.GetProperty("total").GetInt64() == 4 && endpoints.Length == 4 &&
              organization.GetProperty("endpointCount").GetInt32() == 4 &&
              organization.GetProperty("score").GetInt32() == maximumScore &&
              organization.GetProperty("highestRiskEndpointIds").EnumerateArray().Single().GetGuid() == endpointId &&
              organization.GetProperty("highestRiskEndpointCount").GetInt32() == 1 &&
              !organization.GetProperty("highestRiskEndpointIdsTruncated").GetBoolean() &&
              endpoints[0].GetProperty("endpointId").GetGuid() == endpointId,
            "Organization score averaged away risk, failed to rank it, or included an unverified endpoint.");
        Check(!string.IsNullOrWhiteSpace(organization.GetProperty("method").GetString()) &&
              !string.IsNullOrWhiteSpace(organization.GetProperty("explanation").GetString()),
            "Organization risk omitted its aggregation explanation.");
        Check(endpoints[0].GetProperty("unresolvedAlertCount").GetInt32() == 1 &&
              !string.IsNullOrWhiteSpace(endpoints[0].GetProperty("highestContributorReason").GetString()),
            "Ranked endpoint summary omitted its highest contributing reason and unresolved finding count.");
        Check(organization.GetProperty("observedEndpointCount").GetInt32() == 3 &&
              organization.GetProperty("missingInventoryCount").GetInt32() == 1 &&
              organization.GetProperty("unknownSignalCount").GetInt32() == 2 &&
              organization.GetProperty("partialSignalCount").GetInt32() == 0 &&
              organization.GetProperty("staleInventoryCount").GetInt32() == 0 &&
              organization.GetProperty("alertStatusCounts").GetProperty("open").GetInt32() == 1 &&
              endpoints.All(endpoint => endpoint.GetProperty("evaluatedUtc").GetDateTimeOffset() ==
                  organization.GetProperty("evaluatedUtc").GetDateTimeOffset()),
            "Organization coverage, lifecycle counts or consistent evaluation time were incorrect.");

        var first = await ReadAsync(client, ListPath + "?offset=0&limit=1", token);
        var second = await ReadAsync(client, ListPath + "?offset=1&limit=1", token);
        var pastEnd = await ReadAsync(client, ListPath + "?offset=100&limit=200", token);
        Check(first.GetProperty("endpoints").GetArrayLength() == 1 && second.GetProperty("endpoints").GetArrayLength() == 1 &&
              first.GetProperty("endpoints")[0].GetProperty("endpointId").GetGuid() !=
              second.GetProperty("endpoints")[0].GetProperty("endpointId").GetGuid() &&
              pastEnd.GetProperty("endpoints").GetArrayLength() == 0 && pastEnd.GetProperty("total").GetInt64() == 4 &&
              second.GetProperty("organization").GetProperty("score").GetInt32() == maximumScore &&
              pastEnd.GetProperty("organization").GetProperty("score").GetInt32() == maximumScore,
            "Risk pagination duplicated endpoints or calculated the organization score from only the visible page.");

        var missing = await ReadAsync(client, DetailPath(missingId), token);
        var unknown = await ReadAsync(client, DetailPath(unknownId), token);
        var clean = await ReadAsync(client, DetailPath(cleanId), token);
        Check(missing.GetProperty("inventoryCollectedUtc").ValueKind == JsonValueKind.Null &&
              unknown.GetProperty("inventoryCollectedUtc").ValueKind == JsonValueKind.String &&
              Score(missing) == 0 && Score(unknown) == 0 && Score(clean) == 0,
            "Missing or unknown posture fabricated positive findings, or clean posture had positive risk.");
        Check(missing.GetProperty("coverage").GetProperty("inventoryState").GetString() == "missing" &&
              missing.GetProperty("coverage").GetProperty("signalCoverage").GetString() == "unknown" &&
              unknown.GetProperty("coverage").GetProperty("inventoryState").GetString() == "current" &&
              unknown.GetProperty("coverage").GetProperty("signalCoverage").GetString() == "unknown" &&
              unknown.GetProperty("coverage").GetProperty("knownRuleSignals").GetInt32() == 0 &&
              clean.GetProperty("coverage").GetProperty("signalCoverage").GetString() == "complete" &&
              clean.GetProperty("coverage").GetProperty("knownRuleSignals").GetInt32() == 13 &&
              clean.GetProperty("coverage").GetProperty("totalRuleSignals").GetInt32() == 13 &&
              !string.IsNullOrWhiteSpace(unknown.GetProperty("coverage").GetProperty("caution").GetString()),
            "Unknown and missing posture lacked coverage warnings or were confused with known clean configuration.");
    }

    private static void VerifyExplanation(JsonElement detail, params string[] secrets)
    {
        var risk = detail.GetProperty("risk");
        var context = risk.GetProperty("context");
        Check(context.GetProperty("assetCriticality").GetString() == "standard" &&
              context.GetProperty("exposure").GetString() == "unknown" &&
              context.GetProperty("assetCriticalitySource").GetString() == "policyDefault" &&
              context.GetProperty("exposureSource").GetString() == "policyDefault" &&
              risk.GetProperty("assetCriticalityMultiplier").GetDecimal() == 1 &&
              risk.GetProperty("exposureMultiplier").GetDecimal() == 1 &&
              !string.IsNullOrWhiteSpace(risk.GetProperty("explanation").GetString()),
            "Risk explanation hid default context or inferred Internet exposure from a firewall finding.");
        var factor = risk.GetProperty("contributions")[0];
        foreach (var name in new[] { "severityPoints", "detectionConfidence", "assetCriticalityMultiplier",
                     "exposureMultiplier", "ageDays", "ageMultiplier", "remainingRiskMultiplier", "pointsBeforeMitigation",
                     "mitigationReduction", "contribution" })
            Check(factor.GetProperty(name).ValueKind == JsonValueKind.Number, "Risk factor missing numeric explanation: " + name);
        Check(factor.GetProperty("alertId").GetGuid() == detail.GetProperty("alerts")[0].GetProperty("alertId").GetGuid() &&
              factor.GetProperty("ruleId").GetString() == "SA-FW-001" && factor.GetProperty("severity").GetString() == "high" &&
              factor.GetProperty("detectionConfidence").GetDecimal() == 1 &&
              !string.IsNullOrWhiteSpace(factor.GetProperty("confidenceSource").GetString()) &&
              factor.GetProperty("ageBand").GetString() == "fresh" &&
              !factor.GetProperty("futureTimestampClamped").GetBoolean() &&
              factor.GetProperty("lastObservedUtc").GetDateTimeOffset() == detail.GetProperty("inventoryCollectedUtc").GetDateTimeOffset() &&
              !risk.GetProperty("saturated").GetBoolean() && risk.GetProperty("rawScore").GetDecimal() > 0,
            "Risk contributions lost source alert, confidence, age or cap information.");
        foreach (var secret in secrets)
            Check(!detail.GetRawText().Contains(secret, StringComparison.Ordinal), "Risk API leaked a credential.");
    }

    private static async Task VerifyConfiguredPolicyAsync(string directory, Guid endpointId, string username, string password)
    {
        await using var app = CoreHost.Build([
            $"--SentinelAI:DataDirectory={directory}",
            "--SentinelAI:RiskScoring:Policy:Version=synthetic-test-policy",
            "--SentinelAI:RiskScoring:Policy:SeverityPoints:high=40",
            "--SentinelAI:RiskScoring:Policy:ConfidenceByRule:SA-FW-001=0.8",
            "--SentinelAI:RiskScoring:InventoryFreshForHours=1",
            $"--SentinelAI:RiskScoring:EndpointContexts:{endpointId:D}:AssetCriticality=critical",
            $"--SentinelAI:RiskScoring:EndpointContexts:{endpointId:D}:Exposure=internet"
        ]);
        using var client = await StartAsync(app);
        var token = await LoginAsync(client, username, password);
        var detail = await ReadAsync(client, DetailPath(endpointId), token);
        var risk = detail.GetProperty("risk");
        var context = risk.GetProperty("context");
        var firewall = risk.GetProperty("contributions").EnumerateArray().Single(c => c.GetProperty("ruleId").GetString() == "SA-FW-001");
        Check(context.GetProperty("assetCriticality").GetString() == "critical" &&
              context.GetProperty("exposure").GetString() == "internet" &&
              context.GetProperty("assetCriticalitySource").GetString() == "userDeclared" &&
              context.GetProperty("exposureSource").GetString() == "userDeclared" &&
              firewall.GetProperty("severityPoints").GetDecimal() == 40 &&
              firewall.GetProperty("detectionConfidence").GetDecimal() == 0.8m &&
              firewall.GetProperty("confidenceSource").GetString() == "rulePolicyOverride" &&
              risk.GetProperty("assetCriticalityMultiplier").GetDecimal() > 1 &&
              risk.GetProperty("exposureMultiplier").GetDecimal() > 1,
            "Configured weights, confidence or declared endpoint context did not reach the API explanation.");
        var list = await ReadAsync(client, ListPath, token);
        var policy = list.GetProperty("policy");
        Check(policy.GetProperty("version").GetString() == "synthetic-test-policy" &&
              policy.GetProperty("severityPoints").GetProperty("high").GetDecimal() == 40 &&
              policy.GetProperty("maximumScore").GetInt32() == Score(detail) &&
              risk.GetProperty("saturated").GetBoolean() && risk.GetProperty("rawScore").GetDecimal() > Score(detail),
            "Configured policy was hidden, or score saturation discarded its raw-score explanation.");
        Check(detail.GetProperty("coverage").GetProperty("inventoryState").GetString() == "stale" &&
              list.GetProperty("organization").GetProperty("staleInventoryCount").GetInt32() == 3 &&
              list.GetProperty("inventoryFreshForHours").GetInt32() == 1,
            "Configured inventory freshness was ignored or stale observed coverage was hidden.");
    }

    private static async Task VerifyConfigurationValidationAsync(string directory, Guid endpointId)
    {
        foreach (var setting in new[]
                 {
                     "--SentinelAI:RiskScoring:Policy:DefaultConfidence=1.1",
                     "--SentinelAI:RiskScoring:Policy:MisspelledWeight=2",
                     "--SentinelAI:RiskScoring:InventoryFreshForHours=0",
                     $"--SentinelAI:RiskScoring:EndpointContexts:{endpointId:D}:Exposure=unrecognized",
                     $"--SentinelAI:RiskScoring:EndpointContexts:{endpointId:D}:UnrecognizedFactor=high"
                 })
        {
            var rejected = false;
            try
            {
                await using var ignored = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}", setting]);
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                rejected = true;
            }
            Check(rejected, "Invalid scoring configuration silently changed or fell back to default policy: " + setting);
        }
    }

    private static async Task VerifyRemoteHttpAsync(string directory, Guid endpointId, string username, string password)
    {
        await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"]);
        app.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
            await next(context);
        });
        using var client = await StartAsync(app);
        var token = await LoginAsync(client, username, password);
        foreach (var path in new[] { ListPath, DetailPath(endpointId) })
        {
            using var response = await SendAsync(client, HttpMethod.Get, path, "Bearer", token);
            Check(response.StatusCode == HttpStatusCode.Forbidden, "Core exposed administrator risk over remote HTTP.");
        }
    }

    private static string StableRisk(JsonElement detail)
    {
        var risk = detail.GetProperty("risk");
        return JsonSerializer.Serialize(new
        {
            inventory = detail.GetProperty("inventoryCollectedUtc").GetDateTimeOffset(),
            score = Score(detail),
            raw = risk.GetProperty("rawScore").GetDecimal(),
            context = risk.GetProperty("context"),
            correlation = risk.GetProperty("correlationBonus").GetDecimal(),
            contributions = risk.GetProperty("contributions").EnumerateArray().Select(c => new
            {
                alertId = c.GetProperty("alertId").GetGuid(),
                ruleId = c.GetProperty("ruleId").GetString(),
                status = c.GetProperty("status").GetString(),
                observed = c.GetProperty("lastObservedUtc").GetDateTimeOffset(),
                ageBand = c.GetProperty("ageBand").GetString(),
                contribution = c.GetProperty("contribution").GetDecimal(),
                confirmed = c.GetProperty("latestSnapshotConfirmed").GetBoolean(),
                eligible = c.GetProperty("correlationEligible").GetBoolean()
            }).ToArray()
        });
    }

    private static InventoryReport Inventory(Guid endpointId, DateTimeOffset timestamp) => new(
        endpointId, timestamp, "synthetic-test", "synthetic-clean", "Windows", "11 synthetic", "X64",
        new CpuInventory("Synthetic CPU", 4), 8L * 1024 * 1024 * 1024, [],
        new SecurityPostureInventory(true, true, true, new WindowsSecurityConfiguration(
            UacEnabled: true, AdminConsentPromptBehavior: 5, RdpEnabled: false,
            RdpNetworkLevelAuthenticationRequired: true, RdpSecurityLayer: 2, RdpMinimumEncryptionLevel: 3,
            Smb1ServerEnabled: false, SmbInsecureGuestLogonsAllowed: false, AutomaticAdminLogonEnabled: false,
            LsaProtectionEnabled: true, AutomaticUpdatesDisabled: false)));

    private static async Task<EnrollmentResponse> EnrollAsync(WebApplication app)
    {
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrollment = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        return enrollment.Response ?? throw new InvalidOperationException("Synthetic risk endpoint could not enroll.");
    }

    private static async Task SetStatusAsync(HttpClient client, string token, Guid alertId, string status)
    {
        var path = $"/api/admin/alerts/{alertId:D}";
        var alert = await ReadAsync(client, path, token);
        using var response = await SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token,
            new { status, expectedVersion = alert.GetProperty("version").GetInt64() });
        Check(response.StatusCode == HttpStatusCode.OK, "Could not update synthetic alert status: " + status);
    }

    private static async Task UploadAsync(HttpClient client, InventoryReport inventory, string credential)
    {
        using var response = await SendAsync(client, HttpMethod.Post, "/api/agent/inventory", "SentinelAgent",
            $"{inventory.EndpointId:D}.{credential}", inventory);
        Check(response.StatusCode == HttpStatusCode.NoContent, "Risk fixture inventory failed: " + response.StatusCode);
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(10)
        };
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic risk Core could not authenticate.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<JsonElement> ReadAsync(HttpClient client, string path, string token)
    {
        using var response = await SendAsync(client, HttpMethod.Get, path, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            "Administrator risk or source alert was unavailable or cacheable: " + path);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.Clone();
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method,
        string path, string scheme, string token, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        if (body is not null) request.Content = JsonContent.Create(body);
        return await client.SendAsync(request);
    }

    private static string DetailPath(Guid endpointId) => $"/api/admin/devices/{endpointId:D}/risk";
    private static int Score(JsonElement detail) => detail.GetProperty("risk").GetProperty("score").GetInt32();
    private static JsonElement Contribution(JsonElement detail, Guid alertId) =>
        detail.GetProperty("risk").GetProperty("contributions").EnumerateArray().Single(c => c.GetProperty("alertId").GetGuid() == alertId);
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
