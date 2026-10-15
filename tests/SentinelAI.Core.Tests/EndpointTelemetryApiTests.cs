using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

/// <summary>
/// Endpoint telemetry ingest, persistence, rules, Risk, reports and the device view (TASK-029). Synthetic values only:
/// fictitious SIDs (S-1-5-21-1000-1000-1000-*), test-only application names and a per-run marker.
/// </summary>
internal static class EndpointTelemetryApiTests
{
    private const string IngestPath = "/api/agent/security-telemetry";
    private const string Collected = TelemetryAvailability.Collected;
    private static readonly string Marker = $"test-only-telemetry-{Guid.NewGuid():N}";

    private sealed record Agent(Guid EndpointId, string Credential)
    {
        public string Authorization => $"{EndpointId:D}.{Credential}";
        public override string ToString() => nameof(Agent);
    }

    public static async Task VerifyAsync(string username, string password)
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-telemetry-tests-{Guid.NewGuid():N}");
        var logs = new CapturingLoggerProvider();
        try
        {
            await VerifyIngestRulesAndViewsAsync(Path.Combine(root, "ingest"), username, password, logs);
            await VerifyStrictnessAsync(Path.Combine(root, "strict"), logs);
            await VerifyRateLimitAsync(Path.Combine(root, "rate"), logs);
            Check(logs.Entries.Count > 0 && logs.Entries.All(entry =>
                    !entry.Message.Contains(Marker, StringComparison.Ordinal) &&
                    !entry.Message.Contains("S-1-5-21-1000-1000-1000-", StringComparison.Ordinal)),
                "Core logged telemetry content, an identity or a request body.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }

        Console.WriteLine("Endpoint telemetry API tests passed (ingest, newest-wins persistence, strict validation, " +
                          "authentication before the body, rules and alert lifecycle, device view, Risk, reports, restart, rate limit).");
    }

    // T1–T8: ingest, the device projection, newest-wins ordering, rules through the alert lifecycle, Risk, reports
    // and persistence across a restart.
    private static async Task VerifyIngestRulesAndViewsAsync(string directory, string username, string password,
        CapturingLoggerProvider logs)
    {
        Agent agent;
        Agent silent;
        DateTimeOffset newest;
        await using (var app = Build(directory, logs))
        {
            using var client = await StartAsync(app);
            agent = await EnrollAsync(app);
            silent = await EnrollAsync(app);
            var token = await LoginAsync(client, username, password);

            // T1: the Agent's wire form is accepted and projected without the application list.
            var collected = DateTimeOffset.UtcNow.AddMinutes(-10);
            collected = new DateTimeOffset(collected.Ticks - collected.Ticks % TimeSpan.TicksPerMillisecond, TimeSpan.Zero);
            var benign = Benign(agent.EndpointId, collected);
            Check(await PostStatusAsync(client, agent, Wire(benign)) == HttpStatusCode.NoContent,
                "Core did not accept a valid telemetry report.");
            using (var detail = await GetJsonAsync(client, $"/api/admin/devices/{agent.EndpointId:D}", token))
            {
                var telemetry = detail.RootElement.GetProperty("securityTelemetry");
                Check(telemetry.GetProperty("schemaVersion").GetInt32() == 1 &&
                      telemetry.GetProperty("collectedUtc").GetDateTimeOffset() == collected &&
                      telemetry.GetProperty("receivedUtc").GetDateTimeOffset() >= collected,
                    "The device view did not carry the telemetry version and times.");
                Check(Names(telemetry).SequenceEqual(["antivirus", "bitLocker", "collectedUtc", "defender", "localAdministrators",
                        "pendingReboot", "receivedUtc", "schemaVersion", "services", "software", "windowsUpdate"]),
                    "The telemetry projection exposed unexpected members.");
                // Desktop parses this projection strictly; every member name is part of its contract.
                var sections = new Dictionary<string, string[]>
                {
                    ["bitLocker"] = ["availability", "conversionStatus", "protectionStatus"],
                    ["antivirus"] = ["availability", "securityCenterHealth"],
                    ["defender"] = ["antivirusEnabled", "availability", "realTimeProtectionEnabled", "runningMode", "signatureAgeDays",
                        "tamperProtectionEnabled"],
                    ["localAdministrators"] = ["availability", "memberCount", "members"],
                    ["windowsUpdate"] = ["automaticUpdatesPolicy", "lastSuccessfulInstallationUtc", "lastSuccessfulSearchUtc",
                        "managedUpdateServer", "policyAvailability", "resultsAvailability"],
                    ["pendingReboot"] = ["availability", "componentBasedServicing", "pendingFileRenameOperations", "windowsUpdate"],
                    ["services"] = ["availability", "items"]
                };
                foreach (var (section, names) in sections)
                {
                    Check(Names(telemetry.GetProperty(section)).SequenceEqual(names), $"The {section} projection changed its members.");
                }

                Check(Names(telemetry.GetProperty("services").GetProperty("items")[0]).SequenceEqual(["name", "startType", "state"]) &&
                      telemetry.GetProperty("collectedUtc").GetDateTimeOffset().Offset == TimeSpan.Zero,
                    "Service items or telemetry times changed their form.");
                var software = telemetry.GetProperty("software");
                Check(Names(software).SequenceEqual(["availability", "reportedCount", "skippedCount", "totalCount", "truncated"]) &&
                      software.GetProperty("totalCount").GetInt32() == 3 && software.GetProperty("reportedCount").GetInt32() == 2 &&
                      software.GetProperty("truncated").GetBoolean() && software.GetProperty("skippedCount").GetInt32() == 1,
                    "The device view must summarize installed applications without listing them.");
                Check(!detail.RootElement.GetRawText().Contains(Marker, StringComparison.Ordinal),
                    "The device view exposed the installed application list.");
                var members = telemetry.GetProperty("localAdministrators").GetProperty("members");
                Check(members.GetArrayLength() == 2 && Names(members[0]).SequenceEqual(["accountType", "scope", "sid"]),
                    "Administrator members must be SIDs with scope and account type only.");
                Check(telemetry.GetProperty("bitLocker").GetProperty("availability").GetString() == TelemetryAvailability.AccessDenied &&
                      telemetry.GetProperty("bitLocker").GetProperty("protectionStatus").ValueKind == JsonValueKind.Null,
                    "An uncollected section must stay Unknown in the device view.");
            }

            var stored = await app.Services.GetRequiredService<EndpointTelemetryStore>().FindLatestAsync(agent.EndpointId);
            Check(stored is not null && stored.Report.CollectedUtc == collected &&
                  stored.Report.Software.Items!.Count == 2 && stored.Report.Software.Items[0].Name.StartsWith("Example", StringComparison.Ordinal),
                "Core did not persist the complete accepted report, including the application list.");
            Check(await AlertCountAsync(app, agent.EndpointId) == 0, "A benign report raised an alert.");

            // T2: newest wins by the Agent's collection time; older and equal reports change nothing.
            var older = benign with { CollectedUtc = collected.AddMinutes(-5), Antivirus = new AntivirusTelemetry(Collected, "poor") };
            Check(await PostStatusAsync(client, agent, Wire(older)) == HttpStatusCode.NoContent,
                "Core must acknowledge an older report without storing it.");
            var same = benign with { Antivirus = new AntivirusTelemetry(Collected, "snooze") };
            Check(await PostStatusAsync(client, agent, Wire(same)) == HttpStatusCode.NoContent, "Core refused a duplicate report.");
            stored = await app.Services.GetRequiredService<EndpointTelemetryStore>().FindLatestAsync(agent.EndpointId);
            Check(stored!.Report.Antivirus.SecurityCenterHealth == "good" && await AlertCountAsync(app, agent.EndpointId) == 0,
                "An older or equally old report replaced the stored report or raised an alert.");

            // T3: rules raise tracked alerts in the ingest transaction, named before the first inventory.
            var risky = benign with
            {
                CollectedUtc = collected.AddMinutes(1),
                Antivirus = new AntivirusTelemetry(Collected, "poor"),
                BitLocker = new BitLockerTelemetry(Collected, "off", "fullyDecrypted"),
                Services = new SecurityServicesTelemetry(Collected,
                [
                    new("MpsSvc", ServiceRunStates.Stopped, ServiceStartTypes.Auto),
                    new("EventLog", ServiceRunStates.Running, ServiceStartTypes.Disabled),
                    new("WinDefend", ServiceRunStates.Stopped, ServiceStartTypes.Disabled)
                ])
            };
            Check(await PostStatusAsync(client, agent, Wire(risky)) == HttpStatusCode.NoContent, "Core refused a risky report.");
            var alerts = await AlertsAsync(app, agent.EndpointId);
            Check(alerts.Select(alert => alert[0]).Order(StringComparer.Ordinal)
                      .SequenceEqual(["SA-AV-001", "SA-DISK-001", "SA-SVC-001", "SA-SVC-002"]),
                "The telemetry rules did not raise exactly the four expected alerts.");
            Check(alerts.All(alert => alert[1] == "open" && alert[2] == "1" &&
                                      alert[3] == SecurityEventStore.PlaceholderEndpointName(agent.EndpointId) &&
                                      alert[4] == risky.CollectedUtc.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture)),
                "Telemetry alerts must open at version 1, timed by the report, with the placeholder name before inventory.");
            var avAlert = alerts.Single(alert => alert[0] == "SA-AV-001");
            using (var detail = await GetJsonAsync(client, $"/api/admin/alerts/{avAlert[5]}", token))
            {
                var evidence = detail.RootElement.GetProperty("evidence");
                Check(evidence.GetArrayLength() == 1 && evidence[0].GetProperty("field").GetString() == "antivirus.securityCenterHealth" &&
                      evidence[0].GetProperty("value").GetString() == "poor",
                    "SA-AV-001 did not carry its typed evidence through the alert detail.");
            }

            // A replay of the same report never re-fires; an older risky report never replaces newer evidence.
            Check(await PostStatusAsync(client, agent, Wire(risky)) == HttpStatusCode.NoContent &&
                  (await AlertsAsync(app, agent.EndpointId)).All(alert => alert[2] == "1"),
                "Replaying a stored report changed tracked alerts.");

            // T4: status decisions persist; normal telemetry never resolves; newer positive evidence reopens Resolved.
            await SetStatusAsync(client, token, Guid.Parse(avAlert[5]), "resolved", 1);
            newest = collected.AddMinutes(2);
            Check(await PostStatusAsync(client, agent, Wire(benign with { CollectedUtc = newest })) == HttpStatusCode.NoContent,
                "Core refused a newer benign report.");
            alerts = await AlertsAsync(app, agent.EndpointId);
            Check(alerts.Single(alert => alert[0] == "SA-AV-001")[1] == "resolved" &&
                  alerts.Where(alert => alert[0] != "SA-AV-001").All(alert => alert[1] == "open"),
                "Normal telemetry must neither resolve nor reopen alerts.");
            newest = newest.AddMinutes(1);
            Check(await PostStatusAsync(client, agent, Wire(risky with { CollectedUtc = newest })) == HttpStatusCode.NoContent,
                "Core refused a newer risky report.");
            Check((await AlertsAsync(app, agent.EndpointId)).Single(alert => alert[0] == "SA-AV-001") is ["SA-AV-001", "open", "3", ..],
                "Newer positive telemetry must reopen a resolved alert.");

            // The first inventory renames the placeholder on telemetry alerts too.
            Check(await PostInventoryAsync(client, agent, newest) == HttpStatusCode.NoContent, "Core refused the inventory.");
            Check((await AlertsAsync(app, agent.EndpointId)).All(alert => alert[3] == "test-only-telemetry-host"),
                "The first inventory did not rename telemetry alerts.");

            // T5: Risk scores the findings, correlates those confirmed by the latest report and states telemetry coverage.
            using (var risk = await GetJsonAsync(client, $"/api/admin/devices/{agent.EndpointId:D}/risk", token))
            {
                var contributions = risk.RootElement.GetProperty("risk").GetProperty("contributions").EnumerateArray()
                    .ToDictionary(item => item.GetProperty("ruleId").GetString()!);
                Check(contributions.Count == 4 && contributions.Values.All(item =>
                          item.GetProperty("latestSnapshotConfirmed").GetBoolean() && item.GetProperty("correlationEligible").GetBoolean()),
                    "Telemetry findings confirmed by the latest report must be correlation-eligible.");
                Check(risk.RootElement.GetProperty("risk").GetProperty("correlatedGroups").EnumerateArray()
                          .Select(group => group.GetString()).SequenceEqual(["AV", "DISK", "FW", "LOGGING"]),
                    "Telemetry findings must correlate by their policy groups.");
                var caution = risk.RootElement.GetProperty("coverage").GetProperty("caution").GetString()!;
                Check(caution.Contains("All 4 endpoint telemetry rules have collected inputs.", StringComparison.Ordinal),
                    $"Risk coverage did not state telemetry coverage: {caution}");
            }

            // A newer report that no longer confirms a finding leaves it scored but uncorrelated, and names what is
            // not collected.
            newest = newest.AddMinutes(1);
            var partial = benign with
            {
                CollectedUtc = newest,
                BitLocker = new BitLockerTelemetry(TelemetryAvailability.AccessDenied),
                Antivirus = new AntivirusTelemetry(Collected, "poor")
            };
            Check(await PostStatusAsync(client, agent, Wire(partial)) == HttpStatusCode.NoContent, "Core refused a partial report.");
            using (var risk = await GetJsonAsync(client, $"/api/admin/devices/{agent.EndpointId:D}/risk", token))
            {
                var contributions = risk.RootElement.GetProperty("risk").GetProperty("contributions").EnumerateArray()
                    .ToDictionary(item => item.GetProperty("ruleId").GetString()!);
                Check(contributions["SA-AV-001"].GetProperty("correlationEligible").GetBoolean() &&
                      !contributions["SA-DISK-001"].GetProperty("latestSnapshotConfirmed").GetBoolean() &&
                      contributions["SA-DISK-001"].GetProperty("contribution").GetDecimal() > 0m,
                    "Only findings confirmed by the latest telemetry report may correlate; unconfirmed ones still score.");
                var caution = risk.RootElement.GetProperty("coverage").GetProperty("caution").GetString()!;
                Check(caution.Contains("3 of 4 endpoint telemetry rules can fire; not collected: bitLocker (accessDenied).",
                        StringComparison.Ordinal), $"Risk coverage did not name the uncollected telemetry: {caution}");
            }

            using (var risk = await GetJsonAsync(client, $"/api/admin/devices/{silent.EndpointId:D}/risk", token))
            {
                Check(risk.RootElement.GetProperty("coverage").GetProperty("caution").GetString()!
                        .Contains("No endpoint telemetry is reported, so its 4 rules cannot fire.", StringComparison.Ordinal),
                    "Risk coverage must state that an endpoint without telemetry cannot raise telemetry findings.");
            }

            using (var detail = await GetJsonAsync(client, $"/api/admin/devices/{silent.EndpointId:D}", token))
            {
                Check(detail.RootElement.GetProperty("securityTelemetry").ValueKind == JsonValueKind.Null,
                    "An endpoint without telemetry must have no telemetry projection.");
            }

            // T6: reports use each telemetry rule's own wording and a separate recommendation.
            var today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            var yesterday = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            using (var request = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/reports/security?from={yesterday}&to={today}"))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var response = await client.SendAsync(request);
                var html = await response.Content.ReadAsStringAsync();
                Check(response.StatusCode == HttpStatusCode.OK && html.Contains("Antivirus protection reported at risk", StringComparison.Ordinal) &&
                      html.Contains("Windows Defender Firewall service not running", StringComparison.Ordinal) &&
                      html.Contains("Tracked unresolved endpoint telemetry findings", StringComparison.Ordinal) &&
                      !html.Contains("Unsupported stored rule", StringComparison.Ordinal) &&
                      !html.Contains(Marker, StringComparison.Ordinal),
                    "The report did not present telemetry findings with their own wording.");
            }
        }

        // T7: a restart keeps the newest report and its alerts; initialization is idempotent.
        await using (var app = Build(directory, logs))
        {
            using var client = await StartAsync(app);
            var stored = await app.Services.GetRequiredService<EndpointTelemetryStore>().FindLatestAsync(agent.EndpointId);
            Check(stored?.Report.CollectedUtc == newest && (await AlertsAsync(app, agent.EndpointId)).Count == 4,
                "The newest telemetry report or its alerts did not survive a restart.");
        }
    }

    // T8: strict validation. Every refusal happens before storage; unauthenticated bodies are never read.
    private static async Task VerifyStrictnessAsync(string directory, CapturingLoggerProvider logs)
    {
        await using var app = Build(directory, logs);
        using var client = await StartAsync(app);
        var a = await EnrollAsync(app);
        var b = await EnrollAsync(app);
        var collected = DateTimeOffset.UtcNow.AddMinutes(-1);
        var report = Benign(a.EndpointId, collected);
        var valid = JsonSerializer.Serialize(report, EndpointTelemetryContract.Json);
        var padded = valid.Insert(1, $"\"testOnlyPadding\":\"{new string('x', 4 * 1024)}\",");
        var oversized = valid.Insert(1, $"\"testOnlyPadding\":\"{new string('x', 300 * 1024)}\",");
        string Mutate(Action<JsonObject> change)
        {
            var node = JsonSerializer.SerializeToNode(report, EndpointTelemetryContract.Json)!.AsObject();
            change(node);
            return node.ToJsonString();
        }

        var wrongCredential = a with { Credential = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)) };
        using var unreadClient = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false, Expect100ContinueTimeout = TimeSpan.FromSeconds(30)
        }) { BaseAddress = client.BaseAddress, Timeout = TimeSpan.FromSeconds(30) };
        var unread = new HashSet<string>(StringComparer.Ordinal) { "anonymous body", "anonymous oversized body", "wrong credential" };
        var cases = new (string Name, HttpStatusCode Expected, Agent? Agent, Func<HttpContent> Content)[]
        {
            ("anonymous body", HttpStatusCode.Unauthorized, null, () => Raw(padded)),
            ("anonymous oversized body", HttpStatusCode.Unauthorized, null, () => Raw(oversized)),
            ("wrong credential", HttpStatusCode.Unauthorized, wrongCredential, () => Raw(padded)),
            ("another endpoint's credential", HttpStatusCode.Unauthorized, b, () => Raw(valid)),
            ("oversized body", HttpStatusCode.RequestEntityTooLarge, a, () => Raw(oversized)),
            ("wrong media type", HttpStatusCode.UnsupportedMediaType, a, () => Raw(valid, "text/plain")),
            ("malformed JSON", HttpStatusCode.BadRequest, a, () => Raw(valid[..^2])),
            ("duplicate property", HttpStatusCode.BadRequest, a, () => Raw(valid.Insert(1, "\"schemaVersion\":1,"))),
            ("quoted number", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node["schemaVersion"] = "1"))),
            ("missing section", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node.Remove("services")))),
            ("unknown schema version", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node => node["schemaVersion"] = 2))),
            ("future collection time", HttpStatusCode.BadRequest, a,
                () => Raw(Mutate(node => node["collectedUtc"] = DateTimeOffset.UtcNow.AddMinutes(10)))),
            ("local-offset collection time", HttpStatusCode.BadRequest, a,
                () => Raw(Mutate(node => node["collectedUtc"] = "2026-01-01T10:00:00+02:00"))),
            ("value in an uncollected section", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["bitLocker"]!["protectionStatus"] = "on"))),
            ("unknown availability", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["antivirus"]!["availability"] = "partial"))),
            ("unknown vocabulary value", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["antivirus"]!["securityCenterHealth"] = "excellent"))),
            ("invalid administrator SID", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["localAdministrators"]!["members"]![0]!["sid"] = "Administrator"))),
            ("administrator count below the listed members", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["localAdministrators"]!["memberCount"] = 1))),
            ("service outside the catalog", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["services"]!["items"]![0]!["name"] = "Spooler"))),
            ("absent service with a start type", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["services"]!["items"]![2]!["startType"] = "auto"))),
            ("inconsistent truncation", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["software"]!["truncated"] = false))),
            ("control character in an application name", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["software"]!["items"]![0]!["name"] = "test-only\u0007app"))),
            ("update result after collection", HttpStatusCode.BadRequest, a, () => Raw(Mutate(node =>
                node["windowsUpdate"]!["lastSuccessfulSearchUtc"] = collected.AddDays(3))))
        };
        foreach (var (name, expected, agent, content) in cases)
        {
            var tracked = unread.Contains(name) ? new TrackedContent(content()) : null;
            using var request = new HttpRequestMessage(HttpMethod.Post, IngestPath) { Content = tracked ?? content() };
            if (agent is not null) request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
            request.Headers.ConnectionClose = true;
            request.Headers.ExpectContinue = tracked is not null;
            using var response = await (tracked is null ? client : unreadClient).SendAsync(request);
            Check(response.StatusCode == expected,
                $"Telemetry ingest returned HTTP {(int)response.StatusCode} instead of {(int)expected} for: {name}.");
            Check(tracked is not { Sent: true }, $"Core read a request body it must refuse unread: {name}.");
        }

        var store = app.Services.GetRequiredService<EndpointTelemetryStore>();
        Check(await store.FindLatestAsync(a.EndpointId) is null && await store.FindLatestAsync(b.EndpointId) is null,
            "A rejected telemetry request changed Core state.");
        var refusals = logs.Entries.Where(entry => entry.Level == LogLevel.Warning &&
            entry.Message.StartsWith("Endpoint telemetry from endpoint", StringComparison.Ordinal)).ToArray();
        Check(refusals.Length == cases.Count(item => item.Agent == a) &&
              refusals.All(entry => entry.Message.StartsWith($"Endpoint telemetry from endpoint {a.EndpointId:D} rejected with HTTP 4",
                  StringComparison.Ordinal)),
            "Authenticated refusals must be logged with only the endpoint and status code.");

        // An unknown member is ignored and never stored; the valid remainder is accepted.
        Check(await PostStatusAsync(client, a, Raw(valid.Insert(1, "\"testOnlyExtra\":\"test-only-extra\","))) == HttpStatusCode.NoContent,
            "Core refused a report with an additional unknown member.");
        var rows = await QueryAsync(app, "SELECT ReportJson FROM EndpointSecurityTelemetry WHERE EndpointId = $e;", a.EndpointId);
        Check(rows.Count == 1 && !rows[0].Contains("testOnlyExtra", StringComparison.Ordinal) &&
              !rows[0].Contains("test-only-extra", StringComparison.Ordinal),
            "Core stored a member outside the contract.");

        // Each endpoint stores only its own reports.
        Check(await PostStatusAsync(client, b, Wire(Benign(b.EndpointId, collected))) == HttpStatusCode.NoContent &&
              (await store.FindLatestAsync(b.EndpointId))?.Report.EndpointId == b.EndpointId,
            "A second enrolled endpoint could not report telemetry.");
    }

    // T9: the per-address ingest rate limit applies before authentication.
    private static async Task VerifyRateLimitAsync(string directory, CapturingLoggerProvider logs)
    {
        await using var app = Build(directory, logs);
        using var client = await StartAsync(app);
        var statuses = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 31; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, IngestPath) { Content = Raw("{}") };
            using var response = await client.SendAsync(request);
            statuses.Add(response.StatusCode);
        }

        Check(statuses.Take(30).All(status => status == HttpStatusCode.Unauthorized) &&
              statuses[30] == HttpStatusCode.TooManyRequests, "Telemetry ingest must be rate limited per address.");
    }

    internal static EndpointTelemetryReport Benign(Guid endpointId, DateTimeOffset collectedUtc) => new(
        EndpointTelemetryContract.CurrentSchemaVersion, endpointId, collectedUtc,
        new BitLockerTelemetry(TelemetryAvailability.AccessDenied),
        new AntivirusTelemetry(Collected, "good"),
        new DefenderTelemetry(Collected, "normal", true, true, true, 0),
        new LocalAdministratorsTelemetry(Collected, 2,
        [
            new("S-1-5-21-1000-1000-1000-500", AdministratorScopes.Local, "user"),
            new("S-1-5-21-1000-1000-1000-1001", AdministratorScopes.Local, "user")
        ]),
        new WindowsUpdateTelemetry(Collected, Collected, "notConfigured", false, collectedUtc.AddHours(-2), collectedUtc.AddDays(-1)),
        new PendingRebootTelemetry(Collected, false, true, null),
        new SecurityServicesTelemetry(Collected,
        [
            new("MpsSvc", ServiceRunStates.Running, ServiceStartTypes.Auto),
            new("EventLog", ServiceRunStates.Running, ServiceStartTypes.Auto),
            new("Sense", ServiceRunStates.NotInstalled)
        ]),
        new InstalledSoftwareTelemetry(Collected,
        [
            new("Example test-only application", "1.0.0", Marker, "x64"),
            new("Example test-only viewer", null, null, "x86")
        ], 3, true, 1));

    private static HttpContent Wire(EndpointTelemetryReport report) =>
        JsonContent.Create(report, options: EndpointTelemetryContract.Json);

    private static HttpContent Raw(string json, string mediaType = "application/json") =>
        new StringContent(json, Encoding.UTF8, mediaType);

    private static async Task<HttpStatusCode> PostStatusAsync(HttpClient client, Agent agent, HttpContent content)
    {
        using (content)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, IngestPath) { Content = content };
            request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
            using var response = await client.SendAsync(request);
            return response.StatusCode;
        }
    }

    private static async Task<HttpStatusCode> PostInventoryAsync(HttpClient client, Agent agent, DateTimeOffset collectedUtc)
    {
        var inventory = new InventoryReport(agent.EndpointId, collectedUtc, "0.1.0-test", "test-only-telemetry-host",
            "Windows 11 Pro", "10.0.26100", "X64", new CpuInventory(null, 4), null, [], new SecurityPostureInventory(true, true, true));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory") { Content = JsonContent.Create(inventory) };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    private static async Task SetStatusAsync(HttpClient client, string token, Guid alertId, string status, int version)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/api/admin/alerts/{alertId:D}/status")
        {
            Content = JsonContent.Create(new { status, expectedVersion = version })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, $"The alert status change returned HTTP {(int)response.StatusCode}.");
    }

    private static async Task<JsonDocument> GetJsonAsync(HttpClient client, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, $"GET {path} returned HTTP {(int)response.StatusCode}.");
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static async Task<int> AlertCountAsync(WebApplication app, Guid endpointId) => (await AlertsAsync(app, endpointId)).Count;

    /// <summary>RuleId, Status, Version, EndpointName, LastObservedUtcTicks, AlertId per tracked alert.</summary>
    private static async Task<List<string[]>> AlertsAsync(WebApplication app, Guid endpointId) =>
        (await QueryRowsAsync(app, """
            SELECT RuleId, Status, Version, EndpointName, LastObservedUtcTicks, AlertId FROM TrackedAlerts
            WHERE EndpointId = $e ORDER BY RuleId;
            """, endpointId)).ToList();

    private static async Task<List<string>> QueryAsync(WebApplication app, string sql, Guid endpointId) =>
        (await QueryRowsAsync(app, sql, endpointId)).Select(row => row[0]).ToList();

    private static async Task<List<string[]>> QueryRowsAsync(WebApplication app, string sql, Guid endpointId)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath,
            Mode = SqliteOpenMode.ReadOnly
        }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$e", endpointId.ToString("D"));
        var rows = new List<string[]>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            rows.Add(Enumerable.Range(0, reader.FieldCount)
                .Select(index => Convert.ToString(reader.GetValue(index), CultureInfo.InvariantCulture) ?? string.Empty)
                .ToArray());
        }

        return rows;
    }

    private static IEnumerable<string> Names(JsonElement element) =>
        element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal);

    // The bootstrap administrator comes from the test process environment on each new data directory.
    private static WebApplication Build(string directory, CapturingLoggerProvider logs) =>
        CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"], builder =>
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(logs);
        });

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
        var response = enrollment.Response ?? throw new InvalidOperationException("A synthetic telemetry endpoint could not enroll.");
        return new Agent(response.EndpointId, response.AgentCredential);
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "The telemetry test administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    // Records whether the client transmitted the body; with Expect: 100-continue that happens only once Core reads.
    private sealed class TrackedContent : HttpContent
    {
        private readonly HttpContent _inner;

        public TrackedContent(HttpContent inner)
        {
            Check(inner.Headers.ContentLength > 1024, "A body that must stay unread would be sent after an error response.");
            _inner = inner;
            Headers.ContentType = inner.Headers.ContentType;
        }

        public bool Sent { get; private set; }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            Sent = true;
            await _inner.CopyToAsync(stream);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _inner.Headers.ContentLength ?? -1;
            return length >= 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed record LogEntry(string Category, LogLevel Level, string Message);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogEntry> _entries = new();
        public IReadOnlyCollection<LogEntry> Entries => _entries;
        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
        public void Dispose() { }

        private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner._entries.Enqueue(new LogEntry(category, logLevel, formatter(state, exception) + exception));
        }
    }
}
