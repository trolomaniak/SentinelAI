using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.DefenderDetections;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class DefenderDetectionApiTests
{
    private const string ThreatName = "test-only-<img src=x onerror=alert(1)>";
    private static readonly string[] ViewFields =
    [
        "endpointId", "generatedUtc", "sourceState", "sourceReportedUtc", "lastReadUtc", "retentionDays",
        "offset", "limit", "totalCount", "detections"
    ];
    private static readonly string[] DetectionFields =
    [
        "timeCreatedUtc", "receivedUtc", "eventId", "kind", "detectionId", "threatId", "threatName",
        "severityId", "categoryId", "actionId", "errorCode"
    ];

    public static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-defender-history-{Guid.NewGuid():N}");
        var clock = new ManualTime(DateTimeOffset.UtcNow);
        var initialTime = clock.GetUtcNow();
        Guid endpointId;
        try
        {
            await using (var app = Build(directory, clock))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                var a = await EnrollAsync(app);
                var b = await EnrollAsync(app);
                endpointId = a.EndpointId;
                using (var anonymous = await ReadAsync(client, a.EndpointId))
                    Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Anonymous Defender history access succeeded.");
                using (var agent = await ReadAsync(client, a.EndpointId, a.Authorization, scheme: "SentinelAgent"))
                    Check(agent.StatusCode == HttpStatusCode.Unauthorized, "Agent credential granted administrator Defender history access.");
                using (var missing = await ReadAsync(client, Guid.NewGuid(), token))
                    Check(missing.StatusCode == HttpStatusCode.NotFound, "Missing endpoint returned Defender history.");
                Check(!LocalNetworkRoutes.IsAllowed("GET", HistoryPath(a.EndpointId)),
                    "The Agent-only network listener allowed Defender history.");
                foreach (var query in new[] { "?offset=-1", "?offset=10001", "?limit=0", "?limit=101", "?limit=abc", "?offset=2147483648" })
                {
                    using var invalid = await ReadAsync(client, a.EndpointId, token, query);
                    Check(invalid.StatusCode == HttpStatusCode.BadRequest, "Defender history accepted invalid paging.");
                }

                var empty = await ViewAsync(client, b.EndpointId, token);
                Check(empty is { SourceState: DefenderDetectionContract.NotReported, SourceReportedUtc: null,
                    LastReadUtc: null, TotalCount: 0 } && empty.Detections.Count == 0,
                    "Missing Defender telemetry was presented as known coverage.");
                await IngestAsync(client, b, clock, [], [Status(clock, SecurityEventSourceStates.Collecting)]);
                empty = await ViewAsync(client, b.EndpointId, token);
                Check(empty is { SourceState: SecurityEventSourceStates.Collecting, TotalCount: 0 } &&
                    empty.SourceReportedUtc == initialTime && empty.LastReadUtc == initialTime,
                    "An empty collected Defender history lost its distinct coverage state.");

                var detectionId = Guid.NewGuid();
                var malware = new MalwareEvent(detectionId, 2147735505, ThreatName, 5, 8, null, null);
                SecurityEventObservation Event(int id, long record, MalwareEvent payload) =>
                    Observation(id, record, initialTime.AddSeconds(record)) with { Malware = payload };
                SecurityEventObservation[] events =
                [
                    Event(1116, 1, malware),
                    Event(1117, 2, malware with { ActionId = 2 }),
                    Event(1118, 3, malware with { ActionId = 2, ErrorCode = 2147942402 }),
                    Event(1119, 4, malware with { ActionId = 3, ErrorCode = uint.MaxValue }),
                    Event(1116, 5, new MalwareEvent(null, null, null, null, null, null, null))
                ];
                await IngestAsync(client, a, clock, events, [Status(clock, SecurityEventSourceStates.Collecting)]);
                // More than the old internal recent-event cap, inserted later, must not hide
                // malware history. These same-channel events have no malware payload.
                foreach (var chunk in Enumerable.Range(100, 1200).Chunk(240))
                    await IngestAsync(client, a, clock,
                        chunk.Select(record => Observation(5001, record, initialTime)).ToArray(), []);

                var view = await ViewAsync(client, a.EndpointId, token);
                Check(view is { TotalCount: 5, Offset: 0, Limit: 50, RetentionDays: 30 } &&
                    view.Detections.Select(item => item.EventId).SequenceEqual([1116, 1119, 1118, 1117, 1116]),
                    "Unrelated events displaced Defender detections or history ordering is wrong.");
                Check(view.Detections[0] is { ThreatName: null, ThreatId: null, DetectionId: null } &&
                    view.Detections[1] is { ErrorCode: uint.MaxValue, ActionId: 3, Kind: SecurityEventKinds.MalwareActionFailed } &&
                    view.Detections[3] is { ErrorCode: null, ActionId: 2, Kind: SecurityEventKinds.MalwareActionTaken } &&
                    view.Detections[4].DetectionId == detectionId && view.Detections[4].ThreatName == ThreatName &&
                    view.Detections.All(item => item.ReceivedUtc == initialTime),
                    "Defender malware metadata or unknown values changed during projection.");
                Check((await ViewAsync(client, b.EndpointId, token)).TotalCount == 0,
                    "Defender history crossed endpoint boundaries.");
                var page = await ViewAsync(client, a.EndpointId, token, "?offset=2&limit=2");
                Check(page is { Offset: 2, Limit: 2, TotalCount: 5 } &&
                    page.Detections.Select(item => item.EventId).SequenceEqual([1118, 1117]),
                    "Defender paging did not page the filtered history.");
                Check((await ViewAsync(client, a.EndpointId, token, "?offset=10000&limit=100")).Detections.Count == 0,
                    "A valid empty page failed at the paging bound.");

                using (var response = await ReadAsync(client, a.EndpointId, token))
                {
                    var jsonText = await response.Content.ReadAsStringAsync();
                    using var json = JsonDocument.Parse(jsonText);
                    Check(response.Headers.CacheControl?.NoStore == true &&
                        response.Content.Headers.ContentType?.MediaType == "application/json",
                        "Defender history was cacheable or returned a non-JSON content type.");
                    Check(SameFields(json.RootElement, ViewFields) &&
                        json.RootElement.GetProperty("detections").EnumerateArray().All(item => SameFields(item, DetectionFields)),
                        "Defender history exposed fields outside the safe projection.");
                    Check(!jsonText.Contains(a.Credential, StringComparison.Ordinal) &&
                        json.RootElement.GetProperty("detections")[4].GetProperty("threatName").GetString() == ThreatName,
                        "Defender history exposed a credential or changed the literal threat name.");
                }
                clock.Advance(TimeSpan.FromHours(3));
                token = await LoginAsync(client, username, password);
                view = await ViewAsync(client, a.EndpointId, token);
                Check(view.SourceReportedUtc is { } reported && view.GeneratedUtc - reported > TimeSpan.FromHours(2) &&
                    view.SourceState == SecurityEventSourceStates.Collecting && view.TotalCount == 5,
                    "Defender history hid source age or discarded history just because coverage became stale.");
                await IngestAsync(client, a, clock, [], [Status(clock, SecurityEventSourceStates.AccessDenied)]);
                Check((await ViewAsync(client, a.EndpointId, token)) is { SourceState: SecurityEventSourceStates.AccessDenied, TotalCount: 5 },
                    "Unavailable collection erased retained detections or implied healthy coverage.");
            }

            await using (var app = Build(directory, clock))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                var restored = await ViewAsync(client, endpointId, token);
                Check(restored is { SourceState: SecurityEventSourceStates.AccessDenied, TotalCount: 5 } &&
                    restored.Detections[4].ThreatName == ThreatName,
                    "Defender history/source state did not survive restart.");
                // Read projection applies receipt-time age even before the bounded sweeper
                // has removed every old row. Endpoint-created timestamps do not bypass it.
                clock.Advance(TimeSpan.FromDays(31));
                token = await LoginAsync(client, username, password);
                var expired = await ViewAsync(client, endpointId, token);
                Check(expired.TotalCount == 0 && expired.Detections.Count == 0 &&
                    expired.SourceState == SecurityEventSourceStates.AccessDenied && expired.SourceReportedUtc is not null,
                    "Expired detections remained visible or expired history became a clean-health verdict.");
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("Defender detection history API tests passed (ingest, safe projection, auth, endpoint isolation, paging, unknown/stale source, restart, receipt-time retention).");
    }

    private static SecurityEventObservation Observation(int eventId, long record, DateTimeOffset time)
    {
        var selection = SecurityEventContract.Catalog.First(item => item.EventId == eventId);
        return new SecurityEventObservation(selection.Channel, selection.Provider, eventId, 0, 4, record, time, selection.Kind);
    }

    private static SecurityEventSourceStatus Status(ManualTime clock, string state) =>
        new(SecurityEventChannels.Defender, state, null, 1, 2000, 2000, 20L * 1024 * 1024,
            clock.GetUtcNow(), 2000, 2000, 2000, 0, 0, 0, 0, 0, 0);

    private static async Task IngestAsync(HttpClient client, Agent agent, ManualTime clock,
        IReadOnlyList<SecurityEventObservation> events, IReadOnlyList<SecurityEventSourceStatus> sources)
    {
        var batch = new SecurityEventBatch(agent.EndpointId, SecurityEventContract.Format, "0.1.0-test",
            clock.GetUtcNow(), clock.GetUtcNow().AddHours(-1), sources, [], events);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/security-events")
        {
            Content = JsonContent.Create(batch, options: SecurityEventContract.Json)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
        using var response = await client.SendAsync(request);
        var result = response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<SecurityEventBatchResult>() : null;
        Check(response.StatusCode == HttpStatusCode.OK && result is not null && result.Accepted == events.Count && result.Rejected == 0,
            "Synthetic Defender pipeline events were not accepted through the Agent ingest route.");
    }

    private static string HistoryPath(Guid endpointId) => $"/api/admin/devices/{endpointId:D}/defender-detections";
    private static async Task<HttpResponseMessage> ReadAsync(HttpClient client, Guid endpointId,
        string? token = null, string query = "", string scheme = "Bearer")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, HistoryPath(endpointId) + query);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        return await client.SendAsync(request);
    }

    private static async Task<DefenderDetectionsView> ViewAsync(HttpClient client, Guid endpointId, string token, string query = "")
    {
        using var response = await ReadAsync(client, endpointId, token, query);
        Check(response.StatusCode == HttpStatusCode.OK, "Defender history read failed.");
        return await response.Content.ReadFromJsonAsync<DefenderDetectionsView>() ??
            throw new InvalidOperationException("No Defender history view returned.");
    }

    private static bool SameFields(JsonElement value, string[] expected) =>
        value.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(expected.Order(StringComparer.Ordinal));

    private static WebApplication Build(string directory, ManualTime clock) =>
        CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"], builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<TimeProvider>(clock);
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
        var enrolled = enrollment.Response ?? throw new InvalidOperationException("Synthetic Defender endpoint failed enrollment.");
        return new Agent(enrolled.EndpointId, enrolled.AgentCredential);
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic Defender administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed record Agent(Guid EndpointId, string Credential)
    {
        public string Authorization => $"{EndpointId:D}.{Credential}";
        public override string ToString() => nameof(Agent);
    }

    private sealed class ManualTime(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration) => _utcNow += duration;
    }
}
