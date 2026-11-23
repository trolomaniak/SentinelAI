using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class MonitoringCoverageApiTests
{
    private const string Route = "/api/admin/monitoring-coverage";
    private const string PrivateSoftwareName = "Synthetic private software value";
    private const string PrivateCpuName = "Synthetic private CPU value";

    internal static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-monitoring-coverage-{Guid.NewGuid():N}");
        var now = DateTimeOffset.UtcNow;
        var clock = new ManualTime(now);
        try
        {
            await using var app = CoreHost.Build(
                [$"--SentinelAI:DataDirectory={directory}", "--SentinelAI:RiskScoring:InventoryFreshForHours=4"],
                false, builder =>
                {
                    builder.Logging.ClearProviders();
                    builder.Services.AddSingleton<TimeProvider>(clock);
                },
                configureBeforeAuthentication: application => application.Use((context, next) =>
                {
                    var remote = context.Request.Headers.ContainsKey("Synthetic-Remote");
                    context.Connection.RemoteIpAddress = remote ? IPAddress.Parse("192.0.2.13") : IPAddress.Loopback;
                    if (remote) context.Request.Scheme = "https";
                    return next(context);
                }));
            app.Urls.Clear();
            app.Urls.Add("http://127.0.0.1:0");
            await app.StartAsync();
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
            {
                BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
            };
            using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
            login.EnsureSuccessStatusCode();
            using var loginJson = JsonDocument.Parse(await login.Content.ReadAsByteArrayAsync());
            var bearer = loginJson.RootElement.GetProperty("accessToken").GetString()!;

            var empty = await ReadAsync<MonitoringEndpointPage>(client, "", bearer);
            Check(empty is { Total: 0, Matching: 0, Offset: 0, Limit: 50, InventoryFreshHours: 4 } &&
                empty.Items.Count == 0, "empty fleet and configured inventory horizon");
            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
            var active = new List<Agent>();
            for (var index = 0; index < 6; index++) active.Add(await EnrollAsync(enrollments));
            active.Sort((left, right) => string.CompareOrdinal(left.EndpointId.ToString("D"), right.EndpointId.ToString("D")));
            var current = active[0];
            var warning = active[1];
            var gapOnly = active[2];
            var missing = active[3];
            var future = active[4];
            var offline = active[5];
            var removed = await EnrollAsync(enrollments);
            var database = app.Services.GetRequiredService<AdminStore>().DatabasePath;

            foreach (var path in new[] { Route, Route + EndpointPath(current), Route + EndpointPath(current) + "/gaps" })
            {
                await ExpectAsync(client, path, HttpStatusCode.Unauthorized);
                await ExpectAsync(client, path, HttpStatusCode.Unauthorized, current.Authorization, "SentinelAgent");
                await ExpectAsync(client, path, HttpStatusCode.Forbidden, bearer, remote: true);
                Check(!LocalNetworkRoutes.IsAllowed("GET", path), "Agent listener allowed an administrator route");
            }

            var longName = new string('A', 127) + "\U0001F642-extra";
            await InventoryAsync(client, current, now.AddHours(-4), longName);
            await InventoryAsync(client, warning, now.AddHours(-4).AddTicks(-1), "warning-device");
            await InventoryAsync(client, gapOnly, now, "gap-device");
            await InventoryAsync(client, future, now.AddTicks(1), "future-device");
            await InventoryAsync(client, offline, now, "offline-device");
            await InventoryAsync(client, removed, now, "removed-device");

            await TelemetryAsync(client, current, now.AddHours(-3));
            await TelemetryAsync(client, warning, now.AddHours(-3).AddTicks(-1), mixed: true);
            await TelemetryAsync(client, gapOnly, now);
            await TelemetryAsync(client, future, now.AddTicks(1));
            await TelemetryAsync(client, offline, now, mixed: true);
            await TelemetryAsync(client, removed, now);

            await EventsAsync(client, current, now, AllChannels(now),
                [new(SecurityEventChannels.Security, SecurityEventGapReasons.CoverageStarted, 1, null, now, SecurityEventCoverageCauses.NoCheckpoint)]);
            await EventsAsync(client, warning, now,
                [Source(SecurityEventChannels.Security, now, SecurityEventSourceStates.AccessDenied),
                 Source(SecurityEventChannels.System, now),
                 Source(SecurityEventChannels.PowerShell, now, SecurityEventSourceStates.Error)], []);
            await EventsAsync(client, gapOnly, now, AllChannels(now),
                [new(SecurityEventChannels.Security, SecurityEventGapReasons.CoverageStarted, 10, null, now)]);
            await EventsAsync(client, gapOnly, now, [],
                [new(SecurityEventChannels.Security, SecurityEventGapReasons.Overwritten, 20, 23, now.AddDays(1)),
                 new(SecurityEventChannels.Security, SecurityEventGapReasons.CoverageStarted, 24, null, now, SecurityEventCoverageCauses.CheckpointInvalid),
                 new(SecurityEventChannels.System, SecurityEventGapReasons.LogReset, 30, null, now)]);
            await EventsAsync(client, future, now, AllChannels(now), []);
            await EventsAsync(client, offline, now, AllChannels(now), []);
            await EventsAsync(client, removed, now, AllChannels(now),
                [new(SecurityEventChannels.System, SecurityEventGapReasons.LogReset, 30, null, now)]);
            Check(await enrollments.RemoveEndpointAsync(removed.EndpointId) == EndpointRemoval.Removed, "synthetic enrollment removal");

            await SeedHeartbeatAsync(database, current.InstallationId, now.AddMinutes(-2));
            await SeedHeartbeatAsync(database, warning.InstallationId, now.AddMinutes(-5));
            await SeedHeartbeatAsync(database, gapOnly.InstallationId, now);
            await SeedHeartbeatAsync(database, future.InstallationId, now.AddTicks(1));
            await SeedHeartbeatAsync(database, offline.InstallationId, now.AddMinutes(-5).AddTicks(-1));
            await SeedHeartbeatAsync(database, removed.InstallationId, now);
            await app.Services.GetRequiredService<DeviceStore>().RecordHeartbeatAsync(Guid.NewGuid());
            await SetEventReceiptAsync(database, current.EndpointId, now.AddHours(-2));
            await SetEventReceiptAsync(database, warning.EndpointId, now.AddHours(-2).AddTicks(-1), SecurityEventChannels.System);
            await SetEventReceiptAsync(database, warning.EndpointId, now.AddTicks(1), SecurityEventChannels.PowerShell);
            await SetGapReceiptAsync(database, gapOnly.EndpointId, 20, now.AddDays(-30));
            await SetGapReceiptAsync(database, gapOnly.EndpointId, 30, now.AddDays(-30).AddTicks(-1));

            var all = await ReadAsync<MonitoringEndpointPage>(client, "?limit=100&issuesOnly=false", bearer);
            Check(all is { Total: 6, Matching: 6, Offset: 0, Limit: 100 } && all.GeneratedUtc == now &&
                all.Items.Select(item => item.EndpointId).SequenceEqual(active.Select(item => item.EndpointId)),
                "active fleet excludes removed and unverified devices and has stable ordering");
            Check(all.Items[0] is { HeartbeatState: "healthy", InventoryFreshness: "current", TelemetryFreshness: "current",
                    CurrentTelemetrySources: 9, CurrentEventChannels: 4, HasIssue: false, HasRetainedGaps: false } &&
                all.Items[0].Name == new string('A', 127), "inclusive freshness limits, bounded UTF-16 name and first coverage marker");
            Check(all.Items[1] is { HeartbeatState: "warning", InventoryFreshness: "stale", TelemetryFreshness: "stale",
                CurrentTelemetrySources: 0, CurrentEventChannels: 0, HasIssue: true }, "aged reporting and immediate source failures");
            Check(all.Items[2] is { HeartbeatState: "healthy", CurrentTelemetrySources: 9, CurrentEventChannels: 4,
                HasIssue: true, HasRetainedGaps: true }, "retained continuity loss is independently visible");
            Check(all.Items[3] is { HeartbeatState: "unknown", InventoryFreshness: "missing", TelemetryFreshness: "missing",
                LastHeartbeatUtc: null, InventoryCollectedUtc: null, TelemetryCollectedUtc: null, TelemetryReceivedUtc: null,
                HasIssue: true }, "unknown and missing reporting");
            Check(all.Items[4] is { HeartbeatState: "future", InventoryFreshness: "future", TelemetryFreshness: "future",
                CurrentTelemetrySources: 0, CurrentEventChannels: 4, HasIssue: true }, "future-dated data is separated per source");
            Check(all.Items[5] is { HeartbeatState: "offline", InventoryFreshness: "current", TelemetryFreshness: "current",
                CurrentTelemetrySources: 6, CurrentEventChannels: 4, HasIssue: true }, "heartbeat and source availability are independent");

            var issues = await ReadAsync<MonitoringEndpointPage>(client, "?limit=1&issuesOnly=true", bearer);
            Check(issues is { Total: 6, Matching: 5, Offset: 0, Limit: 1 } && issues.Items.Single().EndpointId == warning.EndpointId,
                "issue predicate filters before the first fleet page");
            issues = await ReadAsync<MonitoringEndpointPage>(client, "?offset=1&limit=1&issuesOnly=true", bearer);
            Check(issues.Items.Single().EndpointId == gapOnly.EndpointId, "filtered page offset follows matching rows");
            var end = await ReadAsync<MonitoringEndpointPage>(client, "?offset=100000&limit=100&issuesOnly=true", bearer);
            Check(end.Matching == 5 && end.Items.Count == 0, "valid out-of-range page retains matching count");

            var detail = await ReadAsync<MonitoringEndpointDetail>(client, EndpointPath(warning), bearer);
            Check(detail.Endpoint == all.Items[1] && detail.InventoryFreshHours == 4 && detail.GapRetentionDays == 30,
                "summary and detail share the same projection");
            Check(detail.Telemetry.Select(source => source.SourceId).SequenceEqual(MonitoringCoverageContract.TelemetrySourceIds) &&
                detail.Telemetry.All(source => source.Freshness == "stale") &&
                detail.Telemetry.Single(source => source.SourceId == "bitLocker").State == TelemetryAvailability.Unsupported &&
                detail.Telemetry.Single(source => source.SourceId == "defender").State == TelemetryAvailability.AccessDenied &&
                detail.Telemetry.Single(source => source.SourceId == "windowsUpdatePolicy").State == TelemetryAvailability.Collected &&
                detail.Telemetry.Single(source => source.SourceId == "windowsUpdateResults").State == TelemetryAvailability.Unavailable,
                "stale telemetry retains nine separate reported states");
            Check(detail.EventChannels.Select(source => source.Channel).SequenceEqual(SecurityEventChannels.All) &&
                detail.EventChannels[0] is { State: "accessDenied", Freshness: "current", CheckpointRecordId: 7,
                    ReportedGaps: 2, SkippedRecords: 3, DroppedUnparsed: 4, DroppedOversize: 5 } &&
                detail.EventChannels[0].FirstCheckpointUtc == now && detail.EventChannels[0].CountersSinceUtc == now.AddHours(-4) &&
                detail.EventChannels[1] is { State: "collecting", Freshness: "stale" } &&
                detail.EventChannels[1].ReportedUtc == now.AddHours(-2).AddTicks(-1) && detail.EventChannels[1].LastReadUtc == now &&
                detail.EventChannels[2] is { State: "error", Freshness: "future" } &&
                detail.EventChannels[3] is { State: "unknown", Freshness: "missing", ReportedUtc: null, LastReadUtc: null, ReportedGaps: null },
                "Core receipt, Agent read time and typed event counters remain distinct");
            var missingDetail = await ReadAsync<MonitoringEndpointDetail>(client, EndpointPath(missing), bearer);
            Check(missingDetail.Telemetry.All(source => source is { State: "unknown", Freshness: "missing" }) &&
                missingDetail.EventChannels.All(source => source is { State: "unknown", Freshness: "missing" }),
                "missing endpoint reports leave every expected source visible");

            var gaps = await ReadAsync<MonitoringGapPage>(client, EndpointPath(gapOnly) + "/gaps?offset=0&limit=1", bearer);
            Check(gaps is { Total: 3, Offset: 0, Limit: 1, RetentionDays: 30 } &&
                gaps.Items.Single() is { FirstRecordId: 24, LastRecordId: null, CoverageRestart: true, Cause: "checkpointInvalid" },
                "expired gaps are filtered before paging and restart keeps its cause");
            gaps = await ReadAsync<MonitoringGapPage>(client, EndpointPath(gapOnly) + "/gaps?offset=1&limit=2", bearer);
            Check(gaps.Items.Count == 2 && gaps.Items[0] is { FirstRecordId: 20, LastRecordId: 23, Reason: "overwritten" } &&
                gaps.Items[0].ReceivedUtc == now.AddDays(-30) && gaps.Items[0].DetectedUtc == now.AddDays(1) &&
                gaps.Items[1] is { FirstRecordId: 10, CoverageRestart: false, Reason: "coverageStarted" },
                "receipt boundary, source timestamps, per-endpoint paging and coverage baseline");
            var baseline = await ReadAsync<MonitoringGapPage>(client, EndpointPath(current) + "/gaps", bearer);
            Check(baseline.Total == 1 && !baseline.Items.Single().CoverageRestart, "first coverage remains visible in gap detail");

            foreach (var query in new[] { "?offset=-1", "?offset=100001", "?offset=2147483648", "?limit=0", "?limit=101",
                         "?limit=50&limit=20", "?offset=abc", "?offset=" })
            {
                await ExpectAsync(client, Route + query, HttpStatusCode.BadRequest, bearer);
                await ExpectAsync(client, Route + EndpointPath(current) + "/gaps" + query, HttpStatusCode.BadRequest, bearer);
            }
            foreach (var query in new[] { "?issuesOnly=maybe", "?issuesOnly=", "?issuesOnly=true&issuesOnly=false" })
                await ExpectAsync(client, Route + query, HttpStatusCode.BadRequest, bearer);
            foreach (var endpointId in new[] { removed.EndpointId, Guid.NewGuid() })
            {
                await ExpectAsync(client, Route + "/" + endpointId.ToString("D"), HttpStatusCode.NotFound, bearer);
                await ExpectAsync(client, Route + "/" + endpointId.ToString("D") + "/gaps", HttpStatusCode.NotFound, bearer);
            }

            using (var response = await SendAsync(client, Route + EndpointPath(current), bearer))
            {
                var content = await response.Content.ReadAsByteArrayAsync();
                var text = System.Text.Encoding.UTF8.GetString(content);
                using var document = JsonDocument.Parse(content);
                Check(content.Length < MonitoringCoverageContract.MaximumResponseBytes &&
                    !text.Contains(PrivateSoftwareName, StringComparison.Ordinal) && !text.Contains(PrivateCpuName, StringComparison.Ordinal) &&
                    !text.Contains(current.Credential, StringComparison.Ordinal) &&
                    document.RootElement.GetProperty("eventChannels")[0].TryGetProperty("checkpointRecordId", out _),
                    "bounded typed projection does not disclose stored report or enrollment data");
            }

            clock.UtcNow = now.AddTicks(1);
            gaps = await ReadAsync<MonitoringGapPage>(client, EndpointPath(gapOnly) + "/gaps", bearer);
            Check(gaps.Total == 2 && gaps.Items.All(gap => gap.FirstRecordId != 20),
                "read-time receipt retention expires gaps before physical sweeps");
            var aged = await ReadAsync<MonitoringEndpointDetail>(client, EndpointPath(current), bearer);
            Check(aged.Endpoint is { HeartbeatState: "warning", InventoryFreshness: "stale", TelemetryFreshness: "stale",
                CurrentTelemetrySources: 0, CurrentEventChannels: 0, HasIssue: true },
                "freshness is reevaluated against a single request clock");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("Monitoring coverage API tests passed (authorization, retention, source freshness, bounded SQL paging and privacy).");
    }

    private static async Task<Agent> EnrollAsync(EnrollmentStore enrollments)
    {
        var installationId = Guid.NewGuid();
        var token = await enrollments.IssueTokenAsync();
        var enrolled = (await enrollments.TryEnrollAsync(new EnrollmentRequest(installationId, token.Token), overLocalNetwork: true)).Response
            ?? throw new InvalidOperationException("Synthetic coverage endpoint failed enrollment.");
        return new Agent(installationId, enrolled.EndpointId, enrolled.AgentCredential);
    }

    private static async Task InventoryAsync(HttpClient client, Agent agent, DateTimeOffset collected, string name)
    {
        var report = new InventoryReport(agent.EndpointId, collected, "0.1.0-test", name, "Windows", "10.0", "x64",
            new CpuInventory(PrivateCpuName, 4), null, [], new SecurityPostureInventory(null, null, null));
        await IngestAsync(client, agent, "/api/agent/inventory", JsonContent.Create(report), HttpStatusCode.NoContent);
    }

    private static async Task TelemetryAsync(HttpClient client, Agent agent, DateTimeOffset collected, bool mixed = false)
    {
        const string available = TelemetryAvailability.Collected;
        var report = new EndpointTelemetryReport(EndpointTelemetryContract.CurrentSchemaVersion, agent.EndpointId, collected,
            new BitLockerTelemetry(mixed ? TelemetryAvailability.Unsupported : available), new AntivirusTelemetry(available),
            new DefenderTelemetry(mixed ? TelemetryAvailability.AccessDenied : available), new LocalAdministratorsTelemetry(available, 0, []),
            new WindowsUpdateTelemetry(available, mixed ? TelemetryAvailability.Unavailable : available), new PendingRebootTelemetry(available),
            new SecurityServicesTelemetry(available, []), new InstalledSoftwareTelemetry(available, [new(PrivateSoftwareName)], 1));
        await IngestAsync(client, agent, "/api/agent/security-telemetry", JsonContent.Create(report, options: EndpointTelemetryContract.Json),
            HttpStatusCode.NoContent);
    }

    private static SecurityEventSourceStatus[] AllChannels(DateTimeOffset read) =>
        SecurityEventChannels.All.Select(channel => Source(channel, read)).ToArray();

    private static SecurityEventSourceStatus Source(string channel, DateTimeOffset read, string state = SecurityEventSourceStates.Collecting) =>
        new(channel, state, null, 1, 7, 7, 1024, read, 10, 8, 6, 4, 5, 0, 2, 3, 0);

    private static async Task EventsAsync(HttpClient client, Agent agent, DateTimeOffset now,
        IReadOnlyList<SecurityEventSourceStatus> sources, IReadOnlyList<SecurityEventGap> gaps)
    {
        var batch = new SecurityEventBatch(agent.EndpointId, SecurityEventContract.Format, "0.1.0-test", now, now.AddHours(-4), sources, gaps, []);
        await IngestAsync(client, agent, "/api/agent/security-events", JsonContent.Create(batch, options: SecurityEventContract.Json), HttpStatusCode.OK);
    }

    private static async Task IngestAsync(HttpClient client, Agent agent, string path, HttpContent content, HttpStatusCode status)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agent.Authorization);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == status, $"synthetic ingest failed for {path}: {response.StatusCode}");
        if (status == HttpStatusCode.OK)
        {
            var result = await response.Content.ReadFromJsonAsync<SecurityEventBatchResult>();
            Check(result is { Rejected: 0, Ignored: 0 }, "synthetic event ingest rejected an item");
        }
    }

    private static Task SeedHeartbeatAsync(string database, Guid installationId, DateTimeOffset time) => ExecuteAsync(database, """
        INSERT INTO Devices(InstallationId, LastSeenUtcTicks, HealthStatus, EnrollmentStatus)
        VALUES($id, $ticks, 'reporting', 'enrolled')
        ON CONFLICT(InstallationId) DO UPDATE SET LastSeenUtcTicks = excluded.LastSeenUtcTicks;
        """, ("$id", installationId.ToString("D")), ("$ticks", time.UtcTicks));

    private static Task SetEventReceiptAsync(string database, Guid endpointId, DateTimeOffset time, string? channel = null) =>
        ExecuteAsync(database, """
            UPDATE SecurityEventSources SET ReceivedUtcTicks = $ticks WHERE EndpointId = $id AND ($channel IS NULL OR Channel = $channel);
            """, ("$id", endpointId.ToString("D")), ("$ticks", time.UtcTicks), ("$channel", (object?)channel ?? DBNull.Value));

    private static Task SetGapReceiptAsync(string database, Guid endpointId, long recordId, DateTimeOffset time) =>
        ExecuteAsync(database, "UPDATE SecurityEventGaps SET ReceivedUtcTicks = $ticks WHERE EndpointId = $id AND FirstRecordId = $record;",
            ("$id", endpointId.ToString("D")), ("$ticks", time.UtcTicks), ("$record", recordId));

    private static async Task ExecuteAsync(string database, string sql, params (string Name, object Value)[] parameters)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, DefaultTimeout = 30 }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value);
        Check(await command.ExecuteNonQueryAsync() > 0, "synthetic timestamp update had no target");
    }

    private static string EndpointPath(Agent agent) => "/" + agent.EndpointId.ToString("D");

    private static async Task<T> ReadAsync<T>(HttpClient client, string suffix, string bearer) where T : class
    {
        using var response = await SendAsync(client, Route + suffix, bearer);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            $"administrator coverage read failed for {suffix}: {response.StatusCode}");
        return await response.Content.ReadFromJsonAsync<T>() ?? throw new InvalidOperationException("No coverage response body.");
    }

    private static async Task ExpectAsync(HttpClient client, string path, HttpStatusCode status, string? credential = null,
        string scheme = "Bearer", bool remote = false)
    {
        using var response = await SendAsync(client, path, credential, scheme, remote);
        Check(response.StatusCode == status && response.Headers.CacheControl?.NoStore == true,
            $"coverage access/bounds for {path}: {response.StatusCode}, expected {status}");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string path, string? credential,
        string scheme = "Bearer", bool remote = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (credential is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, credential);
        if (remote) request.Headers.Add("Synthetic-Remote", "1");
        return await client.SendAsync(request);
    }

    private static void Check(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException("Monitoring coverage API: " + description);
    }

    private sealed record Agent(Guid InstallationId, Guid EndpointId, string Credential)
    {
        public string Authorization => $"{EndpointId:D}.{Credential}";
        public override string ToString() => nameof(Agent);
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
