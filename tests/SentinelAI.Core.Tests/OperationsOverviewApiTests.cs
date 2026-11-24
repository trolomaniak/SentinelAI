using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Monitoring;
using SentinelAI.Contracts.Notifications;
using SentinelAI.Contracts.Overview;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal static class OperationsOverviewApiTests
{
    private const string Route = "/api/admin/overview";
    private const string PrivateMarker = "Synthetic private overview fixture";
    private static readonly string LongLabel = new string('界', OperationsOverviewContract.MaximumTextLength - 1) + "\U0001F642-extra";
    private static readonly string BoundedLabel = LongLabel[..(OperationsOverviewContract.MaximumTextLength - 1)];

    internal static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-overview-{Guid.NewGuid():N}");
        var now = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(1).AddTicks(-1));
        var clock = new ManualTime(now);
        try
        {
            await using var app = CoreHost.Build(
                [$"--SentinelAI:DataDirectory={directory}", "--SentinelAI:RiskScoring:InventoryFreshForHours=4"], false,
                builder =>
                {
                    builder.Logging.ClearProviders();
                    builder.Services.AddSingleton<TimeProvider>(clock);
                },
                configureBeforeAuthentication: application => application.Use((context, next) =>
                {
                    if (context.Request.Headers.ContainsKey("Synthetic-Remote"))
                    {
                        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.13");
                        context.Request.Scheme = "https";
                    }
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

            await ExpectAsync(client, HttpStatusCode.Unauthorized);
            await ExpectAsync(client, HttpStatusCode.Unauthorized, "invalid-test-session");
            await ExpectAsync(client, HttpStatusCode.Forbidden, bearer, remote: true);
            Check(!LocalNetworkRoutes.IsAllowed("GET", Route) && !LocalNetworkRoutes.IsAllowed("GET", Route.ToUpperInvariant()),
                "Agent listener denies overview including case variants");
            var empty = await ReadOverviewAsync(client, bearer);
            Check(empty.GeneratedUtc == now && empty.Counts == new OverviewCounts(0, 0, 0, 0, 0) &&
                empty.PriorityAlerts.Count == 0 && empty.CoverageIssues.Count == 0 && empty.UnreadNotifications.Count == 0 &&
                empty.RisksNeedingAttention.Count == 0 && empty.RecentAlertChanges.Count == 0 && empty.LastSuccessfulBackupUtc is null,
                "successful empty state has zero counts, empty lists and no backup timestamp");

            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
            var covered = await EnrollAsync(enrollments);
            var incomplete = await EnrollAsync(enrollments);
            for (var index = 0; index < 6; index++) await EnrollAsync(enrollments);
            var removed = await EnrollAsync(enrollments);
            await ExpectAsync(client, HttpStatusCode.Unauthorized, $"{covered.EndpointId:D}.{covered.AgentCredential}", "SentinelAgent");
            Check(await enrollments.RemoveEndpointAsync(removed.EndpointId) == EndpointRemoval.Removed, "synthetic endpoint removal");

            await using var database = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath,
                Mode = SqliteOpenMode.ReadWrite,
                DefaultTimeout = 30
            }.ToString());
            await database.OpenAsync();
            await SeedCoveredEndpointAsync(database, covered, now);
            await SeedAlertsAsync(database, incomplete.EndpointId, removed.EndpointId, now);
            await SeedNotificationsAsync(database, incomplete.EndpointId, now);
            var risks = await SeedRisksAsync(app.Services.GetRequiredService<RiskRegisterStore>(), database, now);
            var backupAt = now.AddHours(-2);
            await ExecuteAsync(database, """
                UPDATE BackupSettings SET LastSuccessfulUtcTicks=$backup, RecoveryKeyId=$private, ProtectedKey=CAST($private AS BLOB)
                WHERE Singleton=1;
                """, ("$backup", backupAt.UtcTicks), ("$private", PrivateMarker));

            var snapshot = await ReadOverviewAsync(client, bearer, covered.AgentCredential);
            Check(snapshot.GeneratedUtc == now && snapshot.Counts == new OverviewCounts(8, 7, 6, 6, 7) &&
                snapshot.LastSuccessfulBackupUtc == backupAt, "counts share the current evaluated time and report the stored successful backup");
            Check(snapshot.PriorityAlerts.Select(item => item.AlertId).SequenceEqual(new[] { 1, 2, 3, 4, 5 }.Select(TestId)) &&
                snapshot.PriorityAlerts.Take(3).All(item => item.Severity == "critical") &&
                snapshot.PriorityAlerts[1].Status == "investigating" && snapshot.PriorityAlerts[0].EndpointName == BoundedLabel &&
                snapshot.PriorityAlerts[0].Title == BoundedLabel, "priority alerts cap at five, rank by severity, recency and ID, and have bounded UTF-16");
            Check(snapshot.RecentAlertChanges.Select(item => item.AlertId).SequenceEqual(new[] { 2, 7, 9, 1, 6 }.Select(TestId)) &&
                snapshot.RecentAlertChanges[0] is { PreviousStatus: "resolved", Status: "open" } &&
                snapshot.RecentAlertChanges[1] is { PreviousStatus: null, Status: "open" } &&
                snapshot.RecentAlertChanges[1].ChangedUtc == now && snapshot.RecentAlertChanges[^1].ChangedUtc == now.AddHours(-24) &&
                snapshot.RecentAlertChanges[0].Title == BoundedLabel && snapshot.RecentAlertChanges[0].EndpointName == BoundedLabel,
                "status history includes new, reopened and removed-endpoint changes, breaks ties by sequence and includes both time boundaries");
            Check(snapshot.UnreadNotifications.Select(item => item.NotificationId).SequenceEqual(new[] { 20, 21, 22, 23, 24 }.Select(TestId)) &&
                snapshot.UnreadNotifications[0] is { EndpointName: var notificationName, Occurrences: 3 } && notificationName == BoundedLabel,
                "notification previews use retained inbox order and preserve occurrence counts");
            Check(snapshot.RisksNeedingAttention.Select(item => item.RiskId).SequenceEqual(risks.Take(5)) &&
                snapshot.RisksNeedingAttention[0] is { AcceptanceExpired: true, ReviewOverdue: false, TargetDatePassed: false } &&
                snapshot.RisksNeedingAttention[1] is { ReviewOverdue: true, AcceptanceExpired: false, TargetDatePassed: false } &&
                snapshot.RisksNeedingAttention[2] is { TargetDatePassed: true, ReviewOverdue: false, AcceptanceExpired: false } &&
                snapshot.RisksNeedingAttention[0].Title == BoundedLabel, "risks use real ranks and only overdue attention flags");
            await CheckSourceParityAsync(client, bearer, snapshot);

            clock.UtcNow = now.AddTicks(1);
            var aged = await ReadOverviewAsync(client, bearer);
            Check(aged.GeneratedUtc == now.AddTicks(1) && aged.Counts.CoverageIssues == 8 && aged.Counts.RisksNeedingAttention == 8 &&
                aged.RecentAlertChanges.Count == 4 && aged.RecentAlertChanges.All(item => item.AlertId != TestId(6)),
                "one tick expires source freshness, the 24-hour edge and a risk date at UTC midnight");
            await CheckSourceParityAsync(client, bearer, aged);

            await InsertHistoryAsync(database, 3, "accepted", "open", clock.UtcNow);
            await InsertHistoryAsync(database, 5, "open", "investigating", clock.UtcNow);
            using (var mark = new HttpRequestMessage(HttpMethod.Put, $"/api/admin/notifications/{TestId(20):D}/read"))
            {
                mark.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                using var result = await client.SendAsync(mark);
                Check(result.StatusCode == HttpStatusCode.NoContent, "source inbox marks a notification read");
            }
            var refreshed = await ReadOverviewAsync(client, bearer);
            Check(refreshed.RecentAlertChanges.Select(item => item.AlertId).SequenceEqual(new[] { 5, 3, 2, 7, 9 }.Select(TestId)) &&
                refreshed.Counts.UnreadNotifications == 5 && refreshed.UnreadNotifications[^1].NotificationId == TestId(25),
                "history is capped and source notification updates are reflected on a new read");

            await ExecuteAsync(database, "UPDATE RiskRegister SET RecordJson='invalid synthetic JSON' WHERE RiskId=$id;",
                ("$id", risks[0].ToString("D")));
            await ExpectAsync(client, HttpStatusCode.InternalServerError, bearer);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("Operations overview API tests passed (loopback, count and preview parity, ordering, UTC boundaries, privacy and failed reads).");
    }

    private static async Task<Endpoint> EnrollAsync(EnrollmentStore store)
    {
        var installationId = Guid.NewGuid();
        var token = await store.IssueTokenAsync();
        var enrolled = (await store.TryEnrollAsync(new EnrollmentRequest(installationId, token.Token), overLocalNetwork: true)).Response
            ?? throw new InvalidOperationException("Synthetic overview endpoint failed enrollment.");
        return new Endpoint(installationId, enrolled.EndpointId, enrolled.AgentCredential);
    }

    private static async Task SeedCoveredEndpointAsync(SqliteConnection database, Endpoint endpoint, DateTimeOffset now)
    {
        await ExecuteAsync(database, """
            INSERT INTO Devices(InstallationId, LastSeenUtcTicks, HealthStatus, EnrollmentStatus)
            VALUES($installation, $heartbeat, 'reporting', 'enrolled');
            INSERT INTO EndpointInventories(EndpointId, CollectedUtcTicks, ReportJson) VALUES($id, $inventory, $inventoryJson);
            INSERT INTO EndpointSecurityTelemetry(EndpointId, SchemaVersion, CollectedUtcTicks, ReceivedUtcTicks, ReportJson)
            VALUES($id, 1, $telemetry, $now, $telemetryJson);
            """, ("$installation", endpoint.InstallationId.ToString("D")), ("$id", endpoint.EndpointId.ToString("D")),
            ("$heartbeat", now.AddMinutes(-MonitoringCoverageContract.HeartbeatWarningMinutes).UtcTicks),
            ("$inventory", now.AddHours(-4).UtcTicks), ("$inventoryJson", JsonSerializer.Serialize(new { Hostname = "Overview boundary device", PrivateMarker })),
            ("$telemetry", now.AddHours(-MonitoringCoverageContract.TelemetryFreshHours).UtcTicks), ("$now", now.UtcTicks),
            ("$telemetryJson", """
                {"bitLocker":{"availability":"collected"},"antivirus":{"availability":"collected"},"defender":{"availability":"collected"},
                 "localAdministrators":{"availability":"collected"},"windowsUpdate":{"policyAvailability":"collected","resultsAvailability":"collected"},
                 "pendingReboot":{"availability":"collected"},"services":{"availability":"collected"},"software":{"availability":"collected"}}
                """));
        foreach (var channel in SecurityEventChannels.All)
            await ExecuteAsync(database, """
                INSERT INTO SecurityEventSources(EndpointId, Channel, State, AgentVersion, AgentSentUtcTicks, CountersSinceUtcTicks,
                                                ReceivedUtcTicks, StatusJson)
                VALUES($id, $channel, 'collecting', 'synthetic', $received, $received, $received, '{}');
                """, ("$id", endpoint.EndpointId.ToString("D")), ("$channel", channel),
                ("$received", now.AddHours(-MonitoringCoverageContract.EventFreshHours).UtcTicks));
    }

    private static async Task SeedAlertsAsync(SqliteConnection database, Guid endpoint, Guid removed, DateTimeOffset now)
    {
        foreach (var (order, severity, status, observed, endpointId) in new[]
        {
            (1, "critical", "open", now.AddMinutes(-3), endpoint), (2, "critical", "investigating", now.AddMinutes(-3), endpoint),
            (3, "critical", "open", now.AddDays(-1), endpoint), (4, "high", "investigating", now, endpoint),
            (5, "high", "open", now.AddMinutes(-1), endpoint), (6, "high", "open", now.AddMinutes(-2), endpoint),
            (7, "critical", "open", now, removed), (8, "critical", "resolved", now, endpoint),
            (9, "high", "accepted", now, endpoint), (10, "medium", "open", now, endpoint)
        })
        {
            await ExecuteAsync(database, """
                INSERT INTO TrackedAlerts(AlertId, EndpointId, EndpointName, RuleId, Title, Severity, Status, FirstObservedUtcTicks,
                                          LastObservedUtcTicks, CreatedUtcTicks, UpdatedUtcTicks, StatusChangedUtcTicks, Version,
                                          Reason, EvidenceJson, RecommendedAction)
                VALUES($id, $endpoint, $label, $rule, $label, $severity, $status, $observed, $observed, $observed, $observed, $observed, 1,
                       $private, $evidence, $private);
                """, ("$id", TestId(order).ToString("D")), ("$endpoint", endpointId.ToString("D")), ("$label", LongLabel),
                ("$rule", $"synthetic-overview-{order}"), ("$severity", severity), ("$status", status), ("$observed", observed.UtcTicks),
                ("$private", PrivateMarker), ("$evidence", JsonSerializer.Serialize(new { PrivateMarker })));
        }

        await InsertHistoryAsync(database, 10, null, "open", now.AddHours(-24).AddTicks(-1));
        await InsertHistoryAsync(database, 6, null, "open", now.AddHours(-24));
        await InsertHistoryAsync(database, 1, null, "open", now.AddHours(-2));
        await InsertHistoryAsync(database, 7, null, "open", now);
        await InsertHistoryAsync(database, 2, "resolved", "open", now);
        await InsertHistoryAsync(database, 9, "open", "accepted", now.AddHours(-1));
        await InsertHistoryAsync(database, 8, "open", "resolved", now.AddTicks(2));
    }

    private static Task InsertHistoryAsync(SqliteConnection database, int alert, string? previous, string status, DateTimeOffset changed) =>
        ExecuteAsync(database, """
            INSERT INTO AlertStatusHistory(AlertId, PreviousStatus, Status, ChangedUtcTicks, ChangedBy)
            VALUES($id, $previous, $status, $changed, $private);
            """, ("$id", TestId(alert).ToString("D")), ("$previous", previous), ("$status", status),
            ("$changed", changed.UtcTicks), ("$private", PrivateMarker));

    private static async Task SeedNotificationsAsync(SqliteConnection database, Guid endpoint, DateTimeOffset now)
    {
        for (var order = 20; order <= 26; order++)
        {
            var created = now.AddMinutes(order == 26 ? 0 : -Math.Max(1, order - 20));
            var observed = order == 25 ? now : created;
            await ExecuteAsync(database, """
                INSERT INTO Notifications(NotificationId, Kind, EndpointId, EndpointName, Severity, Occurrences,
                                          CreatedUtcTicks, LastObservedUtcTicks, ReadUtcTicks, GroupKey, GroupUntilUtcTicks)
                VALUES($id, 'monitoringOffline', $endpoint, $name, 'high', 3, $created, $observed, $read, $private, $observed);
                """, ("$id", TestId(order).ToString("D")), ("$endpoint", endpoint.ToString("D")), ("$name", LongLabel),
                ("$created", created.UtcTicks), ("$observed", observed.UtcTicks), ("$read", order == 26 ? now.UtcTicks : null),
                ("$private", PrivateMarker));
        }
    }

    private static async Task<IReadOnlyList<Guid>> SeedRisksAsync(RiskRegisterStore store, SqliteConnection database, DateTimeOffset now)
    {
        string Day(int delta) => now.UtcDateTime.AddDays(delta).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var risks = new List<Guid>();
        for (var index = 0; index < 9; index++)
        {
            var residual = index < 2 ? 5 : index == 2 ? 4 : 3;
            var record = new RiskRecordInput(index == 0 ? LongLabel : $"Synthetic risk {index}", PrivateMarker, PrivateMarker,
                5, 5, PrivateMarker, residual, 4, index == 0 ? "accept" : "mitigate", index == 0 ? PrivateMarker : null,
                index == 0 ? Day(1) : null, null, Day(0), index == 8 ? "closed" : "open", [], [], [], PrivateMarker);
            var result = await store.CreateAsync(record, PrivateMarker);
            var id = result.Record?.RiskId ?? throw new InvalidOperationException("Synthetic overview risk failed creation.");
            risks.Add(id);
            if (index == 7) continue;
            var deadline = index switch { 0 => "$.acceptanceExpiresOn", 2 => "$.targetDate", _ => "$.reviewDate" };
            await ExecuteAsync(database, "UPDATE RiskRegister SET RecordJson=json_set(RecordJson, $path, $day) WHERE RiskId=$id;",
                ("$path", deadline), ("$day", Day(-1)), ("$id", id.ToString("D")));
        }
        return risks;
    }

    private static async Task CheckSourceParityAsync(HttpClient client, string bearer, OperationsOverviewSnapshot overview)
    {
        var coverage = await ReadAsync<MonitoringEndpointPage>(client, "/api/admin/monitoring-coverage?issuesOnly=true&limit=5", bearer);
        Check(overview.GeneratedUtc == coverage.GeneratedUtc && overview.Counts.ActiveEndpoints == coverage.Total &&
            overview.Counts.CoverageIssues == coverage.Matching && overview.CoverageIssues.SequenceEqual(coverage.Items),
            "coverage count and preview equal the filtered source page");
        var notifications = await ReadAsync<NotificationPage>(client, "/api/admin/notifications?unreadOnly=true&limit=5", bearer);
        Check(overview.Counts.UnreadNotifications == notifications.Unread &&
            overview.UnreadNotifications.Select(item => item.NotificationId).SequenceEqual(notifications.Items.Select(item => item.NotificationId)),
            "retained unread count and preview IDs equal the source inbox page");
        var register = await ReadAsync<RiskRegisterPage>(client, "/api/admin/risk-register?attention=true&limit=5", bearer);
        Check(overview.Counts.RisksNeedingAttention == register.Counts.NeedsAttention &&
            overview.RisksNeedingAttention.Select(item => (item.RiskId, item.ReviewOverdue, item.AcceptanceExpired, item.TargetDatePassed))
            .SequenceEqual(register.Records.Select(item => (item.RiskId, item.Flags.ReviewOverdue, item.Flags.AcceptanceExpired, item.Flags.TargetDatePassed))),
            "risk count, preview IDs and flags equal the filtered UTC source page");
    }

    private static async Task<OperationsOverviewSnapshot> ReadOverviewAsync(HttpClient client, string bearer, string? agentCredential = null)
    {
        using var response = await SendAsync(client, Route + "?limit=500", bearer);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            $"authorized overview read is no-store ({response.StatusCode})");
        var bytes = await response.Content.ReadAsByteArrayAsync();
        var text = Encoding.UTF8.GetString(bytes);
        Check(bytes.Length <= OperationsOverviewContract.MaximumResponseBytes && !text.Contains(PrivateMarker, StringComparison.Ordinal) &&
            !text.Contains(bearer, StringComparison.Ordinal) && (agentCredential is null || !text.Contains(agentCredential, StringComparison.Ordinal)),
            "response byte bound and disclosure of approved fields only");
        return JsonSerializer.Deserialize<OperationsOverviewSnapshot>(bytes, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidOperationException("No operations overview response.");
    }

    private static async Task<T> ReadAsync<T>(HttpClient client, string route, string bearer) where T : class
    {
        using var response = await SendAsync(client, route, bearer);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>() ?? throw new InvalidOperationException($"No source response for {route}.");
    }

    private static async Task ExpectAsync(HttpClient client, HttpStatusCode expected, string? credential = null, string scheme = "Bearer",
        bool remote = false)
    {
        using var response = await SendAsync(client, Route, credential, scheme, remote);
        Check(response.StatusCode == expected && response.Headers.CacheControl?.NoStore == true &&
            (await response.Content.ReadAsStringAsync()).Length == 0, $"overview refusal is bounded and no-store ({response.StatusCode}, expected {expected})");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string route, string? credential, string scheme = "Bearer",
        bool remote = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);
        if (credential is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, credential);
        if (remote)
        {
            request.Headers.Add("Synthetic-Remote", "1");
            request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        }
        return await client.SendAsync(request);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        Check(await command.ExecuteNonQueryAsync() > 0, "synthetic fixture write matched no rows");
    }

    private static Guid TestId(int order) => new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, checked((byte)order));

    private static void Check(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException("Operations overview API: " + description);
    }

    private sealed record Endpoint(Guid InstallationId, Guid EndpointId, string AgentCredential)
    {
        public override string ToString() => nameof(Endpoint);
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
