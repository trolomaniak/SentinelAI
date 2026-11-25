using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.RiskHistory;
using SentinelAI.Core;
using SentinelAI.Core.History;
using SentinelAI.Core.Persistence;

internal static class RiskHistoryApiTests
{
    private const string Route = "/api/admin/risk-history";
    private const string PrivateMarker = "synthetic history private alert evidence";
    private static readonly DateTimeOffset Boundary = new(2026, 1, 12, 6, 0, 0, TimeSpan.Zero);

    internal static async Task VerifyAsync(string username, string password)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-risk-history-{Guid.NewGuid():N}");
        try
        {
            await VerifyMeasurementsAsync(Path.Combine(directory, "history"), username, password);
            await VerifyRetentionAsync(Path.Combine(directory, "retention"));
            await VerifyHostedCaptureAsync(Path.Combine(directory, "worker"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine("Risk history tests passed (cadence, actual timestamps, concurrency, retry, restart, policy, parity, UTC periods, retention and loopback access).");
    }

    private static async Task VerifyMeasurementsAsync(string directory, string username, string password)
    {
        var clock = new ManualTime(Boundary.AddTicks(-1));
        var firstTime = clock.UtcNow;
        EnrollmentResponse secondary;
        EnrollmentResponse governing;
        RiskHistoryPoint initial;
        DateTimeOffset priorTime;
        await using (var app = Build(directory, clock))
        {
            using var client = await StartAsync(app);
            var bearer = await LoginAsync(client, username, password);
            var history = app.Services.GetRequiredService<RiskHistoryStore>();
            var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
            secondary = await EnrollAsync(enrollments);
            governing = await EnrollAsync(enrollments);
            var databasePath = app.Services.GetRequiredService<AdminStore>().DatabasePath;
            var empty = await ReadAsync(client, Route, bearer);
            Check(empty.EndpointId is null && empty.PeriodHours == 168 && empty.GeneratedUtc == firstTime &&
                empty.StartUtc == firstTime.AddDays(-7) && empty.Points.Count == 0,
                "opening history did not preserve the empty state or default period");
            await ExpectAsync(client, Route, HttpStatusCode.Unauthorized);
            await ExpectAsync(client, EndpointPath(governing.EndpointId), HttpStatusCode.Unauthorized,
                "invalid-history-test-token");
            await ExpectAsync(client, Route, HttpStatusCode.Unauthorized, $"{governing.EndpointId:D}.{governing.AgentCredential}",
                scheme: "SentinelAgent");
            await ExpectAsync(client, Route, HttpStatusCode.Forbidden, bearer, remote: true);
            await ExpectAsync(client, EndpointPath(governing.EndpointId), HttpStatusCode.Forbidden, bearer, remote: true);
            Check(!LocalNetworkRoutes.IsAllowed("GET", Route) && !LocalNetworkRoutes.IsAllowed("GET", EndpointPath(governing.EndpointId)),
                "Agent listener permits a risk history route");
            foreach (var badQuery in new[] { "?hours=", "?hours=1", "?hours=-24", "?hours=2161", "?hours=99999999999",
                         "?hours=24&hours=24", "?hours=24&offset=0", "?period=24" })
                await ExpectAsync(client, Route + badQuery, HttpStatusCode.BadRequest, bearer);
            await ExpectAsync(client, EndpointPath(Guid.Empty), HttpStatusCode.BadRequest, bearer);
            Check((await ReadAsync(client, EndpointPath(Guid.NewGuid()), bearer)).Points.Count == 0,
                "an unknown endpoint exposed another scope's history");
            Check(await ScalarAsync(databasePath, "SELECT COUNT(*) FROM RiskHistoryCaptures;") == 0,
                "administrator reads created a measurement");

            foreach (var (rule, severity) in new[] { ("SA-FW-001", "critical"), ("SA-UAC-001", "critical"), ("SA-LSA-001", "high") })
                await AddAlertAsync(databasePath, secondary.EndpointId, rule, severity, firstTime);
            foreach (var rule in new[] { "SA-FW-001", "SA-UAC-001", "SA-LSA-001", "SA-RDP-001" })
                await AddAlertAsync(databasePath, governing.EndpointId, rule, "critical", firstTime);

            var attempts = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() => history.CaptureAsync())));
            Check(attempts.Count(saved => saved) == 1 &&
                await ScalarAsync(databasePath, "SELECT COUNT(*) FROM RiskHistoryEndpointPoints;") == 2,
                "concurrent attempts did not commit exactly one complete fleet capture");
            initial = (await ReadAsync(client, Route + "?hours=24", bearer)).Points.Single();
            var endpoint = (await ReadAsync(client, EndpointPath(governing.EndpointId), bearer)).Points.Single();
            var fleet = await app.Services.GetRequiredService<RiskReadStore>().ListAsync(0, 10);
            var current = await app.Services.GetRequiredService<RiskReadStore>().FindAsync(governing.EndpointId);
            Check(initial.CapturedUtc == firstTime && initial.ComparedWithUtc is null && initial.EndpointCount == 2 &&
                initial.GoverningEndpointId == governing.EndpointId && initial.Score == fleet.Organization.Score &&
                initial.RawScore == fleet.Endpoints.Max(item => item.RawScore) && initial.RawScore > initial.Score &&
                endpoint.Score == current!.Risk.Score && endpoint.RawScore == current.Risk.RawScore &&
                endpoint.EndpointCount is null && endpoint.GoverningEndpointId is null &&
                initial.PrincipalRuleIds.SequenceEqual(endpoint.PrincipalRuleIds) && endpoint.PrincipalRuleIds.Count == 3 &&
                initial.Causes.SequenceEqual(new[] { "firstCapture" }),
                "capture lost actual UTC time, scope, uncapped maximum, principal rules or current scoring parity");
            Check(!await history.CaptureAsync(), "same-bucket retry created another point");
            clock.UtcNow = firstTime.AddHours(-6);
            Check(!await history.CaptureAsync() && (await ReadAsync(client, Route, bearer)).Points.Count == 0,
                "clock rollback created a point or exposed a future measurement");

            clock.UtcNow = Boundary;
            await ExecuteAsync(databasePath, "UPDATE TrackedAlerts SET Status='resolved' WHERE EndpointId=$endpoint AND RuleId='SA-FW-001';",
                ("$endpoint", governing.EndpointId.ToString("D")));
            await ExecuteAsync(databasePath, """
                CREATE TRIGGER SyntheticHistoryWriteFailure BEFORE INSERT ON RiskHistoryEndpointPoints
                BEGIN SELECT RAISE(ABORT, 'synthetic risk history write failure'); END;
                """);
            try
            {
                await history.CaptureAsync();
                throw new InvalidOperationException("Risk history tests: injected write failure did not abort the capture");
            }
            catch (SqliteException) { }
            Check(await ScalarAsync(databasePath, "SELECT COUNT(*) FROM RiskHistoryCaptures;") == 1 &&
                await ScalarAsync(databasePath, "SELECT COUNT(*) FROM RiskHistoryBaselines;") == 2,
                "failed capture replaced the history watermark or baseline");
            await ExecuteAsync(databasePath, "DROP TRIGGER SyntheticHistoryWriteFailure;");
            Check(await history.CaptureAsync(), "same-bucket retry after rollback was not recorded");
            var next = (await ReadAsync(client, Route, bearer)).Points[^1];
            Check(next.CapturedUtc == Boundary && next.ComparedWithUtc == firstTime && next.RawScore < initial.RawScore &&
                next.Score == initial.Score && next.Causes.Contains("statusChanged"),
                "adjacent six-hour buckets, including uncapped changes above 100, lost their comparison");

            clock.UtcNow = Boundary.AddHours(24);
            Check(await enrollments.RemoveEndpointAsync(secondary.EndpointId) == EndpointRemoval.Removed,
                "synthetic endpoint removal failed");
            var added = await EnrollAsync(enrollments);
            Check(await history.CaptureAsync(), "current bucket was skipped after a clock jump");
            bearer = await LoginAsync(client, username, password);
            var organization = (await ReadAsync(client, Route, bearer)).Points;
            var newest = organization[^1];
            Check(organization.Count == 3 && newest.CapturedUtc == clock.UtcNow && newest.ComparedWithUtc == Boundary &&
                newest.EndpointCount == 2 && newest.GoverningEndpointId == governing.EndpointId &&
                newest.Causes.SequenceEqual(new[] { "fleetChanged" }) &&
                (await ReadAsync(client, EndpointPath(secondary.EndpointId), bearer)).Points.Count == 2 &&
                (await ReadAsync(client, EndpointPath(added.EndpointId), bearer)).Points.Single().ComparedWithUtc is null,
                "missed buckets were filled or same-count membership changes and removed-endpoint points were lost");
            var pastDay = await ReadAsync(client, Route + "?hours=24", bearer);
            Check(pastDay.Points.Select(point => point.CapturedUtc).SequenceEqual(new[] { Boundary, clock.UtcNow }),
                "24-hour range did not filter points by elapsed UTC time");
            priorTime = clock.UtcNow;
        }

        await using var restart = Build(directory, clock, arguments:
            ["--SentinelAI:RiskScoring:Policy:Version=history-v2", "--SentinelAI:RiskScoring:Policy:DefaultConfidence=0.5"]);
        using var restartedClient = await StartAsync(restart);
        var newBearer = await LoginAsync(restartedClient, username, password);
        var restartedHistory = restart.Services.GetRequiredService<RiskHistoryStore>();
        Check(!await restartedHistory.CaptureAsync(), "restart wrote another point in the recorded bucket");
        clock.UtcNow = priorTime.AddHours(6);
        Check(await restartedHistory.CaptureAsync(), "restart skipped the next bucket");
        newBearer = await LoginAsync(restartedClient, username, password);
        var points = (await ReadAsync(restartedClient, Route + "?hours=720", newBearer)).Points;
        Check(points.Count == 4 && points[0].RawScore == initial.RawScore && points[0].PolicyFingerprint == initial.PolicyFingerprint &&
            points[^1].ComparedWithUtc == priorTime && points[^1].PolicyFingerprint != initial.PolicyFingerprint &&
            points[^1].PolicyVersion == "history-v2" && points[^1].Causes.Contains("policyChanged") && points[^1].RawScore < points[^2].RawScore &&
            (await ReadAsync(restartedClient, EndpointPath(secondary.EndpointId), newBearer)).Points.Count == 2,
            "policy changes rewrote older samples, lost restart comparisons or removed endpoint history");
    }

    private static async Task VerifyRetentionAsync(string directory)
    {
        var clock = new ManualTime(Boundary);
        await using var app = Build(directory, clock, maximumEndpointPoints: 3);
        using var client = await StartAsync(app);
        var path = app.Services.GetRequiredService<AdminStore>().DatabasePath;
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var first = await EnrollAsync(enrollments);
        var second = await EnrollAsync(enrollments);
        var store = app.Services.GetRequiredService<RiskHistoryStore>();
        Check(await store.CaptureAsync(), "row cap fixture did not create its first two-point capture");
        clock.UtcNow = Boundary.AddHours(6);
        Check(await enrollments.RemoveEndpointAsync(second.EndpointId) == EndpointRemoval.Removed && await store.CaptureAsync() &&
            await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryEndpointPoints;") == 3,
            "row count at the exact cap did not remain complete");
        clock.UtcNow = Boundary.AddHours(12);
        Check(await store.CaptureAsync() && await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryEndpointPoints;") == 2 &&
            (await store.ReadAsync(second.EndpointId, 2160, default)).Points.Count == 0 &&
            (await store.ReadAsync(null, 2160, default)).Points.Count == 2 &&
            await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryBaselines;") == 1,
            "row cap did not evict whole oldest captures and prune baselines to the newest active fleet");

        var lastRetainableTime = clock.UtcNow;
        clock.UtcNow = lastRetainableTime.AddDays(RiskHistoryContract.RetentionDays);
        Check(await store.CaptureAsync() && (await store.ReadAsync(first.EndpointId, 2160, default)).Points.Count == 2 &&
            (await store.ReadAsync(null, 2160, default)).Points[0].CapturedUtc == lastRetainableTime &&
            await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryCaptures;") == 2,
            "the exact 90-day boundary was not retained or an older capture was retained");
        clock.UtcNow = clock.UtcNow.AddTicks(1);
        Check((await store.ReadAsync(null, 2160, default)).Points.Count == 1 && !await store.CaptureAsync(),
            "the read retained an expired point or produced a new same-bucket point");
        clock.UtcNow = clock.UtcNow.AddHours(6);
        Check(await store.CaptureAsync() && await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryCaptures;") == 2 &&
            await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryPolicies;") == 1,
            "physical pruning kept expired captures or copied the same policy per point");

        clock.UtcNow = clock.UtcNow.AddHours(6);
        await EnrollAsync(enrollments);
        await EnrollAsync(enrollments);
        var excess = await EnrollAsync(enrollments);
        try
        {
            await store.CaptureAsync();
            throw new InvalidOperationException("Risk history tests: oversized fleet produced a capture");
        }
        catch (InvalidDataException) { }
        Check(await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryEndpointPoints;") == 2 &&
            await enrollments.RemoveEndpointAsync(excess.EndpointId) == EndpointRemoval.Removed && await store.CaptureAsync() &&
            await ScalarAsync(path, "SELECT COUNT(*) FROM RiskHistoryEndpointPoints;") == 3 &&
            (await store.ReadAsync(null, 2160, default)).Points.Single().ComparedWithUtc == clock.UtcNow.AddHours(-6),
            "oversized capture persisted partial rows or prevented a complete same-bucket retry");
    }

    private static async Task VerifyHostedCaptureAsync(string directory)
    {
        var now = Boundary.AddMinutes(17);
        var clock = new ManualTime(now);
        await using var app = Build(directory, clock, backgroundWorker: true);
        using var client = await StartAsync(app);
        var store = app.Services.GetRequiredService<RiskHistoryStore>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (true)
        {
            var point = (await store.ReadAsync(null, 24, timeout.Token)).Points.SingleOrDefault();
            if (point is not null)
            {
                Check(point.CapturedUtc == now && point.Score == 0 && point.EndpointCount == 0 &&
                    point.GoverningEndpointId is null && point.Causes.SequenceEqual(new[] { "firstCapture" }),
                    "hosted worker did not record an actual empty-fleet measurement");
                return;
            }
            await Task.Delay(10, timeout.Token);
        }
    }

    private static WebApplication Build(string directory, ManualTime clock, bool backgroundWorker = false,
        int? maximumEndpointPoints = null, string[]? arguments = null) => CoreHost.Build(
        ["--SentinelAI:DataDirectory=" + directory, .. (arguments ?? [])], false,
        builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<TimeProvider>(clock);
            if (!backgroundWorker)
                builder.Services.Remove(builder.Services.Single(service => service.ServiceType == typeof(IHostedService) &&
                    service.ImplementationType == typeof(RiskHistoryWorker)));
            if (maximumEndpointPoints is int limit)
                builder.Services.AddSingleton(services => new RiskHistoryStore(services.GetRequiredService<AdminStore>(),
                    services.GetRequiredService<RiskReadStore>(), clock, limit));
        }, configureBeforeAuthentication: app => app.Use((context, next) =>
        {
            if (context.Request.Headers.ContainsKey("Synthetic-Remote-History"))
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.50");
                context.Request.Scheme = "https";
            }
            return next(context);
        }));

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        response.EnsureSuccessStatusCode();
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return document.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<RiskHistoryView> ReadAsync(HttpClient client, string path, string bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            $"expected successful no-store history read for {path}, received {response.StatusCode} (cache control: {response.Headers.CacheControl})");
        var bytes = await response.Content.ReadAsByteArrayAsync();
        Check(bytes.Length <= RiskHistoryContract.MaximumResponseBytes, "history read was oversized");
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        Check(!json.Contains(PrivateMarker, StringComparison.Ordinal) && !json.Contains("factors", StringComparison.OrdinalIgnoreCase),
            "history exposed raw alert evidence or a comparison baseline");
        return JsonSerializer.Deserialize<RiskHistoryView>(json, JsonSerializerOptions.Web) ??
            throw new InvalidOperationException("Risk history tests: missing response");
    }

    private static async Task ExpectAsync(HttpClient client, string path, HttpStatusCode status, string? bearer = null,
        bool remote = false, string scheme = "Bearer")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue(scheme, bearer);
        if (remote) request.Headers.Add("Synthetic-Remote-History", "1");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == status && response.Headers.CacheControl?.NoStore == true,
            $"expected {status} and no-store for {path}, received {response.StatusCode}");
    }

    private static async Task<EnrollmentResponse> EnrollAsync(EnrollmentStore store)
    {
        var token = await store.IssueTokenAsync();
        var result = await store.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token), overLocalNetwork: true);
        return result.Response ?? throw new InvalidOperationException("Risk history tests: synthetic enrollment failed");
    }

    private static Task AddAlertAsync(string path, Guid endpoint, string rule, string severity, DateTimeOffset now) =>
        ExecuteAsync(path, """
            INSERT INTO TrackedAlerts(AlertId, EndpointId, EndpointName, RuleId, Title, Severity, Status, FirstObservedUtcTicks,
                LastObservedUtcTicks, CreatedUtcTicks, UpdatedUtcTicks, StatusChangedUtcTicks, Version, Reason, EvidenceJson, RecommendedAction)
            VALUES($id, $endpoint, $marker, $rule, $marker, $severity, 'open', $ticks, $ticks, $ticks, $ticks, $ticks,
                1, $marker, '{}', $marker);
            """, ("$id", Guid.NewGuid().ToString("D")), ("$endpoint", endpoint.ToString("D")), ("$rule", rule),
            ("$severity", severity), ("$ticks", now.UtcTicks), ("$marker", PrivateMarker));

    private static async Task ExecuteAsync(string path, string sql, params (string Name, object Value)[] parameters)
    {
        await using var connection = await OpenAsync(path);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarAsync(string path, string sql)
    {
        await using var connection = await OpenAsync(path);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private static async Task<SqliteConnection> OpenAsync(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        await connection.OpenAsync();
        return connection;
    }

    private static string EndpointPath(Guid endpointId) => Route + "/" + endpointId.ToString("D");

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("Risk history tests: " + message);
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset UtcNow { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
