using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Heartbeat;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.LicenseApi;
using SentinelAI.Rules;

internal static class LicenseStateIntegrationTests
{
    private const string StatusPath = "/api/admin/license";
    private const string RenewPath = "/api/admin/license/renew";
    private const string ExportPath = "/api/admin/incidents/export";
    private const string CriticalRuleId = "synthetic-test-critical-monitoring";
    private static int _assertions;

    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-license-state-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var dataDirectory = Path.Combine(directory, "core-data");
        var username = $"license-state-admin-{Guid.NewGuid():N}";
        var password = $"Development-Test-Only-{Guid.NewGuid():N}!";
        var previousUsername = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME");
        var previousPassword = Environment.GetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD");
        var initialUtc = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new MutableTimeProvider(initialUtc);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(directory, "private.pem");
        var publicPath = Path.Combine(directory, "public.pem");
        var credentialPath = Path.Combine(directory, "activation-credential.txt");
        var credential = Base64Url(RandomNumberGenerator.GetBytes(32));
        try
        {
            await WriteProtectedFileAsync(privatePath, key.ExportPkcs8PrivateKeyPem());
            await WriteProtectedFileAsync(publicPath, key.ExportSubjectPublicKeyInfoPem());
            await WriteProtectedFileAsync(credentialPath, credential);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", username);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", password);

            CoreIdentity identity;
            Guid initialCriticalAlertId;
            await using (var unconfigured = CoreHost.Build(CoreArgs(dataDirectory), Configure(clock)))
            {
                using var client = await StartAsync(unconfigured);
                var token = await LoginAsync(client, username, password);
                identity = await unconfigured.Services.GetRequiredService<EnrollmentStore>().GetCoreIdentityAsync();
                var status = await StatusAsync(client, token, "SAFE_MODE", premium: false);
                Check(status.GetProperty("lastSuccessfulValidationUtc").ValueKind == JsonValueKind.Null,
                    "An unlicensed Core invented a successful validation timestamp.");
                using (var disabled = await RequestAsync(client, HttpMethod.Post, RenewPath, token))
                    Check(disabled.StatusCode == HttpStatusCode.ServiceUnavailable && disabled.Headers.CacheControl?.NoStore == true,
                        "Unconfigured renewal did not fail safely without caching.");
                initialCriticalAlertId = await VerifySafeMonitoringAsync(unconfigured, client, token);
            }

            // Run the real issuer and real Core over loopback HTTP, with generated
            // development credentials. Restart the issuer on the same address to
            // simulate an actual connectivity outage and restoration.
            var issuerArgs = CloudArgs(privatePath, identity, credential);
            var issuer = LicenseApiHost.Build(issuerArgs, Configure(clock, replaceRules: false));
            using var issuerClient = await StartAsync(issuer);
            var issuerOrigin = issuerClient.BaseAddress!.GetLeftPart(UriPartial.Authority);
            var coreArgs = CoreArgs(dataDirectory,
                $"--SentinelAI:Licensing:TrustedPublicKeys:development-key={publicPath}",
                $"--SentinelAI:Licensing:Renewal:Url={issuerOrigin}",
                $"--SentinelAI:Licensing:Renewal:ActivationCredentialPath={credentialPath}",
                "--SentinelAI:Licensing:Renewal:Automatic=false");
            DateTimeOffset safeEffectiveUtc;
            try
            {
                await using var core = CoreHost.Build(coreArgs, Configure(clock));
                using var client = await StartAsync(core);
                var token = await LoginAsync(client, username, password);
                await StatusAsync(client, token, "SAFE_MODE", premium: false);
                var full = await RenewAsync(client, token, "FULL", premium: true);
                Check(Timestamp(full, "lastSuccessfulValidationUtc") == initialUtc &&
                      Timestamp(full, "fullModeUntil") == initialUtc.AddDays(7),
                    "Online validation did not preserve the issuer's seven-day signed deadline.");
                Check(full.GetProperty("enabledFeatures").EnumerateArray().Select(feature => feature.GetString())
                        .SequenceEqual(["inventory", "risk"]),
                    "Full mode did not expose the server-selected entitlement features.");
                var lease = await FetchLeaseAsync(issuerClient, identity, credential);
                await VerifyAccessAndBoundsAsync(core, client, token);

                await issuer.StopAsync();
                clock.Advance(TimeSpan.FromDays(1));
                token = await LoginAsync(client, username, password);
                var grace = await RenewAsync(client, token, "GRACE", premium: true);
                AssertUnextended(grace, initialUtc);
                clock.Advance(TimeSpan.FromDays(6) - TimeSpan.FromSeconds(1));
                token = await LoginAsync(client, username, password);
                await StatusAsync(client, token, "GRACE", premium: true);
                clock.Advance(TimeSpan.FromSeconds(1));
                await StatusAsync(client, token, "SAFE_MODE", premium: false);
                clock.Advance(TimeSpan.FromHours(1));
                token = await LoginAsync(client, username, password);
                var safe = await RenewAsync(client, token, "SAFE_MODE", premium: false);
                AssertUnextended(safe, initialUtc);
                safeEffectiveUtc = Timestamp(safe, "effectiveUtc");
                Check(safeEffectiveUtc >= initialUtc.AddDays(7).AddHours(1),
                    "The outage simulation did not advance beyond seven days.");
                await VerifySafeMonitoringAsync(core, client, token);

                // An in-flight renewal is observable as RECOVERING. Returning a
                // malformed token must restore Safe Mode, never grant entitlement.
                var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                await using (var invalidIssuer = BuildReplyIssuer(issuerOrigin, async () =>
                             {
                                 entered.TrySetResult();
                                 await release.Task;
                                 return "synthetic-invalid-token";
                             }))
                {
                    using var replyClient = await StartAsync(invalidIssuer, issuerOrigin);
                    var renewing = RenewAsync(client, token, "SAFE_MODE", premium: false);
                    try
                    {
                        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                        var recovering = await StatusAsync(client, token, "RECOVERING", premium: false);
                        AssertUnextended(recovering, initialUtc);
                    }
                    finally
                    {
                        release.TrySetResult();
                    }
                    AssertUnextended(await renewing, initialUtc);
                }
                await using (var replayIssuer = BuildReplyIssuer(issuerOrigin, () => Task.FromResult(lease)))
                {
                    using var replyClient = await StartAsync(replayIssuer, issuerOrigin);
                    var replay = await RenewAsync(client, token, "SAFE_MODE", premium: false);
                    AssertUnextended(replay, initialUtc);
                }
            }
            finally
            {
                await issuer.DisposeAsync();
            }

            // A new process has no previous monotonic timestamp. Its persisted
            // effective time must still prevent an obvious wall-clock rollback
            // from reviving a lease that expired during the outage.
            var restartedClock = new MutableTimeProvider(initialUtc.AddHours(-2));
            await using (var restarted = CoreHost.Build(coreArgs, Configure(restartedClock)))
            {
                using var client = await StartAsync(restarted);
                var token = await LoginAsync(client, username, password);
                var restored = await StatusAsync(client, token, "SAFE_MODE", premium: false);
                AssertUnextended(restored, initialUtc);
                Check(restored.GetProperty("clockRollbackDetected").GetBoolean() &&
                      Timestamp(restored, "effectiveUtc") >= safeEffectiveUtc,
                    "Core restart and wall-clock rollback revived an expired lease or lost the persisted high-water time.");
                using (var incident = await RequestAsync(client, HttpMethod.Get,
                           $"/api/admin/alerts/{initialCriticalAlertId:D}", token))
                    Check(incident.StatusCode == HttpStatusCode.OK,
                        "Restart in Safe Mode lost access to a pre-existing critical incident.");
                await VerifySafeMonitoringAsync(restarted, client, token);

                var serverClock = new MutableTimeProvider(safeEffectiveUtc.AddHours(1));
                await using var restoredIssuer = LicenseApiHost.Build(issuerArgs, Configure(serverClock, replaceRules: false));
                using var restoredIssuerClient = await StartAsync(restoredIssuer, issuerOrigin);
                var recovered = await RenewAsync(client, token, "FULL", premium: true);
                Check(Timestamp(recovered, "lastSuccessfulValidationUtc") == serverClock.GetUtcNow() &&
                      Timestamp(recovered, "fullModeUntil") == serverClock.GetUtcNow().AddDays(7) &&
                      Timestamp(recovered, "effectiveUtc") >= serverClock.GetUtcNow(),
                    "Connectivity restoration did not use the fresh signed server time to restore Full mode after rollback.");
                await StatusAsync(client, token, "FULL", premium: true);
            }

            await using (var remote = CoreHost.Build(coreArgs, Configure(clock)))
            {
                remote.Use(async (context, next) =>
                {
                    context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
                    await next(context);
                });
                using var client = await StartAsync(remote);
                var token = await LoginAsync(client, username, password);
                foreach (var (method, path) in ProtectedRoutes())
                {
                    using var denied = await RequestAsync(client, method, path, token);
                    Check(denied.StatusCode == HttpStatusCode.Forbidden && denied.Headers.CacheControl?.NoStore == true,
                        "Remote plaintext HTTP was accepted or cacheable for a licensing/emergency route.");
                }
            }

            // Start beyond the retained lease's expiry so only a fresh automatic
            // renewal can grant Full mode; no administrator renewal is requested.
            var automaticClock = new MutableTimeProvider(safeEffectiveUtc.AddDays(9));
            await using (var automaticIssuer = LicenseApiHost.Build(issuerArgs, Configure(automaticClock, replaceRules: false)))
            {
                using var automaticIssuerClient = await StartAsync(automaticIssuer, issuerOrigin);
                var automaticArgs = coreArgs.Select(argument =>
                    argument == "--SentinelAI:Licensing:Renewal:Automatic=false"
                        ? "--SentinelAI:Licensing:Renewal:Automatic=true" : argument).ToArray();
                await using var automaticCore = CoreHost.Build(automaticArgs, Configure(automaticClock));
                using var client = await StartAsync(automaticCore);
                var token = await LoginAsync(client, username, password);
                var automaticallyValidated = false;
                for (var attempt = 0; attempt < 20; attempt++)
                {
                    using var response = await RequestAsync(client, HttpMethod.Get, StatusPath, token);
                    Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
                        "Automatic startup renewal made the administrator status route unavailable or cacheable.");
                    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    var lastValidation = json.RootElement.GetProperty("lastSuccessfulValidationUtc");
                    if (lastValidation.ValueKind == JsonValueKind.String &&
                        lastValidation.GetDateTimeOffset() == automaticClock.GetUtcNow())
                    {
                        automaticallyValidated = true;
                        break;
                    }
                    await Task.Delay(TimeSpan.FromMilliseconds(250));
                }
                Check(automaticallyValidated, "Core startup did not automatically acquire a fresh lease from the real issuer.");
                var automaticFull = await StatusAsync(client, token, "FULL", premium: true);
                Check(Timestamp(automaticFull, "fullModeUntil") == automaticClock.GetUtcNow().AddDays(7),
                    "Automatic startup renewal retained the old lease instead of the new signed deadline.");
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_USERNAME", previousUsername);
            Environment.SetEnvironmentVariable("SENTINELAI_BOOTSTRAP_PASSWORD", previousPassword);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
        Console.WriteLine($"License state integration tests passed ({_assertions} assertions).");
    }

    private static async Task VerifyAccessAndBoundsAsync(WebApplication app, HttpClient client, string token)
    {
        var store = app.Services.GetRequiredService<EnrollmentStore>();
        var enrollmentToken = await store.IssueTokenAsync();
        var attempt = await store.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), enrollmentToken.Token));
        var agent = attempt.Response ?? throw new Exception("Could not create synthetic Agent credentials.");
        foreach (var (method, path) in ProtectedRoutes())
        {
            using (var anonymous = await RequestAsync(client, method, path))
                Check(anonymous.StatusCode == HttpStatusCode.Unauthorized,
                    "An anonymous caller accessed a licensing/emergency administrator route.");
            using var agentRequest = new HttpRequestMessage(method, path);
            agentRequest.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent",
                $"{agent.EndpointId:D}.{agent.AgentCredential}");
            using var denied = await client.SendAsync(agentRequest);
            Check(denied.StatusCode == HttpStatusCode.Unauthorized,
                "Agent credentials crossed the administrator licensing/emergency boundary.");
        }
        foreach (var query in new[]
                 {
                     "offset=-1", "limit=0", "limit=201", "offset=2147483648", "limit=1&limit=2", "unknown=true"
                 })
        {
            using var invalid = await RequestAsync(client, HttpMethod.Get, ExportPath + "?" + query, token);
            Check(invalid.StatusCode == HttpStatusCode.BadRequest && invalid.Headers.CacheControl?.NoStore == true,
                "Emergency export accepted an invalid/unbounded query or allowed caching.");
        }
        using (var body = await RequestAsync(client, HttpMethod.Post, RenewPath, token,
                   new { url = "http://192.0.2.10", enabledFeatures = new[] { "unlimited" } }))
            Check(body.StatusCode == HttpStatusCode.BadRequest && body.Headers.CacheControl?.NoStore == true,
                "Renewal accepted caller-selected issuer addresses or entitlement features.");
        using (var query = await RequestAsync(client, HttpMethod.Post, RenewPath + "?url=http://192.0.2.10", token))
            Check(query.StatusCode == HttpStatusCode.BadRequest,
                "Renewal accepted caller-selected configuration in the query string.");
        using var oversizedRequest = new HttpRequestMessage(HttpMethod.Post, RenewPath)
        {
            Content = new StringContent(new string('x', 25 * 1024), Encoding.UTF8, "application/json")
        };
        oversizedRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var oversized = await client.SendAsync(oversizedRequest);
        Check(oversized.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge,
            "Renewal accepted an oversized request body.");
    }

    private static async Task<Guid> VerifySafeMonitoringAsync(WebApplication app, HttpClient client, string token)
    {
        using (var health = await client.GetAsync("/api/health"))
            Check(health.StatusCode == HttpStatusCode.OK, "Safe Mode stopped Core health monitoring.");
        var installationId = Guid.NewGuid();
        var enrollmentToken = await app.Services.GetRequiredService<EnrollmentStore>().IssueTokenAsync();
        using var enrollment = await client.PostAsJsonAsync("/api/agent/enroll",
            new EnrollmentRequest(installationId, enrollmentToken.Token));
        Check(enrollment.StatusCode == HttpStatusCode.OK, "Safe Mode stopped Agent enrollment.");
        var enrolled = await enrollment.Content.ReadFromJsonAsync<EnrollmentResponse>()
                       ?? throw new Exception("Agent enrollment omitted its response.");
        var agentCredential = $"{enrolled.EndpointId:D}.{enrolled.AgentCredential}";
        using (var heartbeatRequest = new HttpRequestMessage(HttpMethod.Post, "/api/agent/heartbeat")
               { Content = JsonContent.Create(new HeartbeatRequest(installationId)) })
        {
            heartbeatRequest.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agentCredential);
            using var heartbeat = await client.SendAsync(heartbeatRequest);
            Check(heartbeat.StatusCode == HttpStatusCode.OK, "Safe Mode stopped authenticated Agent telemetry.");
        }
        // Monitoring uses the real observation clock; license time is simulated
        // independently so this remains a valid, bounded inventory request.
        var report = new InventoryReport(enrolled.EndpointId, DateTimeOffset.UtcNow, "0.1.0-test", "safe-mode-endpoint",
            "Windows 11", "10.0.26100", "X64", new CpuInventory("Synthetic CPU", 8), 16L * 1024 * 1024 * 1024,
            [new DiskInventory("C:\\", 512L * 1024 * 1024 * 1024, 256L * 1024 * 1024 * 1024)],
            new SecurityPostureInventory(false, false, false));
        using (var inventoryRequest = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory")
               { Content = JsonContent.Create(report) })
        {
            inventoryRequest.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", agentCredential);
            using var inventory = await client.SendAsync(inventoryRequest);
            Check(inventory.StatusCode == HttpStatusCode.NoContent, "Safe Mode stopped authenticated inventory collection.");
        }
        Check((await app.Services.GetRequiredService<InventoryStore>().FindLatestAsync(enrolled.EndpointId))?.CollectedUtc ==
              report.CollectedUtc, "Safe Mode failed to persist accepted telemetry.");
        using (var findings = await RequestAsync(client, HttpMethod.Get,
                   $"/api/admin/devices/{enrolled.EndpointId:D}/alerts", token))
        {
            Check(findings.StatusCode == HttpStatusCode.OK, "Safe Mode stopped local detection reads.");
            using var json = JsonDocument.Parse(await findings.Content.ReadAsStringAsync());
            var items = json.RootElement.GetProperty("alerts").EnumerateArray().ToArray();
            Check(items.Any(item => item.GetProperty("ruleId").GetString() == CriticalRuleId &&
                                   item.GetProperty("severity").GetString() == "critical") && items.Length >= 4,
                "Safe Mode stopped the critical test rule or built-in local firewall rules.");
        }
        Guid criticalAlertId;
        using (var alerts = await RequestAsync(client, HttpMethod.Get, "/api/admin/alerts?severity=critical", token))
        {
            Check(alerts.StatusCode == HttpStatusCode.OK, "Safe Mode stopped critical alert access.");
            using var json = JsonDocument.Parse(await alerts.Content.ReadAsStringAsync());
            var critical = json.RootElement.GetProperty("alerts").EnumerateArray()
                .Single(item => item.GetProperty("endpointId").GetGuid() == enrolled.EndpointId);
            criticalAlertId = critical.GetProperty("alertId").GetGuid();
        }
        using (var detail = await RequestAsync(client, HttpMethod.Get, $"/api/admin/alerts/{criticalAlertId:D}", token))
        {
            Check(detail.StatusCode == HttpStatusCode.OK, "Safe Mode stopped recent incident details.");
            using var json = JsonDocument.Parse(await detail.Content.ReadAsStringAsync());
            Check(json.RootElement.GetProperty("evidence").GetArrayLength() == 1 &&
                  json.RootElement.GetProperty("statusHistory").GetArrayLength() == 1,
                "Critical incident detail lost evidence or lifecycle history in Safe Mode.");
        }
        using (var exported = await RequestAsync(client, HttpMethod.Get, ExportPath, token))
        {
            Check(exported.StatusCode == HttpStatusCode.OK && exported.Headers.CacheControl?.NoStore == true,
                "Safe Mode stopped emergency export or allowed caching of incidents.");
            using var json = JsonDocument.Parse(await exported.Content.ReadAsStringAsync());
            var root = json.RootElement;
            Check(root.GetProperty("format").GetString() == "sentinelai-emergency-incidents-v1" &&
                  root.GetProperty("offset").GetInt32() == 0 && root.GetProperty("limit").GetInt32() == 50 &&
                  root.GetProperty("total").GetInt64() >= 4,
                "Emergency export did not identify its format and bounded incident page.");
            var critical = root.GetProperty("incidents").EnumerateArray()
                .Single(item => item.GetProperty("alertId").GetGuid() == criticalAlertId);
            Check(critical.GetProperty("evidence").GetArrayLength() == 1 &&
                  critical.GetProperty("statusHistory").GetArrayLength() == 1 &&
                  critical.GetProperty("recommendedAction").GetString() == "Review the synthetic observation.",
                "Emergency export omitted critical incident evidence/history/remediation context.");
        }
        using (var bounded = await RequestAsync(client, HttpMethod.Get, ExportPath + "?offset=1&limit=1", token))
        {
            Check(bounded.StatusCode == HttpStatusCode.OK, "Emergency export rejected a valid bounded page.");
            using var json = JsonDocument.Parse(await bounded.Content.ReadAsStringAsync());
            Check(json.RootElement.GetProperty("incidents").GetArrayLength() == 1 &&
                  json.RootElement.GetProperty("offset").GetInt32() == 1 &&
                  json.RootElement.GetProperty("limit").GetInt32() == 1,
                "Emergency export ignored its pagination bounds.");
        }
        return criticalAlertId;
    }

    private static Task<JsonElement> StatusAsync(HttpClient client, string token, string mode, bool premium) =>
        ReadStatusAsync(client, HttpMethod.Get, StatusPath, token, mode, premium);

    private static Task<JsonElement> RenewAsync(HttpClient client, string token, string mode, bool premium) =>
        ReadStatusAsync(client, HttpMethod.Post, RenewPath, token, mode, premium);

    private static async Task<JsonElement> ReadStatusAsync(HttpClient client, HttpMethod method, string path,
        string token, string mode, bool premium)
    {
        using var response = await RequestAsync(client, method, path, token);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            "License state operation failed or allowed caching: " + mode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var status = json.RootElement.Clone();
        Check(status.GetProperty("mode").GetString() == mode, "License state transition produced the wrong mode: " + mode);
        var capabilities = status.GetProperty("capabilities");
        Check(new[] { "criticalTelemetryCollection", "localDetectionRules", "criticalAlerts", "recentIncidents", "emergencyExport" }
                .All(property => capabilities.GetProperty(property).GetBoolean()),
            "License state advertised disabled core security capabilities: " + mode);
        Check(capabilities.GetProperty("premiumFeatures").GetBoolean() == premium,
            "License state exposed the wrong premium capability: " + mode);
        if (!premium)
            Check(status.GetProperty("enabledFeatures").GetArrayLength() == 0,
                "Safe/recovering mode exposed enabled premium entitlement features.");
        return status;
    }

    private static void AssertUnextended(JsonElement status, DateTimeOffset initialUtc) =>
        Check(Timestamp(status, "lastSuccessfulValidationUtc") == initialUtc &&
              Timestamp(status, "fullModeUntil") == initialUtc.AddDays(7),
            "A failed renewal or replay extended the previous successful validation/deadline.");

    private static DateTimeOffset Timestamp(JsonElement status, string property) =>
        status.GetProperty(property).GetDateTimeOffset();

    private static (HttpMethod Method, string Path)[] ProtectedRoutes() =>
        [(HttpMethod.Get, StatusPath), (HttpMethod.Post, RenewPath), (HttpMethod.Get, ExportPath)];

    private static async Task<HttpResponseMessage> RequestAsync(HttpClient client, HttpMethod method,
        string path, string? token = null, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "Synthetic license-state administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<string> FetchLeaseAsync(HttpClient client, CoreIdentity identity, string credential)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/licenses/lease")
        {
            Content = JsonContent.Create(new { organizationId = identity.OrganizationId, installationId = identity.CoreInstallationId })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.OK, "Real issuer failed to produce the lease used by replay tests.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("lease").GetString()!;
    }

    private static WebApplication BuildReplyIssuer(string origin, Func<Task<string>> lease)
    {
        var builder = WebApplication.CreateBuilder(["--urls=" + origin]);
        builder.Logging.ClearProviders();
        var app = builder.Build();
        app.MapPost("/api/licenses/lease", async () => Results.Ok(new { lease = await lease() }));
        return app;
    }

    private static async Task<HttpClient> StartAsync(WebApplication app, string? origin = null)
    {
        app.Urls.Clear();
        app.Urls.Add(origin ?? "http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(15)
        };
    }

    private static Action<WebApplicationBuilder> Configure(TimeProvider clock, bool replaceRules = true) => builder =>
    {
        builder.Services.Replace(ServiceDescriptor.Singleton(clock));
        if (replaceRules)
            builder.Services.Replace(ServiceDescriptor.Singleton(new RuleEngine(
                [.. RuleEngine.CreateDefault().Rules, new SyntheticCriticalRule()])));
    };

    private static string[] CoreArgs(string dataDirectory, params string[] extra) =>
        [$"--SentinelAI:DataDirectory={dataDirectory}", .. extra];

    private static string[] CloudArgs(string privatePath, CoreIdentity identity, string credential) =>
    [
        "--SentinelAI:LicenseApi:KeyId=development-key",
        $"--SentinelAI:LicenseApi:SigningPrivateKeyPath={privatePath}",
        $"--SentinelAI:LicenseApi:Entitlements:0:OrganizationId={identity.OrganizationId:D}",
        $"--SentinelAI:LicenseApi:Entitlements:0:InstallationId={identity.CoreInstallationId:D}",
        $"--SentinelAI:LicenseApi:Entitlements:0:ActivationCredentialSha256={Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)))}",
        "--SentinelAI:LicenseApi:Entitlements:0:Plan=development-test",
        "--SentinelAI:LicenseApi:Entitlements:0:EndpointLimit=4",
        "--SentinelAI:LicenseApi:Entitlements:0:EnabledFeatures:0=inventory",
        "--SentinelAI:LicenseApi:Entitlements:0:EnabledFeatures:1=risk"
    ];

    private static async Task WriteProtectedFileAsync(string path, string content)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var stream = new FileStream(path, options);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(content);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        _assertions++;
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;
        private long _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _timestamp;
        public override DateTimeOffset GetUtcNow() => _utcNow;
        public void Advance(TimeSpan duration)
        {
            _utcNow = _utcNow.Add(duration);
            _timestamp = checked(_timestamp + duration.Ticks);
        }
    }

    // Current production rules have no critical-severity case. This isolated
    // fixture exercises critical alert retention through the real pipeline
    // without altering production rule severity or introducing future rules.
    private sealed class SyntheticCriticalRule : IEndpointRule
    {
        public string Id => CriticalRuleId;
        public string Title => "Synthetic critical monitoring observation";
        public string Severity => "critical";
        public SecurityAlert? Evaluate(EndpointState state) => state.IsWindows
            ? new SecurityAlert(Id, Title, Severity, "Synthetic development test observation.",
                [RuleEvidence.Boolean("syntheticCriticalObservation", true)], state.EndpointId, state.Timestamp,
                "Review the synthetic observation.")
            : null;
    }
}
