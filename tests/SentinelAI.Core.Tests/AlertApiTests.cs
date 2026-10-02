using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

internal sealed record AlertApiTestState(InventoryReport LatestInventory, Guid AlertId, long FinalVersion);

internal static class AlertApiTests
{
    private const string ListPath = "/api/admin/alerts";

    public static async Task VerifyEmptyAsync(HttpClient client, string token)
    {
        var list = await ReadAsync(client, ListPath, token);
        Check(list.GetProperty("total").GetInt64() == 0 &&
              list.GetProperty("alerts").GetArrayLength() == 0 &&
              list.GetProperty("offset").GetInt32() == 0 &&
              list.GetProperty("limit").GetInt32() == 50,
            "Fresh Core did not return an empty, bounded alert list.");
    }

    public static async Task<AlertApiTestState> VerifyAsync(HttpClient client, WebApplication app,
        Guid endpointId, string credential, string token, InventoryReport original,
        string username, string password)
    {
        // TASK-007's preceding API checks submit a positive observation and then a
        // normal observation. The tracked alerts must retain that positive history.
        var list = await ReadAsync(client, ListPath, token);
        var endpointAlerts = ForEndpoint(list, endpointId);
        Check(endpointAlerts.Length == 2 && endpointAlerts.All(a => Status(a) == "open"),
            "Accepted risky inventory was not persisted, or normal inventory auto-resolved its alerts.");
        var selected = endpointAlerts.Single(a => a.GetProperty("ruleId").GetString() == "SA-FW-001");
        var alertId = selected.GetProperty("alertId").GetGuid();
        var path = $"{ListPath}/{alertId:D}";
        var initial = await ReadAsync(client, path, token);
        VerifyStructuredDetail(initial, endpointId, original.Hostname, credential, token);
        var firstObserved = initial.GetProperty("firstObservedUtc").GetDateTimeOffset();
        var created = initial.GetProperty("createdUtc").GetDateTimeOffset();
        var firstHistory = initial.GetProperty("statusHistory");
        Check(firstHistory.GetArrayLength() == 1 &&
              firstHistory[0].GetProperty("previousStatus").ValueKind == JsonValueKind.Null &&
              firstHistory[0].GetProperty("status").GetString() == "open" &&
              firstHistory[0].GetProperty("changedBy").GetString() == "system",
            "Initial alert creation did not retain its system audit event.");

        await VerifyAccessAsync(client, path, endpointId, credential, token, Version(initial));
        await VerifyInvalidRequestsAsync(client, path, token, Version(initial));

        var investigating = await UpdateAsync(client, path, token, "investigating", Version(initial));
        Check(Status(investigating) == "investigating" && Version(investigating) > Version(initial),
            "Administrator status update did not advance alert state.");
        var same = await UpdateAsync(client, path, token, "investigating", Version(investigating));
        Check(same.GetRawText() == investigating.GetRawText(),
            "An idempotent same-status update changed version, timestamp or audit history.");
        using (var conflict = await SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token,
                   new { status = "accepted", expectedVersion = Version(initial) }))
            Check(conflict.StatusCode == HttpStatusCode.Conflict,
                "A stale administrator update overwrote a newer status.");
        Check((await ReadAsync(client, path, token)).GetRawText() == investigating.GetRawText(),
            "A rejected stale update changed persisted state or audit history.");

        var risky = original with
        {
            Hostname = "task-008-synthetic-endpoint",
            CollectedUtc = original.CollectedUtc.AddTicks(1),
            SecurityPosture = new SecurityPostureInventory(false, true, true,
                new WindowsSecurityConfiguration(RdpEnabled: true,
                    RdpNetworkLevelAuthenticationRequired: false, LsaProtectionEnabled: false))
        };
        await UploadAsync(client, risky, credential);
        var observed = await ReadAsync(client, path, token);
        Check(Status(observed) == "investigating" &&
              observed.GetProperty("lastObservedUtc").GetDateTimeOffset() == risky.CollectedUtc &&
              observed.GetProperty("firstObservedUtc").GetDateTimeOffset() == firstObserved &&
              observed.GetProperty("createdUtc").GetDateTimeOffset() == created &&
              observed.GetProperty("statusHistory").GetArrayLength() == 2,
            "Repeated positive inventory lost initial timestamps or investigating status.");
        VerifyStructuredDetail(observed, endpointId, risky.Hostname, credential, token);
        await UploadAsync(client, risky, credential);
        await UploadAsync(client, original with
        {
            SecurityPosture = new SecurityPostureInventory(false, false, false)
        }, credential);
        Check((await ReadAsync(client, path, token)).GetRawText() == observed.GetRawText(),
            "Equal or older inventory replaced evidence, timestamps or lifecycle state.");

        await VerifyFiltersAsync(client, token, endpointId, alertId);
        var accepted = await UpdateAsync(client, path, token, "accepted", Version(observed));
        risky = risky with { CollectedUtc = risky.CollectedUtc.AddTicks(1) };
        await UploadAsync(client, risky, credential);
        accepted = await ReadAsync(client, path, token);
        Check(Status(accepted) == "accepted" &&
              accepted.GetProperty("statusHistory").GetArrayLength() == 3,
            "A repeated positive observation discarded the administrator's accepted decision.");

        var resolved = await UpdateAsync(client, path, token, "resolved", Version(accepted));
        await UploadAsync(client, risky, credential);
        await UploadAsync(client, risky with { CollectedUtc = original.CollectedUtc }, credential);
        Check((await ReadAsync(client, path, token)).GetRawText() == resolved.GetRawText(),
            "Equal or stale positive observations reopened a resolved alert.");
        risky = risky with { CollectedUtc = risky.CollectedUtc.AddTicks(1) };
        await UploadAsync(client, risky, credential);
        var reopened = await ReadAsync(client, path, token);
        Check(Status(reopened) == "open" && Version(reopened) > Version(resolved),
            "A strictly newer positive observation did not reopen a resolved alert.");
        var history = reopened.GetProperty("statusHistory");
        Check(history.GetArrayLength() == 5 &&
              history[4].GetProperty("previousStatus").GetString() == "resolved" &&
              history[4].GetProperty("status").GetString() == "open" &&
              history[4].GetProperty("changedBy").GetString() == "system",
            "Automatic reopen did not preserve the administrator lifecycle history.");
        foreach (var manual in history.EnumerateArray().Skip(1).Take(3))
            Check(manual.GetProperty("changedBy").GetString() == username,
                "A manual status audit event did not record the authenticated administrator.");

        var normal = original with { CollectedUtc = risky.CollectedUtc.AddTicks(1) };
        await UploadAsync(client, normal, credential);
        var unknown = normal with
        {
            CollectedUtc = normal.CollectedUtc.AddTicks(1),
            SecurityPosture = new SecurityPostureInventory(null, null, null)
        };
        await UploadAsync(client, unknown, credential);
        var afterNormalAndUnknown = await ReadAsync(client, path, token);
        Check(Status(afterNormalAndUnknown) == "open" &&
              Version(afterNormalAndUnknown) == Version(reopened) &&
              afterNormalAndUnknown.GetProperty("lastObservedUtc").GetDateTimeOffset() == risky.CollectedUtc &&
              afterNormalAndUnknown.GetProperty("statusHistory").GetArrayLength() == 5,
            "Normal or unknown inventory silently changed a tracked alert's lifecycle.");
        var final = await UpdateAsync(client, path, token, "accepted", Version(afterNormalAndUnknown));
        var finalList = await ReadAsync(client, ListPath, token);
        Check(ForEndpoint(finalList, endpointId).Length == 3 &&
              ForEndpoint(finalList, endpointId).Select(a => a.GetProperty("alertId").GetGuid()).Distinct().Count() == 3,
            "Repeated observations duplicated tracked endpoint/rule alerts.");

        await VerifyBackfillAsync(app.Services.GetRequiredService<AdminStore>().DatabasePath,
            username, password, risky);
        return new AlertApiTestState(unknown, alertId, Version(final));
    }

    public static async Task VerifyAfterRestartAsync(HttpClient client, string token, AlertApiTestState state)
    {
        var detail = await ReadAsync(client, $"{ListPath}/{state.AlertId:D}", token);
        Check(Status(detail) == "accepted" && Version(detail) == state.FinalVersion &&
              detail.GetProperty("statusHistory").GetArrayLength() == 6 &&
              detail.GetProperty("endpointId").GetGuid() == state.LatestInventory.EndpointId &&
              detail.GetProperty("evidence").GetArrayLength() > 0,
            "Core restart lost persisted evidence, status, version or administrator history.");
        var filtered = await ReadAsync(client, ListPath + "?status=accepted", token);
        Check(filtered.GetProperty("alerts").EnumerateArray()
                  .Any(a => a.GetProperty("alertId").GetGuid() == state.AlertId),
            "Persisted accepted alert was missing from the filtered list after restart.");
    }

    public static async Task VerifyRemoteHttpAsync(HttpClient client, string token, Guid alertId)
    {
        foreach (var path in new[] { ListPath, $"{ListPath}/{alertId:D}" })
        {
            using var response = await SendAsync(client, HttpMethod.Get, path, "Bearer", token);
            Check(response.StatusCode == HttpStatusCode.Forbidden,
                "Core exposed tracked alert information over remote HTTP.");
        }
        using var update = await SendAsync(client, HttpMethod.Put, $"{ListPath}/{alertId:D}/status",
            "Bearer", token, new { status = "resolved", expectedVersion = 1 });
        Check(update.StatusCode == HttpStatusCode.Forbidden,
            "Core accepted a tracked alert status update over remote HTTP.");
    }

    private static async Task VerifyAccessAsync(HttpClient client, string path, Guid endpointId,
        string credential, string token, long version)
    {
        foreach (var scheme in new[] { "", "SentinelAgent" })
        {
            var authorization = scheme == "" ? "" : $"{endpointId:D}.{credential}";
            foreach (var read in new[] { ListPath, path })
            {
                using var response = await SendAsync(client, HttpMethod.Get, read, scheme, authorization);
                Check(response.StatusCode == HttpStatusCode.Unauthorized,
                    "Anonymous or Agent credentials permitted an administrator alert read.");
            }
            using var mutation = await SendAsync(client, HttpMethod.Put, path + "/status", scheme,
                authorization, new { status = "resolved", expectedVersion = version });
            Check(mutation.StatusCode == HttpStatusCode.Unauthorized,
                "Anonymous or Agent credentials permitted an administrator alert update.");
        }
        var missing = $"{ListPath}/{Guid.NewGuid():D}";
        using (var read = await SendAsync(client, HttpMethod.Get, missing, "Bearer", token))
            Check(read.StatusCode == HttpStatusCode.NotFound, "Unknown alert detail did not return 404.");
        using (var update = await SendAsync(client, HttpMethod.Put, missing + "/status", "Bearer", token,
                   new { status = "resolved", expectedVersion = 1 }))
            Check(update.StatusCode == HttpStatusCode.NotFound, "Unknown alert status update did not return 404.");
    }

    private static async Task VerifyInvalidRequestsAsync(HttpClient client, string path, string token, long version)
    {
        foreach (var query in new[]
                 {
                     "severity=invalid", "status=closed", "offset=-1", "offset=text", "limit=0",
                     "limit=201", "limit=text"
                 })
        {
            using var response = await SendAsync(client, HttpMethod.Get, ListPath + "?" + query, "Bearer", token);
            Check(response.StatusCode == HttpStatusCode.BadRequest, $"Invalid alert filter/paging accepted: {query}.");
        }
        foreach (var body in new object[]
                 {
                     new { status = "closed", expectedVersion = version },
                     new { status = "", expectedVersion = version },
                     new { status = (string?)null, expectedVersion = version },
                     new { status = "resolved", expectedVersion = 0 },
                     new { status = "resolved", expectedVersion = -1 },
                     new { status = "resolved" }
                 })
        {
            using var response = await SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token, body);
            Check(response.StatusCode == HttpStatusCode.BadRequest, "Invalid alert status/version update accepted.");
        }
        using var request = new HttpRequestMessage(HttpMethod.Put, path + "/status")
        {
            Content = new StringContent("{", Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var malformed = await client.SendAsync(request);
        Check(malformed.StatusCode == HttpStatusCode.BadRequest, "Malformed alert status JSON accepted.");
    }

    private static async Task VerifyFiltersAsync(HttpClient client, string token, Guid endpointId, Guid alertId)
    {
        var medium = await ReadAsync(client, ListPath + "?severity=medium&status=open", token);
        Check(medium.GetProperty("alerts").EnumerateArray().All(a =>
                  a.GetProperty("severity").GetString() == "medium" && Status(a) == "open") &&
              ForEndpoint(medium, endpointId).Length == 1,
            "Severity/status filters did not match the persisted medium finding.");
        var investigating = await ReadAsync(client, ListPath + "?severity=high&status=investigating", token);
        Check(investigating.GetProperty("total").GetInt64() == 1 &&
              investigating.GetProperty("alerts")[0].GetProperty("alertId").GetGuid() == alertId,
            "Combined alert filters included unrelated statuses/severities.");
        var empty = await ReadAsync(client, ListPath + "?severity=critical", token);
        Check(empty.GetProperty("total").GetInt64() == 0 && empty.GetProperty("alerts").GetArrayLength() == 0,
            "An unmatched severity filter did not return an empty list.");
        var all = await ReadAsync(client, ListPath, token);
        var first = await ReadAsync(client, ListPath + "?offset=0&limit=1", token);
        var second = await ReadAsync(client, ListPath + "?offset=1&limit=1", token);
        Check(first.GetProperty("alerts").GetArrayLength() == 1 &&
              second.GetProperty("alerts").GetArrayLength() == 1 &&
              first.GetProperty("total").GetInt64() == all.GetProperty("total").GetInt64() &&
              second.GetProperty("offset").GetInt32() == 1 && second.GetProperty("limit").GetInt32() == 1 &&
              first.GetProperty("alerts")[0].GetProperty("alertId").GetGuid() !=
              second.GetProperty("alerts")[0].GetProperty("alertId").GetGuid(),
            "Alert pagination duplicated rows or reported an incorrect total/bound.");
        var pastEnd = await ReadAsync(client, ListPath + "?offset=100&limit=200", token);
        Check(pastEnd.GetProperty("alerts").GetArrayLength() == 0 &&
              pastEnd.GetProperty("total").GetInt64() == all.GetProperty("total").GetInt64(),
            "A page past the end lost the unpaged total or returned records.");
    }

    private static void VerifyStructuredDetail(JsonElement detail, Guid endpointId, string name,
        string credential, string token)
    {
        foreach (var field in new[] { "ruleId", "title", "severity", "reason", "recommendedAction", "status" })
            Check(!string.IsNullOrWhiteSpace(detail.GetProperty(field).GetString()), $"Tracked alert lacks {field}.");
        Check(detail.GetProperty("alertId").GetGuid() != Guid.Empty &&
              detail.GetProperty("endpointId").GetGuid() == endpointId &&
              detail.GetProperty("endpointName").GetString() == name && Version(detail) > 0,
            "Tracked alert lost its identity or current endpoint relationship.");
        foreach (var field in new[] { "firstObservedUtc", "lastObservedUtc", "updatedUtc", "createdUtc", "statusChangedUtc" })
            Check(detail.GetProperty(field).GetDateTimeOffset().Offset == TimeSpan.Zero,
                $"Tracked alert's {field} was not a UTC timestamp.");
        var evidence = detail.GetProperty("evidence");
        Check(evidence.GetArrayLength() == 1 &&
              evidence[0].GetProperty("field").GetString() == "securityPosture.domainFirewallEnabled" &&
              evidence[0].GetProperty("value").ValueKind == JsonValueKind.False,
            "Tracked firewall evidence did not preserve its typed observed false value.");
        Check(!detail.GetRawText().Contains(credential, StringComparison.Ordinal) &&
              !detail.GetRawText().Contains(token, StringComparison.Ordinal),
            "Alert data or status history exposed authentication credentials.");
    }

    private static async Task VerifyBackfillAsync(string sourceDatabase, string username,
        string password, InventoryReport risky)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sentinelai-alert-migration-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var database = Path.Combine(directory, "sentinelai.db");
        try
        {
            // Copy only synthetic test data. Removing the new tables simulates the
            // actual TASK-007 schema without altering the primary test database.
            await using (var source = new SqliteConnection($"Data Source={sourceDatabase}"))
            await using (var destination = new SqliteConnection($"Data Source={database}"))
            {
                await source.OpenAsync();
                await destination.OpenAsync();
                source.BackupDatabase(destination);
                await using var seed = destination.CreateCommand();
                seed.CommandText = """
                    DROP TABLE IF EXISTS AlertStatusHistory;
                    DROP TABLE IF EXISTS TrackedAlerts;
                    DELETE FROM EndpointInventories;
                    INSERT INTO EndpointInventories (EndpointId,CollectedUtcTicks,ReportJson)
                    VALUES ($endpointId,$ticks,$report);
                    """;
                seed.Parameters.AddWithValue("$endpointId", risky.EndpointId.ToString("D"));
                seed.Parameters.AddWithValue("$ticks", risky.CollectedUtc.UtcDateTime.Ticks);
                seed.Parameters.AddWithValue("$report", JsonSerializer.Serialize(risky));
                await seed.ExecuteNonQueryAsync();
            }
            string? previous = null;
            for (var restart = 0; restart < 2; restart++)
            {
                await using var app = CoreHost.Build([$"--SentinelAI:DataDirectory={directory}"]);
                app.Urls.Clear();
                app.Urls.Add("http://127.0.0.1:0");
                await app.StartAsync();
                using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
                {
                    BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(10)
                };
                using var login = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
                Check(login.StatusCode == HttpStatusCode.OK, "Migrated Core could not authenticate its persisted administrator.");
                using var auth = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
                var token = auth.RootElement.GetProperty("accessToken").GetString()!;
                var list = await ReadAsync(client, ListPath, token);
                Check(list.GetProperty("total").GetInt64() == 3 && ForEndpoint(list, risky.EndpointId).Length == 3,
                    "Existing TASK-007 inventory was not backfilled into persisted alerts.");
                var firstId = list.GetProperty("alerts")[0].GetProperty("alertId").GetGuid();
                var detail = await ReadAsync(client, $"{ListPath}/{firstId:D}", token);
                Check(detail.GetProperty("firstObservedUtc").GetDateTimeOffset() == risky.CollectedUtc &&
                      detail.GetProperty("statusHistory").GetArrayLength() == 1,
                    "Inventory backfill lost observation time or duplicated initial status history.");
                var current = list.GetRawText() + detail.GetRawText();
                Check(previous is null || current == previous,
                    "Repeated Core startup duplicated or changed backfilled alerts.");
                previous = current;
                if (restart == 0)
                    await VerifyAtomicPersistenceAsync(app, client, token, database, risky, list);
                else
                    await VerifyConcurrentUpdatesAsync(client, token, firstId, detail);
                await app.StopAsync();
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task VerifyAtomicPersistenceAsync(WebApplication app, HttpClient client,
        string token, string database, InventoryReport previousInventory, JsonElement previousList)
    {
        await using var connection = new SqliteConnection($"Data Source={database}");
        await connection.OpenAsync();
        await using (var trigger = connection.CreateCommand())
        {
            trigger.CommandText = """
                CREATE TRIGGER FailTestAlertHistory BEFORE INSERT ON AlertStatusHistory
                BEGIN SELECT RAISE(ABORT, 'Synthetic alert persistence failure'); END;
                """;
            await trigger.ExecuteNonQueryAsync();
        }
        try
        {
            var inventories = app.Services.GetRequiredService<InventoryStore>();
            var report = previousInventory with
            {
                CollectedUtc = previousInventory.CollectedUtc.AddTicks(1),
                SecurityPosture = previousInventory.SecurityPosture with { PrivateFirewallEnabled = false }
            };
            var failed = false;
            try
            {
                await inventories.RecordLatestAsync(report);
            }
            catch (SqliteException)
            {
                failed = true;
            }
            Check(failed, "Synthetic history persistence failure did not abort inventory ingestion.");
            var stored = await inventories.FindLatestAsync(report.EndpointId);
            Check(stored?.CollectedUtc == previousInventory.CollectedUtc &&
                  stored.SecurityPosture.PrivateFirewallEnabled == true &&
                  (await ReadAsync(client, ListPath, token)).GetRawText() == previousList.GetRawText(),
                "Failed alert persistence committed partial inventory or alert changes.");
        }
        finally
        {
            await using var drop = connection.CreateCommand();
            drop.CommandText = "DROP TRIGGER FailTestAlertHistory;";
            await drop.ExecuteNonQueryAsync();
        }
    }

    private static async Task VerifyConcurrentUpdatesAsync(HttpClient client, string token,
        Guid alertId, JsonElement previous)
    {
        var path = $"{ListPath}/{alertId:D}";
        var responses = await Task.WhenAll(
            SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token,
                new { status = "investigating", expectedVersion = Version(previous) }),
            SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token,
                new { status = "accepted", expectedVersion = Version(previous) }));
        try
        {
            Check(responses.Count(r => r.StatusCode == HttpStatusCode.OK) == 1 &&
                  responses.Count(r => r.StatusCode == HttpStatusCode.Conflict) == 1,
                "Concurrent administrator status updates did not choose exactly one version winner.");
            var detail = await ReadAsync(client, path, token);
            Check(Version(detail) == Version(previous) + 1 &&
                  detail.GetProperty("statusHistory").GetArrayLength() == 2,
                "A rejected concurrent administrator update created extra state or audit history.");
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    private static JsonElement[] ForEndpoint(JsonElement list, Guid endpointId) =>
        list.GetProperty("alerts").EnumerateArray()
            .Where(a => a.GetProperty("endpointId").GetGuid() == endpointId).ToArray();

    private static string? Status(JsonElement detail) => detail.GetProperty("status").GetString();
    private static long Version(JsonElement detail) => detail.GetProperty("version").GetInt64();

    private static async Task<JsonElement> ReadAsync(HttpClient client, string path, string token)
    {
        using var response = await SendAsync(client, HttpMethod.Get, path, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            $"Administrator alert read unavailable or cacheable: {path}, {response.StatusCode}.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.Clone();
    }

    private static async Task<JsonElement> UpdateAsync(HttpClient client, string path, string token,
        string status, long version)
    {
        using var response = await SendAsync(client, HttpMethod.Put, path + "/status", "Bearer", token,
            new { status, expectedVersion = version });
        Check(response.StatusCode == HttpStatusCode.OK && response.Headers.CacheControl?.NoStore == true,
            $"Valid administrator status update unavailable or cacheable: {status}, {response.StatusCode}.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.Clone();
    }

    private static async Task UploadAsync(HttpClient client, InventoryReport report, string credential)
    {
        using var response = await SendAsync(client, HttpMethod.Post, "/api/agent/inventory", "SentinelAgent",
            $"{report.EndpointId:D}.{credential}", report);
        Check(response.StatusCode == HttpStatusCode.NoContent,
            $"Authenticated test inventory rejected: {response.StatusCode}.");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method,
        string path, string scheme, string credential, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (!string.IsNullOrEmpty(scheme))
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, credential);
        if (body is not null) request.Content = JsonContent.Create(body);
        return await client.SendAsync(request);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
