using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;

/// <summary>
/// TASK-032 Risk Register: validation, acceptance rules, versioned saves, auditable history, reviews, overdue flags,
/// filters, links and restart. Synthetic records, endpoints and alerts only.
/// </summary>
internal static class RiskRegisterApiTests
{
    public static async Task VerifyAsync(string username, string password)
    {
        var root = Path.Combine(Path.GetTempPath(), $"sentinelai-risk-register-tests-{Guid.NewGuid():N}");
        try
        {
            string[] arguments = [$"--SentinelAI:DataDirectory={root}"];
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            string Day(int days) => today.AddDays(days).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            Guid endpointId, alertId, mitigatedId, acceptedId;
            await using (var app = CoreHost.Build(arguments))
            {
                using var client = await StartAsync(app);
                try
                {
                    var token = await LoginAsync(client, username, password);
                    endpointId = await EnrollAsync(app);
                    alertId = await AddAlertAsync(app, endpointId);

                    using (var empty = await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register", token, null, HttpStatusCode.OK))
                    {
                        var page = empty!.RootElement;
                        Check(page.GetProperty("total").GetInt64() == 0 && page.GetProperty("today").GetString() == Day(0) &&
                              page.GetProperty("counts").GetProperty("needsAttention").GetInt32() == 0, "An empty register was not reported as empty.");
                    }

                    using (var unauthenticated = new HttpRequestMessage(HttpMethod.Get, "/api/admin/risk-register"))
                    using (var refused = await client.SendAsync(unauthenticated))
                        Check(refused.StatusCode == HttpStatusCode.Unauthorized, "The register answered without a session.");
                    foreach (var query in new[] { "?status=bogus", "?unknown=1", "?limit=0", "?limit=201", "?attention=yes", "?endpointId=1", "?level=low&level=high" })
                        await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register" + query, token, null, HttpStatusCode.BadRequest);

                    // Validation answers with field codes and changes nothing.
                    await ExpectErrorsAsync(client, token, Record(title: " ", likelihood: 0, status: "pending"),
                        ("title", "required"), ("likelihood", "range"), ("status", "invalid"));
                    await ExpectErrorsAsync(client, token, Record(treatment: "accept", reviewDate: Day(30)),
                        ("owner", "requiredForAcceptance"), ("acceptanceRationale", "required"), ("acceptanceExpiresOn", "required"));
                    await ExpectErrorsAsync(client, token, Record(treatment: "accept", owner: "Finance lead", rationale: "Legacy system.", expires: Day(367)),
                        ("acceptanceExpiresOn", "tooFar"));
                    await ExpectErrorsAsync(client, token, Record(treatment: "accept", owner: "Finance lead", rationale: "Legacy system.", expires: Day(0)),
                        ("acceptanceExpiresOn", "notFuture"));
                    await ExpectErrorsAsync(client, token, Record(treatment: "mitigate", rationale: "Not an acceptance."),
                        ("acceptanceRationale", "onlyForAcceptance"));
                    await ExpectErrorsAsync(client, token, Record(likelihood: 2, impact: 2, residualLikelihood: 3, residualImpact: 2), ("residual", "exceedsInherent"));
                    await ExpectErrorsAsync(client, token, Record(reviewDate: Day(-1)), ("reviewDate", "past"));
                    await ExpectErrorsAsync(client, token, Record(status: "open", reviewDate: ""), ("reviewDate", "required"));
                    await ExpectErrorsAsync(client, token, Record(status: "monitoring"), ("treatment", "required"));
                    await ExpectErrorsAsync(client, token, Record(endpoints: [Guid.NewGuid()]), ("endpointIds", "unknown"));
                    await ExpectErrorsAsync(client, token, Record(alerts: [Guid.NewGuid()]), ("alertIds", "unknown"));
                    await ExpectErrorsAsync(client, token, Record(tickets: ["INC-1", "INC-1"]), ("tickets", "duplicate"));
                    await ExpectErrorsAsync(client, token, Record(title: "Bad‮title"), ("title", "invalid"));

                    var scoreBefore = await TechnicalScoreAsync(client, token, endpointId);
                    var alertBefore = await AlertStateAsync(client, token, alertId);

                    // A mitigated risk linked to the endpoint, its alert and a ticket.
                    using (var created = await SendAsync(client, HttpMethod.Post, "/api/admin/risk-register", token,
                               Record(title: "Unpatched accounting server", treatment: "mitigate", owner: "IT administrator", endpoints: [endpointId],
                                   alerts: [alertId], tickets: ["INC-2041"], target: Day(10), reviewDate: Day(30), note: "Raised after the quarterly review."),
                               HttpStatusCode.Created))
                    {
                        var record = created!.RootElement;
                        mitigatedId = record.GetProperty("riskId").GetGuid();
                        var history = record.GetProperty("history");
                        Check(record.GetProperty("reference").GetString() == "R-0001" && record.GetProperty("version").GetInt64() == 1 &&
                              record.GetProperty("createdBy").GetString() == record.GetProperty("updatedBy").GetString() &&
                              record.GetProperty("inherent").GetProperty("score").GetInt32() == 12 &&
                              record.GetProperty("inherent").GetProperty("level").GetString() == "high" &&
                              record.GetProperty("residual").GetProperty("level").GetString() == "medium" &&
                              history.GetArrayLength() == 1 && history[0].GetProperty("action").GetString() == "created" &&
                              history[0].GetProperty("note").GetString() == "Raised after the quarterly review." &&
                              history[0].GetProperty("changes").EnumerateArray().Any(change => change.GetProperty("field").GetString() == "title"),
                            "A new risk did not get its reference, ratings and creation history.");
                        var endpoint = record.GetProperty("endpoints")[0];
                        var alert = record.GetProperty("alerts")[0];
                        Check(endpoint.GetProperty("enrolled").GetBoolean() && endpoint.GetProperty("name").GetString() is { Length: > 0 } &&
                              alert.GetProperty("exists").GetBoolean() && alert.GetProperty("ruleId").GetString() == "SA-TEST-RISK-001" &&
                              record.GetProperty("tickets")[0].GetString() == "INC-2041", "Links were not resolved to the endpoint and alert.");
                    }

                    // An accepted risk needs an owner, a rationale and an expiry, and is recorded as such.
                    using (var accepted = await SendAsync(client, HttpMethod.Post, "/api/admin/risk-register", token,
                               Record(title: "Legacy line-of-business application", treatment: "accept", owner: "Finance lead",
                                   rationale: "Vendor support ends next year; replacement is budgeted.", expires: Day(90), reviewDate: Day(60),
                                   endpoints: [endpointId]), HttpStatusCode.Created))
                    {
                        acceptedId = accepted!.RootElement.GetProperty("riskId").GetGuid();
                        Check(accepted.RootElement.GetProperty("reference").GetString() == "R-0002" &&
                              accepted.RootElement.GetProperty("acceptanceExpiresOn").GetString() == Day(90), "The accepted risk was not recorded.");
                    }

                    // Accepting or linking a business risk never changes detection, alerts or the technical score.
                    Check(await TechnicalScoreAsync(client, token, endpointId) == scoreBefore && await AlertStateAsync(client, token, alertId) == alertBefore,
                        "The Risk Register changed an alert or the technical endpoint score.");

                    // Versioned saves: a stale version is refused, a reviewed one recorded with its changes and note.
                    await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{mitigatedId:D}", token,
                        Update(2, Record(title: "Unpatched accounting server", treatment: "mitigate")), HttpStatusCode.Conflict);
                    using (var updated = await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{mitigatedId:D}", token,
                               Update(1, Record(title: "Unpatched accounting server", treatment: "mitigate", owner: "IT administrator", endpoints: [endpointId],
                                   alerts: [alertId], tickets: ["INC-2041"], target: Day(10), reviewDate: Day(30), residualLikelihood: 1,
                                   note: "Patch window agreed.")), HttpStatusCode.OK))
                    {
                        var record = updated!.RootElement;
                        var latest = record.GetProperty("history")[0];
                        Check(record.GetProperty("version").GetInt64() == 2 && latest.GetProperty("action").GetString() == "updated" &&
                              latest.GetProperty("note").GetString() == "Patch window agreed." &&
                              latest.GetProperty("changes").EnumerateArray().Select(change => (change.GetProperty("field").GetString(),
                                  change.GetProperty("from").GetString(), change.GetProperty("to").GetString())).SequenceEqual([("residualLikelihood", "2", "1")]),
                            "An update did not record exactly its change and note.");
                    }

                    using (var unchanged = await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{mitigatedId:D}", token,
                               Update(2, Record(title: "Unpatched accounting server", treatment: "mitigate", owner: "IT administrator", endpoints: [endpointId],
                                   alerts: [alertId], tickets: ["INC-2041"], target: Day(10), reviewDate: Day(30), residualLikelihood: 1)), HttpStatusCode.OK))
                        Check(unchanged!.RootElement.GetProperty("version").GetInt64() == 2, "A save without changes created a new version.");

                    // A review records who reviewed it and the next date.
                    await SendAsync(client, HttpMethod.Post, $"/api/admin/risk-register/{mitigatedId:D}/review", token,
                        Json(new { expectedVersion = 2, nextReviewDate = Day(0) }), HttpStatusCode.UnprocessableEntity);
                    using (var reviewed = await SendAsync(client, HttpMethod.Post, $"/api/admin/risk-register/{mitigatedId:D}/review", token,
                               Json(new { expectedVersion = 2, nextReviewDate = Day(45), note = "Controls verified." }), HttpStatusCode.OK))
                    {
                        var record = reviewed!.RootElement;
                        var latest = record.GetProperty("history")[0];
                        Check(record.GetProperty("version").GetInt64() == 3 && record.GetProperty("reviewDate").GetString() == Day(45) &&
                              record.GetProperty("lastReviewedBy").GetString() == record.GetProperty("createdBy").GetString() &&
                              latest.GetProperty("action").GetString() == "reviewed" && latest.GetProperty("note").GetString() == "Controls verified.",
                            "A review was not recorded.");
                    }

                    // Time passes: the accepted risk's review date and acceptance expire and become visible.
                    await AgeAsync(app, acceptedId, "2020-01-01", "2020-01-02");
                    using (var attention = await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register?attention=true", token, null, HttpStatusCode.OK))
                    {
                        var page = attention!.RootElement;
                        var flags = page.GetProperty("records")[0].GetProperty("flags");
                        Check(page.GetProperty("total").GetInt64() == 1 && page.GetProperty("records")[0].GetProperty("riskId").GetGuid() == acceptedId &&
                              flags.GetProperty("reviewOverdue").GetBoolean() && flags.GetProperty("acceptanceExpired").GetBoolean() &&
                              flags.GetProperty("needsAttention").GetBoolean() && page.GetProperty("counts").GetProperty("needsAttention").GetInt32() == 1,
                            "An expired acceptance and an overdue review were not visible.");
                    }

                    using (var all = await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register", token, null, HttpStatusCode.OK))
                        Check(all!.RootElement.GetProperty("records")[0].GetProperty("riskId").GetGuid() == acceptedId, "Records needing attention are not listed first.");
                    // Saving other fields keeps the lapsed dates visible; setting an acceptance date in the past is refused.
                    await ExpectErrorsAsync(client, token, Record(treatment: "accept", owner: "Finance lead", rationale: "Still needed.", expires: Day(-1)),
                        ("acceptanceExpiresOn", "notFuture"));
                    using (var kept = await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{acceptedId:D}", token,
                               Update(1, Record(title: "Legacy line-of-business application (v2)", treatment: "accept", owner: "Finance lead",
                                   rationale: "Vendor support ends next year; replacement is budgeted.", expires: "2020-01-02", reviewDate: "2020-01-01",
                                   endpoints: [endpointId])), HttpStatusCode.OK))
                        Check(kept!.RootElement.GetProperty("flags").GetProperty("acceptanceExpired").GetBoolean(), "Saving hid an expired acceptance.");

                    // Filters.
                    async Task<long> CountAsync(string query)
                    {
                        using var page = await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register" + query, token, null, HttpStatusCode.OK);
                        return page!.RootElement.GetProperty("total").GetInt64();
                    }

                    Check(await CountAsync("?treatment=accept") == 1 && await CountAsync("?treatment=none") == 0 && await CountAsync("?status=closed") == 0 &&
                          await CountAsync("?status=active") == 2 && await CountAsync($"?alertId={alertId:D}") == 1 &&
                          await CountAsync($"?endpointId={endpointId:D}") == 2 && await CountAsync($"?endpointId={Guid.NewGuid():D}") == 0 &&
                          await CountAsync("?level=medium") == 1 && await CountAsync("?limit=1&offset=1") == 2, "Register filters did not select the expected records.");

                    // Closing ends reviews; a closed record is not flagged.
                    using (var closed = await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{acceptedId:D}", token,
                               Update(2, Record(title: "Legacy line-of-business application (v2)", treatment: "avoid", status: "closed", reviewDate: "",
                                   endpoints: [endpointId], note: "Application retired.")), HttpStatusCode.OK))
                        Check(!closed!.RootElement.GetProperty("flags").GetProperty("needsAttention").GetBoolean(), "A closed record was still flagged.");
                    await SendAsync(client, HttpMethod.Post, $"/api/admin/risk-register/{acceptedId:D}/review", token,
                        Json(new { expectedVersion = 3, nextReviewDate = Day(30) }), HttpStatusCode.UnprocessableEntity);
                    await SendAsync(client, HttpMethod.Get, $"/api/admin/risk-register/{Guid.NewGuid():D}", token, null, HttpStatusCode.NotFound);
                    await SendAsync(client, HttpMethod.Put, $"/api/admin/risk-register/{Guid.NewGuid():D}", token, Update(1, Record()), HttpStatusCode.NotFound);
                }
                finally
                {
                    await app.StopAsync();
                }
            }

            // The register and its history survive a restart.
            await using (var app = CoreHost.Build(arguments))
            {
                using var client = await StartAsync(app);
                try
                {
                    var token = await LoginAsync(client, username, password);
                    using var detail = await SendAsync(client, HttpMethod.Get, $"/api/admin/risk-register/{acceptedId:D}", token, null, HttpStatusCode.OK);
                    var history = detail!.RootElement.GetProperty("history");
                    Check(detail.RootElement.GetProperty("status").GetString() == "closed" && history.GetArrayLength() == 3 &&
                          history.EnumerateArray().Select(entry => entry.GetProperty("version").GetInt64()).SequenceEqual([3L, 2, 1]),
                        "The register history did not survive a restart.");
                    using var page = await SendAsync(client, HttpMethod.Get, "/api/admin/risk-register", token, null, HttpStatusCode.OK);
                    Check(page!.RootElement.GetProperty("total").GetInt64() == 2, "Records were lost across a restart.");
                }
                finally
                {
                    await app.StopAsync();
                }
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }

        Console.WriteLine("Risk Register API tests passed (validation, acceptance, versions, history, reviews, overdue flags, filters, links, " +
                          "unchanged alerts and score, restart).");
    }

    private static string Record(string title = "Synthetic risk", string? description = "Synthetic description.", string? owner = null,
        int likelihood = 3, int impact = 4, string? controls = "Synthetic control.", int residualLikelihood = 2, int residualImpact = 3,
        string? treatment = null, string? rationale = null, string? expires = null, string? target = null, string? reviewDate = null,
        string status = "open", Guid[]? endpoints = null, Guid[]? alerts = null, string[]? tickets = null, string? note = null)
    {
        reviewDate ??= DateOnly.FromDateTime(DateTime.UtcNow).AddDays(30).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        return Json(new
        {
            title, description, owner, likelihood, impact, controls, residualLikelihood, residualImpact, treatment, acceptanceRationale = rationale,
            acceptanceExpiresOn = expires, targetDate = target, reviewDate = reviewDate.Length == 0 ? null : reviewDate, status,
            endpointIds = endpoints ?? [], alertIds = alerts ?? [], tickets = tickets ?? [], note
        });
    }

    private static string Update(long expectedVersion, string record) =>
        "{\"expectedVersion\":" + expectedVersion.ToString(CultureInfo.InvariantCulture) + ",\"record\":" + record + "}";

    private static string Json(object value) => JsonSerializer.Serialize(value);

    private static async Task ExpectErrorsAsync(HttpClient client, string token, string body, params (string Field, string Code)[] expected)
    {
        using var response = await SendAsync(client, HttpMethod.Post, "/api/admin/risk-register", token, body, HttpStatusCode.UnprocessableEntity);
        var errors = response!.RootElement.GetProperty("errors").EnumerateArray()
            .Select(error => (error.GetProperty("field").GetString()!, error.GetProperty("code").GetString()!)).ToArray();
        Check(expected.All(errors.Contains), "Expected validation errors " + string.Join(", ", expected) + " but got " + string.Join(", ", errors) + ".");
    }

    private static async Task<string> TechnicalScoreAsync(HttpClient client, string token, Guid endpointId)
    {
        using var risk = await SendAsync(client, HttpMethod.Get, $"/api/admin/devices/{endpointId:D}/risk", token, null, HttpStatusCode.OK);
        var score = risk!.RootElement.GetProperty("risk");
        return score.GetProperty("score").GetInt32().ToString(CultureInfo.InvariantCulture) + "/" + score.GetProperty("rawScore").GetDecimal()
            .ToString(CultureInfo.InvariantCulture) + "/" + score.GetProperty("contributions").GetArrayLength().ToString(CultureInfo.InvariantCulture);
    }

    private static async Task<string> AlertStateAsync(HttpClient client, string token, Guid alertId)
    {
        using var alert = await SendAsync(client, HttpMethod.Get, $"/api/admin/alerts/{alertId:D}", token, null, HttpStatusCode.OK);
        var root = alert!.RootElement;
        var summary = root.TryGetProperty("alert", out var nested) ? nested : root;
        return summary.GetProperty("status").GetString() + "/" + summary.GetProperty("version").GetInt64().ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Moves the stored review and acceptance dates into the past, as the passage of time would.</summary>
    private static async Task AgeAsync(WebApplication app, Guid riskId, string reviewDate, string acceptanceExpiresOn)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath, Mode = SqliteOpenMode.ReadWrite
        }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE RiskRegister SET RecordJson = json_set(RecordJson, '$.reviewDate', $review, '$.acceptanceExpiresOn', $expires) WHERE RiskId = $id;";
        command.Parameters.AddWithValue("$review", reviewDate);
        command.Parameters.AddWithValue("$expires", acceptanceExpiresOn);
        command.Parameters.AddWithValue("$id", riskId.ToString("D"));
        Check(await command.ExecuteNonQueryAsync() == 1, "The synthetic record could not be aged.");
    }

    /// <summary>A synthetic tracked alert for the endpoint, as the rule engines would record it.</summary>
    private static async Task<Guid> AddAlertAsync(WebApplication app, Guid endpointId)
    {
        var alertId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow.UtcTicks;
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = app.Services.GetRequiredService<AdminStore>().DatabasePath, Mode = SqliteOpenMode.ReadWrite, ForeignKeys = true
        }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO TrackedAlerts (AlertId, EndpointId, EndpointName, RuleId, Title, Severity, Status, FirstObservedUtcTicks, LastObservedUtcTicks,
                CreatedUtcTicks, UpdatedUtcTicks, StatusChangedUtcTicks, Version, Reason, EvidenceJson, RecommendedAction)
            VALUES ($alertId, $endpointId, 'synthetic-endpoint', 'SA-TEST-RISK-001', 'Synthetic finding', 'high', 'open', $now, $now, $now, $now, $now, 1,
                'Synthetic reason.', '[]', 'Synthetic action.');
            """;
        command.Parameters.AddWithValue("$alertId", alertId.ToString("D"));
        command.Parameters.AddWithValue("$endpointId", endpointId.ToString("D"));
        command.Parameters.AddWithValue("$now", now);
        await command.ExecuteNonQueryAsync();
        return alertId;
    }

    private static async Task<JsonDocument?> SendAsync(HttpClient client, HttpMethod method, string path, string token, string? body, HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        Check(response.StatusCode == expected, $"{method} {path} answered {(int)response.StatusCode}, expected {(int)expected}: {text}");
        return text.Length > 0 && response.Content.Headers.ContentType?.MediaType == "application/json" ? JsonDocument.Parse(text) : null;
    }

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30) };
    }

    private static async Task<Guid> EnrollAsync(WebApplication app)
    {
        var enrollments = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await enrollments.IssueTokenAsync();
        var enrollment = await enrollments.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        return (enrollment.Response ?? throw new InvalidOperationException("A synthetic endpoint could not enroll.")).EndpointId;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "The Risk Register test administrator could not log in.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
