using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Contracts.Ai;
using SentinelAI.Contracts.Enrollment;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core;
using SentinelAI.Core.Persistence;
using SentinelAI.Core.Reports;

internal static class ReportApiTests
{
    private const string PathRoot = "/api/admin/reports/security";
    private const string PeriodPath = PathRoot + "?from=2026-09-01&to=2026-09-30";
    private const string HostileName = "synthetic-report-<img src=x onerror=alert(1)>";
    private const string PrivateText = "synthetic-report-private-evidence";
    private const string PrivateActor = "synthetic-report-private-actor";
    private const string PrivateLease = "synthetic-report-private-lease";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-02T12:00:00Z", CultureInfo.InvariantCulture);
    private static readonly ReportPeriod September = new(new DateOnly(2026, 9, 1), new DateOnly(2026, 9, 30));
    private static int assertions;

    public static async Task VerifyAsync(string username, string password)
    {
        VerifyPeriods();
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"sentinelai-report-tests-{Guid.NewGuid():N}");
        string persistedHtml;
        var offline = new OfflineGateway();
        try
        {
            await using (var app = Build(directory, offline))
            {
                using var client = await StartAsync(app);
                var token = await LoginAsync(client, username, password);
                await VerifyEmptyAsync(app, client, token);
                await VerifyQueryValidationAsync(client, token);
                var risky = await EnrollAsync(app);
                await VerifyAccessAsync(client, token, risky);
                var missing = await EnrollAsync(app);
                var warning = await EnrollAsync(app);
                var offlineEndpoint = await EnrollAsync(app);
                await UploadAsync(client, risky, Inventory(risky.EndpointId) with
                {
                    Hostname = HostileName,
                    SecurityPosture = new(false, false, false, new WindowsSecurityConfiguration(
                        UacEnabled: true, AdminConsentPromptBehavior: 5, RdpEnabled: false,
                        Smb1ServerEnabled: false, SmbInsecureGuestLogonsAllowed: false,
                        AutomaticAdminLogonEnabled: true, LsaProtectionEnabled: false, AutomaticUpdatesDisabled: true))
                });
                await UploadAsync(client, warning, Inventory(warning.EndpointId) with
                {
                    Hostname = "synthetic-partial-posture", SecurityPosture = new(true, null, null)
                });
                // A newer normal snapshot retains the tracked incidents, while startup backfill
                // cannot replace their older evidence/history with a fresh positive observation.
                await UploadAsync(client, risky, Inventory(risky.EndpointId) with
                {
                    Hostname = HostileName, CollectedUtc = Now.AddHours(-1).AddTicks(1)
                });
                var admins = app.Services.GetRequiredService<AdminStore>();
                await SeedChronologyAsync(admins.DatabasePath, risky.EndpointId);
                await SeedHeartbeatAsync(admins.DatabasePath, risky.EndpointId, Now.AddMinutes(-1));
                await SeedHeartbeatAsync(admins.DatabasePath, warning.EndpointId, Now.AddMinutes(-3));
                await SeedHeartbeatAsync(admins.DatabasePath, offlineEndpoint.EndpointId, Now.AddMinutes(-6));
                await SeedLeaseAsync(admins.DatabasePath);

                // The deliberately invalid synthetic lease leaves Core in Safe Mode.
                using (var license = await ReadAsync(client, "/api/admin/license", token))
                    Check(license.RootElement.GetProperty("mode").GetString() == "SAFE_MODE",
                        "The local report fixture did not exercise Safe Mode.");

                var report = await app.Services.GetRequiredService<SecurityReportReadStore>().GenerateAsync(September);
                VerifyStoredActivity(report);
                Check(report.Endpoints.Count == 4 && report.Health == new ReportHealthSummary(1, 1, 1, 1),
                    "Report health did not evaluate enrolled endpoint heartbeats at the single injected UTC time.");
                Check(report.Endpoints.Single(endpoint => endpoint.EndpointId == missing.EndpointId)
                        .CurrentRisk.Coverage.InventoryState == "missing" &&
                      report.Endpoints.Single(endpoint => endpoint.EndpointId == warning.EndpointId)
                        .CurrentRisk.Coverage.SignalCoverage == "partial",
                    "Report hid absent or partially observed inventory behind a zero score.");
                await VerifyRiskConsistencyAsync(client, token, report);
                VerifyEvidence(report);
                persistedHtml = await DownloadAsync(client, token);
                VerifyContent(persistedHtml);
                var passwordHash = await ScalarAsync(admins.DatabasePath,
                    "SELECT PasswordHash FROM Administrators LIMIT 1;");
                foreach (var secret in new[] { username, password, token, risky.AgentCredential, passwordHash,
                             PrivateLease, PrivateActor, PrivateText, "SentinelAI:Ai", "CredentialHash", "PasswordHash" })
                    Check(!persistedHtml.Contains(secret, StringComparison.Ordinal), "Report included a private field or credential.");
                Check(!persistedHtml.Contains("<img", StringComparison.OrdinalIgnoreCase) &&
                      persistedHtml.Contains("&lt;img", StringComparison.Ordinal),
                    "An endpoint name was emitted as executable HTML instead of escaped text.");

                var culture = CultureInfo.CurrentCulture;
                var uiCulture = CultureInfo.CurrentUICulture;
                try
                {
                    foreach (var name in new[] { "pl-PL", "ar-SA" })
                    {
                        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
                        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
                        var repeated = await app.Services.GetRequiredService<SecurityReportReadStore>().GenerateAsync(September);
                        Check(SecurityReportRenderer.Render(repeated) == persistedHtml,
                            "Report output depended on culture or introduced nondeterministic content.");
                    }
                }
                finally
                {
                    CultureInfo.CurrentCulture = culture;
                    CultureInfo.CurrentUICulture = uiCulture;
                }
                Check(await DownloadAsync(client, token) == persistedHtml, "Repeated report generation changed fixed-state output.");
                Check(offline.Requests == 0, "Local reporting called cloud AI.");
                await app.StopAsync();
            }

            await using (var restarted = Build(directory, offline))
            {
                using var client = await StartAsync(restarted);
                var token = await LoginAsync(client, username, password);
                Check(await DownloadAsync(client, token) == persistedHtml,
                    "Restart changed report bytes derived from the same persisted SentinelAI state and UTC time.");
                await VerifyCapacityAsync(restarted, client, token);
                await restarted.StopAsync();
            }
            await VerifyRemoteHttpAsync(directory, username, password, offline);
            Check(offline.Requests == 0, "Report generation used an AI request during offline verification.");
            Console.WriteLine($"Report API tests passed ({assertions} assertions, stored chronology, offline Safe Mode, HTML safety, deterministic restart and access boundaries).");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static void VerifyPeriods()
    {
        Check(ReportPeriod.TryParse("2024-02-29", "2024-02-29", out var leap) &&
              leap!.EndExclusiveUtc - leap.StartUtc == TimeSpan.FromDays(1), "A one-day leap-date report was rejected.");
        Check(ReportPeriod.TryParse("2024-01-01", "2024-12-31", out _), "The permitted 366-day range was rejected.");
        foreach (var (from, to) in new (string?, string?)[]
        {
            (null, "2026-09-30"), ("", "2026-09-30"), ("2026-9-01", "2026-09-30"),
            (" 2026-09-01", "2026-09-30"), ("2026-09-01", "2026-09-31"),
            ("2026-09-01T00:00:00Z", "2026-09-30"), ("2026-10-01", "2026-09-30"),
            ("2024-01-01", "2025-01-01"), ("9999-12-31", "9999-12-31")
        }) Check(!ReportPeriod.TryParse(from, to, out _), "Report accepted an ambiguous, invalid or unbounded date range.");
    }

    private static async Task VerifyEmptyAsync(WebApplication app, HttpClient client, string token)
    {
        var report = await app.Services.GetRequiredService<SecurityReportReadStore>().GenerateAsync(September);
        Check(report.Endpoints.Count == 0 && report.OrganizationRisk.Score == 0 && report.Activity.AssociatedAlertCount == 0 &&
              report.Activity.ResolvedAlertCount == 0 && report.PriorityActions.Count == 0,
            "An empty installation fabricated security observations, incidents or priority actions.");
        var html = await DownloadAsync(client, token);
        Check(html.Contains("2026-09-01", StringComparison.Ordinal) && html.Contains("2026-09-30", StringComparison.Ordinal) &&
              html.Contains("historical risk scores are not stored", StringComparison.Ordinal),
            "An empty report concealed its period or fabricated a historical score trend.");
    }

    private static async Task VerifyQueryValidationAsync(HttpClient client, string token)
    {
        foreach (var query in new[]
        {
            "", "?from=2026-09-01", "?to=2026-09-30", "?from=2026-09-01&to=2026-09-31",
            "?from=2026-10-01&to=2026-09-30", "?from=2024-01-01&to=2025-01-01",
            "?from=2026-09-01&to=2026-09-30&from=2026-09-02",
            "?from=2026-09-01&to=2026-09-30&to=2026-09-29",
            "?from=2026-09-01&to=2026-09-30&format=html",
            "?From=2026-09-01&to=2026-09-30", "?from=2026-9-1&to=2026-09-30"
        })
        {
            using var response = await SendAsync(client, PathRoot + query, "Bearer", token);
            Check(response.StatusCode == HttpStatusCode.BadRequest, "Report endpoint accepted an invalid or duplicate range parameter.");
        }
    }

    private static async Task VerifyAccessAsync(HttpClient client, string token, EnrollmentResponse agent)
    {
        using (var anonymous = await client.GetAsync(PeriodPath))
            Check(anonymous.StatusCode == HttpStatusCode.Unauthorized, "Anonymous access generated a security report.");
        using (var unauthenticated = await SendAsync(client, PeriodPath, "Bearer", "synthetic-invalid-administrator-token"))
            Check(unauthenticated.StatusCode == HttpStatusCode.Unauthorized, "An invalid administrator token generated a report.");
        using (var credential = await SendAsync(client, PeriodPath, "SentinelAgent", $"{agent.EndpointId:D}.{agent.AgentCredential}"))
            Check(credential.StatusCode == HttpStatusCode.Unauthorized, "An Agent credential crossed the administrator report boundary.");
        using var allowed = await SendAsync(client, PeriodPath, "Bearer", token);
        Check(allowed.StatusCode == HttpStatusCode.OK, "An authenticated local administrator could not generate a report.");
    }

    private static void VerifyStoredActivity(SecurityReport report)
    {
        Check(report.GeneratedAtUtc == Now && report.Period == September,
            "The report did not use the requested period and single configured evaluation time.");
        Check(report.Activity.AssociatedAlertCount == 4 && report.Activity.NewAlertCount == 2 &&
              report.Activity.ResolvedAlertCount == 1,
            "Period counts lost boundary observations or confused current status with period resolution history.");
        Check(report.Activity.SeverityCounts.Single(item => item.Severity == "critical") is
                { AssociatedAlerts: 1, NewAlerts: 1 } &&
              report.Activity.SeverityCounts.Single(item => item.Severity == "high") is
                { AssociatedAlerts: 3, NewAlerts: 1 },
            "The report did not count stored severity consistently across associated and newly observed incidents.");
        var newIncident = report.PeriodIncidents.Single(item => item.RuleId == "SA-FW-001");
        Check(newIncident.FirstObservedInPeriod && !newIncident.LastObservedInPeriod && newIncident.LastObservedUtc > September.EndExclusiveUtc,
            "A newly observed incident disappeared when its latest observation was outside the reporting period.");
        var lastTick = report.PeriodIncidents.Single(item => item.RuleId == "SA-UPDATE-001");
        Check(lastTick.FirstObservedUtc == September.EndExclusiveUtc.AddTicks(-1) && lastTick.FirstObservedInPeriod,
            "The inclusive final UTC calendar day was not included.");
        var oldIncident = report.PeriodIncidents.Single(item => item.RuleId == "SA-FW-002");
        Check(!oldIncident.FirstObservedInPeriod && oldIncident.LastObservedInPeriod,
            "An old incident with its latest observation in the period was counted as newly observed.");
        Check(report.PeriodIncidents.All(item => item.RuleId is not ("SA-FW-003" or "SA-LSA-001")),
            "Period association included an incident wholly outside the selected UTC dates.");
        var resolved = report.PeriodIncidents.Single(item => item.RuleId == "SA-LOGON-001");
        Check(resolved.ResolutionsInPeriod == 2 && resolved.ReopenedAfterPeriodResolution &&
              resolved.CurrentStatus == "open" && resolved.StatusChangesInPeriod == 3,
            "The report truncated old history or treated a reopened incident as currently resolved.");
        Check(report.MajorPostureFindings.Any(item => item.RuleId == "SA-FW-003") && report.PriorityActions.Count > 0,
            "Current posture and recommended actions incorrectly reused only period-associated findings.");
    }

    private static async Task VerifyRiskConsistencyAsync(HttpClient client, string token, SecurityReport report)
    {
        using var organization = await ReadAsync(client, "/api/admin/risk", token);
        Check(organization.RootElement.GetProperty("organization").GetProperty("score").GetInt32() == report.OrganizationRisk.Score,
            "Report organization risk diverged from the existing deterministic current-risk API.");
        foreach (var endpoint in report.Endpoints)
        {
            using var detail = await ReadAsync(client, $"/api/admin/devices/{endpoint.EndpointId:D}/risk", token);
            var risk = detail.RootElement.GetProperty("risk");
            Check(risk.GetProperty("score").GetInt32() == endpoint.CurrentRisk.Risk.Score &&
                  risk.GetProperty("rawScore").GetDecimal() == endpoint.CurrentRisk.Risk.RawScore,
                "Report endpoint risk changed the scoring policy or used the period end as a historical evaluation time.");
        }
    }

    private static void VerifyEvidence(SecurityReport report)
    {
        var domain = report.PeriodIncidents.Single(item => item.RuleId == "SA-FW-001");
        Check(domain.Evidence.Count == 1 && domain.Evidence[0].Field == "securityPosture.domainFirewallEnabled" &&
              domain.Evidence[0].Value.ValueKind == JsonValueKind.False,
            "The report lost supported technical evidence or exported arbitrary raw evidence fields.");
        Check(report.PeriodIncidents.Single(item => item.RuleId == "SA-FW-002").Evidence.Count == 0 &&
              report.MajorPostureFindings.Single(item => item.RuleId == "SA-FW-003").Evidence.Count == 0,
            "Malformed or ambiguous duplicate evidence was exported as a supported configuration value.");
        foreach (var finding in report.PeriodIncidents.Concat(report.MajorPostureFindings))
            Check(!finding.Title.Contains(PrivateText, StringComparison.Ordinal) &&
                  !finding.Reason.Contains(PrivateText, StringComparison.Ordinal) &&
                  !finding.RecommendedAction.Contains(PrivateText, StringComparison.Ordinal) &&
                  finding.Evidence.All(item => item.Value.ValueKind is JsonValueKind.True or JsonValueKind.False ||
                      item.Value.ValueKind == JsonValueKind.Number && item.Value.TryGetInt32(out var number) && number is >= 0 and <= 5),
                "Report projection copied arbitrary stored text or unbounded evidence into a shareable artifact.");
    }

    private static void VerifyContent(string html)
    {
        foreach (var text in new[]
        {
            "Management summary", "Retained activity in the selected UTC period", "Current endpoint health and risk",
            "Critical/high incidents associated with the period", "Incidents resolved during the period",
            "Current major security posture findings", "Recommended priority actions", "SA-FW-001", "SA-LOGON-001",
            "historical risk scores are not stored", "evaluated at report generation", "historical state"
        }) Check(html.Contains(text, StringComparison.Ordinal), "Report omitted required content or a material current/historical limitation: " + text);
        Check(!html.Contains("<script", StringComparison.OrdinalIgnoreCase) &&
              !html.Contains("https://", StringComparison.OrdinalIgnoreCase) && !html.Contains("http://", StringComparison.OrdinalIgnoreCase),
            "The offline report included executable code or an external resource dependency.");
    }

    private static async Task<string> DownloadAsync(HttpClient client, string token)
    {
        using var response = await SendAsync(client, PeriodPath, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.OK, "Report download failed: " + response.StatusCode);
        Check(response.Content.Headers.ContentType?.MediaType == "text/html" &&
              response.Content.Headers.ContentDisposition?.DispositionType == "attachment" &&
              (response.Content.Headers.ContentDisposition.FileNameStar ?? response.Content.Headers.ContentDisposition.FileName?.Trim('"')) ==
                "SentinelAI-security-report-2026-09-01-2026-09-30.html",
            "Report did not return a bounded-date HTML download attachment.");
        Check(response.Headers.CacheControl?.NoStore == true && response.Headers.GetValues("X-Content-Type-Options").Single() == "nosniff" &&
              response.Headers.GetValues("Content-Security-Policy").Single().Contains("script-src 'none'", StringComparison.Ordinal),
            "Report download lost no-store, nosniff or static-content execution restrictions.");
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task SeedChronologyAsync(string database, Guid endpointId)
    {
        await using var connection = Connection(database);
        await connection.OpenAsync();
        using var transaction = connection.BeginTransaction();
        var timelines = new[]
        {
            ("SA-FW-001", September.StartUtc, Now.AddHours(-1)),
            ("SA-FW-002", September.StartUtc.AddTicks(-1), September.EndExclusiveUtc.AddTicks(-1)),
            ("SA-FW-003", September.EndExclusiveUtc, Now.AddHours(-1)),
            ("SA-LOGON-001", September.StartUtc.AddDays(-27), September.StartUtc.AddDays(-26)),
            ("SA-LSA-001", September.StartUtc.AddDays(-2), September.StartUtc.AddTicks(-1)),
            ("SA-UPDATE-001", September.EndExclusiveUtc.AddTicks(-1), Now.AddHours(-1))
        };
        foreach (var (rule, first, last) in timelines)
        {
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE TrackedAlerts SET FirstObservedUtcTicks=$first, LastObservedUtcTicks=$last,
                    CreatedUtcTicks=$first, UpdatedUtcTicks=$last, StatusChangedUtcTicks=$last,
                    Severity=CASE WHEN RuleId='SA-FW-001' THEN 'critical' ELSE Severity END,
                    Title=$private, Reason=$private, RecommendedAction=$private WHERE EndpointId=$endpoint AND RuleId=$rule;
                DELETE FROM AlertStatusHistory WHERE AlertId IN
                    (SELECT AlertId FROM TrackedAlerts WHERE EndpointId=$endpoint AND RuleId=$rule);
                """;
            update.Parameters.AddWithValue("$first", first.UtcTicks);
            update.Parameters.AddWithValue("$last", last.UtcTicks);
            update.Parameters.AddWithValue("$private", PrivateText);
            update.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
            update.Parameters.AddWithValue("$rule", rule);
            await update.ExecuteNonQueryAsync();
            await AddHistoryAsync(connection, transaction, endpointId, rule, null, "open", first);
        }
        await AddHistoryAsync(connection, transaction, endpointId, "SA-LOGON-001", "open", "resolved", September.StartUtc.AddDays(9));
        await AddHistoryAsync(connection, transaction, endpointId, "SA-LOGON-001", "resolved", "open", September.StartUtc.AddDays(10));
        await AddHistoryAsync(connection, transaction, endpointId, "SA-LOGON-001", "open", "resolved", September.StartUtc.AddDays(19));
        await AddHistoryAsync(connection, transaction, endpointId, "SA-LOGON-001", "resolved", "open", September.EndExclusiveUtc);
        for (var index = 0; index < 102; index++)
            await AddHistoryAsync(connection, transaction, endpointId, "SA-LOGON-001",
                index % 2 == 0 ? "open" : "investigating", index % 2 == 0 ? "investigating" : "open",
                September.EndExclusiveUtc.AddMinutes(index + 1));
        await using (var chronology = connection.CreateCommand())
        {
            chronology.Transaction = transaction;
            chronology.CommandText = """
                UPDATE TrackedAlerts SET StatusChangedUtcTicks=$changed, UpdatedUtcTicks=$changed, Version=107
                WHERE EndpointId=$endpoint AND RuleId='SA-LOGON-001';
                """;
            chronology.Parameters.AddWithValue("$changed", September.EndExclusiveUtc.AddMinutes(102).UtcTicks);
            chronology.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
            await chronology.ExecuteNonQueryAsync();
        }
        await using var evidence = connection.CreateCommand();
        evidence.Transaction = transaction;
        evidence.CommandText = "UPDATE TrackedAlerts SET EvidenceJson=$evidence WHERE EndpointId=$endpoint AND RuleId='SA-FW-001';";
        evidence.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        evidence.Parameters.AddWithValue("$evidence", JsonSerializer.Serialize(new object[]
        {
            new { Field = "securityPosture.domainFirewallEnabled", Value = (object)false },
            new { Field = "credentials.password", Value = (object)PrivateText },
            new { Field = "raw.log", Value = (object)PrivateText }
        }));
        await evidence.ExecuteNonQueryAsync();
        await using var malformed = connection.CreateCommand();
        malformed.Transaction = transaction;
        malformed.CommandText = """
            UPDATE TrackedAlerts SET EvidenceJson=$malformed WHERE EndpointId=$endpoint AND RuleId='SA-FW-002';
            UPDATE TrackedAlerts SET EvidenceJson=$duplicates WHERE EndpointId=$endpoint AND RuleId='SA-FW-003';
            """;
        malformed.Parameters.AddWithValue("$endpoint", endpointId.ToString("D"));
        malformed.Parameters.AddWithValue("$malformed", JsonSerializer.Serialize(new[]
        {
            new { Field = "securityPosture.privateFirewallEnabled", Value = PrivateText }
        }));
        malformed.Parameters.AddWithValue("$duplicates", JsonSerializer.Serialize(new[]
        {
            new { Field = "securityPosture.publicFirewallEnabled", Value = false },
            new { Field = "securityPosture.publicFirewallEnabled", Value = true }
        }));
        await malformed.ExecuteNonQueryAsync();
        transaction.Commit();
    }

    private static async Task AddHistoryAsync(SqliteConnection connection, SqliteTransaction transaction, Guid endpoint,
        string rule, string? previous, string status, DateTimeOffset changed)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO AlertStatusHistory (AlertId, PreviousStatus, Status, ChangedUtcTicks, ChangedBy)
            SELECT AlertId, $previous, $status, $ticks, $actor FROM TrackedAlerts WHERE EndpointId=$endpoint AND RuleId=$rule;
            """;
        command.Parameters.AddWithValue("$endpoint", endpoint.ToString("D"));
        command.Parameters.AddWithValue("$rule", rule);
        command.Parameters.AddWithValue("$previous", (object?)previous ?? DBNull.Value);
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$ticks", changed.UtcTicks);
        command.Parameters.AddWithValue("$actor", PrivateActor);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task SeedHeartbeatAsync(string database, Guid endpoint, DateTimeOffset seen)
    {
        await using var connection = Connection(database);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR REPLACE INTO Devices (InstallationId, LastSeenUtcTicks, HealthStatus, EnrollmentStatus)
            SELECT InstallationId, $seen, 'reporting', 'enrolled' FROM EndpointEnrollments WHERE EndpointId=$endpoint;
            """;
        command.Parameters.AddWithValue("$seen", seen.UtcTicks);
        command.Parameters.AddWithValue("$endpoint", endpoint.ToString("D"));
        await command.ExecuteNonQueryAsync();
    }

    private static async Task SeedLeaseAsync(string database)
    {
        await using var connection = Connection(database);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR REPLACE INTO LicenseState (Singleton,Lease,LastSuccessfulValidationUtcTicks,HighWaterUtcTicks,
                LastAttemptSucceeded,ClockRollbackDetected) VALUES (1,$lease,NULL,$now,0,0);
            """;
        command.Parameters.AddWithValue("$lease", PrivateLease);
        command.Parameters.AddWithValue("$now", Now.UtcTicks);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task VerifyCapacityAsync(WebApplication app, HttpClient client, string token)
    {
        await using var connection = Connection(app.Services.GetRequiredService<AdminStore>().DatabasePath);
        await connection.OpenAsync();
        using var transaction = connection.BeginTransaction();
        // Synthetic enrolled rows exercise the actual work cap without changing enrollment or API limits.
        for (var index = 4; index < 1001; index++)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO EndpointEnrollments (InstallationId,EndpointId,CoreInstallationId,OrganizationId,CredentialHash)
                SELECT $installation,$endpoint,CoreInstallationId,OrganizationId,$hash FROM CoreIdentity;
                """;
            command.Parameters.AddWithValue("$installation", Guid.NewGuid().ToString("D"));
            command.Parameters.AddWithValue("$endpoint", Guid.NewGuid().ToString("D"));
            command.Parameters.AddWithValue("$hash", new byte[32]);
            await command.ExecuteNonQueryAsync();
        }
        transaction.Commit();
        using var response = await SendAsync(client, PeriodPath, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.UnprocessableEntity,
            "Report silently truncated or attempted unlimited work above the enrolled endpoint capacity.");

        // Restore the valid endpoint count so the independent tracked-alert cap is exercised.
        await using var alerts = connection.CreateCommand();
        alerts.CommandText = """
            DELETE FROM EndpointEnrollments WHERE CredentialHash=$hash;
            WITH RECURSIVE items(number) AS (SELECT 1 UNION ALL SELECT number+1 FROM items WHERE number<13001)
            INSERT INTO TrackedAlerts (AlertId,EndpointId,EndpointName,RuleId,Title,Severity,Status,
                FirstObservedUtcTicks,LastObservedUtcTicks,CreatedUtcTicks,UpdatedUtcTicks,StatusChangedUtcTicks,
                Version,Reason,EvidenceJson,RecommendedAction)
            SELECT printf('00000000-0000-0000-0001-%012d',number),
                (SELECT EndpointId FROM EndpointEnrollments ORDER BY EndpointId LIMIT 1),
                'synthetic-capacity-endpoint','synthetic-capacity-rule-'||number,'synthetic finding','low','open',
                $now,$now,$now,$now,$now,1,'synthetic evidence','[]','synthetic action' FROM items;
            """;
        alerts.Parameters.AddWithValue("$hash", new byte[32]);
        alerts.Parameters.AddWithValue("$now", Now.UtcTicks);
        await alerts.ExecuteNonQueryAsync();
        using var tooManyAlerts = await SendAsync(client, PeriodPath, "Bearer", token);
        Check(tooManyAlerts.StatusCode == HttpStatusCode.UnprocessableEntity,
            "Report silently truncated or attempted unlimited work above the tracked-alert capacity.");
    }

    private static async Task VerifyRemoteHttpAsync(string directory, string username, string password, OfflineGateway gateway)
    {
        await using var app = Build(directory, gateway);
        app.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.13");
            await next(context);
        });
        using var client = await StartAsync(app);
        var token = await LoginAsync(client, username, password);
        using var response = await SendAsync(client, PeriodPath, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.Forbidden, "Core exposed a security report over remote cleartext HTTP.");
        await app.StopAsync();
    }

    private static WebApplication Build(string directory, OfflineGateway gateway) => CoreHost.Build(
        [$"--SentinelAI:DataDirectory={directory}"], builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<TimeProvider>(new FixedTime());
            builder.Services.AddSingleton<IAiGatewayClient>(gateway);
            builder.Services.AddSingleton<ILicenseLeaseClient>(new OfflineLicenseClient());
        });

    private static async Task<HttpClient> StartAsync(WebApplication app)
    {
        app.Urls.Clear();
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        return new HttpClient(new HttpClientHandler { UseProxy = false })
            { BaseAddress = new Uri(app.Urls.Single()), Timeout = TimeSpan.FromSeconds(30) };
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Check(response.StatusCode == HttpStatusCode.OK, "The synthetic report administrator could not sign in.");
        using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return data.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<EnrollmentResponse> EnrollAsync(WebApplication app)
    {
        var store = app.Services.GetRequiredService<EnrollmentStore>();
        var token = await store.IssueTokenAsync();
        var result = await store.TryEnrollAsync(new EnrollmentRequest(Guid.NewGuid(), token.Token));
        return result.Response ?? throw new InvalidOperationException("Could not enroll a synthetic report endpoint.");
    }

    private static InventoryReport Inventory(Guid endpoint) => new(endpoint, Now.AddHours(-1), "synthetic-report-test",
        "synthetic-report-endpoint", "Windows 11", "10.0.26100.1000", "X64", new("Synthetic CPU", 4), null, [],
        new(true, true, true, new WindowsSecurityConfiguration(UacEnabled: true, AdminConsentPromptBehavior: 5,
            RdpEnabled: false, Smb1ServerEnabled: false, SmbInsecureGuestLogonsAllowed: false,
            AutomaticAdminLogonEnabled: false, LsaProtectionEnabled: true, AutomaticUpdatesDisabled: false)));

    private static async Task UploadAsync(HttpClient client, EnrollmentResponse agent, InventoryReport inventory)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/agent/inventory") { Content = JsonContent.Create(inventory) };
        request.Headers.Authorization = new AuthenticationHeaderValue("SentinelAgent", $"{agent.EndpointId:D}.{agent.AgentCredential}");
        using var response = await client.SendAsync(request);
        Check(response.StatusCode == HttpStatusCode.NoContent, "The synthetic report inventory was rejected.");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string path, string scheme, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        return await client.SendAsync(request);
    }

    private static async Task<JsonDocument> ReadAsync(HttpClient client, string path, string token)
    {
        using var response = await SendAsync(client, path, "Bearer", token);
        Check(response.StatusCode == HttpStatusCode.OK, "The report fixture could not read local state: " + path);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static SqliteConnection Connection(string path) => new(new SqliteConnectionStringBuilder
        { DataSource = path, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 30 }.ToString());

    private static async Task<string> ScalarAsync(string database, string query)
    {
        await using var connection = Connection(database);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = query;
        return (string)(await command.ExecuteScalarAsync())!;
    }

    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class OfflineGateway : IAiGatewayClient
    {
        public bool Configured => true;
        public int Requests { get; private set; }
        public Task<AiExplanationResponse?> ExplainAsync(AiAlertContext context, CancellationToken cancellationToken = default)
        {
            Requests++;
            throw new InvalidOperationException("Offline reports must never call the AI Gateway.");
        }
    }

    private sealed class OfflineLicenseClient : ILicenseLeaseClient
    {
        public bool Configured => false;
        public Task<string?> FetchAsync(CoreIdentity identity, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Offline reports must never contact a license issuer.");
    }
}
