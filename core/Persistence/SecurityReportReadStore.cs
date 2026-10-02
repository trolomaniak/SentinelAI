using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Ai;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Core.Reports;
using SentinelAI.Rules;

namespace SentinelAI.Core.Persistence;

/// <summary>A local read-only projection from one SQLite snapshot, with no licensing or AI dependency.</summary>
public sealed class SecurityReportReadStore(AdminStore admins, RiskScoringOptions options,
    RiskReadStore risks, TimeProvider timeProvider)
{
    public const int MaximumEndpointCount = 1000;
    public const int MaximumAlertCount = 13000;
    private static readonly IReadOnlyDictionary<string, SecurityAlert> Catalog = CreateCatalog();

    public async Task<SecurityReport> GenerateAsync(ReportPeriod period, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(period);
        if (!period.IsValid) throw new ArgumentOutOfRangeException(nameof(period));
        var now = timeProvider.GetUtcNow().ToUniversalTime();
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath, Mode = SqliteOpenMode.ReadWrite, DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        await CheckCapacityAsync(connection, transaction, cancellationToken);
        var snapshots = await ReadEndpointsAsync(connection, transaction, cancellationToken);
        var retained = await ReadAlertsAsync(connection, transaction, snapshots, period, cancellationToken);
        transaction.Commit();

        var endpoints = snapshots.Values.OrderBy(endpoint => endpoint.EndpointId).Select(endpoint =>
            new ReportEndpoint(endpoint.EndpointId, endpoint.EndpointName, HealthState(endpoint.LastSeenUtc, now),
                endpoint.LastSeenUtc, risks.ScoreSnapshot(endpoint.EndpointId, endpoint.EndpointName,
                    endpoint.Inventory?.CollectedUtc, endpoint.Inventory, endpoint.Alerts, now))).ToArray();
        var contributions = endpoints.SelectMany(endpoint => endpoint.CurrentRisk.Risk.Contributions)
            .ToDictionary(contribution => contribution.AlertId, contribution => contribution.Contribution);
        var incidents = retained.Select(incident => incident with
        {
            CurrentRiskContribution = contributions.GetValueOrDefault(incident.AlertId)
        }).ToArray();
        var periodIncidents = OrderIncidents(incidents.Where(incident => incident.FirstObservedInPeriod ||
            incident.LastObservedInPeriod || incident.StatusChangesInPeriod > 0));
        var findings = OrderIncidents(incidents.Where(incident => incident.CurrentStatus != "resolved"));
        var activity = new ReportActivitySummary(periodIncidents.Length,
            periodIncidents.Count(incident => incident.FirstObservedInPeriod),
            periodIncidents.Count(incident => incident.ResolutionsInPeriod > 0),
            new[] { "critical", "high", "medium", "low", "info" }.Select(severity => new ReportSeverityCount(severity,
                periodIncidents.Count(incident => incident.Severity == severity),
                periodIncidents.Count(incident => incident.Severity == severity && incident.FirstObservedInPeriod))).ToArray());
        return new SecurityReport(period, now, options.Scorer.ScoreOrganization(endpoints.Select(endpoint => endpoint.CurrentRisk.Risk)),
            new ReportHealthSummary(endpoints.Count(endpoint => endpoint.Health == "healthy"),
                endpoints.Count(endpoint => endpoint.Health == "warning"), endpoints.Count(endpoint => endpoint.Health == "offline"),
                endpoints.Count(endpoint => endpoint.Health == "unknown")), activity, endpoints, periodIncidents,
            findings, BuildRecommendations(findings, endpoints), options.Scorer.Policy, options.InventoryFreshForHours);
    }

    private static async Task CheckCapacityAsync(SqliteConnection connection, SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT (SELECT COUNT(*) FROM EndpointEnrollments),
                (SELECT COUNT(*) FROM TrackedAlerts AS a
                 INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId);
            """;
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        if (reader.GetInt64(0) > MaximumEndpointCount || reader.GetInt64(1) > MaximumAlertCount)
            throw new ReportCapacityException();
    }

    private static async Task<Dictionary<Guid, SnapshotEndpoint>> ReadEndpointsAsync(SqliteConnection connection,
        SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var endpoints = new Dictionary<Guid, SnapshotEndpoint>();
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        // Project only fields needed for names and existing rule coverage, never raw inventory or credentials.
        query.CommandText = """
            SELECT e.EndpointId, d.LastSeenUtcTicks, i.CollectedUtcTicks,
                substr(json_extract(i.ReportJson, '$.Hostname'), 1, 256),
                substr(json_extract(i.ReportJson, '$.OsName'), 1, 128),
                json_extract(i.ReportJson, '$.SecurityPosture.DomainFirewallEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.PrivateFirewallEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.PublicFirewallEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.UacEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.AdminConsentPromptBehavior'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.RdpEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.RdpNetworkLevelAuthenticationRequired'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.RdpSecurityLayer'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.RdpMinimumEncryptionLevel'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.Smb1ServerEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.SmbInsecureGuestLogonsAllowed'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.AutomaticAdminLogonEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.LsaProtectionEnabled'),
                json_extract(i.ReportJson, '$.SecurityPosture.Configuration.AutomaticUpdatesDisabled')
            FROM EndpointEnrollments AS e
            LEFT JOIN Devices AS d ON d.InstallationId = e.InstallationId
            LEFT JOIN EndpointInventories AS i ON i.EndpointId = e.EndpointId
            ORDER BY e.EndpointId;
            """;
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var id = Guid.Parse(reader.GetString(0));
            var name = reader.IsDBNull(3) ? $"Endpoint {id:N}" : reader.GetString(3);
            InventoryReport? inventory = null;
            if (!reader.IsDBNull(2))
            {
                var configuration = new WindowsSecurityConfiguration(ReadBoolean(reader, 8), ReadInteger(reader, 9),
                    ReadBoolean(reader, 10), ReadBoolean(reader, 11), ReadInteger(reader, 12), ReadInteger(reader, 13),
                    ReadBoolean(reader, 14), ReadBoolean(reader, 15), ReadBoolean(reader, 16), ReadBoolean(reader, 17),
                    ReadBoolean(reader, 18));
                inventory = new InventoryReport(id, ReadUtc(reader, 2), "", name,
                    reader.IsDBNull(4) ? "" : reader.GetString(4), "", "", new CpuInventory(null, 0), null, [],
                    new SecurityPostureInventory(ReadBoolean(reader, 5), ReadBoolean(reader, 6), ReadBoolean(reader, 7), configuration));
            }
            endpoints.Add(id, new SnapshotEndpoint(id, name, reader.IsDBNull(1) ? null : ReadUtc(reader, 1), inventory, []));
        }
        return endpoints;
    }

    private static async Task<List<ReportIncident>> ReadAlertsAsync(SqliteConnection connection, SqliteTransaction transaction,
        IReadOnlyDictionary<Guid, SnapshotEndpoint> endpoints, ReportPeriod period, CancellationToken cancellationToken)
    {
        var incidents = new List<ReportIncident>();
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        // All retained period transitions participate, without the incident export's recent-history limit.
        // Transition actors and freeform stored titles/reasons/actions are deliberately not selected.
        query.CommandText = """
            WITH period_history AS (
                SELECT h.AlertId, COUNT(*) AS ChangeCount,
                    SUM(CASE WHEN h.Status = 'resolved' THEN 1 ELSE 0 END) AS ResolutionCount,
                    MAX(CASE WHEN h.Status = 'resolved' THEN h.ChangedUtcTicks END) AS LatestResolutionTicks,
                    MIN(CASE WHEN h.Status = 'resolved' THEN h.SequenceId END) AS FirstResolutionSequence
                FROM AlertStatusHistory AS h
                INNER JOIN TrackedAlerts AS a ON a.AlertId = h.AlertId
                INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId
                WHERE h.ChangedUtcTicks >= $from AND h.ChangedUtcTicks < $to
                GROUP BY h.AlertId
            )
            SELECT a.AlertId, a.EndpointId, a.RuleId, a.Severity, a.Status,
                a.FirstObservedUtcTicks, a.LastObservedUtcTicks,
                CASE WHEN length(a.EvidenceJson) <= 8192 THEN a.EvidenceJson ELSE NULL END,
                COALESCE(p.ChangeCount, 0), COALESCE(p.ResolutionCount, 0), p.LatestResolutionTicks,
                EXISTS(SELECT 1 FROM AlertStatusHistory AS later
                    WHERE later.AlertId = a.AlertId AND later.SequenceId > p.FirstResolutionSequence
                    AND later.PreviousStatus = 'resolved' AND later.Status <> 'resolved')
            FROM TrackedAlerts AS a
            INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId
            LEFT JOIN period_history AS p ON p.AlertId = a.AlertId
            ORDER BY a.EndpointId, a.AlertId;
            """;
        query.Parameters.AddWithValue("$from", period.StartUtc.UtcTicks);
        query.Parameters.AddWithValue("$to", period.EndExclusiveUtc.UtcTicks);
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var alertId = Guid.Parse(reader.GetString(0));
            var endpointId = Guid.Parse(reader.GetString(1));
            var ruleId = reader.GetString(2);
            var metadata = Catalog.GetValueOrDefault(ruleId);
            var first = ReadUtc(reader, 5);
            var last = ReadUtc(reader, 6);
            var incident = new ReportIncident(alertId, endpointId, endpoints[endpointId].EndpointName,
                metadata?.RuleId ?? "unsupported", metadata?.Title ?? "Unsupported stored rule",
                reader.GetString(3), reader.GetString(4), first, last,
                metadata?.Reason ?? "Technical details are unavailable for this stored rule.",
                ReadEvidence(ruleId, reader.IsDBNull(7) ? null : reader.GetString(7)),
                metadata?.RecommendedAction ?? "Review this stored incident locally; no supported deterministic recommendation is available.",
                InPeriod(first, period), InPeriod(last, period), reader.GetInt64(8), reader.GetInt64(9),
                reader.IsDBNull(10) ? null : ReadUtc(reader, 10), reader.GetInt64(11) != 0, 0m);
            incidents.Add(incident);
            endpoints[endpointId].Alerts.Add(new RiskAlertView(alertId, ruleId, incident.Title, incident.Severity,
                incident.CurrentStatus, last, incident.Reason));
        }
        return incidents;
    }

    private static IReadOnlyList<RuleEvidence> ReadEvidence(string ruleId, string? json)
    {
        if (json is null || AiContract.GetEvidenceFields(ruleId) is not { } allowed) return [];
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.GetArrayLength() > 32) return [];
            var evidence = new SortedDictionary<string, RuleEvidence>(StringComparer.Ordinal);
            var duplicates = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in document.RootElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("Field", out var field) ||
                    field.ValueKind != JsonValueKind.String || field.GetString() is not { } name ||
                    !allowed.TryGetValue(name, out var kind) || !item.TryGetProperty("Value", out var value)) continue;
                var isBoolean = kind == JsonValueKind.True && value.ValueKind is JsonValueKind.True or JsonValueKind.False;
                var isInteger = kind == JsonValueKind.Number && value.ValueKind == JsonValueKind.Number &&
                    value.TryGetInt32(out var integer) && integer is >= 0 and <= 5;
                // A malformed duplicate is not supported evidence; valid conflicting duplicates are excluded.
                if (!isBoolean && !isInteger) continue;
                if (evidence.ContainsKey(name) || duplicates.Contains(name))
                {
                    evidence.Remove(name);
                    duplicates.Add(name);
                    continue;
                }
                if (isBoolean)
                    evidence.Add(name, RuleEvidence.Boolean(name, value.GetBoolean()));
                else evidence.Add(name, RuleEvidence.Integer(name, value.GetInt32()));
            }
            return evidence.Values.ToArray();
        }
        catch (JsonException) { return []; }
    }

    private static IReadOnlyDictionary<string, SecurityAlert> CreateCatalog()
    {
        var engine = RuleEngine.CreateDefault();
        var posture = new SecurityPostureInventory(false, false, false,
            new WindowsSecurityConfiguration(true, 0, true, false, 0, 1, true, true, true, false, true));
        var first = engine.Evaluate(new EndpointState(Guid.Empty, DateTimeOffset.UnixEpoch, true, posture));
        var second = engine.Evaluate(new EndpointState(Guid.Empty, DateTimeOffset.UnixEpoch, true,
            posture with { Configuration = posture.Configuration! with { UacEnabled = false } }));
        return first.Concat(second).DistinctBy(alert => alert.RuleId).ToDictionary(alert => alert.RuleId, StringComparer.Ordinal);
    }

    private static IReadOnlyList<ReportPriorityAction> BuildRecommendations(IReadOnlyList<ReportIncident> findings,
        IReadOnlyList<ReportEndpoint> endpoints)
    {
        var recommendations = findings.GroupBy(incident => incident.RuleId, StringComparer.Ordinal)
            .Select(group => new ReportPriorityAction(group.OrderByDescending(incident => SeverityRank(incident.Severity)).First().Severity,
                group.Key, group.First().RecommendedAction, group.Select(incident => incident.EndpointId).Distinct().Count(),
                "Tracked unresolved configuration findings; verify current configuration before approved changes.",
                group.Sum(incident => incident.CurrentRiskContribution)))
            .OrderByDescending(action => SeverityRank(action.Priority)).ThenByDescending(action => action.CurrentRiskContribution)
            .ThenBy(action => action.RuleId, StringComparer.Ordinal).ToList();
        var unavailable = endpoints.Count(endpoint => endpoint.CurrentRisk.Coverage.InventoryState != "current" ||
            endpoint.CurrentRisk.Coverage.SignalCoverage != "complete");
        if (unavailable > 0) recommendations.Add(new ReportPriorityAction("coverage", "coverage",
            "Refresh missing, stale or future-dated inventories and investigate unknown supported configuration signals.",
            unavailable, "Unknown observations can conceal risks and do not contribute a score.", 0m));
        var disconnected = endpoints.Count(endpoint => endpoint.Health != "healthy");
        if (disconnected > 0) recommendations.Add(new ReportPriorityAction("health", "health",
            "Check Agent connectivity and heartbeat freshness on endpoints that are warning, offline or unknown.",
            disconnected, "Heartbeat health describes reporting freshness, not endpoint safety.", 0m));
        return recommendations;
    }

    internal static int SeverityRank(string severity) => severity switch
    {
        "critical" => 5, "high" => 4, "medium" => 3, "low" => 2, "info" => 1, _ => 0
    };
    private static ReportIncident[] OrderIncidents(IEnumerable<ReportIncident> incidents) => incidents
        .OrderByDescending(incident => SeverityRank(incident.Severity)).ThenByDescending(incident => incident.CurrentRiskContribution)
        .ThenBy(incident => incident.RuleId, StringComparer.Ordinal).ThenBy(incident => incident.EndpointId)
        .ThenBy(incident => incident.AlertId).ToArray();
    private static bool InPeriod(DateTimeOffset time, ReportPeriod period) => time >= period.StartUtc && time < period.EndExclusiveUtc;
    private static DateTimeOffset ReadUtc(SqliteDataReader reader, int ordinal) => new(reader.GetInt64(ordinal), TimeSpan.Zero);
    private static bool? ReadBoolean(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal) != 0;
    private static int? ReadInteger(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    private static string HealthState(DateTimeOffset? lastSeen, DateTimeOffset now) => lastSeen is null ? "unknown"
        : now - lastSeen.Value <= TimeSpan.FromMinutes(2) ? "healthy"
        : now - lastSeen.Value <= TimeSpan.FromMinutes(5) ? "warning" : "offline";
    private sealed record SnapshotEndpoint(Guid EndpointId, string EndpointName, DateTimeOffset? LastSeenUtc,
        InventoryReport? Inventory, List<RiskAlertView> Alerts);
}
