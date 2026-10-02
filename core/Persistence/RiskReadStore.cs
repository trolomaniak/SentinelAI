using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Rules;
using SentinelAI.Scoring;

namespace SentinelAI.Core.Persistence;

/// <summary>Scores enrollment, inventory and lifecycle state from one SQLite read snapshot.</summary>
public sealed class RiskReadStore(AdminStore admins, RiskScoringOptions options, TimeProvider timeProvider)
{
    public async Task<RiskPage> ListAsync(int offset, int limit, CancellationToken cancellationToken = default)
    {
        if (offset < 0 || limit is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Offset must be nonnegative and limit between 1 and 200.");
        }

        var snapshot = await ReadSnapshotAsync(null, cancellationToken);
        var now = timeProvider.GetUtcNow();
        var details = snapshot.Select(endpoint => Score(endpoint, now)).ToArray();
        var organizationRisk = options.Scorer.ScoreOrganization(details.Select(endpoint => endpoint.Risk));
        var alerts = details.SelectMany(endpoint => endpoint.Alerts).ToArray();
        var organization = new OrganizationRiskView(organizationRisk.Score, organizationRisk.EndpointCount,
            organizationRisk.HighestRiskEndpointIds, organizationRisk.HighestRiskEndpointCount,
            organizationRisk.HighestRiskEndpointIdsTruncated,
            organizationRisk.Method, organizationRisk.Explanation, now,
            details.Count(endpoint => endpoint.InventoryCollectedUtc is not null),
            details.Count(endpoint => endpoint.Coverage.InventoryState == "missing"),
            details.Count(endpoint => endpoint.Coverage.SignalCoverage == "unknown"),
            details.Count(endpoint => endpoint.Coverage.SignalCoverage == "partial"),
            details.Count(endpoint => endpoint.Coverage.InventoryState == "stale"),
            new RiskAlertStatusCounts(alerts.Count(alert => alert.Status == "open"),
                alerts.Count(alert => alert.Status == "investigating"),
                alerts.Count(alert => alert.Status == "accepted"),
                alerts.Count(alert => alert.Status == "resolved")));
        var endpoints = details.OrderByDescending(endpoint => endpoint.Risk.Score)
            .ThenByDescending(endpoint => endpoint.Risk.RawScore)
            .ThenBy(endpoint => endpoint.EndpointId)
            .Skip(offset).Take(limit).Select(Summarize).ToArray();
        return new RiskPage(organization, endpoints, details.LongLength, offset, limit, options.Scorer.Policy,
            options.InventoryFreshForHours);
    }

    public async Task<EndpointRiskDetail?> FindAsync(Guid endpointId, CancellationToken cancellationToken = default)
    {
        if (endpointId == Guid.Empty)
        {
            return null;
        }

        var snapshot = await ReadSnapshotAsync(endpointId, cancellationToken);
        return snapshot.Count == 0 ? null : Score(snapshot[0], timeProvider.GetUtcNow());
    }

    private EndpointRiskDetail Score(SnapshotEndpoint endpoint, DateTimeOffset now) => new(
        endpoint.EndpointId,
        endpoint.EndpointName,
        endpoint.InventoryCollectedUtc,
        options.Scorer.ScoreEndpoint(endpoint.EndpointId,
            endpoint.Alerts.Select(alert => new ScoringAlert(alert.AlertId, alert.RuleId, alert.Severity,
                alert.Status, alert.LastObservedUtc)),
            options.ContextFor(endpoint.EndpointId, endpoint.InventoryCollectedUtc), now),
        AssessCoverage(endpoint.Inventory, now),
        endpoint.Alerts,
        options.Scorer.Policy,
        options.InventoryFreshForHours);

    private static EndpointRiskSummary Summarize(EndpointRiskDetail endpoint)
    {
        var highest = endpoint.Risk.Contributions.Where(contribution => contribution.Contribution > 0m)
            .OrderByDescending(contribution => contribution.Contribution)
            .ThenBy(contribution => contribution.AlertId).FirstOrDefault();
        var reason = highest is null
            ? "No remaining scored alert contribution; this does not establish that the endpoint is secure."
            : endpoint.Alerts.First(alert => alert.AlertId == highest.AlertId).Reason;
        return new EndpointRiskSummary(endpoint.EndpointId, endpoint.EndpointName, endpoint.InventoryCollectedUtc,
            endpoint.Risk.Score, endpoint.Risk.RawScore, endpoint.Coverage,
            endpoint.Alerts.Count(alert => alert.Status != "resolved"), reason, endpoint.Risk.CalculatedUtc);
    }

    private RiskCoverage AssessCoverage(InventoryReport? inventory, DateTimeOffset now)
    {
        const string caution = "Coverage counts only the 13 supported Windows configuration rules. " +
            "Missing or unknown observations have no score; a zero score is not a security assurance.";
        if (inventory is null)
        {
            return new RiskCoverage("missing", "unknown", 0, 13, caution);
        }

        var inventoryState = inventory.CollectedUtc > now ? "future"
            : now - inventory.CollectedUtc > TimeSpan.FromHours(options.InventoryFreshForHours) ? "stale" : "current";
        var known = EndpointState.FromInventory(inventory).IsWindows ? CountKnownSignals(inventory.SecurityPosture) : 0;
        return new RiskCoverage(inventoryState, known == 0 ? "unknown" : known == 13 ? "complete" : "partial",
            known, 13, caution);
    }

    private static int CountKnownSignals(SecurityPostureInventory posture)
    {
        var config = posture.Configuration;
        var rdpDisabled = config?.RdpEnabled == false;
        var rdpEnabled = config?.RdpEnabled == true;
        var known = new[]
        {
            posture.DomainFirewallEnabled.HasValue,
            posture.PrivateFirewallEnabled.HasValue,
            posture.PublicFirewallEnabled.HasValue,
            config?.UacEnabled.HasValue == true,
            config?.UacEnabled == false || (config?.UacEnabled == true && config.AdminConsentPromptBehavior.HasValue),
            rdpDisabled || (rdpEnabled && config!.RdpNetworkLevelAuthenticationRequired.HasValue),
            rdpDisabled || (rdpEnabled && config!.RdpSecurityLayer.HasValue),
            rdpDisabled || (rdpEnabled && (config!.RdpSecurityLayer == 2 ||
                (config.RdpSecurityLayer is 0 or 1 && config.RdpMinimumEncryptionLevel.HasValue))),
            config?.Smb1ServerEnabled.HasValue == true,
            config?.SmbInsecureGuestLogonsAllowed.HasValue == true,
            config?.AutomaticAdminLogonEnabled.HasValue == true,
            config?.LsaProtectionEnabled.HasValue == true,
            config?.AutomaticUpdatesDisabled.HasValue == true
        };
        return known.Count(value => value);
    }

    private async Task<IReadOnlyList<SnapshotEndpoint>> ReadSnapshotAsync(
        Guid? endpointId, CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = admins.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            DefaultTimeout = 30
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction(deferred: true);
        var endpoints = new Dictionary<Guid, SnapshotEndpoint>();
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT e.EndpointId, i.CollectedUtcTicks, i.ReportJson
                FROM EndpointEnrollments AS e
                LEFT JOIN EndpointInventories AS i ON i.EndpointId = e.EndpointId
                WHERE ($endpointId IS NULL OR e.EndpointId = $endpointId)
                ORDER BY e.EndpointId;
                """;
            query.Parameters.AddWithValue("$endpointId", endpointId?.ToString("D") ?? (object)DBNull.Value);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = Guid.Parse(reader.GetString(0));
                var inventory = reader.IsDBNull(2) ? null
                    : JsonSerializer.Deserialize<InventoryReport>(reader.GetString(2));
                endpoints.Add(id, new SnapshotEndpoint(id,
                    inventory?.Hostname ?? $"Endpoint {id.ToString("N")[..8]}",
                    reader.IsDBNull(1) ? null : new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero), inventory, []));
            }
        }

        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT a.AlertId, a.EndpointId, a.RuleId, a.Title, a.Severity, a.Status,
                    a.LastObservedUtcTicks, a.Reason
                FROM TrackedAlerts AS a
                INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId
                WHERE ($endpointId IS NULL OR a.EndpointId = $endpointId)
                ORDER BY a.EndpointId, a.AlertId;
                """;
            query.Parameters.AddWithValue("$endpointId", endpointId?.ToString("D") ?? (object)DBNull.Value);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                endpoints[Guid.Parse(reader.GetString(1))].Alerts.Add(new RiskAlertView(
                    Guid.Parse(reader.GetString(0)), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5),
                    new DateTimeOffset(reader.GetInt64(6), TimeSpan.Zero), reader.GetString(7)));
            }
        }

        transaction.Commit();
        return endpoints.Values.ToArray();
    }

    private sealed record SnapshotEndpoint(Guid EndpointId, string EndpointName,
        DateTimeOffset? InventoryCollectedUtc, InventoryReport? Inventory, List<RiskAlertView> Alerts);
}
