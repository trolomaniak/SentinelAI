using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.Inventory;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Rules;
using SentinelAI.Rules.Vulnerabilities;
using SentinelAI.Scoring;
using SentinelAI.Localization;

namespace SentinelAI.Core.Persistence;

/// <summary>Scores enrollment, inventory and lifecycle state from one SQLite read snapshot.</summary>
public sealed class RiskReadStore(AdminStore admins, RiskScoringOptions options, TimeProvider timeProvider, InstallationLanguageStore language)
{
    // The Agent reports channel status at least hourly; an older report no longer describes collection.
    private static readonly TimeSpan EventStatusFreshFor = TimeSpan.FromHours(2);
    private static readonly EventRuleEngine EventRules = EventRuleEngine.CreateDefault();
    // The Agent reports telemetry hourly; an older report may no longer describe the endpoint.
    private static readonly TimeSpan TelemetryFreshFor = TimeSpan.FromHours(3);
    private static readonly TelemetryRuleEngine TelemetryRules = TelemetryRuleEngine.CreateDefault();

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

    private EndpointRiskDetail Score(SnapshotEndpoint endpoint, DateTimeOffset now) =>
        ScoreSnapshot(endpoint.EndpointId, endpoint.EndpointName, endpoint.InventoryCollectedUtc,
            endpoint.Inventory, endpoint.Alerts, now, endpoint.EventChannels, endpoint.Telemetry);

    /// <summary>
    /// <paramref name="eventChannels"/> is null when the caller did not read event channel status;
    /// <paramref name="telemetry"/> is null when the endpoint has no stored telemetry report.
    /// </summary>
    internal EndpointRiskDetail ScoreSnapshot(Guid endpointId, string endpointName,
        DateTimeOffset? inventoryCollectedUtc, InventoryReport? inventory,
        IReadOnlyList<RiskAlertView> alerts, DateTimeOffset now, IReadOnlyList<EventChannelState>? eventChannels = null,
        TelemetryState? telemetry = null) => new(
        endpointId,
        endpointName,
        inventoryCollectedUtc,
        options.Scorer.ScoreEndpoint(endpointId,
            alerts.Select(alert => new ScoringAlert(alert.AlertId, alert.RuleId, alert.Severity,
                alert.Status, alert.LastObservedUtc, EventRuleEngine.DefaultRuleIds.Contains(alert.RuleId),
                TelemetryRuleEngine.DefaultRuleIds.Contains(alert.RuleId) || VulnerabilityRules.RuleIds.Contains(alert.RuleId), telemetry?.CollectedUtc)),
            options.ContextFor(endpointId, inventoryCollectedUtc), now),
        AssessCoverage(inventory, eventChannels, telemetry, now),
        alerts,
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

    private RiskCoverage AssessCoverage(InventoryReport? inventory, IReadOnlyList<EventChannelState>? eventChannels,
        TelemetryState? telemetry, DateTimeOffset now)
    {
        // Written in the installation language, like the rest of what administrators read.
        var lang = language.Current;
        var caution = Localizer.Translate("Coverage counts only the 13 supported Windows configuration rules.", lang) + " " +
            Localizer.Translate("Missing or unknown observations have no score; a zero score is not a security assurance.", lang) + " " +
            EventCaution(eventChannels, now, lang) + " " + TelemetryCaution(telemetry, now, lang);
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

    /// <summary>
    /// Event rules fire only on collected events. A channel counts as collecting only while its latest status is
    /// collecting and was reported within the Agent's liveness bound; anything else leaves its rules unable to fire.
    /// </summary>
    private static string EventCaution(IReadOnlyList<EventChannelState>? channels, DateTimeOffset now, UiLanguage lang)
    {
        var unknown = Localizer.Translate("Events that were not collected are unknown, not absent.", lang);
        var rules = EventRules.Rules;
        if (channels is null) return Localizer.Format("Event rules ({0}) fire only on collected events.", lang, rules.Count) + " " + unknown;
        var byChannel = channels.ToDictionary(channel => channel.Channel, StringComparer.Ordinal);
        string StateOf(string channel) => !byChannel.TryGetValue(channel, out var status) ? "not reported"
            : now - status.ReportedUtc > EventStatusFreshFor ? status.State + ", stale" : status.State;
        string Shown(string state) => state == "not reported" ? Localizer.Translate(state, lang)
            : state.EndsWith(", stale", StringComparison.Ordinal) ? state[..^7] + Localizer.Translate(", stale", lang) : state;
        var collecting = SecurityEventChannels.All.Where(channel => StateOf(channel) == SecurityEventSourceStates.Collecting)
            .ToHashSet(StringComparer.Ordinal);
        var able = rules.Count(rule => rule.Channels.Any(collecting.Contains));
        if (able == rules.Count) return Localizer.Format("All {0} event rules have a collecting channel.", lang, rules.Count) + " " + unknown;
        var missing = SecurityEventChannels.All.Where(channel => !collecting.Contains(channel))
            .Select(channel => $"{channel} ({Shown(StateOf(channel))})");
        return Localizer.Format("{0} of {1} event rules can fire; channels not collecting: {2}.", lang, able, rules.Count, string.Join(", ", missing)) + " " + unknown;
    }

    /// <summary>
    /// Telemetry rules fire only on collected report sections. A section that is not collected, or a report older
    /// than the Agent's reporting bound, leaves its rules unable to fire; that is stated, never scored as safe.
    /// </summary>
    private static string TelemetryCaution(TelemetryState? telemetry, DateTimeOffset now, UiLanguage lang)
    {
        var rules = TelemetryRules.Rules;
        if (telemetry is null) return Localizer.Format("No endpoint telemetry is reported, so its {0} rules cannot fire.", lang, rules.Count);
        var stale = now - telemetry.CollectedUtc > TelemetryFreshFor ? Localizer.Translate(" (latest report is stale)", lang) : string.Empty;
        string StateOf(string section) => telemetry.Sections.GetValueOrDefault(section) ?? "not reported";
        var able = rules.Count(rule => rule.Sections.All(section => StateOf(section) == TelemetryAvailability.Collected));
        if (able == rules.Count) return Localizer.Format("All {0} endpoint telemetry rules have collected inputs{1}.", lang, rules.Count, stale);
        var missing = TelemetryState.SectionNames.Where(section => StateOf(section) != TelemetryAvailability.Collected)
            .Select(section => $"{section} ({(StateOf(section) == "not reported" ? Localizer.Translate("not reported", lang) : StateOf(section))})");
        return Localizer.Format("{0} of {1} endpoint telemetry rules can fire{2}; not collected: {3}.", lang, able, rules.Count, stale, string.Join(", ", missing));
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
                WHERE e.RemovedUtcTicks IS NULL AND ($endpointId IS NULL OR e.EndpointId = $endpointId)
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
                    reader.IsDBNull(1) ? null : new DateTimeOffset(reader.GetInt64(1), TimeSpan.Zero), inventory, [], []));
            }
        }

        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = $"""
                SELECT t.EndpointId, {TelemetryState.Columns}
                FROM EndpointSecurityTelemetry AS t
                INNER JOIN EndpointEnrollments AS e ON e.EndpointId = t.EndpointId AND e.RemovedUtcTicks IS NULL
                WHERE ($endpointId IS NULL OR t.EndpointId = $endpointId);
                """;
            query.Parameters.AddWithValue("$endpointId", endpointId?.ToString("D") ?? (object)DBNull.Value);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = Guid.Parse(reader.GetString(0));
                endpoints[id] = endpoints[id] with { Telemetry = TelemetryState.Read(reader, 1) };
            }
        }

        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT s.EndpointId, s.Channel, s.State, s.ReceivedUtcTicks
                FROM SecurityEventSources AS s
                INNER JOIN EndpointEnrollments AS e ON e.EndpointId = s.EndpointId AND e.RemovedUtcTicks IS NULL
                WHERE ($endpointId IS NULL OR s.EndpointId = $endpointId);
                """;
            query.Parameters.AddWithValue("$endpointId", endpointId?.ToString("D") ?? (object)DBNull.Value);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                endpoints[Guid.Parse(reader.GetString(0))].EventChannels.Add(new EventChannelState(reader.GetString(1),
                    reader.GetString(2), new DateTimeOffset(reader.GetInt64(3), TimeSpan.Zero)));
            }
        }

        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT a.AlertId, a.EndpointId, a.RuleId, a.Title, a.Severity, a.Status,
                    a.LastObservedUtcTicks, a.Reason
                FROM TrackedAlerts AS a
                INNER JOIN EndpointEnrollments AS e ON e.EndpointId = a.EndpointId AND e.RemovedUtcTicks IS NULL
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
        DateTimeOffset? InventoryCollectedUtc, InventoryReport? Inventory, List<RiskAlertView> Alerts,
        List<EventChannelState> EventChannels, TelemetryState? Telemetry = null);
}

/// <summary>The latest reported state of one event channel and Core's receipt time of that report.</summary>
internal sealed record EventChannelState(string Channel, string State, DateTimeOffset ReportedUtc);
