using System.Text.Json;
using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Rules;

/// <summary>Endpoint telemetry rule tests: synthetic reports only.</summary>
internal static class TelemetryRuleTests
{
    private const string Collected = TelemetryAvailability.Collected;
    private static readonly Guid EndpointId = Guid.Parse("8d5e2c1a-4b7f-4e3d-9a6c-1f0b2e7d5c84");
    private static readonly DateTimeOffset CollectedUtc = new(2026, 4, 6, 10, 15, 0, TimeSpan.Zero);

    public static int Run()
    {
        var engine = TelemetryRuleEngine.CreateDefault();
        var checks = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
            checks++;
        }

        string[] expected = ["SA-AV-001", "SA-DISK-001", "SA-SVC-001", "SA-SVC-002"];
        Check(engine.Rules.Select(rule => rule.Id).SequenceEqual(expected) &&
              TelemetryRuleEngine.DefaultRuleIds.SetEquals(expected), "The default telemetry engine must hold the four rules in order.");
        foreach (var rule in engine.Rules)
        {
            Check(rule.Severity is "info" or "low" or "medium" or "high" or "critical", $"{rule.Id}: severity must be a known level.");
            Check(rule.Title.Length is > 0 and <= 128 && rule.Reason.Length > 0 && rule.RecommendedAction.Length > 0,
                $"{rule.Id}: title, reason and recommended action are required.");
            Check(rule.Sections.Count > 0 && rule.Sections.All(section =>
                    section is TelemetrySections.BitLocker or TelemetrySections.Antivirus or TelemetrySections.Services),
                $"{rule.Id}: a rule must name the report sections it reads.");
            Check(!rule.Reason.Contains("compromise", StringComparison.OrdinalIgnoreCase),
                $"{rule.Id}: a finding must not be presented as proof of compromise.");
            Check(!RuleEngine.CreateDefault().Rules.Any(other => other.Id == rule.Id) &&
                  !EventRuleEngine.DefaultRuleIds.Contains(rule.Id), $"{rule.Id}: telemetry rule IDs must not collide with other rules.");
        }

        // Benign, Unknown and uncollected inputs never fire.
        Check(engine.Evaluate(Benign()).Count == 0, "A benign collected report must produce no finding.");
        Check(engine.Evaluate(AllUnknown()).Count == 0, "Collected sections with Unknown values must produce no finding.");
        foreach (var availability in new[] { TelemetryAvailability.Unsupported, TelemetryAvailability.AccessDenied, TelemetryAvailability.Unavailable })
        {
            Check(engine.Evaluate(NotCollected(availability)).Count == 0, $"{availability} sections must produce no finding.");
            // Even values that slipped past the contract never fire while their section is not collected.
            var leaked = Benign() with
            {
                Antivirus = new AntivirusTelemetry(availability, SecurityCenterHealthStates.Poor),
                BitLocker = new BitLockerTelemetry(availability, BitLockerProtectionStates.Off),
                Services = new SecurityServicesTelemetry(availability, [new("MpsSvc", ServiceRunStates.Stopped, ServiceStartTypes.Disabled)])
            };
            Check(engine.Evaluate(leaked).Count == 0, $"Values in a {availability} section must never fire.");
        }

        // SA-AV-001
        foreach (var health in new[] { SecurityCenterHealthStates.Poor, SecurityCenterHealthStates.Snooze })
        {
            var finding = Single(engine, Benign() with { Antivirus = new AntivirusTelemetry(Collected, health) }, "SA-AV-001");
            Check(Text(finding, "antivirus.securityCenterHealth") == health && finding.Evidence.Count == 1,
                $"SA-AV-001 must carry the reported health {health}.");
        }

        Check(engine.Evaluate(Benign() with { Antivirus = new AntivirusTelemetry(Collected, SecurityCenterHealthStates.NotMonitored) }).Count == 0,
            "An unmonitored antivirus state is Unknown, not a finding.");

        // SA-DISK-001
        var disk = Single(engine, Benign() with { BitLocker = new BitLockerTelemetry(Collected, "off", "fullyDecrypted") }, "SA-DISK-001");
        Check(Text(disk, "bitLocker.protectionStatus") == "off" && Text(disk, "bitLocker.conversionStatus") == "fullyDecrypted",
            "SA-DISK-001 must carry the protection and conversion status.");
        disk = Single(engine, Benign() with { BitLocker = new BitLockerTelemetry(Collected, "off") }, "SA-DISK-001");
        Check(disk.Evidence.Count == 1, "SA-DISK-001 must not invent an unknown conversion status.");
        Check(engine.Evaluate(Benign() with { BitLocker = new BitLockerTelemetry(Collected, null, "fullyDecrypted") }).Count == 0,
            "A fully decrypted volume with Unknown protection status is not a finding.");

        // SA-SVC-001 and SA-SVC-002: stopped, or start disabled.
        foreach (var (ruleId, service) in new[] { ("SA-SVC-001", "MpsSvc"), ("SA-SVC-002", "EventLog") })
        {
            var stopped = Single(engine, WithService(service, ServiceRunStates.Stopped, ServiceStartTypes.Auto), ruleId);
            Check(Text(stopped, "service.name") == service && Text(stopped, "service.state") == "stopped" &&
                  Text(stopped, "service.startType") == "auto", $"{ruleId}: a stopped service must carry its state and start type.");
            var disabled = Single(engine, WithService(service, null, ServiceStartTypes.Disabled), ruleId);
            Check(Text(disabled, "service.startType") == "disabled" && Evidence(disabled, "service.state") is null,
                $"{ruleId}: a disabled service with Unknown state must not invent a state.");
            foreach (var benign in new[]
                     {
                         new SecurityServiceObservation(service, ServiceRunStates.Running, ServiceStartTypes.Auto),
                         new SecurityServiceObservation(service, ServiceRunStates.NotInstalled),
                         new SecurityServiceObservation(service),
                         new SecurityServiceObservation(service, "stopPending", ServiceStartTypes.Demand)
                     })
            {
                Check(engine.Evaluate(Benign() with { Services = new SecurityServicesTelemetry(Collected, [benign]) }).Count == 0,
                    $"{ruleId}: {benign.State ?? "unknown"}/{benign.StartType ?? "unknown"} must not fire.");
            }
        }

        Check(engine.Evaluate(WithService("BFE", ServiceRunStates.Stopped, ServiceStartTypes.Disabled)).Count == 0,
            "Only the named services raise service findings.");

        // All four at once, in rule order, timed by the report and deterministic.
        var all = Benign() with
        {
            Antivirus = new AntivirusTelemetry(Collected, SecurityCenterHealthStates.Poor),
            BitLocker = new BitLockerTelemetry(Collected, "off", "encryptionPaused"),
            Services = new SecurityServicesTelemetry(Collected,
            [
                new("MpsSvc", ServiceRunStates.Stopped, ServiceStartTypes.Disabled),
                new("EventLog", ServiceRunStates.Stopped, ServiceStartTypes.Disabled)
            ])
        };
        var findings = engine.Evaluate(all);
        Check(findings.Select(finding => finding.RuleId).SequenceEqual(expected), "Findings must follow rule order.");
        Check(findings.All(finding => finding.EndpointId == EndpointId && finding.Timestamp == CollectedUtc),
            "Findings must carry the endpoint and the report's collection time.");
        Check(JsonSerializer.Serialize(findings) == JsonSerializer.Serialize(engine.Evaluate(all)),
            "Evaluation must be repeatable byte for byte.");

        // Engine construction guards.
        Check(Throws(() => new TelemetryRuleEngine([new AntivirusAtRiskRule(), new AntivirusAtRiskRule()])),
            "Duplicate telemetry rule IDs must be rejected.");
        Check(Throws(() => TelemetrySections.AvailabilityOf(Benign(), "software")), "Only rule sections have an availability.");
        return checks;
    }

    internal static EndpointTelemetryReport Benign() => new(EndpointTelemetryContract.CurrentSchemaVersion, EndpointId, CollectedUtc,
        new BitLockerTelemetry(Collected, "on", "fullyEncrypted"),
        new AntivirusTelemetry(Collected, SecurityCenterHealthStates.Good),
        new DefenderTelemetry(Collected, "normal", true, true, true, 0),
        new LocalAdministratorsTelemetry(Collected, 1, [new("S-1-5-21-1000-1000-1000-500", AdministratorScopes.Local, "user")]),
        new WindowsUpdateTelemetry(Collected, Collected, "notConfigured", false, CollectedUtc.AddHours(-3), CollectedUtc.AddDays(-2)),
        new PendingRebootTelemetry(Collected, false, false, false),
        new SecurityServicesTelemetry(Collected, EndpointTelemetryContract.MonitoredServices
            .Select(name => new SecurityServiceObservation(name, ServiceRunStates.Running, ServiceStartTypes.Auto)).ToArray()),
        new InstalledSoftwareTelemetry(Collected, [new("Example Viewer", "1.2.3", "Example Corp", "x64")], 1));

    private static EndpointTelemetryReport AllUnknown() => Benign() with
    {
        BitLocker = new BitLockerTelemetry(Collected),
        Antivirus = new AntivirusTelemetry(Collected),
        Services = new SecurityServicesTelemetry(Collected, [])
    };

    private static EndpointTelemetryReport NotCollected(string availability) => new(EndpointTelemetryContract.CurrentSchemaVersion,
        EndpointId, CollectedUtc, new(availability), new(availability), new(availability), new(availability),
        new(availability, availability), new(availability), new(availability), new(availability));

    private static EndpointTelemetryReport WithService(string name, string? state, string? startType) => Benign() with
    {
        Services = new SecurityServicesTelemetry(Collected, [new(name, state, startType)])
    };

    private static SecurityAlert Single(TelemetryRuleEngine engine, EndpointTelemetryReport report, string ruleId)
    {
        var findings = engine.Evaluate(report);
        return findings.Count == 1 && findings[0].RuleId == ruleId
            ? findings[0]
            : throw new InvalidOperationException($"Expected exactly {ruleId}, found {string.Join(", ", findings.Select(f => f.RuleId))}.");
    }

    private static JsonElement? Evidence(SecurityAlert alert, string field) =>
        alert.Evidence.FirstOrDefault(item => item.Field == field)?.Value;

    private static string? Text(SecurityAlert alert, string field) =>
        Evidence(alert, field) is { ValueKind: JsonValueKind.String } value ? value.GetString() : null;

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }
}
