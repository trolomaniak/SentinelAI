using System.Text.Json;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Rules;

/// <summary>Event rule tests: synthetic observations only (SIDs S-1-5-21-1000-1000-1000-100x, IPs 192.0.2.x).</summary>
internal static class EventRuleTests
{
    private const string UserSid = "S-1-5-21-1000-1000-1000-1001";
    private static readonly Guid EndpointId = Guid.Parse("3b9f6a0e-5c1d-4f7a-9b2e-0d4c8e1a7f63");
    private static readonly DateTimeOffset Start = new(2026, 3, 2, 8, 0, 0, TimeSpan.Zero);
    private static long _record;

    public static int Run()
    {
        var engine = EventRuleEngine.CreateDefault();
        var checks = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
            checks++;
        }

        // Catalog of rules: stable, unique, complete metadata over the TASK-027 vocabulary.
        Check(engine.Rules.Count == 12 && EventRuleEngine.DefaultRuleIds.Count == 12, "The default event engine must hold twelve rules.");
        foreach (var rule in engine.Rules.Cast<EventRule>())
        {
            Check(rule.Id.StartsWith("SA-EVT-", StringComparison.Ordinal) && EventRuleEngine.DefaultRuleIds.Contains(rule.Id),
                $"{rule.Id}: event rule IDs must be stable SA-EVT identifiers.");
            Check(rule.Severity is "info" or "low" or "medium" or "high" or "critical", $"{rule.Id}: severity must be a known level.");
            Check(rule.Title.Length is > 0 and <= 128 && rule.Reason.Length > 0 && rule.RecommendedAction.Length > 0,
                $"{rule.Id}: title, reason and recommended action are required.");
            Check(rule.Channels.All(channel => SecurityEventChannels.All.Contains(channel)) &&
                  rule.TriggerKinds.All(kind => SecurityEventContract.Catalog.Any(row => row.Kind == kind && rule.Channels.Contains(row.Channel))),
                $"{rule.Id}: every trigger kind must be collected from one of the rule's channels.");
            Check(!rule.Reason.Contains("compromise", StringComparison.OrdinalIgnoreCase) &&
                  !rule.Title.Contains("compromise", StringComparison.OrdinalIgnoreCase),
                $"{rule.Id}: a detection must not be presented as proof of compromise.");
        }

        Check(engine.Evaluate(EndpointId, [], []).Count == 0, "No observations must produce no detections.");
        Check(engine.MaximumHistoryWindow == TimeSpan.FromMinutes(30) && engine.HistoryKinds.SequenceEqual([SecurityEventKinds.LogonFailed]),
            "History must be bounded to the failed-logon window.");

        // One isolated positive case per rule; each fires exactly its rule with typed evidence.
        var cases = new (string RuleId, Func<List<EventRuleObservation>> Build, string Field, object Expected)[]
        {
            ("SA-EVT-LOGON-001", () => Failures(10, "192.0.2.10"), "logon.failedLogons", 10L),
            ("SA-EVT-RDP-001", () => [.. Failures(5, "192.0.2.20"), At(Logon(SecurityEventKinds.LogonSucceeded, 10, "192.0.2.20", elevated: true), 6)],
                "logon.priorFailedLogons", 5L),
            ("SA-EVT-DEF-001", () => [At(Malware(SecurityEventKinds.MalwareDetected, 1116), 1)], "malware.threatName", "Test.Synthetic.Detection"),
            ("SA-EVT-DEF-002", () => [At(Malware(SecurityEventKinds.MalwareActionFailed, 1118), 1)], "malware.errorCode", 2147942405L),
            ("SA-EVT-PROT-001", () => [At(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5001), 1)], "event.eventId", 5001L),
            ("SA-EVT-PROT-002", () => [At(Observation(SecurityEventKinds.ProtectionServiceStartTypeChanged) with
                { ServiceStartType = new ServiceStartTypeEvent("WinDefend", ServiceStartTypes.Disabled) }, 1)], "service.name", "WinDefend"),
            ("SA-EVT-PROT-003", () => [At(Observation(SecurityEventKinds.DefenderSettingChanged) with
                { DefenderSetting = new DefenderSettingEvent(DefenderSettingAreas.ExclusionPath, DefenderSettingChanges.Added) }, 1)],
                "defender.settingArea", DefenderSettingAreas.ExclusionPath),
            ("SA-EVT-LOG-001", () => [At(Observation(SecurityEventKinds.LogCleared, SecurityEventChannels.System, 104) with
                { LogCleared = new LogClearedEvent("Application") }, 1)], "log.clearedChannel", "Application"),
            ("SA-EVT-PS-001", () => [At(Observation(SecurityEventKinds.ScriptBlockFlagged) with
                { ScriptBlock = new ScriptBlockEvent(Guid.Parse("7c1e3f52-2d4a-4b8e-9f10-5a6b7c8d9e0f"), 1) }, 1)], "script.partCount", 1L),
            ("SA-EVT-PERSIST-001", () => [At(Service("test-only-tmp", ServiceImageLocations.Temp, ServiceTypes.UserModeService), 1)],
                "service.imageLocation", ServiceImageLocations.Temp),
            ("SA-EVT-PERSIST-002", () => [At(Service("test-only-drv", ServiceImageLocations.ProgramFiles, ServiceTypes.KernelDriver), 1)],
                "service.serviceType", ServiceTypes.KernelDriver),
            ("SA-EVT-PERSIST-003", () => [At(Observation(SecurityEventKinds.ScheduledTaskCreated) with
                { ScheduledTask = new ScheduledTaskEvent("\\test-only-task", UserSid) }, 1)], "task.name", "\\test-only-task")
        };
        var exercised = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (ruleId, build, field, expected) in cases)
        {
            var added = build();
            var alerts = engine.Evaluate(EndpointId, added, added);
            Check(alerts.Count == 1 && alerts[0].RuleId == ruleId, $"{ruleId}: the isolated condition must fire exactly this rule.");
            var alert = alerts[0];
            var trigger = added[^1];
            Check(alert.EndpointId == EndpointId && alert.Timestamp == trigger.EffectiveUtc,
                $"{ruleId}: the detection must carry the endpoint and the trigger's effective time.");
            Check(Evidence(alert, "event.recordId") is { ValueKind: JsonValueKind.Number } record && record.GetInt64() == trigger.Observation.RecordId &&
                  Evidence(alert, "event.channel")?.GetString() == trigger.Observation.Channel,
                $"{ruleId}: evidence must locate the triggering record.");
            Check(Evidence(alert, field) is { } value && (expected is string text
                    ? value.ValueKind == JsonValueKind.String && value.GetString() == text
                    : value.ValueKind == JsonValueKind.Number && value.GetInt64() == (long)expected),
                $"{ruleId}: evidence {field} must be typed and exact.");
            Check(alert.Evidence.Select(item => item.Field).Distinct(StringComparer.Ordinal).Count() == alert.Evidence.Count &&
                  alert.Evidence.Count <= 16, $"{ruleId}: evidence fields must be unique and bounded.");
            Check(JsonSerializer.Serialize(engine.Evaluate(EndpointId, added, added)) == JsonSerializer.Serialize(alerts),
                $"{ruleId}: evaluation must be deterministic.");
            exercised.Add(ruleId);
        }
        Check(exercised.SetEquals(EventRuleEngine.DefaultRuleIds), "Every default event rule must have a positive test.");

        // Thresholds and windows.
        var nine = Failures(9, "192.0.2.10");
        Check(engine.Evaluate(EndpointId, nine, nine).Count == 0, "Nine failed logons must not fire SA-EVT-LOGON-001.");
        var spread = Failures(10, "192.0.2.10", spacingMinutes: 1.2);
        Check(engine.Evaluate(EndpointId, spread, spread).Count == 0,
            "Ten failed logons spread beyond ten minutes must not fire SA-EVT-LOGON-001.");
        var older = Failures(9, "192.0.2.10");
        var newer = new List<EventRuleObservation> { At(Logon(SecurityEventKinds.LogonFailed, 3, "192.0.2.11"), 9.5) };
        var burst = engine.Evaluate(EndpointId, newer, [.. older, .. newer]);
        Check(burst.SingleOrDefault() is { RuleId: "SA-EVT-LOGON-001" } fired && Evidence(fired, "logon.failedLogons")!.Value.GetInt64() == 10 &&
              Evidence(fired, "logon.distinctSourceAddresses")!.Value.GetInt64() == 2 &&
              Evidence(fired, "logon.mostFrequentSourceAddress")!.Value.GetString() == "192.0.2.10",
            "Failed logons stored by earlier batches must count toward the window.");

        var fourThenRdp = new List<EventRuleObservation>(Failures(4, "192.0.2.20")) { At(Logon(SecurityEventKinds.LogonSucceeded, 10, "192.0.2.20"), 5) };
        Check(engine.Evaluate(EndpointId, fourThenRdp, fourThenRdp).Count == 0, "Four prior failures must not fire SA-EVT-RDP-001.");
        var otherAddress = new List<EventRuleObservation>(Failures(5, "192.0.2.21")) { At(Logon(SecurityEventKinds.LogonSucceeded, 10, "192.0.2.20"), 6) };
        Check(engine.Evaluate(EndpointId, otherAddress, otherAddress).Count == 0, "Failures from another address must not count for SA-EVT-RDP-001.");
        var interactive = new List<EventRuleObservation>(Failures(5, "192.0.2.20")) { At(Logon(SecurityEventKinds.LogonSucceeded, 2, "192.0.2.20"), 6) };
        Check(engine.Evaluate(EndpointId, interactive, interactive).Count == 0, "A local interactive logon must not fire SA-EVT-RDP-001.");
        var stale = new List<EventRuleObservation>(Failures(5, "192.0.2.20")) { At(Logon(SecurityEventKinds.LogonSucceeded, 10, "192.0.2.20"), 35) };
        Check(engine.Evaluate(EndpointId, stale, stale).Count == 0, "Failures older than thirty minutes must not fire SA-EVT-RDP-001.");

        // Unknown or benign values never match.
        foreach (var benign in new[]
                 {
                     At(Observation(SecurityEventKinds.ProtectionServiceStartTypeChanged) with { ServiceStartType = new ServiceStartTypeEvent("WinDefend", ServiceStartTypes.Auto) }, 1),
                     At(Observation(SecurityEventKinds.ProtectionServiceStartTypeChanged) with { ServiceStartType = new ServiceStartTypeEvent("WinDefend", null) }, 1),
                     At(Observation(SecurityEventKinds.DefenderSettingChanged) with { DefenderSetting = new DefenderSettingEvent(DefenderSettingAreas.ExclusionPath, DefenderSettingChanges.Removed) }, 1),
                     At(Observation(SecurityEventKinds.DefenderSettingChanged) with { DefenderSetting = new DefenderSettingEvent(DefenderSettingAreas.RealTimeProtection, DefenderSettingChanges.Added) }, 1),
                     At(Service("test-only-svc", ServiceImageLocations.ProgramFiles, ServiceTypes.UserModeService), 1),
                     At(Service("test-only-drv", ServiceImageLocations.Windows, ServiceTypes.KernelDriver), 1),
                     At(Service("test-only-unknown", null, ServiceTypes.KernelDriver), 1),
                     At(Observation(SecurityEventKinds.ServiceInstalled), 1),
                     At(Observation(SecurityEventKinds.ScheduledTaskCreated) with { ScheduledTask = new ScheduledTaskEvent("\\Microsoft\\Windows\\test-only", UserSid) }, 1),
                     At(Observation(SecurityEventKinds.ScheduledTaskCreated) with { ScheduledTask = new ScheduledTaskEvent(null, UserSid) }, 1),
                     At(Logon(SecurityEventKinds.LogonSucceeded, 10, null), 1),
                     At(Observation(SecurityEventKinds.MalwareActionTaken) with { Malware = new MalwareEvent(null, 1, "Test.Synthetic.Detection", 5, 8, 2, null) }, 1)
                 })
        {
            Check(engine.Evaluate(EndpointId, [benign], [benign]).Count == 0,
                $"A benign or unknown {benign.Observation.Kind} must not fire any rule.");
        }

        // A future-dated event is ordered at Core's receipt time, never later.
        var received = Start.AddMinutes(1);
        var future = EventRuleObservation.Clamped(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5001) with
            { TimeCreatedUtc = Start.AddDays(3) }, received);
        Check(future.EffectiveUtc == received && engine.Evaluate(EndpointId, [future], [future]).Single().Timestamp == received,
            "A future event time must be clamped to the receipt time.");
        var past = EventRuleObservation.Clamped(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5001), received);
        Check(past.EffectiveUtc == Start, "A past event time must be kept.");

        // Several triggers for one rule in a batch keep the latest evidence; rules report in rule order.
        var several = new List<EventRuleObservation>
        {
            At(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5001), 3),
            At(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5012), 7),
            At(Observation(SecurityEventKinds.ProtectionDisabled, eventId: 5010), 5),
            At(Malware(SecurityEventKinds.MalwareDetected, 1116), 4)
        };
        var mixed = engine.Evaluate(EndpointId, several, several);
        Check(mixed.Select(alert => alert.RuleId).SequenceEqual(["SA-EVT-DEF-001", "SA-EVT-PROT-001"]) &&
              Evidence(mixed[1], "event.eventId")!.Value.GetInt64() == 5012 && mixed[1].Timestamp == Start.AddMinutes(7),
            "Each rule must report once per batch, with its latest evidence, in rule order.");

        // The engine rejects inconsistent rule sets.
        var rejected = 0;
        foreach (var invalid in new Func<EventRuleEngine>[]
                 {
                     () => new EventRuleEngine([new DefenderProtectionDisabledRule(), new DefenderProtectionDisabledRule()]),
                     () => new EventRuleEngine([new BrokenHistoryRule()])
                 })
        {
            try { invalid(); }
            catch (ArgumentException) { rejected++; }
        }
        Check(rejected == 2, "Duplicate IDs and a history without a window must be rejected.");
        return checks;
    }

    private static List<EventRuleObservation> Failures(int count, string address, double spacingMinutes = 0.5) =>
        Enumerable.Range(0, count).Select(index => At(Logon(SecurityEventKinds.LogonFailed, 3, address), index * spacingMinutes)).ToList();

    private static EventRuleObservation At(SecurityEventObservation observation, double minutes)
    {
        var time = Start.AddMinutes(minutes);
        return new EventRuleObservation(observation with { TimeCreatedUtc = time }, time);
    }

    private static SecurityEventObservation Observation(string kind, string? channel = null, int? eventId = null)
    {
        var row = SecurityEventContract.Catalog.First(item => item.Kind == kind && (channel is null || item.Channel == channel) &&
                                                              (eventId is null || item.EventId == eventId));
        return new SecurityEventObservation(row.Channel, row.Provider, row.EventId, 0, 4, ++_record, Start, kind);
    }

    private static SecurityEventObservation Logon(string kind, int logonType, string? address, bool? elevated = null) =>
        Observation(kind) with { Logon = new LogonEvent(logonType, UserSid, address, kind == SecurityEventKinds.LogonFailed ? 0xC000006DL : null, null, elevated) };

    private static SecurityEventObservation Malware(string kind, int eventId) =>
        Observation(kind, eventId: eventId) with
        {
            Malware = new MalwareEvent(Guid.Parse("0f1e2d3c-4b5a-6978-8a9b-acbdcedfe0f1"), 2147519003, "Test.Synthetic.Detection", 5, 8,
                kind == SecurityEventKinds.MalwareActionFailed ? 2 : null, kind == SecurityEventKinds.MalwareActionFailed ? 2147942405 : null)
        };

    private static SecurityEventObservation Service(string name, string? location, string type) =>
        Observation(SecurityEventKinds.ServiceInstalled) with
        {
            ServiceInstall = new ServiceInstallEvent(name, "test-only.exe", location, type, ServiceStartTypes.Demand, ServiceAccountKinds.LocalSystem)
        };

    private static JsonElement? Evidence(SecurityAlert alert, string field) =>
        alert.Evidence.FirstOrDefault(item => item.Field == field)?.Value;

    private sealed class BrokenHistoryRule() : EventRule("test-broken", "Broken", "low", "Broken.", "None.",
        [SecurityEventChannels.Security], [SecurityEventKinds.LogonFailed], [SecurityEventKinds.LogonFailed])
    {
        protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) => null;
    }
}
