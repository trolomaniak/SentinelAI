using System.Globalization;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Rules;

/// <summary>
/// A stored security event observation with the time it is ordered by: the Agent's event time clamped
/// to Core's receipt time, so a future-dated event can neither fire early nor outrank later evidence.
/// </summary>
public sealed record EventRuleObservation(SecurityEventObservation Observation, DateTimeOffset EffectiveUtc)
{
    public static EventRuleObservation Clamped(SecurityEventObservation observation, DateTimeOffset receivedUtc)
    {
        ArgumentNullException.ThrowIfNull(observation);
        return new(observation, observation.TimeCreatedUtc <= receivedUtc ? observation.TimeCreatedUtc : receivedUtc);
    }
}

/// <summary>
/// A deterministic runtime detection over continuous security observations. A rule fires only on
/// positive evidence; an absent, unreadable or unreported channel never produces a detection and never
/// means the condition is absent.
/// </summary>
public interface IEventRule
{
    string Id { get; }
    string Title { get; }
    string Severity { get; }

    /// <summary>Channels whose observations the rule reads; it can fire only while one of them is collected.</summary>
    IReadOnlyList<string> Channels { get; }

    /// <summary>Observation kinds whose arrival evaluates the rule.</summary>
    IReadOnlyList<string> TriggerKinds { get; }

    /// <summary>Earlier observation kinds the rule reads, at most <see cref="HistoryWindow"/> before the trigger.</summary>
    IReadOnlyList<string> HistoryKinds { get; }

    TimeSpan HistoryWindow { get; }

    /// <summary>
    /// Evaluates one newly stored trigger. <paramref name="history"/> holds the endpoint's observations of
    /// <see cref="HistoryKinds"/> in (trigger − window, trigger], including the trigger itself when its kind matches.
    /// </summary>
    SecurityAlert? Evaluate(Guid endpointId, EventRuleObservation trigger, IReadOnlyList<EventRuleObservation> history);
}

/// <summary>Runs event rules over newly stored observations, with no clock, I/O, randomness or model input.</summary>
public sealed class EventRuleEngine
{
    public IReadOnlyList<IEventRule> Rules { get; }

    /// <summary>The longest history any rule reads.</summary>
    public TimeSpan MaximumHistoryWindow { get; }

    /// <summary>Every observation kind any rule reads as history.</summary>
    public IReadOnlyList<string> HistoryKinds { get; }

    public EventRuleEngine(IEnumerable<IEventRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var snapshot = rules.ToArray();
        if (snapshot.Any(rule => rule is null || string.IsNullOrWhiteSpace(rule.Id) || rule.TriggerKinds.Count == 0 ||
                                 rule.Channels.Count == 0 || rule.HistoryWindow < TimeSpan.Zero ||
                                 rule.HistoryKinds.Count == 0 != (rule.HistoryWindow == TimeSpan.Zero)))
            throw new ArgumentException("Every event rule needs an ID, channels, trigger kinds and a consistent history.", nameof(rules));
        if (snapshot.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
            throw new ArgumentException("Event rule IDs must be unique.", nameof(rules));
        Rules = Array.AsReadOnly(snapshot);
        MaximumHistoryWindow = snapshot.Select(rule => rule.HistoryWindow).DefaultIfEmpty(TimeSpan.Zero).Max();
        HistoryKinds = Array.AsReadOnly(snapshot.SelectMany(rule => rule.HistoryKinds)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
    }

    public static EventRuleEngine CreateDefault() => new([
        new FailedLogonBurstRule(),
        new RemoteLogonAfterFailuresRule(),
        new DefenderMalwareDetectedRule(),
        new DefenderRemediationFailedRule(),
        new DefenderProtectionDisabledRule(),
        new ProtectionServiceDisabledRule(),
        new DefenderExclusionAddedRule(),
        new EventLogClearedRule(),
        new SuspiciousScriptBlockRule(),
        new ServiceFromUserWritableLocationRule(),
        new DriverOutsideWindowsRule(),
        new ScheduledTaskOutsideMicrosoftRule()
    ]);

    /// <summary>Rule IDs of the default engine; their alerts come from events rather than inventory snapshots.</summary>
    public static IReadOnlySet<string> DefaultRuleIds { get; } =
        CreateDefault().Rules.Select(rule => rule.Id).ToHashSet(StringComparer.Ordinal);

    public bool IsTrigger(string kind) => Rules.Any(rule => rule.TriggerKinds.Contains(kind, StringComparer.Ordinal));

    /// <summary>
    /// Evaluates every newly stored observation in effective-time order and returns, per rule, the
    /// detection with the latest evidence (ties keep the later observation), in rule order.
    /// <paramref name="history"/> is the endpoint's stored observations of <see cref="HistoryKinds"/> covering
    /// <see cref="MaximumHistoryWindow"/> before the earliest added trigger; it may include the added observations.
    /// </summary>
    public IReadOnlyList<SecurityAlert> Evaluate(Guid endpointId, IReadOnlyList<EventRuleObservation> added,
        IReadOnlyList<EventRuleObservation> history)
    {
        ArgumentNullException.ThrowIfNull(added);
        ArgumentNullException.ThrowIfNull(history);
        var ordered = added.OrderBy(item => item.EffectiveUtc).ThenBy(item => item.Observation.Channel, StringComparer.Ordinal)
            .ThenBy(item => item.Observation.RecordId).ToArray();
        var known = history.ToList();
        foreach (var item in ordered)
        {
            if (!known.Any(entry => SameRecord(entry, item))) known.Add(item);
        }

        var findings = new List<SecurityAlert>();
        foreach (var rule in Rules)
        {
            SecurityAlert? latest = null;
            foreach (var trigger in ordered)
            {
                if (!rule.TriggerKinds.Contains(trigger.Observation.Kind, StringComparer.Ordinal)) continue;
                var since = trigger.EffectiveUtc - rule.HistoryWindow;
                var window = rule.HistoryWindow == TimeSpan.Zero
                    ? []
                    : known.Where(entry => rule.HistoryKinds.Contains(entry.Observation.Kind, StringComparer.Ordinal) &&
                                           entry.EffectiveUtc > since && entry.EffectiveUtc <= trigger.EffectiveUtc).ToArray();
                if (rule.Evaluate(endpointId, trigger, window) is { } finding &&
                    (latest is null || finding.Timestamp >= latest.Timestamp))
                    latest = finding;
            }

            if (latest is not null) findings.Add(latest);
        }

        return findings.AsReadOnly();
    }

    private static bool SameRecord(EventRuleObservation left, EventRuleObservation right) =>
        left.Observation.Channel == right.Observation.Channel && left.Observation.RecordId == right.Observation.RecordId &&
        left.Observation.TimeCreatedUtc == right.Observation.TimeCreatedUtc;
}

/// <summary>A rule with fixed identity, wording and inputs; subclasses supply only the evidence match.</summary>
public abstract class EventRule(
    string id, string title, string severity, string reason, string recommendedAction,
    string[] channels, string[] triggerKinds, string[]? historyKinds = null, TimeSpan historyWindow = default) : IEventRule
{
    public string Id { get; } = id;
    public string Title { get; } = title;
    public string Severity { get; } = severity;
    public string Reason { get; } = reason;
    public string RecommendedAction { get; } = recommendedAction;
    public IReadOnlyList<string> Channels { get; } = Array.AsReadOnly(channels);
    public IReadOnlyList<string> TriggerKinds { get; } = Array.AsReadOnly(triggerKinds);
    public IReadOnlyList<string> HistoryKinds { get; } = Array.AsReadOnly(historyKinds ?? []);
    public TimeSpan HistoryWindow { get; } = historyWindow;

    public SecurityAlert? Evaluate(Guid endpointId, EventRuleObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        ArgumentNullException.ThrowIfNull(history);
        if (!TriggerKinds.Contains(trigger.Observation.Kind, StringComparer.Ordinal)) return null;
        var evidence = Match(trigger.Observation, history);
        if (evidence is null) return null;
        List<RuleEvidence> all = [.. evidence, RuleEvidence.Text("event.channel", trigger.Observation.Channel),
            RuleEvidence.Integer("event.eventId", trigger.Observation.EventId),
            RuleEvidence.Integer("event.recordId", trigger.Observation.RecordId)];
        return new SecurityAlert(Id, Title, Severity, Reason, all.AsReadOnly(), endpointId, trigger.EffectiveUtc,
            RecommendedAction);
    }

    /// <summary>Returns the rule's evidence when it matches, or null; unknown values never match.</summary>
    protected abstract IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history);

    protected static void AddText(List<RuleEvidence> evidence, string field, string? value)
    {
        if (value is not null) evidence.Add(RuleEvidence.Text(field, value));
    }

    protected static void AddInteger(List<RuleEvidence> evidence, string field, long? value)
    {
        if (value is { } number) evidence.Add(RuleEvidence.Integer(field, number));
    }

    protected static void AddBoolean(List<RuleEvidence> evidence, string field, bool? value)
    {
        if (value is { } flag) evidence.Add(RuleEvidence.Boolean(field, flag));
    }
}

/// <summary>SA-EVT-LOGON-001: many failed logons in a short window, from any source.</summary>
public sealed class FailedLogonBurstRule() : EventRule(
    "SA-EVT-LOGON-001", "Repeated failed logons", "medium",
    $"At least {Threshold} failed logons were recorded within {WindowMinutes} minutes.",
    "Identify the accounts and source addresses involved, check for password guessing or stale saved credentials, " +
    "and enforce account lockout and strong authentication.",
    [SecurityEventChannels.Security], [SecurityEventKinds.LogonFailed], [SecurityEventKinds.LogonFailed],
    TimeSpan.FromMinutes(WindowMinutes))
{
    public const int Threshold = 10;
    public const int WindowMinutes = 10;

    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        var failures = history.Where(item => item.Observation.Kind == SecurityEventKinds.LogonFailed).ToArray();
        if (failures.Length < Threshold) return null;
        var addresses = failures.Select(item => item.Observation.Logon?.IpAddress).OfType<string>().ToArray();
        List<RuleEvidence> evidence =
        [
            RuleEvidence.Integer("logon.failedLogons", failures.Length),
            RuleEvidence.Integer("logon.windowMinutes", WindowMinutes),
            RuleEvidence.Integer("logon.distinctTargetAccounts",
                failures.Select(item => item.Observation.Logon?.TargetUserSid).OfType<string>().Distinct(StringComparer.Ordinal).Count()),
            RuleEvidence.Integer("logon.distinctSourceAddresses", addresses.Distinct(StringComparer.Ordinal).Count())
        ];
        AddText(evidence, "logon.mostFrequentSourceAddress", addresses
            .GroupBy(address => address, StringComparer.Ordinal)
            .OrderByDescending(group => group.Count()).ThenBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => group.Key).FirstOrDefault());
        return evidence;
    }
}

/// <summary>SA-EVT-RDP-001: a successful RDP logon from an address that had just failed repeatedly.</summary>
public sealed class RemoteLogonAfterFailuresRule() : EventRule(
    "SA-EVT-RDP-001", "Remote interactive logon after repeated failures", "high",
    $"A remote interactive (RDP) logon succeeded from an address that had at least {Threshold} failed logons " +
    $"in the previous {WindowMinutes} minutes.",
    "Confirm with the account owner that the remote session is legitimate. If it is not, disconnect it, reset the " +
    "account's password, and restrict remote desktop exposure.",
    [SecurityEventChannels.Security], [SecurityEventKinds.LogonSucceeded], [SecurityEventKinds.LogonFailed],
    TimeSpan.FromMinutes(WindowMinutes))
{
    public const int Threshold = 5;
    public const int WindowMinutes = 30;
    private const int RemoteInteractive = 10;

    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        if (trigger.Logon is not { LogonType: RemoteInteractive, IpAddress: { } address } logon) return null;
        var failures = history.Count(item => item.Observation.Kind == SecurityEventKinds.LogonFailed &&
                                             string.Equals(item.Observation.Logon?.IpAddress, address, StringComparison.Ordinal));
        if (failures < Threshold) return null;
        List<RuleEvidence> evidence =
        [
            RuleEvidence.Text("logon.sourceAddress", address),
            RuleEvidence.Integer("logon.priorFailedLogons", failures),
            RuleEvidence.Integer("logon.windowMinutes", WindowMinutes)
        ];
        AddText(evidence, "logon.targetUserSid", logon.TargetUserSid);
        AddBoolean(evidence, "logon.elevatedToken", logon.ElevatedToken);
        return evidence;
    }
}

/// <summary>SA-EVT-DEF-001: Microsoft Defender reported a detection.</summary>
public sealed class DefenderMalwareDetectedRule() : EventRule(
    "SA-EVT-DEF-001", "Microsoft Defender detected malware", "high",
    "Microsoft Defender reported a malware or potentially unwanted software detection.",
    "Review the detection in Windows Security, confirm that the threat was remediated, and investigate how the item " +
    "reached the endpoint.",
    [SecurityEventChannels.Defender], [SecurityEventKinds.MalwareDetected])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        DefenderEvidence.For(trigger.Malware);
}

/// <summary>SA-EVT-DEF-002: Microsoft Defender could not complete an action against a threat.</summary>
public sealed class DefenderRemediationFailedRule() : EventRule(
    "SA-EVT-DEF-002", "Microsoft Defender could not remediate a threat", "critical",
    "Microsoft Defender reported that an action against a detected threat failed, so the threat may still be present.",
    "Isolate the endpoint if the threat is active, run a full or offline scan, and remove the threat manually if " +
    "Defender cannot.",
    [SecurityEventChannels.Defender], [SecurityEventKinds.MalwareActionFailed])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        DefenderEvidence.For(trigger.Malware);
}

/// <summary>SA-EVT-PROT-001: Defender real-time, antispyware or antivirus protection was disabled.</summary>
public sealed class DefenderProtectionDisabledRule() : EventRule(
    "SA-EVT-PROT-001", "Microsoft Defender protection disabled", "high",
    "Microsoft Defender reported that real-time, antispyware or antivirus protection was disabled.",
    "Confirm whether the change was authorized, re-enable protection, and check for tampering by other software or " +
    "policies.",
    [SecurityEventChannels.Defender], [SecurityEventKinds.ProtectionDisabled])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) => [];
}

/// <summary>SA-EVT-PROT-002: a monitored protection service was set to start disabled.</summary>
public sealed class ProtectionServiceDisabledRule() : EventRule(
    "SA-EVT-PROT-002", "Protection service start type set to disabled", "high",
    "The start type of a monitored protection service (such as Microsoft Defender, the firewall or the event log) " +
    "was changed to disabled.",
    "Confirm whether the change was authorized, restore the service's start type, and check which account or software " +
    "changed it.",
    [SecurityEventChannels.System], [SecurityEventKinds.ProtectionServiceStartTypeChanged])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        trigger.ServiceStartType is { NewStartType: ServiceStartTypes.Disabled, ServiceName: { } name }
            ? [RuleEvidence.Text("service.name", name), RuleEvidence.Text("service.newStartType", ServiceStartTypes.Disabled)]
            : null;
}

/// <summary>SA-EVT-PROT-003: a Microsoft Defender exclusion was added.</summary>
public sealed class DefenderExclusionAddedRule() : EventRule(
    "SA-EVT-PROT-003", "Microsoft Defender exclusion added", "medium",
    "A Microsoft Defender exclusion (path, process, extension or address) was added, so matching items are no longer " +
    "scanned.",
    "Review the exclusion in Windows Security or policy, remove it if it is not required, and confirm who added it.",
    [SecurityEventChannels.Defender], [SecurityEventKinds.DefenderSettingChanged])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        trigger.DefenderSetting is { Change: DefenderSettingChanges.Added, SettingArea: { } area } &&
        area is DefenderSettingAreas.ExclusionPath or DefenderSettingAreas.ExclusionProcess or
            DefenderSettingAreas.ExclusionExtension or DefenderSettingAreas.ExclusionIpAddress
            ? [RuleEvidence.Text("defender.settingArea", area), RuleEvidence.Text("defender.change", DefenderSettingChanges.Added)]
            : null;
}

/// <summary>SA-EVT-LOG-001: the Security log, or a log recorded by System, was cleared.</summary>
public sealed class EventLogClearedRule() : EventRule(
    "SA-EVT-LOG-001", "Windows event log cleared", "high",
    "A Windows event log was cleared, which removes the history that investigations rely on.",
    "Confirm whether the clear was authorized maintenance. If not, treat earlier activity on the endpoint as unknown " +
    "and review other evidence sources.",
    [SecurityEventChannels.Security, SecurityEventChannels.System], [SecurityEventKinds.LogCleared])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        List<RuleEvidence> evidence = [];
        AddText(evidence, "log.clearedChannel", trigger.LogCleared?.ClearedChannel);
        return evidence;
    }
}

/// <summary>SA-EVT-PS-001: Windows PowerShell logged a script block it considers suspicious.</summary>
public sealed class SuspiciousScriptBlockRule() : EventRule(
    "SA-EVT-PS-001", "PowerShell flagged a suspicious script block", "medium",
    "Windows PowerShell logged a script block at warning level, which it does for script content it considers " +
    "suspicious.",
    "Review the script block in the PowerShell/Operational log, identify the script and the account that ran it, and " +
    "confirm whether it is expected.",
    [SecurityEventChannels.PowerShell], [SecurityEventKinds.ScriptBlockFlagged])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        List<RuleEvidence> evidence = [];
        AddText(evidence, "script.blockId", trigger.ScriptBlock?.ScriptBlockId?.ToString("D", CultureInfo.InvariantCulture));
        AddInteger(evidence, "script.partCount", trigger.ScriptBlock?.PartCount);
        return evidence;
    }
}

/// <summary>SA-EVT-PERSIST-001: a service whose binary lives in a user-writable or remote location.</summary>
public sealed class ServiceFromUserWritableLocationRule() : EventRule(
    "SA-EVT-PERSIST-001", "Service installed from a user-writable or remote location", "high",
    "A new service was installed whose program is in a user profile, a temporary folder or a network location.",
    "Identify the software that installed the service, verify the program's publisher and signature, and remove the " +
    "service if it is not expected.",
    [SecurityEventChannels.System], [SecurityEventKinds.ServiceInstalled])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        trigger.ServiceInstall is { ImageLocation: ServiceImageLocations.UserProfile or ServiceImageLocations.Temp or ServiceImageLocations.Network } service
            ? ServiceEvidence.For(service)
            : null;
}

/// <summary>SA-EVT-PERSIST-002: a kernel or file system driver installed from outside the Windows directory.</summary>
public sealed class DriverOutsideWindowsRule() : EventRule(
    "SA-EVT-PERSIST-002", "Driver installed outside the Windows directory", "high",
    "A new kernel or file system driver service was installed whose program is outside the Windows directory.",
    "Identify the software that installed the driver, verify its publisher and signature, and check it against known " +
    "vulnerable drivers before allowing it.",
    [SecurityEventChannels.System], [SecurityEventKinds.ServiceInstalled])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history) =>
        trigger.ServiceInstall is { ServiceType: ServiceTypes.KernelDriver or ServiceTypes.FileSystemDriver, ImageLocation: { } location } service &&
        location != ServiceImageLocations.Windows
            ? ServiceEvidence.For(service)
            : null;
}

/// <summary>SA-EVT-PERSIST-003: a scheduled task created outside Windows' own task folder.</summary>
public sealed class ScheduledTaskOutsideMicrosoftRule() : EventRule(
    "SA-EVT-PERSIST-003", "Scheduled task created outside the Microsoft task folder", "low",
    "A scheduled task was created outside the \\Microsoft\\ task folder. Software installers commonly do this, and so " +
    "does persistent malware.",
    "Review the task in Task Scheduler, identify the program it runs and the account that created it, and delete it if " +
    "it is not expected.",
    [SecurityEventChannels.Security], [SecurityEventKinds.ScheduledTaskCreated])
{
    protected override IReadOnlyList<RuleEvidence>? Match(SecurityEventObservation trigger, IReadOnlyList<EventRuleObservation> history)
    {
        if (trigger.ScheduledTask is not { TaskName: { } name } task ||
            name.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase)) return null;
        List<RuleEvidence> evidence = [RuleEvidence.Text("task.name", name)];
        AddText(evidence, "task.subjectUserSid", task.SubjectUserSid);
        return evidence;
    }
}

internal static class DefenderEvidence
{
    public static IReadOnlyList<RuleEvidence> For(MalwareEvent? malware)
    {
        List<RuleEvidence> evidence = [];
        if (malware is null) return evidence;
        if (malware.ThreatName is { } name) evidence.Add(RuleEvidence.Text("malware.threatName", name));
        if (malware.ThreatId is { } threat) evidence.Add(RuleEvidence.Integer("malware.threatId", threat));
        if (malware.SeverityId is { } severity) evidence.Add(RuleEvidence.Integer("malware.defenderSeverityId", severity));
        if (malware.CategoryId is { } category) evidence.Add(RuleEvidence.Integer("malware.categoryId", category));
        if (malware.ActionId is { } action) evidence.Add(RuleEvidence.Integer("malware.actionId", action));
        if (malware.ErrorCode is { } error) evidence.Add(RuleEvidence.Integer("malware.errorCode", error));
        if (malware.DetectionId is { } detection) evidence.Add(RuleEvidence.Text("malware.detectionId", detection.ToString("D", CultureInfo.InvariantCulture)));
        return evidence;
    }
}

internal static class ServiceEvidence
{
    public static IReadOnlyList<RuleEvidence> For(ServiceInstallEvent service)
    {
        List<RuleEvidence> evidence = [];
        if (service.ServiceName is { } name) evidence.Add(RuleEvidence.Text("service.name", name));
        if (service.ImageFileName is { } file) evidence.Add(RuleEvidence.Text("service.imageFileName", file));
        if (service.ImageLocation is { } location) evidence.Add(RuleEvidence.Text("service.imageLocation", location));
        if (service.ServiceType is { } type) evidence.Add(RuleEvidence.Text("service.serviceType", type));
        if (service.StartType is { } start) evidence.Add(RuleEvidence.Text("service.startType", start));
        if (service.AccountKind is { } account) evidence.Add(RuleEvidence.Text("service.accountKind", account));
        return evidence;
    }
}
