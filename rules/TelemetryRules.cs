using SentinelAI.Contracts.EndpointTelemetry;
using SentinelAI.Contracts.SecurityEvents;

namespace SentinelAI.Rules;

/// <summary>
/// A deterministic finding over one endpoint telemetry report. A rule fires only on an explicit collected value;
/// a section that was not collected, or a value that is Unknown, never matches and never means the condition is absent.
/// </summary>
public interface ITelemetryRule
{
    string Id { get; }
    string Title { get; }
    string Severity { get; }
    string Reason { get; }
    string RecommendedAction { get; }

    /// <summary>Report sections (<see cref="TelemetrySections"/>) the rule reads; it can fire only while they are collected.</summary>
    IReadOnlyList<string> Sections { get; }

    SecurityAlert? Evaluate(EndpointTelemetryReport report);
}

public static class TelemetrySections
{
    public const string BitLocker = "bitLocker";
    public const string Antivirus = "antivirus";
    public const string Services = "services";

    /// <summary>The availability a report states for a rule section.</summary>
    public static string AvailabilityOf(EndpointTelemetryReport report, string section)
    {
        ArgumentNullException.ThrowIfNull(report);
        return section switch
        {
            BitLocker => report.BitLocker.Availability,
            Antivirus => report.Antivirus.Availability,
            Services => report.Services.Availability,
            _ => throw new ArgumentOutOfRangeException(nameof(section))
        };
    }
}

/// <summary>Evaluates telemetry rules in a fixed order, with no clock, I/O, randomness or model input.</summary>
public sealed class TelemetryRuleEngine
{
    public IReadOnlyList<ITelemetryRule> Rules { get; }

    public TelemetryRuleEngine(IEnumerable<ITelemetryRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var snapshot = rules.ToArray();
        if (snapshot.Any(rule => rule is null || string.IsNullOrWhiteSpace(rule.Id) || rule.Sections.Count == 0))
            throw new ArgumentException("Every telemetry rule needs an ID and the sections it reads.", nameof(rules));
        if (snapshot.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
            throw new ArgumentException("Telemetry rule IDs must be unique.", nameof(rules));
        Rules = Array.AsReadOnly(snapshot);
    }

    public static TelemetryRuleEngine CreateDefault() => new([
        new AntivirusAtRiskRule(),
        new BitLockerProtectionOffRule(),
        new FirewallServiceNotRunningRule(),
        new EventLogServiceNotRunningRule()
    ]);

    /// <summary>Rule IDs of the default engine; their alerts come from endpoint telemetry reports.</summary>
    public static IReadOnlySet<string> DefaultRuleIds { get; } =
        CreateDefault().Rules.Select(rule => rule.Id).ToHashSet(StringComparer.Ordinal);

    public IReadOnlyList<SecurityAlert> Evaluate(EndpointTelemetryReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return Array.AsReadOnly(Rules.Select(rule => rule.Evaluate(report)).OfType<SecurityAlert>().ToArray());
    }
}

/// <summary>A rule with fixed identity and wording; subclasses supply only the evidence match.</summary>
public abstract class TelemetryRule(
    string id, string title, string severity, string reason, string recommendedAction, string[] sections) : ITelemetryRule
{
    public string Id { get; } = id;
    public string Title { get; } = title;
    public string Severity { get; } = severity;
    public string Reason { get; } = reason;
    public string RecommendedAction { get; } = recommendedAction;
    public IReadOnlyList<string> Sections { get; } = Array.AsReadOnly(sections);

    public SecurityAlert? Evaluate(EndpointTelemetryReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (Sections.Any(section => TelemetrySections.AvailabilityOf(report, section) != TelemetryAvailability.Collected))
            return null;
        var evidence = Match(report);
        return evidence is null ? null : new SecurityAlert(Id, Title, Severity, Reason, evidence, report.EndpointId,
            report.CollectedUtc, RecommendedAction);
    }

    /// <summary>Returns the rule's evidence when it matches, or null; unknown values never match.</summary>
    protected abstract IReadOnlyList<RuleEvidence>? Match(EndpointTelemetryReport report);

    /// <summary>Evidence for a monitored service that is explicitly stopped or set to start disabled.</summary>
    protected static IReadOnlyList<RuleEvidence>? ServiceNotRunning(EndpointTelemetryReport report, string name)
    {
        var service = report.Services.Items?.FirstOrDefault(item => item.Name == name);
        if (service is null || (service.State != ServiceRunStates.Stopped && service.StartType != ServiceStartTypes.Disabled))
            return null;
        List<RuleEvidence> evidence = [RuleEvidence.Text("service.name", name)];
        if (service.State is { } state) evidence.Add(RuleEvidence.Text("service.state", state));
        if (service.StartType is { } startType) evidence.Add(RuleEvidence.Text("service.startType", startType));
        return evidence.AsReadOnly();
    }
}

/// <summary>SA-AV-001: Windows Security Center reports the registered antivirus protection as poor or snoozed.</summary>
public sealed class AntivirusAtRiskRule() : TelemetryRule(
    "SA-AV-001", "Antivirus protection reported at risk", "high",
    "Windows Security Center reports the endpoint's registered antivirus protection as poor or snoozed, for example " +
    "because real-time protection is off or definitions are out of date.",
    "Open Windows Security on the endpoint, restore real-time protection and definition updates for the registered " +
    "antivirus product, and confirm whether the change was authorized.",
    [TelemetrySections.Antivirus])
{
    protected override IReadOnlyList<RuleEvidence>? Match(EndpointTelemetryReport report) =>
        report.Antivirus.SecurityCenterHealth is SecurityCenterHealthStates.Poor or SecurityCenterHealthStates.Snooze
            ? [RuleEvidence.Text("antivirus.securityCenterHealth", report.Antivirus.SecurityCenterHealth)]
            : null;
}

/// <summary>SA-DISK-001: BitLocker reports protection off on the operating system volume.</summary>
public sealed class BitLockerProtectionOffRule() : TelemetryRule(
    "SA-DISK-001", "Operating system volume without BitLocker protection", "medium",
    "BitLocker reports protection off on the operating system volume: it is not encrypted, only partially encrypted, " +
    "or its key is available in the clear, for example while protection is suspended.",
    "Encrypt the operating system volume or resume BitLocker protection under the organization's policy, and confirm " +
    "that any suspension was planned and is time-limited.",
    [TelemetrySections.BitLocker])
{
    protected override IReadOnlyList<RuleEvidence>? Match(EndpointTelemetryReport report)
    {
        if (report.BitLocker.ProtectionStatus != BitLockerProtectionStates.Off) return null;
        List<RuleEvidence> evidence = [RuleEvidence.Text("bitLocker.protectionStatus", BitLockerProtectionStates.Off)];
        if (report.BitLocker.ConversionStatus is { } conversion)
            evidence.Add(RuleEvidence.Text("bitLocker.conversionStatus", conversion));
        return evidence.AsReadOnly();
    }
}

/// <summary>SA-SVC-001: the Windows Defender Firewall service is stopped or set to start disabled.</summary>
public sealed class FirewallServiceNotRunningRule() : TelemetryRule(
    "SA-SVC-001", "Windows Defender Firewall service not running", "high",
    "The Service Control Manager reports the Windows Defender Firewall service (MpsSvc) stopped or set to start " +
    "disabled, so firewall and connection security policy may not be enforced regardless of the configured profiles.",
    "Restore the Windows Defender Firewall service to start automatically and run, and check which account or software " +
    "stopped or disabled it.",
    [TelemetrySections.Services])
{
    protected override IReadOnlyList<RuleEvidence>? Match(EndpointTelemetryReport report) => ServiceNotRunning(report, "MpsSvc");
}

/// <summary>SA-SVC-002: the Windows Event Log service is stopped or set to start disabled.</summary>
public sealed class EventLogServiceNotRunningRule() : TelemetryRule(
    "SA-SVC-002", "Windows Event Log service not running", "high",
    "The Service Control Manager reports the Windows Event Log service (EventLog) stopped or set to start disabled, so " +
    "Windows and security events are not being recorded.",
    "Restore the Windows Event Log service to start automatically and run, review what happened while it was stopped, " +
    "and check which account or software stopped or disabled it.",
    [TelemetrySections.Services])
{
    protected override IReadOnlyList<RuleEvidence>? Match(EndpointTelemetryReport report) => ServiceNotRunning(report, "EventLog");
}
