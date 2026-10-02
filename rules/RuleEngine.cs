using System.Text.Json;
using SentinelAI.Contracts.Inventory;

namespace SentinelAI.Rules;

/// <summary>A normalized snapshot; the timestamp is the observation time, never the evaluation clock.</summary>
public sealed record EndpointState(
    Guid EndpointId,
    DateTimeOffset Timestamp,
    bool IsWindows,
    SecurityPostureInventory SecurityPosture)
{
    public static EndpointState FromInventory(InventoryReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return new EndpointState(report.EndpointId, report.CollectedUtc,
            IsWindowsName(report.OsName),
            report.SecurityPosture);
    }

    private static bool IsWindowsName(string name) =>
        string.Equals(name, "Windows", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Windows ", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Microsoft Windows ", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Preserves the evidence value's JSON boolean/integer type without string coercion.</summary>
public sealed record RuleEvidence(string Field, JsonElement Value)
{
    public static RuleEvidence Boolean(string field, bool value) =>
        new(field, JsonSerializer.SerializeToElement(value));

    public static RuleEvidence Integer(string field, int value) =>
        new(field, JsonSerializer.SerializeToElement(value));
}

public sealed record SecurityAlert(
    string RuleId,
    string Title,
    string Severity,
    string Reason,
    IReadOnlyList<RuleEvidence> Evidence,
    Guid EndpointId,
    DateTimeOffset Timestamp,
    string RecommendedAction);

public interface IEndpointRule
{
    string Id { get; }
    string Title { get; }
    string Severity { get; }
    SecurityAlert? Evaluate(EndpointState state);
}

/// <summary>Rules execute in the supplied order, with no clock, network, storage, or random inputs.</summary>
public sealed class RuleEngine
{
    public IReadOnlyList<IEndpointRule> Rules { get; }

    public RuleEngine(IEnumerable<IEndpointRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var snapshot = rules.ToArray();
        if (snapshot.Any(rule => rule is null || string.IsNullOrWhiteSpace(rule.Id)))
            throw new ArgumentException("Every rule must have an ID.", nameof(rules));
        if (snapshot.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
            throw new ArgumentException("Rule IDs must be unique.", nameof(rules));
        Rules = Array.AsReadOnly(snapshot);
    }

    public static RuleEngine CreateDefault() => new([
        new DomainFirewallDisabledRule(),
        new PrivateFirewallDisabledRule(),
        new PublicFirewallDisabledRule(),
        new UacDisabledRule(),
        new UacAdministratorPromptDisabledRule(),
        new RdpNlaDisabledRule(),
        new RdpNativeSecurityRule(),
        new RdpLowEncryptionRule(),
        new Smb1ServerEnabledRule(),
        new SmbInsecureGuestLogonsRule(),
        new AutomaticWindowsLogonRule(),
        new LsaProtectionDisabledRule(),
        new AutomaticUpdatesDisabledRule()
    ]);

    public IReadOnlyList<SecurityAlert> Evaluate(EndpointState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        return Array.AsReadOnly(Rules.Select(rule => rule.Evaluate(state))
            .OfType<SecurityAlert>().ToArray());
    }
}

/// <summary>All built-in rules require Windows and explicit reported values; unknown is not a match.</summary>
public abstract class EndpointRule(
    string id, string title, string severity, string reason, string recommendedAction) : IEndpointRule
{
    public string Id { get; } = id;
    public string Title { get; } = title;
    public string Severity { get; } = severity;

    public SecurityAlert? Evaluate(EndpointState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.IsWindows)
            return null;
        var evidence = Match(state.SecurityPosture);
        return evidence is null ? null : new SecurityAlert(Id, Title, Severity, reason,
            evidence, state.EndpointId, state.Timestamp, recommendedAction);
    }

    protected abstract IReadOnlyList<RuleEvidence>? Match(SecurityPostureInventory posture);

    protected static IReadOnlyList<RuleEvidence>? BooleanMatch(string field, bool? value, bool expected) =>
        value == expected ? [RuleEvidence.Boolean(field, expected)] : null;
}
