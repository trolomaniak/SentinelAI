using System.Collections.ObjectModel;

namespace SentinelAI.Scoring;

/// <summary>Bindable policy. RiskScorer validates and snapshots it before use.</summary>
public sealed class ScoringPolicy
{
    public string Version { get; set; } = "risk-v1";
    public Dictionary<string, decimal> SeverityPoints { get; set; } = new(StringComparer.Ordinal)
    {
        ["info"] = 1m, ["low"] = 5m, ["medium"] = 15m, ["high"] = 25m, ["critical"] = 50m
    };
    public decimal DefaultConfidence { get; set; } = 1m;
    public Dictionary<string, decimal> ConfidenceByRule { get; set; } = new(StringComparer.Ordinal);
    public Dictionary<string, decimal> AssetMultipliers { get; set; } = new(StringComparer.Ordinal)
    {
        ["low"] = 0.75m, ["standard"] = 1m, ["high"] = 1.5m, ["critical"] = 2m
    };
    public Dictionary<string, decimal> ExposureMultipliers { get; set; } = new(StringComparer.Ordinal)
    {
        ["isolated"] = 0.75m, ["internal"] = 1m, ["internet"] = 1.5m, ["unknown"] = 1m
    };
    public Dictionary<string, decimal> RemainingRiskByStatus { get; set; } = new(StringComparer.Ordinal)
    {
        ["open"] = 1m, ["investigating"] = 1m, ["accepted"] = 1m, ["resolved"] = 0m
    };
    public int FreshForDays { get; set; } = 7;
    public int AgingForDays { get; set; } = 30;
    public decimal AgingMultiplier { get; set; } = 0.75m;
    public decimal OldMultiplier { get; set; } = 0.5m;
    public decimal CorrelationPointsPerExtraGroup { get; set; } = 5m;
    public decimal MaximumCorrelationBaseBonus { get; set; } = 20m;
    public Dictionary<string, string> CorrelationGroupsByRule { get; set; } = new(StringComparer.Ordinal)
    {
        ["SA-FW-001"] = "FW", ["SA-FW-002"] = "FW", ["SA-FW-003"] = "FW",
        ["SA-UAC-001"] = "UAC", ["SA-UAC-002"] = "UAC",
        ["SA-RDP-001"] = "RDP", ["SA-RDP-002"] = "RDP", ["SA-RDP-003"] = "RDP",
        ["SA-SMB-001"] = "SMB", ["SA-SMB-002"] = "SMB",
        ["SA-LOGON-001"] = "LOGON", ["SA-LSA-001"] = "LSA", ["SA-UPDATE-001"] = "UPDATE"
    };

    internal ScoringPolicySnapshot Snapshot()
    {
        if (string.IsNullOrWhiteSpace(Version) || Version.Length > 100)
            throw new ArgumentException("Scoring policy must have a version of at most 100 characters.");
        var severity = ValidateMap(SeverityPoints, ["info", "low", "medium", "high", "critical"], 0m, 100m);
        var assets = ValidateMap(AssetMultipliers, ["low", "standard", "high", "critical"], 0m, 10m);
        var exposure = ValidateMap(ExposureMultipliers, ["isolated", "internal", "internet", "unknown"], 0m, 10m);
        var statuses = ValidateMap(RemainingRiskByStatus, ["open", "investigating", "accepted", "resolved"], 0m, 1m);
        if (severity.Values.Any(value => value <= 0m) || assets.Values.Any(value => value <= 0m) ||
            exposure.Values.Any(value => value <= 0m))
            throw new ArgumentException("Severity, asset and exposure weights must be positive.");
        if (severity["info"] > severity["low"] || severity["low"] > severity["medium"] ||
            severity["medium"] > severity["high"] || severity["high"] > severity["critical"])
            throw new ArgumentException("Severity points must not decrease as severity increases.");
        if (assets["low"] > assets["standard"] || assets["standard"] > assets["high"] ||
            assets["high"] > assets["critical"])
            throw new ArgumentException("Asset multipliers must not decrease as criticality increases.");
        if (exposure["isolated"] > exposure["internal"] || exposure["internal"] > exposure["internet"])
            throw new ArgumentException("Exposure multipliers must not decrease from isolated to internal to internet.");
        if (statuses["open"] != 1m || statuses["investigating"] != 1m ||
            statuses["accepted"] != 1m || statuses["resolved"] != 0m)
            throw new ArgumentException("Only resolved is remediation: resolved must be 0; open, investigating and accepted must be 1.");
        ValidateRange(DefaultConfidence, 0m, 1m, nameof(DefaultConfidence));
        if (DefaultConfidence == 0m)
            throw new ArgumentException("Default confidence must be positive; a named rule override may deliberately be zero.");
        ArgumentNullException.ThrowIfNull(ConfidenceByRule);
        var confidence = new Dictionary<string, decimal>(StringComparer.Ordinal);
        foreach (var pair in ConfidenceByRule)
        {
            ValidateLabel(pair.Key, nameof(ConfidenceByRule));
            ValidateRange(pair.Value, 0m, 1m, nameof(ConfidenceByRule));
            confidence.Add(pair.Key, pair.Value);
        }
        if (FreshForDays < 1 || FreshForDays > 3650 || AgingForDays <= FreshForDays || AgingForDays > 3650)
            throw new ArgumentException("Age thresholds must satisfy 1 <= FreshForDays < AgingForDays <= 3650.");
        ValidateRange(AgingMultiplier, 0m, 1m, nameof(AgingMultiplier));
        ValidateRange(OldMultiplier, 0m, AgingMultiplier, nameof(OldMultiplier));
        if (OldMultiplier == 0m)
            throw new ArgumentException("Age weights must be positive so age alone cannot erase a finding.");
        ValidateRange(CorrelationPointsPerExtraGroup, 0m, 100m, nameof(CorrelationPointsPerExtraGroup));
        ValidateRange(MaximumCorrelationBaseBonus, 0m, 100m, nameof(MaximumCorrelationBaseBonus));
        ArgumentNullException.ThrowIfNull(CorrelationGroupsByRule);
        var groups = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in CorrelationGroupsByRule)
        {
            ValidateLabel(pair.Key, nameof(CorrelationGroupsByRule));
            ValidateLabel(pair.Value, nameof(CorrelationGroupsByRule));
            groups.Add(pair.Key, pair.Value);
        }
        return new ScoringPolicySnapshot(Version, severity, DefaultConfidence, ReadOnly(confidence), assets,
            exposure, statuses, FreshForDays, AgingForDays, AgingMultiplier, OldMultiplier,
            CorrelationPointsPerExtraGroup, MaximumCorrelationBaseBonus, ReadOnly(groups), 100);
    }

    private static IReadOnlyDictionary<string, decimal> ValidateMap(
        Dictionary<string, decimal>? map, string[] keys, decimal minimum, decimal maximum)
    {
        ArgumentNullException.ThrowIfNull(map);
        if (map.Count != keys.Length || keys.Any(key => !map.ContainsKey(key)))
            throw new ArgumentException($"Policy map requires exactly: {string.Join(", ", keys)}.");
        var snapshot = new Dictionary<string, decimal>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            ValidateRange(map[key], minimum, maximum, key);
            snapshot.Add(key, map[key]);
        }
        return ReadOnly(snapshot);
    }

    private static void ValidateLabel(string? label, string name)
    {
        if (string.IsNullOrWhiteSpace(label) || label.Length > 100)
            throw new ArgumentException($"{name} labels must have 1–100 non-whitespace characters.");
    }

    private static void ValidateRange(decimal value, decimal minimum, decimal maximum, string name)
    {
        if (value < minimum || value > maximum)
            throw new ArgumentOutOfRangeException(name, $"Value must be between {minimum} and {maximum}.");
    }

    private static IReadOnlyDictionary<string, T> ReadOnly<T>(Dictionary<string, T> value) =>
        new ReadOnlyDictionary<string, T>(value);
}

public sealed record ScoringPolicySnapshot(
    string Version,
    IReadOnlyDictionary<string, decimal> SeverityPoints,
    decimal DefaultConfidence,
    IReadOnlyDictionary<string, decimal> ConfidenceByRule,
    IReadOnlyDictionary<string, decimal> AssetMultipliers,
    IReadOnlyDictionary<string, decimal> ExposureMultipliers,
    IReadOnlyDictionary<string, decimal> RemainingRiskByStatus,
    int FreshForDays,
    int AgingForDays,
    decimal AgingMultiplier,
    decimal OldMultiplier,
    decimal CorrelationPointsPerExtraGroup,
    decimal MaximumCorrelationBaseBonus,
    IReadOnlyDictionary<string, string> CorrelationGroupsByRule,
    int MaximumScore);
