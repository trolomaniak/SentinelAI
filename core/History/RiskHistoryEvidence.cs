using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SentinelAI.Contracts.RiskHistory;
using SentinelAI.Contracts.SecurityEvents;
using SentinelAI.Scoring;

namespace SentinelAI.Core.History;

internal sealed record RiskHistoryPolicy(string Version, string Fingerprint, string Json);

// Only the latest capture needs comparison inputs. Digests avoid retaining alert details in every point.
internal sealed record RiskHistoryFactors(string Membership, string Status, string Severity, string Observation,
    string Age, string Confirmation, string Context, decimal CorrelationBonus, decimal RawScore,
    IReadOnlyList<string> RuleIds);

internal static class RiskHistoryEvidence
{
    private const string AlgorithmRevision = "sentinelai-risk-score-v1";
    internal const int MaximumPolicyBytes = 2 * 1024 * 1024;
    // Current Risk already bounds each policy mapping returned to Desktop to this many entries.
    private const int MaximumEntriesPerMapping = 1024;

    internal static RiskHistoryPolicy DescribePolicy(ScoringPolicySnapshot policy)
    {
        if (policy.ConfidenceByRule.Count > MaximumEntriesPerMapping || policy.CorrelationGroupsByRule.Count > MaximumEntriesPerMapping)
            throw new InvalidDataException("The scoring policy exceeds the history storage limit.");

        var bytes = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(bytes))
        {
            writer.WriteStartObject();
            writer.WriteString("algorithm", AlgorithmRevision);
            writer.WriteString("version", policy.Version);
            WriteMap(writer, "severityPoints", policy.SeverityPoints);
            WriteDecimal(writer, "defaultConfidence", policy.DefaultConfidence);
            WriteMap(writer, "confidenceByRule", policy.ConfidenceByRule);
            WriteMap(writer, "assetMultipliers", policy.AssetMultipliers);
            WriteMap(writer, "exposureMultipliers", policy.ExposureMultipliers);
            WriteMap(writer, "remainingRiskByStatus", policy.RemainingRiskByStatus);
            writer.WriteNumber("freshForDays", policy.FreshForDays);
            writer.WriteNumber("agingForDays", policy.AgingForDays);
            WriteDecimal(writer, "agingMultiplier", policy.AgingMultiplier);
            WriteDecimal(writer, "oldMultiplier", policy.OldMultiplier);
            WriteDecimal(writer, "correlationPointsPerExtraGroup", policy.CorrelationPointsPerExtraGroup);
            WriteDecimal(writer, "maximumCorrelationBaseBonus", policy.MaximumCorrelationBaseBonus);
            writer.WriteStartObject("correlationGroupsByRule");
            foreach (var item in policy.CorrelationGroupsByRule.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                writer.WriteString(item.Key, item.Value);
            writer.WriteEndObject();
            writer.WriteNumber("maximumScore", policy.MaximumScore);
            writer.WriteEndObject();
        }
        if (bytes.WrittenCount > MaximumPolicyBytes)
            throw new InvalidDataException("The scoring policy exceeds the history storage limit.");

        // The markers allow surrounding whitespace while still checking every original character.
        var version = SecurityEventContract.IsBoundedText("[" + policy.Version + "]", RiskHistoryContract.MaximumPolicyVersionLength + 2)
            ? policy.Version : "—";
        return new(version, Convert.ToHexStringLower(SHA256.HashData(bytes.WrittenSpan)), Encoding.UTF8.GetString(bytes.WrittenSpan));
    }

    private static void WriteMap(Utf8JsonWriter writer, string name, IReadOnlyDictionary<string, decimal> values)
    {
        writer.WriteStartObject(name);
        foreach (var item in values.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            WriteDecimal(writer, item.Key, item.Value);
        writer.WriteEndObject();
    }

    private static void WriteDecimal(Utf8JsonWriter writer, string name, decimal value)
    {
        writer.WritePropertyName(name);
        writer.WriteRawValue(value.ToString("G29", CultureInfo.InvariantCulture));
    }

    internal static RiskHistoryFactors Build(EndpointRiskScore score)
    {
        // Keep tracked identities stable when a resolution or policy edit reduces their weight to zero.
        var inputs = score.Contributions.OrderBy(contribution => contribution.AlertId)
            .ThenBy(contribution => contribution.RuleId, StringComparer.Ordinal).ToArray();
        var rules = inputs.Where(contribution => contribution.Contribution > 0m && IsRuleId(contribution.RuleId))
            .OrderByDescending(contribution => contribution.Contribution).ThenBy(contribution => contribution.RuleId, StringComparer.Ordinal)
            .Select(contribution => contribution.RuleId).Distinct(StringComparer.Ordinal).Take(RiskHistoryContract.MaximumRuleIds).ToArray();
        var context = score.Context;
        return new(
            Digest(inputs.Select(input => new { input.AlertId, input.RuleId })),
            Digest(inputs.Select(input => input.RemainingRiskMultiplier != 0m)),
            Digest(inputs.Select(input => input.Severity)),
            Digest(inputs.Select(input => input.LastObservedUtc.UtcTicks)),
            Digest(inputs.Select(input => input.AgeBand)),
            Digest(inputs.Select(input => input.LatestSnapshotConfirmed)),
            Digest(new { context.AssetCriticality, context.Exposure, context.AssetCriticalitySource, context.ExposureSource }),
            score.CorrelationBonus, score.RawScore, rules);
    }

    private static bool IsRuleId(string value) => value is { Length: > 0 and <= RiskHistoryContract.MaximumRuleIdLength } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static string Digest<T>(T value) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));

    internal static IReadOnlyList<string> Compare(RiskHistoryFactors? previous, RiskHistoryFactors current, bool policyChanged)
    {
        if (previous is null) return ["firstCapture"];
        var changes = new List<string>();
        if (policyChanged) changes.Add("policyChanged");
        if (previous.RawScore == current.RawScore) return changes;

        if (previous.Context != current.Context) changes.Add("contextChanged");
        if (previous.Membership != current.Membership)
        {
            changes.Add("findingSetChanged");
        }
        else
        {
            if (previous.Status != current.Status) changes.Add("statusChanged");
            if (previous.Severity != current.Severity) changes.Add("severityChanged");
            if (previous.Observation != current.Observation) changes.Add("observationChanged");
            else if (!policyChanged && previous.Age != current.Age) changes.Add("ageChanged");
            if (previous.Confirmation != current.Confirmation) changes.Add("confirmationChanged");
        }
        if (previous.CorrelationBonus != current.CorrelationBonus) changes.Add("correlationChanged");
        if (changes.Count == 0) changes.Add("unclassified");
        return changes;
    }
}
