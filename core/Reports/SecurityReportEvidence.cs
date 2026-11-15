using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using SentinelAI.Contracts.Ai;
using SentinelAI.Rules;
using SentinelAI.Rules.Vulnerabilities;

namespace SentinelAI.Core.Reports;

/// <summary>Report-only evidence projection. This does not change the cloud AI contract.</summary>
internal static class SecurityReportEvidence
{
    private static readonly Regex Finding = new(
        @"^(CVE-[0-9]{4}-[0-9]{4,7}) .{1,128} ([0-9]+(?:\.[0-9]+){0,5})(?: \(fixed in ([0-9]+(?:\.[0-9]+){0,5})\))?$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Cve = new(@"^CVE-[0-9]{4}-[0-9]{4,7}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static IReadOnlyList<RuleEvidence> Read(string ruleId, string? json)
    {
        if (json is null || json.Length > 8192) return [];
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.GetArrayLength() > 32) return [];
            var evidence = new List<RuleEvidence>();
            foreach (var item in document.RootElement.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("Field", out var field) &&
                    field.ValueKind == JsonValueKind.String && field.GetString() is { } name &&
                    item.TryGetProperty("Value", out var value))
                    evidence.Add(new RuleEvidence(name, value.Clone()));
            }
            if (!VulnerabilityRules.RuleIds.Contains(ruleId)) return Filter(ruleId, evidence);

            var projected = new List<RuleEvidence>();
            foreach (var group in evidence.GroupBy(item => item.Field, StringComparer.Ordinal))
            {
                // A stored finding is one CVE/version tuple. Ambiguous duplicates disclose no tuple.
                if (group.Count() != 1) continue;
                var item = group.Single();
                if (item.Field is "vulnerabilities.count" or "feed.version" or "feed.generatedUtc")
                    projected.Add(item);
                else if (FindingIndex(item.Field, out _) && item.Value.ValueKind == JsonValueKind.String &&
                    item.Value.GetString() is { Length: > 0 and <= 300 } text && !text.Any(char.IsControl))
                {
                    var match = Finding.Match(text);
                    if (!match.Success || !VulnerabilityVersion.TryParse(match.Groups[2].Value, out _) ||
                        (match.Groups[3].Success && !VulnerabilityVersion.TryParse(match.Groups[3].Value, out _))) continue;
                    // Product names in legacy combined evidence are free text. Export only the strictly
                    // parsed CVE and comparable versions, never that name or arbitrary appended content.
                    projected.Add(RuleEvidence.Text(item.Field + ".cve", match.Groups[1].Value));
                    projected.Add(RuleEvidence.Text(item.Field + ".installedVersion", match.Groups[2].Value));
                    if (match.Groups[3].Success)
                        projected.Add(RuleEvidence.Text(item.Field + ".fixedVersion", match.Groups[3].Value));
                }
            }
            return Filter(ruleId, projected);
        }
        catch (JsonException) { return []; }
    }

    // Validate again at rendering, including callers that supply a report without using the read store.
    public static IReadOnlyList<RuleEvidence> Filter(string ruleId, IReadOnlyList<RuleEvidence> source)
    {
        if (source.Count > 64) return [];
        var allowed = AiContract.GetEvidenceFields(ruleId);
        var vulnerability = VulnerabilityRules.RuleIds.Contains(ruleId);
        if (allowed is null && !vulnerability) return [];
        var evidence = new SortedDictionary<string, RuleEvidence>(StringComparer.Ordinal);
        var duplicates = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in source)
        {
            var valid = vulnerability ? IsVulnerabilityValue(item) :
                allowed!.TryGetValue(item.Field, out var kind) &&
                ((kind == JsonValueKind.True && item.Value.ValueKind is JsonValueKind.True or JsonValueKind.False) ||
                 (kind == JsonValueKind.Number && item.Value.ValueKind == JsonValueKind.Number &&
                  item.Value.TryGetInt32(out var number) && number is >= 0 and <= 5));
            // Preserve configuration behavior: a malformed duplicate is not supported evidence.
            if (!valid) continue;
            if (evidence.ContainsKey(item.Field) || duplicates.Contains(item.Field))
            {
                evidence.Remove(item.Field);
                duplicates.Add(item.Field);
            }
            else evidence.Add(item.Field, item);
        }
        return evidence.Values.ToArray();
    }

    private static bool IsVulnerabilityValue(RuleEvidence item)
    {
        if (item.Field == "vulnerabilities.count")
            return item.Value.ValueKind == JsonValueKind.Number && item.Value.TryGetInt32(out var count) &&
                count is >= 0 and <= VulnerabilityFeedFormat.MaximumVulnerabilities;
        if (item.Value.ValueKind != JsonValueKind.String || item.Value.GetString() is not { Length: > 0 and <= 64 } text ||
            text.Any(char.IsControl)) return false;
        if (item.Field == "feed.version") return FeedVersion.IsValid(text);
        if (item.Field == "feed.generatedUtc")
            return DateTimeOffset.TryParseExact(text, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out _);
        var separator = item.Field.LastIndexOf('.');
        if (separator < 0 || !FindingIndex(item.Field[..separator], out _)) return false;
        return item.Field[(separator + 1)..] switch
        {
            "cve" => Cve.IsMatch(text),
            "installedVersion" or "fixedVersion" => VulnerabilityVersion.TryParse(text, out _),
            _ => false
        };
    }

    private static bool FindingIndex(string field, out int index)
    {
        const string prefix = "vulnerability.";
        index = 0;
        return field.StartsWith(prefix, StringComparison.Ordinal) &&
            int.TryParse(field.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out index) &&
            index is >= 1 and <= VulnerabilityRules.MaximumEvidenceFindings &&
            field == prefix + index.ToString(CultureInfo.InvariantCulture);
    }
}
