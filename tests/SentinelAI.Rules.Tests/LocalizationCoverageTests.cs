using SentinelAI.Localization;
using SentinelAI.Rules;
using SentinelAI.Rules.Vulnerabilities;

/// <summary>Every title, reason and recommended action a rule can raise has a Polish translation.</summary>
internal static class LocalizationCoverageTests
{
    public static IReadOnlyList<string> RuleTexts()
    {
        var texts = new List<string>();
        foreach (var rule in RuleEngine.CreateDefault().Rules.Cast<EndpointRule>()) texts.AddRange([rule.Title, rule.Reason, rule.RecommendedAction]);
        foreach (var rule in TelemetryRuleEngine.CreateDefault().Rules.Cast<TelemetryRule>()) texts.AddRange([rule.Title, rule.Reason, rule.RecommendedAction]);
        foreach (var rule in EventRuleEngine.CreateDefault().Rules.Cast<EventRule>()) texts.AddRange([rule.Title, rule.Reason, rule.RecommendedAction]);
        VulnerabilityFinding Finding(string cve, string severity, bool exploited) => new(cve, "synthetic", "Synthetic", "Synthetic", "1.0", severity, null,
            null, exploited, exploited ? "2099-01-01" : null, null, "Synthetic.");
        var assessment = new VulnerabilityAssessment("2026.1031.1405", [], null,
            [Finding("CVE-2099-0001", VulnerabilitySeverities.Critical, true), Finding("CVE-2099-0002", VulnerabilitySeverities.Critical, false),
             Finding("CVE-2099-0003", VulnerabilitySeverities.High, false)]);
        foreach (var alert in VulnerabilityRules.Evaluate(assessment, Guid.NewGuid(), DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch))
            texts.AddRange([alert.Title, alert.Reason, alert.RecommendedAction]);
        return texts.Distinct(StringComparer.Ordinal).ToArray();
    }

    public static int Run()
    {
        var texts = RuleTexts();
        var missing = texts.Where(text => !TextCatalog.Polish.Entries.ContainsKey(text)).ToArray();
        if (missing.Length > 0)
            throw new InvalidOperationException("Rule texts without a Polish translation:" + Environment.NewLine + string.Join(Environment.NewLine, missing));
        Console.WriteLine($"Rule localization tests passed ({texts.Count} titles, reasons and actions translated).");
        return texts.Count;
    }
}
