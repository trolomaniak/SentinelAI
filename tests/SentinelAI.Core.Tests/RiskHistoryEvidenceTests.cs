using System.Text.Json;
using SentinelAI.Core.History;
using SentinelAI.Scoring;

internal static class RiskHistoryEvidenceTests
{
    internal static void Run()
    {
        var checks = 0;
        void Check(bool value, string message)
        {
            checks++;
            if (!value) throw new InvalidOperationException(message);
        }

        var baselinePolicy = new ScoringPolicy();
        var baseline = RiskHistoryEvidence.DescribePolicy(new RiskScorer(baselinePolicy).Policy);
        var reordered = new ScoringPolicy
        {
            SeverityPoints = baselinePolicy.SeverityPoints.Reverse().ToDictionary(pair => pair.Key, pair => pair.Value),
            ConfidenceByRule = baselinePolicy.ConfidenceByRule.Reverse().ToDictionary(pair => pair.Key, pair => pair.Value),
            CorrelationGroupsByRule = baselinePolicy.CorrelationGroupsByRule.Reverse().ToDictionary(pair => pair.Key, pair => pair.Value),
            DefaultConfidence = 1.0000m
        };
        Check(RiskHistoryEvidence.DescribePolicy(new RiskScorer(reordered).Policy) == baseline,
            "The policy identity changed with dictionary ordering or decimal trailing zeros.");
        reordered.SeverityPoints["high"] = 26m;
        var modified = RiskHistoryEvidence.DescribePolicy(new RiskScorer(reordered).Policy);
        Check(modified.Version == baseline.Version && modified.Fingerprint != baseline.Fingerprint,
            "An effective policy edit under the same version did not change the identity.");
        reordered.Version = " release 1 ";
        Check(RiskHistoryEvidence.DescribePolicy(new RiskScorer(reordered).Policy).Version == reordered.Version,
            "The recorded version did not preserve the current scorer's display label.");
        using (var json = JsonDocument.Parse(modified.Json))
        {
            var root = json.RootElement;
            Check(root.GetProperty("algorithm").GetString() == "sentinelai-risk-score-v1" &&
                root.GetProperty("severityPoints").GetProperty("high").GetDecimal() == 26m &&
                root.GetProperty("maximumScore").GetInt32() == 100,
                "The persisted policy did not retain algorithm and effective scoring values.");
        }

        var scorer = new RiskScorer();
        var endpoint = Guid.NewGuid();
        var at = new DateTimeOffset(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
        var alert = new ScoringAlert(Guid.NewGuid(), "SA-FW-001", "high", "open", at);
        var context = new EndpointScoringContext();
        RiskHistoryFactors Factors(ScoringAlert finding, DateTimeOffset now, EndpointScoringContext? declared = null)
            => RiskHistoryEvidence.Build(scorer.ScoreEndpoint(endpoint, [finding], declared ?? context, now));
        var current = Factors(alert, at);
        var aging = Factors(alert, at.AddDays(7).AddTicks(1));
        Check(RiskHistoryEvidence.Compare(null, current, false).SequenceEqual(["firstCapture"]), "First history sample lacked its baseline marker.");
        Check(RiskHistoryEvidence.Compare(current, current, true).SequenceEqual(["policyChanged"]), "A policy boundary disappeared when risk stayed unchanged.");
        Check(RiskHistoryEvidence.Compare(current, aging, false).SequenceEqual(["ageChanged"]), "Aging alone was not distinguished from remediation.");
        Check(RiskHistoryEvidence.Compare(current, Factors(alert with { Status = "accepted" }, at), false).Count == 0,
            "Acceptance was described as changing current risk.");
        Check(RiskHistoryEvidence.Compare(current, Factors(alert with { Status = "accepted" }, at.AddDays(8)), false)
            .SequenceEqual(["ageChanged"]), "Acceptance was described as contributing to a simultaneous age-driven change.");
        var zeroWeight = new ScoringPolicy();
        zeroWeight.ConfidenceByRule[alert.RuleId] = 0m;
        var discounted = RiskHistoryEvidence.Build(new RiskScorer(zeroWeight).ScoreEndpoint(endpoint, [alert], context, at));
        Check(RiskHistoryEvidence.Compare(current, discounted, true).SequenceEqual(["policyChanged"]),
            "A zero confidence weight was described as removing an existing finding.");
        Check(RiskHistoryEvidence.Compare(current, Factors(alert with { Status = "resolved" }, at), false).SequenceEqual(["statusChanged"]),
            "A recorded resolution appeared as alert removal or as an unexplained reduction.");
        Check(RiskHistoryEvidence.Compare(current, Factors(alert with { Severity = "critical" }, at), false).SequenceEqual(["severityChanged"]),
            "A severity change was not identified.");
        Check(RiskHistoryEvidence.Compare(aging, Factors(alert with { LastObservedUtc = at.AddDays(8) }, at.AddDays(8)), false)
            .SequenceEqual(["observationChanged"]), "A renewed finding was mislabeled as aging under unchanged observation time.");
        Check(RiskHistoryEvidence.Compare(current, Factors(alert, at, context with { Exposure = "internet" }), false)
            .SequenceEqual(["contextChanged"]), "A declaration change did not explain the changed inputs.");
        var findings = new[] { alert, new ScoringAlert(Guid.NewGuid(), "SA-RDP-001", "critical", "open", at),
            new ScoringAlert(Guid.NewGuid(), "SA-SMB-001", "critical", "open", at),
            new ScoringAlert(Guid.NewGuid(), "SA-LSA-001", "high", "open", at) };
        var high = RiskHistoryEvidence.Build(scorer.ScoreEndpoint(endpoint, findings, context with { LatestInventoryUtc = at }, at));
        Check(high.RawScore > 100m && high.RuleIds.SequenceEqual(["SA-RDP-001", "SA-SMB-001", "SA-FW-001"]),
            "Principal rule selection was not bounded or deterministically ranked.");
        Check(RiskHistoryEvidence.Compare(current, high, false).SequenceEqual(["findingSetChanged", "correlationChanged"]),
            "Adding findings falsely changed individual prior finding properties.");
        var staleConfirmation = RiskHistoryEvidence.Build(scorer.ScoreEndpoint(endpoint, findings, context, at));
        Check(RiskHistoryEvidence.Compare(high, staleConfirmation, false).SequenceEqual(["confirmationChanged", "correlationChanged"]),
            "Loss of snapshot confirmation and its correlation change were not visible.");
        Check(RiskHistoryEvidence.Compare(high, high with { RawScore = high.RawScore + 1 }, false).SequenceEqual(["unclassified"]),
            "An unexplained score delta was assigned a cause without evidence.");
        Console.WriteLine($"Risk history evidence tests passed ({checks} checks).");
    }
}
