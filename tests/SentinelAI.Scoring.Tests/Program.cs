using SentinelAI.Scoring;

var now = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
var endpoint = Guid.Parse("11111111-1111-1111-1111-111111111111");
var secondEndpoint = Guid.Parse("22222222-2222-2222-2222-222222222222");
var engine = new RiskScorer();
var context = new EndpointScoringContext(LatestInventoryUtc: now);
var assertions = 0;

ScoringAlert Alert(string rule = "SA-FW-001", string severity = "high", string status = "open",
    DateTimeOffset? observed = null) => new(Guid.NewGuid(), rule, severity, status, observed ?? now);
EndpointRiskScore Score(params ScoringAlert[] alerts) => engine.ScoreEndpoint(endpoint, alerts, context, now);

Ensure(Score().Score == 0 && Score().RawScore == 0m, "Empty known findings produce zero, not an invented risk.");
var active = Alert();
var open = Score(active);
Ensure(open.Score == 25 && open.Contributions.Single().SeverityPoints == 25m &&
       open.Contributions.Single().DetectionConfidence == 1m && open.Context.Exposure == "unknown" &&
       open.Context.ExposureSource == "policyDefault", "Defaults expose high severity and neutral unknown exposure.");
Ensure(Score(active with { Status = "investigating" }).Score == open.Score &&
       Score(active with { Status = "accepted" }).Score == open.Score,
    "Acceptance and investigation do not prove remediation.");
var resolved = Score(active with { Status = "resolved" });
Ensure(resolved.Score == 0 && resolved.Contributions.Single().PointsBeforeMitigation == 25m &&
       resolved.Contributions.Single().MitigationReduction == 25m && !resolved.Contributions.Single().CorrelationEligible,
    "Resolved zeroes risk with an explicit mitigation reduction and cannot correlate.");

var freshEdge = Score(active with { LastObservedUtc = now.AddDays(-7) }).Contributions.Single();
var agingStart = Score(active with { LastObservedUtc = now.AddDays(-7).AddTicks(-1) }).Contributions.Single();
var agingEdge = Score(active with { LastObservedUtc = now.AddDays(-30) }).Contributions.Single();
var oldStart = Score(active with { LastObservedUtc = now.AddDays(-30).AddTicks(-1) }).Contributions.Single();
Ensure(freshEdge.AgeMultiplier == 1m && freshEdge.AgeBand == "fresh" && agingStart.AgeMultiplier == 0.75m &&
       agingStart.AgeBand == "aging" && agingEdge.AgeMultiplier == 0.75m && oldStart.AgeMultiplier == 0.5m &&
       oldStart.Contribution > 0m, "Inclusive age boundaries remain deterministic and old findings retain nonzero risk.");
var future = Score(active with { LastObservedUtc = now.AddMinutes(1) }).Contributions.Single();
Ensure(future.AgeDays == 0m && future.AgeMultiplier == 1m && future.FutureTimestampClamped,
    "Future observations clamp age to zero and expose clock skew.");
var sameInstant = Score(active with { LastObservedUtc = now.ToOffset(TimeSpan.FromHours(2)) }).Contributions.Single();
Ensure(sameInstant.LatestSnapshotConfirmed && sameInstant.AgeDays == 0m, "Snapshot equality uses absolute instants, not offsets.");

var twoGroups = Score(Alert(severity: "medium"), Alert("SA-UAC-001", "medium"));
Ensure(twoGroups.RawScore == 35m && twoGroups.CorrelationBaseBonus == 5m && twoGroups.CorrelatedGroups.Count == 2,
    "Two independent current groups add a five-point base correlation bonus.");
var sameGroup = Score(Alert(), Alert("SA-FW-002"), Alert("SA-FW-003"));
Ensure(sameGroup.CorrelationBaseBonus == 0m && sameGroup.CorrelatedGroups.Count == 1 && sameGroup.RawScore == 75m,
    "Three firewall profiles are one signal group, preventing duplicate group inflation.");
var historical = Score(Alert(), Alert("SA-UAC-001", observed: now.AddMinutes(-1)));
Ensure(historical.CorrelationBaseBonus == 0m && !historical.Contributions.Single(item => item.RuleId == "SA-UAC-001").LatestSnapshotConfirmed,
    "Historical positives cannot correlate with a newer snapshot that did not reconfirm them.");
var absentSnapshot = engine.ScoreEndpoint(endpoint, [Alert(), Alert("SA-UAC-001")], new(), now);
Ensure(absentSnapshot.CorrelationBonus == 0m && absentSnapshot.Contributions.All(item => !item.LatestSnapshotConfirmed),
    "An absent snapshot cannot imply confirmation.");
var oldSnapshotUtc = now.AddDays(-7).AddTicks(-1);
var oldSnapshot = engine.ScoreEndpoint(endpoint, [Alert(observed: oldSnapshotUtc), Alert("SA-UAC-001", observed: oldSnapshotUtc)],
    context with { LatestInventoryUtc = oldSnapshotUtc }, now);
Ensure(oldSnapshot.CorrelationBonus == 0m && oldSnapshot.Contributions.All(item => item.LatestSnapshotConfirmed && !item.CorrelationEligible),
    "Co-observation alone is insufficient once the snapshot is older than the fresh window.");
var ageBoundary = now.AddDays(-7);
var freshSnapshot = engine.ScoreEndpoint(endpoint, [Alert(observed: ageBoundary), Alert("SA-UAC-001", observed: ageBoundary)],
    context with { LatestInventoryUtc = ageBoundary }, now);
Ensure(freshSnapshot.CorrelationBonus == 5m, "Fresh correlation includes the exact seven-day boundary.");
Ensure(Score(Alert(), Alert("SA-UAC-001", status: "resolved")).CorrelationBonus == 0m,
    "A remediated signal cannot supply a second correlation group.");
Ensure(Score(Alert(), Alert("FUTURE-UNKNOWN-RULE")).CorrelationBonus == 0m,
    "A rule without a declared group cannot silently acquire one.");
var allGroups = new[] { "SA-FW-001", "SA-UAC-001", "SA-RDP-001", "SA-SMB-001", "SA-LOGON-001", "SA-LSA-001", "SA-UPDATE-001" }
    .Select(rule => Alert(rule, "info")).ToArray();
var cappedCorrelation = Score(allGroups);
Ensure(cappedCorrelation.CorrelationBaseBonus == 20m && cappedCorrelation.RawScore == 27m,
    "Independent group correlation is capped before contextual multipliers.");

var confidencePolicy = new ScoringPolicy { ConfidenceByRule = new() { ["SA-FW-001"] = 0.5m, ["SA-UAC-001"] = 0m } };
var weightedEngine = new RiskScorer(confidencePolicy);
var weighted = weightedEngine.ScoreEndpoint(endpoint, [Alert()],
    context with { AssetCriticality = "critical", Exposure = "internet", AssetCriticalitySource = "userDeclared", ExposureSource = "userDeclared" }, now);
Ensure(weighted.RawScore == 37.5m && weighted.Score == 38 && weighted.AssetCriticalityMultiplier == 2m && weighted.ExposureMultiplier == 1.5m &&
       weighted.Contributions.Single().ConfidenceSource == "rulePolicyOverride", "Confidence and explicit context multiply and are individually exposed.");
var disabledConfidence = weightedEngine.ScoreEndpoint(endpoint, [Alert(), Alert("SA-UAC-001")], context, now);
Ensure(disabledConfidence.RawScore == 12.5m && disabledConfidence.CorrelationBonus == 0m &&
       disabledConfidence.Contributions.Single(item => item.RuleId == "SA-UAC-001").Contribution == 0m,
    "An intentional zero-confidence rule cannot reintroduce points through correlation.");
var half = weightedEngine.ScoreEndpoint(endpoint, [Alert(severity: "low")], context, now);
Ensure(half.RawScore == 2.5m && half.Score == 3, "Exact half scores round away from zero.");
var small = new RiskScorer(new ScoringPolicy { DefaultConfidence = 0.1m })
    .ScoreEndpoint(endpoint, [Alert(severity: "info")], context, now);
Ensure(small.Score == 0 && small.RawScore == 0.1m && small.Contributions.Single().Contribution == 0.1m,
    "A rounded zero preserves small positive raw contributions for explanation.");
var agedWeighted = weightedEngine.ScoreEndpoint(endpoint, [Alert(observed: now.AddDays(-10))],
    context with { AssetCriticality = "critical", Exposure = "internet" }, now);
Ensure(agedWeighted.RawScore == 28.125m, "Age applies after severity, confidence and context without intermediate rounding.");
var saturating = engine.ScoreEndpoint(endpoint, [Alert(severity: "critical")],
    context with { AssetCriticality = "critical", Exposure = "internet" }, now);
Ensure(saturating.Score == 100 && saturating.RawScore == 150m && saturating.Saturated, "Saturation preserves uncapped contributing risk.");
var exactlyCap = engine.ScoreEndpoint(endpoint, [Alert(severity: "critical")], context with { AssetCriticality = "critical" }, now);
Ensure(exactlyCap.Score == 100 && !exactlyCap.Saturated, "A raw score exactly at the cap is not mislabeled as truncated.");
var amplifiedCorrelation = engine.ScoreEndpoint(endpoint, allGroups, context with { AssetCriticality = "critical", Exposure = "internet" }, now);
Ensure(amplifiedCorrelation.CorrelationBaseBonus == 20m && amplifiedCorrelation.CorrelationBonus == 60m && amplifiedCorrelation.RawScore == 81m,
    "The API distinguishes the capped base bonus from the context-weighted final bonus.");

var emptyOrganization = engine.ScoreOrganization([]);
Ensure(emptyOrganization.Score == 0 && emptyOrganization.EndpointCount == 0 && emptyOrganization.HighestRiskEndpointCount == 0,
    "An empty fleet has defined zero score and no fabricated highest-risk endpoint.");
var organization = engine.ScoreOrganization([saturating, engine.ScoreEndpoint(secondEndpoint, [], context, now)]);
Ensure(organization.Score == 100 && organization.Method == "maximumEndpointScore" && organization.EndpointCount == 2 &&
       organization.HighestRiskEndpointIds.Single() == endpoint, "Low-risk devices cannot dilute the maximum endpoint risk.");
var tied = engine.ScoreOrganization([open, open with { EndpointId = secondEndpoint }]);
Ensure(tied.HighestRiskEndpointIds.Count == 1 && tied.HighestRiskEndpointCount == 2 && tied.HighestRiskEndpointIdsTruncated &&
       tied.HighestRiskEndpointIds.Single() == endpoint, "Highest-score ties retain a deterministic bounded representative and total count.");
Ensure(Score(allGroups).Contributions.Select(item => item.RuleId).SequenceEqual(Score(allGroups.Reverse().ToArray()).Contributions.Select(item => item.RuleId)),
    "Input ordering does not affect contribution ordering or arithmetic.");

var mutablePolicy = new ScoringPolicy();
var immutableEngine = new RiskScorer(mutablePolicy);
mutablePolicy.SeverityPoints["high"] = 49m;
mutablePolicy.ConfidenceByRule["SA-FW-001"] = 0m;
Ensure(immutableEngine.ScoreEndpoint(endpoint, [Alert()], context, now).Score == 25,
    "External mutation after construction cannot change scoring policy mid-request.");
Throws<NotSupportedException>(() => ((IDictionary<string, decimal>)immutableEngine.Policy.SeverityPoints)["high"] = 49m,
    "The exposed policy snapshot cannot be mutated.");
var customPolicy = new ScoringPolicy { CorrelationPointsPerExtraGroup = 2m, MaximumCorrelationBaseBonus = 3m };
customPolicy.SeverityPoints["high"] = 40m;
var customEngine = new RiskScorer(customPolicy);
Ensure(customEngine.ScoreEndpoint(endpoint, [Alert()], context, now).Score == 40 &&
       customEngine.ScoreEndpoint(endpoint, allGroups, context, now).CorrelationBaseBonus == 3m,
    "Valid centralized policy overrides affect scores and their explanations.");

InvalidPolicy(policy => policy.DefaultConfidence = 0m, "Zero default confidence would erase all unknown rules.");
InvalidPolicy(policy => policy.DefaultConfidence = 1.01m, "Confidence above one is invalid.");
InvalidPolicy(policy => policy.ConfidenceByRule["SA-FW-001"] = -0.1m, "Negative rule confidence is invalid.");
InvalidPolicy(policy => policy.ConfidenceByRule["SA-FW-001"] = 1.01m, "Rule confidence above one is invalid.");
InvalidPolicy(policy => policy.SeverityPoints["high"] = 0m, "Severity weights must be positive.");
InvalidPolicy(policy => policy.SeverityPoints["low"] = 26m, "Severity weights must respect severity ordering.");
InvalidPolicy(policy => policy.SeverityPoints.Remove("critical"), "Missing severity configuration cannot silently become zero.");
InvalidPolicy(policy => policy.AssetMultipliers["standard"] = 0m, "Asset multipliers must be positive.");
InvalidPolicy(policy => policy.AssetMultipliers["low"] = 2m, "Asset multipliers must respect criticality ordering.");
InvalidPolicy(policy => policy.ExposureMultipliers["internet"] = 0m, "Exposure multipliers must be positive.");
InvalidPolicy(policy => policy.ExposureMultipliers["isolated"] = 2m, "Exposure ordering is enforced.");
InvalidPolicy(policy => policy.RemainingRiskByStatus["accepted"] = 0m, "Acceptance cannot be configured to mean remediation.");
InvalidPolicy(policy => policy.RemainingRiskByStatus["resolved"] = 0.1m, "Resolved means zero remaining risk in this lifecycle contract.");
InvalidPolicy(policy => policy.FreshForDays = 0, "The fresh window must be positive.");
InvalidPolicy(policy => policy.AgingForDays = policy.FreshForDays, "Age windows must have distinct ordered boundaries.");
InvalidPolicy(policy => policy.OldMultiplier = 0m, "Age alone must not erase a tracked finding.");
InvalidPolicy(policy => policy.OldMultiplier = 0.9m, "Old observations cannot outweigh aging observations.");
InvalidPolicy(policy => policy.AgingMultiplier = 1.01m, "Age cannot amplify fresh evidence.");
InvalidPolicy(policy => policy.MaximumCorrelationBaseBonus = -1m, "Correlation bonus cannot be negative.");
InvalidPolicy(policy => policy.CorrelationGroupsByRule["SA-FW-001"] = "", "Correlation groups must be explicit nonempty labels.");
Throws<ArgumentException>(() => Score(active with { Severity = "future-unknown" }), "Unknown severities cannot silently receive a fallback score.");
Throws<ArgumentException>(() => Score(active with { Status = "ignored" }), "Unknown lifecycle statuses cannot silently erase risk.");
Throws<ArgumentException>(() => Score(active, active), "Duplicate alert input cannot inflate scores.");
Throws<ArgumentException>(() => Score(active, active with { AlertId = Guid.NewGuid() }), "Duplicate rules cannot inflate endpoint scores.");
Throws<ArgumentException>(() => engine.ScoreEndpoint(Guid.Empty, [], context, now), "Empty endpoint identity is rejected.");
Throws<ArgumentException>(() => engine.ValidateContext(context with { Exposure = "publicguess" }), "Unknown exposure labels cannot fall back silently.");
Throws<ArgumentException>(() => engine.ValidateContext(context with { AssetCriticalitySource = "inferred" }), "Context source cannot falsely claim protection inference.");
Throws<ArgumentException>(() => engine.ScoreOrganization([open, open]), "A duplicated endpoint cannot inflate fleet counts.");

Console.WriteLine($"Scoring tests passed ({assertions} assertions).");

void Ensure(bool condition, string message)
{
    assertions++;
    if (!condition) throw new InvalidOperationException(message);
}

void Throws<T>(Action action, string message) where T : Exception
{
    assertions++;
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException(message);
}

void InvalidPolicy(Action<ScoringPolicy> mutation, string message)
{
    var invalid = new ScoringPolicy();
    mutation(invalid);
    Throws<ArgumentException>(() => _ = new RiskScorer(invalid), message);
}
