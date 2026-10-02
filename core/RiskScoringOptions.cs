using SentinelAI.Scoring;

namespace SentinelAI.Core;

/// <summary>Operator policy and declarations. They never infer Internet exposure from telemetry.</summary>
public sealed class RiskScoringOptions
{
    private readonly IReadOnlyDictionary<Guid, EndpointScoringContext> _contexts;

    private RiskScoringOptions(RiskScorer scorer, IReadOnlyDictionary<Guid, EndpointScoringContext> contexts,
        int inventoryFreshForHours)
    {
        Scorer = scorer;
        _contexts = contexts;
        InventoryFreshForHours = inventoryFreshForHours;
    }

    public RiskScorer Scorer { get; }
    public int InventoryFreshForHours { get; }

    public EndpointScoringContext ContextFor(Guid endpointId, DateTimeOffset? inventoryCollectedUtc) =>
        (_contexts.TryGetValue(endpointId, out var configured) ? configured : new EndpointScoringContext())
            with { LatestInventoryUtc = inventoryCollectedUtc };

    public static RiskScoringOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("SentinelAI:RiskScoring");
        RequireKnownKeys(section, ["Policy", "EndpointContexts", "InventoryFreshForHours"]);
        RequireKnownKeys(section.GetSection("Policy"), typeof(ScoringPolicy).GetProperties().Select(property => property.Name));
        var inventoryFreshForHours = section.GetValue("InventoryFreshForHours", 12);
        if (inventoryFreshForHours is < 1 or > 8760)
        {
            throw new InvalidOperationException("Risk scoring inventory freshness must be between 1 and 8760 hours.");
        }
        var scorer = new RiskScorer(section.GetSection("Policy").Get<ScoringPolicy>() ?? new ScoringPolicy());
        var contexts = new Dictionary<Guid, EndpointScoringContext>();
        foreach (var endpoint in section.GetSection("EndpointContexts").GetChildren())
        {
            if (endpoint.Value is not null)
            {
                throw new InvalidOperationException("Risk scoring endpoint contexts must contain named factor values.");
            }
            RequireKnownKeys(endpoint, ["AssetCriticality", "Exposure"]);
            if (endpoint.GetChildren().Any(factor => factor.Value is null || factor.GetChildren().Any()))
            {
                throw new InvalidOperationException("Risk scoring endpoint factors must be scalar criticality or exposure labels.");
            }
            if (!Guid.TryParse(endpoint.Key, out var endpointId) || endpointId == Guid.Empty)
            {
                throw new InvalidOperationException("Risk scoring endpoint context keys must be nonempty endpoint GUIDs.");
            }

            var criticality = endpoint["AssetCriticality"];
            var exposure = endpoint["Exposure"];
            var context = new EndpointScoringContext(
                AssetCriticality: criticality ?? "standard",
                Exposure: exposure ?? "unknown",
                AssetCriticalitySource: criticality is null ? "policyDefault" : "userDeclared",
                ExposureSource: exposure is null ? "policyDefault" : "userDeclared");
            scorer.ValidateContext(context);
            if (!contexts.TryAdd(endpointId, context))
            {
                throw new InvalidOperationException("Risk scoring endpoint contexts contain a duplicate endpoint GUID.");
            }
        }

        return new RiskScoringOptions(scorer, contexts, inventoryFreshForHours);
    }

    private static void RequireKnownKeys(IConfigurationSection section, IEnumerable<string> permittedKeys)
    {
        var keys = permittedKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var child in section.GetChildren())
        {
            if (!keys.Contains(child.Key))
            {
                throw new InvalidOperationException($"Unknown risk scoring configuration key: {child.Path}.");
            }
        }
    }
}
