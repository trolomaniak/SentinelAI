using SentinelAI.Contracts.Ai;

namespace SentinelAI.Core;

/// <summary>Explicitly projects stored findings into the small allowlisted cloud contract.</summary>
public static class AiContextSanitizer
{
    public static AiAlertContext? Create(AlertDetail alert, DateTimeOffset now)
    {
        if (AiContract.GetEvidenceFields(alert.RuleId) is not { } fields) return null;
        var evidence = new List<AiEvidence>(fields.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in alert.Evidence)
        {
            // Unknown/freeform evidence is discarded, even if it appears alongside a supported field.
            if (!fields.ContainsKey(item.Field)) continue;
            if (!seen.Add(item.Field)) return null;
            evidence.Add(new(item.Field, item.Value.Clone()));
        }
        var freshness = alert.LastObservedUtc > now ? "unknown" :
            now - alert.LastObservedUtc <= TimeSpan.FromHours(24) ? "recent" : "stale";
        var context = new AiAlertContext(alert.RuleId, alert.Severity, evidence.AsReadOnly(), "windows", freshness);
        return AiContract.IsValidContext(context) ? context : null;
    }
}
