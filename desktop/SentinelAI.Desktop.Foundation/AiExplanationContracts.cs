using SentinelAI.Contracts.Ai;

namespace SentinelAI.Desktop.Foundation;

public enum AiExplanationOutcome
{
    Success, Unauthenticated, Disabled, Unsupported, NotFound, Throttled,
    Unavailable, UntrustedConnection, InvalidResponse
}

public sealed record AiExplanationResult(AiExplanationOutcome Outcome, AiExplanation? Analysis = null);

/// <summary>A single explicit request for a stored alert; no prompt or destination override.</summary>
public interface IAiExplanationClient
{
    Task<AiExplanationResult> ExplainAlertAsync(Guid alertId, CancellationToken cancellationToken);
}

/// <summary>Local eligibility is advisory; Core enforces evidence and signed feature permission.</summary>
public static class AiExplanationSupport
{
    public static bool IsSupported(AlertDetail? detail)
    {
        if (detail?.Alert is not { AlertId: var id } alert || id == Guid.Empty ||
            alert.Severity is not ("info" or "low" or "medium" or "high" or "critical") ||
            string.IsNullOrEmpty(alert.RuleId) || AiContract.GetEvidenceFields(alert.RuleId) is not { } expected || detail.Evidence is null)
            return false;
        foreach (var field in expected)
        {
            AlertEvidence? match = null;
            foreach (var evidence in detail.Evidence)
            {
                if (evidence is null || evidence.Field != field.Key) continue;
                if (match is not null) return false;
                match = evidence;
            }
            if (match is null) return false;
            if (field.Value == System.Text.Json.JsonValueKind.True &&
                (match.Kind != AlertEvidenceKind.Boolean || match.BooleanValue is null)) return false;
            if (field.Value == System.Text.Json.JsonValueKind.Number &&
                (match.Kind != AlertEvidenceKind.Integer || match.IntegerValue is not (>= 0 and <= 5))) return false;
        }
        return true;
    }
}
