using SentinelAI.Contracts.Ai;
using SentinelAI.Core.Persistence;

namespace SentinelAI.Core;

public enum AiExplanationOutcome { Success, Forbidden, NotFound, UnsupportedContext, Unavailable }
public sealed record AiExplanationResult(AiExplanationOutcome Outcome, AiExplanationResponse? Response = null);

/// <summary>Read-only assistive analysis; deterministic findings and local alert workflows are untouched.</summary>
public sealed class AiExplanationService(AlertStore alerts, LicenseStateService licensing,
    IAiGatewayClient gateway, TimeProvider clock)
{
    public async Task<AiExplanationResult> ExplainAsync(Guid alertId, CancellationToken cancellationToken = default)
    {
        var license = await licensing.GetAsync(cancellationToken);
        if (!license.Capabilities.PremiumFeatures || !license.EnabledFeatures.Contains("cloud_ai", StringComparer.Ordinal))
            return new(AiExplanationOutcome.Forbidden);
        if (!gateway.Configured) return new(AiExplanationOutcome.Unavailable);
        var alert = await alerts.FindAsync(alertId, cancellationToken);
        if (alert is null) return new(AiExplanationOutcome.NotFound);
        var context = AiContextSanitizer.Create(alert, clock.GetUtcNow());
        if (context is null) return new(AiExplanationOutcome.UnsupportedContext);
        var response = await gateway.ExplainAsync(context, cancellationToken);
        if (response?.Label != AiContract.AssistiveLabel || !AiContract.IsValidAnalysis(response.Analysis))
            return new(AiExplanationOutcome.Unavailable);
        return new(AiExplanationOutcome.Success, response);
    }
}
